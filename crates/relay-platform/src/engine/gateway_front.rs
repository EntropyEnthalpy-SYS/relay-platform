//! The public listener of a protocol gateway. The protocol engine listens on
//! loopback only ([`crate::gateway::Upstream`]); clients reach it through
//! here, judged by their own address before the engine sees a byte of them:
//! the rule's expiry, the server's and the rule's inbound rule sets, then the
//! rule's source lists, as for other rules. A refused TCP client is closed
//! without a read. Every datagram is judged as it arrives, either way (those
//! the kernel joins come from one sender and are judged together, see
//! [`Datagrams`]), so a policy change holds an open association at its next
//! datagram, and a client whose address changes is a new association,
//! judged afresh. Refusals go to the block records.
//!
//! What clients that pass hold here is bounded so that none can starve the
//! others or the Agent: places per gateway ([`FRONT_LIMIT`]) and per source
//! ([`TCP_PER_SOURCE`], [`UDP_PER_SOURCE`]), descriptors for all gateways
//! together ([`descriptor_budget`]), a short life for an association whose
//! client has not shown that it receives the engine's answers
//! ([`UNCONFIRMED`], [`Reach`]), and an idle limit on a connection once one
//! side has ended it.
//!
//! Nothing here meters or throttles: the gateway's traffic is metered,
//! limited and checked at its destination on the bridge, as before.
use super::*;
use socket2::{Domain, SockRef, Socket, TcpKeepalive, Type};
use std::{
    net::{IpAddr, Ipv6Addr},
    sync::{Mutex as StdMutex, OnceLock},
};
use tokio::{
    io::Interest,
    net::tcp::{OwnedReadHalf, OwnedWriteHalf},
    time::timeout,
};

/// Client TCP connections, and client UDP associations, a gateway's public
/// listener holds at once: a bound on descriptors only, never under the
/// rule's `max_connections` or `udp_max_sessions`. Those keep counting what
/// clients open through the gateway, once, on the bridge, as before; a
/// client's own TCP or QUIC connection counts against neither.
const FRONT_LIMIT: usize = 4096;
/// Client TCP connections one source holds at once on one gateway: an IPv4
/// address, or an IPv6 /64, the least one client can count on holding.
const TCP_PER_SOURCE: usize = 256;
/// Client UDP associations one source holds at once on one gateway; a QUIC
/// client needs one, and one more for a while after its port changes.
const UDP_PER_SOURCE: usize = 64;
/// An association whose client has not shown, within this long after it
/// opened, that it receives what the engine answers ([`Reach`]) ends: a
/// QUIC handshake shows it within a round trip, so datagrams the engine
/// ignores, or answers to an address that does not hear them (a spoofed
/// one), hold no place for the idle timeout.
const UNCONFIRMED: Duration = Duration::from_secs(5);
/// Keepalive on client TCP connections, so a client that vanished while
/// its connection was open gives its place back.
const KEEPALIVE_TIME: Duration = Duration::from_secs(60);
const KEEPALIVE_INTERVAL: Duration = Duration::from_secs(15);
const KEEPALIVE_RETRIES: u32 = 4;
/// The shortest time an association with no datagram either way stays:
/// longer than the engine's QUIC idle timeout (30 s for Hysteria2 and
/// TUIC), so the engine ends a quiet connection first. A rule's longer
/// `idle_timeout_secs` applies as it is.
const UDP_IDLE: Duration = Duration::from_secs(31);
/// Socket buffers of the public UDP listener and of each association's
/// loopback socket, as the engine asks for its own (the kernel caps them).
const UDP_BUFFER: usize = 4 << 20;
const CONNECT: Duration = Duration::from_secs(5);

/// The public listener a protocol gateway needs besides its bridge: TCP or
/// UDP at the gateway's address, as its engine inbound uses.
pub(super) fn key(spec: &Rule) -> Option<ListenerKey> {
    spec.protocol_gateway.as_ref().map(public_key)
}
/// [`key`] of a rule that is the gateway `gateway`.
pub(super) fn public_key(gateway: &crate::gateway::Config) -> ListenerKey {
    ListenerKey {
        address: gateway.listen,
        tcp: !gateway.protocol.uses_udp_socket(),
    }
}
/// Binds a gateway's public listener as the engine bound it before: `[::]`
/// also takes IPv4 clients, which arrive IPv4-mapped. Datagrams keep the
/// don't-fragment bit, so the engine's path MTU probes see the real path.
pub(super) fn bind(key: ListenerKey) -> std::io::Result<StagedSocket> {
    let address = key.address;
    let kind = if key.tcp { Type::STREAM } else { Type::DGRAM };
    let socket = Socket::new(Domain::for_address(address), kind, None)?;
    if address.is_ipv6() {
        socket.set_only_v6(!address.ip().is_unspecified())?;
    }
    if key.tcp {
        socket.set_reuse_address(true)?;
        socket.bind(&address.into())?;
        socket.listen(1024)?;
        socket.set_nonblocking(true)?;
        return Ok(StagedSocket::GatewayTcp(TcpListener::from_std(
            socket.into(),
        )?));
    }
    datagram_socket(&socket);
    dont_fragment(&socket, address)?;
    crate::datagram::configure(&socket, address)?;
    socket.bind(&address.into())?;
    socket.set_nonblocking(true)?;
    Ok(StagedSocket::GatewayUdp(UdpSocket::from_std(
        socket.into(),
    )?))
}
#[cfg(target_os = "linux")]
fn dont_fragment(socket: &Socket, address: SocketAddr) -> std::io::Result<()> {
    use nix::libc;
    use std::os::fd::AsRawFd;
    let value: libc::c_int = libc::IP_PMTUDISC_DO;
    let mut options = vec![(libc::IPPROTO_IP, libc::IP_MTU_DISCOVER)];
    if address.is_ipv6() {
        options = vec![(libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER)];
        if address.ip().is_unspecified() {
            options.push((libc::IPPROTO_IP, libc::IP_MTU_DISCOVER));
        }
    }
    for (level, option) in options {
        // SAFETY: socket owns a live descriptor; value and its exact size stay
        // valid for the duration of setsockopt, which does not retain the pointer.
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                level,
                option,
                (&value as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error());
        }
    }
    Ok(())
}
#[cfg(not(target_os = "linux"))]
fn dont_fragment(_: &Socket, _: SocketAddr) -> std::io::Result<()> {
    Ok(())
}

/// Why `rule`'s gateway refuses a client at `ip`, as its block record says.
fn refusal(rule: &RuntimeRule, ip: IpAddr) -> Option<(Reason, String)> {
    let spec = &rule.spec;
    if spec.expires_at_ms.is_some_and(|expiry| expiry <= now_ms()) {
        return Some((Reason::Expired, "the rule expired".into()));
    }
    let rule_set = spec.firewall_inbound_set.as_deref();
    if (rule_set.is_some() || rule.firewall.server_inbound())
        && let Some(refused) = rule.firewall.load().inbound_refusal(rule_set, ip)
    {
        return Some((Reason::Firewall, refused.detail()));
    }
    if let Some(network) = spec.deny_sources.iter().find(|n| n.contains(&ip)) {
        return Some((
            Reason::SourceDenied,
            format!("matches deny-list network {network}"),
        ));
    }
    if !spec.allow_sources.is_empty() && !spec.allow_sources.iter().any(|n| n.contains(&ip)) {
        return Some((Reason::SourceNotAllowed, "not in the allow list".into()));
    }
    None
}
/// Where the engine takes `rule`'s clients now, and a token cancelled once
/// it no longer does.
fn upstream(rule: &RuntimeRule) -> Option<(SocketAddr, CancellationToken)> {
    rule.gateway_upstream.as_ref()?.current()
}
/// Descriptors the public listeners of every gateway hold for their clients
/// together.
static DESCRIPTORS: AtomicUsize = AtomicUsize::new(0);
/// How many descriptors [`DESCRIPTORS`] may reach: half of this process's
/// limit at the time, so a flood of clients leaves the rest of the Agent
/// (bridges, other rules, the controller connection) room to work.
fn descriptor_budget() -> usize {
    #[cfg(any(target_os = "linux", target_os = "macos"))]
    {
        use nix::libc;
        let mut limit = libc::rlimit {
            rlim_cur: 0,
            rlim_max: 0,
        };
        // SAFETY: getrlimit only fills `limit`, a valid rlimit that outlives
        // the call.
        if unsafe { libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit) } == 0 {
            return usize::try_from(limit.rlim_cur).unwrap_or(usize::MAX) / 2;
        }
    }
    usize::MAX
}
/// The source a client's address counts against: the address itself, or
/// for IPv6 its /64.
fn source(ip: IpAddr) -> IpAddr {
    match ip {
        IpAddr::V6(v6) => {
            let s = v6.segments();
            IpAddr::V6(Ipv6Addr::new(s[0], s[1], s[2], s[3], 0, 0, 0, 0))
        }
        v4 => v4,
    }
}
/// What clients hold on one gateway's public listener.
#[derive(Default)]
struct Places(StdMutex<Held>);
#[derive(Default)]
struct Held {
    all: usize,
    sources: HashMap<IpAddr, usize>,
}
/// One client's place, given back on drop.
struct Place {
    places: Arc<Places>,
    source: IpAddr,
    descriptors: usize,
}
impl Places {
    /// A place for a client at `ip` that needs `descriptors`, among at most
    /// `limit` and `per_source` from its source; or why there is none.
    /// `what` names the places in that answer.
    fn take(
        self: &Arc<Self>,
        ip: IpAddr,
        limit: usize,
        per_source: usize,
        descriptors: usize,
        what: &str,
    ) -> Result<Place, String> {
        let source = source(ip);
        let mut held = self.0.lock().unwrap();
        if held.all >= limit {
            return Err(format!("limit {limit} client {what}"));
        }
        if held.sources.get(&source).is_some_and(|&n| n >= per_source) {
            return Err(format!("limit {per_source} client {what} from one address"));
        }
        let budget = descriptor_budget();
        if DESCRIPTORS.fetch_add(descriptors, Ordering::AcqRel) + descriptors > budget {
            DESCRIPTORS.fetch_sub(descriptors, Ordering::AcqRel);
            return Err(format!(
                "the Agent's {budget} descriptors for gateway clients are in use"
            ));
        }
        held.all += 1;
        *held.sources.entry(source).or_default() += 1;
        Ok(Place {
            places: self.clone(),
            source,
            descriptors,
        })
    }
}
impl Drop for Place {
    fn drop(&mut self) {
        DESCRIPTORS.fetch_sub(self.descriptors, Ordering::AcqRel);
        let mut held = self.places.0.lock().unwrap();
        held.all -= 1;
        if let Some(n) = held.sources.get_mut(&self.source) {
            *n -= 1;
            if *n == 0 {
                held.sources.remove(&self.source);
            }
        }
    }
}
/// Runs `work` without a deadline until `other` is cancelled, then gives
/// what is left of it `idle`.
async fn once_other_ends<T>(
    work: impl std::future::Future<Output = io::Result<T>>,
    other: &CancellationToken,
    idle: Duration,
) -> io::Result<T> {
    tokio::pin!(work);
    if !other.is_cancelled() {
        tokio::select! {
            biased;
            result = &mut work => return result,
            _ = other.cancelled() => {}
        }
    }
    timeout(idle, work)
        .await
        .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))?
}
/// Carries one direction, passing its end on; `done` says it ended. Once
/// the other direction (`other`) has ended, each read or write here gets
/// `idle` at most.
async fn half(
    mut from: OwnedReadHalf,
    mut to: OwnedWriteHalf,
    done: &CancellationToken,
    other: &CancellationToken,
    idle: Duration,
) -> io::Result<()> {
    let mut buffer = vec![0u8; MIN_STREAM_BUFFER];
    loop {
        let read = once_other_ends(from.read(&mut buffer), other, idle).await?;
        if read == 0 {
            once_other_ends(to.shutdown(), other, idle).await?;
            done.cancel();
            return Ok(());
        }
        once_other_ends(to.write_all(&buffer[..read]), other, idle).await?;
        if read == buffer.len() && buffer.len() < BUFFER_SIZE {
            buffer = vec![0u8; (buffer.len() * 2).min(BUFFER_SIZE)];
        }
    }
}
/// Carries a client connection to the engine and back, each direction's
/// end passed on as it comes. An open connection has no idle limit; once
/// one side has ended its direction, the other ends after `idle` without
/// data, so a client gone quiet after the engine closed does not keep its
/// place.
async fn relay(client: TcpStream, engine: TcpStream, idle: Duration) -> io::Result<()> {
    let (client_read, client_write) = client.into_split();
    let (engine_read, engine_write) = engine.into_split();
    let (up, down) = (CancellationToken::new(), CancellationToken::new());
    tokio::try_join!(
        half(client_read, engine_write, &up, &down, idle),
        half(engine_read, client_write, &down, &up, idle),
    )?;
    Ok(())
}

pub(super) async fn tcp(
    listener: TcpListener,
    updates: watch::Receiver<Arc<RuntimeRule>>,
    stop: CancellationToken,
    stats: Arc<Counters>,
    tasks: TaskTracker,
) {
    let places = Arc::<Places>::default();
    loop {
        let accepted = tokio::select! {biased; _ = stop.cancelled() => break, result = listener.accept() => result};
        let (client, peer) = match accepted {
            Ok(pair) => pair,
            Err(error) => {
                tracing::warn!(%error, "gateway TCP accept failed");
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let rule = updates.borrow().clone();
        let ip = canonical_ip(peer.ip());
        // The client's socket and the one to the engine.
        let place = match refusal(&rule, ip) {
            Some(refused) => Err(refused),
            None => places
                .take(
                    ip,
                    FRONT_LIMIT.max(rule.spec.max_connections as usize),
                    TCP_PER_SOURCE,
                    2,
                    "connections",
                )
                .map_err(|detail| (Reason::ConnectionLimit, detail)),
        };
        let place = match place {
            Ok(place) => place,
            Err((reason, detail)) => {
                stats.rejected_connections.fetch_add(1, Ordering::Relaxed);
                stats
                    .blocks
                    .record(&rule.key, rule.kinds[0], ip, reason, || detail);
                // Reset at once: nothing the client sent is read.
                let _ = SockRef::from(&client).set_linger(Some(Duration::ZERO));
                continue;
            }
        };
        // The engine is not listening: closed, never passed on.
        let Some((engine, gone)) = upstream(&rule) else {
            let _ = SockRef::from(&client).set_linger(Some(Duration::ZERO));
            continue;
        };
        tasks.spawn(async move {
            let _place = place;
            let idle = Duration::from_secs(rule.spec.idle_timeout_secs);
            let carry = async {
                client.set_nodelay(true)?;
                let keepalive = TcpKeepalive::new()
                    .with_time(KEEPALIVE_TIME)
                    .with_interval(KEEPALIVE_INTERVAL)
                    .with_retries(KEEPALIVE_RETRIES);
                SockRef::from(&client).set_tcp_keepalive(&keepalive)?;
                let engine = timeout(CONNECT, TcpStream::connect(engine))
                    .await
                    .map_err(|_| io::Error::from(io::ErrorKind::TimedOut))??;
                engine.set_nodelay(true)?;
                relay(client, engine, idle).await
            };
            tokio::select! {
                biased;
                _ = rule.cancel.cancelled() => {}
                _ = gone.cancelled() => {}
                result = carry => if let Err(error) = result {
                    tracing::debug!(rule_id = %rule.spec.id, %error, "gateway client connection ended");
                }
            }
        });
    }
}

/// An open association: the client's datagrams go to the engine on
/// `engine`; its task carries the engine's back, holds its place and ends
/// it.
struct Peer {
    generation: u64,
    engine: Arc<UdpSocket>,
    /// [`clock`] at the last datagram either way.
    last: Arc<AtomicU64>,
    reach: Arc<Reach>,
    end: CancellationToken,
}
/// Whether an association's client has shown that it receives what the
/// engine sends it. A QUIC server answers a valid Initial before any
/// authentication, to whatever address it came from; a client that sent it
/// from an address it does not hold keeps sending without the answer.
/// Only a client that received the answer addresses the connection ID the
/// engine chose in it, as every QUIC packet after the first does.
#[derive(Default)]
struct Reach {
    answered: AtomicBool,
    /// The connection ID the engine's first QUIC long-header answer chose.
    engine_id: OnceLock<Vec<u8>>,
    shown: AtomicBool,
}
impl Reach {
    /// Takes in datagrams the engine sent the client.
    fn answer(&self, datagrams: Datagrams) {
        self.answered.store(true, Ordering::Release);
        if self.engine_id.get().is_none()
            && let Some(id) = datagrams.into_iter().find_map(engine_id)
        {
            let _ = self.engine_id.set(id);
        }
    }
    /// Takes in datagrams the client sent the engine. `opaque` when the
    /// engine's QUIC headers cannot be read (Hysteria2 obfuscation, whose
    /// password a client needs for any answer at all): then any datagram
    /// after an answer shows it.
    fn sent(&self, datagrams: Datagrams, opaque: bool) {
        if self.shown.load(Ordering::Acquire) {
            return;
        }
        let shown = if opaque {
            self.answered.load(Ordering::Acquire)
        } else {
            self.engine_id
                .get()
                .is_some_and(|id| datagrams.into_iter().any(|d| addresses(d, id)))
        };
        if shown {
            self.shown.store(true, Ordering::Release);
        }
    }
}
/// The source connection ID of a QUIC long-header packet other than a
/// version negotiation, when it names one.
fn engine_id(datagram: &[u8]) -> Option<Vec<u8>> {
    if datagram.first()? & 0x80 == 0 || datagram.get(1..5)? == [0; 4] {
        return None;
    }
    let source = 6 + *datagram.get(5)? as usize;
    let length = *datagram.get(source)? as usize;
    let id = datagram.get(source + 1..source + 1 + length)?;
    (!id.is_empty()).then(|| id.to_vec())
}
/// Whether the first QUIC packet of `datagram` is addressed to connection
/// `id`, by a long header or a short one.
fn addresses(datagram: &[u8], id: &[u8]) -> bool {
    let Some(&first) = datagram.first() else {
        return false;
    };
    let destination = if first & 0x80 != 0 {
        datagram
            .get(5)
            .and_then(|&length| datagram.get(6..6 + length as usize))
    } else {
        datagram.get(1..1 + id.len())
    };
    destination == Some(id)
}
/// Whether `spec`'s gateway obfuscates its QUIC packets.
fn opaque(spec: &Rule) -> bool {
    spec.protocol_gateway.as_ref().is_some_and(|gateway| {
        matches!(
            gateway.protocol,
            crate::gateway::WireProtocol::Hysteria2 { obfs: Some(_), .. }
        )
    })
}

/// Datagrams one sender sent back to back, as one receive took them: the
/// kernel joins those of one flow (UDP GRO) and splits them again as they
/// go out (UDP GSO), so carrying many costs one receive and one send. Each
/// is `segment` bytes but the last, which may be shorter.
#[derive(Clone, Copy)]
struct Datagrams<'a> {
    data: &'a [u8],
    segment: usize,
}
impl<'a> Datagrams<'a> {
    fn count(self) -> u64 {
        self.data.len().div_ceil(self.segment).max(1) as u64
    }
    /// Those after the first `bytes`, which are whole datagrams.
    fn after(self, bytes: usize) -> Self {
        Self {
            data: &self.data[bytes..],
            ..self
        }
    }
}
impl<'a> IntoIterator for Datagrams<'a> {
    type Item = &'a [u8];
    type IntoIter = std::slice::Chunks<'a, u8>;
    fn into_iter(self) -> Self::IntoIter {
        self.data.chunks(self.segment)
    }
}
/// Datagrams one receive could not take whole, or without their packet
/// information: how many.
#[derive(Debug)]
struct Truncated(u64);
impl std::fmt::Display for Truncated {
    fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
        write!(
            f,
            "{} truncated UDP datagrams or packet information",
            self.0
        )
    }
}
impl std::error::Error for Truncated {}
/// How many datagrams the failed receive `error` lost: those it truncated,
/// or one.
fn lost(error: &io::Error) -> u64 {
    error
        .get_ref()
        .and_then(|error| error.downcast_ref::<Truncated>())
        .map_or(1, |truncated| truncated.0)
}
/// What one receive on the public listener took.
struct Received {
    size: usize,
    segment: usize,
    peer: SocketAddr,
    /// The address the client reached.
    local: SocketAddr,
}

/// Receiving and sending datagrams on a socket at once, without waiting:
/// whatever its readiness says, which its owner tracks.
#[cfg(any(target_os = "linux", target_os = "macos"))]
mod batch {
    use super::*;
    use nix::{
        libc,
        sys::socket::{self, ControlMessage, ControlMessageOwned, MsgFlags, SockaddrStorage},
    };
    use std::{
        io::{IoSlice, IoSliceMut},
        net::{Ipv4Addr, SocketAddrV6},
        os::fd::AsRawFd,
    };

    /// The most datagrams one send hands the kernel (its UDP_MAX_SEGMENTS).
    const SEGMENTS: usize = 64;

    /// Lets `socket` receive the datagrams of one flow joined (UDP GRO), where
    /// the kernel can.
    pub(super) fn join(socket: &Socket) {
        #[cfg(target_os = "linux")]
        let _ = socket::setsockopt(socket, socket::sockopt::UdpGroSegment, &true);
        #[cfg(not(target_os = "linux"))]
        let _ = socket;
    }

    /// The datagrams waiting first on `socket`, bound at `bound`; for a
    /// wildcard address, with the address they reached.
    pub(super) fn receive(
        socket: &UdpSocket,
        buffer: &mut [u8],
        bound: SocketAddr,
    ) -> io::Result<Received> {
        let mut ancillary = nix::cmsg_space!(libc::in_pktinfo, libc::in6_pktinfo, libc::c_int);
        let mut slices = [IoSliceMut::new(buffer)];
        let message = socket::recvmsg::<SockaddrStorage>(
            socket.as_raw_fd(),
            &mut slices,
            Some(&mut ancillary),
            MsgFlags::MSG_DONTWAIT,
        )?;
        let peer = message
            .address
            .ok_or_else(|| io::Error::other("UDP source missing"))?;
        let peer = if let Some(v4) = peer.as_sockaddr_in() {
            SocketAddr::from(*v4)
        } else if let Some(v6) = peer.as_sockaddr_in6() {
            SocketAddr::from(*v6)
        } else {
            return Err(io::Error::other("non-IP UDP source"));
        };
        let size = message.bytes;
        // Packet information cut short: what was joined, and how, is
        // unknown; dropped as one datagram (reading it would fail anyway).
        if message.flags.contains(MsgFlags::MSG_CTRUNC) {
            return Err(io::Error::new(io::ErrorKind::InvalidData, Truncated(1)));
        }
        let mut segment = size;
        let mut local = None;
        for item in message.cmsgs()? {
            match item {
                #[cfg(target_os = "linux")]
                ControlMessageOwned::UdpGroSegments(joined) => {
                    segment = usize::try_from(joined).unwrap_or(size)
                }
                ControlMessageOwned::Ipv4PacketInfo(info) => {
                    local = Some(SocketAddr::new(
                        Ipv4Addr::from(info.ipi_addr.s_addr.to_ne_bytes()).into(),
                        bound.port(),
                    ))
                }
                ControlMessageOwned::Ipv6PacketInfo(info) => {
                    let ip = std::net::Ipv6Addr::from(info.ipi6_addr.s6_addr);
                    local = Some(SocketAddr::V6(SocketAddrV6::new(
                        ip,
                        bound.port(),
                        0,
                        if ip.is_unicast_link_local() {
                            info.ipi6_ifindex
                        } else {
                            0
                        },
                    )))
                }
                _ => {}
            }
        }
        let segment = segment.clamp(1, size.max(1));
        if message.flags.contains(MsgFlags::MSG_TRUNC) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                Truncated(size.div_ceil(segment).max(1) as u64),
            ));
        }
        let local = if bound.ip().is_unspecified() {
            local
                .filter(|a| !a.ip().is_unspecified())
                .ok_or_else(|| io::Error::other("UDP destination packet information missing"))?
        } else {
            bound
        };
        Ok(Received {
            size,
            segment,
            peer,
            local,
        })
    }

    /// Sends what it can of `datagrams`: on a connected socket, or to `peer`
    /// from `local` (the address the client reached on a wildcard
    /// listener). Returns the bytes of those sent, at least one, or why
    /// none was.
    pub(super) fn send(
        socket: &UdpSocket,
        datagrams: Datagrams,
        peer: Option<SocketAddr>,
        local: Option<SocketAddr>,
    ) -> io::Result<usize> {
        let segment = datagrams.segment;
        let data = &datagrams.data[..datagrams.data.len().min(segment * SEGMENTS)];
        if data.len() <= segment {
            return send_one(socket, data, None, peer, local);
        }
        match send_one(socket, data, Some(segment), peer, local) {
            Err(error) if error.kind() != io::ErrorKind::WouldBlock => {}
            result => return result,
        }
        // The route cannot take them joined: one by one.
        let mut sent = 0;
        for datagram in data.chunks(segment) {
            match send_one(socket, datagram, None, peer, local) {
                Ok(size) => sent += size,
                Err(error) if sent == 0 => return Err(error),
                Err(_) => break,
            }
        }
        Ok(sent)
    }

    fn send_one(
        socket: &UdpSocket,
        data: &[u8],
        segment: Option<usize>,
        peer: Option<SocketAddr>,
        local: Option<SocketAddr>,
    ) -> io::Result<usize> {
        let peer = peer.map(SockaddrStorage::from);
        let slices = [IoSlice::new(data)];
        let (v4, v6);
        let reached = match local {
            Some(SocketAddr::V4(local)) => {
                v4 = libc::in_pktinfo {
                    ipi_ifindex: 0,
                    ipi_spec_dst: libc::in_addr {
                        s_addr: u32::from_ne_bytes(local.ip().octets()),
                    },
                    ipi_addr: libc::in_addr { s_addr: 0 },
                };
                Some(ControlMessage::Ipv4PacketInfo(&v4))
            }
            Some(SocketAddr::V6(local)) => {
                v6 = libc::in6_pktinfo {
                    ipi6_ifindex: local.scope_id(),
                    ipi6_addr: libc::in6_addr {
                        s6_addr: local.ip().octets(),
                    },
                };
                Some(ControlMessage::Ipv6PacketInfo(&v6))
            }
            None => None,
        };
        #[cfg(target_os = "linux")]
        let size = segment.map(|segment| segment as u16);
        #[cfg(target_os = "linux")]
        let joined = size.as_ref().map(ControlMessage::UdpGsoSegments);
        #[cfg(not(target_os = "linux"))]
        let joined: Option<ControlMessage> = {
            let _ = segment;
            None
        };
        let (one, two);
        let messages: &[ControlMessage] = match (reached, joined) {
            (Some(a), Some(b)) => {
                two = [a, b];
                &two
            }
            (Some(a), None) | (None, Some(a)) => {
                one = [a];
                &one
            }
            (None, None) => &[],
        };
        Ok(socket::sendmsg(
            socket.as_raw_fd(),
            &slices,
            messages,
            MsgFlags::MSG_DONTWAIT,
            peer.as_ref(),
        )?)
    }
}
/// The datagrams go one by one here, on addresses of their own only (a
/// wildcard listener needs packet information this target lacks).
#[cfg(not(any(target_os = "linux", target_os = "macos")))]
mod batch {
    use super::*;

    pub(super) fn join(_: &Socket) {}
    pub(super) fn receive(
        socket: &UdpSocket,
        buffer: &mut [u8],
        bound: SocketAddr,
    ) -> io::Result<Received> {
        let (size, peer) = socket.try_recv_from(buffer)?;
        Ok(Received {
            size,
            segment: size.max(1),
            peer,
            local: bound,
        })
    }
    pub(super) fn send(
        socket: &UdpSocket,
        datagrams: Datagrams,
        peer: Option<SocketAddr>,
        _: Option<SocketAddr>,
    ) -> io::Result<usize> {
        let datagram = datagrams.into_iter().next().unwrap_or_default();
        match peer {
            Some(peer) => socket.try_send_to(datagram, peer),
            None => socket.try_send(datagram),
        }
    }
}
/// Sends `datagrams` on to the engine; what its socket cannot take now is
/// dropped, as a full network would.
fn forward(engine: &UdpSocket, datagrams: Datagrams, stats: &Counters) {
    let mut sent = 0;
    loop {
        match batch::send(engine, datagrams.after(sent), None, None) {
            Ok(size) => sent += size,
            Err(_) => {
                let lost = datagrams.after(sent).count();
                stats.dropped_datagrams.fetch_add(lost, Ordering::Relaxed);
                return;
            }
        }
        if sent >= datagrams.data.len() {
            return;
        }
    }
}
/// Socket buffers of the public UDP listener and of each association's
/// loopback socket, and joined datagrams where the kernel can.
fn datagram_socket(socket: &Socket) {
    let _ = socket.set_recv_buffer_size(UDP_BUFFER);
    let _ = socket.set_send_buffer_size(UDP_BUFFER);
    batch::join(socket);
}
/// A loopback socket that sends to and takes datagrams from the engine at
/// `engine` only.
fn engine_socket(engine: SocketAddr) -> io::Result<UdpSocket> {
    let socket = Socket::new(Domain::for_address(engine), Type::DGRAM, None)?;
    datagram_socket(&socket);
    socket.bind(&SocketAddr::new(engine.ip(), 0).into())?;
    socket.connect(&engine.into())?;
    socket.set_nonblocking(true)?;
    UdpSocket::from_std(socket.into())
}
thread_local! {
    /// Where an association takes the engine's datagrams in, one buffer per
    /// thread: none holds one between them.
    static REPLIES: std::cell::RefCell<Vec<u8>> = std::cell::RefCell::new(vec![0; BUFFER_SIZE]);
}
/// What became of datagrams the engine sent a client.
enum Reply {
    Sent,
    /// The policy refuses the client now: it gets nothing more.
    Refused,
    /// The listener cannot take these yet.
    Waiting(Vec<u8>, usize),
}
/// Batches of the engine's datagrams one association carries at a wake;
/// each takes one unit of the task's budget, so a busy association yields
/// its thread when the budget runs out, as other I/O does.
const DRAIN: usize = 16;

pub(super) async fn udp(
    listener: UdpSocket,
    updates: watch::Receiver<Arc<RuntimeRule>>,
    stop: CancellationToken,
    stats: Arc<Counters>,
    tasks: TaskTracker,
) {
    let bound = listener.local_addr().expect("bound UDP listener");
    let wildcard = bound.ip().is_unspecified();
    let listener = Arc::new(listener);
    let places = Arc::<Places>::default();
    // Associations hold the listener: it closes once they have ended, which
    // a listener reopened at its address waits for. This task waits for its
    // own associations instead of the engine's bounded wait for a released
    // listener's work: that wait stays short only because every await here
    // and in an association races `stop` (the associations' through
    // `ending`), except the 100 ms pause after a failed receive and yields
    // to the scheduler. An await added without that race can hold up every
    // apply that releases this listener.
    let associations = TaskTracker::new();
    let mut peers = HashMap::<(SocketAddr, SocketAddr), Peer>::new();
    let (ended_tx, mut ended_rx) = mpsc::unbounded_channel::<((SocketAddr, SocketAddr), u64)>();
    let mut generation = 0u64;
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let stopped = stop.cancelled();
    tokio::pin!(stopped);
    loop {
        tokio::select! {
            biased;
            _ = &mut stopped => break,
            Some((key, id)) = ended_rx.recv() => {
                if peers.get(&key).is_some_and(|peer| peer.generation == id) {
                    peers.remove(&key);
                }
            }
            received = listener.async_io(Interest::READABLE, || batch::receive(&listener, &mut buffer, bound)) => {
                let Received { size, segment, peer, local } = match received {
                    Ok(received) => received,
                    Err(error) => {
                        if error.kind() != io::ErrorKind::InvalidData {
                            tracing::warn!(%error, "gateway UDP receive failed");
                            sleep(Duration::from_millis(100)).await;
                        }
                        stats.dropped_datagrams.fetch_add(lost(&error), Ordering::Relaxed);
                        continue;
                    }
                };
                // One sender's, judged together.
                let datagrams = Datagrams { data: &buffer[..size], segment };
                let key = (peer, local);
                let rule = updates.borrow().clone();
                let ip = canonical_ip(peer.ip());
                if let Some((reason, detail)) = refusal(&rule, ip) {
                    for _ in 0..datagrams.count() {
                        stats.dropped_datagrams.fetch_add(1, Ordering::Relaxed);
                        stats.blocks.record(&rule.key, rule.kinds[0], ip, reason, || detail.clone());
                    }
                    // Refused now: the engine's replies stop too.
                    if let Some(peer) = peers.remove(&key) {
                        peer.end.cancel();
                    }
                    continue;
                }
                if let Some(peer) = peers.get(&key).filter(|peer| !peer.end.is_cancelled()) {
                    peer.last.store(clock(), Ordering::Relaxed);
                    peer.reach.sent(datagrams, opaque(&rule.spec));
                    forward(&peer.engine, datagrams, &stats);
                    continue;
                }
                peers.remove(&key);
                // Its socket to the engine.
                let limit = FRONT_LIMIT.max(rule.spec.udp_max_sessions as usize);
                let place = match places.take(ip, limit, UDP_PER_SOURCE, 1, "associations") {
                    Ok(place) => place,
                    Err(detail) => {
                        for _ in 0..datagrams.count() {
                            stats.dropped_datagrams.fetch_add(1, Ordering::Relaxed);
                            stats.blocks.record(&rule.key, rule.kinds[0], ip, Reason::UdpSessionLimit, || detail.clone());
                        }
                        continue;
                    }
                };
                let opened = upstream(&rule).map(|(address, gone)| (engine_socket(address), address, gone));
                let Some((Ok(engine), engine_address, gone)) = opened else {
                    // The engine is not listening, or no socket reaches it.
                    stats.dropped_datagrams.fetch_add(datagrams.count(), Ordering::Relaxed);
                    continue;
                };
                forward(&engine, datagrams, &stats);
                let engine = Arc::new(engine);
                generation = generation.wrapping_add(1);
                let id = generation;
                let last = Arc::new(AtomicU64::new(clock()));
                let reach = Arc::<Reach>::default();
                let end = CancellationToken::new();
                peers.insert(key, Peer { generation: id, engine: engine.clone(), last: last.clone(), reach: reach.clone(), end: end.clone() });
                let (listener, ended, stop, stats) = (listener.clone(), ended_tx.clone(), stop.clone(), stats.clone());
                let mut current = updates.clone();
                let expiry = UDP_IDLE.max(Duration::from_secs(rule.spec.idle_timeout_secs));
                let local = wildcard.then_some(local);
                tasks.spawn(associations.track_future(async move {
                    // Its place, until its engine socket closes.
                    let _place = place;
                    let ending = async {
                        tokio::select! {
                            _ = end.cancelled() => {}
                            _ = stop.cancelled() => {}
                            _ = rule.cancel.cancelled() => {}
                            _ = gone.cancelled() => {}
                        }
                    };
                    tokio::pin!(ending);
                    // Until its client shows it receives the engine's
                    // answers, the association lives a short while from its
                    // first datagram, whatever the client sends; then until
                    // it idles. One timer, moved on as it fires.
                    let deadline = sleep(UNCONFIRMED);
                    tokio::pin!(deadline);
                    // The engine's datagrams for the client, as they come.
                    let mut reply = |buffer: &mut Vec<u8>| -> io::Result<Reply> {
                        let received = batch::receive(&engine, buffer, engine_address)?;
                        let datagrams = Datagrams { data: &buffer[..received.size], segment: received.segment };
                        reach.answer(datagrams);
                        last.store(clock(), Ordering::Relaxed);
                        // The policy now: a client it refuses gets nothing
                        // more, and its association ends.
                        if refusal(&current.borrow_and_update(), ip).is_some() {
                            return Ok(Reply::Refused);
                        }
                        let mut sent = 0;
                        loop {
                            match batch::send(&listener, datagrams.after(sent), Some(peer), local) {
                                Ok(size) => sent += size,
                                Err(error) if error.kind() == io::ErrorKind::WouldBlock => {
                                    return Ok(Reply::Waiting(datagrams.data[sent..].to_vec(), datagrams.segment));
                                }
                                Err(_) => {
                                    let lost = datagrams.after(sent).count();
                                    stats.dropped_datagrams.fetch_add(lost, Ordering::Relaxed);
                                    return Ok(Reply::Sent);
                                }
                            }
                            if sent >= datagrams.data.len() {
                                return Ok(Reply::Sent);
                            }
                        }
                    };
                    let mut waiting: Option<(Vec<u8>, usize)> = None;
                    'association: loop {
                        // A full listener does not hold up its end.
                        if let Some((data, segment)) = waiting.take() {
                            let datagrams = Datagrams { data: &data, segment };
                            let mut sent = 0;
                            loop {
                                let result = tokio::select! {
                                    biased;
                                    _ = &mut ending => break 'association,
                                    result = listener.async_io(Interest::WRITABLE, || batch::send(&listener, datagrams.after(sent), Some(peer), local)) => result,
                                };
                                match result {
                                    Ok(size) => sent += size,
                                    Err(_) => {
                                        stats.dropped_datagrams.fetch_add(datagrams.after(sent).count(), Ordering::Relaxed);
                                        break;
                                    }
                                }
                                if sent >= data.len() {
                                    break;
                                }
                            }
                        }
                        tokio::select! {
                            biased;
                            _ = &mut ending => break,
                            () = &mut deadline => {
                                let left = if reach.shown.load(Ordering::Acquire) {
                                    let idle = Duration::from_millis(clock().saturating_sub(last.load(Ordering::Relaxed)));
                                    expiry.checked_sub(idle)
                                } else {
                                    None
                                };
                                let Some(left) = left else {
                                    break;
                                };
                                deadline.as_mut().reset(Instant::now() + left);
                            }
                            ready = engine.readable() => {
                                if ready.is_err() {
                                    break;
                                }
                                for _ in 0..DRAIN {
                                    let replied = engine.try_io(Interest::READABLE, || REPLIES.with_borrow_mut(&mut reply));
                                    match replied {
                                        Ok(Reply::Sent) => {}
                                        Ok(Reply::Waiting(data, segment)) => {
                                            waiting = Some((data, segment));
                                            break;
                                        }
                                        Ok(Reply::Refused) => break 'association,
                                        Err(error) if error.kind() == io::ErrorKind::WouldBlock => break,
                                        Err(error) if error.kind() == io::ErrorKind::InvalidData => {
                                            stats.dropped_datagrams.fetch_add(lost(&error), Ordering::Relaxed);
                                        }
                                        // The engine went away: its port refuses.
                                        Err(_) => break 'association,
                                    }
                                    // Its turn ends with its budget, as at
                                    // other I/O: an engine that never stops
                                    // sending does not hold the thread.
                                    tokio::task::coop::consume_budget().await;
                                }
                            }
                        }
                    }
                    end.cancel();
                    let _ = ended.send((key, id));
                }));
            }
        }
    }
    for peer in peers.values() {
        peer.end.cancel();
    }
    drop(peers);
    associations.close();
    associations.wait().await;
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_source_is_an_ipv4_address_or_an_ipv6_64() {
        let places = Arc::<Places>::default();
        let mut held = vec![];
        let mut take = |ip: &str| {
            places
                .take(ip.parse().unwrap(), 100, 1, 0, "associations")
                .map(|place| held.push(place))
        };
        let full = Err("limit 1 client associations from one address".to_string());
        assert_eq!(take("2001:db8:0:1::1"), Ok(()));
        assert_eq!(take("2001:db8:0:1:ffff:ffff:ffff:ffff"), full);
        assert_eq!(take("2001:db8:0:2::1"), Ok(()));
        assert_eq!(take("192.0.2.1"), Ok(()));
        assert_eq!(take("192.0.2.2"), Ok(()));
        assert_eq!(take("192.0.2.1"), full);
    }

    /// Datagrams sent together go one by one where the kernel will not split
    /// them: it refuses to for a socket without UDP checksums.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn datagrams_go_one_by_one_where_the_kernel_cannot_split_them() {
        use nix::libc;
        use std::os::fd::AsRawFd;
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let on: libc::c_int = 1;
        // SAFETY: sender owns a live descriptor; `on` and its exact size stay
        // valid for the call, which does not keep the pointer.
        let set = unsafe {
            libc::setsockopt(
                sender.as_raw_fd(),
                libc::SOL_SOCKET,
                libc::SO_NO_CHECK,
                (&on as *const libc::c_int).cast(),
                std::mem::size_of::<libc::c_int>() as libc::socklen_t,
            )
        };
        assert_eq!(set, 0);
        let data: Vec<u8> = [vec![1; 1000], vec![2; 1000], vec![3; 10]].concat();
        let datagrams = Datagrams {
            data: &data,
            segment: 1000,
        };
        let to = receiver.local_addr().unwrap();
        assert_eq!(
            batch::send(&sender, datagrams, Some(to), None).unwrap(),
            data.len()
        );
        let mut buffer = [0; 2048];
        for expected in datagrams {
            let n = timeout(Duration::from_secs(1), receiver.recv(&mut buffer))
                .await
                .expect("not sent")
                .unwrap();
            assert_eq!(&buffer[..n], expected);
        }
    }

    /// Packet information a receive has no room for drops its datagram as
    /// one lost, as a truncated one; the next is received as usual.
    #[cfg(target_os = "linux")]
    #[tokio::test]
    async fn packet_information_cut_short_drops_one_datagram() {
        use nix::libc;
        use std::os::fd::AsRawFd;
        let receiver = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let sender = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let to = receiver.local_addr().unwrap();
        let option = |level, name, value: libc::c_int| {
            // SAFETY: receiver owns a live descriptor; `value` and its exact
            // size stay valid for the call, which does not keep the pointer.
            let set = unsafe {
                libc::setsockopt(
                    receiver.as_raw_fd(),
                    level,
                    name,
                    (&value as *const libc::c_int).cast(),
                    std::mem::size_of::<libc::c_int>() as libc::socklen_t,
                )
            };
            assert_eq!(set, 0);
        };
        let mut buffer = [0; 2048];
        // More kinds of it than a receive takes room for, then fewer.
        for (extra, datagram) in [(1, &b"cut"[..]), (0, &b"whole"[..])] {
            option(libc::IPPROTO_IP, libc::IP_PKTINFO, 1);
            option(libc::IPPROTO_IP, libc::IP_RECVTTL, extra);
            option(libc::IPPROTO_IP, libc::IP_RECVTOS, extra);
            option(libc::SOL_SOCKET, libc::SO_TIMESTAMPNS, extra);
            sender.send_to(datagram, to).await.unwrap();
            timeout(Duration::from_secs(1), receiver.readable())
                .await
                .expect("not sent")
                .unwrap();
            let received = batch::receive(&receiver, &mut buffer, to);
            if extra == 1 {
                let error = received.err().expect("received whole");
                assert_eq!(
                    (error.kind(), lost(&error)),
                    (io::ErrorKind::InvalidData, 1)
                );
            } else {
                assert_eq!(&buffer[..received.unwrap().size], datagram);
            }
        }
    }
}
