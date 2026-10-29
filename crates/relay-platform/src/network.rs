//! Business socket construction. Binding failures never fall back to an unbound socket.
use crate::model::{DnsCache, OutboundBind, Rule, canonical_address};
use anyhow::{Context, Result, ensure};
use hickory_resolver::{
    TokioResolver,
    config::{LookupIpStrategy, NameServerConfig, ResolverConfig},
    net::runtime::TokioRuntimeProvider,
};
use socket2::{Domain, Protocol, SockRef, Socket, Type};
use std::{net::SocketAddr, time::Duration};
use tokio::net::{TcpListener, TcpSocket, TcpStream, UdpSocket};

pub(crate) struct TargetResolver(Option<TokioResolver>);
impl TargetResolver {
    pub fn new(policy: Option<&DnsCache>) -> Result<Self> {
        let Some(policy) = policy else {
            return Ok(Self(None));
        };
        let mut builder = if policy.servers.is_empty() {
            TokioResolver::builder_tokio().context("cannot read system DNS configuration")?
        } else {
            let servers = policy
                .servers
                .iter()
                .map(|address| {
                    let mut server = NameServerConfig::udp_and_tcp(address.ip());
                    for connection in &mut server.connections {
                        connection.port = address.port();
                    }
                    server
                })
                .collect();
            TokioResolver::builder_with_config(
                ResolverConfig::from_name_servers(servers),
                TokioRuntimeProvider::default(),
            )
        };
        let options = builder.options_mut();
        options.cache_size = u64::from(policy.capacity);
        options.positive_min_ttl = Some(Duration::ZERO);
        options.negative_min_ttl = Some(Duration::ZERO);
        options.positive_max_ttl = Some(Duration::from_secs(u64::from(policy.max_ttl_secs)));
        options.negative_max_ttl =
            Some(Duration::from_secs(u64::from(policy.negative_max_ttl_secs)));
        options.ip_strategy = LookupIpStrategy::Ipv4AndIpv6;
        Ok(Self(Some(
            builder.build().context("cannot build DNS resolver")?,
        )))
    }

    pub async fn resolve(&self, target: &str) -> Result<Vec<SocketAddr>> {
        let addresses = if let Ok(address) = target.parse::<SocketAddr>() {
            vec![address]
        } else if let Some(resolver) = &self.0 {
            let (host, port) = target.rsplit_once(':').context("invalid target")?;
            let port = port.parse()?;
            resolver
                .lookup_ip(host)
                .await?
                .iter()
                .take(64)
                .map(|ip| SocketAddr::new(ip, port))
                .collect()
        } else {
            tokio::net::lookup_host(target).await?.take(64).collect()
        };
        let mut result = Vec::new();
        for address in addresses {
            let address = canonical_address(address);
            if !address.ip().is_unspecified()
                && !address.ip().is_multicast()
                && !result.contains(&address)
            {
                result.push(address);
            }
        }
        ensure!(!result.is_empty(), "target has no usable unicast address");
        Ok(result)
    }
}

fn bind_interface(socket: &Socket, bind: &OutboundBind, ipv4: bool) -> Result<()> {
    let Some(name) = &bind.interface else {
        return Ok(());
    };
    let interfaces = if_addrs::get_if_addrs().context("cannot enumerate outbound interfaces")?;
    let matching: Vec<_> = interfaces.iter().filter(|i| &i.name == name).collect();
    ensure!(
        !matching.is_empty(),
        "outbound interface does not exist: {name}"
    );
    ensure!(
        bind.ip
            .is_none_or(|ip| matching.iter().any(|i| i.ip() == ip)),
        "outbound IP is not on interface {name}"
    );
    #[cfg(any(target_os = "linux", target_os = "android"))]
    {
        let _ = ipv4;
        socket
            .bind_device(Some(name.as_bytes()))
            .context("cannot bind outbound interface")?;
    }
    #[cfg(target_os = "macos")]
    {
        let index = matching
            .iter()
            .find_map(|i| i.index.and_then(std::num::NonZeroU32::new))
            .context("outbound interface has no index")?;
        if ipv4 {
            socket.bind_device_by_index_v4(Some(index))?;
        } else {
            socket.bind_device_by_index_v6(Some(index))?;
        }
    }
    #[cfg(not(any(target_os = "linux", target_os = "android", target_os = "macos")))]
    {
        let _ = (socket, ipv4);
        anyhow::bail!("interface binding is unsupported on this operating system");
    }
    Ok(())
}

fn source_address(bind: Option<&OutboundBind>, ipv4: bool) -> Result<SocketAddr> {
    if let Some(ip) = bind.and_then(|b| b.ip) {
        ensure!(
            ip.is_ipv4() == ipv4,
            "outbound IP and target use different address families"
        );
        Ok(SocketAddr::new(ip, 0))
    } else if ipv4 {
        Ok("0.0.0.0:0".parse().unwrap())
    } else {
        Ok("[::]:0".parse().unwrap())
    }
}

fn tcp_socket(
    bind: Option<&OutboundBind>,
    ipv4: bool,
    mode: crate::mptcp::Mode,
) -> Result<TcpSocket> {
    let raw = crate::mptcp::stream_socket(if ipv4 { Domain::IPV4 } else { Domain::IPV6 }, mode)?;
    raw.set_nonblocking(true)?;
    let socket = TcpSocket::from_std_stream(raw.into());
    let reference = SockRef::from(&socket);
    if !ipv4 {
        reference.set_only_v6(true)?;
    }
    if let Some(bind) = bind {
        bind_interface(&reference, bind, ipv4)?;
    }
    // Choose the source port at connect time, per destination. Binding port 0
    // otherwise reserves a port that is unique across all destinations, so one
    // node could hold only one ephemeral range of outbound connections in total
    // and any port in TIME_WAIT would be unusable.
    #[cfg(target_os = "linux")]
    nix::sys::socket::setsockopt(
        &socket,
        nix::sys::socket::sockopt::IpBindAddressNoPort,
        &true,
    )?;
    socket.bind(source_address(bind, ipv4)?)?;
    Ok(socket)
}

pub(crate) async fn connect_tcp(
    bind: Option<&OutboundBind>,
    target: SocketAddr,
    mode: crate::mptcp::Mode,
) -> Result<TcpStream> {
    Ok(tcp_socket(bind, target.is_ipv4(), mode)?
        .connect(target)
        .await?)
}

pub(crate) fn outbound_udp(bind: Option<&OutboundBind>, ipv4: bool) -> Result<UdpSocket> {
    let socket = Socket::new(
        if ipv4 { Domain::IPV4 } else { Domain::IPV6 },
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if !ipv4 {
        socket.set_only_v6(true)?;
    }
    configure_udp(&socket, ipv4)?;
    if let Some(bind) = bind {
        bind_interface(&socket, bind, ipv4)?;
    }
    socket.bind(&source_address(bind, ipv4)?.into())?;
    socket.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(socket.into())?)
}

fn configure_udp(socket: &Socket, ipv4: bool) -> Result<()> {
    // Keep bursts bounded without inheriting very small VPS image defaults.
    // Linux accounts this capacity as datagrams arrive, not as an idle allocation.
    const RECEIVE_CAPACITY: usize = 256 * 1024;
    if socket.recv_buffer_size()? < RECEIVE_CAPACITY {
        socket.set_recv_buffer_size(RECEIVE_CAPACITY)?;
    }
    #[cfg(target_os = "linux")]
    {
        use nix::libc;
        use std::os::fd::AsRawFd;
        // Transparent UDP cannot shrink or replay an application's datagram.
        // Permit IPv4 routers to fragment the first oversized packet, before
        // an ICMP message has populated the kernel's path-MTU cache. Apply this
        // to replies from listeners as well as sockets connecting to targets.
        let (level, option) = if ipv4 {
            (libc::IPPROTO_IP, libc::IP_MTU_DISCOVER)
        } else {
            (libc::IPPROTO_IPV6, libc::IPV6_MTU_DISCOVER)
        };
        let value: libc::c_int = libc::IP_PMTUDISC_DONT;
        // SAFETY: socket owns a live descriptor; value and its exact size stay
        // valid for the duration of setsockopt, which does not retain the pointer.
        let result = unsafe {
            libc::setsockopt(
                socket.as_raw_fd(),
                level,
                option,
                (&value as *const libc::c_int).cast(),
                std::mem::size_of_val(&value) as libc::socklen_t,
            )
        };
        if result != 0 {
            return Err(std::io::Error::last_os_error()).context("configure UDP fragmentation");
        }
    }
    #[cfg(not(target_os = "linux"))]
    let _ = ipv4;
    Ok(())
}

pub(crate) fn preflight(rule: &Rule) -> Result<()> {
    for mode in [rule.mptcp_inbound(), rule.mptcp_outbound()] {
        if mode != crate::mptcp::Mode::Off {
            let domain = Domain::for_address(rule.listen);
            crate::mptcp::stream_socket(domain, mode)?;
        }
    }
    if let Some(bind) = &rule.outbound_bind {
        preflight_bind(
            bind,
            &rule
                .targets
                .iter()
                .map(|t| t.address.as_str())
                .collect::<Vec<_>>(),
            rule.protocol.tcp(),
            rule.protocol.udp(),
        )?;
    }
    if let Some(spec) = &rule.outbound_multipath {
        for (path, target) in spec.paths.iter().zip(&rule.targets) {
            if let Some(bind) = &path.outbound_bind {
                preflight_bind(bind, &[&target.address], true, false)?;
            }
        }
    }
    Ok(())
}
fn preflight_bind(bind: &OutboundBind, addresses: &[&str], tcp: bool, udp: bool) -> Result<()> {
    let families = if let Some(ip) = bind.ip {
        vec![ip.is_ipv4()]
    } else if addresses
        .iter()
        .any(|address| address.parse::<SocketAddr>().is_err())
    {
        vec![true, false]
    } else {
        let mut families: Vec<_> = addresses
            .iter()
            .map(|address| canonical_address(address.parse().unwrap()).is_ipv4())
            .collect();
        families.sort();
        families.dedup();
        families
    };
    for ipv4 in families {
        if tcp {
            tcp_socket(Some(bind), ipv4, crate::mptcp::Mode::Off)?;
        }
        if udp {
            outbound_udp(Some(bind), ipv4)?;
        }
    }
    Ok(())
}

pub(crate) fn tcp_listener(address: SocketAddr, mode: crate::mptcp::Mode) -> Result<TcpListener> {
    let socket = crate::mptcp::stream_socket(Domain::for_address(address), mode)?;
    socket.set_reuse_address(true)?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    socket.bind(&address.into())?;
    socket.listen(1024)?;
    socket.set_nonblocking(true)?;
    Ok(TcpListener::from_std(socket.into())?)
}

pub(crate) fn udp_listener(address: SocketAddr) -> Result<UdpSocket> {
    let socket = Socket::new(
        Domain::for_address(address),
        Type::DGRAM,
        Some(Protocol::UDP),
    )?;
    if address.is_ipv6() {
        socket.set_only_v6(true)?;
    }
    configure_udp(&socket, address.is_ipv4())?;
    crate::datagram::configure(&socket, address)?;
    socket.bind(&address.into())?;
    socket.set_nonblocking(true)?;
    Ok(UdpSocket::from_std(socket.into())?)
}

#[cfg(all(test, target_os = "linux"))]
mod tests {
    #[tokio::test]
    async fn outbound_sockets_take_their_port_at_connect_time() {
        // A port reserved at bind time would be unique across destinations,
        // capping a node at one ephemeral range of outbound connections.
        let socket = super::tcp_socket(None, true, crate::mptcp::Mode::Off).unwrap();
        assert_eq!(socket.local_addr().unwrap().port(), 0);
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let stream = socket
            .connect(listener.local_addr().unwrap())
            .await
            .unwrap();
        assert_ne!(stream.local_addr().unwrap().port(), 0);
    }
}
