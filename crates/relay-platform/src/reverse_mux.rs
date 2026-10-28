//! Single-connection multiplexed reverse TCP tunnel.
//!
//! The control connection carries length-prefixed frames for many public
//! connections. This is separate from the legacy line protocol in `reverse`;
//! the legacy commands keep their one-public-connection-per-control behavior.
use anyhow::{Context, Result, bail, ensure};
use ipnet::IpNet;
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::Path,
    sync::{
        Arc,
        atomic::AtomicU64,
        atomic::{AtomicBool, AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Mutex, OwnedSemaphorePermit, Semaphore, mpsc, oneshot},
};
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    rustls::{
        ClientConfig, RootCertStore, ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
    },
};
use tokio_util::sync::CancellationToken;

const MAX_LINE: usize = 512;
const AUTH_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(10);
const CONNECT_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);
const TLS_HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);
const MAX_PENDING_HANDSHAKES: usize = 64;
const MAX_FRAME: usize = 64 * 1024;
const READY: &str = "READY";
const DENY: &str = "DENY";
const OPEN: u8 = 1;
const OK: u8 = 2;
const FAIL: u8 = 3;
const DATA: u8 = 4;
const FIN: u8 = 5;
const RESET: u8 = 6;
const WINDOW: u8 = 7;
const DATAGRAM: u8 = 8;
const UDP_FEATURE: &[u8] = b"udp-v1";
static UDP_IDLE_SECS: AtomicU64 = AtomicU64::new(60);
// OPEN/OK opt-in preserves interoperability with the original six-frame peers.
const FLOW_CONTROL_V1: &[u8] = b"flow-control-v1";
const OPEN_TIMEOUT: Duration = Duration::from_secs(5);
const CONTROL_WRITE_TIMEOUT: Duration = Duration::from_secs(5);
const LOCAL_WRITE_TIMEOUT: Duration = Duration::from_secs(30);
const STREAM_QUEUE_CAPACITY: usize = 32;

trait PublicIo: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> PublicIo for T {}
type PublicStream = Box<dyn PublicIo>;
type ControlRead = Box<dyn AsyncRead + Send + Unpin>;
type ControlWrite = Box<dyn AsyncWrite + Send + Unpin>;
struct ControlWriter {
    stream: Mutex<ControlWrite>,
    cancel: CancellationToken,
}
type Writer = Arc<ControlWriter>;
#[derive(Clone)]
struct StreamInbox {
    sender: mpsc::Sender<(u8, Vec<u8>)>,
    cancel: CancellationToken,
    flow: Arc<StreamFlow>,
}
struct StreamFlow {
    enabled: AtomicBool,
    credits: Semaphore,
    max_bytes: u64,
    bytes: AtomicU64,
}
impl StreamFlow {
    fn new(enabled: bool) -> Arc<Self> {
        Self::with_limit(enabled, MAX_STREAM_BYTES.load(Ordering::Relaxed))
    }
    fn with_limit(enabled: bool, max_bytes: u64) -> Arc<Self> {
        Arc::new(Self {
            enabled: AtomicBool::new(enabled),
            credits: Semaphore::new(STREAM_QUEUE_CAPACITY),
            max_bytes,
            bytes: AtomicU64::new(0),
        })
    }
    fn consume(&self, size: usize) -> bool {
        if self.max_bytes == 0 {
            return true;
        }
        let size = size as u64;
        let mut current = self.bytes.load(Ordering::Relaxed);
        loop {
            let next = match current.checked_add(size) {
                Some(next) if next <= self.max_bytes => next,
                _ => return false,
            };
            match self.bytes.compare_exchange_weak(
                current,
                next,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }
}
type Sessions = Arc<Mutex<HashMap<u32, StreamInbox>>>;
type Responses = Arc<Mutex<HashMap<u32, oneshot::Sender<bool>>>>;
type UdpSessions = Arc<Mutex<HashMap<u32, (Arc<UdpSocket>, CancellationToken, bool, bool)>>>;

#[derive(Clone, Debug)]
enum UdpMode {
    Fixed(String),
    Socks5 { allow_private: bool },
}

struct ActiveControl;
impl ActiveControl {
    fn try_new() -> Option<Self> {
        let limit = MAX_CONTROLS.load(Ordering::Relaxed);
        let mut current = ACTIVE_CONTROLS.load(Ordering::Relaxed);
        loop {
            if current >= limit {
                return None;
            }
            match ACTIVE_CONTROLS.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(observed) => current = observed,
            }
        }
        TOTAL_CONTROLS.fetch_add(1, Ordering::Relaxed);
        Some(Self)
    }
}
impl Drop for ActiveControl {
    fn drop(&mut self) {
        ACTIVE_CONTROLS.fetch_sub(1, Ordering::Relaxed);
    }
}
struct ActiveStream {
    local: Arc<AtomicU32>,
}
impl ActiveStream {
    fn reserve(counter: &AtomicU32, limit: u32) -> bool {
        let mut current = counter.load(Ordering::Relaxed);
        loop {
            if current >= limit {
                return false;
            }
            match counter.compare_exchange_weak(
                current,
                current + 1,
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => return true,
                Err(observed) => current = observed,
            }
        }
    }
    fn try_new(local: Arc<AtomicU32>, max_streams: usize) -> Option<Self> {
        let global_limit = MAX_TOTAL_STREAMS.load(Ordering::Relaxed);
        if !Self::reserve(&ACTIVE_STREAMS, global_limit) {
            return None;
        }
        if !Self::reserve(&local, max_streams as u32) {
            ACTIVE_STREAMS.fetch_sub(1, Ordering::Relaxed);
            return None;
        }
        TOTAL_STREAMS.fetch_add(1, Ordering::Relaxed);
        Some(Self { local })
    }
}
impl Drop for ActiveStream {
    fn drop(&mut self) {
        self.local.fetch_sub(1, Ordering::Relaxed);
        ACTIVE_STREAMS.fetch_sub(1, Ordering::Relaxed);
    }
}
type Frame = (u8, u32, Vec<u8>);

static ACTIVE_CONTROLS: AtomicU32 = AtomicU32::new(0);
static MAX_CONTROLS: AtomicU32 = AtomicU32::new(1024);
static MAX_TOTAL_STREAMS: AtomicU32 = AtomicU32::new(4096);
static MAX_STREAM_BYTES: AtomicU64 = AtomicU64::new(0);
static TOTAL_CONTROLS: AtomicU64 = AtomicU64::new(0);
static ACTIVE_STREAMS: AtomicU32 = AtomicU32::new(0);
static TOTAL_STREAMS: AtomicU64 = AtomicU64::new(0);
static PUBLIC_TO_TARGET_BYTES: AtomicU64 = AtomicU64::new(0);
static CONTROL_LIMIT_REJECTIONS: AtomicU64 = AtomicU64::new(0);
static STREAM_LIMIT_REJECTIONS: AtomicU64 = AtomicU64::new(0);
static STREAM_BYTE_LIMIT_RESETS: AtomicU64 = AtomicU64::new(0);
static UDP_DROPPED: AtomicU64 = AtomicU64::new(0);
static TARGET_TO_PUBLIC_BYTES: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug)]
pub struct Stats {
    pub active_controls: u32,
    pub total_controls: u64,
    pub active_streams: u32,
    pub total_streams: u64,
    pub public_to_target_bytes: u64,
    pub target_to_public_bytes: u64,
    pub control_limit_rejections: u64,
    pub stream_limit_rejections: u64,
    pub stream_byte_limit_resets: u64,
    pub udp_dropped: u64,
}

pub fn set_max_controls(max_controls: u32) {
    MAX_CONTROLS.store(max_controls.clamp(1, 65_535), Ordering::Relaxed);
}

pub fn max_controls() -> u32 {
    MAX_CONTROLS.load(Ordering::Relaxed)
}

pub fn set_max_total_streams(max_total_streams: u32) {
    MAX_TOTAL_STREAMS.store(max_total_streams.clamp(1, 1_000_000), Ordering::Relaxed);
}

pub fn max_total_streams() -> u32 {
    MAX_TOTAL_STREAMS.load(Ordering::Relaxed)
}

pub fn set_max_stream_bytes(max_stream_bytes: u64) {
    MAX_STREAM_BYTES.store(max_stream_bytes, Ordering::Relaxed);
}

pub fn max_stream_bytes() -> u64 {
    MAX_STREAM_BYTES.load(Ordering::Relaxed)
}

pub fn set_udp_idle_secs(seconds: u64) {
    UDP_IDLE_SECS.store(seconds.clamp(1, 86_400), Ordering::Relaxed);
}

pub fn udp_idle_secs() -> u64 {
    UDP_IDLE_SECS.load(Ordering::Relaxed)
}

pub fn stats() -> Stats {
    Stats {
        active_controls: ACTIVE_CONTROLS.load(Ordering::Relaxed),
        total_controls: TOTAL_CONTROLS.load(Ordering::Relaxed),
        active_streams: ACTIVE_STREAMS.load(Ordering::Relaxed),
        total_streams: TOTAL_STREAMS.load(Ordering::Relaxed),
        public_to_target_bytes: PUBLIC_TO_TARGET_BYTES.load(Ordering::Relaxed),
        target_to_public_bytes: TARGET_TO_PUBLIC_BYTES.load(Ordering::Relaxed),
        control_limit_rejections: CONTROL_LIMIT_REJECTIONS.load(Ordering::Relaxed),
        stream_limit_rejections: STREAM_LIMIT_REJECTIONS.load(Ordering::Relaxed),
        stream_byte_limit_resets: STREAM_BYTE_LIMIT_RESETS.load(Ordering::Relaxed),
        udp_dropped: UDP_DROPPED.load(Ordering::Relaxed),
    }
}

pub async fn serve_mux(control: TcpListener, public: TcpListener, token: String) -> Result<()> {
    serve_mux_with_options(control, public, token, 256, 300, Vec::new()).await
}

pub async fn serve_mux_with_limit(
    control: TcpListener,
    public: TcpListener,
    token: String,
    max_streams: usize,
) -> Result<()> {
    serve_mux_with_options(control, public, token, max_streams, 300, Vec::new()).await
}

pub async fn serve_mux_with_options(
    control: TcpListener,
    public: TcpListener,
    token: String,
    max_streams: usize,
    idle_timeout_secs: u64,
    allow_public: Vec<IpNet>,
) -> Result<()> {
    serve_mux_plain_public(
        control,
        public,
        token,
        None,
        None,
        max_streams,
        idle_timeout_secs,
        allow_public,
    )
    .await
}

pub async fn serve_mux_public_tls(
    control: TcpListener,
    public: TcpListener,
    token: String,
    public_acceptor: TlsAcceptor,
    max_streams: usize,
    idle_timeout_secs: u64,
    allow_public: Vec<IpNet>,
) -> Result<()> {
    serve_mux_plain_public(
        control,
        public,
        token,
        Some(public_acceptor),
        None,
        max_streams,
        idle_timeout_secs,
        allow_public,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn serve_mux_plain_udp(
    control: TcpListener,
    public: TcpListener,
    token: String,
    udp: Arc<UdpSocket>,
    max_streams: usize,
    idle_timeout_secs: u64,
    allow_public: Vec<IpNet>,
) -> Result<()> {
    serve_mux_plain_public(
        control,
        public,
        token,
        None,
        Some(udp),
        max_streams,
        idle_timeout_secs,
        allow_public,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn serve_mux_public_tls_udp(
    control: TcpListener,
    public: TcpListener,
    token: String,
    public_acceptor: TlsAcceptor,
    udp: Arc<UdpSocket>,
    max_streams: usize,
    idle_timeout_secs: u64,
    allow_public: Vec<IpNet>,
) -> Result<()> {
    serve_mux_plain_public(
        control,
        public,
        token,
        Some(public_acceptor),
        Some(udp),
        max_streams,
        idle_timeout_secs,
        allow_public,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
async fn serve_mux_plain_public(
    control: TcpListener,
    public: TcpListener,
    token: String,
    public_acceptor: Option<TlsAcceptor>,
    udp: Option<Arc<UdpSocket>>,
    max_streams: usize,
    idle_timeout_secs: u64,
    allow_public: Vec<IpNet>,
) -> Result<()> {
    ensure!(
        !token.is_empty() && token.len() <= 256,
        "reverse token must be 1..256 bytes"
    );
    ensure!(
        (1..=1024).contains(&max_streams),
        "reverse mux max streams must be 1..=1024"
    );
    ensure!(
        (1..=86_400).contains(&idle_timeout_secs),
        "reverse mux idle timeout must be 1..=86400 seconds"
    );
    let public = Arc::new(public);
    let auth_slots = Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES));
    loop {
        let (control_stream, peer) = control.accept().await?;
        control_stream.set_nodelay(true).ok();
        let permit = match auth_slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::warn!(%peer, "reverse mux plain authentication capacity is full");
                continue;
            }
        };
        let public = public.clone();
        let public_acceptor = public_acceptor.clone();
        let udp = udp.clone();
        let allow_public = allow_public.clone();
        let token = token.clone();
        tokio::spawn(async move {
            authenticate_control_and_spawn(
                control_stream,
                permit,
                "plain",
                peer,
                token,
                public,
                public_acceptor,
                udp,
                allow_public,
                max_streams,
                idle_timeout_secs,
            )
            .await;
        });
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_authorized_control<S>(
    control: S,
    active: ActiveControl,
    public: Arc<TcpListener>,
    public_acceptor: Option<TlsAcceptor>,
    udp: Option<Arc<UdpSocket>>,
    token: String,
    max_streams: usize,
    idle_timeout_secs: u64,
    allow_public: Vec<IpNet>,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let _ = token;
    let (reader, writer) = tokio::io::split(control);
    let _active = active;
    serve_control(
        Box::new(reader),
        Box::new(writer),
        public,
        public_acceptor,
        udp,
        max_streams,
        idle_timeout_secs,
        allow_public,
    )
    .await
}

struct UdpPeer {
    id: u32,
    _active: ActiveStream,
    last: std::time::Instant,
    bytes: u64,
}

#[allow(clippy::too_many_arguments)]
async fn serve_udp(
    socket: Arc<UdpSocket>,
    writer: Writer,
    active_streams: Arc<AtomicU32>,
    max_streams: usize,
    allow_public: Vec<IpNet>,
    cancel: CancellationToken,
    next_id: Arc<AtomicU32>,
    mut down: mpsc::Receiver<(u32, Vec<u8>)>,
) {
    let mut peers: HashMap<SocketAddr, UdpPeer> = HashMap::new();
    let mut addresses: HashMap<u32, SocketAddr> = HashMap::new();
    let mut buffer = vec![0u8; 65_535];
    let idle = Duration::from_secs(UDP_IDLE_SECS.load(Ordering::Relaxed));
    let mut sweep = tokio::time::interval(Duration::from_secs(1));
    loop {
        tokio::select! {
            received = socket.recv_from(&mut buffer) => {
                let (size, peer) = match received {
                    Ok(value) => value,
                    Err(error) => {
                        tracing::warn!(%error, "reverse mux UDP receive failed");
                        cancel.cancel();
                        break;
                    }
                };
                if size == 0 || (!allow_public.is_empty() && !allow_public.iter().any(|network| network.contains(&peer.ip()))) {
                    continue;
                }
                let id = if let Some(existing) = peers.get_mut(&peer) {
                    existing.last = std::time::Instant::now();
                    existing.id
                } else {
                    let Some(active) = ActiveStream::try_new(active_streams.clone(), max_streams) else {
                        STREAM_LIMIT_REJECTIONS.fetch_add(1, Ordering::Relaxed);
                        continue;
                    };
                    let id = next_id.fetch_add(1, Ordering::Relaxed);
                    if write_frame(&writer, OPEN, id, UDP_FEATURE).await.is_err() {
                        cancel.cancel();
                        break;
                    }
                    peers.insert(peer, UdpPeer {
                        id,
                        _active: active,
                        last: std::time::Instant::now(),
                        bytes: 0,
                    });
                    addresses.insert(id, peer);
                    id
                };
                let limit = MAX_STREAM_BYTES.load(Ordering::Relaxed);
                let exceeds = limit != 0
                    && peers
                        .get(&peer)
                        .is_some_and(|entry| entry.bytes.saturating_add(size as u64) > limit);
                if exceeds {
                    if let Some(entry) = peers.remove(&peer) {
                        addresses.remove(&entry.id);
                        STREAM_BYTE_LIMIT_RESETS.fetch_add(1, Ordering::Relaxed);
                        let _ = write_frame(&writer, RESET, entry.id, &[]).await;
                    }
                    continue;
                }
                if let Some(entry) = peers.get_mut(&peer) {
                    entry.bytes = entry.bytes.saturating_add(size as u64);
                }
                if write_frame(&writer, DATAGRAM, id, &buffer[..size]).await.is_err() {
                    cancel.cancel();
                    break;
                }
                PUBLIC_TO_TARGET_BYTES.fetch_add(size as u64, Ordering::Relaxed);
            }
            message = down.recv() => {
                let Some((id, payload)) = message else { break };
                let Some(peer) = addresses.get(&id).copied() else { continue };
                let limit = MAX_STREAM_BYTES.load(Ordering::Relaxed);
                let exceeds = limit != 0
                    && peers
                        .get(&peer)
                        .is_some_and(|entry| entry.bytes.saturating_add(payload.len() as u64) > limit);
                if exceeds {
                    if let Some(entry) = peers.remove(&peer) {
                        addresses.remove(&entry.id);
                        STREAM_BYTE_LIMIT_RESETS.fetch_add(1, Ordering::Relaxed);
                        let _ = write_frame(&writer, RESET, entry.id, &[]).await;
                    }
                    continue;
                }
                match socket.send_to(&payload, peer).await {
                    Ok(size) => {
                        TARGET_TO_PUBLIC_BYTES.fetch_add(size as u64, Ordering::Relaxed);
                        if let Some(entry) = peers.get_mut(&peer) {
                            entry.last = std::time::Instant::now();
                            entry.bytes = entry.bytes.saturating_add(size as u64);
                        }
                    }
                    Err(error) => tracing::debug!(%error, "reverse mux UDP send failed"),
                }
            }
            _ = sweep.tick() => {
                let now = std::time::Instant::now();
                let expired: Vec<SocketAddr> = peers.iter()
                    .filter(|(_, entry)| now.duration_since(entry.last) >= idle)
                    .map(|(peer, _)| *peer)
                    .collect();
                for peer in expired {
                    if let Some(entry) = peers.remove(&peer) {
                        addresses.remove(&entry.id);
                        let _ = write_frame(&writer, FIN, entry.id, &[]).await;
                    }
                }
            }
            _ = cancel.cancelled() => break,
        }
    }
}

#[allow(clippy::too_many_arguments)]
async fn serve_control(
    reader: ControlRead,
    writer: ControlWrite,
    public: Arc<TcpListener>,
    public_acceptor: Option<TlsAcceptor>,
    udp: Option<Arc<UdpSocket>>,
    max_streams: usize,
    idle_timeout_secs: u64,
    allow_public: Vec<IpNet>,
) -> Result<()> {
    let cancel = CancellationToken::new();
    let _cancel_on_exit = cancel.clone().drop_guard();
    let writer = Arc::new(ControlWriter {
        stream: Mutex::new(writer),
        cancel: cancel.clone(),
    });
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    let responses: Arc<Mutex<HashMap<u32, oneshot::Sender<bool>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let (udp_down_tx, udp_down_rx) = if udp.is_some() {
        let (tx, rx) = mpsc::channel(1024);
        (Some(tx), Some(rx))
    } else {
        (None, None)
    };
    let read_task = tokio::spawn(read_frames(
        reader,
        sessions.clone(),
        responses.clone(),
        udp_down_tx,
        cancel.clone(),
    ));
    let active_streams = Arc::new(AtomicU32::new(0));
    let next_id = Arc::new(AtomicU32::new(1));
    if let (Some(socket), Some(down)) = (udp, udp_down_rx) {
        tokio::spawn(serve_udp(
            socket,
            writer.clone(),
            active_streams.clone(),
            max_streams,
            allow_public.clone(),
            cancel.clone(),
            next_id.clone(),
            down,
        ));
    }
    let public_slots = Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES));
    let result: Result<()> = loop {
        let (mut exposed, peer) = tokio::select! {
            accepted = public.accept() => match accepted { Ok(pair) => pair, Err(error) => break Err(error.into()) },
            _ = cancel.cancelled() => break Ok(()),
        };
        if !allow_public.is_empty()
            && !allow_public
                .iter()
                .any(|network| network.contains(&peer.ip()))
        {
            tracing::warn!(%peer, "reverse mux public connection denied by CIDR allowlist");
            let _ = exposed.shutdown().await;
            continue;
        }
        let writer = writer.clone();
        let sessions = sessions.clone();
        let responses = responses.clone();
        let active_streams = active_streams.clone();
        let next_id = next_id.clone();
        let cancel = cancel.clone();
        if let Some(acceptor) = &public_acceptor {
            let permit = match public_slots.clone().try_acquire_owned() {
                Ok(permit) => permit,
                Err(_) => {
                    tracing::warn!(%peer, "reverse mux public TLS handshake capacity is full");
                    let _ = exposed.shutdown().await;
                    continue;
                }
            };
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let exposed = tokio::select! {
                    result = tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(exposed)) => match result {
                        Ok(Ok(stream)) => stream,
                        Ok(Err(error)) => {
                            tracing::warn!(%peer, %error, "reverse mux public TLS handshake failed");
                            return;
                        }
                        Err(_) => {
                            tracing::warn!(%peer, "reverse mux public TLS handshake timed out");
                            return;
                        }
                    },
                    _ = cancel.cancelled() => return,
                };
                drop(permit);
                open_public_stream(
                    Box::new(exposed),
                    peer,
                    writer,
                    sessions,
                    responses,
                    active_streams,
                    next_id,
                    max_streams,
                    idle_timeout_secs,
                    cancel,
                )
                .await;
            });
        } else {
            tokio::spawn(open_public_stream(
                Box::new(exposed),
                peer,
                writer,
                sessions,
                responses,
                active_streams,
                next_id,
                max_streams,
                idle_timeout_secs,
                cancel,
            ));
        }
    };
    cancel.cancel();
    let _ = read_task.await;
    result
}

#[allow(clippy::too_many_arguments)]
async fn open_public_stream(
    mut exposed: PublicStream,
    peer: SocketAddr,
    writer: Writer,
    sessions: Sessions,
    responses: Responses,
    active_streams: Arc<AtomicU32>,
    next_id: Arc<AtomicU32>,
    max_streams: usize,
    idle_timeout_secs: u64,
    cancel: CancellationToken,
) {
    let Some(active) = ActiveStream::try_new(active_streams.clone(), max_streams) else {
        STREAM_LIMIT_REJECTIONS.fetch_add(1, Ordering::Relaxed);
        let _ = exposed.shutdown().await;
        return;
    };
    let id = next_id.fetch_add(1, Ordering::Relaxed);
    let stream_cancel = cancel.child_token();
    let flow = StreamFlow::new(false);
    let (data_tx, data_rx) = mpsc::channel(STREAM_QUEUE_CAPACITY);
    let (response_tx, response_rx) = oneshot::channel();
    sessions.lock().await.insert(
        id,
        StreamInbox {
            sender: data_tx,
            cancel: stream_cancel.clone(),
            flow: flow.clone(),
        },
    );
    responses.lock().await.insert(id, response_tx);
    if write_frame(&writer, OPEN, id, FLOW_CONTROL_V1)
        .await
        .is_err()
    {
        sessions.lock().await.remove(&id);
        responses.lock().await.remove(&id);
        cancel.cancel();
        return;
    }
    let opened = tokio::select! {
        response = tokio::time::timeout(OPEN_TIMEOUT, response_rx) =>
            response.ok().and_then(Result::ok).unwrap_or(false),
        _ = stream_cancel.cancelled() => false,
    };
    if !opened {
        sessions.lock().await.remove(&id);
        responses.lock().await.remove(&id);
        stream_cancel.cancel();
        let _ = write_frame(&writer, RESET, id, &[]).await;
        tracing::warn!(%peer, "reverse mux client did not open the target");
        return;
    }
    tokio::spawn(async move {
        let _active = active;
        let result = bridge_io(
            id,
            exposed,
            data_rx,
            &writer,
            &stream_cancel,
            &flow,
            Some(Duration::from_secs(idle_timeout_secs)),
            true,
        )
        .await;
        sessions.lock().await.remove(&id);
        stream_cancel.cancel();
        if let Err(error) = result {
            let _ = write_frame(&writer, RESET, id, &[]).await;
            tracing::debug!(%error, "reverse mux public bridge ended");
        }
    });
}

// Each stream has independent reader/writer tasks within this future. A blocked
// socket write cannot stop its opposite direction, its deadline, or cancellation.
#[allow(clippy::too_many_arguments)]
async fn bridge_io<S>(
    id: u32,
    stream: S,
    mut frames: mpsc::Receiver<(u8, Vec<u8>)>,
    writer: &Writer,
    cancel: &CancellationToken,
    flow: &StreamFlow,
    idle_timeout: Option<Duration>,
    server: bool,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let (mut reader, mut output) = tokio::io::split(stream);
    let last_activity = Arc::new(std::sync::Mutex::new(tokio::time::Instant::now()));
    let reading = async {
        let result = async {
            let mut buffer = vec![0u8; 16 * 1024];
            loop {
                let credit = if flow.enabled.load(Ordering::Relaxed) {
                    Some(tokio::select! {
                        credit = flow.credits.acquire() => credit.context("reverse mux flow window closed")?,
                        _ = cancel.cancelled() => bail!("reverse mux stream cancelled"),
                        _ = wait_idle(&last_activity, idle_timeout) => bail!("reverse mux stream idle timeout"),
                    })
                } else { None };
                let size = tokio::select! {
                    read = reader.read(&mut buffer) => read?,
                    _ = cancel.cancelled() => bail!("reverse mux stream cancelled"),
                    _ = wait_idle(&last_activity, idle_timeout) => bail!("reverse mux stream idle timeout"),
                };
                if size == 0 {
                    write_frame(writer, FIN, id, &[]).await?;
                    return Ok::<_, anyhow::Error>(());
                }
                if !flow.consume(size) {
                    STREAM_BYTE_LIMIT_RESETS.fetch_add(1, Ordering::Relaxed);
                    bail!("reverse mux stream byte limit reached");
                }
                // Finish an in-progress control frame even when this stream is
                // cancelled; abandoning it would corrupt neighboring streams.
                write_frame(writer, DATA, id, &buffer[..size]).await?;
                if let Some(credit) = credit { credit.forget(); }
                if server { PUBLIC_TO_TARGET_BYTES.fetch_add(size as u64, Ordering::Relaxed); }
                *last_activity.lock().unwrap() = tokio::time::Instant::now();
            }
        }.await;
        if result.is_err() {
            cancel.cancel();
        }
        result
    };
    let writing = async {
        let result = async {
            loop {
                let frame = tokio::select! {
                    frame = frames.recv() => frame,
                    _ = cancel.cancelled() => bail!("reverse mux stream cancelled"),
                    _ = wait_idle(&last_activity, idle_timeout) => bail!("reverse mux stream idle timeout"),
                };
                let Some((kind, payload)) = frame else { bail!("reverse mux stream closed without FIN") };
                let io = async {
                    match kind {
                        DATA if !flow.consume(payload.len()) => {
                            STREAM_BYTE_LIMIT_RESETS.fetch_add(1, Ordering::Relaxed);
                            Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reverse mux stream byte limit reached"))
                        }
                        DATA => output.write_all(&payload).await,
                        FIN => output.shutdown().await,
                        _ => Err(std::io::Error::new(std::io::ErrorKind::ConnectionReset, "reverse mux stream reset")),
                    }
                };
                tokio::select! {
                    result = tokio::time::timeout(idle_timeout.unwrap_or(LOCAL_WRITE_TIMEOUT), io) => {
                        result.context("reverse mux socket write timed out")??;
                    }
                    _ = cancel.cancelled() => bail!("reverse mux stream cancelled"),
                }
                if kind == FIN { return Ok::<_, anyhow::Error>(()); }
                if flow.enabled.load(Ordering::Relaxed) {
                    write_frame(writer, WINDOW, id, &1u32.to_be_bytes()).await?;
                }
                if server { TARGET_TO_PUBLIC_BYTES.fetch_add(payload.len() as u64, Ordering::Relaxed); }
                *last_activity.lock().unwrap() = tokio::time::Instant::now();
            }
        }.await;
        if result.is_err() {
            cancel.cancel();
        }
        result
    };
    // Do not drop a sibling future in the middle of a control-frame write.
    let (read, write) = tokio::join!(reading, writing);
    read?;
    write
}

async fn wait_idle(last: &std::sync::Mutex<tokio::time::Instant>, idle: Option<Duration>) {
    let Some(idle) = idle else {
        return std::future::pending().await;
    };
    loop {
        let deadline = *last.lock().unwrap() + idle;
        tokio::time::sleep_until(deadline).await;
        if last.lock().unwrap().elapsed() >= idle {
            return;
        }
    }
}

// Never await space in an individual stream's queue in the control reader.
// One cooperative yield allows a ready consumer to drain a burst. A stream
// still overloaded after that is reset, leaving the shared reader available.
async fn dispatch_frame(sessions: &Sessions, id: u32, kind: u8, payload: Vec<u8>) {
    let inbox = sessions.lock().await.get(&id).cloned();
    if let Some(inbox) = inbox {
        if kind == WINDOW {
            if inbox.flow.enabled.load(Ordering::Relaxed) && payload.len() == 4 {
                let credits = u32::from_be_bytes(payload.as_slice().try_into().unwrap()) as usize;
                if credits > 0
                    && credits <= STREAM_QUEUE_CAPACITY
                    && inbox.flow.credits.available_permits() + credits <= STREAM_QUEUE_CAPACITY
                {
                    inbox.flow.credits.add_permits(credits);
                    return;
                }
            }
            sessions.lock().await.remove(&id);
            inbox.cancel.cancel();
            return;
        }
        if kind != RESET {
            let result = match inbox.sender.try_send((kind, payload)) {
                Err(mpsc::error::TrySendError::Full(frame)) => {
                    tokio::task::yield_now().await;
                    inbox.sender.try_send(frame)
                }
                result => result,
            };
            if result.is_ok() {
                return;
            }
        }
        sessions.lock().await.remove(&id);
        inbox.cancel.cancel();
    }
}

async fn read_frames(
    mut reader: ControlRead,
    sessions: Sessions,
    responses: Arc<Mutex<HashMap<u32, oneshot::Sender<bool>>>>,
    udp_down: Option<mpsc::Sender<(u32, Vec<u8>)>>,
    cancel: CancellationToken,
) {
    loop {
        let frame = tokio::select! {
            frame = read_frame(&mut reader) => frame,
            _ = cancel.cancelled() => return,
        };
        match frame {
            Ok(Some((kind, id, payload))) => match kind {
                OK | FAIL => {
                    if kind == OK
                        && payload == FLOW_CONTROL_V1
                        && let Some(inbox) = sessions.lock().await.get(&id)
                    {
                        inbox.flow.enabled.store(true, Ordering::Relaxed);
                    }
                    if let Some(response) = responses.lock().await.remove(&id) {
                        let _ = response.send(kind == OK);
                    }
                }
                DATA | FIN | RESET | WINDOW => dispatch_frame(&sessions, id, kind, payload).await,
                DATAGRAM => {
                    if let Some(sender) = &udp_down
                        && sender.try_send((id, payload)).is_err()
                    {
                        UDP_DROPPED.fetch_add(1, Ordering::Relaxed);
                    }
                }
                _ => {}
            },
            _ => {
                cancel.cancel();
                return;
            }
        }
    }
}

pub fn tls_acceptor(cert_path: &Path, key_path: &Path) -> Result<TlsAcceptor> {
    tls_acceptor_inner(cert_path, key_path, None)
}

pub fn tls_acceptor_with_client_ca(
    cert_path: &Path,
    key_path: &Path,
    client_ca_path: &Path,
) -> Result<TlsAcceptor> {
    tls_acceptor_inner(cert_path, key_path, Some(client_ca_path))
}

fn tls_acceptor_inner(
    cert_path: &Path,
    key_path: &Path,
    client_ca_path: Option<&Path>,
) -> Result<TlsAcceptor> {
    let certs = CertificateDer::pem_slice_iter(&std::fs::read(cert_path)?)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(!certs.is_empty(), "TLS certificate file is empty");
    let key = PrivateKeyDer::from_pem_slice(&std::fs::read(key_path)?)
        .context("cannot parse TLS private key")?;
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?;
    let builder = if let Some(ca_path) = client_ca_path {
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(&std::fs::read(ca_path)?) {
            roots.add(cert?)?;
        }
        ensure!(!roots.is_empty(), "TLS client CA file has no certificates");
        let verifier = tokio_rustls::rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider,
        )
        .build()?;
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };
    let config = builder.with_single_cert(certs, key)?;
    Ok(TlsAcceptor::from(Arc::new(config)))
}

pub fn tls_connector(
    ca_path: &Path,
    server_name: &str,
) -> Result<(TlsConnector, ServerName<'static>)> {
    tls_connector_inner(ca_path, server_name, None)
}

pub fn tls_connector_with_identity(
    ca_path: &Path,
    server_name: &str,
    client_cert_path: &Path,
    client_key_path: &Path,
) -> Result<(TlsConnector, ServerName<'static>)> {
    tls_connector_inner(
        ca_path,
        server_name,
        Some((client_cert_path, client_key_path)),
    )
}

fn tls_connector_inner(
    ca_path: &Path,
    server_name: &str,
    identity: Option<(&Path, &Path)>,
) -> Result<(TlsConnector, ServerName<'static>)> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&std::fs::read(ca_path)?) {
        roots.add(cert?)?;
    }
    ensure!(!roots.is_empty(), "TLS CA file has no certificates");
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let builder = ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots);
    let config = if let Some((cert_path, key_path)) = identity {
        let certs = CertificateDer::pem_slice_iter(&std::fs::read(cert_path)?)
            .collect::<std::result::Result<Vec<_>, _>>()?;
        ensure!(!certs.is_empty(), "TLS client certificate file is empty");
        let key = PrivateKeyDer::from_pem_slice(&std::fs::read(key_path)?)
            .context("cannot parse TLS client private key")?;
        builder.with_client_auth_cert(certs, key)?
    } else {
        builder.with_no_client_auth()
    };
    Ok((
        TlsConnector::from(Arc::new(config)),
        ServerName::try_from(server_name.to_owned())?,
    ))
}

#[allow(clippy::too_many_arguments)]
async fn authenticate_control_and_spawn<S>(
    mut control_stream: S,
    permit: OwnedSemaphorePermit,
    transport: &'static str,
    peer: SocketAddr,
    token: String,
    public: Arc<TcpListener>,
    public_acceptor: Option<TlsAcceptor>,
    udp: Option<Arc<UdpSocket>>,
    allow_public: Vec<IpNet>,
    max_streams: usize,
    idle_timeout_secs: u64,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let authorized = match tokio::time::timeout(AUTH_TIMEOUT, read_line(&mut control_stream))
        .await
        .ok()
        .and_then(Result::ok)
    {
        Some(line) => line
            .strip_prefix("REVERSE-MUX ")
            .is_some_and(|provided| token_matches(&token, provided)),
        None => false,
    };
    if !authorized {
        let _ = tokio::time::timeout(AUTH_TIMEOUT, control_stream.write_all(b"DENY\n")).await;
        tracing::warn!(%peer, transport, "reverse mux control authentication failed");
        return;
    }
    let Some(active) = ActiveControl::try_new() else {
        CONTROL_LIMIT_REJECTIONS.fetch_add(1, Ordering::Relaxed);
        let _ = tokio::time::timeout(AUTH_TIMEOUT, control_stream.write_all(b"DENY\n")).await;
        tracing::warn!(%peer, transport, "reverse mux active control limit reached");
        return;
    };
    if !matches!(
        tokio::time::timeout(AUTH_TIMEOUT, control_stream.write_all(b"READY\n")).await,
        Ok(Ok(()))
    ) {
        return;
    }
    drop(permit);
    tracing::info!(%peer, transport, "reverse mux control connected");
    if let Err(error) = serve_authorized_control(
        control_stream,
        active,
        public,
        public_acceptor,
        udp,
        token,
        max_streams,
        idle_timeout_secs,
        allow_public,
    )
    .await
    {
        tracing::warn!(%error, transport, "reverse mux control ended");
    }
}

pub async fn serve_mux_tls(
    control: TcpListener,
    public: TcpListener,
    token: String,
    acceptor: TlsAcceptor,
    max_streams: usize,
    idle_timeout_secs: u64,
    allow_public: Vec<IpNet>,
) -> Result<()> {
    serve_mux_tls_public(
        control,
        public,
        token,
        acceptor,
        None,
        max_streams,
        idle_timeout_secs,
        allow_public,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn serve_mux_tls_public(
    control: TcpListener,
    public: TcpListener,
    token: String,
    acceptor: TlsAcceptor,
    public_acceptor: Option<TlsAcceptor>,
    max_streams: usize,
    idle_timeout_secs: u64,
    allow_public: Vec<IpNet>,
) -> Result<()> {
    serve_mux_tls_public_udp(
        control,
        public,
        token,
        acceptor,
        public_acceptor,
        None,
        max_streams,
        idle_timeout_secs,
        allow_public,
    )
    .await
}

#[allow(clippy::too_many_arguments)]
pub async fn serve_mux_tls_public_udp(
    control: TcpListener,
    public: TcpListener,
    token: String,
    acceptor: TlsAcceptor,
    public_acceptor: Option<TlsAcceptor>,
    udp: Option<Arc<UdpSocket>>,
    max_streams: usize,
    idle_timeout_secs: u64,
    allow_public: Vec<IpNet>,
) -> Result<()> {
    ensure!(
        !token.is_empty() && token.len() <= 256,
        "reverse token must be 1..256 bytes"
    );
    ensure!(
        (1..=1024).contains(&max_streams),
        "reverse mux max streams must be 1..=1024"
    );
    ensure!(
        (1..=86_400).contains(&idle_timeout_secs),
        "reverse mux idle timeout must be 1..=86400 seconds"
    );
    let public = Arc::new(public);
    let handshake_slots = Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES));
    loop {
        let (stream, peer) = control.accept().await?;
        let permit = match handshake_slots.clone().try_acquire_owned() {
            Ok(permit) => permit,
            Err(_) => {
                tracing::warn!(%peer, "reverse mux TLS handshake capacity is full");
                continue;
            }
        };
        let acceptor = acceptor.clone();
        let token = token.clone();
        let public = public.clone();
        let public_acceptor = public_acceptor.clone();
        let udp = udp.clone();
        let allow_public = allow_public.clone();
        tokio::spawn(async move {
            let control_stream =
                match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(error)) => {
                        tracing::warn!(%peer, %error, "reverse mux TLS handshake failed");
                        return;
                    }
                    Err(_) => {
                        tracing::warn!(%peer, "reverse mux TLS handshake timed out");
                        return;
                    }
                };
            authenticate_control_and_spawn(
                control_stream,
                permit,
                "TLS",
                peer,
                token,
                public,
                public_acceptor,
                udp,
                allow_public,
                max_streams,
                idle_timeout_secs,
            )
            .await;
        });
    }
}

pub async fn client_mux_tls(
    server: SocketAddr,
    target: String,
    token: String,
    connector: TlsConnector,
    server_name: ServerName<'static>,
) -> Result<()> {
    client_mux_tls_udp(server, target, token, connector, server_name, None).await
}

pub async fn client_mux_tls_udp(
    server: SocketAddr,
    target: String,
    token: String,
    connector: TlsConnector,
    server_name: ServerName<'static>,
    udp_target: Option<String>,
) -> Result<()> {
    client_mux_tls_udp_mode(
        server,
        target,
        token,
        connector,
        server_name,
        udp_target.map(UdpMode::Fixed),
    )
    .await
}

pub async fn client_mux_tls_udp_socks5(
    server: SocketAddr,
    target: String,
    token: String,
    connector: TlsConnector,
    server_name: ServerName<'static>,
) -> Result<()> {
    client_mux_tls_udp_socks5_with_policy(server, target, token, connector, server_name, false)
        .await
}

#[allow(clippy::too_many_arguments)]
pub async fn client_mux_tls_udp_socks5_with_policy(
    server: SocketAddr,
    target: String,
    token: String,
    connector: TlsConnector,
    server_name: ServerName<'static>,
    allow_private: bool,
) -> Result<()> {
    client_mux_tls_udp_mode(
        server,
        target,
        token,
        connector,
        server_name,
        Some(UdpMode::Socks5 { allow_private }),
    )
    .await
}

async fn client_mux_tls_udp_mode(
    server: SocketAddr,
    target: String,
    token: String,
    connector: TlsConnector,
    server_name: ServerName<'static>,
    udp_mode: Option<UdpMode>,
) -> Result<()> {
    ensure!(
        !token.is_empty() && token.len() <= 256,
        "reverse token must be 1..256 bytes"
    );
    let tcp = TcpStream::connect(server)
        .await
        .with_context(|| format!("connect reverse mux TLS server {server}"))?;
    tcp.set_nodelay(true).ok();
    let mut control = connector
        .connect(server_name, tcp)
        .await
        .context("reverse mux TLS handshake failed")?;
    control
        .write_all(format!("REVERSE-MUX {token}\n").as_bytes())
        .await?;
    let reply = read_line(&mut control).await?;
    match reply.as_str() {
        READY => {}
        DENY => bail!("reverse mux server rejected the token"),
        other => bail!("unexpected reverse mux handshake: {other}"),
    }
    let (reader, writer) = tokio::io::split(control);
    let cancel = CancellationToken::new();
    let _cancel_on_exit = cancel.clone().drop_guard();
    let writer = Arc::new(ControlWriter {
        stream: Mutex::new(Box::new(writer)),
        cancel: cancel.clone(),
    });
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    let read_task = tokio::spawn(client_read_loop(
        Box::new(reader),
        target,
        udp_mode,
        writer,
        sessions,
        cancel.clone(),
    ));
    let _ = read_task.await;
    cancel.cancel();
    Ok(())
}

pub async fn client_mux(server: SocketAddr, target: String, token: String) -> Result<()> {
    client_mux_udp(server, target, token, None).await
}

pub async fn client_mux_udp(
    server: SocketAddr,
    target: String,
    token: String,
    udp_target: Option<String>,
) -> Result<()> {
    client_mux_udp_mode(server, target, token, udp_target.map(UdpMode::Fixed)).await
}

pub async fn client_mux_udp_socks5(
    server: SocketAddr,
    target: String,
    token: String,
) -> Result<()> {
    client_mux_udp_socks5_with_policy(server, target, token, false).await
}

pub async fn client_mux_udp_socks5_with_policy(
    server: SocketAddr,
    target: String,
    token: String,
    allow_private: bool,
) -> Result<()> {
    client_mux_udp_mode(
        server,
        target,
        token,
        Some(UdpMode::Socks5 { allow_private }),
    )
    .await
}

async fn client_mux_udp_mode(
    server: SocketAddr,
    target: String,
    token: String,
    udp_mode: Option<UdpMode>,
) -> Result<()> {
    ensure!(
        !token.is_empty() && token.len() <= 256,
        "reverse token must be 1..256 bytes"
    );
    let mut control = TcpStream::connect(server)
        .await
        .with_context(|| format!("connect reverse mux server {server}"))?;
    control.set_nodelay(true).ok();
    control
        .write_all(format!("REVERSE-MUX {token}\n").as_bytes())
        .await?;
    let reply = read_line(&mut control).await?;
    match reply.as_str() {
        READY => {}
        DENY => bail!("reverse mux server rejected the token"),
        other => bail!("unexpected reverse mux handshake: {other}"),
    }
    let (reader, writer) = control.into_split();
    let cancel = CancellationToken::new();
    let _cancel_on_exit = cancel.clone().drop_guard();
    let writer = Arc::new(ControlWriter {
        stream: Mutex::new(Box::new(writer)),
        cancel: cancel.clone(),
    });
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    let read_task = tokio::spawn(client_read_loop(
        Box::new(reader),
        target,
        udp_mode,
        writer.clone(),
        sessions.clone(),
        cancel.clone(),
    ));
    let _ = read_task.await;
    cancel.cancel();
    Ok(())
}

async fn client_read_loop(
    mut reader: ControlRead,
    target: String,
    udp_mode: Option<UdpMode>,
    writer: Writer,
    sessions: Sessions,
    cancel: CancellationToken,
) {
    let udp_sessions: UdpSessions = Arc::new(Mutex::new(HashMap::new()));
    loop {
        let frame = tokio::select! {
            frame = read_frame(&mut reader) => frame,
            _ = cancel.cancelled() => return,
        };
        match frame {
            Ok(Some((OPEN, id, payload))) => {
                if payload == UDP_FEATURE {
                    client_open_udp(
                        id,
                        udp_mode.clone(),
                        writer.clone(),
                        udp_sessions.clone(),
                        cancel.clone(),
                    )
                    .await;
                    continue;
                }
                let stream_cancel = cancel.child_token();
                let flow = StreamFlow::new(payload == FLOW_CONTROL_V1);
                let (data_tx, data_rx) = mpsc::channel(STREAM_QUEUE_CAPACITY);
                let old = sessions.lock().await.insert(
                    id,
                    StreamInbox {
                        sender: data_tx,
                        cancel: stream_cancel.clone(),
                        flow: flow.clone(),
                    },
                );
                if old.is_some() {
                    cancel.cancel();
                    return;
                }
                let target = target.clone();
                let writer = writer.clone();
                let sessions = sessions.clone();
                tokio::spawn(async move {
                    let local = tokio::select! {
                        local = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&target)) => local,
                        _ = stream_cancel.cancelled() => {
                            sessions.lock().await.remove(&id);
                            let _ = write_frame(&writer, RESET, id, &[]).await;
                            return;
                        }
                    };
                    match local {
                        Ok(Ok(local)) => {
                            local.set_nodelay(true).ok();
                            let features = if flow.enabled.load(Ordering::Relaxed) {
                                FLOW_CONTROL_V1
                            } else {
                                &[]
                            };
                            if write_frame(&writer, OK, id, features).await.is_ok()
                                && let Err(error) = bridge_io(
                                    id,
                                    local,
                                    data_rx,
                                    &writer,
                                    &stream_cancel,
                                    &flow,
                                    None,
                                    false,
                                )
                                .await
                            {
                                let _ = write_frame(&writer, RESET, id, &[]).await;
                                tracing::debug!(%error, "reverse mux local bridge ended");
                            }
                        }
                        _ => {
                            let _ = write_frame(&writer, FAIL, id, &[]).await;
                        }
                    }
                    sessions.lock().await.remove(&id);
                    stream_cancel.cancel();
                });
            }
            Ok(Some((DATAGRAM, id, payload))) => {
                let session = udp_sessions
                    .lock()
                    .await
                    .get(&id)
                    .map(|entry| (entry.0.clone(), entry.2, entry.3));
                if let Some((socket, socks5, allow_private)) = session {
                    if socks5 {
                        match crate::socks5::parse_udp_datagram(&payload) {
                            Ok(datagram) => {
                                if let Some(destination) =
                                    udp_socks5_destination(datagram.destination, allow_private)
                                        .await
                                {
                                    let _ = socket
                                        .send_to(&datagram.payload, destination.to_string())
                                        .await;
                                }
                            }
                            Err(error) => {
                                tracing::debug!(%error, "reverse mux UDP SOCKS5 datagram rejected");
                            }
                        }
                    } else {
                        let _ = socket.send(&payload).await;
                    }
                }
            }
            Ok(Some((kind @ (FIN | RESET), id, _))) => {
                if let Some((_, stream_cancel, _, _)) = udp_sessions.lock().await.remove(&id) {
                    stream_cancel.cancel();
                }
                dispatch_frame(&sessions, id, kind, vec![]).await;
            }
            Ok(Some((kind @ (DATA | WINDOW), id, payload))) => {
                dispatch_frame(&sessions, id, kind, payload).await
            }
            _ => {
                cancel.cancel();
                return;
            }
        }
    }
}

async fn udp_socks5_destination(
    destination: crate::shadowsocks::Destination,
    allow_private: bool,
) -> Option<crate::shadowsocks::Destination> {
    use crate::shadowsocks::Destination;
    match destination {
        Destination::Ip(address) => (allow_private || crate::shadowsocks::public(address.ip()))
            .then_some(Destination::Ip(address)),
        Destination::Domain(name, port) if allow_private => Some(Destination::Domain(name, port)),
        Destination::Domain(name, port) => {
            let addresses = tokio::net::lookup_host((name.as_str(), port)).await.ok()?;
            addresses
                .filter(|address| crate::shadowsocks::public(address.ip()))
                .map(Destination::Ip)
                .next()
        }
    }
}

async fn client_open_udp(
    id: u32,
    mode: Option<UdpMode>,
    writer: Writer,
    sessions: UdpSessions,
    cancel: CancellationToken,
) {
    let Some(mode) = mode else {
        let _ = write_frame(&writer, FAIL, id, &[]).await;
        return;
    };
    let socket = match tokio::time::timeout(CONNECT_TIMEOUT, UdpSocket::bind("0.0.0.0:0")).await {
        Ok(Ok(socket)) => socket,
        _ => {
            let _ = write_frame(&writer, FAIL, id, &[]).await;
            return;
        }
    };
    let (socks5, allow_private) = match &mode {
        UdpMode::Fixed(_) => (false, false),
        UdpMode::Socks5 { allow_private } => (true, *allow_private),
    };
    if let UdpMode::Fixed(target) = &mode
        && !matches!(
            tokio::time::timeout(CONNECT_TIMEOUT, socket.connect(target)).await,
            Ok(Ok(()))
        )
    {
        let _ = write_frame(&writer, FAIL, id, &[]).await;
        return;
    }
    let session_cancel = cancel.child_token();
    let socket = Arc::new(socket);
    if let Some((_, previous, _, _)) = sessions.lock().await.insert(
        id,
        (
            socket.clone(),
            session_cancel.clone(),
            socks5,
            allow_private,
        ),
    ) {
        previous.cancel();
    }
    tokio::spawn(client_udp_read(id, socket, writer, session_cancel, socks5));
}

async fn client_udp_read(
    id: u32,
    socket: Arc<UdpSocket>,
    writer: Writer,
    cancel: CancellationToken,
    socks5: bool,
) {
    let mut buffer = vec![0u8; 65_535];
    loop {
        let (size, peer) = if socks5 {
            tokio::select! {
                result = socket.recv_from(&mut buffer) => match result {
                    Ok((size, peer)) => (size, Some(peer)),
                    Err(_) => return,
                },
                _ = cancel.cancelled() => return,
            }
        } else {
            let size = tokio::select! {
                result = socket.recv(&mut buffer) => match result {
                    Ok(size) => size,
                    Err(_) => return,
                },
                _ = cancel.cancelled() => return,
            };
            (size, None::<SocketAddr>)
        };
        if size == 0 {
            continue;
        }
        if socks5 {
            let packet = crate::socks5::encode_udp_datagram(
                &crate::shadowsocks::Destination::Ip(peer.unwrap()),
                &buffer[..size],
            );
            if write_frame(&writer, DATAGRAM, id, &packet).await.is_err() {
                return;
            }
        } else if write_frame(&writer, DATAGRAM, id, &buffer[..size])
            .await
            .is_err()
        {
            return;
        }
    }
}

// The frame is atomic with respect to other writers. Cancellation or a timeout
// after a partial frame poisons the entire control; never reuse its byte stream.
async fn write_frame(writer: &Writer, kind: u8, id: u32, payload: &[u8]) -> std::io::Result<()> {
    ensure_frame(payload.len())?;
    let result = tokio::select! {
        biased;
        _ = writer.cancel.cancelled() => Err(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "reverse mux control cancelled")),
        result = tokio::time::timeout(CONTROL_WRITE_TIMEOUT, async {
            let mut stream = writer.stream.lock().await;
            if writer.cancel.is_cancelled() {
                return Err(std::io::Error::new(std::io::ErrorKind::ConnectionAborted, "reverse mux control cancelled"));
            }
            let poison_on_drop = writer.cancel.clone().drop_guard();
            let mut header = [0u8; 9];
            header[0] = kind;
            header[1..5].copy_from_slice(&id.to_be_bytes());
            header[5..9].copy_from_slice(&(payload.len() as u32).to_be_bytes());
            stream.write_all(&header).await?;
            stream.write_all(payload).await?;
            stream.flush().await?;
            poison_on_drop.disarm();
            Ok(())
        }) => result.unwrap_or_else(|_| Err(std::io::Error::new(std::io::ErrorKind::TimedOut, "reverse mux control write timed out"))),
    };
    if result.is_err() {
        writer.cancel.cancel();
    }
    result
}

fn ensure_frame(length: usize) -> std::io::Result<()> {
    if length > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "reverse mux frame too large",
        ));
    }
    Ok(())
}

async fn read_frame(reader: &mut ControlRead) -> Result<Option<Frame>> {
    let mut header = [0u8; 9];
    let first = reader.read(&mut header[..1]).await?;
    if first == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut header[1..]).await?;
    let id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let length = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
    if length > MAX_FRAME {
        bail!("reverse mux frame too large");
    }
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload).await?;
    Ok(Some((header[0], id, payload)))
}

pub fn metrics_text() -> String {
    let stats = stats();
    format!(
        "# HELP relay_reverse_mux_process_available 1 when metrics come from the tunnel process.\n# TYPE relay_reverse_mux_process_available gauge\nrelay_reverse_mux_process_available 1\n# HELP relay_reverse_mux_controls Authorized reverse mux controls.\n# TYPE relay_reverse_mux_controls gauge\nrelay_reverse_mux_controls {}\nrelay_reverse_mux_controls_total {}\n# HELP relay_reverse_mux_streams Public mux streams.\n# TYPE relay_reverse_mux_streams gauge\nrelay_reverse_mux_streams {}\nrelay_reverse_mux_streams_total {}\n# HELP relay_reverse_mux_bytes Bytes forwarded by the mux server.\n# TYPE relay_reverse_mux_bytes counter\nrelay_reverse_mux_bytes{{direction=\"public_to_target\"}} {}\nrelay_reverse_mux_bytes{{direction=\"target_to_public\"}} {}\n# HELP relay_reverse_mux_control_limit_rejections_total Controls denied by --max-controls.\n# TYPE relay_reverse_mux_control_limit_rejections_total counter\nrelay_reverse_mux_control_limit_rejections_total {}\n# HELP relay_reverse_mux_stream_limit_rejections_total Public streams refused by --max-streams or --max-total-streams.\n# TYPE relay_reverse_mux_stream_limit_rejections_total counter\nrelay_reverse_mux_stream_limit_rejections_total {}\n# HELP relay_reverse_mux_stream_byte_limit_resets_total Streams reset by --max-stream-bytes.\n# TYPE relay_reverse_mux_stream_byte_limit_resets_total counter\nrelay_reverse_mux_stream_byte_limit_resets_total {}\n# HELP relay_reverse_mux_udp_dropped_total UDP datagrams dropped by a full receive queue.\n# TYPE relay_reverse_mux_udp_dropped_total counter\nrelay_reverse_mux_udp_dropped_total {}\n",
        stats.active_controls,
        stats.total_controls,
        stats.active_streams,
        stats.total_streams,
        stats.public_to_target_bytes,
        stats.target_to_public_bytes,
        stats.control_limit_rejections,
        stats.stream_limit_rejections,
        stats.stream_byte_limit_resets,
        stats.udp_dropped,
    )
}

fn token_matches(expected: &str, provided: &str) -> bool {
    if expected.len() != provided.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in expected.bytes().zip(provided.bytes()) {
        difference |= left ^ right;
    }
    difference == 0
}

async fn read_line<S: AsyncRead + Unpin>(stream: &mut S) -> Result<String> {
    let mut line = Vec::with_capacity(32);
    loop {
        let mut byte = [0u8; 1];
        if stream.read(&mut byte).await? == 0 {
            bail!("reverse control connection closed");
        }
        if byte[0] == b'\n' {
            break;
        }
        if line.len() >= MAX_LINE {
            bail!("reverse control line too long");
        }
        line.push(byte[0]);
    }
    String::from_utf8(line).context("reverse control line is not UTF-8")
}

#[cfg(test)]
mod regression_tests {
    use super::*;

    #[test]
    fn stream_byte_limit_counts_both_directions() {
        let flow = StreamFlow::with_limit(false, 8);
        assert!(flow.consume(3));
        assert!(flow.consume(5));
        assert!(!flow.consume(1));
        assert!(flow.consume(0));
        let unlimited = StreamFlow::with_limit(false, 0);
        assert!(unlimited.consume(usize::MAX / 2));
    }

    #[tokio::test]
    async fn full_stream_queue_does_not_block_a_neighbor_or_reset() {
        let sessions: Sessions = Arc::default();
        let (full_tx, mut full_rx) = mpsc::channel(1);
        let full_cancel = CancellationToken::new();
        full_tx.send((DATA, vec![1])).await.unwrap();
        sessions.lock().await.insert(
            1,
            StreamInbox {
                sender: full_tx,
                cancel: full_cancel.clone(),
                flow: StreamFlow::new(false),
            },
        );
        let (other_tx, mut other_rx) = mpsc::channel(1);
        let other_cancel = CancellationToken::new();
        sessions.lock().await.insert(
            2,
            StreamInbox {
                sender: other_tx,
                cancel: other_cancel.clone(),
                flow: StreamFlow::new(false),
            },
        );
        tokio::time::timeout(
            Duration::from_millis(100),
            dispatch_frame(&sessions, 1, DATA, vec![2]),
        )
        .await
        .unwrap();
        assert!(full_cancel.is_cancelled());
        assert!(!sessions.lock().await.contains_key(&1));
        dispatch_frame(&sessions, 2, DATA, b"neighbor".to_vec()).await;
        assert_eq!(other_rx.recv().await.unwrap().1, b"neighbor");
        assert!(!other_cancel.is_cancelled());
        // RESET must also bypass a queue with pending data.
        dispatch_frame(&sessions, 2, DATA, vec![3]).await;
        dispatch_frame(&sessions, 2, RESET, vec![]).await;
        assert!(other_cancel.is_cancelled());
        assert!(full_rx.recv().await.is_some());
    }

    #[tokio::test]
    async fn blocked_socket_writes_observe_cancellation_in_both_roles() {
        for server in [false, true] {
            let (stream, _blocked_reader) = tokio::io::duplex(32);
            let (control, _control_peer) = tokio::io::duplex(1024);
            let writer = Arc::new(ControlWriter {
                stream: Mutex::new(Box::new(control)),
                cancel: CancellationToken::new(),
            });
            let cancel = CancellationToken::new();
            let (tx, rx) = mpsc::channel(2);
            tx.send((DATA, vec![1; 1024])).await.unwrap();
            let task_cancel = cancel.clone();
            let task_writer = writer.clone();
            let task = tokio::spawn(async move {
                bridge_io(
                    1,
                    stream,
                    rx,
                    &task_writer,
                    &task_cancel,
                    &StreamFlow::new(false),
                    Some(Duration::from_secs(10)),
                    server,
                )
                .await
            });
            tokio::time::sleep(Duration::from_millis(20)).await;
            cancel.cancel();
            assert!(
                tokio::time::timeout(Duration::from_millis(200), task)
                    .await
                    .unwrap()
                    .unwrap()
                    .is_err()
            );
            assert!(
                !writer.cancel.is_cancelled(),
                "a stalled local socket must not poison the control"
            );
        }
    }

    #[tokio::test]
    async fn idle_deadline_closes_a_blocked_public_write() {
        let (stream, _blocked_reader) = tokio::io::duplex(32);
        let (control, _control_peer) = tokio::io::duplex(1024);
        let writer = Arc::new(ControlWriter {
            stream: Mutex::new(Box::new(control)),
            cancel: CancellationToken::new(),
        });
        let cancel = CancellationToken::new();
        let (tx, rx) = mpsc::channel(2);
        tx.send((DATA, vec![1; 1024])).await.unwrap();
        let result = tokio::time::timeout(
            Duration::from_millis(300),
            bridge_io(
                1,
                stream,
                rx,
                &writer,
                &cancel,
                &StreamFlow::new(false),
                Some(Duration::from_millis(30)),
                true,
            ),
        )
        .await
        .unwrap();
        assert!(result.is_err());
        assert!(cancel.is_cancelled());
        assert!(!writer.cancel.is_cancelled());
    }

    #[tokio::test]
    async fn abandoned_partial_control_frame_poison_closes_connection() {
        // The nine-byte header cannot fit, so cancellation happens after a
        // partial frame. A subsequent frame must never reuse these bytes.
        let (control, _peer) = tokio::io::duplex(8);
        let cancel = CancellationToken::new();
        let writer = Arc::new(ControlWriter {
            stream: Mutex::new(Box::new(control)),
            cancel: cancel.clone(),
        });
        assert!(
            tokio::time::timeout(
                Duration::from_millis(30),
                write_frame(&writer, DATA, 1, b"payload")
            )
            .await
            .is_err()
        );
        assert!(cancel.is_cancelled());
        assert!(write_frame(&writer, DATA, 2, b"neighbor").await.is_err());
    }
}
