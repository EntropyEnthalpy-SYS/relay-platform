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
        atomic::{AtomicBool, AtomicU32, Ordering},
        atomic::{AtomicU64, Ordering as AtomicOrdering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
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
}
impl StreamFlow {
    fn new(enabled: bool) -> Arc<Self> {
        Arc::new(Self {
            enabled: AtomicBool::new(enabled),
            credits: Semaphore::new(STREAM_QUEUE_CAPACITY),
        })
    }
}
type Sessions = Arc<Mutex<HashMap<u32, StreamInbox>>>;

struct ActiveControl;
impl Drop for ActiveControl {
    fn drop(&mut self) {
        ACTIVE_CONTROLS.fetch_sub(1, Ordering::Relaxed);
    }
}
struct ActiveStream(Arc<AtomicU32>);
impl ActiveStream {
    fn new(local: Arc<AtomicU32>) -> Self {
        local.fetch_add(1, Ordering::Relaxed);
        ACTIVE_STREAMS.fetch_add(1, Ordering::Relaxed);
        TOTAL_STREAMS.fetch_add(1, Ordering::Relaxed);
        Self(local)
    }
}
impl Drop for ActiveStream {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
        ACTIVE_STREAMS.fetch_sub(1, Ordering::Relaxed);
    }
}
type Frame = (u8, u32, Vec<u8>);

static ACTIVE_CONTROLS: AtomicU32 = AtomicU32::new(0);
static TOTAL_CONTROLS: AtomicU64 = AtomicU64::new(0);
static ACTIVE_STREAMS: AtomicU32 = AtomicU32::new(0);
static TOTAL_STREAMS: AtomicU64 = AtomicU64::new(0);
static PUBLIC_TO_TARGET_BYTES: AtomicU64 = AtomicU64::new(0);
static TARGET_TO_PUBLIC_BYTES: AtomicU64 = AtomicU64::new(0);

#[derive(Clone, Copy, Debug)]
pub struct Stats {
    pub active_controls: u32,
    pub total_controls: u64,
    pub active_streams: u32,
    pub total_streams: u64,
    pub public_to_target_bytes: u64,
    pub target_to_public_bytes: u64,
}

pub fn stats() -> Stats {
    Stats {
        active_controls: ACTIVE_CONTROLS.load(Ordering::Relaxed),
        total_controls: TOTAL_CONTROLS.load(Ordering::Relaxed),
        active_streams: ACTIVE_STREAMS.load(Ordering::Relaxed),
        total_streams: TOTAL_STREAMS.load(Ordering::Relaxed),
        public_to_target_bytes: PUBLIC_TO_TARGET_BYTES.load(Ordering::Relaxed),
        target_to_public_bytes: TARGET_TO_PUBLIC_BYTES.load(Ordering::Relaxed),
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
        max_streams,
        idle_timeout_secs,
        allow_public,
    )
    .await
}

async fn serve_mux_plain_public(
    control: TcpListener,
    public: TcpListener,
    token: String,
    public_acceptor: Option<TlsAcceptor>,
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
    loop {
        let (mut control_stream, peer) = control.accept().await?;
        control_stream.set_nodelay(true).ok();
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
            let _ = control_stream.write_all(b"DENY\n").await;
            tracing::warn!(%peer, "reverse mux authentication failed");
            continue;
        }
        if control_stream.write_all(b"READY\n").await.is_err() {
            continue;
        }
        tracing::info!(%peer, "reverse mux client connected");
        let public = public.clone();
        let public_acceptor = public_acceptor.clone();
        let allow_public = allow_public.clone();
        let token = token.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_authorized_control(
                control_stream,
                public,
                public_acceptor,
                token,
                max_streams,
                idle_timeout_secs,
                allow_public,
            )
            .await
            {
                tracing::warn!(%error, "reverse mux control ended");
            }
        });
    }
}

async fn serve_authorized_control<S>(
    control: S,
    public: Arc<TcpListener>,
    public_acceptor: Option<TlsAcceptor>,
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
    ACTIVE_CONTROLS.fetch_add(1, AtomicOrdering::Relaxed);
    TOTAL_CONTROLS.fetch_add(1, AtomicOrdering::Relaxed);
    let _active = ActiveControl;
    serve_control(
        Box::new(reader),
        Box::new(writer),
        public,
        public_acceptor,
        max_streams,
        idle_timeout_secs,
        allow_public,
    )
    .await
}

async fn serve_control(
    reader: ControlRead,
    writer: ControlWrite,
    public: Arc<TcpListener>,
    public_acceptor: Option<TlsAcceptor>,
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
    let read_task = tokio::spawn(read_frames(
        reader,
        sessions.clone(),
        responses.clone(),
        cancel.clone(),
    ));
    let next_id = AtomicU32::new(1);
    let active_streams = Arc::new(AtomicU32::new(0));
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
        if active_streams.load(Ordering::Relaxed) >= max_streams as u32 {
            let _ = exposed.shutdown().await;
            continue;
        }
        let exposed: PublicStream = if let Some(acceptor) = &public_acceptor {
            match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(exposed)).await {
                Ok(Ok(stream)) => Box::new(stream),
                Ok(Err(error)) => {
                    tracing::warn!(%peer, %error, "reverse mux public TLS handshake failed");
                    continue;
                }
                Err(_) => {
                    tracing::warn!(%peer, "reverse mux public TLS handshake timed out");
                    continue;
                }
            }
        } else {
            Box::new(exposed)
        };
        let id = next_id.fetch_add(1, Ordering::Relaxed);
        let active = ActiveStream::new(active_streams.clone());
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
        if let Err(error) = write_frame(&writer, OPEN, id, FLOW_CONTROL_V1).await {
            sessions.lock().await.remove(&id);
            responses.lock().await.remove(&id);
            break Err(error.into());
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
            continue;
        }
        let writer = writer.clone();
        let sessions = sessions.clone();
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
    };
    cancel.cancel();
    let _ = read_task.await;
    result
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
    peer: SocketAddr,
    token: String,
    public: Arc<TcpListener>,
    public_acceptor: Option<TlsAcceptor>,
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
        tracing::warn!(%peer, "reverse mux TLS authentication failed");
        return;
    }
    if !matches!(
        tokio::time::timeout(AUTH_TIMEOUT, control_stream.write_all(b"READY\n")).await,
        Ok(Ok(()))
    ) {
        return;
    }
    drop(permit);
    tracing::info!(%peer, "reverse mux TLS client connected");
    if let Err(error) = serve_authorized_control(
        control_stream,
        public,
        public_acceptor,
        token,
        max_streams,
        idle_timeout_secs,
        allow_public,
    )
    .await
    {
        tracing::warn!(%error, "reverse mux TLS control ended");
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
                peer,
                token,
                public,
                public_acceptor,
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
        writer,
        sessions,
        cancel.clone(),
    ));
    let _ = read_task.await;
    cancel.cancel();
    Ok(())
}

pub async fn client_mux(server: SocketAddr, target: String, token: String) -> Result<()> {
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
    writer: Writer,
    sessions: Sessions,
    cancel: CancellationToken,
) {
    loop {
        let frame = tokio::select! {
            frame = read_frame(&mut reader) => frame,
            _ = cancel.cancelled() => return,
        };
        match frame {
            Ok(Some((OPEN, id, payload))) => {
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
            Ok(Some((kind @ (DATA | FIN | RESET | WINDOW), id, payload))) => {
                dispatch_frame(&sessions, id, kind, payload).await
            }
            _ => {
                cancel.cancel();
                return;
            }
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
        "# HELP relay_reverse_mux_process_available 1 when metrics come from the tunnel process.\n# TYPE relay_reverse_mux_process_available gauge\nrelay_reverse_mux_process_available 1\n# HELP relay_reverse_mux_controls Authorized reverse mux controls.\n# TYPE relay_reverse_mux_controls gauge\nrelay_reverse_mux_controls {}\nrelay_reverse_mux_controls_total {}\n# HELP relay_reverse_mux_streams Public mux streams.\n# TYPE relay_reverse_mux_streams gauge\nrelay_reverse_mux_streams {}\nrelay_reverse_mux_streams_total {}\n# HELP relay_reverse_mux_bytes Bytes forwarded by the mux server.\n# TYPE relay_reverse_mux_bytes counter\nrelay_reverse_mux_bytes{{direction=\"public_to_target\"}} {}\nrelay_reverse_mux_bytes{{direction=\"target_to_public\"}} {}\n",
        stats.active_controls,
        stats.total_controls,
        stats.active_streams,
        stats.total_streams,
        stats.public_to_target_bytes,
        stats.target_to_public_bytes,
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
