//! Single-connection multiplexed reverse TCP tunnel.
//!
//! The control connection carries length-prefixed frames for many public
//! connections. This is separate from the legacy line protocol in `reverse`;
//! the legacy commands keep their one-public-connection-per-control behavior.
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::{Mutex, mpsc, oneshot},
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
const MAX_FRAME: usize = 64 * 1024;
const READY: &str = "READY";
const DENY: &str = "DENY";
const OPEN: u8 = 1;
const OK: u8 = 2;
const FAIL: u8 = 3;
const DATA: u8 = 4;
const FIN: u8 = 5;
const RESET: u8 = 6;
const OPEN_TIMEOUT: Duration = Duration::from_secs(5);

trait PublicIo: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> PublicIo for T {}
type PublicStream = Box<dyn PublicIo>;
type ControlRead = Box<dyn AsyncRead + Send + Unpin>;
type ControlWrite = Box<dyn AsyncWrite + Send + Unpin>;
type Writer = Arc<Mutex<ControlWrite>>;
type Sessions = Arc<Mutex<HashMap<u32, mpsc::Sender<(u8, Vec<u8>)>>>>;
type Frame = (u8, u32, Vec<u8>);

pub async fn serve_mux(control: TcpListener, public: TcpListener, token: String) -> Result<()> {
    serve_mux_with_options(control, public, token, 256, 300).await
}

pub async fn serve_mux_with_limit(
    control: TcpListener,
    public: TcpListener,
    token: String,
    max_streams: usize,
) -> Result<()> {
    serve_mux_with_options(control, public, token, max_streams, 300).await
}

pub async fn serve_mux_with_options(
    control: TcpListener,
    public: TcpListener,
    token: String,
    max_streams: usize,
    idle_timeout_secs: u64,
) -> Result<()> {
    serve_mux_plain_public(control, public, token, None, max_streams, idle_timeout_secs).await
}

pub async fn serve_mux_public_tls(
    control: TcpListener,
    public: TcpListener,
    token: String,
    public_acceptor: TlsAcceptor,
    max_streams: usize,
    idle_timeout_secs: u64,
) -> Result<()> {
    serve_mux_plain_public(
        control,
        public,
        token,
        Some(public_acceptor),
        max_streams,
        idle_timeout_secs,
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
        let token = token.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_authorized_control(
                control_stream,
                public,
                public_acceptor,
                token,
                max_streams,
                idle_timeout_secs,
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
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let _ = token;
    let (reader, writer) = tokio::io::split(control);
    serve_control(
        Box::new(reader),
        Box::new(writer),
        public,
        public_acceptor,
        max_streams,
        idle_timeout_secs,
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
) -> Result<()> {
    let writer: Writer = Arc::new(Mutex::new(writer));
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    let responses: Arc<Mutex<HashMap<u32, oneshot::Sender<bool>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let cancel = CancellationToken::new();
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
        if active_streams.load(Ordering::Relaxed) >= max_streams as u32 {
            let _ = exposed.shutdown().await;
            continue;
        }
        let mut exposed: PublicStream = if let Some(acceptor) = &public_acceptor {
            match acceptor.accept(exposed).await {
                Ok(stream) => Box::new(stream),
                Err(error) => {
                    tracing::warn!(%peer, %error, "reverse mux public TLS handshake failed");
                    continue;
                }
            }
        } else {
            Box::new(exposed)
        };
        let id = next_id.fetch_add(1, Ordering::Relaxed);
        active_streams.fetch_add(1, Ordering::Relaxed);
        let (data_tx, data_rx) = mpsc::channel(32);
        let (response_tx, response_rx) = oneshot::channel();
        sessions.lock().await.insert(id, data_tx);
        responses.lock().await.insert(id, response_tx);
        if let Err(error) = write_frame(&writer, OPEN, id, &[]).await {
            sessions.lock().await.remove(&id);
            responses.lock().await.remove(&id);
            active_streams.fetch_sub(1, Ordering::Relaxed);
            let _ = exposed.shutdown().await;
            break Err(error.into());
        }
        let opened = tokio::time::timeout(OPEN_TIMEOUT, response_rx)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(false);
        if !opened {
            sessions.lock().await.remove(&id);
            responses.lock().await.remove(&id);
            active_streams.fetch_sub(1, Ordering::Relaxed);
            let _ = exposed.shutdown().await;
            tracing::warn!(%peer, "reverse mux client did not open the target");
            continue;
        }
        let writer = writer.clone();
        let sessions = sessions.clone();
        let active_streams = active_streams.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            if let Err(error) = bridge_public(
                id,
                exposed,
                data_rx,
                writer,
                sessions,
                active_streams,
                cancel,
                Duration::from_secs(idle_timeout_secs),
            )
            .await
            {
                tracing::debug!(%error, "reverse mux public bridge ended");
            }
        });
    };
    cancel.cancel();
    let _ = read_task.await;
    result
}

#[allow(clippy::too_many_arguments)]
async fn bridge_public(
    id: u32,
    exposed: PublicStream,
    mut frames: mpsc::Receiver<(u8, Vec<u8>)>,
    writer: Writer,
    sessions: Sessions,
    active_streams: Arc<AtomicU32>,
    cancel: CancellationToken,
    idle_timeout: Duration,
) -> Result<()> {
    let (mut reader, mut writer_stream) = tokio::io::split(exposed);
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        let idle = tokio::time::sleep(idle_timeout);
        tokio::pin!(idle);
        tokio::select! {
            _ = &mut idle => {
                let _ = write_frame(&writer, RESET, id, &[]).await;
                break;
            }
            read = reader.read(&mut buffer) => match read {
                Ok(0) => { let _ = write_frame(&writer, FIN, id, &[]).await; break; }
                Ok(size) => if write_frame(&writer, DATA, id, &buffer[..size]).await.is_err() { break; }
                Err(_) => { let _ = write_frame(&writer, RESET, id, &[]).await; break; }
            },
            frame = frames.recv() => match frame {
                Some((DATA, payload)) => if writer_stream.write_all(&payload).await.is_err() { break; },
                Some((FIN, _)) => { let _ = writer_stream.shutdown().await; break; }
                Some((RESET, _)) | None => break,
                _ => {}
            },
            _ = cancel.cancelled() => break,
        }
    }
    sessions.lock().await.remove(&id);
    active_streams.fetch_sub(1, Ordering::Relaxed);
    Ok(())
}

async fn read_frames(
    mut reader: ControlRead,
    sessions: Sessions,
    responses: Arc<Mutex<HashMap<u32, oneshot::Sender<bool>>>>,
    cancel: CancellationToken,
) {
    loop {
        match read_frame(&mut reader).await {
            Ok(Some((kind, id, payload))) => match kind {
                OK | FAIL => {
                    if let Some(response) = responses.lock().await.remove(&id) {
                        let _ = response.send(kind == OK);
                    }
                }
                DATA | FIN | RESET => {
                    let sender = sessions.lock().await.get(&id).cloned();
                    if let Some(sender) = sender {
                        let _ = sender.send((kind, payload)).await;
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

pub async fn serve_mux_tls(
    control: TcpListener,
    public: TcpListener,
    token: String,
    acceptor: TlsAcceptor,
    max_streams: usize,
    idle_timeout_secs: u64,
) -> Result<()> {
    serve_mux_tls_public(
        control,
        public,
        token,
        acceptor,
        None,
        max_streams,
        idle_timeout_secs,
    )
    .await
}

pub async fn serve_mux_tls_public(
    control: TcpListener,
    public: TcpListener,
    token: String,
    acceptor: TlsAcceptor,
    public_acceptor: Option<TlsAcceptor>,
    max_streams: usize,
    idle_timeout_secs: u64,
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
        let (stream, peer) = control.accept().await?;
        let mut control_stream = match acceptor.accept(stream).await {
            Ok(stream) => stream,
            Err(error) => {
                tracing::warn!(%peer, %error, "reverse mux TLS handshake failed");
                continue;
            }
        };
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
            tracing::warn!(%peer, "reverse mux TLS authentication failed");
            continue;
        }
        if control_stream.write_all(b"READY\n").await.is_err() {
            continue;
        }
        tracing::info!(%peer, "reverse mux TLS client connected");
        let public = public.clone();
        let public_acceptor = public_acceptor.clone();
        let token = token.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_authorized_control(
                control_stream,
                public,
                public_acceptor,
                token,
                max_streams,
                idle_timeout_secs,
            )
            .await
            {
                tracing::warn!(%error, "reverse mux TLS control ended");
            }
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
    let writer: Writer = Arc::new(Mutex::new(Box::new(writer)));
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    let cancel = CancellationToken::new();
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
    let writer: Writer = Arc::new(Mutex::new(Box::new(writer)));
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    let cancel = CancellationToken::new();
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
        match read_frame(&mut reader).await {
            Ok(Some((OPEN, id, _))) => {
                let (data_tx, data_rx) = mpsc::channel(32);
                sessions.lock().await.insert(id, data_tx);
                let target = target.clone();
                let writer = writer.clone();
                let sessions = sessions.clone();
                let cancel = cancel.clone();
                tokio::spawn(async move {
                    if let Err(error) = bridge_local(
                        id,
                        target,
                        data_rx,
                        writer.clone(),
                        sessions.clone(),
                        cancel,
                    )
                    .await
                    {
                        let _ = write_frame(&writer, FAIL, id, &[]).await;
                        sessions.lock().await.remove(&id);
                        tracing::debug!(%error, "reverse mux local bridge ended");
                    }
                });
            }
            Ok(Some((DATA, id, payload))) => {
                let sender = sessions.lock().await.get(&id).cloned();
                if let Some(sender) = sender {
                    let _ = sender.send((DATA, payload)).await;
                }
            }
            Ok(Some((FIN, id, _))) => {
                let sender = sessions.lock().await.get(&id).cloned();
                if let Some(sender) = sender {
                    let _ = sender.send((FIN, Vec::new())).await;
                }
            }
            Ok(Some((RESET, id, _))) => {
                let sender = sessions.lock().await.get(&id).cloned();
                if let Some(sender) = sender {
                    let _ = sender.send((RESET, Vec::new())).await;
                }
            }
            _ => {
                cancel.cancel();
                return;
            }
        }
    }
}

async fn bridge_local(
    id: u32,
    target: String,
    mut frames: mpsc::Receiver<(u8, Vec<u8>)>,
    writer: Writer,
    sessions: Sessions,
    cancel: CancellationToken,
) -> Result<()> {
    let local = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(&target))
        .await
        .with_context(|| format!("connect reverse mux target {target} timed out"))?
        .with_context(|| format!("connect reverse mux target {target}"))?;
    local.set_nodelay(true).ok();
    write_frame(&writer, OK, id, &[]).await?;
    let (mut reader, mut writer_stream) = local.into_split();
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        tokio::select! {
            read = reader.read(&mut buffer) => match read {
                Ok(0) => { let _ = write_frame(&writer, FIN, id, &[]).await; break; }
                Ok(size) => if write_frame(&writer, DATA, id, &buffer[..size]).await.is_err() { break; }
                Err(_) => { let _ = write_frame(&writer, RESET, id, &[]).await; break; }
            },
            frame = frames.recv() => match frame {
                Some((DATA, payload)) => if writer_stream.write_all(&payload).await.is_err() { break; },
                Some((FIN, _)) => { let _ = writer_stream.shutdown().await; break; }
                Some((RESET, _)) | None => break,
                _ => {}
            },
            _ = cancel.cancelled() => break,
        }
    }
    sessions.lock().await.remove(&id);
    Ok(())
}

async fn write_frame(writer: &Writer, kind: u8, id: u32, payload: &[u8]) -> std::io::Result<()> {
    ensure_frame(payload.len())?;
    let mut stream = writer.lock().await;
    let mut header = [0u8; 9];
    header[0] = kind;
    header[1..5].copy_from_slice(&id.to_be_bytes());
    header[5..9].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    stream.write_all(&header).await?;
    stream.write_all(payload).await?;
    stream.flush().await
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
