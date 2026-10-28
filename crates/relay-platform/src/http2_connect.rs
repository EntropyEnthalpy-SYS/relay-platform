//! HTTP/2 CONNECT listeners and the managed rule-engine transport.
use crate::{http_connect, shadowsocks::Destination, transport::BoxStream};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http_body_util::Empty;
use hyper::{
    Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header::PROXY_AUTHORIZATION,
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    future::Future,
    net::SocketAddr,
    path::Path,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::{Duration, Instant},
};
use subtle::ConstantTimeEq;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, copy_bidirectional},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        RootCertStore, ServerConfig as TlsServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    },
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

/// Credentials belong to the rule owner. Multiple digests allow a short
/// rotation overlap; replacing the configuration closes existing connections.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub bearer_token_sha256: Vec<String>,
    #[serde(default)]
    pub allow_private_destinations: bool,
    /// Shared across all TCP connections and listen ports of a managed rule.
    #[serde(default = "default_streams")]
    pub max_concurrent_streams: u32,
    /// Optional per-direction OS socket buffer request on both sides of each tunnel.
    /// Linux charges roughly twice this request per socket direction.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socket_buffer_bytes: Option<u32>,
}
fn default_streams() -> u32 {
    128
}
impl From<http_connect::ServerConfig> for ServerConfig {
    fn from(config: http_connect::ServerConfig) -> Self {
        Self {
            username: config.username,
            password: config.password,
            allow_private_destinations: config.allow_private_destinations,
            bearer_token_sha256: vec![],
            max_concurrent_streams: default_streams(),
            socket_buffer_bytes: None,
        }
    }
}
impl ServerConfig {
    pub fn validate(&self) -> Result<()> {
        http_connect::validate(&http_connect::ServerConfig {
            username: self.username.clone(),
            password: self.password.clone(),
            allow_private_destinations: self.allow_private_destinations,
        })?;
        ensure!(
            (1..=4096).contains(&self.max_concurrent_streams),
            "HTTP/2 stream limit must be 1..4096"
        );
        ensure!(
            self.socket_buffer_bytes
                .is_none_or(|size| (16_384..=4_194_304).contains(&size)),
            "HTTP/2 socket buffer must be 16384..4194304 bytes"
        );
        ensure!(
            self.bearer_token_sha256.len() <= 8,
            "at most eight HTTP/2 bearer digests are allowed"
        );
        let mut hashes = std::collections::HashSet::new();
        for digest in &self.bearer_token_sha256 {
            ensure!(
                digest.len() == 64 && digest.bytes().all(|b| b.is_ascii_hexdigit()),
                "HTTP/2 bearer digest must be 64 hexadecimal characters"
            );
            ensure!(
                hashes.insert(digest.to_ascii_lowercase()),
                "duplicate HTTP/2 bearer digest"
            );
        }
        Ok(())
    }
}

type DialFuture = Pin<Box<dyn Future<Output = std::result::Result<BoxStream, StatusCode>> + Send>>;
type RelayFuture = Pin<Box<dyn Future<Output = Result<()>> + Send>>;
pub(crate) type Dial = Arc<dyn Fn(Destination) -> DialFuture + Send + Sync>;
pub(crate) type Relay = Arc<dyn Fn(BoxStream, BoxStream) -> RelayFuture + Send + Sync>;

/// The engine supplies its ACL-aware connector and its ordinary metered copy
/// loop. No payload bypasses the rule's accounting or shared throttles.
pub(crate) struct Session {
    pub config: Arc<ServerConfig>,
    pub dial: Dial,
    pub relay: Relay,
    pub cancel: CancellationToken,
    pub tasks: TaskTracker,
    pub handshake_timeout: Duration,
    pub connect_timeout: Duration,
    pub idle_timeout: Duration,
}
#[derive(Default)]
struct Activity {
    active: AtomicUsize,
    last: Mutex<Option<Instant>>,
}
struct Active(Arc<Activity>);
impl Active {
    fn new(activity: Arc<Activity>) -> Self {
        activity.active.fetch_add(1, Ordering::Relaxed);
        *activity.last.lock().unwrap() = Some(Instant::now());
        Self(activity)
    }
}
impl Drop for Active {
    fn drop(&mut self) {
        *self.0.last.lock().unwrap() = Some(Instant::now());
        self.0.active.fetch_sub(1, Ordering::Relaxed);
    }
}

pub async fn serve(listener: TcpListener, config: http_connect::ServerConfig) -> Result<()> {
    http_connect::validate(&config)?;
    let server = Arc::new(config);
    loop {
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true).ok();
        let server = server.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_connection(stream, server, peer).await {
                tracing::debug!(%peer, %error, "HTTP/2 CONNECT connection ended");
            }
        });
    }
}

pub async fn serve_tls(
    listener: TcpListener,
    config: http_connect::ServerConfig,
    acceptor: TlsAcceptor,
) -> Result<()> {
    http_connect::validate(&config)?;
    let server = Arc::new(config);
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let server = server.clone();
        tokio::spawn(async move {
            let stream = match timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    tracing::debug!(%peer, %error, "HTTP/2 TLS handshake failed");
                    return;
                }
                Err(_) => {
                    tracing::debug!(%peer, "HTTP/2 TLS handshake timed out");
                    return;
                }
            };
            if let Err(error) = serve_connection(stream, server, peer).await {
                tracing::debug!(%peer, %error, "HTTP/2 CONNECT connection ended");
            }
        });
    }
}

async fn serve_connection<S>(
    stream: S,
    config: Arc<http_connect::ServerConfig>,
    peer: SocketAddr,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let private = config.allow_private_destinations;
    let session = Session {
        config: Arc::new((*config).clone().into()),
        dial: Arc::new(move |destination| {
            Box::pin(async move {
                let target = resolve_target(&destination, private)
                    .await
                    .ok_or(StatusCode::FORBIDDEN)?;
                let stream = TcpStream::connect(target)
                    .await
                    .map_err(|_| StatusCode::BAD_GATEWAY)?;
                stream.set_nodelay(true).ok();
                Ok(Box::new(stream) as BoxStream)
            })
        }),
        relay: Arc::new(|mut client, mut upstream| {
            Box::pin(async move {
                copy_bidirectional(&mut client, &mut upstream).await?;
                Ok(())
            })
        }),
        cancel: CancellationToken::new(),
        tasks: TaskTracker::new(),
        handshake_timeout: HANDSHAKE_TIMEOUT,
        connect_timeout: CONNECT_TIMEOUT,
        idle_timeout: Duration::from_secs(300),
    };
    serve_managed(Box::new(stream), session, peer).await
}

pub(crate) async fn serve_managed(
    mut stream: BoxStream,
    session: Session,
    peer: SocketAddr,
) -> Result<()> {
    let cancel = session.cancel.child_token();
    // Also fires if the engine drops this future during disable/reload/shutdown.
    let _cancel_on_drop = cancel.clone().drop_guard();
    let session = Arc::new(Session {
        cancel: cancel.clone(),
        ..session
    });
    let preface = timeout(session.handshake_timeout, read_preface(&mut stream))
        .await
        .context("HTTP/2 CONNECT handshake timed out")??;
    let (reader, writer) = tokio::io::split(stream);
    let stream = tokio::io::join(std::io::Cursor::new(preface).chain(reader), writer);
    let activity = Arc::new(Activity::default());
    let idle_activity = activity.clone();
    let idle = session.idle_timeout;
    let max_streams = session.config.max_concurrent_streams;
    let service =
        service_fn(move |request| handle(request, session.clone(), activity.clone(), peer));
    let mut builder = hyper::server::conn::http2::Builder::new(TokioExecutor::new());
    builder
        .max_concurrent_streams(max_streams)
        .max_header_list_size(16 * 1024)
        .max_send_buf_size(64 * 1024)
        .initial_stream_window_size(64 * 1024)
        .initial_connection_window_size(1024 * 1024);
    let inactive = async move {
        loop {
            tokio::time::sleep(idle).await;
            if idle_activity.active.load(Ordering::Relaxed) == 0
                && idle_activity
                    .last
                    .lock()
                    .unwrap()
                    .is_none_or(|last| last.elapsed() >= idle)
            {
                break;
            }
        }
    };
    tokio::select! {
        result = builder.serve_connection(TokioIo::new(stream), service) => { result?; }
        _ = cancel.cancelled() => {}
        _ = inactive => {}
    }
    Ok(())
}

async fn read_preface<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    const MAGIC: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let mut preface = vec![0; MAGIC.len() + 9];
    stream.read_exact(&mut preface[..MAGIC.len()]).await?;
    ensure!(&preface[..MAGIC.len()] == MAGIC, "invalid HTTP/2 preface");
    stream.read_exact(&mut preface[MAGIC.len()..]).await?;
    let header = &preface[MAGIC.len()..];
    let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    ensure!(
        header[3] == 4
            && header[4] & 1 == 0
            && u32::from_be_bytes(header[5..9].try_into()?) & 0x7fff_ffff == 0
            && length <= 16_384
            && length.is_multiple_of(6),
        "invalid initial HTTP/2 SETTINGS frame"
    );
    let offset = preface.len();
    preface.resize(offset + length, 0);
    stream.read_exact(&mut preface[offset..]).await?;
    // Hyper still validates SETTINGS values and the rest of the protocol. Replay
    // the exact bytes so its connection state sees an ordinary client handshake.
    Ok(preface)
}

pub fn tls_acceptor_h2(
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
    let builder = TlsServerConfig::builder_with_provider(provider.clone())
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
    let mut config = builder.with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

pub fn tls_connector_h2(
    ca_path: &Path,
    server_name: &str,
) -> Result<(
    tokio_rustls::TlsConnector,
    tokio_rustls::rustls::pki_types::ServerName<'static>,
)> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&std::fs::read(ca_path)?) {
        roots.add(cert?)?;
    }
    ensure!(!roots.is_empty(), "TLS CA file has no certificates");
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let mut config = tokio_rustls::rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok((
        tokio_rustls::TlsConnector::from(Arc::new(config)),
        tokio_rustls::rustls::pki_types::ServerName::try_from(server_name.to_owned())?,
    ))
}

async fn handle(
    mut request: Request<Incoming>,
    session: Arc<Session>,
    activity: Arc<Activity>,
    peer: SocketAddr,
) -> Result<Response<Empty<Bytes>>, hyper::Error> {
    let active = Active::new(activity);
    let config = &session.config;
    if request.method() != hyper::Method::CONNECT {
        return Ok(reply(StatusCode::METHOD_NOT_ALLOWED, config));
    }
    let Some(authority) = request.uri().authority().map(|v| v.to_string()) else {
        return Ok(reply(StatusCode::BAD_REQUEST, config));
    };
    if !authorized(request.headers(), config) {
        return Ok(reply(StatusCode::PROXY_AUTHENTICATION_REQUIRED, config));
    }
    let destination = match http_connect::parse_authority(&authority) {
        Ok(destination) => destination,
        Err(_) => return Ok(reply(StatusCode::BAD_REQUEST, config)),
    };
    let upstream = tokio::select! {
        _ = session.cancel.cancelled() => return Ok(reply(StatusCode::SERVICE_UNAVAILABLE, config)),
        result = timeout(session.connect_timeout, (session.dial)(destination)) => match result {
            Ok(Ok(stream)) => stream,
            Ok(Err(status)) => return Ok(reply(status, config)),
            Err(_) => return Ok(reply(StatusCode::BAD_GATEWAY, config)),
        }
    };
    let upgrade = hyper::upgrade::on(&mut request);
    let task_session = session.clone();
    session.tasks.spawn(async move {
        let _active = active;
        tokio::select! {
            _ = task_session.cancel.cancelled() => {}
            _ = async {
                if let Ok(Ok(upgraded)) = timeout(task_session.connect_timeout, upgrade).await {
                    let _ = (task_session.relay)(Box::new(TokioIo::new(upgraded)), upstream).await;
                }
            } => {}
        }
    });
    tracing::debug!(%peer, "HTTP/2 CONNECT tunnel established");
    Ok(reply(StatusCode::OK, config))
}
fn reply(status: StatusCode, config: &ServerConfig) -> Response<Empty<Bytes>> {
    let mut response = Response::new(Empty::new());
    *response.status_mut() = status;
    if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        for challenge in [
            config.username.as_ref().map(|_| "Basic realm=\"relay\""),
            (!config.bearer_token_sha256.is_empty()).then_some("Bearer realm=\"relay\""),
        ]
        .into_iter()
        .flatten()
        {
            response.headers_mut().append(
                hyper::header::PROXY_AUTHENTICATE,
                hyper::header::HeaderValue::from_static(challenge),
            );
        }
    }
    response
}
fn authorized(headers: &hyper::HeaderMap, config: &ServerConfig) -> bool {
    if config.username.is_none() && config.bearer_token_sha256.is_empty() {
        return true;
    }
    let mut values = headers.get_all(PROXY_AUTHORIZATION).iter();
    let Some(value) = values.next().and_then(|v| v.to_str().ok()) else {
        return false;
    };
    if values.next().is_some() {
        return false;
    }
    let Some((scheme, credential)) = value.split_once(' ') else {
        return false;
    };
    if scheme.eq_ignore_ascii_case("Basic") && config.username.is_some() {
        let Ok(decoded) = STANDARD.decode(credential) else {
            return false;
        };
        let expected = format!(
            "{}:{}",
            config.username.as_deref().unwrap_or_default(),
            config.password.as_deref().unwrap_or_default()
        );
        return bool::from(Sha256::digest(decoded).ct_eq(&Sha256::digest(expected)));
    }
    if scheme.eq_ignore_ascii_case("Bearer") && !credential.is_empty() {
        let digest = format!("{:x}", Sha256::digest(credential.as_bytes()));
        let mut matched = subtle::Choice::from(0);
        for expected in &config.bearer_token_sha256 {
            matched |= digest
                .as_bytes()
                .ct_eq(expected.to_ascii_lowercase().as_bytes());
        }
        return bool::from(matched);
    }
    false
}

async fn resolve_target(destination: &Destination, allow_private: bool) -> Option<SocketAddr> {
    match destination {
        Destination::Ip(address) => {
            (allow_private || crate::shadowsocks::public(address.ip())).then_some(*address)
        }
        Destination::Domain(name, port) => {
            let mut addresses = tokio::net::lookup_host((name.as_str(), *port)).await.ok()?;
            addresses.find(|address| allow_private || crate::shadowsocks::public(address.ip()))
        }
    }
}
