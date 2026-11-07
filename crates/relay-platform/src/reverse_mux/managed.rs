//! Panel-managed reverse tunnels on the mux protocol.
//!
//! A private server keeps one TLS connection to each public server it has
//! tunnels with, and that connection carries the streams and datagrams of
//! every such tunnel. The frames, credit flow control, datagrams and stream
//! lifecycle are the mux's own. What differs from the command-line tools:
//!
//! - The public server proves itself with a key it made: a self-signed
//!   Ed25519 certificate whose SHA-256 fingerprint the private server pins.
//!   No CA or host name is trusted.
//! - After `REVERSE-MUX-MANAGED 1` / `READY`, the private server attaches
//!   each tunnel with its own token: ATTACH (kind 9) with payload
//!   `<tunnel id> <token>`, answered by ATTACHED (10) or REFUSED (11) with a
//!   reason. Tokens travel only inside TLS. A connection that attaches
//!   nothing within 10 seconds, or is refused 64 times, is closed.
//! - OPEN carries the tunnel id after the feature word
//!   (`flow-control-v1 <id>` or `udp-v1 <id>`). The private server serves
//!   only tunnels it was given, on the protocols each allows, and always
//!   connects to the tunnel's own target: the public server cannot choose
//!   where the private server connects.
//! - The public end is not a listener of this module: the agent's rule
//!   engine accepts clients and asks [`Server::open_stream`] or
//!   [`Server::open_datagrams`] for a path through the tunnel, so metering,
//!   source ACLs and limits are the rule's own. That also lifts the CLI's
//!   "UDP needs `--max-controls 1`" restriction: each datagram association
//!   is bound to the connection it was opened on.
use super::*;
use serde::{Deserialize, Serialize};
use sha2::Digest;
use std::{
    collections::BTreeMap,
    sync::{RwLock as StdRwLock, Weak},
};
use tokio::sync::watch;
use tokio_rustls::rustls::{
    self, DigitallySignedStruct, SignatureScheme,
    client::danger::{HandshakeSignatureValid, ServerCertVerified, ServerCertVerifier},
    crypto::CryptoProvider,
    pki_types::UnixTime,
};

const HELLO: &str = "REVERSE-MUX-MANAGED 1";
const ATTACH: u8 = 9;
const ATTACHED: u8 = 10;
const REFUSED: u8 = 11;
const MAX_REFUSALS: u32 = 64;
const MAX_TUNNELS_PER_CONNECTION: usize = 1024;
const DATAGRAM_QUEUE: usize = 256;
/// The name the client sends in TLS; the server's key, not a name, is checked.
const SERVER_NAME: &str = "relay-reverse-tunnel";
const FIRST_RETRY: Duration = Duration::from_millis(500);
const LAST_RETRY: Duration = Duration::from_secs(30);
/// A connection that lasted this long resets the reconnect delay.
const STABLE: Duration = Duration::from_secs(10);
pub const UNKNOWN_TUNNEL: &str = "unknown tunnel";
pub const TOKEN_REJECTED: &str = "token rejected";

pub(super) fn is_reply(kind: u8) -> bool {
    matches!(kind, ATTACHED | REFUSED)
}

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

fn der(tag: u8, content: &[u8]) -> Vec<u8> {
    let mut out = vec![tag];
    let length = content.len();
    if length < 0x80 {
        out.push(length as u8);
    } else if length < 0x100 {
        out.extend([0x81, length as u8]);
    } else {
        out.extend([0x82, (length >> 8) as u8, length as u8]);
    }
    out.extend_from_slice(content);
    out
}

/// The public server's tunnel key and its self-signed certificate.
#[derive(Clone)]
pub struct Identity {
    key: Vec<u8>,
    certificate: Vec<u8>,
}
#[derive(Serialize, Deserialize)]
struct SavedIdentity {
    key: String,
    certificate: String,
}
impl Identity {
    /// A new Ed25519 key with a certificate for it; the certificate names
    /// nothing, because clients pin its fingerprint instead.
    pub fn generate() -> Result<Self> {
        use ring::signature::{Ed25519KeyPair, KeyPair};
        let random = ring::rand::SystemRandom::new();
        let pkcs8 = Ed25519KeyPair::generate_pkcs8(&random)
            .map_err(|_| anyhow::anyhow!("cannot make a tunnel key"))?;
        let pair = Ed25519KeyPair::from_pkcs8(pkcs8.as_ref())
            .map_err(|_| anyhow::anyhow!("cannot read the new tunnel key"))?;
        let mut serial = [0u8; 16];
        ring::rand::SecureRandom::fill(&random, &mut serial)
            .map_err(|_| anyhow::anyhow!("no randomness for the certificate"))?;
        serial[0] = (serial[0] & 0x7f) | 0x40;
        let algorithm = der(0x30, &der(0x06, &[0x2b, 0x65, 0x70]));
        let name = der(
            0x30,
            &der(
                0x31,
                &der(
                    0x30,
                    &[
                        der(0x06, &[0x55, 0x04, 0x03]),
                        der(0x0c, b"relay reverse tunnel"),
                    ]
                    .concat(),
                ),
            ),
        );
        let validity = der(
            0x30,
            &[der(0x17, b"250101000000Z"), der(0x18, b"99991231235959Z")].concat(),
        );
        let public_key = der(
            0x30,
            &[
                algorithm.clone(),
                der(0x03, &[&[0u8][..], pair.public_key().as_ref()].concat()),
            ]
            .concat(),
        );
        let tbs = der(
            0x30,
            &[
                der(0xa0, &der(0x02, &[2])),
                der(0x02, &serial),
                algorithm.clone(),
                name.clone(),
                validity,
                name,
                public_key,
            ]
            .concat(),
        );
        let signature = pair.sign(&tbs);
        let certificate = der(
            0x30,
            &[
                tbs,
                algorithm,
                der(0x03, &[&[0u8][..], signature.as_ref()].concat()),
            ]
            .concat(),
        );
        Ok(Self {
            key: pkcs8.as_ref().to_vec(),
            certificate,
        })
    }
    /// Lowercase hex SHA-256 of the certificate, which clients pin.
    pub fn fingerprint(&self) -> String {
        hex(&sha2::Sha256::digest(&self.certificate))
    }
    pub fn to_saved(&self) -> String {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        serde_json::to_string(&SavedIdentity {
            key: engine.encode(&self.key),
            certificate: engine.encode(&self.certificate),
        })
        .expect("serializable")
    }
    pub fn from_saved(saved: &str) -> Result<Self> {
        use base64::Engine;
        let engine = base64::engine::general_purpose::STANDARD;
        let saved: SavedIdentity = serde_json::from_str(saved).context("invalid tunnel key")?;
        let identity = Self {
            key: engine.decode(saved.key)?,
            certificate: engine.decode(saved.certificate)?,
        };
        identity.acceptor()?;
        Ok(identity)
    }
    fn acceptor(&self) -> Result<TlsAcceptor> {
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let config = ServerConfig::builder_with_provider(provider)
            .with_protocol_versions(&[&rustls::version::TLS13])?
            .with_no_client_auth()
            .with_single_cert(
                vec![CertificateDer::from(self.certificate.clone())],
                PrivateKeyDer::Pkcs8(self.key.clone().into()),
            )?;
        Ok(TlsAcceptor::from(Arc::new(config)))
    }
}

/// Accepts exactly the certificate whose SHA-256 is `fingerprint` and checks
/// that the server holds its key; no CA, name or validity period counts.
#[derive(Debug)]
struct Pinned {
    fingerprint: [u8; 32],
    provider: Arc<CryptoProvider>,
}
impl ServerCertVerifier for Pinned {
    fn verify_server_cert(
        &self,
        end_entity: &CertificateDer<'_>,
        _intermediates: &[CertificateDer<'_>],
        _server_name: &ServerName<'_>,
        _ocsp: &[u8],
        _now: UnixTime,
    ) -> std::result::Result<ServerCertVerified, rustls::Error> {
        let digest = sha2::Sha256::digest(end_entity.as_ref());
        if subtle::ConstantTimeEq::ct_eq(digest.as_slice(), &self.fingerprint).into() {
            Ok(ServerCertVerified::assertion())
        } else {
            Err(rustls::Error::InvalidCertificate(
                rustls::CertificateError::ApplicationVerificationFailure,
            ))
        }
    }
    fn verify_tls12_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls12_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn verify_tls13_signature(
        &self,
        message: &[u8],
        cert: &CertificateDer<'_>,
        dss: &DigitallySignedStruct,
    ) -> std::result::Result<HandshakeSignatureValid, rustls::Error> {
        rustls::crypto::verify_tls13_signature(
            message,
            cert,
            dss,
            &self.provider.signature_verification_algorithms,
        )
    }
    fn supported_verify_schemes(&self) -> Vec<SignatureScheme> {
        self.provider
            .signature_verification_algorithms
            .supported_schemes()
    }
}

/// Parses a 64-digit hex fingerprint.
pub fn parse_fingerprint(text: &str) -> Option<[u8; 32]> {
    if text.len() != 64 || !text.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let mut out = [0u8; 32];
    for (index, byte) in out.iter_mut().enumerate() {
        *byte = u8::from_str_radix(&text[index * 2..index * 2 + 2], 16).ok()?;
    }
    Some(out)
}

fn pinned_connector(fingerprint: &str) -> Result<TlsConnector> {
    let fingerprint = parse_fingerprint(fingerprint).context("invalid tunnel key fingerprint")?;
    let provider = Arc::new(rustls::crypto::ring::default_provider());
    let config = ClientConfig::builder_with_provider(provider.clone())
        .with_protocol_versions(&[&rustls::version::TLS13])?
        .dangerous()
        .with_custom_certificate_verifier(Arc::new(Pinned {
            fingerprint,
            provider,
        }))
        .with_no_client_auth();
    Ok(TlsConnector::from(Arc::new(config)))
}

/// A tunnel a public listener admits, with its token.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Admitted {
    pub id: String,
    pub token: String,
}
/// A tunnel listener of the public server and the tunnels it admits.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Listener {
    pub listen: SocketAddr,
    pub tunnels: Vec<Admitted>,
}
/// One tunnel as the public or private end sees it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Status {
    pub id: String,
    /// Time since the tunnel was attached on its current connection.
    pub connected_for: Option<Duration>,
    pub error: Option<String>,
}

/// One authenticated tunnel connection on the public server.
struct Control {
    writer: Writer,
    sessions: Sessions,
    responses: Responses,
    datagrams: StdMutex<HashMap<u32, mpsc::Sender<Vec<u8>>>>,
    next_id: AtomicU32,
    cancel: CancellationToken,
}
struct Running {
    cancel: CancellationToken,
    error: Option<String>,
}
#[derive(Default)]
struct ServerState {
    identity: Option<(String, TlsAcceptor)>,
    listeners: HashMap<SocketAddr, Running>,
    /// Tunnel id to the listener that admits it and its token.
    tunnels: HashMap<String, (SocketAddr, String)>,
    /// Tunnel id to the connection it is attached on, and since when.
    controls: HashMap<String, (Arc<Control>, std::time::Instant)>,
}

/// The public end: tunnel listeners and the connections attached to them.
#[derive(Default)]
pub struct Server(StdMutex<ServerState>);

impl Server {
    /// Makes `listeners` the running set. Tunnels left out lose their
    /// connection at once; a listener left out closes with its connections.
    /// A listener that could not bind is retried on the next call.
    pub fn reconcile(self: &Arc<Self>, identity: Option<&Identity>, listeners: &[Listener]) {
        let mut state = self.0.lock().unwrap();
        let fingerprint = identity.map(Identity::fingerprint);
        if state.identity.as_ref().map(|(f, _)| f) != fingerprint.as_ref() {
            state.identity = identity.and_then(|identity| {
                identity
                    .acceptor()
                    .map_err(|error| tracing::warn!(%error, "tunnel key unusable"))
                    .ok()
                    .map(|acceptor| (identity.fingerprint(), acceptor))
            });
            // Connections made with the old key end with it.
            for running in state.listeners.values() {
                running.cancel.cancel();
            }
            state.listeners.clear();
        }
        state.tunnels = listeners
            .iter()
            .flat_map(|listener| {
                listener.tunnels.iter().map(|tunnel| {
                    (
                        tunnel.id.clone(),
                        (listener.listen, tunnel.token.to_ascii_lowercase()),
                    )
                })
            })
            .collect();
        let ServerState {
            tunnels, controls, ..
        } = &mut *state;
        controls.retain(|id, _| tunnels.contains_key(id));
        let wanted: HashMap<SocketAddr, ()> = if state.identity.is_some() {
            listeners.iter().map(|l| (l.listen, ())).collect()
        } else {
            HashMap::new()
        };
        state.listeners.retain(|address, running| {
            let keep = wanted.contains_key(address) && running.error.is_none();
            if !keep {
                running.cancel.cancel();
            }
            keep
        });
        for address in wanted.keys() {
            if state.listeners.contains_key(address) {
                continue;
            }
            let cancel = CancellationToken::new();
            let error = match bind(*address) {
                Ok(listener) => {
                    tokio::spawn(accept(
                        Arc::downgrade(self),
                        listener,
                        *address,
                        cancel.clone(),
                    ));
                    None
                }
                Err(error) => {
                    tracing::warn!(%address, %error, "tunnel listener cannot start");
                    Some(format!("tunnel port {}: {error}", address.port()))
                }
            };
            state.listeners.insert(*address, Running { cancel, error });
        }
    }
    pub fn shutdown(&self) {
        let mut state = self.0.lock().unwrap();
        for running in state.listeners.values() {
            running.cancel.cancel();
        }
        state.listeners.clear();
        state.controls.clear();
        state.tunnels.clear();
    }
    pub fn status(&self) -> Vec<Status> {
        let state = self.0.lock().unwrap();
        let mut out: Vec<Status> = state
            .tunnels
            .iter()
            .map(|(id, (listen, _))| Status {
                id: id.clone(),
                connected_for: state
                    .controls
                    .get(id)
                    .filter(|(control, _)| !control.cancel.is_cancelled())
                    .map(|(_, at)| at.elapsed()),
                error: state.listeners.get(listen).and_then(|r| r.error.clone()),
            })
            .collect();
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }
    fn acceptor(&self) -> Option<TlsAcceptor> {
        self.0
            .lock()
            .unwrap()
            .identity
            .as_ref()
            .map(|(_, a)| a.clone())
    }
    fn control(&self, tunnel: &str) -> Result<Arc<Control>> {
        self.0
            .lock()
            .unwrap()
            .controls
            .get(tunnel)
            .filter(|(control, _)| !control.cancel.is_cancelled())
            .map(|(control, _)| control.clone())
            .context("the private server is not connected to this tunnel")
    }
    fn attach(
        &self,
        listen: SocketAddr,
        payload: &[u8],
        control: &Arc<Control>,
    ) -> std::result::Result<(), &'static str> {
        let text = std::str::from_utf8(payload).map_err(|_| "malformed attach")?;
        let (id, token) = text.split_once(' ').ok_or("malformed attach")?;
        let mut state = self.0.lock().unwrap();
        let Some((at, expected)) = state.tunnels.get(id) else {
            return Err(UNKNOWN_TUNNEL);
        };
        if *at != listen {
            return Err(UNKNOWN_TUNNEL);
        }
        if !token_matches(expected, &token.to_ascii_lowercase()) {
            return Err(TOKEN_REJECTED);
        }
        let attached = state
            .controls
            .values()
            .filter(|(c, _)| Arc::ptr_eq(c, control))
            .count();
        if attached >= MAX_TUNNELS_PER_CONNECTION {
            return Err("too many tunnels on one connection");
        }
        // A newer connection for the same tunnel replaces the older one.
        state
            .controls
            .insert(id.to_owned(), (control.clone(), std::time::Instant::now()));
        Ok(())
    }
    fn detach(&self, control: &Arc<Control>) {
        self.0
            .lock()
            .unwrap()
            .controls
            .retain(|_, (c, _)| !Arc::ptr_eq(c, control));
    }

    /// A byte stream to the tunnel's target, opened by the private server.
    /// `idle` closes the stream after that long without data either way.
    pub async fn open_stream(
        &self,
        tunnel: &str,
        idle: Duration,
    ) -> Result<tokio::io::DuplexStream> {
        let control = self.control(tunnel)?;
        let id = control.next_id.fetch_add(1, Ordering::Relaxed);
        let stream_cancel = control.cancel.child_token();
        let flow = StreamFlow::with_limit(false, 0);
        let (data_tx, data_rx) = mpsc::channel(STREAM_QUEUE_CAPACITY);
        let (response_tx, response_rx) = oneshot::channel();
        control.sessions.lock().await.insert(
            id,
            StreamInbox {
                sender: data_tx,
                cancel: stream_cancel.clone(),
                flow: flow.clone(),
            },
        );
        control.responses.lock().await.insert(id, response_tx);
        let open = [FLOW_CONTROL_V1, b" ", tunnel.as_bytes()].concat();
        let opened = write_frame(&control.writer, OPEN, id, &open).await.is_ok()
            && tokio::select! {
                response = tokio::time::timeout(OPEN_TIMEOUT, response_rx) =>
                    response.ok().and_then(Result::ok).unwrap_or(false),
                _ = stream_cancel.cancelled() => false,
            };
        if !opened {
            control.sessions.lock().await.remove(&id);
            control.responses.lock().await.remove(&id);
            stream_cancel.cancel();
            let _ = write_frame(&control.writer, RESET, id, &[]).await;
            bail!("the private server could not connect to the target");
        }
        let (near, far) = tokio::io::duplex(64 * 1024);
        tokio::spawn(async move {
            let result = bridge_io(
                id,
                far,
                data_rx,
                &control.writer,
                &stream_cancel,
                &flow,
                Some(idle),
                false,
            )
            .await;
            control.sessions.lock().await.remove(&id);
            stream_cancel.cancel();
            if let Err(error) = result {
                let _ = write_frame(&control.writer, RESET, id, &[]).await;
                tracing::debug!(%error, "reverse tunnel stream ended");
            }
        });
        Ok(near)
    }
    /// A datagram association with the tunnel's UDP target.
    pub async fn open_datagrams(&self, tunnel: &str) -> Result<Datagrams> {
        let control = self.control(tunnel)?;
        let id = control.next_id.fetch_add(1, Ordering::Relaxed);
        let (sender, incoming) = mpsc::channel(DATAGRAM_QUEUE);
        control.datagrams.lock().unwrap().insert(id, sender);
        let open = [UDP_FEATURE, b" ", tunnel.as_bytes()].concat();
        if let Err(error) = write_frame(&control.writer, OPEN, id, &open).await {
            control.datagrams.lock().unwrap().remove(&id);
            return Err(error.into());
        }
        Ok(Datagrams {
            control,
            id,
            incoming: Mutex::new(incoming),
        })
    }
}

/// One UDP association through a tunnel. Dropping it closes the association.
pub struct Datagrams {
    control: Arc<Control>,
    id: u32,
    incoming: Mutex<mpsc::Receiver<Vec<u8>>>,
}
impl Datagrams {
    pub async fn send(&self, payload: &[u8]) -> std::io::Result<()> {
        write_frame(&self.control.writer, DATAGRAM, self.id, payload).await
    }
    /// The next reply; `None` once the private server or the connection
    /// closed the association.
    pub async fn recv(&self) -> Option<Vec<u8>> {
        self.incoming.lock().await.recv().await
    }
}
impl Drop for Datagrams {
    fn drop(&mut self) {
        let open = self
            .control
            .datagrams
            .lock()
            .unwrap()
            .remove(&self.id)
            .is_some();
        if open
            && !self.control.cancel.is_cancelled()
            && let Ok(runtime) = tokio::runtime::Handle::try_current()
        {
            let writer = self.control.writer.clone();
            let id = self.id;
            runtime.spawn(async move {
                let _ = write_frame(&writer, FIN, id, &[]).await;
            });
        }
    }
}

fn bind(address: SocketAddr) -> std::io::Result<TcpListener> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(address),
        socket2::Type::STREAM,
        Some(socket2::Protocol::TCP),
    )?;
    socket.set_reuse_address(true)?;
    if address.is_ipv6() && address.ip().is_unspecified() {
        // `[::]` takes IPv4 clients too, as rule listeners do.
        socket.set_only_v6(false)?;
    }
    socket.set_nonblocking(true)?;
    socket.bind(&address.into())?;
    socket.listen(1024)?;
    TcpListener::from_std(socket.into())
}

async fn accept(
    server: Weak<Server>,
    listener: TcpListener,
    listen: SocketAddr,
    cancel: CancellationToken,
) {
    let pending = Arc::new(Semaphore::new(MAX_PENDING_HANDSHAKES));
    loop {
        let (stream, peer) = tokio::select! {
            _ = cancel.cancelled() => return,
            accepted = listener.accept() => match accepted {
                Ok(pair) => pair,
                Err(error) => {
                    tracing::warn!(%error, "tunnel accept failed");
                    tokio::time::sleep(Duration::from_millis(100)).await;
                    continue;
                }
            },
        };
        stream.set_nodelay(true).ok();
        let Ok(permit) = pending.clone().try_acquire_owned() else {
            tracing::warn!(%peer, "tunnel handshake capacity is full");
            continue;
        };
        let Some(acceptor) = server.upgrade().and_then(|s| s.acceptor()) else {
            return;
        };
        let server = server.clone();
        let cancel = cancel.child_token();
        tokio::spawn(async move {
            let mut stream =
                match tokio::time::timeout(TLS_HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                    Ok(Ok(stream)) => stream,
                    Ok(Err(error)) => {
                        tracing::debug!(%peer, %error, "tunnel TLS handshake failed");
                        return;
                    }
                    Err(_) => return,
                };
            let hello = tokio::time::timeout(AUTH_TIMEOUT, read_line(&mut stream)).await;
            if !matches!(hello, Ok(Ok(ref line)) if line == HELLO) {
                let _ = tokio::time::timeout(AUTH_TIMEOUT, stream.write_all(b"DENY\n")).await;
                return;
            }
            if !matches!(
                tokio::time::timeout(AUTH_TIMEOUT, stream.write_all(b"READY\n")).await,
                Ok(Ok(()))
            ) {
                return;
            }
            serve(server, stream, listen, peer, permit, cancel).await;
        });
    }
}

async fn serve<S>(
    server: Weak<Server>,
    stream: S,
    listen: SocketAddr,
    peer: SocketAddr,
    permit: OwnedSemaphorePermit,
    cancel: CancellationToken,
) where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (reader, writer) = tokio::io::split(stream);
    let _close = cancel.clone().drop_guard();
    let control = Arc::new(Control {
        writer: Arc::new(ControlWriter {
            stream: Mutex::new(Box::new(writer)),
            cancel: cancel.clone(),
        }),
        sessions: Arc::default(),
        responses: Arc::default(),
        datagrams: StdMutex::new(HashMap::new()),
        next_id: AtomicU32::new(1),
        cancel: cancel.clone(),
    });
    let mut reader: ControlRead = Box::new(reader);
    // Held until the first tunnel is attached, so unauthenticated
    // connections stay bounded; they get AUTH_TIMEOUT to attach one.
    let mut permit = Some(permit);
    let deadline = tokio::time::Instant::now() + AUTH_TIMEOUT;
    let mut refusals = 0;
    loop {
        let frame = tokio::select! {
            _ = cancel.cancelled() => break,
            _ = tokio::time::sleep_until(deadline), if permit.is_some() => {
                tracing::warn!(%peer, "tunnel connection attached no tunnel in time");
                break;
            }
            frame = read_frame(&mut reader) => frame,
        };
        let Ok(Some((kind, id, payload))) = frame else {
            break;
        };
        if matches!(kind, FAIL | FIN | RESET) {
            control.datagrams.lock().unwrap().remove(&id);
        }
        match kind {
            ATTACH => {
                let Some(server) = server.upgrade() else {
                    break;
                };
                let (reply, reason) = match server.attach(listen, &payload, &control) {
                    Ok(()) => {
                        permit = None;
                        (ATTACHED, "")
                    }
                    Err(reason) => {
                        refusals += 1;
                        tracing::warn!(%peer, reason, "tunnel attach refused");
                        (REFUSED, reason)
                    }
                };
                let writer = control.writer.clone();
                tokio::spawn(async move {
                    let _ = write_frame(&writer, reply, id, reason.as_bytes()).await;
                });
                if refusals >= MAX_REFUSALS {
                    break;
                }
            }
            OK | FAIL => {
                if kind == OK
                    && payload == FLOW_CONTROL_V1
                    && let Some(inbox) = control.sessions.lock().await.get(&id)
                {
                    inbox.flow.enabled.store(true, Ordering::Relaxed);
                }
                if let Some(response) = control.responses.lock().await.remove(&id) {
                    let _ = response.send(kind == OK);
                }
            }
            DATA | FIN | RESET | WINDOW => {
                dispatch_frame(&control.sessions, id, kind, payload).await
            }
            DATAGRAM => {
                let sender = control.datagrams.lock().unwrap().get(&id).cloned();
                if let Some(sender) = sender
                    && sender.try_send(payload).is_err()
                {
                    UDP_DROPPED.fetch_add(1, Ordering::Relaxed);
                }
            }
            _ => {}
        }
    }
    cancel.cancel();
    control.datagrams.lock().unwrap().clear();
    if let Some(server) = server.upgrade() {
        server.detach(&control);
    }
}

/// A tunnel the private server dials.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Dial {
    pub id: String,
    /// `host:port` of the public server's tunnel listener.
    pub server: String,
    pub fingerprint: String,
    pub token: String,
    /// `host:port` the private server connects to.
    pub target: String,
    pub tcp: bool,
    pub udp: bool,
}
#[derive(Clone, Debug)]
pub(super) struct Route {
    target: String,
    tcp: bool,
    udp: bool,
}
pub(super) type Routes = Arc<StdRwLock<HashMap<String, Route>>>;

/// What the private server does with an OPEN: (udp, flow control, TCP
/// target, UDP mode), or `None` to refuse it.
pub(super) fn route(
    routes: &Routes,
    payload: &[u8],
) -> Option<(bool, bool, String, Option<UdpMode>)> {
    let split = payload.iter().position(|b| *b == b' ')?;
    let (feature, tunnel) = (&payload[..split], &payload[split + 1..]);
    let tunnel = std::str::from_utf8(tunnel).ok()?;
    let route = routes.read().unwrap().get(tunnel).cloned()?;
    if feature == UDP_FEATURE && route.udp {
        Some((
            true,
            false,
            String::new(),
            Some(UdpMode::Fixed(route.target)),
        ))
    } else if feature == FLOW_CONTROL_V1 && route.tcp {
        Some((false, true, route.target, None))
    } else {
        None
    }
}

#[derive(Default)]
struct TunnelState {
    attached_at: Option<std::time::Instant>,
    error: Option<String>,
}
#[derive(Default)]
struct GroupState {
    /// Why the connection is down, while it is.
    error: Option<String>,
    tunnels: HashMap<String, TunnelState>,
}
struct Group {
    routes: Routes,
    tokens: watch::Sender<BTreeMap<String, String>>,
    state: Arc<StdMutex<GroupState>>,
    cancel: CancellationToken,
}

/// The private end: one connection per public server and key.
#[derive(Default)]
pub struct Client(StdMutex<HashMap<(String, String), Group>>);

impl Client {
    /// Makes `dials` the tunnels this server keeps. Tunnels to the same
    /// server and key share a connection; adding or removing one attaches
    /// or forgets it on that connection without reconnecting.
    pub fn reconcile(&self, dials: &[Dial]) {
        let mut wanted: HashMap<(String, String), Vec<&Dial>> = HashMap::new();
        for dial in dials {
            wanted
                .entry((dial.server.clone(), dial.fingerprint.to_ascii_lowercase()))
                .or_default()
                .push(dial);
        }
        let mut groups = self.0.lock().unwrap();
        groups.retain(|key, group| {
            let keep = wanted.contains_key(key);
            if !keep {
                group.cancel.cancel();
            }
            keep
        });
        for (key, dials) in wanted {
            let routes: HashMap<String, Route> = dials
                .iter()
                .map(|d| {
                    (
                        d.id.clone(),
                        Route {
                            target: d.target.clone(),
                            tcp: d.tcp,
                            udp: d.udp,
                        },
                    )
                })
                .collect();
            let tokens: BTreeMap<String, String> = dials
                .iter()
                .map(|d| (d.id.clone(), d.token.to_ascii_lowercase()))
                .collect();
            if let Some(group) = groups.get(&key) {
                *group.routes.write().unwrap() = routes;
                group
                    .state
                    .lock()
                    .unwrap()
                    .tunnels
                    .retain(|id, _| tokens.contains_key(id));
                group.tokens.send_if_modified(|current| {
                    let changed = *current != tokens;
                    *current = tokens;
                    changed
                });
                continue;
            }
            let routes: Routes = Arc::new(StdRwLock::new(routes));
            let (sender, receiver) = watch::channel(tokens);
            let state = Arc::new(StdMutex::new(GroupState::default()));
            let cancel = CancellationToken::new();
            tokio::spawn(run_group(
                key.0.clone(),
                key.1.clone(),
                routes.clone(),
                receiver,
                state.clone(),
                cancel.clone(),
            ));
            groups.insert(
                key,
                Group {
                    routes,
                    tokens: sender,
                    state,
                    cancel,
                },
            );
        }
    }
    pub fn shutdown(&self) {
        for (_, group) in self.0.lock().unwrap().drain() {
            group.cancel.cancel();
        }
    }
    pub fn status(&self) -> Vec<Status> {
        let groups = self.0.lock().unwrap();
        let mut out = vec![];
        for group in groups.values() {
            let state = group.state.lock().unwrap();
            for id in group.tokens.borrow().keys() {
                let tunnel = state.tunnels.get(id);
                let connected_for = tunnel
                    .and_then(|t| t.attached_at)
                    .filter(|_| state.error.is_none())
                    .map(|at| at.elapsed());
                out.push(Status {
                    id: id.clone(),
                    connected_for,
                    error: if connected_for.is_some() {
                        None
                    } else {
                        state
                            .error
                            .clone()
                            .or_else(|| tunnel.and_then(|t| t.error.clone()))
                    },
                });
            }
        }
        out.sort_by(|a, b| a.id.cmp(&b.id));
        out
    }
}
impl Drop for Client {
    fn drop(&mut self) {
        self.shutdown();
    }
}
impl Drop for Server {
    fn drop(&mut self) {
        for running in self.0.get_mut().unwrap().listeners.values() {
            running.cancel.cancel();
        }
    }
}

async fn run_group(
    server: String,
    fingerprint: String,
    routes: Routes,
    mut tokens: watch::Receiver<BTreeMap<String, String>>,
    state: Arc<StdMutex<GroupState>>,
    cancel: CancellationToken,
) {
    let mut delay = FIRST_RETRY;
    loop {
        let started = std::time::Instant::now();
        let result = tokio::select! {
            _ = cancel.cancelled() => return,
            result = session(&server, &fingerprint, &routes, &mut tokens, &state) => result,
        };
        let error = match result {
            Ok(()) => return,
            Err(error) => format!("{error:#}"),
        };
        tracing::debug!(%server, %error, "reverse tunnel connection ended");
        {
            let mut state = state.lock().unwrap();
            state.error = Some(error);
            for tunnel in state.tunnels.values_mut() {
                tunnel.attached_at = None;
            }
        }
        if started.elapsed() >= STABLE {
            delay = FIRST_RETRY;
        }
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = tokio::time::sleep(delay) => {}
        }
        delay = (delay * 2).min(LAST_RETRY);
    }
}

fn describe_tls(error: std::io::Error) -> anyhow::Error {
    let pinned = error
        .get_ref()
        .and_then(|inner| inner.downcast_ref::<rustls::Error>())
        .is_some_and(|inner| {
            matches!(
                inner,
                rustls::Error::InvalidCertificate(
                    rustls::CertificateError::ApplicationVerificationFailure
                )
            )
        });
    if pinned {
        anyhow::anyhow!("the public server's key does not match its reported fingerprint")
    } else {
        anyhow::Error::from(error).context("TLS handshake with the public server failed")
    }
}

/// One connection: attaches every wanted tunnel and keeps attaching new
/// ones until the connection ends (an error) or the group stops (`Ok`).
async fn session(
    server: &str,
    fingerprint: &str,
    routes: &Routes,
    tokens: &mut watch::Receiver<BTreeMap<String, String>>,
    state: &StdMutex<GroupState>,
) -> Result<()> {
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, TcpStream::connect(server))
        .await
        .map_err(|_| anyhow::anyhow!("connecting to {server} timed out"))?
        .with_context(|| format!("cannot connect to {server}"))?;
    tcp.set_nodelay(true).ok();
    let connector = pinned_connector(fingerprint)?;
    let mut control = tokio::time::timeout(
        TLS_HANDSHAKE_TIMEOUT,
        connector.connect(ServerName::try_from(SERVER_NAME)?, tcp),
    )
    .await
    .map_err(|_| anyhow::anyhow!("TLS handshake with {server} timed out"))?
    .map_err(describe_tls)?;
    control.write_all(format!("{HELLO}\n").as_bytes()).await?;
    let reply = tokio::time::timeout(AUTH_TIMEOUT, read_line(&mut control))
        .await
        .map_err(|_| anyhow::anyhow!("the public server did not answer"))??;
    ensure!(
        reply == READY,
        "the public server refused the tunnel connection"
    );
    state.lock().unwrap().error = None;
    let (reader, writer) = tokio::io::split(control);
    let cancel = CancellationToken::new();
    let _cancel_on_exit = cancel.clone().drop_guard();
    let writer = Arc::new(ControlWriter {
        stream: Mutex::new(Box::new(writer)),
        cancel: cancel.clone(),
    });
    let (replies, mut replies_rx) = mpsc::unbounded_channel();
    let mut reader = tokio::spawn(client_read_loop_with(
        Box::new(reader),
        ClientTargets::Managed {
            routes: routes.clone(),
            replies,
        },
        writer.clone(),
        Arc::default(),
        cancel.clone(),
    ));
    let mut pending: HashMap<u32, (String, String)> = HashMap::new();
    let mut attached: HashMap<String, String> = HashMap::new();
    let mut retry: HashMap<String, (std::time::Instant, Duration)> = HashMap::new();
    let mut sequence = 0u32;
    let mut tick = tokio::time::interval(Duration::from_millis(500));
    loop {
        let wanted = tokens.borrow_and_update().clone();
        attached.retain(|id, token| wanted.get(id) == Some(token));
        let now = std::time::Instant::now();
        for (id, token) in &wanted {
            if attached.contains_key(id)
                || pending.values().any(|(p, _)| p == id)
                || retry.get(id).is_some_and(|(at, _)| *at > now)
            {
                continue;
            }
            sequence = sequence.wrapping_add(1);
            pending.insert(sequence, (id.clone(), token.clone()));
            write_frame(
                &writer,
                ATTACH,
                sequence,
                format!("{id} {token}").as_bytes(),
            )
            .await?;
        }
        tokio::select! {
            _ = &mut reader => bail!("the public server closed the tunnel connection"),
            changed = tokens.changed() => if changed.is_err() { return Ok(()) },
            reply = replies_rx.recv() => {
                let Some((kind, sequence, reason)) = reply else {
                    bail!("the tunnel connection closed");
                };
                let Some((id, token)) = pending.remove(&sequence) else { continue };
                let mut state = state.lock().unwrap();
                let tunnel = state.tunnels.entry(id.clone()).or_default();
                if kind == ATTACHED {
                    tunnel.attached_at = Some(std::time::Instant::now());
                    tunnel.error = None;
                    retry.remove(&id);
                    attached.insert(id, token);
                } else {
                    let reason = String::from_utf8_lossy(&reason).into_owned();
                    tunnel.attached_at = None;
                    tunnel.error = Some(match reason.as_str() {
                        UNKNOWN_TUNNEL => "the public server does not have this tunnel yet".into(),
                        TOKEN_REJECTED => "the public server rejected the tunnel token".into(),
                        _ => format!("the public server refused the tunnel: {reason}"),
                    });
                    let wait = retry.get(&id).map_or(Duration::from_secs(1), |(_, d)| (*d * 2).min(LAST_RETRY));
                    retry.insert(id, (std::time::Instant::now() + wait, wait));
                }
            }
            _ = tick.tick() => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    async fn echo() -> (SocketAddr, SocketAddr) {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap();
        tokio::spawn(async move {
            loop {
                let Ok((mut stream, _)) = tcp.accept().await else {
                    return;
                };
                tokio::spawn(async move {
                    let mut buffer = [0u8; 1024];
                    while let Ok(n) = stream.read(&mut buffer).await {
                        if n == 0 || stream.write_all(&buffer[..n]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let udp_address = udp.local_addr().unwrap();
        tokio::spawn(async move {
            let mut buffer = [0u8; 2048];
            while let Ok((n, peer)) = udp.recv_from(&mut buffer).await {
                let _ = udp.send_to(&buffer[..n], peer).await;
            }
        });
        (address, udp_address)
    }

    fn free() -> SocketAddr {
        std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
    }

    async fn wait_status(client: &Client, id: &str, connected: bool) -> Status {
        for _ in 0..200 {
            if let Some(status) = client.status().into_iter().find(|s| s.id == id)
                && status.connected_for.is_some() == connected
                && (connected || status.error.is_some())
            {
                return status;
            }
            tokio::time::sleep(Duration::from_millis(25)).await;
        }
        panic!("tunnel {id} never became connected={connected}");
    }

    #[test]
    fn identity_survives_saving_and_has_a_stable_fingerprint() {
        let identity = Identity::generate().unwrap();
        let fingerprint = identity.fingerprint();
        assert!(parse_fingerprint(&fingerprint).is_some());
        let restored = Identity::from_saved(&identity.to_saved()).unwrap();
        assert_eq!(restored.fingerprint(), fingerprint);
        assert_ne!(Identity::generate().unwrap().fingerprint(), fingerprint);
        assert!(parse_fingerprint("zz").is_none());
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 4)]
    async fn tunnels_share_one_connection_and_refuse_wrong_keys_and_tokens() {
        let (tcp_target, udp_target) = echo().await;
        let (second_target, _) = echo().await;
        let identity = Identity::generate().unwrap();
        let server = Arc::new(Server::default());
        let listen = free();
        let token = "ab".repeat(32);
        server.reconcile(
            Some(&identity),
            &[Listener {
                listen,
                tunnels: vec![
                    Admitted {
                        id: "one".into(),
                        token: token.clone(),
                    },
                    Admitted {
                        id: "two".into(),
                        token: "cd".repeat(32),
                    },
                ],
            }],
        );
        let client = Client::default();
        let dial = |id: &str, token: &str, target: SocketAddr, udp: bool| Dial {
            id: id.into(),
            server: listen.to_string(),
            fingerprint: identity.fingerprint(),
            token: token.into(),
            target: target.to_string(),
            tcp: true,
            udp,
        };
        client.reconcile(&[dial("one", &token, tcp_target, false)]);
        wait_status(&client, "one", true).await;
        let mut stream = server
            .open_stream("one", Duration::from_secs(10))
            .await
            .unwrap();
        stream.write_all(b"ping").await.unwrap();
        let mut reply = [0u8; 4];
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"ping");
        // UDP was not allowed for this tunnel: the association is refused.
        let refused = server.open_datagrams("one").await.unwrap();
        refused.send(b"no").await.unwrap();
        assert!(
            tokio::time::timeout(Duration::from_secs(2), refused.recv())
                .await
                .unwrap()
                .is_none()
        );
        // A second tunnel joins the same connection; the first keeps its stream.
        client.reconcile(&[
            dial("one", &token, udp_target, true),
            dial("two", &"cd".repeat(32), second_target, false),
        ]);
        wait_status(&client, "two", true).await;
        stream.write_all(b"pong").await.unwrap();
        stream.read_exact(&mut reply).await.unwrap();
        assert_eq!(&reply, b"pong");
        assert_eq!(
            client.0.lock().unwrap().len(),
            1,
            "both tunnels share one connection"
        );
        let datagrams = server.open_datagrams("one").await.unwrap();
        datagrams.send(b"datagram").await.unwrap();
        assert_eq!(
            tokio::time::timeout(Duration::from_secs(2), datagrams.recv())
                .await
                .unwrap()
                .unwrap(),
            b"datagram"
        );
        // A wrong token is refused and reported; the right one still works.
        let other = Client::default();
        other.reconcile(&[dial("two", &"ee".repeat(32), second_target, false)]);
        let status = wait_status(&other, "two", false).await;
        assert!(status.error.unwrap().contains("rejected the tunnel token"));
        // A key other than the pinned one fails the TLS handshake.
        let impostor = Client::default();
        let mut wrong = dial("one", &token, tcp_target, false);
        wrong.fingerprint = Identity::generate().unwrap().fingerprint();
        impostor.reconcile(&[wrong]);
        let status = wait_status(&impostor, "one", false).await;
        assert!(
            status.error.as_deref().unwrap().contains("does not match"),
            "{status:?}"
        );
        // Removing a tunnel on the public side drops its connection mapping.
        server.reconcile(
            Some(&identity),
            &[Listener {
                listen,
                tunnels: vec![Admitted {
                    id: "two".into(),
                    token: "cd".repeat(32),
                }],
            }],
        );
        assert!(
            server
                .open_stream("one", Duration::from_secs(1))
                .await
                .is_err()
        );
        assert!(server.status().iter().all(|s| s.id == "two"));
        client.shutdown();
        server.shutdown();
    }
}
