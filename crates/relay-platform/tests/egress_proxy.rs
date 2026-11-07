//! Egress proxies: real agents on loopback send the destinations of SOCKS5,
//! HTTP CONNECT, HTTP/2 CONNECT and Shadowsocks rules through an upstream
//! SOCKS5 proxy that requires a username and password. The upstream
//! connects onward from its own address (127.0.0.2), so a target that sees
//! any other peer was reached directly. Also: falling back to the next
//! server, a wrong password, destination rules applied before the upstream,
//! UDP refused, and the 409 for servers whose agent is too old.
mod common;
use common::*;
use relay_platform::{
    agent::{self, AgentOptions},
    api::{self, AppState},
    egress, http_connect, http2_connect, logs,
    model::*,
    shadowsocks, socks5,
    store::{Store, write_secret},
};
use serde_json::{Value, json};
use std::{
    net::{IpAddr, Ipv4Addr, SocketAddr},
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpSocket, TcpStream, UdpSocket},
    time::{Instant, sleep, timeout},
};
use tokio_util::sync::CancellationToken;

const UPSTREAM_USER: &str = "relay-egress";
const UPSTREAM_PASSWORD: &str = "upstream-Pass-9Zq";
/// A name only the test upstream knows: the agent cannot resolve it.
const TARGET_NAME: &str = "target.egress.test";
/// Where the upstream connects onward from.
const UPSTREAM_SOURCE: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);

async fn serve(store: Store) -> (SocketAddr, CancellationToken) {
    let stop = CancellationToken::new();
    let router = api::router(AppState::new(store).with_shutdown(stop.clone()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = stop.clone();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await
        .unwrap();
    });
    (address, stop)
}
struct Api {
    client: reqwest::Client,
    origin: String,
    token: String,
}
impl Api {
    async fn new(address: SocketAddr) -> Self {
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let origin = format!("http://{address}");
        let body: Value = client
            .post(format!("{origin}/api/v1/auth/login"))
            .json(&json!({"username": "admin", "password": PASSWORD}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let token = body["token"].as_str().unwrap().to_string();
        Self {
            client,
            origin,
            token,
        }
    }
    async fn call(&self, method: reqwest::Method, path: &str, body: Option<Value>) -> (u16, Value) {
        let request = self
            .client
            .request(method, format!("{}/api/v1{path}", self.origin))
            .bearer_auth(&self.token);
        let request = match body {
            Some(body) => request.json(&body),
            None => request,
        };
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let text = response.text().await.unwrap();
        (
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }
    async fn get(&self, path: &str) -> Value {
        let (code, body) = self.call(reqwest::Method::GET, path, None).await;
        assert_eq!(code, 200, "GET {path}: {body}");
        body
    }
    async fn node(&self, id: &str) -> Value {
        let nodes = self.get("/nodes").await;
        nodes
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["id"] == id)
            .unwrap()
            .clone()
    }
    /// Publishes `rules` on `node` at its current revision.
    async fn publish(&self, node: &str, rules: &[&Rule]) -> (u16, Value) {
        let config = self.get(&format!("/nodes/{node}/config")).await;
        self.call(
            reqwest::Method::PUT,
            &format!("/nodes/{node}/config"),
            Some(json!({ "expected_revision": config["revision"], "rules": rules })),
        )
        .await
    }
    /// Publishes and waits until the node's agent applied it.
    async fn apply(&self, node: &str, rules: &[&Rule]) {
        let (code, config) = self.publish(node, rules).await;
        assert_eq!(code, 200, "{config}");
        let revision = config["revision"].clone();
        self.until("the agent to apply the configuration", || async {
            self.node(node).await["applied_revision"] == revision
        })
        .await;
    }
    async fn until<F: std::future::Future<Output = bool>>(
        &self,
        what: &str,
        check: impl Fn() -> F,
    ) {
        let until = Instant::now() + Duration::from_secs(20);
        while !check().await {
            assert!(Instant::now() < until, "waiting for {what}");
            sleep(Duration::from_millis(50)).await;
        }
    }
    async fn stat(&self, node: &str, name: &str) -> u64 {
        self.node(node).await["stats"][name].as_u64().unwrap_or(0)
    }
}

/// Real agents for `nodes`, stopped on drop.
struct Agents(Vec<CancellationToken>);
impl Agents {
    fn start(dir: &Path, origin: &str, nodes: &[(&str, &str)]) -> Self {
        let mut stops = vec![];
        for (index, (node, enrollment)) in nodes.iter().enumerate() {
            let secret = dir.join(format!("agent-{node}-{index}.secret"));
            write_secret(&secret, enrollment.as_bytes()).unwrap();
            let db = Store::open(&dir.join(format!("agent-{node}-{index}.db"))).unwrap();
            let stop = CancellationToken::new();
            let options = AgentOptions {
                controller: origin.into(),
                node_id: (*node).into(),
                enrollment_token_file: Some(secret),
                ca_certificate: None,
                tls_directory: None,
                poll_interval: Duration::from_millis(50),
                controller_addresses: vec![],
                controller_proxy: None,
            };
            tokio::spawn(agent::run(db, options, stop.clone()));
            stops.push(stop);
        }
        Self(stops)
    }
}
impl Drop for Agents {
    fn drop(&mut self) {
        for stop in &self.0 {
            stop.cancel();
        }
    }
}

struct Panel {
    temp: tempfile::TempDir,
    store: Store,
    admin: relay_platform::store::Actor,
    api: Api,
    stop: CancellationToken,
}
impl Panel {
    async fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("controller.db")).unwrap();
        store.set_kind("controller").unwrap();
        let admin = store.bootstrap(PASSWORD).unwrap();
        let (address, stop) = serve(store.clone()).await;
        let api = Api::new(address).await;
        Self {
            temp,
            store,
            admin,
            api,
            stop,
        }
    }
    /// A server with a running agent, once it reported egress proxy support.
    async fn server(&self, name: &str) -> (String, Agents) {
        let (node, enrollment) = self
            .store
            .create_node(&self.admin, "default", name)
            .unwrap();
        let agents = Agents::start(
            self.temp.path(),
            &self.api.origin,
            &[(node.id.as_str(), enrollment.as_str())],
        );
        self.api
            .until("the agent to report egress proxy support", || async {
                self.api.node(&node.id).await["egress_proxy_support"] == true
            })
            .await;
        (node.id, agents)
    }
}
impl Drop for Panel {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

/// What a client of the upstream asked to connect to.
#[derive(Clone, Debug, PartialEq)]
enum Asked {
    Name(String, u16),
    Address(SocketAddr),
}

/// A SOCKS5 proxy requiring `UPSTREAM_USER`/`UPSTREAM_PASSWORD` that knows
/// `TARGET_NAME` as the target's address and connects onward from
/// `UPSTREAM_SOURCE`. It keeps every CONNECT with the peer that sent it.
struct Upstream {
    address: SocketAddr,
    asked: Arc<Mutex<Vec<(SocketAddr, Asked)>>>,
    rejected_logins: Arc<AtomicUsize>,
    stop: CancellationToken,
}
impl Upstream {
    async fn start(target: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let asked = Arc::new(Mutex::new(vec![]));
        let rejected_logins = Arc::new(AtomicUsize::new(0));
        let stop = CancellationToken::new();
        let (log, rejected, shutdown) = (asked.clone(), rejected_logins.clone(), stop.clone());
        tokio::spawn(async move {
            loop {
                let accepted =
                    tokio::select! {_=shutdown.cancelled()=>break,a=listener.accept()=>a};
                let Ok((stream, peer)) = accepted else { break };
                let (log, rejected) = (log.clone(), rejected.clone());
                let session = serve_upstream(stream, peer, target, log, rejected);
                let shutdown = shutdown.clone();
                tokio::spawn(async move {
                    tokio::select! {_=shutdown.cancelled()=>{},_=session=>{}}
                });
            }
        });
        Self {
            address,
            asked,
            rejected_logins,
            stop,
        }
    }
    fn asked(&self) -> Vec<(SocketAddr, Asked)> {
        self.asked.lock().unwrap().clone()
    }
}
impl Drop for Upstream {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
async fn serve_upstream(
    mut stream: TcpStream,
    peer: SocketAddr,
    target: SocketAddr,
    log: Arc<Mutex<Vec<(SocketAddr, Asked)>>>,
    rejected: Arc<AtomicUsize>,
) -> std::io::Result<()> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    let mut methods = vec![0u8; usize::from(head[1])];
    stream.read_exact(&mut methods).await?;
    if head[0] != 5 || !methods.contains(&2) {
        return stream.write_all(&[5, 0xff]).await;
    }
    stream.write_all(&[5, 2]).await?;
    let mut length = [0u8; 2];
    stream.read_exact(&mut length).await?;
    let mut user = vec![0u8; usize::from(length[1])];
    stream.read_exact(&mut user).await?;
    stream.read_exact(&mut length[..1]).await?;
    let mut password = vec![0u8; usize::from(length[0])];
    stream.read_exact(&mut password).await?;
    if user != UPSTREAM_USER.as_bytes() || password != UPSTREAM_PASSWORD.as_bytes() {
        rejected.fetch_add(1, Ordering::Relaxed);
        return stream.write_all(&[1, 1]).await;
    }
    stream.write_all(&[1, 0]).await?;
    let mut request = [0u8; 4];
    stream.read_exact(&mut request).await?;
    let mut port = [0u8; 2];
    let asked = match request[3] {
        1 => {
            let mut ip = [0u8; 4];
            stream.read_exact(&mut ip).await?;
            stream.read_exact(&mut port).await?;
            Asked::Address(SocketAddr::new(ip.into(), u16::from_be_bytes(port)))
        }
        4 => {
            let mut ip = [0u8; 16];
            stream.read_exact(&mut ip).await?;
            stream.read_exact(&mut port).await?;
            Asked::Address(SocketAddr::new(ip.into(), u16::from_be_bytes(port)))
        }
        _ => {
            stream.read_exact(&mut length[..1]).await?;
            let mut name = vec![0u8; usize::from(length[0])];
            stream.read_exact(&mut name).await?;
            stream.read_exact(&mut port).await?;
            Asked::Name(String::from_utf8(name).unwrap(), u16::from_be_bytes(port))
        }
    };
    log.lock().unwrap().push((peer, asked.clone()));
    let onward = match asked {
        Asked::Name(name, port) if name == TARGET_NAME => Some(SocketAddr::new(target.ip(), port)),
        Asked::Address(address) if address.is_ipv4() => Some(address),
        _ => None,
    };
    let Some(onward) = onward else {
        return stream.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0]).await;
    };
    let socket = TcpSocket::new_v4()?;
    socket.bind(SocketAddr::new(UPSTREAM_SOURCE.into(), 0))?;
    let Ok(mut out) = socket.connect(onward).await else {
        return stream.write_all(&[5, 5, 0, 1, 0, 0, 0, 0, 0, 0]).await;
    };
    let bound = out.local_addr()?;
    let mut reply = vec![5, 0, 0, 1];
    if let IpAddr::V4(ip) = bound.ip() {
        reply.extend(ip.octets());
    }
    reply.extend(bound.port().to_be_bytes());
    stream.write_all(&reply).await?;
    tokio::io::copy_bidirectional(&mut stream, &mut out).await?;
    Ok(())
}

/// A TCP echo service that keeps the peer address of each connection.
struct Target {
    address: SocketAddr,
    peers: Arc<Mutex<Vec<SocketAddr>>>,
    received: Arc<Mutex<Vec<u8>>>,
    stop: CancellationToken,
}
impl Target {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peers = Arc::new(Mutex::new(vec![]));
        let received = Arc::new(Mutex::new(vec![]));
        let stop = CancellationToken::new();
        let (seen, kept, shutdown) = (peers.clone(), received.clone(), stop.clone());
        tokio::spawn(async move {
            loop {
                let accepted =
                    tokio::select! {_=shutdown.cancelled()=>break,a=listener.accept()=>a};
                let Ok((mut stream, peer)) = accepted else {
                    break;
                };
                seen.lock().unwrap().push(peer);
                let kept = kept.clone();
                tokio::spawn(async move {
                    let mut buffer = [0u8; 16 * 1024];
                    while let Ok(read) = stream.read(&mut buffer).await {
                        if read == 0 || stream.write_all(&buffer[..read]).await.is_err() {
                            break;
                        }
                        kept.lock().unwrap().extend_from_slice(&buffer[..read]);
                    }
                });
            }
        });
        Self {
            address,
            peers,
            received,
            stop,
        }
    }
    fn peers(&self) -> Vec<SocketAddr> {
        self.peers.lock().unwrap().clone()
    }
}
impl Drop for Target {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

fn upstream_proxy(servers: &[SocketAddr], password: &str) -> egress::Config {
    egress::Config {
        kind: egress::Kind::Socks5,
        servers: servers.iter().map(ToString::to_string).collect(),
        username: Some(UPSTREAM_USER.into()),
        password: Some(password.into()),
    }
}
/// A SOCKS5 rule (no client authentication) reaching destinations through
/// `servers`.
fn socks_rule(id: &str, servers: &[SocketAddr]) -> Rule {
    let mut rule = rule(free_address(), Protocol::Tcp);
    rule.id = id.into();
    rule.name = id.into();
    rule.meter_epoch = format!("epoch-{id}");
    rule.targets.clear();
    rule.connect_timeout_ms = 3000;
    rule.inbound_socks5 = Some(socks5::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: true,
    });
    rule.egress_proxy = Some(upstream_proxy(servers, UPSTREAM_PASSWORD));
    rule
}
fn http_rule(id: &str, servers: &[SocketAddr]) -> Rule {
    let mut rule = socks_rule(id, servers);
    rule.inbound_socks5 = None;
    rule.inbound_http_connect = Some(http_connect::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: true,
    });
    rule
}

enum Ask<'a> {
    Name(&'a str, u16),
    Address(SocketAddr),
}
/// A SOCKS5 CONNECT through `entry`: the stream and the reply code.
async fn socks5_connect(entry: SocketAddr, ask: Ask<'_>) -> (TcpStream, u8) {
    let mut client = TcpStream::connect(entry).await.unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut selected = [0u8; 2];
    client.read_exact(&mut selected).await.unwrap();
    assert_eq!(selected, [5, 0]);
    let mut request = vec![5, 1, 0];
    match ask {
        Ask::Name(name, port) => {
            request.extend([3, name.len() as u8]);
            request.extend(name.as_bytes());
            request.extend(port.to_be_bytes());
        }
        Ask::Address(address) => {
            let IpAddr::V4(ip) = address.ip() else {
                panic!("IPv4 only")
            };
            request.push(1);
            request.extend(ip.octets());
            request.extend(address.port().to_be_bytes());
        }
    }
    client.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    timeout(Duration::from_secs(10), client.read_exact(&mut reply))
        .await
        .expect("a SOCKS5 reply")
        .unwrap();
    (client, reply[1])
}
/// An HTTP CONNECT through `entry`: the stream and the status code.
async fn http_connect(entry: SocketAddr, authority: &str) -> (TcpStream, u16) {
    let mut client = TcpStream::connect(entry).await.unwrap();
    client
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = vec![];
    timeout(Duration::from_secs(10), async {
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            if client.read(&mut byte).await.unwrap() == 0 {
                break;
            }
            head.push(byte[0]);
        }
    })
    .await
    .expect("an HTTP CONNECT response");
    let text = String::from_utf8(head).unwrap();
    let status = text.split(' ').nth(1).unwrap_or("0").parse().unwrap_or(0);
    (client, status)
}
async fn echo_round(stream: &mut TcpStream, bytes: usize) {
    let sent: Vec<u8> = (0..bytes).map(|i| i as u8).collect();
    stream.write_all(&sent).await.unwrap();
    let mut back = vec![0u8; bytes];
    timeout(Duration::from_secs(5), stream.read_exact(&mut back))
        .await
        .expect("the echo")
        .unwrap();
    assert_eq!(back, sent);
}
fn from_upstream(peers: &[SocketAddr]) -> bool {
    peers.iter().all(|p| p.ip() == IpAddr::V4(UPSTREAM_SOURCE))
}

/// A Shadowsocks 2022 (AES-128) request to an IPv4 destination, with
/// `payload` as its first data.
fn ss_request(destination: SocketAddr, psk: &[u8], payload: &[u8]) -> Vec<u8> {
    use ring::aead::{AES_128_GCM, Aad, LessSafeKey, Nonce, UnboundKey};
    let salt: [u8; 16] = rand_salt();
    let mut subkey = [0u8; 16];
    let mut hash = blake3::Hasher::new_derive_key("shadowsocks 2022 session subkey");
    hash.update(psk)
        .update(&salt)
        .finalize_xof()
        .fill(&mut subkey);
    let key = LessSafeKey::new(UnboundKey::new(&AES_128_GCM, &subkey).unwrap());
    let IpAddr::V4(ip) = destination.ip() else {
        panic!("IPv4 only")
    };
    let mut variable = vec![1];
    variable.extend(ip.octets());
    variable.extend(destination.port().to_be_bytes());
    variable.extend([0, 0]);
    variable.extend_from_slice(payload);
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs();
    let mut fixed = vec![0];
    fixed.extend(now.to_be_bytes());
    fixed.extend((variable.len() as u16).to_be_bytes());
    let mut request = salt.to_vec();
    for (counter, mut block) in [fixed, variable].into_iter().enumerate() {
        let mut nonce = [0; 12];
        nonce[0] = counter as u8;
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key(nonce),
            Aad::empty(),
            &mut block,
        )
        .unwrap();
        request.extend_from_slice(&block);
    }
    request
}
fn rand_salt() -> [u8; 16] {
    let mut salt = [0u8; 16];
    ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut salt).unwrap();
    salt
}

/// Debug lines of the engine in this process, from here on.
fn capture_engine_logs() {
    use tracing_subscriber::prelude::*;
    static INSTALLED: std::sync::OnceLock<()> = std::sync::OnceLock::new();
    INSTALLED.get_or_init(|| {
        tracing_subscriber::registry()
            .with(tracing_subscriber::EnvFilter::new(
                "relay_platform::engine=debug",
            ))
            .with(logs::Capture)
            .init();
    });
}
fn logged() -> Vec<String> {
    let mut cursor = logs::Cursor::default();
    let mut lines = vec![];
    while let Some(batch) = logs::after(Some(&cursor)) {
        cursor = logs::Cursor {
            stream: batch.stream.clone(),
            seq: batch.lines.last().unwrap().seq,
        };
        lines.extend(batch.lines.into_iter().map(|line| line.text));
    }
    lines
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn every_proxy_inbound_reaches_its_destination_only_through_the_authenticated_upstream() {
    let panel = Panel::new().await;
    let (node, _agents) = panel.server("tokyo").await;
    let api = &panel.api;
    let target = Target::start().await;
    let upstream = Upstream::start(target.address).await;

    // The SOCKS5 rule binds its outbound connections to 127.0.0.3: the
    // upstream sees that address, so `outbound_bind` reaches it.
    let mut socks = socks_rule("socks", &[upstream.address]);
    socks.outbound_bind = Some(OutboundBind {
        ip: Some("127.0.0.3".parse().unwrap()),
        interface: None,
    });
    let http = http_rule("http", &[upstream.address]);
    let mut h2 = http_rule("h2", &[upstream.address]);
    h2.inbound_http_connect = None;
    h2.inbound_http2_connect = Some(http2_connect::ServerConfig {
        username: None,
        password: None,
        bearer_token_sha256: vec![],
        allow_private_destinations: true,
        max_concurrent_streams: 16,
        socket_buffer_bytes: None,
    });
    let psk: Vec<u8> = (0..16).collect();
    let mut ss = socks_rule("ss", &[upstream.address]);
    ss.inbound_socks5 = None;
    ss.inbound_shadowsocks = Some(shadowsocks::ServerConfig {
        method: shadowsocks::Method::Blake3Aes128Gcm,
        password: {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(&psk)
        },
        allow_private_destinations: true,
        udp_over_tcp: false,
    });
    api.apply(&node, &[&socks, &http, &h2, &ss]).await;
    let config = api.get(&format!("/nodes/{node}/config")).await;
    assert_eq!(
        config["rules"][0]["egress_proxy"],
        json!({"kind": "socks5", "servers": [upstream.address.to_string()], "username": UPSTREAM_USER, "password": UPSTREAM_PASSWORD})
    );

    // A name goes to the upstream as a name: the agent cannot resolve it.
    let port = target.address.port();
    let (mut client, status) = socks5_connect(socks.listen, Ask::Name(TARGET_NAME, port)).await;
    assert_eq!(status, 0);
    echo_round(&mut client, 1000).await;
    let bound: IpAddr = "127.0.0.3".parse().unwrap();
    let asked = upstream.asked();
    assert_eq!(asked.len(), 1);
    assert_eq!(
        (asked[0].0.ip(), &asked[0].1),
        (bound, &Asked::Name(TARGET_NAME.into(), port))
    );
    assert_eq!(target.peers().len(), 1);
    assert!(from_upstream(&target.peers()), "{:?}", target.peers());

    // The session's next hop is the upstream; its destination the client's.
    let local = client.local_addr().unwrap();
    let until = Instant::now() + Duration::from_secs(20);
    let session = loop {
        let view = api
            .get(&format!("/nodes/{node}/rules/socks/connections"))
            .await;
        let found = view["sessions"]
            .as_array()
            .into_iter()
            .flatten()
            .find(|s| s["client"] == local.to_string())
            .cloned();
        if view["state"] == "ready"
            && let Some(session) = found
        {
            break session;
        }
        assert!(Instant::now() < until, "waiting for the session: {view}");
        sleep(Duration::from_millis(100)).await;
    };
    assert_eq!(session["destination"], format!("{TARGET_NAME}:{port}"));
    assert_eq!(session["remote"], upstream.address.to_string());
    drop(client);

    // An address goes as an address.
    let (mut client, status) = socks5_connect(socks.listen, Ask::Address(target.address)).await;
    assert_eq!(status, 0);
    echo_round(&mut client, 24).await;
    drop(client);
    assert_eq!(upstream.asked()[1].1, Asked::Address(target.address));

    // HTTP CONNECT.
    let (mut client, status) = http_connect(http.listen, &format!("{TARGET_NAME}:{port}")).await;
    assert_eq!(status, 200);
    echo_round(&mut client, 300).await;
    drop(client);
    let asked = upstream.asked();
    assert_eq!(asked[2].1, Asked::Name(TARGET_NAME.into(), port));
    assert_eq!(asked[2].0.ip(), IpAddr::V4(Ipv4Addr::LOCALHOST));

    // Managed HTTP/2 CONNECT.
    {
        use http_body_util::Empty;
        use hyper::{Request, body::Bytes, client::conn::http2::handshake};
        use hyper_util::rt::{TokioExecutor, TokioIo};
        let tcp = TcpStream::connect(h2.listen).await.unwrap();
        let (mut sender, connection) = handshake(TokioExecutor::new(), TokioIo::new(tcp))
            .await
            .unwrap();
        tokio::spawn(connection);
        let request = Request::builder()
            .method(hyper::Method::CONNECT)
            .uri(format!("http://{TARGET_NAME}:{port}"))
            .body(Empty::<Bytes>::new())
            .unwrap();
        let mut response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), hyper::StatusCode::OK);
        let upgraded = timeout(Duration::from_secs(5), hyper::upgrade::on(&mut response))
            .await
            .unwrap()
            .unwrap();
        let mut tunnel = TokioIo::new(upgraded);
        tunnel.write_all(b"over-h2").await.unwrap();
        let mut back = [0u8; 7];
        timeout(Duration::from_secs(5), tunnel.read_exact(&mut back))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&back, b"over-h2");
    }
    assert_eq!(upstream.asked()[3].1, Asked::Name(TARGET_NAME.into(), port));

    // Shadowsocks: the client's first data arrives at the target.
    let mut client = TcpStream::connect(ss.listen).await.unwrap();
    client
        .write_all(&ss_request(target.address, &psk, b"over-ss"))
        .await
        .unwrap();
    api.until("the Shadowsocks payload", || async {
        target.received.lock().unwrap().ends_with(b"over-ss")
    })
    .await;
    // The echo comes back encrypted.
    let mut reply = [0u8; 1];
    timeout(Duration::from_secs(5), client.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    drop(client);
    assert_eq!(upstream.asked()[4].1, Asked::Address(target.address));

    // Every connection the target saw came from the upstream.
    assert_eq!(target.peers().len(), 5);
    assert!(from_upstream(&target.peers()), "{:?}", target.peers());
    assert_eq!(upstream.rejected_logins.load(Ordering::Relaxed), 0);

    // Only the clients' bytes are counted, as without the upstream: not the
    // SOCKS5 exchange with it.
    let payload = 1000 + 24 + 300 + 7 + 7;
    api.until("the agent to report the forwarded bytes", || async {
        api.stat(&node, "forwarded_upload_bytes").await == payload
            && api.stat(&node, "forwarded_download_bytes").await == payload
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_next_server_is_tried_when_one_cannot_be_reached_or_drops_the_connection() {
    let panel = Panel::new().await;
    let (node, _agents) = panel.server("osaka").await;
    let api = &panel.api;
    let target = Target::start().await;
    let upstream = Upstream::start(target.address).await;
    // Nothing listens on the first; the second accepts and closes at once.
    let refused = free_address();
    let closing = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let closer = closing.local_addr().unwrap();
    let closed = Arc::new(AtomicUsize::new(0));
    let count = closed.clone();
    tokio::spawn(async move {
        while let Ok((stream, _)) = closing.accept().await {
            count.fetch_add(1, Ordering::Relaxed);
            drop(stream);
        }
    });
    let rule = socks_rule("fallback", &[refused, closer, upstream.address]);
    let dead = socks_rule("dead", &[refused, closer]);
    api.apply(&node, &[&rule, &dead]).await;

    let port = target.address.port();
    let (mut client, status) = socks5_connect(rule.listen, Ask::Name(TARGET_NAME, port)).await;
    assert_eq!(status, 0);
    echo_round(&mut client, 64).await;
    assert_eq!(closed.load(Ordering::Relaxed), 1);
    assert_eq!(upstream.asked().len(), 1);
    assert!(from_upstream(&target.peers()));

    // With no server left, the client is refused and the attempt counts as
    // a failed connection.
    let failed = api.stat(&node, "failed_connections").await;
    let (_client, status) = socks5_connect(dead.listen, Ask::Name(TARGET_NAME, port)).await;
    assert_eq!(status, 5);
    api.until("the failure to be counted", || async {
        api.stat(&node, "failed_connections").await > failed
    })
    .await;
    assert_eq!(target.peers().len(), 1, "nothing was sent directly");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_wrong_password_is_refused_with_a_clear_error_that_does_not_name_it() {
    capture_engine_logs();
    let panel = Panel::new().await;
    let (node, _agents) = panel.server("kyoto").await;
    let api = &panel.api;
    let target = Target::start().await;
    let upstream = Upstream::start(target.address).await;
    let wrong = "wrong-Pass-7Kx";
    let mut socks = socks_rule("socks", &[upstream.address]);
    socks.egress_proxy = Some(upstream_proxy(&[upstream.address], wrong));
    let mut http = http_rule("http", &[upstream.address]);
    http.egress_proxy = socks.egress_proxy.clone();
    api.apply(&node, &[&socks, &http]).await;

    let failed = api.stat(&node, "failed_connections").await;
    let port = target.address.port();
    let (_client, status) = socks5_connect(socks.listen, Ask::Name(TARGET_NAME, port)).await;
    assert_eq!(status, 5);
    let (_client, status) = http_connect(http.listen, &format!("{TARGET_NAME}:{port}")).await;
    assert_eq!(status, 502);
    api.until("both failures to be counted", || async {
        api.stat(&node, "failed_connections").await >= failed + 2
    })
    .await;
    assert_eq!(upstream.rejected_logins.load(Ordering::Relaxed), 2);
    assert!(upstream.asked().is_empty() && target.peers().is_empty());

    let expected = format!(
        "egress proxy {} rejected the username and password",
        upstream.address
    );
    let lines = logged();
    assert!(
        lines.iter().filter(|l| l.contains(&expected)).count() >= 2,
        "{lines:#?}"
    );
    // Nor do the agent's reports, the panel's logs, the audit log or the
    // diagnostic report.
    let views = [
        api.node(&node).await,
        api.get("/logs").await,
        api.get("/audit").await,
        api.get("/diagnostics/report").await,
    ];
    for secret in [wrong, UPSTREAM_PASSWORD] {
        assert!(!lines.iter().any(|l| l.contains(secret)), "{lines:#?}");
        for view in &views {
            assert!(!view.to_string().contains(secret), "{view}");
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn destination_rules_refuse_before_the_upstream_is_used() {
    let panel = Panel::new().await;
    let (node, _agents) = panel.server("nagoya").await;
    let api = &panel.api;
    let target = Target::start().await;
    let upstream = Upstream::start(target.address).await;
    let port = target.address.port();

    // Name and port entries are decided on the name: nothing is resolved.
    let mut names = socks_rule("names", &[upstream.address]);
    names.deny_destinations = vec!["*.blocked.test".into()];
    names.deny_destination_ports = vec!["9".into()];
    // An address entry needs the addresses: the name is resolved on the
    // node, as without the upstream, and only permitted addresses are sent.
    let mut addresses = socks_rule("addresses", &[upstream.address]);
    addresses.deny_destinations = vec!["192.0.2.0/24".into()];
    // The default: private destinations are refused, also behind names.
    let mut public = socks_rule("public", &[upstream.address]);
    public
        .inbound_socks5
        .as_mut()
        .unwrap()
        .allow_private_destinations = false;
    api.apply(&node, &[&names, &addresses, &public]).await;

    for (entry, ask) in [
        (names.listen, Ask::Name("www.blocked.test", 80)),
        (names.listen, Ask::Name(TARGET_NAME, 9)),
        (
            addresses.listen,
            Ask::Address("192.0.2.7:80".parse().unwrap()),
        ),
        (public.listen, Ask::Address(target.address)),
        (public.listen, Ask::Name("localhost", port)),
    ] {
        let (_client, status) = socks5_connect(entry, ask).await;
        assert_eq!(status, 5);
    }
    assert!(upstream.asked().is_empty(), "{:?}", upstream.asked());
    assert!(target.peers().is_empty());

    // Allowed: by name, and by the node's own resolution of `localhost`.
    let (mut client, status) = socks5_connect(names.listen, Ask::Name(TARGET_NAME, port)).await;
    assert_eq!(status, 0);
    echo_round(&mut client, 8).await;
    let (mut client, status) = socks5_connect(addresses.listen, Ask::Name("localhost", port)).await;
    assert_eq!(status, 0);
    echo_round(&mut client, 8).await;
    let asked: Vec<Asked> = upstream.asked().into_iter().map(|(_, a)| a).collect();
    assert_eq!(asked[0], Asked::Name(TARGET_NAME.into(), port));
    assert!(
        asked[1..].iter().all(|a| matches!(a, Asked::Address(_)))
            && asked.contains(&Asked::Address(SocketAddr::new(
                Ipv4Addr::LOCALHOST.into(),
                port
            ))),
        "{asked:?}"
    );
    assert!(from_upstream(&target.peers()));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_is_refused_so_nothing_leaves_around_the_upstream() {
    let panel = Panel::new().await;
    let (node, _agents) = panel.server("sendai").await;
    let api = &panel.api;
    let upstream = Upstream::start(free_address()).await;

    // Rules that would carry UDP are refused when published.
    let mut both = socks_rule("both", &[upstream.address]);
    both.protocol = Protocol::Both;
    let mut uot = socks_rule("uot", &[upstream.address]);
    uot.inbound_socks5 = None;
    uot.inbound_shadowsocks = Some(shadowsocks::ServerConfig {
        method: shadowsocks::Method::Blake3Aes128Gcm,
        password: "AAECAwQFBgcICQoLDA0ODw==".into(),
        allow_private_destinations: true,
        udp_over_tcp: true,
    });
    let mut forward = rule(free_address(), Protocol::Tcp);
    forward.egress_proxy = Some(upstream_proxy(&[upstream.address], UPSTREAM_PASSWORD));
    for (rule, reason) in [
        (
            &both,
            "an egress proxy carries TCP only; set the rule's protocol to TCP (UDP is never sent around the egress proxy)",
        ),
        (
            &uot,
            "an egress proxy carries TCP only; turn off Shadowsocks UDP over TCP",
        ),
        (
            &forward,
            "an egress proxy applies only to rules whose clients choose the destination: a SOCKS5, HTTP CONNECT, HTTP/2 CONNECT or Shadowsocks inbound",
        ),
    ] {
        let (code, error) = api.publish(&node, &[rule]).await;
        assert_eq!((code, error["error"].as_str()), (400, Some(reason)));
    }

    // The SOCKS5 rule refuses UDP ASSOCIATE and BIND (command not supported).
    let socks = socks_rule("socks", &[upstream.address]);
    api.apply(&node, &[&socks]).await;
    let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    for command in [3u8, 2] {
        let mut client = TcpStream::connect(socks.listen).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut selected = [0u8; 2];
        client.read_exact(&mut selected).await.unwrap();
        let mut request = vec![5, command, 0, 1, 127, 0, 0, 1];
        request.extend(udp_target.local_addr().unwrap().port().to_be_bytes());
        client.write_all(&request).await.unwrap();
        let mut reply = [0u8; 2];
        timeout(Duration::from_secs(5), client.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, [5, 7], "command {command}");
    }
    let mut buffer = [0u8; 64];
    assert!(
        timeout(
            Duration::from_millis(300),
            udp_target.recv_from(&mut buffer)
        )
        .await
        .is_err()
    );
    assert!(upstream.asked().is_empty());
}

/// One sync as an agent of 0.148.0 or earlier, which reports no support.
fn old_sync(store: &Store, node: &str) -> Value {
    let ledger_id = store
        .reconcile(
            node,
            ReconcileRequest {
                lease: None,
                ledger_id: None,
                after: None,
                expected_revision: None,
            },
        )
        .unwrap()
        .ledger_id;
    let response = store
        .sync(
            node,
            SyncRequest {
                logs: None,
                lease: None,
                budget: None,
                ledger_id,
                need_config: true,
                applied_revision: 0,
                apply_error: None,
                usage: vec![],
                stats: EngineStats::default(),
            },
        )
        .unwrap();
    serde_json::to_value(response).unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn servers_whose_agent_is_too_old_refuse_egress_proxies_with_409() {
    let panel = Panel::new().await;
    let (api, store, admin) = (&panel.api, &panel.store, &panel.admin);
    let (old, _) = store.create_node(admin, "default", "old").unwrap();
    let (fresh, _) = store.create_node(admin, "default", "fresh").unwrap();
    let sent = old_sync(store, &old.id);
    // The controller asks; an older agent ignores fields it does not know.
    assert_eq!(sent["egress_proxy"], true);
    assert_eq!(api.node(&old.id).await["egress_proxy_support"], false);
    let too_old = "the agent on server old is too old for egress proxies; upgrade it first";
    let upstream: SocketAddr = "203.0.113.9:1080".parse().unwrap();
    let proxied = socks_rule("proxied", &[upstream]);
    let mut plain = proxied.clone();
    plain.egress_proxy = None;

    // Single publish, batch publish, template and shared rule.
    let (code, error) = api.publish(&old.id, &[&proxied]).await;
    assert_eq!((code, error["error"].as_str()), (409, Some(too_old)));
    let (code, error) = api.publish(&fresh.id, &[&proxied]).await;
    assert_eq!(
        (code, error["error"].as_str()),
        (
            409,
            Some(
                "server fresh has not connected to the panel yet; egress proxies need its agent to report in first"
            )
        )
    );
    let (code, error) = api
        .call(
            reqwest::Method::POST,
            "/configurations/publish",
            Some(json!({"updates": [{"node_id": old.id, "expected_revision": 0, "rules": [proxied]}]})),
        )
        .await;
    assert_eq!((code, error["error"].as_str()), (409, Some(too_old)));
    let (code, template) = api
        .call(
            reqwest::Method::POST,
            "/templates",
            Some(json!({"name": "Proxied", "rule": proxied})),
        )
        .await;
    assert_eq!(code, 200, "{template}");
    let (code, error) = api
        .call(
            reqwest::Method::POST,
            &format!("/nodes/{}/templates/{}", old.id, template["id"].as_str().unwrap()),
            Some(json!({"expected_revision": 0, "name": "From template", "listen": free_address().to_string()})),
        )
        .await;
    assert_eq!((code, error["error"].as_str()), (409, Some(too_old)));
    let (code, error) = api
        .call(
            reqwest::Method::POST,
            "/shared-rules",
            Some(json!({"name": "Shared", "node_ids": [old.id], "listen_port": free_address().port(), "rule": proxied})),
        )
        .await;
    assert_eq!(code, 409, "{error}");
    assert!(error.to_string().contains(too_old), "{error}");

    // The same rule without the upstream publishes as before, and the old
    // agent gets no new field.
    let (code, config) = api.publish(&old.id, &[&plain]).await;
    assert_eq!(code, 200, "{config}");
    let sent = old_sync(store, &old.id);
    assert!(
        !sent["config"].to_string().contains("egress_proxy"),
        "{sent}"
    );

    // Once the agent reports support, the same publish goes through.
    let ledger_id = store
        .reconcile(
            &old.id,
            ReconcileRequest {
                lease: None,
                ledger_id: None,
                after: None,
                expected_revision: None,
            },
        )
        .unwrap()
        .ledger_id;
    store
        .sync(
            &old.id,
            SyncRequest {
                logs: None,
                lease: None,
                budget: None,
                ledger_id,
                need_config: false,
                applied_revision: 0,
                apply_error: None,
                usage: vec![],
                stats: EngineStats {
                    egress_proxy: Some(egress::Report::default()),
                    ..EngineStats::default()
                },
            },
        )
        .unwrap();
    assert_eq!(api.node(&old.id).await["egress_proxy_support"], true);
    let (code, config) = api.publish(&old.id, &[&proxied]).await;
    assert_eq!(code, 200, "{config}");
}

#[test]
fn configurations_and_reports_without_egress_proxies_read_and_write_as_before() {
    let rule = rule(free_address(), Protocol::Tcp);
    let text = serde_json::to_string(&config(rule)).unwrap();
    assert!(!text.contains("egress_proxy"), "{text}");
    let read: NodeConfig = serde_json::from_str(&text).unwrap();
    assert_eq!(serde_json::to_string(&read).unwrap(), text);
    let stats = serde_json::to_value(EngineStats::default()).unwrap();
    assert!(stats.get("egress_proxy").is_none());
    // An agent's report of support is an empty object.
    let reported = EngineStats {
        egress_proxy: Some(egress::Report::default()),
        ..EngineStats::default()
    };
    assert_eq!(
        serde_json::to_value(&reported).unwrap()["egress_proxy"],
        json!({})
    );
}
