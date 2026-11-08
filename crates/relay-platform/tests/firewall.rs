//! Firewall rule sets with real agents on loopback. Clients connect from
//! chosen loopback addresses (127.0.0.1, .3, .4), so source rules can tell
//! them apart. Covers: the server's and a rule's inbound sets both having
//! to allow (and the rule's set without a server set), the server's set
//! judging the sender of PROXY headers, SOCKS5 BIND peers and the first
//! SOCKS5 UDP datagram, a set edit reaching the agent without a publish,
//! outbound sets refusing plain targets and SOCKS5/HTTP CONNECT
//! destinations before any connection is made and refusing egress proxy
//! upstreams (the next upstream is tried), names that are not hostnames
//! never reaching the egress proxy by name, block records, the 409s for a
//! bound set and for agents too old, an agent that stops reporting losing
//! its confirmation, tenant isolation (the tester included), the limits on
//! sets, and the tester agreeing with the agent.
mod common;
use common::*;
use relay_platform::{
    agent::{self, AgentOptions},
    api::{self, AppState},
    http_connect,
    model::*,
    socks5,
    store::{Role, Store, write_secret},
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

const ONE: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 1);
const THREE: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 3);
const FOUR: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 4);

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
    async fn login(origin: &str, username: &str, password: &str) -> Self {
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let body: Value = client
            .post(format!("{origin}/api/v1/auth/login"))
            .json(&json!({"username": username, "password": password}))
            .send()
            .await
            .unwrap()
            .json()
            .await
            .unwrap();
        let token = body["token"].as_str().expect("signed in").to_string();
        Self {
            client,
            origin: origin.into(),
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
    async fn ok(&self, method: reqwest::Method, path: &str, body: Value) -> Value {
        let (code, reply) = self.call(method, path, Some(body)).await;
        assert_eq!(code, 200, "{path}: {reply}");
        reply
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
    async fn publish(&self, node: &str, rules: &[&Rule]) -> (u16, Value) {
        let config = self.get(&format!("/nodes/{node}/config")).await;
        self.call(
            reqwest::Method::PUT,
            &format!("/nodes/{node}/config"),
            Some(json!({ "expected_revision": config["revision"], "rules": rules })),
        )
        .await
    }
    /// Publishes and waits until the agent applied the configuration and
    /// confirmed the firewall policy that goes with it.
    async fn apply(&self, node: &str, rules: &[&Rule]) {
        let (code, config) = self.publish(node, rules).await;
        assert_eq!(code, 200, "{config}");
        let revision = config["revision"].clone();
        self.until("the agent to apply the configuration", || async {
            let node = self.node(node).await;
            node["applied_revision"] == revision && node["firewall"]["state"] == "applied"
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
    async fn create_set(&self, body: Value) -> String {
        let set = self.ok(reqwest::Method::POST, "/firewall/sets", body).await;
        set["id"].as_str().unwrap().to_string()
    }
    async fn bind(&self, node: &str, inbound: Option<&str>, outbound: Option<&str>) -> Value {
        self.ok(
            reqwest::Method::PUT,
            &format!("/nodes/{node}/firewall"),
            json!({"inbound_set_id": inbound, "outbound_set_id": outbound}),
        )
        .await
    }
    /// Waits until the agent confirmed the server's desired policy.
    async fn confirmed(&self, node: &str) {
        self.until("the agent to confirm the firewall policy", || async {
            self.node(node).await["firewall"]["state"] == "applied"
        })
        .await;
    }
    /// Waits for `node`'s block records of `rule` to satisfy `check`.
    async fn blocks(&self, node: &str, rule: &str, check: impl Fn(&[Value]) -> bool) -> Vec<Value> {
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            let view = self
                .get(&format!("/nodes/{node}/blocks?rule_id={rule}"))
                .await;
            let blocks = view["blocks"].as_array().unwrap().clone();
            if check(&blocks) {
                return blocks;
            }
            assert!(
                Instant::now() < until,
                "waiting for records of {rule}: {blocks:?}"
            );
            sleep(Duration::from_millis(50)).await;
        }
    }
}

/// Real agents, stopped on drop.
struct Agents(Vec<CancellationToken>);
impl Agents {
    fn start(dir: &Path, origin: &str, node: &str, enrollment: &str, poll: Duration) -> Self {
        let secret = dir.join(format!("agent-{node}.secret"));
        write_secret(&secret, enrollment.as_bytes()).unwrap();
        let db = Store::open(&dir.join(format!("agent-{node}.db"))).unwrap();
        let stop = CancellationToken::new();
        let options = AgentOptions {
            controller: origin.into(),
            node_id: node.into(),
            enrollment_token_file: Some(secret),
            ca_certificate: None,
            tls_directory: None,
            poll_interval: poll,
            controller_addresses: vec![],
            controller_proxy: None,
        };
        tokio::spawn(agent::run(db, options, stop.clone()));
        Self(vec![stop])
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
        let api = Api::login(&format!("http://{address}"), "admin", PASSWORD).await;
        Self {
            temp,
            store,
            admin,
            api,
            stop,
        }
    }
    /// A server with a running agent that polls every `poll`, once it
    /// reported that it enforces rule sets.
    async fn server_polling(&self, name: &str, poll: Duration) -> (String, Agents) {
        let (node, enrollment) = self
            .store
            .create_node(&self.admin, "default", name)
            .unwrap();
        let agents = Agents::start(
            self.temp.path(),
            &self.api.origin,
            &node.id,
            &enrollment,
            poll,
        );
        self.api
            .until("the agent to report rule set support", || async {
                self.api.node(&node.id).await["firewall_support"] == true
            })
            .await;
        (node.id, agents)
    }
    async fn server(&self, name: &str) -> (String, Agents) {
        self.server_polling(name, Duration::from_millis(50)).await
    }
}
impl Drop for Panel {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

fn inbound(name: &str, scope: &str, default: &str, rules: &[(&str, &[&str])]) -> Value {
    json!({
        "name": name,
        "scope": scope,
        "direction": "inbound",
        "default_action": default,
        "rules": rules.iter().map(|(action, sources)| json!({"action": action, "match": {"sources": sources}})).collect::<Vec<_>>(),
    })
}
fn forward(id: &str, target: SocketAddr) -> Rule {
    let mut rule = rule(target, Protocol::Tcp);
    rule.id = id.into();
    rule.name = id.into();
    rule.meter_epoch = format!("epoch-{id}");
    rule
}

/// A TCP connection to `entry` from the loopback address `source`.
async fn connect_from(source: Ipv4Addr, entry: SocketAddr) -> TcpStream {
    let socket = TcpSocket::new_v4().unwrap();
    socket.bind(SocketAddr::new(source.into(), 0)).unwrap();
    socket.connect(entry).await.unwrap()
}
/// Whether data sent from `source` through `entry` comes back from the echo.
async fn echoes(source: Ipv4Addr, entry: SocketAddr) -> bool {
    let mut stream = connect_from(source, entry).await;
    if stream.write_all(b"ping").await.is_err() {
        return false;
    }
    let mut back = [0u8; 4];
    matches!(
        timeout(Duration::from_secs(5), stream.read_exact(&mut back)).await,
        Ok(Ok(_)) if &back == b"ping"
    )
}

/// [`echoes`] with a PROXY v1 header first that claims the client is at
/// `claimed`.
async fn echoes_behind_proxy(source: Ipv4Addr, claimed: Ipv4Addr, entry: SocketAddr) -> bool {
    let mut stream = connect_from(source, entry).await;
    let header = format!(
        "PROXY TCP4 {claimed} {} 40000 {}\r\n",
        entry.ip(),
        entry.port()
    );
    if stream.write_all(header.as_bytes()).await.is_err()
        || stream.write_all(b"ping").await.is_err()
    {
        return false;
    }
    let mut back = [0u8; 4];
    matches!(
        timeout(Duration::from_secs(5), stream.read_exact(&mut back)).await,
        Ok(Ok(_)) if &back == b"ping"
    )
}

/// A TCP echo service that keeps the peer of every connection it accepts.
struct Target {
    address: SocketAddr,
    peers: Arc<Mutex<Vec<SocketAddr>>>,
    stop: CancellationToken,
}
impl Target {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let peers = Arc::new(Mutex::new(vec![]));
        let stop = CancellationToken::new();
        let (seen, shutdown) = (peers.clone(), stop.clone());
        tokio::spawn(async move {
            loop {
                let accepted =
                    tokio::select! {_=shutdown.cancelled()=>break,a=listener.accept()=>a};
                let Ok((mut stream, peer)) = accepted else {
                    break;
                };
                seen.lock().unwrap().push(peer);
                tokio::spawn(async move {
                    let mut buffer = [0u8; 4096];
                    while let Ok(read) = stream.read(&mut buffer).await {
                        if read == 0 || stream.write_all(&buffer[..read]).await.is_err() {
                            break;
                        }
                    }
                });
            }
        });
        Self {
            address,
            peers,
            stop,
        }
    }
    fn peers(&self) -> usize {
        self.peers.lock().unwrap().len()
    }
}
impl Drop for Target {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_connection_must_pass_both_the_server_and_the_rule_inbound_set() {
    let panel = Panel::new().await;
    let api = &panel.api;
    let (node, _agents) = panel.server("edge").await;
    let echo = tcp_echo().await;
    // The server refuses .3; the rule's set would let all of loopback in.
    let server_denies = api
        .create_set(inbound(
            "Server deny .3",
            "system",
            "allow",
            &[("deny", &["127.0.0.3/32"])],
        ))
        .await;
    let rule_allows = api
        .create_set(inbound(
            "Rule allow loopback",
            "tenant",
            "deny",
            &[("allow", &["127.0.0.0/8"])],
        ))
        .await;
    api.bind(&node, Some(&server_denies), None).await;
    let mut guarded = forward("guarded", echo.address);
    guarded.firewall_inbound_set = Some(rule_allows.clone());
    api.apply(&node, &[&guarded]).await;
    assert!(echoes(ONE, guarded.listen).await, "allowed by both layers");
    assert!(
        !echoes(THREE, guarded.listen).await,
        "the server refuses even though the rule's set allows"
    );
    let blocks = api
        .blocks(&node, "guarded", |b| {
            b.iter().any(|b| b["reason"] == "firewall")
        })
        .await;
    let block = blocks.iter().find(|b| b["reason"] == "firewall").unwrap();
    assert_eq!(block["source"], "127.0.0.3");
    assert_eq!(
        block["detail"],
        "server inbound rule set: rule 1 denies (Server deny .3)"
    );

    // The other way round: the server lets loopback in, the rule refuses .4.
    // (Another source: refusals of one source join its record for a minute.)
    let server_allows = api
        .create_set(inbound(
            "Server allow loopback",
            "system",
            "deny",
            &[("allow", &["127.0.0.0/8"])],
        ))
        .await;
    let rule_denies = api
        .create_set(inbound(
            "Rule deny .4",
            "tenant",
            "allow",
            &[("deny", &["127.0.0.4/32"])],
        ))
        .await;
    api.bind(&node, Some(&server_allows), None).await;
    guarded.firewall_inbound_set = Some(rule_denies);
    api.apply(&node, &[&guarded]).await;
    assert!(echoes(ONE, guarded.listen).await);
    assert!(
        !echoes(FOUR, guarded.listen).await,
        "the rule refuses even though the server's set allows"
    );
    api.blocks(&node, "guarded", |b| {
        b.iter().any(|b| {
            b["source"] == "127.0.0.4"
                && b["detail"] == "rule inbound rule set: rule 1 denies (Rule deny .4)"
        })
    })
    .await;
    // With no server set bound, the rule's set still decides on its own.
    api.bind(&node, None, None).await;
    api.confirmed(&node).await;
    assert!(echoes(ONE, guarded.listen).await);
    assert!(
        !echoes(FOUR, guarded.listen).await,
        "the rule's set refuses without a server set"
    );
    // The rule's own lists still apply after both sets.
    guarded.firewall_inbound_set = None;
    guarded.deny_sources = vec!["127.0.0.1/32".parse().unwrap()];
    api.apply(&node, &[&guarded]).await;
    assert!(!echoes(ONE, guarded.listen).await);
    assert!(echoes(FOUR, guarded.listen).await);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_server_set_judges_the_sender_of_proxy_headers_as_well_as_the_header() {
    let panel = Panel::new().await;
    let api = &panel.api;
    let (node, _agents) = panel.server("edge").await;
    let target = Target::start().await;
    let server_denies = api
        .create_set(inbound(
            "Server deny .3",
            "system",
            "allow",
            &[("deny", &["127.0.0.3/32"])],
        ))
        .await;
    api.bind(&node, Some(&server_denies), None).await;
    // The rule's publisher trusts PROXY headers from anyone.
    let mut proxied = forward("proxied", target.address);
    proxied.inbound_proxy = Some(ProxyInbound {
        version: ProxyAccept::V1,
        trusted_sources: vec!["0.0.0.0/0".parse().unwrap()],
        placement: ProxyPlacement::BeforeTls,
        max_header_bytes: 4096,
        accept_prewarmed: false,
    });
    api.apply(&node, &[&proxied]).await;
    assert!(echoes_behind_proxy(ONE, ONE, proxied.listen).await);
    assert_eq!(target.peers(), 1);
    // A sender the server refuses cannot vouch for an allowed address.
    assert!(
        !echoes_behind_proxy(THREE, ONE, proxied.listen).await,
        "the header does not get a refused sender past the server's set"
    );
    assert_eq!(target.peers(), 1, "the target never saw the refused sender");
    api.blocks(&node, "proxied", |b| {
        b.iter().any(|b| {
            b["reason"] == "firewall"
                && b["source"] == "127.0.0.3"
                && b["detail"] == "server inbound rule set: rule 1 denies (Server deny .3)"
        })
    })
    .await;
    // The address in the header is judged too.
    assert!(!echoes_behind_proxy(ONE, THREE, proxied.listen).await);
    assert_eq!(target.peers(), 1);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_socks5_bind_peer_must_pass_the_inbound_sets() {
    let panel = Panel::new().await;
    let api = &panel.api;
    let (node, _agents) = panel.server("edge").await;
    let server_denies = api
        .create_set(inbound(
            "Server deny .3",
            "system",
            "allow",
            &[("deny", &["127.0.0.3/32"])],
        ))
        .await;
    let mut socks = forward("socks", "127.0.0.1:9".parse().unwrap());
    socks.targets.clear();
    socks.connect_timeout_ms = 1000;
    socks.inbound_socks5 = Some(socks5::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: true,
    });
    api.apply(&node, &[&socks]).await;
    api.bind(&node, Some(&server_denies), None).await;
    api.confirmed(&node).await;
    assert_eq!(bind_from(socks.listen, THREE).await, 5, "a refused peer");
    assert_eq!(bind_from(socks.listen, ONE).await, 0, "an allowed peer");
}

/// The code of the second reply to a SOCKS5 BIND through `entry` that
/// takes any peer, when the peer connects from `peer`.
async fn bind_from(entry: SocketAddr, peer: Ipv4Addr) -> u8 {
    let mut control = TcpStream::connect(entry).await.unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut selected = [0u8; 2];
    control.read_exact(&mut selected).await.unwrap();
    control
        .write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut first = [0u8; 10];
    timeout(Duration::from_secs(5), control.read_exact(&mut first))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&first[..4], &[5, 0, 0, 1]);
    let bound = SocketAddr::from((
        [first[4], first[5], first[6], first[7]],
        u16::from_be_bytes([first[8], first[9]]),
    ));
    let _peer = connect_from(peer, bound).await;
    let mut second = [0u8; 10];
    timeout(Duration::from_secs(5), control.read_exact(&mut second))
        .await
        .unwrap()
        .unwrap();
    second[1]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_first_socks5_udp_datagram_must_pass_the_inbound_sets() {
    let panel = Panel::new().await;
    let api = &panel.api;
    let (node, _agents) = panel.server("edge").await;
    let echo = udp_echo().await;
    let server_denies = api
        .create_set(inbound(
            "Server deny .3",
            "system",
            "allow",
            &[("deny", &["127.0.0.3/32"])],
        ))
        .await;
    let mut socks = forward("socks", echo.address);
    socks.targets.clear();
    socks.protocol = Protocol::Both;
    socks.inbound_socks5 = Some(socks5::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: true,
    });
    api.apply(&node, &[&socks]).await;
    api.bind(&node, Some(&server_denies), None).await;
    api.confirmed(&node).await;
    // The client asks for the association from .1; a host the server
    // refuses sends to the relay port first, which would claim it.
    let mut control = TcpStream::connect(socks.listen).await.unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut selected = [0u8; 2];
    control.read_exact(&mut selected).await.unwrap();
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    let relay = SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    let packet = |payload: &[u8]| {
        let IpAddr::V4(ip) = echo.address.ip() else {
            unreachable!()
        };
        let mut packet = vec![0, 0, 0, 1];
        packet.extend(ip.octets());
        packet.extend(echo.address.port().to_be_bytes());
        packet.extend(payload);
        packet
    };
    let mut buffer = [0u8; 256];
    let refused = UdpSocket::bind((THREE, 0)).await.unwrap();
    refused
        .send_to(&packet(b"from three"), relay)
        .await
        .unwrap();
    assert!(
        timeout(Duration::from_secs(1), refused.recv_from(&mut buffer))
            .await
            .is_err(),
        "the refused host got an answer"
    );
    let client = UdpSocket::bind((ONE, 0)).await.unwrap();
    client.send_to(&packet(b"from one"), relay).await.unwrap();
    let (size, _) = timeout(Duration::from_secs(5), client.recv_from(&mut buffer))
        .await
        .expect("the client still owns the association")
        .unwrap();
    assert!(buffer[..size].ends_with(b"from one"));
    api.blocks(&node, "socks", |b| {
        b.iter()
            .any(|b| b["source"] == "127.0.0.3" && b["reason"] == "firewall")
    })
    .await;
    drop(control);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_set_edit_reaches_the_agent_without_publishing_and_the_confirmed_hash_catches_up() {
    let panel = Panel::new().await;
    let api = &panel.api;
    // A slow poll: only the watch wake can bring the edit over in time.
    let (node, _agents) = panel.server_polling("edge", Duration::from_secs(60)).await;
    let echo = tcp_echo().await;
    let set = api
        .create_set(inbound("Office", "tenant", "allow", &[]))
        .await;
    let mut guarded = forward("guarded", echo.address);
    guarded.firewall_inbound_set = Some(set.clone());
    api.apply(&node, &[&guarded]).await;
    assert!(echoes(THREE, guarded.listen).await);
    let before = api.node(&node).await;
    let old_hash = before["firewall"]["desired_hash"].clone();
    assert_eq!(before["firewall"]["applied_hash"], old_hash);
    assert_eq!(before["firewall"]["rule_bindings"], 1);

    let edited = api
        .ok(
            reqwest::Method::PUT,
            &format!("/firewall/sets/{set}"),
            json!({"name": "Office", "direction": "inbound", "default_action": "allow", "expected_revision": 1,
                   "rules": [{"action": "deny", "match": {"sources": ["127.0.0.3/32"]}}]}),
        )
        .await;
    assert_eq!(edited["revision"], 2);
    let started = Instant::now();
    let after = api.node(&node).await;
    let new_hash = after["firewall"]["desired_hash"].clone();
    assert_ne!(new_hash, old_hash, "the desired policy changed at once");
    api.confirmed(&node).await;
    assert!(
        started.elapsed() < Duration::from_secs(10),
        "a watch wake, not the 60 s poll, brought it"
    );
    let after = api.node(&node).await;
    assert_eq!(after["firewall"]["applied_hash"], new_hash);
    assert_eq!(
        after["desired_revision"], before["desired_revision"],
        "no configuration was published"
    );
    assert!(
        !echoes(THREE, guarded.listen).await,
        "the edited set refuses .3"
    );
    assert!(echoes(ONE, guarded.listen).await);

    // A stale edit is refused, the direction cannot change.
    let (code, error) = api
        .call(
            reqwest::Method::PUT,
            &format!("/firewall/sets/{set}"),
            Some(json!({"name": "Office", "direction": "inbound", "default_action": "deny", "expected_revision": 1})),
        )
        .await;
    assert_eq!(code, 409, "{error}");
    let (code, error) = api
        .call(
            reqwest::Method::PUT,
            &format!("/firewall/sets/{set}"),
            Some(json!({"name": "Office", "direction": "outbound", "default_action": "deny"})),
        )
        .await;
    assert_eq!(
        (code, error["error"].as_str()),
        (400, Some("the direction of a rule set cannot change"))
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_outbound_set_refuses_targets_and_proxy_destinations_before_connecting() {
    let panel = Panel::new().await;
    let api = &panel.api;
    let (node, _agents) = panel.server("edge").await;
    let blocked = Target::start().await;
    let open = Target::start().await;
    let set = api
        .create_set(json!({
            "name": "No blocked port", "scope": "system", "direction": "outbound", "default_action": "allow",
            "rules": [{"action": "deny", "match": {"destinations": ["127.0.0.0/8"], "ports": [blocked.address.port().to_string()]}}],
        }))
        .await;
    let plain = forward("plain", blocked.address);
    let mut socks = forward("socks", blocked.address);
    socks.targets.clear();
    socks.inbound_socks5 = Some(socks5::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: true,
    });
    let mut http = forward("http", blocked.address);
    http.targets.clear();
    http.inbound_http_connect = Some(http_connect::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: true,
    });
    api.apply(&node, &[&plain, &socks, &http]).await;
    api.bind(&node, None, Some(&set)).await;
    api.confirmed(&node).await;

    assert!(
        !echoes(ONE, plain.listen).await,
        "the plain target is refused"
    );
    // SOCKS5 CONNECT to the blocked port: general failure, no connection.
    let mut client = TcpStream::connect(socks.listen).await.unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut selected = [0u8; 2];
    client.read_exact(&mut selected).await.unwrap();
    let ask = |target: SocketAddr| {
        let IpAddr::V4(ip) = target.ip() else {
            unreachable!()
        };
        let mut request = vec![5, 1, 0, 1];
        request.extend(ip.octets());
        request.extend(target.port().to_be_bytes());
        request
    };
    client.write_all(&ask(blocked.address)).await.unwrap();
    let mut reply = [0u8; 10];
    timeout(Duration::from_secs(5), client.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply[1], 5, "SOCKS5 refusal");
    // HTTP CONNECT to the blocked port: 502.
    let mut client = TcpStream::connect(http.listen).await.unwrap();
    let authority = blocked.address.to_string();
    client
        .write_all(format!("CONNECT {authority} HTTP/1.1\r\nHost: {authority}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = [0u8; 12];
    timeout(Duration::from_secs(5), client.read_exact(&mut head))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&head, b"HTTP/1.1 502");
    assert_eq!(
        blocked.peers(),
        0,
        "the blocked target never saw a connection"
    );

    // Another port is not refused: the proxy itself works.
    let mut client = TcpStream::connect(socks.listen).await.unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    client.read_exact(&mut selected).await.unwrap();
    client.write_all(&ask(open.address)).await.unwrap();
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0);
    client.write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    client.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"ping");
    assert_eq!(open.peers(), 1);

    let detail = "server outbound rule set: rule 1 denies (No blocked port)";
    for rule in ["plain", "socks", "http"] {
        api.blocks(&node, rule, |b| {
            b.iter()
                .any(|b| b["reason"] == "firewall" && b["detail"] == detail)
        })
        .await;
    }
    // Without the binding the same target is reached.
    api.bind(&node, None, None).await;
    api.confirmed(&node).await;
    assert!(echoes(ONE, plain.listen).await);
    assert_eq!(blocked.peers(), 1);
}

/// A SOCKS5 proxy without authentication that connects to the IPv4 address
/// it is asked for, counting the clients it accepted.
struct Upstream {
    address: SocketAddr,
    accepted: Arc<AtomicUsize>,
    stop: CancellationToken,
}
impl Upstream {
    async fn start() -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let accepted = Arc::new(AtomicUsize::new(0));
        let stop = CancellationToken::new();
        let (count, shutdown) = (accepted.clone(), stop.clone());
        tokio::spawn(async move {
            loop {
                let next = tokio::select! {_=shutdown.cancelled()=>break,a=listener.accept()=>a};
                let Ok((stream, _)) = next else { break };
                count.fetch_add(1, Ordering::Relaxed);
                tokio::spawn(relay_through(stream));
            }
        });
        Self {
            address,
            accepted,
            stop,
        }
    }
    fn accepted(&self) -> usize {
        self.accepted.load(Ordering::Relaxed)
    }
}
impl Drop for Upstream {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
async fn relay_through(mut stream: TcpStream) -> std::io::Result<()> {
    let mut head = [0u8; 2];
    stream.read_exact(&mut head).await?;
    let mut methods = vec![0u8; usize::from(head[1])];
    stream.read_exact(&mut methods).await?;
    stream.write_all(&[5, 0]).await?;
    let mut request = [0u8; 10];
    stream.read_exact(&mut request).await?;
    assert_eq!(request[3], 1, "the agent asks for an IPv4 address");
    let onward = SocketAddr::new(
        Ipv4Addr::new(request[4], request[5], request[6], request[7]).into(),
        u16::from_be_bytes([request[8], request[9]]),
    );
    let mut onward = TcpStream::connect(onward).await?;
    stream.write_all(&[5, 0, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
    tokio::io::copy_bidirectional(&mut stream, &mut onward).await?;
    Ok(())
}
/// The SOCKS5 reply code for a CONNECT to `target` through `entry`, and
/// whether data then echoes back.
async fn socks_connect(entry: SocketAddr, target: SocketAddr) -> (u8, bool) {
    let mut client = TcpStream::connect(entry).await.unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut selected = [0u8; 2];
    client.read_exact(&mut selected).await.unwrap();
    let IpAddr::V4(ip) = target.ip() else {
        unreachable!()
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend(ip.octets());
    request.extend(target.port().to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut reply = [0u8; 10];
    timeout(Duration::from_secs(10), client.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    if reply[1] != 0 {
        return (reply[1], false);
    }
    client.write_all(b"ping").await.unwrap();
    let mut back = [0u8; 4];
    let echoed = matches!(
        timeout(Duration::from_secs(5), client.read_exact(&mut back)).await,
        Ok(Ok(_)) if &back == b"ping"
    );
    (0, echoed)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_outbound_set_also_guards_the_egress_proxy_upstream() {
    let panel = Panel::new().await;
    let api = &panel.api;
    let (node, _agents) = panel.server("edge").await;
    let target = Target::start().await;
    let (first, second) = (Upstream::start().await, Upstream::start().await);
    let port = |u: &Upstream| u.address.port().to_string();
    let deny = |name: &str, ports: Vec<String>| {
        json!({
            "name": name, "scope": "system", "direction": "outbound", "default_action": "allow",
            "rules": [{"action": "deny", "match": {"destinations": ["127.0.0.0/8"], "ports": ports}}],
        })
    };
    let skip_first = api
        .create_set(deny("Not the first upstream", vec![port(&first)]))
        .await;
    let neither = api
        .create_set(deny("No upstream", vec![port(&first), port(&second)]))
        .await;
    let mut socks = forward("socks", target.address);
    socks.targets.clear();
    socks.connect_timeout_ms = 3000;
    socks.inbound_socks5 = Some(socks5::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: true,
    });
    socks.egress_proxy = Some(relay_platform::egress::Config {
        kind: relay_platform::egress::Kind::Socks5,
        servers: vec![first.address.to_string(), second.address.to_string()],
        username: None,
        password: None,
    });
    api.apply(&node, &[&socks]).await;

    // The first upstream is refused: the agent goes to the second without
    // ever connecting to the first, and the destination is reached.
    api.bind(&node, None, Some(&skip_first)).await;
    api.confirmed(&node).await;
    assert_eq!(socks_connect(socks.listen, target.address).await, (0, true));
    assert_eq!((first.accepted(), second.accepted()), (0, 1));
    assert_eq!(target.peers(), 1);

    // Every upstream refused: the client is refused, nothing is connected
    // and the block record names the upstream and the set's rule.
    api.bind(&node, None, Some(&neither)).await;
    api.confirmed(&node).await;
    let (code, _) = socks_connect(socks.listen, target.address).await;
    assert_ne!(code, 0, "refused");
    assert_eq!((first.accepted(), second.accepted()), (0, 1));
    assert_eq!(target.peers(), 1);
    let detail = format!(
        "egress proxy {}: server outbound rule set: rule 1 denies (No upstream)",
        second.address
    );
    api.blocks(&node, "socks", |b| {
        b.iter()
            .any(|b| b["reason"] == "firewall" && b["detail"] == detail.as_str())
    })
    .await;

    // Without a binding the first upstream is used again: only the set made
    // the agent skip it.
    api.bind(&node, None, None).await;
    api.confirmed(&node).await;
    assert_eq!(socks_connect(socks.listen, target.address).await, (0, true));
    assert_eq!((first.accepted(), second.accepted()), (1, 1));
}

/// The SOCKS5 reply code for a CONNECT to the name `host` on `port`.
async fn socks_connect_name(entry: SocketAddr, host: &str, port: u16) -> u8 {
    let mut client = TcpStream::connect(entry).await.unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut selected = [0u8; 2];
    client.read_exact(&mut selected).await.unwrap();
    let mut request = vec![5, 1, 0, 3, u8::try_from(host.len()).unwrap()];
    request.extend(host.as_bytes());
    request.extend(port.to_be_bytes());
    client.write_all(&request).await.unwrap();
    let mut reply = [0u8; 2];
    timeout(Duration::from_secs(10), client.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    reply[1]
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_name_that_is_not_a_hostname_never_reaches_the_egress_proxy_by_name() {
    let panel = Panel::new().await;
    let api = &panel.api;
    let (node, _agents) = panel.server("edge").await;
    let upstream = Upstream::start().await;
    let set = api
        .create_set(json!({
            "name": "No internal", "scope": "system", "direction": "outbound", "default_action": "allow",
            "rules": [{"action": "deny", "match": {"destinations": ["*.internal.corp"]}}],
        }))
        .await;
    let mut socks = forward("socks", upstream.address);
    socks.targets.clear();
    socks.connect_timeout_ms = 3000;
    socks.inbound_socks5 = Some(socks5::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: true,
    });
    socks.egress_proxy = Some(relay_platform::egress::Config {
        kind: relay_platform::egress::Kind::Socks5,
        servers: vec![upstream.address.to_string()],
        username: None,
        password: None,
    });
    api.apply(&node, &[&socks]).await;
    api.bind(&node, None, Some(&set)).await;
    api.confirmed(&node).await;
    assert_ne!(
        socks_connect_name(socks.listen, "db.internal.corp", 443).await,
        0
    );
    // The set's entry does not match this name, but a resolver could read
    // it as db.internal.corp: it is resolved here, not sent on by name.
    assert_ne!(
        socks_connect_name(socks.listen, "db.internal.corp\0", 443).await,
        0
    );
    assert_eq!(upstream.accepted(), 0, "the egress proxy was never asked");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_bound_set_cannot_be_deleted() {
    let panel = Panel::new().await;
    let api = &panel.api;
    let (node, _agents) = panel.server("edge").await;
    let server_set = api
        .create_set(inbound("Server set", "system", "allow", &[]))
        .await;
    let rule_set = api
        .create_set(inbound("Rule set", "tenant", "allow", &[]))
        .await;
    api.bind(&node, Some(&server_set), None).await;
    let mut guarded = forward("guarded", "127.0.0.1:9".parse().unwrap());
    guarded.firewall_inbound_set = Some(rule_set.clone());
    api.apply(&node, &[&guarded]).await;

    let (code, error) = api
        .call(
            reqwest::Method::DELETE,
            &format!("/firewall/sets/{server_set}"),
            None,
        )
        .await;
    assert_eq!(
        (code, error["error"].as_str()),
        (
            409,
            Some(
                "rule set Server set is still bound: server edge (inbound); remove these bindings first"
            )
        )
    );
    let (code, error) = api
        .call(
            reqwest::Method::DELETE,
            &format!("/firewall/sets/{rule_set}"),
            None,
        )
        .await;
    assert_eq!(
        (code, error["error"].as_str()),
        (
            409,
            Some(
                "rule set Rule set is still bound: rule guarded on server edge; remove these bindings first"
            )
        )
    );
    let view = api.get(&format!("/firewall/sets/{rule_set}")).await;
    assert_eq!(view["bindings"][0]["layer"], "rule_inbound");
    assert_eq!(view["bindings"][0]["rule_id"], "guarded");

    api.bind(&node, None, None).await;
    let (code, _) = api
        .call(
            reqwest::Method::DELETE,
            &format!("/firewall/sets/{server_set}"),
            None,
        )
        .await;
    assert_eq!(code, 200);
    let (code, _) = api
        .call(
            reqwest::Method::GET,
            &format!("/firewall/sets/{server_set}"),
            None,
        )
        .await;
    assert_eq!(code, 404);
    // A rule bound to a set that is gone cannot be published again.
    let (code, error) = api.publish(&node, &[&guarded]).await;
    assert_eq!(code, 200, "{error}");
    guarded.firewall_inbound_set = Some(server_set.clone());
    let (code, error) = api.publish(&node, &[&guarded]).await;
    assert_eq!(
        (code, error["error"].as_str().map(str::to_owned)),
        (
            404,
            Some(format!("firewall rule set {server_set} not found"))
        )
    );
}

/// One sync as an agent of 0.149.0 or earlier, which reports no support.
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
async fn servers_whose_agent_is_too_old_refuse_bindings_with_409() {
    let panel = Panel::new().await;
    let (api, store, admin) = (&panel.api, &panel.store, &panel.admin);
    let (old, _) = store.create_node(admin, "default", "old").unwrap();
    let (fresh, _) = store.create_node(admin, "default", "fresh").unwrap();
    let sent = old_sync(store, &old.id);
    // The controller sends the (empty) policy; an older agent ignores it.
    assert!(sent["firewall"]["hash"].is_string(), "{sent}");
    let node = api.node(&old.id).await;
    assert_eq!(node["firewall_support"], false);
    assert_eq!(node["firewall"]["state"], "unused");
    let too_old = "the agent on server old is too old for firewall rule sets; upgrade it first";
    let server_set = api
        .create_set(inbound("Server", "system", "deny", &[]))
        .await;
    let rule_set = api.create_set(inbound("Rule", "tenant", "deny", &[])).await;

    let (code, error) = api
        .call(
            reqwest::Method::PUT,
            &format!("/nodes/{}/firewall", old.id),
            Some(json!({"inbound_set_id": server_set})),
        )
        .await;
    assert_eq!((code, error["error"].as_str()), (409, Some(too_old)));
    let (code, error) = api
        .call(
            reqwest::Method::PUT,
            &format!("/nodes/{}/firewall", fresh.id),
            Some(json!({"inbound_set_id": server_set})),
        )
        .await;
    assert_eq!(
        (code, error["error"].as_str()),
        (
            409,
            Some(
                "server fresh has not connected to the panel yet; firewall rule sets need its agent to report in first"
            )
        )
    );
    let mut bound = forward("bound", "127.0.0.1:9".parse().unwrap());
    bound.firewall_inbound_set = Some(rule_set.clone());
    let mut plain = bound.clone();
    plain.firewall_inbound_set = None;
    // Single and batch publish, and a shared rule.
    let (code, error) = api.publish(&old.id, &[&bound]).await;
    assert_eq!((code, error["error"].as_str()), (409, Some(too_old)));
    let (code, error) = api
        .call(
            reqwest::Method::POST,
            "/configurations/publish",
            Some(
                json!({"updates": [{"node_id": old.id, "expected_revision": 0, "rules": [bound]}]}),
            ),
        )
        .await;
    assert_eq!((code, error["error"].as_str()), (409, Some(too_old)));
    let (code, error) = api
        .call(
            reqwest::Method::POST,
            "/shared-rules",
            Some(json!({"name": "Shared", "node_ids": [old.id], "listen_port": free_address().port(), "rule": bound})),
        )
        .await;
    assert_eq!(code, 409, "{error}");
    assert!(error.to_string().contains(too_old), "{error}");
    // The panel still shows nothing to confirm, and nothing new reaches the agent.
    let (code, config) = api.publish(&old.id, &[&plain]).await;
    assert_eq!(code, 200, "{config}");
    let sent = old_sync(store, &old.id);
    assert!(
        !sent["config"].to_string().contains("firewall_inbound_set"),
        "{sent}"
    );
    // Unbinding never needs the agent.
    api.bind(&old.id, None, None).await;

    // Once the agent reports support, the same binding goes through.
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
                applied_revision: 1,
                apply_error: None,
                usage: vec![],
                stats: EngineStats {
                    firewall: Some(relay_platform::firewall::Report::default()),
                    ..EngineStats::default()
                },
            },
        )
        .unwrap();
    assert_eq!(api.node(&old.id).await["firewall_support"], true);
    let status = api.bind(&old.id, Some(&server_set), None).await;
    assert_eq!(status["inbound_set_name"], "Server");
    assert_eq!(status["state"], "waiting");
}

/// One sync as a current agent that reports `firewall`.
fn report_sync(store: &Store, node: &str, firewall: relay_platform::firewall::Report) {
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
    store
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
                stats: EngineStats {
                    firewall: Some(firewall),
                    ..EngineStats::default()
                },
            },
        )
        .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_agent_that_stops_reporting_is_no_longer_shown_as_applied() {
    let panel = Panel::new().await;
    let (api, store, admin) = (&panel.api, &panel.store, &panel.admin);
    let (node, _) = store.create_node(admin, "default", "edge").unwrap();
    report_sync(store, &node.id, Default::default());
    let set = api
        .create_set(inbound("Server", "system", "allow", &[]))
        .await;
    let desired = api.bind(&node.id, Some(&set), None).await["desired_hash"]
        .as_str()
        .unwrap()
        .to_owned();
    let confirms = || relay_platform::firewall::Report {
        applied_hash: Some(desired.clone()),
        error: None,
    };
    report_sync(store, &node.id, confirms());
    let status = api.node(&node.id).await["firewall"].clone();
    assert_eq!(status["state"], "applied", "{status}");
    assert_eq!(status["applied_hash"], desired.as_str());
    // A downgraded agent, or one whose state directory is new, sends no
    // report: it enforces nothing, whatever it confirmed before.
    old_sync(store, &node.id);
    let status = api.node(&node.id).await["firewall"].clone();
    assert_eq!(status["state"], "waiting", "{status}");
    assert_eq!(status["applied_hash"], Value::Null);
    report_sync(store, &node.id, confirms());
    assert_eq!(api.node(&node.id).await["firewall"]["state"], "applied");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn tenants_never_see_or_use_another_tenants_sets() {
    let panel = Panel::new().await;
    let (api, store, admin) = (&panel.api, &panel.store, &panel.admin);
    let mut tenants = vec![];
    for name in ["alpha", "beta"] {
        let tenant = store.create_tenant(admin, name).unwrap();
        store
            .create_user(
                admin,
                &tenant,
                &format!("{name}-admin"),
                PASSWORD,
                Role::TenantAdmin,
            )
            .unwrap();
        store
            .create_user(
                admin,
                &tenant,
                &format!("{name}-viewer"),
                PASSWORD,
                Role::Viewer,
            )
            .unwrap();
        tenants.push(tenant);
    }
    let alpha = Api::login(&api.origin, "alpha-admin", PASSWORD).await;
    let beta = Api::login(&api.origin, "beta-admin", PASSWORD).await;
    let viewer = Api::login(&api.origin, "beta-viewer", PASSWORD).await;
    let alpha_set = alpha
        .create_set(inbound(
            "Alpha office",
            "tenant",
            "deny",
            &[("allow", &["192.0.2.0/24"])],
        ))
        .await;
    let beta_set = beta
        .create_set(inbound("Beta", "tenant", "allow", &[]))
        .await;
    let system_set = api
        .create_set(inbound("System", "system", "allow", &[]))
        .await;
    let ids = |sets: Value| -> Vec<String> {
        sets.as_array()
            .unwrap()
            .iter()
            .map(|s| s["id"].as_str().unwrap().to_owned())
            .collect()
    };
    assert_eq!(
        ids(beta.get("/firewall/sets").await),
        vec![beta_set.clone()]
    );
    assert_eq!(
        ids(viewer.get("/firewall/sets").await),
        vec![beta_set.clone()]
    );
    assert_eq!(api.get("/firewall/sets").await.as_array().unwrap().len(), 3);
    for (method, body) in [
        (reqwest::Method::GET, None),
        (
            reqwest::Method::PUT,
            Some(json!({"name": "Mine", "direction": "inbound", "default_action": "allow"})),
        ),
        (reqwest::Method::DELETE, None),
    ] {
        for id in [&alpha_set, &system_set] {
            let (code, _) = beta
                .call(
                    method.clone(),
                    &format!("/firewall/sets/{id}"),
                    body.clone(),
                )
                .await;
            assert_eq!(code, 404, "{method} {id}");
        }
    }
    let (code, _) = beta
        .call(
            reqwest::Method::POST,
            "/firewall/test",
            Some(json!({"set_id": alpha_set, "source": "192.0.2.1"})),
        )
        .await;
    assert_eq!(code, 404);
    // A tenant keeps no system sets, picks no other tenant, binds no server.
    let (code, _) = beta
        .call(
            reqwest::Method::POST,
            "/firewall/sets",
            Some(inbound("Sys", "system", "allow", &[])),
        )
        .await;
    assert_eq!(code, 403);
    let mut other = inbound("Other", "tenant", "allow", &[]);
    other["tenant_id"] = json!(tenants[0]);
    let (code, _) = beta
        .call(reqwest::Method::POST, "/firewall/sets", Some(other))
        .await;
    assert_eq!(code, 404);
    let (code, _) = viewer
        .call(
            reqwest::Method::POST,
            "/firewall/sets",
            Some(inbound("V", "tenant", "allow", &[])),
        )
        .await;
    assert_eq!(code, 403);
    let (beta_node, _) = store.create_node(admin, &tenants[1], "beta-edge").unwrap();
    let (code, _) = beta
        .call(
            reqwest::Method::PUT,
            &format!("/nodes/{}/firewall", beta_node.id),
            Some(json!({"inbound_set_id": null})),
        )
        .await;
    assert_eq!(code, 403);
    // Beta's rule cannot use Alpha's set: it does not exist for Beta.
    let owner = beta.get("/session").await;
    let mut rule = forward("beta-rule", "127.0.0.1:9".parse().unwrap());
    rule.tenant_id = tenants[1].clone();
    rule.owner_id = owner["id"].as_str().unwrap().to_owned();
    rule.firewall_inbound_set = Some(alpha_set.clone());
    let (code, error) = beta.publish(&beta_node.id, &[&rule]).await;
    assert_eq!(
        (code, error["error"].as_str().map(str::to_owned)),
        (
            404,
            Some(format!("firewall rule set {alpha_set} not found"))
        )
    );
    // Its own set gets as far as the agent check.
    rule.firewall_inbound_set = Some(beta_set);
    let (code, error) = beta.publish(&beta_node.id, &[&rule]).await;
    assert_eq!(code, 409, "{error}");

    // The tester tells Beta what its server's system sets decide, never
    // which set or rule decided.
    report_sync(store, &beta_node.id, Default::default());
    let guard_in = api
        .create_set(inbound(
            "System guard",
            "system",
            "allow",
            &[("deny", &["192.0.2.0/24"])],
        ))
        .await;
    let guard_out = api
        .create_set(json!({
            "name": "System out", "scope": "system", "direction": "outbound", "default_action": "allow",
            "rules": [{"action": "deny", "match": {"destinations": ["*.example.com"]}}],
        }))
        .await;
    api.bind(&beta_node.id, Some(&guard_in), Some(&guard_out))
        .await;
    for body in [
        json!({"node_id": beta_node.id, "source": "192.0.2.1"}),
        json!({"node_id": beta_node.id, "destination": "api.example.com", "port": 443}),
    ] {
        let seen = beta
            .ok(reqwest::Method::POST, "/firewall/test", body.clone())
            .await;
        assert_eq!(seen["decision"], "deny", "{seen}");
        let layer = &seen["layers"][0];
        assert_eq!(layer["result"], "deny", "{seen}");
        assert_eq!(layer["default_action"], false, "{seen}");
        for hidden in ["set_id", "set_name", "rule_index"] {
            assert!(layer.get(hidden).is_none(), "{hidden}: {seen}");
        }
        let text = seen.to_string();
        assert!(
            !text.contains(&guard_in) && !text.contains(&guard_out) && !text.contains("System"),
            "{seen}"
        );
        // The system administrator sees which.
        let full = api.ok(reqwest::Method::POST, "/firewall/test", body).await;
        let layer = &full["layers"][0];
        assert_eq!(layer["rule_index"], 0, "{full}");
        assert!(
            layer["set_name"].as_str().unwrap().starts_with("System"),
            "{full}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sets_are_limited_in_number_per_tenant_and_in_size() {
    let panel = Panel::new().await;
    let api = &panel.api;
    for number in 0..64 {
        api.create_set(inbound(&format!("Set {number}"), "tenant", "allow", &[]))
            .await;
    }
    let (code, error) = api
        .call(
            reqwest::Method::POST,
            "/firewall/sets",
            Some(inbound("One more", "tenant", "allow", &[])),
        )
        .await;
    assert_eq!(
        (code, error["error"].as_str()),
        (
            409,
            Some("at most 64 firewall rule sets per tenant; delete one first")
        )
    );
    // System sets are counted apart.
    let small = api
        .create_set(json!({"name": "Small", "scope": "system", "direction": "outbound", "default_action": "allow"}))
        .await;
    // 65 536 names of about 20 characters: over 1 MiB as a set, under the
    // 2 MiB a request may carry.
    let rules: Vec<Value> = (0..256)
        .map(|r| {
            let names: Vec<String> = (0..256).map(|n| format!("h{n}.r{r}.example.com")).collect();
            json!({"action": "deny", "match": {"destinations": names}})
        })
        .collect();
    let big = json!({"name": "Big", "scope": "system", "direction": "outbound", "default_action": "allow", "rules": rules});
    let too_big = Some("a rule set is at most 1024 KiB; use fewer rules or entries");
    let (code, error) = api
        .call(reqwest::Method::POST, "/firewall/sets", Some(big.clone()))
        .await;
    assert_eq!((code, error["error"].as_str()), (400, too_big));
    // An edit that makes a set too big is refused too, bound or not.
    let (code, error) = api
        .call(
            reqwest::Method::PUT,
            &format!("/firewall/sets/{small}"),
            Some(big),
        )
        .await;
    assert_eq!((code, error["error"].as_str()), (400, too_big));
    assert_eq!(
        api.get(&format!("/firewall/sets/{small}")).await["revision"],
        1
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_tester_answers_as_the_agent_acts() {
    let panel = Panel::new().await;
    let api = &panel.api;
    let (node, _agents) = panel.server("edge").await;
    let echo = tcp_echo().await;
    let server_set = api
        .create_set(inbound(
            "Server",
            "system",
            "allow",
            &[("deny", &["127.0.0.3/32"])],
        ))
        .await;
    let rule_set = api
        .create_set(inbound(
            "Rule",
            "tenant",
            "deny",
            &[("deny", &["127.0.0.4/32"]), ("allow", &["127.0.0.0/8"])],
        ))
        .await;
    api.bind(&node, Some(&server_set), None).await;
    let mut guarded = forward("guarded", echo.address);
    guarded.firewall_inbound_set = Some(rule_set.clone());
    api.apply(&node, &[&guarded]).await;
    let desired = api.node(&node).await["firewall"]["desired_hash"].clone();
    let test = |source: &str| json!({"node_id": node, "rule_id": "guarded", "source": source});

    let allowed = api
        .ok(reqwest::Method::POST, "/firewall/test", test("127.0.0.1"))
        .await;
    assert_eq!(allowed["decision"], "allow", "{allowed}");
    assert_eq!(allowed["policy_hash"], desired);
    let layers = allowed["layers"].as_array().unwrap();
    assert_eq!(layers.len(), 3, "{allowed}");
    assert_eq!(
        (
            &layers[0]["layer"],
            &layers[0]["default_action"],
            &layers[0]["result"]
        ),
        (&json!("server_inbound"), &json!(true), &json!("allow"))
    );
    assert_eq!(
        (
            &layers[1]["layer"],
            &layers[1]["rule_index"],
            &layers[1]["result"]
        ),
        (&json!("rule_inbound"), &json!(1), &json!("allow"))
    );
    assert_eq!(layers[1]["set_name"], "Rule");
    assert_eq!(
        (&layers[2]["layer"], &layers[2]["result"]),
        (&json!("rule_lists"), &json!("allow"))
    );
    assert!(
        echoes(ONE, guarded.listen).await,
        "the agent lets it in too"
    );

    let denied = api
        .ok(reqwest::Method::POST, "/firewall/test", test("127.0.0.4"))
        .await;
    assert_eq!(denied["decision"], "deny", "{denied}");
    let layers = denied["layers"].as_array().unwrap();
    assert_eq!(
        (&layers[1]["rule_index"], &layers[1]["result"]),
        (&json!(0), &json!("deny"))
    );
    assert!(
        !echoes(FOUR, guarded.listen).await,
        "the agent refuses it too"
    );
    api.blocks(&node, "guarded", |b| {
        b.iter().any(|b| {
            b["source"] == "127.0.0.4"
                && b["detail"] == "rule inbound rule set: rule 1 denies (Rule)"
        })
    })
    .await;

    // A set alone, and a destination by name and by address.
    let outbound = api
        .create_set(json!({
            "name": "Out", "scope": "system", "direction": "outbound", "default_action": "allow",
            "rules": [
                {"action": "deny", "match": {"destinations": ["10.0.0.0/8"]}},
                {"action": "allow", "match": {"destinations": ["*.example.com"], "ports": ["443"]}},
            ],
        }))
        .await;
    let ask = |body: Value| api.ok(reqwest::Method::POST, "/firewall/test", body);
    let by_name =
        ask(json!({"set_id": outbound, "destination": "api.example.com", "port": 443})).await;
    assert_eq!(by_name["decision"], "needs_address", "{by_name}");
    let private =
        ask(json!({"set_id": outbound, "destination": "api.example.com", "port": 443, "address": "10.1.2.3"}))
            .await;
    assert_eq!(
        (&private["decision"], &private["layers"][0]["rule_index"]),
        (&json!("deny"), &json!(0))
    );
    let public = ask(
        json!({"set_id": outbound, "destination": "api.example.com", "port": 443, "address": "203.0.113.5"}),
    )
    .await;
    assert_eq!(
        (&public["decision"], &public["layers"][0]["rule_index"]),
        (&json!("allow"), &json!(1))
    );
    let (code, error) = api
        .call(
            reqwest::Method::POST,
            "/firewall/test",
            Some(json!({"set_id": outbound, "source": "192.0.2.1"})),
        )
        .await;
    assert_eq!(
        (code, error["error"].as_str()),
        (
            400,
            Some("this is an outbound set: give a destination and port")
        )
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn sets_check_their_rules_and_bindings_their_direction() {
    let panel = Panel::new().await;
    let api = &panel.api;
    let (node, _agents) = panel.server("edge").await;
    // A match of the other direction is refused.
    let (code, error) = api
        .call(
            reqwest::Method::POST,
            "/firewall/sets",
            Some(json!({"name": "Bad", "direction": "inbound", "default_action": "allow",
                         "rules": [{"action": "deny", "match": {"destinations": ["example.com"]}}]})),
        )
        .await;
    assert_eq!(
        (code, error["error"].as_str()),
        (
            400,
            Some("rule 1: an inbound set matches source addresses only, not destinations or ports")
        )
    );
    let (code, _) = api
        .call(
            reqwest::Method::POST,
            "/firewall/sets",
            Some(
                json!({"name": "Bad", "direction": "outbound", "default_action": "allow",
                         "rules": [{"action": "deny", "match": {"sources": ["192.0.2.0/24"]}}]}),
            ),
        )
        .await;
    assert_eq!(code, 400);
    let outbound = api
        .create_set(json!({"name": "Out", "scope": "system", "direction": "outbound", "default_action": "allow"}))
        .await;
    let tenant_inbound = api
        .create_set(inbound("Tenant in", "tenant", "allow", &[]))
        .await;
    let (code, _) = api
        .call(
            reqwest::Method::PUT,
            &format!("/nodes/{node}/firewall"),
            Some(json!({"inbound_set_id": outbound})),
        )
        .await;
    assert_eq!(code, 400, "an outbound set is not a server's inbound set");
    let (code, error) = api
        .call(
            reqwest::Method::PUT,
            &format!("/nodes/{node}/firewall"),
            Some(json!({"inbound_set_id": tenant_inbound})),
        )
        .await;
    assert_eq!(
        (code, error["error"].as_str()),
        (
            400,
            Some("rule set Tenant in belongs to a tenant; servers take system rule sets")
        )
    );
    let mut rule = forward("r", "127.0.0.1:9".parse().unwrap());
    rule.firewall_inbound_set = Some(outbound.clone());
    let (code, _) = api.publish(&node, &[&rule]).await;
    assert_eq!(code, 404, "a rule takes only its tenant's sets");
}
