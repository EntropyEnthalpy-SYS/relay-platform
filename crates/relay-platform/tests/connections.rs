//! Live connections and block records through the public API with real
//! agents on loopback: TCP and UDP sessions with their client, target and
//! growing byte counts that go away when they end; deny-list, allow-list
//! and connection-limit refusals as aggregated records, sent once; a SOCKS5
//! client's destination and a refused one; single TCP, UDP and SOCKS5 UDP
//! sessions ended from the panel while others go on; block records that
//! survive a controller restart, page and stay apart per tenant; then,
//! without agents, older agents that get no requests, oversize reports, and
//! who may look or end sessions; an agent whose controller goes back to an
//! older release, or keeps refusing its reports. Then, on agents' engines,
//! one session of each kind that can end, ended: its client and its target
//! side close (or, for UDP, nothing more is forwarded) while other sessions
//! go on, also over IPv6, through TLS, WebSocket and multipath hops from
//! either server, after PROXY headers, with proxy inbounds inside TLS, over
//! MPTCP, and while a SOCKS5 UDP relay waits for a DNS server that never
//! answers; and those that cannot end alone (a protocol gateway's bridge,
//! Shadowsocks over TCP, UDP over TCP and UDP) answer `unsupported` and go
//! on forwarding.
//! Waits poll for up to 20 s; nothing depends on exact timing.
mod common;
#[allow(dead_code)]
#[path = "common/tls.rs"]
mod tls;
use common::*;
use http_body_util::Empty;
use hyper::{Request, StatusCode, body::Bytes, client::conn::http2::SendRequest};
use hyper_util::rt::{TokioExecutor, TokioIo};
use relay_platform::{
    agent::{self, AgentOptions},
    api::{self, AppState},
    connections::{Block, BlockBatch, Cursor, Report, Retention, Session, Snapshot, Termination},
    engine::Engine,
    gateway, http_connect, http2_connect,
    model::*,
    multipath, shadowsocks, socks5,
    store::{Actor, Role, Scope, Store, write_secret},
};
use serde_json::{Value, json};
use sha2::{Digest, Sha256};
use std::{
    net::SocketAddr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::mpsc,
    time::{Instant, sleep, timeout},
};
use tokio_util::sync::CancellationToken;

async fn serve(store: Store) -> (SocketAddr, CancellationToken) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    (address, serve_on(store, listener).0)
}
/// Serves until the token is cancelled; the task ends once it stopped.
fn serve_on(
    store: Store,
    listener: TcpListener,
) -> (CancellationToken, tokio::task::JoinHandle<()>) {
    let stop = CancellationToken::new();
    let router = api::router(AppState::new(store).with_shutdown(stop.clone()));
    let shutdown = stop.clone();
    let task = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await
        .unwrap();
    });
    (stop, task)
}

struct Api {
    client: reqwest::Client,
    origin: String,
    token: String,
}
impl Api {
    async fn new(address: SocketAddr, username: &str) -> Self {
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        let origin = format!("http://{address}");
        let body: Value = client
            .post(format!("{origin}/api/v1/auth/login"))
            .json(&json!({"username": username, "password": PASSWORD}))
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
    fn with_token(&self, token: &str) -> Self {
        Self {
            client: self.client.clone(),
            origin: self.origin.clone(),
            token: token.into(),
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
    /// The body of `GET path` as sent.
    async fn text(&self, path: &str) -> String {
        let response = self
            .client
            .get(format!("{}/api/v1{path}", self.origin))
            .bearer_auth(&self.token)
            .send()
            .await
            .unwrap();
        assert_eq!(response.status().as_u16(), 200, "GET {path}");
        response.text().await.unwrap()
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
    /// Publishes `rules` on `node` and waits until its agent applied them.
    async fn apply(&self, node: &str, rules: &[&Rule]) {
        let config = self.get(&format!("/nodes/{node}/config")).await;
        let (code, config) = self
            .call(
                reqwest::Method::PUT,
                &format!("/nodes/{node}/config"),
                Some(json!({"expected_revision": config["revision"], "rules": rules})),
            )
            .await;
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
    /// The rule's sessions once a snapshot that `check` accepts arrived.
    /// Snapshots are reused for 2 s, so this asks again until one does.
    async fn connections(
        &self,
        node: &str,
        rule: &str,
        what: &str,
        check: impl Fn(&Value) -> bool,
    ) -> Value {
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            let view = self
                .get(&format!("/nodes/{node}/rules/{rule}/connections"))
                .await;
            if view["state"] == "ready" && check(&view) {
                return view;
            }
            assert!(Instant::now() < until, "waiting for {what}: {view}");
            sleep(Duration::from_millis(100)).await;
        }
    }
    /// The node's block records of `rule` once `check` accepts them.
    async fn blocks(&self, node: &str, rule: &str, check: impl Fn(&[Value]) -> bool) -> Vec<Value> {
        let until = Instant::now() + Duration::from_secs(20);
        loop {
            let view = self
                .get(&format!("/nodes/{node}/blocks?rule_id={rule}"))
                .await;
            assert_eq!(view["supported"], true);
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
    fn start(dir: &Path, origin: &str, nodes: &[(&str, &str)]) -> Self {
        let mut stops = vec![];
        for (index, (node, enrollment)) in nodes.iter().enumerate() {
            let secret = dir.join(format!("agent-{index}.secret"));
            write_secret(&secret, enrollment.as_bytes()).unwrap();
            let db = Store::open(&dir.join(format!("agent-{index}.db"))).unwrap();
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
    admin: Actor,
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
        let api = Api::new(address, "admin").await;
        Self {
            temp,
            store,
            admin,
            api,
            stop,
        }
    }
    /// A server with a running agent, once it reported support.
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
            .until("the agent to report support", || async {
                self.api.node(&node.id).await["connections_support"] == true
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

fn forward(id: &str, target: SocketAddr, protocol: Protocol) -> Rule {
    let mut rule = rule(target, protocol);
    rule.id = id.into();
    rule.name = id.into();
    rule
}
fn session(view: &Value, client: SocketAddr) -> Option<&Value> {
    view["sessions"]
        .as_array()
        .unwrap()
        .iter()
        .find(|s| s["client"] == client.to_string())
}
async fn echo_round<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S, bytes: usize) {
    let payload = vec![0x5a; bytes];
    stream.write_all(&payload).await.unwrap();
    let mut back = vec![0; bytes];
    timeout(Duration::from_secs(5), stream.read_exact(&mut back))
        .await
        .unwrap()
        .unwrap();
}
/// Connects and waits until the relay closes the connection.
async fn refused(entry: SocketAddr) {
    let mut stream = TcpStream::connect(entry).await.unwrap();
    let mut byte = [0u8; 1];
    let read = timeout(Duration::from_secs(5), stream.read(&mut byte))
        .await
        .expect("a refused connection is closed");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_and_udp_sessions_show_their_client_target_and_bytes_and_go_away() {
    let panel = Panel::new().await;
    let (node, _agents) = panel.server("tokyo").await;
    let api = &panel.api;
    let (tcp_echo, udp_echo) = (tcp_echo().await, udp_echo().await);
    let web = forward("web", tcp_echo.address, Protocol::Tcp);
    let mut dns = forward("dns", udp_echo.address, Protocol::Udp);
    dns.idle_timeout_secs = 4;
    api.apply(&node, &[&web, &dns]).await;

    let mut first = TcpStream::connect(web.listen).await.unwrap();
    let mut second = TcpStream::connect(web.listen).await.unwrap();
    echo_round(&mut first, 5).await;
    echo_round(&mut second, 7).await;
    let (a, b) = (first.local_addr().unwrap(), second.local_addr().unwrap());

    let view = api
        .connections(&node, "web", "both TCP sessions", |v| {
            v["totals"]["tcp"] == 2
                && session(v, a).is_some_and(|s| s["download_bytes"] == 5)
                && session(v, b).is_some_and(|s| s["download_bytes"] == 7)
        })
        .await;
    assert_eq!(view["totals"]["udp"], 0);
    assert_eq!(view["truncated"], false);
    assert!(view["taken_at_ms"].as_i64().unwrap() > 0);
    for (client, bytes) in [(a, 5), (b, 7)] {
        let s = session(&view, client).unwrap();
        assert_eq!(s["protocol"], "tcp");
        assert_eq!(s["udp"], Value::Null, "omitted for TCP");
        assert_eq!(s["target_index"], 0);
        assert_eq!(s["target"], tcp_echo.address.to_string());
        assert_eq!(s["remote"], tcp_echo.address.to_string());
        assert_eq!(s["upload_bytes"], bytes);
        assert!(s["started_ms"].as_i64().unwrap() > 0);
    }
    // Newest first.
    assert_eq!(view["sessions"][0]["client"], b.to_string());
    // The counters of the rule: accepted connections and dials per target.
    let counters = &view["counters"];
    assert!(
        counters["inbound"]["connected"].as_u64().unwrap() >= 2,
        "{counters}"
    );
    assert_eq!(counters["targets"][0]["target_index"], 0);
    assert_eq!(
        counters["targets"][0]["target_address"],
        tcp_echo.address.to_string()
    );
    assert!(
        counters["targets"][0]["counts"]["connected"]
            .as_u64()
            .unwrap()
            >= 2
    );

    // Bytes grow while the session runs.
    echo_round(&mut first, 1000).await;
    api.connections(&node, "web", "the first session's new bytes", |v| {
        session(v, a).is_some_and(|s| s["upload_bytes"] == 1005 && s["download_bytes"] == 1005)
    })
    .await;

    // A UDP session, seen before its idle timeout ends it.
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.send_to(b"ping", dns.listen).await.unwrap();
    let mut back = [0u8; 16];
    timeout(Duration::from_secs(5), udp.recv_from(&mut back))
        .await
        .unwrap()
        .unwrap();
    let view = api
        .connections(&node, "dns", "the UDP session", |v| v["totals"]["udp"] == 1)
        .await;
    let s = session(&view, udp.local_addr().unwrap()).unwrap();
    assert_eq!(
        (s["protocol"].as_str(), s["udp"].as_bool()),
        (Some("udp"), Some(true))
    );
    assert_eq!(s["target"], udp_echo.address.to_string());
    assert_eq!(s["remote"], udp_echo.address.to_string());
    assert_eq!(
        (s["upload_bytes"].as_u64(), s["download_bytes"].as_u64()),
        (Some(4), Some(4))
    );

    // Closed sessions go away; the UDP one ends after its idle timeout.
    drop((first, second));
    api.connections(&node, "web", "the closed TCP sessions to go", |v| {
        v["totals"]["tcp"] == 0 && v["sessions"].as_array().unwrap().is_empty()
    })
    .await;
    api.connections(&node, "dns", "the idle UDP session to go", |v| {
        v["totals"]["udp"] == 0
    })
    .await;
    // A rule the node does not have.
    let (code, _) = api
        .call(
            reqwest::Method::GET,
            &format!("/nodes/{node}/rules/missing/connections"),
            None,
        )
        .await;
    assert_eq!(code, 404);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn refusals_become_aggregated_records_that_are_sent_once() {
    let panel = Panel::new().await;
    let (node, _agents) = panel.server("osaka").await;
    let api = &panel.api;
    let echo = tcp_echo().await;
    let mut denied = forward("denied", echo.address, Protocol::Tcp);
    denied.deny_sources = vec!["127.0.0.0/8".parse().unwrap()];
    let mut allowed = forward("allowed", echo.address, Protocol::Tcp);
    allowed.allow_sources = vec!["10.0.0.0/8".parse().unwrap()];
    let mut limited = forward("limited", echo.address, Protocol::Tcp);
    limited.max_connections = 1;
    api.apply(&node, &[&denied, &allowed, &limited]).await;

    for _ in 0..3 {
        refused(denied.listen).await;
    }
    for _ in 0..2 {
        refused(allowed.listen).await;
    }
    let mut held = TcpStream::connect(limited.listen).await.unwrap();
    echo_round(&mut held, 3).await;
    for _ in 0..2 {
        refused(limited.listen).await;
    }

    let one = |reason: &'static str, count: u64| {
        move |blocks: &[Value]| {
            blocks.len() == 1 && blocks[0]["reason"] == reason && blocks[0]["count"] == count
        }
    };
    let blocks = api.blocks(&node, "denied", one("source_denied", 3)).await;
    assert_eq!(blocks[0]["detail"], "matches deny-list network 127.0.0.0/8");
    assert_eq!(blocks[0]["source"], "127.0.0.1");
    assert_eq!(blocks[0]["protocol"], "tcp");
    assert_eq!(blocks[0]["rule_id"], "denied");
    let (first, last) = (
        blocks[0]["first_ms"].as_i64().unwrap(),
        blocks[0]["last_ms"].as_i64().unwrap(),
    );
    assert!(first > 0 && last >= first);
    let blocks = api
        .blocks(&node, "allowed", one("source_not_allowed", 2))
        .await;
    assert_eq!(blocks[0]["detail"], "not in the allow list");
    let blocks = api
        .blocks(&node, "limited", one("connection_limit", 2))
        .await;
    assert_eq!(blocks[0]["detail"], "limit 1 connections");

    // Every rule's records, the latest change first; and at most `limit`.
    let all = api.get(&format!("/nodes/{node}/blocks")).await;
    let rules: Vec<&str> = all["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["rule_id"].as_str().unwrap())
        .collect();
    assert_eq!(rules, ["limited", "allowed", "denied"]);
    let limited_view = api.get(&format!("/nodes/{node}/blocks?limit=1")).await;
    assert_eq!(limited_view["blocks"].as_array().unwrap().len(), 1);

    // Many more syncs bring nothing twice.
    sleep(Duration::from_millis(1500)).await;
    let again = api.get(&format!("/nodes/{node}/blocks")).await;
    assert_eq!(again["blocks"], all["blocks"]);
    // More refusals of the same source grow the same record.
    refused(denied.listen).await;
    refused(denied.listen).await;
    api.blocks(&node, "denied", one("source_denied", 5)).await;
    assert_eq!(
        api.get(&format!("/nodes/{node}/blocks")).await["blocks"]
            .as_array()
            .unwrap()
            .len(),
        3
    );
    // The rule's counters count refusals since the agent started.
    let view = api
        .connections(&node, "denied", "refusals in the counters", |v| {
            v["counters"]["refused"] == json!([{"reason": "source_denied", "count": 5}])
        })
        .await;
    assert_eq!(view["totals"]["tcp"], 0);
    drop(held);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_socks5_session_shows_its_destination_and_a_denied_one_is_recorded() {
    let panel = Panel::new().await;
    let (node, _agents) = panel.server("seoul").await;
    let api = &panel.api;
    let echo = tcp_echo().await;
    let mut proxy = forward("proxy", echo.address, Protocol::Tcp);
    proxy.targets.clear();
    proxy.inbound_socks5 = Some(socks5::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: true,
    });
    proxy.deny_destination_ports = vec!["9".into()];
    api.apply(&node, &[&proxy]).await;

    async fn connect(entry: SocketAddr, destination: SocketAddr) -> (TcpStream, u8) {
        let mut client = TcpStream::connect(entry).await.unwrap();
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut selected = [0u8; 2];
        client.read_exact(&mut selected).await.unwrap();
        assert_eq!(selected, [5, 0]);
        let port = destination.port();
        client
            .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, (port >> 8) as u8, port as u8])
            .await
            .unwrap();
        let mut reply = [0u8; 10];
        timeout(Duration::from_secs(5), client.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        (client, reply[1])
    }
    let (mut client, status) = connect(proxy.listen, echo.address).await;
    assert_eq!(status, 0);
    echo_round(&mut client, 11).await;
    let local = client.local_addr().unwrap();
    let view = api
        .connections(&node, "proxy", "the SOCKS5 session", |v| {
            session(v, local).is_some_and(|s| s["download_bytes"] == 11)
        })
        .await;
    let s = session(&view, local).unwrap();
    assert_eq!(s["protocol"], "socks5");
    assert_eq!(s["destination"], echo.address.to_string());
    assert_eq!(s["remote"], echo.address.to_string());
    assert_eq!(s["target"], Value::Null, "a proxy has no configured target");

    let (_denied, status) = connect(proxy.listen, "127.0.0.1:9".parse().unwrap()).await;
    assert_ne!(status, 0);
    let blocks = api
        .blocks(&node, "proxy", |b| {
            b.len() == 1 && b[0]["reason"] == "destination_denied"
        })
        .await;
    assert_eq!(
        blocks[0]["detail"],
        "destination denied by rule policy: 127.0.0.1:9"
    );
    assert_eq!(blocks[0]["protocol"], "socks5");
    drop(client);
}

/// Asks to end `session` of `rule` as the panel does, with confirmation.
async fn terminate(
    api: &Api,
    node: &str,
    rule: &str,
    instance: &Value,
    session: &Value,
) -> (u16, Value) {
    api.call(
        reqwest::Method::POST,
        &format!("/nodes/{node}/rules/{rule}/connections/terminate"),
        Some(json!({"instance": instance, "session_id": session, "confirm": true})),
    )
    .await
}
/// The request's final state, once the agent answered.
async fn terminated(api: &Api, node: &str, rule: &str, request: &Value) -> Value {
    let path = format!(
        "/nodes/{node}/rules/{rule}/connections/terminations/{}",
        request["id"].as_str().unwrap()
    );
    let until = Instant::now() + Duration::from_secs(20);
    loop {
        let view = api.get(&path).await;
        if view["state"] != "pending" {
            return view;
        }
        assert!(
            Instant::now() < until,
            "waiting for the agent's answer: {view}"
        );
        sleep(Duration::from_millis(50)).await;
    }
}
/// Waits until the relay closed `stream`.
async fn closed<S: AsyncRead + Unpin>(stream: &mut S) {
    let mut byte = [0u8; 1];
    let read = timeout(Duration::from_secs(5), stream.read(&mut byte))
        .await
        .expect("the relay closes an ended session");
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_session_ends_from_the_panel_while_the_others_go_on() {
    let panel = Panel::new().await;
    let (node, _agents) = panel.server("kyoto").await;
    let api = &panel.api;
    let (tcp_echo, udp_echo) = (tcp_echo().await, udp_echo().await);
    // Sessions stay open however long the test takes; only ending them
    // closes them.
    let mut web = forward("web", tcp_echo.address, Protocol::Tcp);
    web.idle_timeout_secs = 600;
    let mut dns = forward("dns", udp_echo.address, Protocol::Udp);
    dns.idle_timeout_secs = 600;
    let mut proxy = forward("proxy", tcp_echo.address, Protocol::Both);
    proxy.idle_timeout_secs = 600;
    proxy.targets.clear();
    proxy.inbound_socks5 = Some(socks5::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: true,
    });
    api.apply(&node, &[&web, &dns, &proxy]).await;

    // Two TCP sessions; the first one is ended.
    let mut first = TcpStream::connect(web.listen).await.unwrap();
    let mut second = TcpStream::connect(web.listen).await.unwrap();
    echo_round(&mut first, 3).await;
    echo_round(&mut second, 4).await;
    let (a, b) = (first.local_addr().unwrap(), second.local_addr().unwrap());
    let view = api
        .connections(&node, "web", "both TCP sessions", |v| {
            session(v, a).is_some() && session(v, b).is_some()
        })
        .await;
    assert_eq!(view["can_terminate"], true);
    let instance = view["instance"].clone();
    assert_eq!(instance.as_str().map(str::len), Some(32));
    let target = session(&view, a).unwrap().clone();
    assert_eq!(target["terminable"], true);
    // Without confirmation nothing is asked.
    let (code, _) = api
        .call(
            reqwest::Method::POST,
            &format!("/nodes/{node}/rules/web/connections/terminate"),
            Some(json!({"instance": instance, "session_id": target["id"]})),
        )
        .await;
    assert_eq!(code, 400);
    let (code, request) = terminate(api, &node, "web", &instance, &target["id"]).await;
    assert_eq!(code, 202, "{request}");
    assert_eq!(
        (request["state"].as_str(), request["protocol"].as_str()),
        (Some("pending"), Some("tcp"))
    );
    assert_eq!(request["client"], a.to_string());
    let done = terminated(api, &node, "web", &request).await;
    assert_eq!(done["state"], "closed", "{done}");
    closed(&mut first).await;
    echo_round(&mut second, 5).await;
    api.connections(&node, "web", "only the second session", |v| {
        v["totals"]["tcp"] == 1 && session(v, b).is_some() && session(v, a).is_none()
    })
    .await;
    // The same request again is the same, answered request.
    let (code, again) = terminate(api, &node, "web", &instance, &target["id"]).await;
    assert_eq!(code, 200);
    assert_eq!(
        (
            again["id"].clone(),
            again["state"].clone(),
            again["duplicate"].clone()
        ),
        (request["id"].clone(), json!("closed"), json!(true))
    );
    // Ending is not blocking: the client connects again at once.
    let mut back = TcpStream::connect(web.listen).await.unwrap();
    echo_round(&mut back, 6).await;
    // A run that is not the agent's is refused before anything is sent.
    let (code, body) = terminate(
        api,
        &node,
        "web",
        &json!("0123456789abcdef0123456789abcdef"),
        &target["id"],
    )
    .await;
    assert_eq!(code, 409, "{body}");
    // A session id the agent no longer has: an explicit not_found.
    let (code, gone) = terminate(api, &node, "web", &instance, &json!(999_999)).await;
    assert_eq!(code, 202);
    assert_eq!(
        terminated(api, &node, "web", &gone).await["state"],
        "not_found"
    );

    // A UDP session ends; the client's next datagram starts a new one.
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buffer = [0u8; 64];
    async fn round(udp: &UdpSocket, to: SocketAddr) {
        udp.send_to(b"ping", to).await.unwrap();
        let mut back = [0u8; 16];
        timeout(Duration::from_secs(5), udp.recv_from(&mut back))
            .await
            .unwrap()
            .unwrap();
    }
    round(&udp, dns.listen).await;
    let local = udp.local_addr().unwrap();
    let view = api
        .connections(&node, "dns", "the UDP session", |v| {
            session(v, local).is_some()
        })
        .await;
    let old = session(&view, local).unwrap()["id"].clone();
    let (code, request) = terminate(api, &node, "dns", &instance, &old).await;
    assert_eq!(code, 202);
    assert_eq!(
        terminated(api, &node, "dns", &request).await["state"],
        "closed"
    );
    api.connections(&node, "dns", "the ended UDP session to go", |v| {
        v["totals"]["udp"] == 0
    })
    .await;
    round(&udp, dns.listen).await;
    let view = api
        .connections(&node, "dns", "a new UDP session", |v| {
            session(v, local).is_some()
        })
        .await;
    assert_ne!(session(&view, local).unwrap()["id"], old);

    // A SOCKS5 UDP association ends with its control connection.
    let mut control = TcpStream::connect(proxy.listen).await.unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut selected = [0u8; 2];
    control.read_exact(&mut selected).await.unwrap();
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    timeout(Duration::from_secs(5), control.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply[1], 0);
    let relay = SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ));
    let associated = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = udp_echo.address.port().to_be_bytes();
    let datagram = [&[0, 0, 0, 1, 127, 0, 0, 1, port[0], port[1]][..], b"hello"].concat();
    associated.send_to(&datagram, relay).await.unwrap();
    let size = timeout(Duration::from_secs(5), associated.recv(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[10..size], b"hello");
    let control_client = control.local_addr().unwrap();
    let view = api
        .connections(&node, "proxy", "the SOCKS5 UDP association", |v| {
            session(v, control_client).is_some_and(|s| s["protocol"] == "socks5_udp")
        })
        .await;
    let association = session(&view, control_client).unwrap()["id"].clone();
    let (code, request) = terminate(api, &node, "proxy", &instance, &association).await;
    assert_eq!(code, 202);
    assert_eq!(
        terminated(api, &node, "proxy", &request).await["state"],
        "closed"
    );
    closed(&mut control).await;
    // Its relay port relays no more.
    associated.send_to(&datagram, relay).await.unwrap();
    assert!(
        timeout(Duration::from_millis(1500), associated.recv(&mut buffer))
            .await
            .is_err(),
        "an ended association relays nothing"
    );

    // Who may end sessions: viewers and read-only tokens may not, other
    // tenants do not see the rule.
    let db = &panel.store;
    db.create_user(&panel.admin, "default", "watcher", PASSWORD, Role::Viewer)
        .unwrap();
    let tenant = db.create_tenant(&panel.admin, "other").unwrap();
    db.create_user(
        &panel.admin,
        &tenant,
        "outsider",
        PASSWORD,
        Role::TenantAdmin,
    )
    .unwrap();
    let address: SocketAddr = api.origin.trim_start_matches("http://").parse().unwrap();
    let watcher = Api::new(address, "watcher").await;
    let view = watcher
        .connections(&node, "web", "the viewer's list", |v| {
            session(v, b).is_some()
        })
        .await;
    assert_eq!(view["can_terminate"], false);
    assert_eq!(session(&view, b).unwrap()["terminable"], false);
    let still = session(&view, b).unwrap()["id"].clone();
    assert_eq!(
        terminate(&watcher, &node, "web", &instance, &still).await.0,
        403
    );
    let outsider = Api::new(address, "outsider").await;
    assert_eq!(
        terminate(&outsider, &node, "web", &instance, &still)
            .await
            .0,
        404
    );
    let (reader, _) = db
        .create_api_token(&panel.admin, "reader", &[Scope::Read], 1)
        .unwrap();
    // A token that may read but not end sessions is not offered to.
    let view = api
        .with_token(&reader)
        .connections(&node, "web", "the read-only token's list", |v| {
            session(v, b).is_some()
        })
        .await;
    assert_eq!(view["can_terminate"], false);
    assert_eq!(session(&view, b).unwrap()["terminable"], false);
    // As sent, each session says once whether it can end: the agent's own
    // `true` is not there too for a client that takes the first key.
    for (who, client) in [("writer", api), ("reader", &api.with_token(&reader))] {
        let text = client
            .text(&format!("/nodes/{node}/rules/web/connections"))
            .await;
        let sessions = serde_json::from_str::<Value>(&text).unwrap()["sessions"]
            .as_array()
            .unwrap()
            .len();
        assert!(sessions > 0);
        assert_eq!(
            text.matches("\"terminable\"").count(),
            sessions,
            "{who}: {text}"
        );
    }
    assert_eq!(
        terminate(&api.with_token(&reader), &node, "web", &instance, &still)
            .await
            .0,
        403
    );
    echo_round(&mut second, 7).await;
    drop((second, back));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn block_records_survive_a_controller_restart_once_each_and_page() {
    let temp = tempfile::tempdir().unwrap();
    let open = || {
        let store = Store::open(&temp.path().join("controller.db")).unwrap();
        store.set_kind("controller").unwrap();
        store.enable_block_records(
            &temp.path().join("blocks.sqlite"),
            Retention {
                days: 7,
                per_node: 500,
            },
        );
        store
    };
    let store = open();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (stop, served) = serve_on(store.clone(), listener);
    let api = Api::new(address, "admin").await;
    let (node, enrollment) = store.create_node(&admin, "default", "nara").unwrap();
    let _agents = Agents::start(
        temp.path(),
        &api.origin,
        &[(node.id.as_str(), enrollment.as_str())],
    );
    let node = node.id;
    api.until("the agent to report support", || async {
        api.node(&node).await["connections_support"] == true
    })
    .await;
    let echo = tcp_echo().await;
    let denied: Vec<Rule> = (0..3)
        .map(|i| {
            let mut r = forward(&format!("denied-{i}"), echo.address, Protocol::Tcp);
            r.deny_sources = vec!["127.0.0.0/8".parse().unwrap()];
            r
        })
        .collect();
    api.apply(&node, &denied.iter().collect::<Vec<_>>()).await;
    for rule in &denied {
        refused(rule.listen).await;
    }
    refused(denied[0].listen).await;
    let count = |blocks: &[Value], rule: &str| -> Vec<u64> {
        blocks
            .iter()
            .filter(|b| b["rule_id"] == rule)
            .map(|b| b["count"].as_u64().unwrap())
            .collect()
    };
    api.blocks(&node, "denied-0", |b| count(b, "denied-0") == [2])
        .await;
    for rule in ["denied-1", "denied-2"] {
        api.blocks(&node, rule, |b| count(b, rule) == [1]).await;
    }
    let before = api.get(&format!("/nodes/{node}/blocks")).await;
    assert_eq!(before["retention"], json!({"days": 7, "per_node": 500}));

    // The controller restarts on the same address; the agent keeps running.
    stop.cancel();
    served.await.unwrap();
    drop(store);
    let store = open();
    // The records are there before the agent can report again, which would
    // send them again to a controller that lost them.
    let reopened = store.node_blocks(&admin, &node, None, None, 200).unwrap();
    assert_eq!(
        serde_json::to_value(&reopened.blocks).unwrap(),
        before["blocks"]
    );
    let listener = TcpListener::bind(address).await.unwrap();
    let (stop, _served) = serve_on(store.clone(), listener);
    let _stop = stop.drop_guard();
    let api = Api::new(address, "admin").await;
    // More refusals grow the same record; nothing came twice.
    let restarted_ms = now_ms();
    api.until(
        "the agent to sync with the restarted controller",
        || async {
            api.node(&node).await["last_seen_ms"]
                .as_i64()
                .is_some_and(|seen| seen > restarted_ms)
        },
    )
    .await;
    refused(denied[0].listen).await;
    api.blocks(&node, "denied-0", |b| count(b, "denied-0") == [3])
        .await;
    sleep(Duration::from_millis(500)).await;
    let all = api.get(&format!("/nodes/{node}/blocks")).await;
    let blocks = all["blocks"].as_array().unwrap();
    assert_eq!(blocks.len(), 3, "{all}");
    assert_eq!(blocks[0]["rule_id"], "denied-0", "the latest change first");
    // Pages of two: every record once, in order, then no next page.
    let first = api.get(&format!("/nodes/{node}/blocks?limit=2")).await;
    assert_eq!(first["blocks"].as_array().unwrap().len(), 2);
    let next = first["next_before"].as_i64().unwrap();
    let second = api
        .get(&format!("/nodes/{node}/blocks?limit=2&before={next}"))
        .await;
    assert_eq!(second["blocks"].as_array().unwrap().len(), 1);
    assert!(second.get("next_before").is_none());
    let paged: Vec<Value> = [first["blocks"].clone(), second["blocks"].clone()]
        .iter()
        .flat_map(|p| p.as_array().unwrap().clone())
        .collect();
    assert_eq!(paged, *blocks);
    // Other tenants do not see the server's records.
    let tenant = store.create_tenant(&admin, "other").unwrap();
    store
        .create_user(&admin, &tenant, "outsider", PASSWORD, Role::TenantAdmin)
        .unwrap();
    let outsider = Api::new(address, "outsider").await;
    assert_eq!(
        outsider
            .call(reqwest::Method::GET, &format!("/nodes/{node}/blocks"), None)
            .await
            .0,
        404
    );
    // The record file is private.
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = std::fs::metadata(temp.path().join("blocks.sqlite"))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }
}

/// The test's store-level sync; `report` is `None` for an older agent.
fn sync(db: &Store, node: &str, report: Option<Report>) -> anyhow::Result<SyncResponse> {
    let ledger = db
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
    db.sync(
        node,
        SyncRequest {
            logs: None,
            lease: None,
            budget: None,
            ledger_id: ledger,
            need_config: false,
            applied_revision: 0,
            apply_error: None,
            usage: vec![],
            stats: EngineStats {
                live_connections: report,
                ..EngineStats::default()
            },
        },
    )
}
fn status<T: std::fmt::Debug>(result: anyhow::Result<T>) -> u16 {
    result
        .unwrap_err()
        .downcast_ref::<relay_platform::store::Rejection>()
        .map_or(500, |r| r.status)
}
fn block(id: u64, seq: u64, count: u64) -> Block {
    Block {
        id,
        seq,
        rule_id: "r-new".into(),
        protocol: "tcp".into(),
        source: "203.0.113.7".parse().unwrap(),
        reason: "source_denied".into(),
        detail: "matches deny-list network 203.0.113.0/24".into(),
        first_ms: 1,
        last_ms: seq as i64,
        count,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn older_agents_get_no_requests_reports_are_bounded_and_only_readers_see_them() {
    let panel = Panel::new().await;
    let (db, admin, api) = (&panel.store, &panel.admin, &panel.api);
    let (new, _) = db.create_node(admin, "default", "new").unwrap();
    let (old, _) = db.create_node(admin, "default", "old").unwrap();
    let target: SocketAddr = "127.0.0.1:9000".parse().unwrap();
    // Rule ids are unique across servers.
    for node in [&new, &old] {
        let mut r = forward(&format!("r-{}", node.name), target, Protocol::Tcp);
        r.listen = free_address();
        db.set_config(admin, &node.id, 0, vec![r]).unwrap();
    }
    // Before any report the server is offline; after an older agent's
    // report it is too old. Neither gets requests or a cursor.
    let path = |node: &relay_platform::store::Node| {
        format!("/nodes/{}/rules/r-{}/connections", node.id, node.name)
    };
    let view = api.get(&path(&old)).await;
    assert_eq!(view["state"], "offline");
    let reply = sync(db, &old.id, None).unwrap();
    assert!(reply.live_connections);
    assert!(reply.live_connection_requests.is_empty() && reply.block_cursor.is_none());
    let view = api.get(&path(&old)).await;
    assert_eq!(view["state"], "unsupported");
    assert_eq!(view["sessions"], json!([]));
    let reply = sync(db, &old.id, None).unwrap();
    assert!(reply.live_connection_requests.is_empty() && reply.block_cursor.is_none());
    let blocks = api.get(&format!("/nodes/{}/blocks", old.id)).await;
    assert_eq!(
        blocks,
        json!({"supported": false, "blocks": [], "retention": {"days": 30, "per_node": 10000}})
    );
    let raw = serde_json::to_value(&reply).unwrap();
    assert!(raw.get("live_connection_requests").is_none() && raw.get("block_cursor").is_none());
    // Every reply says that the controller ends sessions; an older agent
    // ignores it, never names its run, and none of its sessions can be ended.
    assert_eq!(raw["connection_termination"], true);
    assert!(raw.get("connection_terminations").is_none());
    let (code, body) = api
        .call(
            reqwest::Method::POST,
            &format!("/nodes/{}/rules/r-old/connections/terminate", old.id),
            Some(json!({"instance": "0123456789abcdef0123456789abcdef", "session_id": 1, "confirm": true})),
        )
        .await;
    assert_eq!(code, 409, "{body}");
    assert!(body.to_string().contains("upgrade it first"), "{body}");

    // A supporting agent gets a cursor, then the request, and answers it.
    let reply = sync(db, &new.id, Some(Report::default())).unwrap();
    assert_eq!(reply.block_cursor, Some(Default::default()));
    let nodes = api.get("/nodes").await;
    let support = |id: &str| {
        nodes
            .as_array()
            .unwrap()
            .iter()
            .find(|n| n["id"] == id)
            .unwrap()["connections_support"]
            .clone()
    };
    assert_eq!(
        (support(&new.id), support(&old.id)),
        (json!(true), json!(false))
    );
    assert_eq!(api.get(&path(&new)).await["state"], "pending");
    // Asking again while waiting does not ask the agent twice.
    assert_eq!(api.get(&path(&new)).await["state"], "pending");
    let reply = sync(db, &new.id, Some(Report::default())).unwrap();
    assert_eq!(reply.live_connection_requests, ["r-new"]);
    let session: Session = serde_json::from_value(json!({
        "id": 7, "protocol": "tcp", "client": "198.51.100.4:40000", "started_ms": 5,
        "target_index": 0, "target": "127.0.0.1:9000", "upload_bytes": 1, "download_bytes": 2,
    }))
    .unwrap();
    let answer = Report {
        snapshots: vec![Snapshot {
            rule_id: "r-new".into(),
            taken_at_ms: 9,
            tcp: 250,
            udp: 0,
            sessions: vec![session.clone(); 200],
            refused: vec![],
        }],
        ..Report::default()
    };
    let reply = sync(db, &new.id, Some(answer.clone())).unwrap();
    assert!(reply.live_connection_requests.is_empty(), "answered");
    let view = api.get(&path(&new)).await;
    assert_eq!(view["state"], "ready");
    assert_eq!(
        (view["taken_at_ms"].as_i64(), view["truncated"].as_bool()),
        (Some(9), Some(true))
    );
    assert_eq!(view["totals"], json!({"tcp": 250, "udp": 0}));
    assert_eq!(view["sessions"][0]["client"], "198.51.100.4:40000");
    // Older agents still get nothing.
    assert!(
        sync(db, &old.id, None)
            .unwrap()
            .live_connection_requests
            .is_empty()
    );

    // Reports are bounded like every other part of a sync.
    let mut over = answer.clone();
    over.snapshots = vec![over.snapshots[0].clone(); 5];
    assert_eq!(status(sync(db, &new.id, Some(over))), 400);
    let mut over = answer.clone();
    over.snapshots[0].sessions.push(session.clone());
    assert_eq!(status(sync(db, &new.id, Some(over))), 400);
    let batch = |entries: Vec<Block>| Report {
        blocks: Some(BlockBatch {
            stream: "s1".into(),
            entries,
        }),
        ..Report::default()
    };
    assert_eq!(
        status(sync(
            db,
            &new.id,
            Some(batch((1..=201).map(|i| block(i, i, 1)).collect()))
        )),
        400
    );
    let mut long = block(1, 1, 1);
    long.detail = "x".repeat(121);
    assert_eq!(status(sync(db, &new.id, Some(batch(vec![long])))), 400);

    // Records sent again, or grown, are kept once.
    for _ in 0..2 {
        let reply = sync(
            db,
            &new.id,
            Some(batch(vec![block(1, 1, 1), block(2, 2, 1)])),
        )
        .unwrap();
        assert_eq!(reply.block_cursor.as_ref().map(|c| c.seq), Some(2));
    }
    sync(db, &new.id, Some(batch(vec![block(1, 3, 4)]))).unwrap();
    let kept = api.get(&format!("/nodes/{}/blocks", new.id)).await;
    let counts: Vec<u64> = kept["blocks"]
        .as_array()
        .unwrap()
        .iter()
        .map(|b| b["count"].as_u64().unwrap())
        .collect();
    assert_eq!(counts, [4, 1]);

    // Readers of the node only: another tenant's users get 404, read tokens
    // may look, tokens without `read` may not.
    let tenant = db.create_tenant(admin, "other").unwrap();
    db.create_user(admin, &tenant, "outsider", PASSWORD, Role::TenantAdmin)
        .unwrap();
    db.create_user(admin, "default", "watcher", PASSWORD, Role::Viewer)
        .unwrap();
    let address: SocketAddr = api.origin.trim_start_matches("http://").parse().unwrap();
    let outsider = Api::new(address, "outsider").await;
    for path in [path(&new), format!("/nodes/{}/blocks", new.id)] {
        assert_eq!(
            outsider.call(reqwest::Method::GET, &path, None).await.0,
            404,
            "{path}"
        );
    }
    let watcher = Api::new(address, "watcher").await;
    assert_eq!(
        watcher.get(&format!("/nodes/{}/blocks", new.id)).await["blocks"],
        kept["blocks"]
    );
    assert_eq!(watcher.get(&path(&new)).await["totals"]["tcp"], 250);
    let (reader, _) = db
        .create_api_token(admin, "reader", &[Scope::Read], 1)
        .unwrap();
    let (writer, _) = db
        .create_api_token(admin, "writer", &[Scope::NodesWrite], 1)
        .unwrap();
    assert_eq!(
        api.with_token(&reader)
            .call(reqwest::Method::GET, &path(&new), None)
            .await
            .0,
        200
    );
    assert_eq!(
        api.with_token(&writer)
            .call(reqwest::Method::GET, &path(&new), None)
            .await
            .0,
        403
    );
    let (code, _) = api
        .call(
            reqwest::Method::GET,
            &format!("/nodes/{}/blocks?rule_id=missing", new.id),
            None,
        )
        .await;
    assert_eq!(code, 404);

    // Compatibility in both directions: a new agent's stats without the
    // report carry no new key for a 0.147.0 controller, and a reply from
    // one parses as no reporting, no requests and no cursor.
    let stats = serde_json::to_value(EngineStats::default()).unwrap();
    assert!(stats.get("live_connections").is_none());
    // A new agent reporting to a controller that did not ask names no run
    // and sends no answers, so a 0.150.0 controller, which rejects unknown
    // fields of the report, accepts it.
    let report = serde_json::to_value(Report::default()).unwrap();
    assert_eq!(report, json!({}));
    // The agent's own report names its run and carries answers only once the
    // controller said `connection_termination`, which 0.150.0 never says.
    let engine = relay_platform::engine::Engine::new(
        Store::open(&panel.temp.path().join("agent.db")).unwrap(),
    );
    let unasked =
        serde_json::to_value(engine.connection_report(&[], &Default::default(), None)).unwrap();
    assert!(
        unasked.get("instance").is_none() && unasked.get("terminations").is_none(),
        "{unasked}"
    );
    let asked =
        serde_json::to_value(engine.connection_report(&[], &Default::default(), Some(vec![])))
            .unwrap();
    assert!(
        asked["instance"]
            .as_str()
            .is_some_and(|run| run.len() == 32),
        "{asked}"
    );
    // A new agent that supports live connections but not ending sessions
    // (as a 0.150.0 agent): the controller refuses to end its sessions.
    let (code, body) = api
        .call(
            reqwest::Method::POST,
            &format!("/nodes/{}/rules/r-new/connections/terminate", new.id),
            Some(json!({"instance": "0123456789abcdef0123456789abcdef", "session_id": 7, "confirm": true})),
        )
        .await;
    assert_eq!(code, 409, "{body}");
    assert!(body.to_string().contains("upgrade it first"), "{body}");
    let old_reply: SyncResponse = serde_json::from_value(json!({
        "budget": null, "controller_instance": "x", "config": null,
        "acknowledgements": [], "server_time_ms": 1, "rate_limits": true,
    }))
    .unwrap();
    assert!(!old_reply.live_connections);
    assert!(!old_reply.connection_termination && old_reply.connection_terminations.is_empty());
    assert!(old_reply.live_connection_requests.is_empty() && old_reply.block_cursor.is_none());
}

/// What a 0.150.0 controller does with this release's agent, while
/// `older` is set: it rejects a report that names the agent's run, carries
/// answers or says which sessions can end (HTTP 422, unknown fields), and
/// never offers to end sessions.
#[derive(Default)]
struct Older {
    older: AtomicBool,
    /// Says it takes the reports and refuses them all the same.
    refusing: AtomicBool,
    /// Answers as another controller run.
    restarted: AtomicBool,
    /// Requests with the new fields, rejected ones, and passed ones while older.
    named: AtomicUsize,
    rejected: AtomicUsize,
    passed: AtomicUsize,
    /// Asked of the agent in each reply while refusing, before a restart.
    termination: std::sync::Mutex<Option<Value>>,
    asked: AtomicUsize,
}
async fn as_older_controller(
    axum::extract::State(seen): axum::extract::State<Arc<Older>>,
    request: axum::extract::Request,
    next: axum::middleware::Next,
) -> axum::response::Response {
    use axum::{
        body::{Body, to_bytes},
        response::IntoResponse,
    };
    if request.uri().path() != "/api/v1/agent/sync" {
        return next.run(request).await;
    }
    let (parts, body) = request.into_parts();
    let bytes = to_bytes(body, 64 << 20).await.unwrap();
    let sent: Value = serde_json::from_slice(&bytes).unwrap_or_default();
    let live = &sent["stats"]["live_connections"];
    let new_fields = live.get("instance").is_some()
        || live.get("terminations").is_some()
        || live["snapshots"]
            .as_array()
            .into_iter()
            .flatten()
            .filter_map(|s| s["sessions"].as_array())
            .flatten()
            .any(|s| s.get("terminable").is_some());
    if new_fields {
        seen.named.fetch_add(1, Ordering::SeqCst);
    }
    let request = axum::extract::Request::from_parts(parts, Body::from(bytes));
    let (older, restarted) = (
        seen.older.load(Ordering::SeqCst),
        seen.restarted.load(Ordering::SeqCst),
    );
    let rejecting = older || seen.refusing.load(Ordering::SeqCst);
    if rejecting && new_fields {
        seen.rejected.fetch_add(1, Ordering::SeqCst);
        return (
            axum::http::StatusCode::UNPROCESSABLE_ENTITY,
            "unknown field `instance`",
        )
            .into_response();
    }
    if rejecting {
        seen.passed.fetch_add(1, Ordering::SeqCst);
    }
    let termination = if seen.refusing.load(Ordering::SeqCst) && !restarted {
        seen.termination.lock().unwrap().clone()
    } else {
        None
    };
    if !older && !restarted && termination.is_none() {
        return next.run(request).await;
    }
    let (mut parts, body) = next.run(request).await.into_parts();
    let bytes = to_bytes(body, 64 << 20).await.unwrap();
    let Ok(mut reply) = serde_json::from_slice::<Value>(&bytes) else {
        return axum::response::Response::from_parts(parts, Body::from(bytes));
    };
    if let Some(reply) = reply.as_object_mut() {
        if older {
            reply.remove("connection_termination");
            reply.remove("connection_terminations");
        }
        if restarted && reply.contains_key("controller_instance") {
            reply.insert(
                "controller_instance".into(),
                json!("restarted0controller0run"),
            );
        }
        if let Some(termination) = termination.filter(|_| reply.contains_key("controller_instance"))
        {
            reply.insert("connection_terminations".into(), json!([termination]));
            seen.asked.fetch_add(1, Ordering::SeqCst);
        }
    }
    parts.headers.remove(axum::http::header::CONTENT_LENGTH);
    axum::response::Response::from_parts(parts, Body::from(serde_json::to_vec(&reply).unwrap()))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_agent_keeps_forwarding_when_its_controller_goes_back_to_an_older_release() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let seen = Arc::new(Older::default());
    let router = api::router(AppState::new(store.clone())).layer(
        axum::middleware::from_fn_with_state(seen.clone(), as_older_controller),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let served = tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .await
        .unwrap();
    });
    let api = Api::new(address, "admin").await;
    let (node, enrollment) = store.create_node(&admin, "default", "hakone").unwrap();
    let secret = temp.path().join("agent.secret");
    write_secret(&secret, enrollment.as_bytes()).unwrap();
    let stop = CancellationToken::new();
    let agent = tokio::spawn(agent::run(
        Store::open(&temp.path().join("agent.db")).unwrap(),
        AgentOptions {
            controller: api.origin.clone(),
            node_id: node.id.clone(),
            enrollment_token_file: Some(secret),
            ca_certificate: None,
            tls_directory: None,
            poll_interval: Duration::from_millis(50),
            controller_addresses: vec![],
            controller_proxy: None,
        },
        stop.clone(),
    ));
    let _stop = stop.drop_guard();
    api.until("the agent to name its run", || async {
        seen.named.load(Ordering::SeqCst) > 0
    })
    .await;
    let echo = tcp_echo().await;
    let mut web = forward("web", echo.address, Protocol::Tcp);
    web.idle_timeout_secs = 600;
    api.apply(&node.id, &[&web]).await;
    let mut held = TcpStream::connect(web.listen).await.unwrap();
    echo_round(&mut held, 3).await;
    // The controller goes back to 0.150.0: one report is rejected, then the
    // agent reports without the new fields and forwarding goes on.
    seen.older.store(true, Ordering::SeqCst);
    api.until("syncs without the new fields", || async {
        seen.passed.load(Ordering::SeqCst) >= 3
    })
    .await;
    assert_eq!(seen.rejected.load(Ordering::SeqCst), 1);
    assert!(!agent.is_finished(), "the agent stopped");
    echo_round(&mut held, 4).await;
    // Upgraded again: the agent names its run again.
    let named = seen.named.load(Ordering::SeqCst);
    seen.older.store(false, Ordering::SeqCst);
    api.until("the agent to name its run again", || async {
        seen.named.load(Ordering::SeqCst) > named
    })
    .await;
    echo_round(&mut held, 5).await;
    // A controller that says it takes the reports and refuses them: after
    // its second refusal they stay off for the rest of its run, instead of
    // every other sync, and forwarding goes on. It asks to end the held
    // session in every reply, also the one between its two refusals: the
    // agent ends nothing whose answer it may not be able to report.
    let client = held.local_addr().unwrap();
    let view = api
        .connections(&node.id, "web", "the held session", |v| {
            session(v, client).is_some()
        })
        .await;
    *seen.termination.lock().unwrap() = Some(json!({
        "id": "0123456789abcdef0123456789abcdef",
        "rule_id": "web",
        "instance": view["instance"],
        "session_id": session(&view, client).unwrap()["id"],
    }));
    let (rejected, passed) = (
        seen.rejected.load(Ordering::SeqCst),
        seen.passed.load(Ordering::SeqCst),
    );
    seen.refusing.store(true, Ordering::SeqCst);
    api.until("syncs without the refused reports", || async {
        seen.passed.load(Ordering::SeqCst) >= passed + 8
    })
    .await;
    api.until("the refusing controller to ask eight times", || async {
        seen.asked.load(Ordering::SeqCst) >= 8
    })
    .await;
    assert_eq!(seen.rejected.load(Ordering::SeqCst), rejected + 2);
    assert!(!agent.is_finished(), "the agent stopped");
    echo_round(&mut held, 6).await;
    // Restarted, it is another run: tried again, twice, then off again.
    let passed = seen.passed.load(Ordering::SeqCst);
    seen.restarted.store(true, Ordering::SeqCst);
    api.until("the restarted controller's refusals", || async {
        seen.passed.load(Ordering::SeqCst) >= passed + 8
    })
    .await;
    assert_eq!(seen.rejected.load(Ordering::SeqCst), rejected + 4);
    // Fixed and restarted again: the agent names its run again.
    let named = seen.named.load(Ordering::SeqCst);
    seen.refusing.store(false, Ordering::SeqCst);
    seen.restarted.store(false, Ordering::SeqCst);
    api.until("the agent to name its run once more", || async {
        seen.named.load(Ordering::SeqCst) > named
    })
    .await;
    assert!(!agent.is_finished(), "the agent stopped");
    echo_round(&mut held, 7).await;
    served.abort();
}

// Ending one session on an agent's engine, as its controller asks.

/// A TCP echo server that tells when each of its connections ended.
async fn watched_echo(bind: &str) -> (SocketAddr, mpsc::UnboundedReceiver<()>) {
    let listener = TcpListener::bind(bind).await.unwrap();
    let address = listener.local_addr().unwrap();
    let (ended, closes) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let ended = ended.clone();
            tokio::spawn(async move {
                let mut buffer = [0u8; 4096];
                while let Ok(read) = socket.read(&mut buffer).await {
                    if read == 0 || socket.write_all(&buffer[..read]).await.is_err() {
                        break;
                    }
                }
                let _ = ended.send(());
            });
        }
    });
    (address, closes)
}
/// `count` of the echo's connections end, and no other.
async fn target_closed(closes: &mut mpsc::UnboundedReceiver<()>, count: usize) {
    for _ in 0..count {
        timeout(Duration::from_secs(10), closes.recv())
            .await
            .expect("the target's connection closes")
            .unwrap();
    }
    sleep(Duration::from_millis(200)).await;
    assert!(
        closes.try_recv().is_err(),
        "another target connection closed"
    );
}
/// A UDP echo that answers each datagram 800 ms later.
async fn late_udp_echo() -> SocketAddr {
    let socket = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0u8; 512];
        while let Ok((read, from)) = socket.recv_from(&mut buffer).await {
            let (socket, data) = (socket.clone(), buffer[..read].to_vec());
            tokio::spawn(async move {
                sleep(Duration::from_millis(800)).await;
                let _ = socket.send_to(&data, from).await;
            });
        }
    });
    address
}
/// `rule`'s sessions as the engine reports them to a controller that ends
/// sessions, and its run.
fn engine_sessions(engine: &Engine, rule: &str) -> (String, Vec<Session>) {
    let report = engine.connection_report(&[rule.to_owned()], &Cursor::default(), Some(vec![]));
    let sessions = report
        .snapshots
        .into_iter()
        .next()
        .map(|s| s.sessions)
        .unwrap_or_default();
    (report.instance, sessions)
}
/// Waits until the sessions of `rule` that `pick` takes are just one.
async fn engine_session(
    engine: &Engine,
    rule: &str,
    pick: impl Fn(&Session) -> bool,
) -> (String, Session) {
    let deadline = Instant::now() + Duration::from_secs(10);
    loop {
        let (instance, sessions) = engine_sessions(engine, rule);
        let mut picked: Vec<Session> = sessions.into_iter().filter(|s| pick(s)).collect();
        if picked.len() == 1 {
            return (instance, picked.remove(0));
        }
        assert!(
            Instant::now() < deadline,
            "no single such session of {rule}"
        );
        sleep(Duration::from_millis(20)).await;
    }
}
/// Ends session `id` of `rule` as the controller asks: the agent's answer.
async fn end(engine: &Engine, instance: &str, rule: &str, id: u64) -> String {
    let answers = engine
        .terminate_sessions(&[Termination {
            id: format!("{rule}-{id}"),
            rule_id: rule.into(),
            instance: instance.into(),
            session_id: id,
        }])
        .await;
    answers[0].outcome.clone()
}
async fn socks5_reply<S: AsyncRead + Unpin>(stream: &mut S) -> SocketAddr {
    let mut reply = [0u8; 10];
    timeout(Duration::from_secs(5), stream.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((reply[0], reply[1], reply[3]), (5, 0, 1), "{reply:?}");
    SocketAddr::from((
        [reply[4], reply[5], reply[6], reply[7]],
        u16::from_be_bytes([reply[8], reply[9]]),
    ))
}
async fn socks5_hello(stream: &mut TcpStream) {
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut selected = [0u8; 2];
    stream.read_exact(&mut selected).await.unwrap();
    assert_eq!(selected, [5, 0]);
}
fn socks5_address(command: u8, address: SocketAddr) -> Vec<u8> {
    let SocketAddr::V4(address) = address else {
        unreachable!()
    };
    [
        &[5, command, 0, 1][..],
        &address.ip().octets(),
        &address.port().to_be_bytes(),
    ]
    .concat()
}
async fn h2_client(address: SocketAddr) -> (SocketAddr, SendRequest<Empty<Bytes>>) {
    let stream = TcpStream::connect(address).await.unwrap();
    let local = stream.local_addr().unwrap();
    let (sender, connection) =
        hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .unwrap();
    tokio::spawn(connection);
    (local, sender)
}
async fn h2_tunnel(
    sender: &mut SendRequest<Empty<Bytes>>,
    target: SocketAddr,
) -> TokioIo<hyper::upgrade::Upgraded> {
    let request = Request::builder()
        .method("CONNECT")
        .uri(format!("http://{target}"))
        .header("proxy-authorization", "Bearer token")
        .body(Empty::<Bytes>::new())
        .unwrap();
    let mut response = timeout(Duration::from_secs(5), sender.send_request(request))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response.status(), StatusCode::OK);
    TokioIo::new(hyper::upgrade::on(&mut response).await.unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn one_session_of_each_inbound_that_can_end_closes_on_both_sides() {
    let (echo4, mut closes4) = watched_echo("127.0.0.1:0").await;
    let (echo6, mut closes6) = watched_echo("[::1]:0").await;
    let tcp4 = forward("tcp4", echo4, Protocol::Tcp);
    let mut tcp6 = forward("tcp6", echo6, Protocol::Tcp);
    tcp6.listen = std::net::TcpListener::bind("[::1]:0")
        .unwrap()
        .local_addr()
        .unwrap();
    let mut connect = forward("connect", echo4, Protocol::Tcp);
    connect.targets.clear();
    connect.inbound_http_connect = Some(http_connect::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: true,
    });
    let mut proxy = forward("proxy", echo4, Protocol::Tcp);
    proxy.targets.clear();
    proxy.inbound_socks5 = Some(socks5::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: true,
    });
    let mut h2 = forward("h2", echo4, Protocol::Tcp);
    h2.targets.clear();
    h2.inbound_http2_connect = Some(http2_connect::ServerConfig {
        username: None,
        password: None,
        bearer_token_sha256: vec![format!("{:x}", Sha256::digest(b"token"))],
        allow_private_destinations: true,
        max_concurrent_streams: 8,
        socket_buffer_bytes: None,
    });
    let udp = forward("udp", late_udp_echo().await, Protocol::Udp);
    let mut rules = vec![tcp4, tcp6, connect, proxy, h2, udp];
    for rule in &mut rules {
        rule.idle_timeout_secs = 600;
    }
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut node = config(rules[0].clone());
    node.rules = rules.clone();
    engine.apply(node).await.unwrap();
    let [tcp4, tcp6, connect, proxy, h2, udp] = &rules[..] else {
        unreachable!()
    };

    // Plain TCP, over IPv4 and IPv6.
    for (rule, closes) in [(tcp4, &mut closes4), (tcp6, &mut closes6)] {
        let mut ended = TcpStream::connect(rule.listen).await.unwrap();
        let mut other = TcpStream::connect(rule.listen).await.unwrap();
        echo_round(&mut ended, 3).await;
        echo_round(&mut other, 3).await;
        let client = ended.local_addr().unwrap();
        let (instance, session) = engine_session(&engine, &rule.id, |s| s.client == client).await;
        assert!(session.terminable, "{}", rule.id);
        assert_eq!(
            end(&engine, &instance, &rule.id, session.id).await,
            "closed"
        );
        closed(&mut ended).await;
        target_closed(closes, 1).await;
        echo_round(&mut other, 4).await;
        drop(other);
        target_closed(closes, 1).await;
    }

    // HTTP CONNECT.
    let mut tunnel = TcpStream::connect(connect.listen).await.unwrap();
    tunnel
        .write_all(format!("CONNECT {echo4} HTTP/1.1\r\nHost: {echo4}\r\n\r\n").as_bytes())
        .await
        .unwrap();
    let mut head = vec![];
    while !head.ends_with(b"\r\n\r\n") {
        let mut byte = [0u8; 1];
        tunnel.read_exact(&mut byte).await.unwrap();
        head.push(byte[0]);
    }
    assert!(head.starts_with(b"HTTP/1.1 200"), "{head:?}");
    echo_round(&mut tunnel, 5).await;
    let client = tunnel.local_addr().unwrap();
    let (instance, session) = engine_session(&engine, "connect", |s| s.client == client).await;
    assert!(session.terminable);
    assert_eq!(
        end(&engine, &instance, "connect", session.id).await,
        "closed"
    );
    closed(&mut tunnel).await;
    target_closed(&mut closes4, 1).await;

    // SOCKS5 CONNECT.
    let mut socks = TcpStream::connect(proxy.listen).await.unwrap();
    socks5_hello(&mut socks).await;
    socks.write_all(&socks5_address(1, echo4)).await.unwrap();
    socks5_reply(&mut socks).await;
    echo_round(&mut socks, 6).await;
    let client = socks.local_addr().unwrap();
    let (instance, session) = engine_session(&engine, "proxy", |s| s.client == client).await;
    assert_eq!(end(&engine, &instance, "proxy", session.id).await, "closed");
    closed(&mut socks).await;
    target_closed(&mut closes4, 1).await;

    // SOCKS5 BIND: the peer that connected to the bound port is the target.
    let mut bind = TcpStream::connect(proxy.listen).await.unwrap();
    socks5_hello(&mut bind).await;
    bind.write_all(&socks5_address(2, "127.0.0.1:0".parse().unwrap()))
        .await
        .unwrap();
    let bound = socks5_reply(&mut bind).await;
    let mut peer = TcpStream::connect(bound).await.unwrap();
    socks5_reply(&mut bind).await;
    bind.write_all(b"up").await.unwrap();
    let mut up = [0u8; 2];
    timeout(Duration::from_secs(5), peer.read_exact(&mut up))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&up, b"up");
    let client = bind.local_addr().unwrap();
    let (instance, session) = engine_session(&engine, "proxy", |s| s.client == client).await;
    assert_eq!(end(&engine, &instance, "proxy", session.id).await, "closed");
    closed(&mut bind).await;
    closed(&mut peer).await;

    // HTTP/2 CONNECT: a session is one HTTP/2 connection; ending it ends
    // all of its tunnels, and another connection's go on.
    let (first, mut one) = h2_client(h2.listen).await;
    let mut tunnels = vec![
        h2_tunnel(&mut one, echo4).await,
        h2_tunnel(&mut one, echo4).await,
    ];
    let (_, mut two) = h2_client(h2.listen).await;
    let mut other = h2_tunnel(&mut two, echo4).await;
    for tunnel in tunnels.iter_mut().chain([&mut other]) {
        echo_round(tunnel, 7).await;
    }
    assert_eq!(
        engine_sessions(&engine, "h2").1.len(),
        2,
        "one per connection"
    );
    let (instance, session) = engine_session(&engine, "h2", |s| s.client == first).await;
    assert!(session.terminable);
    assert_eq!(end(&engine, &instance, "h2", session.id).await, "closed");
    // Closed means its tunnels ended first: only the other one is open.
    assert_eq!(engine.stats().active_http2_streams, 1);
    for tunnel in &mut tunnels {
        closed(tunnel).await;
    }
    target_closed(&mut closes4, 2).await;
    echo_round(&mut other, 8).await;

    // UDP: after the end, the target's late reply is not forwarded.
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local = client.local_addr().unwrap();
    let mut buffer = [0u8; 64];
    client.send_to(b"first", udp.listen).await.unwrap();
    let (read, _) = timeout(Duration::from_secs(5), client.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..read], b"first");
    client.send_to(b"late", udp.listen).await.unwrap();
    // Both datagrams went out through the session before it ends.
    let (instance, session) =
        engine_session(&engine, "udp", |s| s.client == local && s.upload_bytes >= 9).await;
    assert!(session.udp && session.terminable);
    assert_eq!(end(&engine, &instance, "udp", session.id).await, "closed");
    assert!(
        timeout(Duration::from_millis(2000), client.recv_from(&mut buffer))
            .await
            .is_err(),
        "an ended UDP session forwarded a reply"
    );
    engine.shutdown().await.unwrap();
}

/// Two servers: the client connects to `entry`, which reaches `exit` over
/// `kind` (`tls`, `websocket`, `wss` or `multipath`), which reaches `backend`.
fn hops(kind: &str, backend: SocketAddr) -> (Rule, Rule) {
    let mut exit = forward("exit", backend, Protocol::Tcp);
    let paths = if kind == "multipath" || kind == "ws-multipath" {
        // Two consecutive ports, one per path.
        exit.listen = loop {
            let first = free_address();
            if std::net::TcpListener::bind((first.ip(), first.port() + 1)).is_ok() {
                let _ = free_address();
                break first;
            }
        };
        exit.listen_end_port = Some(exit.listen.port() + 1);
        let limits = multipath::Limits {
            window_frames: 16,
            max_sessions: 4,
            retransmit_ms: 100,
            stall_timeout_ms: 3000,
        };
        exit.inbound_multipath = Some(multipath::ServerConfig {
            limits: limits.clone(),
            max_paths: 2,
            allow_replication: false,
        });
        Some(multipath::ClientConfig {
            limits,
            mode: multipath::Mode::Stripe,
            min_paths: 2,
            paths: vec![
                multipath::PathConfig {
                    upload_weight: 1,
                    download_weight: 1,
                    outbound_bind: None,
                };
                2
            ],
        })
    } else {
        None
    };
    let mut entry = forward("entry", exit.listen, Protocol::Tcp);
    if paths.is_some() {
        let mut second = entry.targets[0].clone();
        second.address = SocketAddr::new(exit.listen.ip(), exit.listen.port() + 1).to_string();
        entry.targets.push(second);
    }
    entry.outbound_multipath = paths;
    if kind != "websocket" {
        exit.inbound_tls = Some(TlsServer {
            identity: "server".into(),
            client_ca: Some("root".into()),
        });
        for target in &mut entry.targets {
            target.tls = Some(TlsClient {
                server_name: "relay.test".into(),
                ca: Some("root".into()),
                identity: Some("client".into()),
            });
        }
    }
    if kind == "websocket" || kind == "wss" || kind == "ws-multipath" {
        exit.inbound_websocket = Some(WebSocketServer {
            path: "/hop".into(),
            host: Some("relay.test".into()),
            allowed_origins: vec![],
        });
        for target in &mut entry.targets {
            target.websocket = Some(WebSocketClient {
                path: "/hop".into(),
                host: "relay.test".into(),
                origin: None,
            });
        }
    }
    for rule in [&mut entry, &mut exit] {
        rule.idle_timeout_secs = 600;
        rule.connect_timeout_ms = 5000;
    }
    (entry, exit)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tls_websocket_and_multipath_sessions_end_from_either_server() {
    let certificates = tls::Certificates::new();
    for kind in ["tls", "websocket", "wss", "multipath"] {
        let (echo, mut closes) = watched_echo("127.0.0.1:0").await;
        let (entry_rule, exit_rule) = hops(kind, echo);
        let temp = tempfile::tempdir().unwrap();
        let open = |name: &str| {
            Engine::with_tls_directory(
                Store::open(&temp.path().join(format!("{name}.db"))).unwrap(),
                Some(certificates.root.clone()),
            )
        };
        let (entry, exit) = (open("entry"), open("exit"));
        for (engine, rule, name) in [(&exit, &exit_rule, "exit"), (&entry, &entry_rule, "entry")] {
            let mut node = config(rule.clone());
            node.node_id = name.into();
            engine.apply(node).await.unwrap();
        }
        let mut first = TcpStream::connect(entry_rule.listen).await.unwrap();
        echo_round(&mut first, 3).await;
        // The exit lists the first client's session, as `kind`.
        let (instance, at_exit) = engine_session(&exit, "exit", |s| s.protocol == kind).await;
        let mut second = TcpStream::connect(entry_rule.listen).await.unwrap();
        let mut third = TcpStream::connect(entry_rule.listen).await.unwrap();
        echo_round(&mut second, 3).await;
        echo_round(&mut third, 3).await;
        // Ended at the exit.
        assert!(at_exit.terminable, "{kind}");
        assert_eq!(
            end(&exit, &instance, "exit", at_exit.id).await,
            "closed",
            "{kind}"
        );
        closed(&mut first).await;
        target_closed(&mut closes, 1).await;
        // Ended at the entry.
        let client = second.local_addr().unwrap();
        let (instance, at_entry) = engine_session(&entry, "entry", |s| s.client == client).await;
        assert!(at_entry.terminable, "{kind}");
        assert_eq!(
            end(&entry, &instance, "entry", at_entry.id).await,
            "closed",
            "{kind}"
        );
        closed(&mut second).await;
        target_closed(&mut closes, 1).await;
        // The third goes on.
        echo_round(&mut third, 4).await;
        drop(third);
        target_closed(&mut closes, 1).await;
        entry.shutdown().await.unwrap();
        exit.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_multipath_inbound_over_websocket_is_one_session_not_ended_alone() {
    let certificates = tls::Certificates::new();
    let (echo, mut closes) = watched_echo("127.0.0.1:0").await;
    // The entry opens two WebSocket paths over TLS to the exit.
    let (entry_rule, exit_rule) = hops("ws-multipath", echo);
    let temp = tempfile::tempdir().unwrap();
    let open = |name: &str| {
        Engine::with_tls_directory(
            Store::open(&temp.path().join(format!("{name}.db"))).unwrap(),
            Some(certificates.root.clone()),
        )
    };
    let (entry, exit) = (open("entry"), open("exit"));
    for (engine, rule, name) in [(&exit, &exit_rule, "exit"), (&entry, &entry_rule, "entry")] {
        let mut node = config(rule.clone());
        node.node_id = name.into();
        engine.apply(node).await.unwrap();
    }
    let mut client = TcpStream::connect(entry_rule.listen).await.unwrap();
    echo_round(&mut client, 3).await;
    // The exit lists the session once: the path that joined it handed over
    // its stream and is not listed on its own.
    let deadline = Instant::now() + Duration::from_secs(5);
    let (instance, at_exit) = loop {
        let (instance, sessions) = engine_sessions(&exit, "exit");
        if let [session] = &sessions[..] {
            break (instance, session.clone());
        }
        assert!(
            Instant::now() < deadline,
            "sessions at the exit: {sessions:?}"
        );
        sleep(Duration::from_millis(20)).await;
    };
    // It cannot be ended alone there: the agent answers at once and it goes on.
    assert!(!at_exit.terminable);
    let asked = Instant::now();
    assert_eq!(
        end(&exit, &instance, "exit", at_exit.id).await,
        "unsupported"
    );
    assert!(asked.elapsed() < Duration::from_secs(1));
    echo_round(&mut client, 4).await;
    assert_eq!(engine_sessions(&exit, "exit").1.len(), 1);
    // At the entry, its outbound multipath over WebSocket ends on both
    // sides, and the exit's session with it.
    let local = client.local_addr().unwrap();
    let (instance, at_entry) = engine_session(&entry, "entry", |s| s.client == local).await;
    assert!(at_entry.terminable);
    assert_eq!(end(&entry, &instance, "entry", at_entry.id).await, "closed");
    closed(&mut client).await;
    target_closed(&mut closes, 1).await;
    let deadline = Instant::now() + Duration::from_secs(5);
    while !engine_sessions(&exit, "exit").1.is_empty() {
        assert!(Instant::now() < deadline, "the exit's session stayed");
        sleep(Duration::from_millis(20)).await;
    }
    entry.shutdown().await.unwrap();
    exit.shutdown().await.unwrap();
}

/// A TLS client of `address`, which presents the `server` identity.
async fn tls_client(
    certificates: &tls::Certificates,
    address: SocketAddr,
) -> tokio_rustls::client::TlsStream<TcpStream> {
    let tcp = TcpStream::connect(address).await.unwrap();
    let name = tokio_rustls::rustls::pki_types::ServerName::try_from("relay.test").unwrap();
    certificates
        .connector(false)
        .connect(name, tcp)
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_header_and_tls_proxy_sessions_end_on_both_sides() {
    let certificates = tls::Certificates::new();
    let (echo, mut closes) = watched_echo("127.0.0.1:0").await;
    // A PROXY header before the client's data names the client shown.
    let mut proxied = forward("proxied", echo, Protocol::Tcp);
    proxied.inbound_proxy = Some(
        serde_json::from_value(json!({"version": "v1", "trusted_sources": ["127.0.0.1/32"]}))
            .unwrap(),
    );
    let server = TlsServer {
        identity: "server".into(),
        client_ca: None,
    };
    let mut h2 = forward("tls-h2", echo, Protocol::Tcp);
    h2.targets.clear();
    h2.inbound_tls = Some(server.clone());
    h2.inbound_http2_connect = Some(http2_connect::ServerConfig {
        username: None,
        password: None,
        bearer_token_sha256: vec![format!("{:x}", Sha256::digest(b"token"))],
        allow_private_destinations: true,
        max_concurrent_streams: 8,
        socket_buffer_bytes: None,
    });
    let mut socks = forward("tls-socks", echo, Protocol::Tcp);
    socks.targets.clear();
    socks.inbound_tls = Some(server.clone());
    socks.inbound_socks5 = Some(socks5::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: true,
    });
    let mut connect = forward("tls-connect", echo, Protocol::Tcp);
    connect.targets.clear();
    connect.inbound_tls = Some(server.clone());
    connect.inbound_http_connect = Some(http_connect::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: true,
    });
    // A PROXY header inside TLS.
    let mut inside = forward("tls-header", echo, Protocol::Tcp);
    inside.inbound_tls = Some(server);
    inside.inbound_proxy = Some(
        serde_json::from_value(json!({
            "version": "v1", "trusted_sources": ["127.0.0.1/32"], "placement": "inside_tls",
        }))
        .unwrap(),
    );
    // A PROXY v2 header on a TCP and UDP rule, before its TCP clients' data.
    let mut both = forward("proxied-both", echo, Protocol::Both);
    both.inbound_proxy = Some(
        serde_json::from_value(json!({"version": "v2", "trusted_sources": ["127.0.0.1/32"]}))
            .unwrap(),
    );
    // A PROXY header before the TLS handshake.
    let mut before = forward("tls-after-header", echo, Protocol::Tcp);
    before.inbound_tls = Some(TlsServer {
        identity: "server".into(),
        client_ca: None,
    });
    before.inbound_proxy = Some(
        serde_json::from_value(json!({
            "version": "v1", "trusted_sources": ["127.0.0.1/32"], "placement": "before_tls",
        }))
        .unwrap(),
    );
    let mut rules = vec![proxied, h2, socks, connect, inside, both, before];
    for rule in &mut rules {
        rule.idle_timeout_secs = 600;
    }
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::with_tls_directory(
        Store::open(&temp.path().join("agent.db")).unwrap(),
        Some(certificates.root.clone()),
    );
    let mut node = config(rules[0].clone());
    node.rules = rules.clone();
    engine.apply(node).await.unwrap();
    let [proxied, h2, socks, connect, inside, both, before] = &rules[..] else {
        unreachable!()
    };

    // PROXY header: the session shows the client the header named.
    let with_header = |port: u16| async move {
        let mut stream = TcpStream::connect(proxied.listen).await.unwrap();
        stream
            .write_all(format!("PROXY TCP4 198.51.100.7 127.0.0.1 {port} 80\r\n").as_bytes())
            .await
            .unwrap();
        echo_round(&mut stream, 3).await;
        stream
    };
    let mut ended = with_header(40001).await;
    let mut other = with_header(40002).await;
    let named: SocketAddr = "198.51.100.7:40001".parse().unwrap();
    let (instance, session) = engine_session(&engine, "proxied", |s| s.client == named).await;
    assert!(session.terminable);
    assert_eq!(
        end(&engine, &instance, "proxied", session.id).await,
        "closed"
    );
    closed(&mut ended).await;
    target_closed(&mut closes, 1).await;
    echo_round(&mut other, 4).await;
    drop(other);
    target_closed(&mut closes, 1).await;

    // HTTP/2 CONNECT inside TLS (ALPN h2): the connection's tunnels end
    // with it.
    let (connector, name) =
        http2_connect::tls_connector_h2(&certificates.root.join("root/ca.pem"), "relay.test")
            .unwrap();
    let h2_over_tls = || async {
        let tcp = TcpStream::connect(h2.listen).await.unwrap();
        let stream = connector.connect(name.clone(), tcp).await.unwrap();
        let local = stream.get_ref().0.local_addr().unwrap();
        let (sender, connection) =
            hyper::client::conn::http2::handshake(TokioExecutor::new(), TokioIo::new(stream))
                .await
                .unwrap();
        tokio::spawn(connection);
        (local, sender)
    };
    let (first, mut one) = h2_over_tls().await;
    let mut tunnels = vec![
        h2_tunnel(&mut one, echo).await,
        h2_tunnel(&mut one, echo).await,
    ];
    let (_, mut two) = h2_over_tls().await;
    let mut other = h2_tunnel(&mut two, echo).await;
    for tunnel in tunnels.iter_mut().chain([&mut other]) {
        echo_round(tunnel, 5).await;
    }
    let (instance, session) = engine_session(&engine, "tls-h2", |s| s.client == first).await;
    assert_eq!(session.protocol, "http2_connect");
    assert!(session.terminable);
    assert_eq!(
        end(&engine, &instance, "tls-h2", session.id).await,
        "closed"
    );
    for tunnel in &mut tunnels {
        closed(tunnel).await;
    }
    target_closed(&mut closes, 2).await;
    echo_round(&mut other, 6).await;
    drop((other, two));
    target_closed(&mut closes, 1).await;

    // SOCKS5 inside TLS.
    let socks_over_tls = || async {
        let mut stream = tls_client(&certificates, socks.listen).await;
        stream.write_all(&[5, 1, 0]).await.unwrap();
        let mut selected = [0u8; 2];
        stream.read_exact(&mut selected).await.unwrap();
        assert_eq!(selected, [5, 0]);
        stream.write_all(&socks5_address(1, echo)).await.unwrap();
        socks5_reply(&mut stream).await;
        echo_round(&mut stream, 7).await;
        stream
    };
    let mut ended = socks_over_tls().await;
    let mut other = socks_over_tls().await;
    let client = ended.get_ref().0.local_addr().unwrap();
    let (instance, session) = engine_session(&engine, "tls-socks", |s| s.client == client).await;
    assert!(session.terminable);
    assert_eq!(
        end(&engine, &instance, "tls-socks", session.id).await,
        "closed"
    );
    closed(&mut ended).await;
    target_closed(&mut closes, 1).await;
    echo_round(&mut other, 8).await;
    drop(other);
    target_closed(&mut closes, 1).await;

    // HTTP CONNECT inside TLS.
    let connect_over_tls = || async {
        let mut stream = tls_client(&certificates, connect.listen).await;
        stream
            .write_all(format!("CONNECT {echo} HTTP/1.1\r\nHost: {echo}\r\n\r\n").as_bytes())
            .await
            .unwrap();
        let mut head = vec![];
        while !head.ends_with(b"\r\n\r\n") {
            let mut byte = [0u8; 1];
            stream.read_exact(&mut byte).await.unwrap();
            head.push(byte[0]);
        }
        assert!(head.starts_with(b"HTTP/1.1 200"), "{head:?}");
        echo_round(&mut stream, 9).await;
        stream
    };
    let mut ended = connect_over_tls().await;
    let mut other = connect_over_tls().await;
    let client = ended.get_ref().0.local_addr().unwrap();
    let (instance, session) = engine_session(&engine, "tls-connect", |s| s.client == client).await;
    assert!(session.terminable);
    assert_eq!(
        end(&engine, &instance, "tls-connect", session.id).await,
        "closed"
    );
    closed(&mut ended).await;
    target_closed(&mut closes, 1).await;
    echo_round(&mut other, 10).await;
    drop(other);
    target_closed(&mut closes, 1).await;

    // A PROXY header inside TLS names the client shown.
    let header_in_tls = |port: u16| {
        let certificates = &certificates;
        async move {
            let mut stream = tls_client(certificates, inside.listen).await;
            stream
                .write_all(format!("PROXY TCP4 198.51.100.8 127.0.0.1 {port} 80\r\n").as_bytes())
                .await
                .unwrap();
            echo_round(&mut stream, 11).await;
            stream
        }
    };
    let mut ended = header_in_tls(40003).await;
    let mut other = header_in_tls(40004).await;
    let named: SocketAddr = "198.51.100.8:40003".parse().unwrap();
    let (instance, session) = engine_session(&engine, "tls-header", |s| s.client == named).await;
    assert!(session.terminable);
    assert_eq!(
        end(&engine, &instance, "tls-header", session.id).await,
        "closed"
    );
    closed(&mut ended).await;
    target_closed(&mut closes, 1).await;
    echo_round(&mut other, 12).await;
    drop(other);
    target_closed(&mut closes, 1).await;

    // A PROXY v2 header on a TCP and UDP rule: its TCP session ends alone.
    let v2_header = |port: u16| async move {
        let mut stream = TcpStream::connect(both.listen).await.unwrap();
        let SocketAddr::V4(to) = both.listen else {
            unreachable!()
        };
        let source: [u8; 4] = [198, 51, 100, 9];
        let header = [
            &b"\r\n\r\n\0\r\nQUIT\n\x21\x11\0\x0c"[..],
            &source,
            &to.ip().octets(),
            &port.to_be_bytes(),
            &to.port().to_be_bytes(),
        ]
        .concat();
        stream.write_all(&header).await.unwrap();
        echo_round(&mut stream, 13).await;
        stream
    };
    let mut ended = v2_header(40005).await;
    let mut other = v2_header(40006).await;
    let named: SocketAddr = "198.51.100.9:40005".parse().unwrap();
    let (instance, session) = engine_session(&engine, "proxied-both", |s| s.client == named).await;
    assert!(session.terminable);
    assert_eq!(
        end(&engine, &instance, "proxied-both", session.id).await,
        "closed"
    );
    closed(&mut ended).await;
    target_closed(&mut closes, 1).await;
    echo_round(&mut other, 14).await;
    drop(other);
    target_closed(&mut closes, 1).await;

    // A PROXY header before the TLS handshake names the client shown.
    let header_before_tls = |port: u16| {
        let certificates = &certificates;
        async move {
            let mut tcp = TcpStream::connect(before.listen).await.unwrap();
            tcp.write_all(format!("PROXY TCP4 198.51.100.10 127.0.0.1 {port} 80\r\n").as_bytes())
                .await
                .unwrap();
            let name = tokio_rustls::rustls::pki_types::ServerName::try_from("relay.test").unwrap();
            let mut stream = certificates
                .connector(false)
                .connect(name, tcp)
                .await
                .unwrap();
            echo_round(&mut stream, 15).await;
            stream
        }
    };
    let mut ended = header_before_tls(40007).await;
    let mut other = header_before_tls(40008).await;
    let named: SocketAddr = "198.51.100.10:40007".parse().unwrap();
    let (instance, session) =
        engine_session(&engine, "tls-after-header", |s| s.client == named).await;
    assert!(session.terminable);
    assert_eq!(
        end(&engine, &instance, "tls-after-header", session.id).await,
        "closed"
    );
    closed(&mut ended).await;
    target_closed(&mut closes, 1).await;
    echo_round(&mut other, 16).await;
    drop(other);
    target_closed(&mut closes, 1).await;
    engine.shutdown().await.unwrap();
}

/// A Shadowsocks 2022 (AES-128) client stream: its request, then chunks.
struct SsStream {
    key: ring::aead::LessSafeKey,
    nonce: u64,
}
/// The session subkey of `psk` for `salt`, as SIP022 derives it.
fn ss_subkey(psk: &[u8], salt: &[u8]) -> ring::aead::LessSafeKey {
    let mut subkey = [0u8; 16];
    let mut hash = blake3::Hasher::new_derive_key("shadowsocks 2022 session subkey");
    hash.update(psk)
        .update(salt)
        .finalize_xof()
        .fill(&mut subkey);
    ring::aead::LessSafeKey::new(
        ring::aead::UnboundKey::new(&ring::aead::AES_128_GCM, &subkey).unwrap(),
    )
}
fn unix_now() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
/// A SOCKS-style address: IPv4, or a name.
fn ss_address(ip: Option<SocketAddr>, name: (&str, u16)) -> Vec<u8> {
    match ip {
        Some(SocketAddr::V4(address)) => [
            &[1][..],
            &address.ip().octets(),
            &address.port().to_be_bytes(),
        ]
        .concat(),
        _ => [
            &[3, name.0.len() as u8][..],
            name.0.as_bytes(),
            &name.1.to_be_bytes(),
        ]
        .concat(),
    }
}
impl SsStream {
    /// The request for `address` with `payload` as its first data.
    fn request(psk: &[u8], address: &[u8], payload: &[u8]) -> (Self, Vec<u8>) {
        let mut salt = [0u8; 16];
        ring::rand::SecureRandom::fill(&ring::rand::SystemRandom::new(), &mut salt).unwrap();
        let mut stream = Self {
            key: ss_subkey(psk, &salt),
            nonce: 0,
        };
        let variable = [address, &[0, 0], payload].concat();
        let fixed = [
            &[0][..],
            &unix_now().to_be_bytes(),
            &(variable.len() as u16).to_be_bytes(),
        ]
        .concat();
        let request = [&salt[..], &stream.seal(fixed), &stream.seal(variable)].concat();
        (stream, request)
    }
    fn seal(&mut self, mut block: Vec<u8>) -> Vec<u8> {
        let mut nonce = [0u8; 12];
        nonce[..8].copy_from_slice(&self.nonce.to_le_bytes());
        self.nonce += 1;
        self.key
            .seal_in_place_append_tag(
                ring::aead::Nonce::assume_unique_for_key(nonce),
                ring::aead::Aad::empty(),
                &mut block,
            )
            .unwrap();
        block
    }
    fn chunk(&mut self, payload: &[u8]) -> Vec<u8> {
        let length = self.seal((payload.len() as u16).to_be_bytes().to_vec());
        [length, self.seal(payload.to_vec())].concat()
    }
}
/// A Shadowsocks 2022 (AES-128) client datagram of `session`.
fn ss_datagram(psk: &[u8], session: u64, packet: u64, to: SocketAddr, payload: &[u8]) -> Vec<u8> {
    use aes::cipher::{BlockCipherEncrypt, KeyInit};
    let mut header = [session.to_be_bytes(), packet.to_be_bytes()].concat();
    let mut body = [
        &[0][..],
        &unix_now().to_be_bytes(),
        &[0, 0],
        &ss_address(Some(to), ("", 0)),
        payload,
    ]
    .concat();
    ss_subkey(psk, &header[..8])
        .seal_in_place_append_tag(
            ring::aead::Nonce::try_assume_unique_for_key(&header[4..]).unwrap(),
            ring::aead::Aad::empty(),
            &mut body,
        )
        .unwrap();
    let block = <&mut aes::Block>::try_from(&mut header[..]).unwrap();
    aes::Aes128::new_from_slice(psk)
        .unwrap()
        .encrypt_block(block);
    [header, body].concat()
}

/// The next data a target received is `what`.
async fn forwarded(received: &mut mpsc::UnboundedReceiver<Vec<u8>>, what: &[u8]) {
    let next = timeout(Duration::from_secs(5), received.recv())
        .await
        .expect("forwarded")
        .unwrap();
    assert_eq!(next, what, "{}", String::from_utf8_lossy(what));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn shadowsocks_sessions_answer_unsupported_and_keep_forwarding() {
    // What the targets receive, over TCP and UDP.
    let tcp_target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp_address = tcp_target.local_addr().unwrap();
    let (got, mut received) = mpsc::unbounded_channel::<Vec<u8>>();
    let tcp_got = got.clone();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = tcp_target.accept().await {
            let got = tcp_got.clone();
            tokio::spawn(async move {
                let mut buffer = [0u8; 512];
                while let Ok(read) = socket.read(&mut buffer).await {
                    if read == 0 || got.send(buffer[..read].to_vec()).is_err() {
                        break;
                    }
                }
            });
        }
    });
    let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_address = udp_target.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = [0u8; 512];
        while let Ok((read, _)) = udp_target.recv_from(&mut buffer).await {
            let _ = got.send(buffer[..read].to_vec());
        }
    });

    let psk: Vec<u8> = (0..16).collect();
    let mut ss = forward("ss", tcp_address, Protocol::Both);
    ss.targets.clear();
    ss.idle_timeout_secs = 600;
    ss.inbound_shadowsocks = Some(shadowsocks::ServerConfig {
        method: shadowsocks::Method::Blake3Aes128Gcm,
        password: {
            use base64::Engine as _;
            base64::engine::general_purpose::STANDARD.encode(&psk)
        },
        allow_private_destinations: true,
        udp_over_tcp: true,
    });
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    engine.apply(config(ss.clone())).await.unwrap();
    let unsupported = |pick: Box<dyn Fn(&Session) -> bool + Send + Sync>| {
        let engine = &engine;
        async move {
            let (instance, session) = engine_session(engine, "ss", pick).await;
            assert!(!session.terminable, "{}", session.protocol);
            assert_eq!(
                end(engine, &instance, "ss", session.id).await,
                "unsupported",
                "{}",
                session.protocol
            );
        }
    };

    // An established TCP session: asked to end, it forwards on.
    let mut client = TcpStream::connect(ss.listen).await.unwrap();
    let (mut stream, request) =
        SsStream::request(&psk, &ss_address(Some(tcp_address), ("", 0)), b"first");
    client.write_all(&request).await.unwrap();
    forwarded(&mut received, b"first").await;
    let local = client.local_addr().unwrap();
    unsupported(Box::new(move |s| s.client == local)).await;
    client.write_all(&stream.chunk(b"second")).await.unwrap();
    forwarded(&mut received, b"second").await;

    // UDP over TCP (version 2, connected to the UDP target).
    let mut uot = TcpStream::connect(ss.listen).await.unwrap();
    let frame = |payload: &[u8]| [&(payload.len() as u16).to_be_bytes()[..], payload].concat();
    let header = [&[1u8][..], &ss_address(Some(udp_address), ("", 0))].concat();
    let (mut stream, request) = SsStream::request(
        &psk,
        &ss_address(None, ("sp.v2.udp-over-tcp.arpa", 0)),
        &[header, frame(b"uot-one")].concat(),
    );
    uot.write_all(&request).await.unwrap();
    forwarded(&mut received, b"uot-one").await;
    let local = uot.local_addr().unwrap();
    unsupported(Box::new(move |s| s.client == local)).await;
    uot.write_all(&stream.chunk(&frame(b"uot-two")))
        .await
        .unwrap();
    forwarded(&mut received, b"uot-two").await;

    // A UDP association.
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let local = socket.local_addr().unwrap();
    socket
        .send_to(&ss_datagram(&psk, 7, 0, udp_address, b"udp-one"), ss.listen)
        .await
        .unwrap();
    forwarded(&mut received, b"udp-one").await;
    unsupported(Box::new(move |s| s.udp && s.client == local)).await;
    socket
        .send_to(&ss_datagram(&psk, 7, 1, udp_address, b"udp-two"), ss.listen)
        .await
        .unwrap();
    forwarded(&mut received, b"udp-two").await;
    drop((client, uot));
    engine.shutdown().await.unwrap();
}

/// MPTCP from the client and to the target, which the kernel must offer.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires Linux with enabled MPTCP; run explicitly during Linux acceptance"]
async fn an_mptcp_session_ends_on_both_sides() {
    use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
    let mptcp = || {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(SocketProtocol::MPTCP)).unwrap();
        socket.set_nonblocking(true).unwrap();
        socket
    };
    // A watched echo that takes MPTCP only.
    let listening = mptcp();
    listening
        .bind(&"127.0.0.1:0".parse::<SocketAddr>().unwrap().into())
        .unwrap();
    listening.listen(8).unwrap();
    let listener = TcpListener::from_std(listening.into()).unwrap();
    let echo = listener.local_addr().unwrap();
    let (ended_tx, mut closes) = mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            assert_eq!(
                relay_platform::mptcp::inspect(&socket).negotiated,
                Some(true)
            );
            let ended = ended_tx.clone();
            tokio::spawn(async move {
                let (mut reader, mut writer) = socket.split();
                let _ = tokio::io::copy(&mut reader, &mut writer).await;
                let _ = ended.send(());
            });
        }
    });
    let mut rule = forward("mptcp", echo, Protocol::Tcp);
    rule.idle_timeout_secs = 600;
    rule.mptcp = Some(relay_platform::mptcp::Config {
        inbound: relay_platform::mptcp::Mode::Require,
        outbound: relay_platform::mptcp::Mode::Require,
    });
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    engine.apply(config(rule.clone())).await.unwrap();
    let client = || async {
        let mut stream = tokio::net::TcpSocket::from_std_stream(mptcp().into())
            .connect(rule.listen)
            .await
            .unwrap();
        echo_round(&mut stream, 3).await;
        assert_eq!(
            relay_platform::mptcp::inspect(&stream).negotiated,
            Some(true)
        );
        stream
    };
    let mut ended = client().await;
    let mut other = client().await;
    let local = ended.local_addr().unwrap();
    let (instance, session) = engine_session(&engine, "mptcp", |s| s.client == local).await;
    assert!(session.terminable);
    assert_eq!(end(&engine, &instance, "mptcp", session.id).await, "closed");
    closed(&mut ended).await;
    target_closed(&mut closes, 1).await;
    echo_round(&mut other, 4).await;
    drop(other);
    target_closed(&mut closes, 1).await;
    engine.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gateway_bridges_and_shadowsocks_sessions_are_not_ended_alone() {
    let certificates = tls::Certificates::new();
    let temp = tempfile::tempdir().unwrap();
    // A stand-in for the protocol engine, enough to load the gateway; it
    // keeps the configuration it checked, for the bridge's credential, and
    // names a loopback port for the gateway's inbound as the engine does.
    // Nothing listens there: this test reaches the bridge directly.
    let checked = temp.path().join("checked.json");
    let stand_in = temp.path().join("sing-box");
    std::fs::write(
        &stand_in,
        format!(
            "#!/bin/sh\ncase \"$1\" in\n  version) echo 'sing-box version {}' ;;\n  check) cp \"$3\" '{}' ;;\n  run) echo 'INFO[0000] inbound/vless[in-gw]: tcp server started at {}' >&2; echo 'INFO[0000] sing-box started (0.00s)' >&2; exec sleep 600 ;;\nesac\n",
            gateway::ENGINE_VERSION,
            checked.display(),
            free_address()
        ),
    )
    .unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&stand_in, std::fs::Permissions::from_mode(0o755)).unwrap();
    }
    let udp = udp_echo().await;
    let mut bridge = forward("gw", udp.address, Protocol::Both);
    bridge.targets.clear();
    bridge.idle_timeout_secs = 600;
    bridge.protocol_gateway = Some(gateway::Config {
        listen: free_address(),
        protocol: gateway::WireProtocol::Vless {
            uuid: "bf000d23-0752-40b4-affe-68f7707a9661".into(),
            vision: false,
        },
        security: gateway::Security::Certificate {
            identity: "server".into(),
            server_name: Some("relay.test".into()),
        },
        allow_private_destinations: true,
    });
    let mut ss = forward("ss", udp.address, Protocol::Tcp);
    ss.targets.clear();
    ss.connect_timeout_ms = 30_000;
    ss.inbound_shadowsocks = Some(shadowsocks::ServerConfig {
        method: shadowsocks::Method::Blake3Aes128Gcm,
        password: "MDEyMzQ1Njc4OWFiY2RlZg==".into(),
        allow_private_destinations: true,
        udp_over_tcp: false,
    });
    let engine = Engine::with_tls_directory(
        Store::open(&temp.path().join("agent.db")).unwrap(),
        Some(certificates.root.clone()),
    )
    .with_protocol_engine(stand_in);
    let mut node = config(bridge.clone());
    node.rules.push(ss.clone());
    engine.apply(node).await.unwrap();

    // The bridge as the protocol engine uses it: SOCKS5 with the rule's
    // credential, then a UDP association, shown as `socks5_udp`.
    let checked: Value = serde_json::from_slice(&std::fs::read(&checked).unwrap()).unwrap();
    let outbound = checked["outbounds"]
        .as_array()
        .unwrap()
        .iter()
        .find(|o| o["tag"] == "meter-gw")
        .unwrap();
    let user = outbound["username"].as_str().unwrap();
    let password = outbound["password"].as_str().unwrap();
    let mut control = TcpStream::connect(bridge.listen).await.unwrap();
    control.write_all(&[5, 1, 2]).await.unwrap();
    let mut answer = [0u8; 2];
    control.read_exact(&mut answer).await.unwrap();
    assert_eq!(answer, [5, 2]);
    let login = [
        &[1, user.len() as u8][..],
        user.as_bytes(),
        &[password.len() as u8],
        password.as_bytes(),
    ]
    .concat();
    control.write_all(&login).await.unwrap();
    control.read_exact(&mut answer).await.unwrap();
    assert_eq!(answer, [1, 0]);
    control
        .write_all(&socks5_address(3, "0.0.0.0:0".parse().unwrap()))
        .await
        .unwrap();
    let relay = socks5_reply(&mut control).await;
    let associated = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let port = udp.address.port().to_be_bytes();
    let datagram = [&[0, 0, 0, 1, 127, 0, 0, 1, port[0], port[1]][..], b"hello"].concat();
    let relays = || async {
        associated.send_to(&datagram, relay).await.unwrap();
        let mut buffer = [0u8; 64];
        let size = timeout(Duration::from_secs(5), associated.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[10..size], b"hello");
    };
    relays().await;
    let client = control.local_addr().unwrap();
    let (instance, session) = engine_session(&engine, "gw", |s| s.client == client).await;
    assert_eq!(session.protocol, "socks5_udp");
    assert!(
        !session.terminable,
        "whatever it shows, a bridge does not end alone"
    );
    assert_eq!(
        end(&engine, &instance, "gw", session.id).await,
        "unsupported"
    );
    relays().await;
    engine_session(&engine, "gw", |s| s.client == client).await;

    // Shadowsocks: listed from its accept, while it waits for the handshake.
    let raw = TcpStream::connect(ss.listen).await.unwrap();
    let client = raw.local_addr().unwrap();
    let (instance, session) = engine_session(&engine, "ss", |s| s.client == client).await;
    assert!(!session.terminable);
    assert_eq!(
        end(&engine, &instance, "ss", session.id).await,
        "unsupported"
    );
    engine_session(&engine, "ss", |s| s.client == client).await;
    drop(raw);
    engine.shutdown().await.unwrap();
}

/// A DNS server that never answers, over UDP and TCP on one port: a lookup
/// through it waits until the resolver gives up.
async fn silent_dns() -> (SocketAddr, UdpSocket, TcpListener) {
    loop {
        let tcp = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = tcp.local_addr().unwrap();
        if let Ok(udp) = UdpSocket::bind(address).await {
            return (address, udp, tcp);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_socks5_udp_session_ends_while_its_relay_resolves_a_name() {
    let (dns, queries, _held) = silent_dns().await;
    let mut proxy = forward("proxy", dns, Protocol::Both);
    proxy.targets.clear();
    proxy.idle_timeout_secs = 600;
    proxy.inbound_socks5 = Some(socks5::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: true,
    });
    proxy.dns_cache = Some(DnsCache {
        servers: vec![dns],
        capacity: 16,
        max_ttl_secs: 60,
        negative_max_ttl_secs: 5,
    });
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    engine.apply(config(proxy.clone())).await.unwrap();

    let mut control = TcpStream::connect(proxy.listen).await.unwrap();
    socks5_hello(&mut control).await;
    control
        .write_all(&socks5_address(3, "0.0.0.0:0".parse().unwrap()))
        .await
        .unwrap();
    let relay = socks5_reply(&mut control).await;
    let associated = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let echo = udp_echo().await;
    let port = echo.address.port().to_be_bytes();
    let to_echo =
        |payload: &[u8]| [&[0, 0, 0, 1, 127, 0, 0, 1, port[0], port[1]][..], payload].concat();
    let mut buffer = [0u8; 64];
    associated
        .send_to(&to_echo(b"before"), relay)
        .await
        .unwrap();
    let size = timeout(Duration::from_secs(5), associated.recv(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[10..size], b"before");
    let name = b"stuck.test";
    let datagram = [
        &[0, 0, 0, 3, name.len() as u8][..],
        name,
        &9u16.to_be_bytes(),
        b"hello",
    ]
    .concat();
    associated.send_to(&datagram, relay).await.unwrap();
    // The relay waits for the name: the server got the question.
    let mut query = [0u8; 512];
    timeout(Duration::from_secs(10), queries.recv_from(&mut query))
        .await
        .expect("the relay asks for the name")
        .unwrap();
    let client = control.local_addr().unwrap();
    let (instance, session) = engine_session(&engine, "proxy", |s| s.client == client).await;
    assert_eq!(session.protocol, "socks5_udp");
    // The lookup stops with the session: it is closed at once, its client
    // connection closes and nothing more is relayed.
    assert_eq!(end(&engine, &instance, "proxy", session.id).await, "closed");
    assert!(engine_sessions(&engine, "proxy").1.is_empty());
    closed(&mut control).await;
    associated.send_to(&to_echo(b"after"), relay).await.unwrap();
    assert!(
        timeout(Duration::from_millis(1000), associated.recv(&mut buffer))
            .await
            .is_err(),
        "an ended association relayed"
    );
    drop(control);
    engine.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn an_http2_connect_session_ends_while_one_of_its_streams_dials() {
    let (dns, queries, _held) = silent_dns().await;
    let (echo, mut closes) = watched_echo("127.0.0.1:0").await;
    let mut h2 = forward("h2", echo, Protocol::Tcp);
    h2.targets.clear();
    h2.idle_timeout_secs = 600;
    h2.connect_timeout_ms = 30_000;
    h2.inbound_http2_connect = Some(http2_connect::ServerConfig {
        username: None,
        password: None,
        bearer_token_sha256: vec![format!("{:x}", Sha256::digest(b"token"))],
        allow_private_destinations: true,
        max_concurrent_streams: 8,
        socket_buffer_bytes: None,
    });
    h2.dns_cache = Some(DnsCache {
        servers: vec![dns],
        capacity: 16,
        max_ttl_secs: 60,
        negative_max_ttl_secs: 5,
    });
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    engine.apply(config(h2.clone())).await.unwrap();

    let (client, mut sender) = h2_client(h2.listen).await;
    let mut tunnel = h2_tunnel(&mut sender, echo).await;
    echo_round(&mut tunnel, 3).await;
    // Another stream of the connection dials a name nobody answers.
    let mut stuck = sender.clone();
    let dialing = tokio::spawn(async move {
        let request = Request::builder()
            .method("CONNECT")
            .uri("http://stuck.test:9")
            .header("proxy-authorization", "Bearer token")
            .body(Empty::<Bytes>::new())
            .unwrap();
        stuck.send_request(request).await
    });
    let mut query = [0u8; 512];
    timeout(Duration::from_secs(10), queries.recv_from(&mut query))
        .await
        .expect("the stream asks for the name")
        .unwrap();
    let (instance, session) = engine_session(&engine, "h2", |s| s.client == client).await;
    assert!(session.terminable);
    // The whole connection ends at once, the dialing stream with it: its
    // tunnel closes on both sides and the dialing stream gets no tunnel.
    assert_eq!(end(&engine, &instance, "h2", session.id).await, "closed");
    assert!(engine_sessions(&engine, "h2").1.is_empty());
    closed(&mut tunnel).await;
    target_closed(&mut closes, 1).await;
    let answer = timeout(Duration::from_secs(5), dialing)
        .await
        .expect("the dialing stream ends with its connection")
        .unwrap();
    assert!(
        answer
            .as_ref()
            .map_or(true, |response| response.status() != StatusCode::OK),
        "{answer:?}"
    );
    engine.shutdown().await.unwrap();
}
