//! Live connections and block records through the public API with real
//! agents on loopback: TCP and UDP sessions with their client, target and
//! growing byte counts that go away when they end; deny-list, allow-list
//! and connection-limit refusals as aggregated records, sent once; a SOCKS5
//! client's destination and a refused one; then, without agents, older
//! agents that get no requests, oversize reports, and who may look.
//! Waits poll for up to 20 s; nothing depends on exact timing.
mod common;
use common::*;
use relay_platform::{
    agent::{self, AgentOptions},
    api::{self, AppState},
    connections::{Block, BlockBatch, Report, Session, Snapshot},
    model::*,
    socks5,
    store::{Actor, Role, Scope, Store, write_secret},
};
use serde_json::{Value, json};
use std::{net::SocketAddr, path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{Instant, sleep, timeout},
};
use tokio_util::sync::CancellationToken;

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
async fn echo_round(stream: &mut TcpStream, bytes: usize) {
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
    assert_eq!(blocks, json!({"supported": false, "blocks": []}));
    let raw = serde_json::to_value(&reply).unwrap();
    assert!(raw.get("live_connection_requests").is_none() && raw.get("block_cursor").is_none());

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
        blocks: None,
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
        snapshots: vec![],
        blocks: Some(BlockBatch {
            stream: "s1".into(),
            entries,
        }),
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
    let old_reply: SyncResponse = serde_json::from_value(json!({
        "budget": null, "controller_instance": "x", "config": null,
        "acknowledgements": [], "server_time_ms": 1, "rate_limits": true,
    }))
    .unwrap();
    assert!(!old_reply.live_connections);
    assert!(old_reply.live_connection_requests.is_empty() && old_reply.block_cursor.is_none());
}
