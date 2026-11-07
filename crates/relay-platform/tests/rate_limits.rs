//! Upload, download and burst speed limits: real agents enforcing a rule's
//! and a server's upload-only and download-only limits and a rule's burst
//! through the public API, a user's upload and download totals split between
//! two servers, UDP directions in the engine, the 409 for servers whose agent
//! is too old, and records and configs without the new limits unchanged.
//! Throughput bounds leave wide margins; a limited transfer takes about three
//! seconds and an unlimited one milliseconds.
mod common;
use common::*;
use relay_platform::{
    agent::{self, AgentOptions},
    api::{self, AppState},
    engine::Engine,
    model::*,
    store::{Store, write_secret},
};
use serde_json::{Value, json};
use std::{net::SocketAddr, path::Path, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{Instant, sleep, timeout},
};
use tokio_util::sync::CancellationToken;

/// A limited transfer: 256 KiB at 64 KiB/s with one second banked is 3 s.
const LIMIT: u64 = 64 << 10;
const AMOUNT: usize = 256 << 10;
const SLOW: Duration = Duration::from_millis(2400);
const FAST: Duration = Duration::from_millis(1500);

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
    /// Publishes `body` (rules and limits) on `node` at its current revision.
    async fn publish(&self, node: &str, mut body: Value) -> (u16, Value) {
        let config = self.get(&format!("/nodes/{node}/config")).await;
        body["expected_revision"] = config["revision"].clone();
        self.call(
            reqwest::Method::PUT,
            &format!("/nodes/{node}/config"),
            Some(body),
        )
        .await
    }
    /// Publishes and waits until the node's agent applied it.
    async fn apply(&self, node: &str, body: Value) {
        let (code, config) = self.publish(node, body).await;
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
}

/// Real agents for `nodes`, stopped on drop.
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

/// A TCP target that reads a request of two little-endian u64 (upload and
/// download byte counts), takes the upload bytes, sends the download bytes
/// and closes.
async fn target() -> SocketAddr {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut header = [0u8; 16];
                stream.read_exact(&mut header).await?;
                let up = u64::from_le_bytes(header[..8].try_into().unwrap()) as usize;
                let down = u64::from_le_bytes(header[8..].try_into().unwrap()) as usize;
                let mut upload = vec![0; up];
                stream.read_exact(&mut upload).await?;
                stream.write_all(&vec![0x5a; down]).await?;
                stream.shutdown().await
            });
        }
    });
    address
}
/// Sends `up` bytes through `entry` and receives `down`; how long it took.
async fn transfer(entry: SocketAddr, up: usize, down: usize) -> Duration {
    timeout(Duration::from_secs(40), async {
        let started = Instant::now();
        let mut stream = TcpStream::connect(entry).await.unwrap();
        let mut request = Vec::with_capacity(16 + up);
        request.extend((up as u64).to_le_bytes());
        request.extend((down as u64).to_le_bytes());
        request.resize(16 + up, 0xa5);
        stream.write_all(&request).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut received = vec![];
        stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received.len(), down);
        started.elapsed()
    })
    .await
    .expect("the transfer finished")
}
/// Upload-heavy and download-heavy transfers through `entry`.
async fn both_ways(entry: SocketAddr) -> (Duration, Duration) {
    (
        transfer(entry, AMOUNT, 0).await,
        transfer(entry, 0, AMOUNT).await,
    )
}

fn forward(id: &str, owner: &str, target: SocketAddr) -> Rule {
    let mut rule = rule(target, Protocol::Tcp);
    rule.id = id.into();
    rule.owner_id = owner.into();
    rule
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
    /// Servers with running agents, once each reported that it enforces these limits.
    async fn servers(&self, names: &[&str]) -> (Vec<String>, Agents) {
        let created: Vec<_> = names
            .iter()
            .map(|name| {
                self.store
                    .create_node(&self.admin, "default", name)
                    .unwrap()
            })
            .collect();
        let pairs: Vec<(&str, &str)> = created
            .iter()
            .map(|(node, enrollment)| (node.id.as_str(), enrollment.as_str()))
            .collect();
        let agents = Agents::start(self.temp.path(), &self.api.origin, &pairs);
        let ids: Vec<String> = created.iter().map(|(node, _)| node.id.clone()).collect();
        for id in &ids {
            self.api
                .until("the agent to report support", || async {
                    self.api.node(id).await["rate_limit_support"] == true
                })
                .await;
        }
        (ids, agents)
    }
}
impl Drop for Panel {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rule_and_server_direction_limits_and_a_rule_burst_through_a_real_agent() {
    let panel = Panel::new().await;
    let (nodes, _agents) = panel.servers(&["tokyo"]).await;
    let (node, api) = (&nodes[0], &panel.api);
    let mut rule = forward("limited", &panel.admin.id, target().await);
    let entry = rule.listen;

    // Upload only: the client's bytes toward the target wait, the replies do not.
    rule.rate_limits = Some(RateLimits {
        upload_bytes_per_sec: Some(LIMIT),
        ..Default::default()
    });
    api.apply(node, json!({ "rules": [rule] })).await;
    let config = api.get(&format!("/nodes/{node}/config")).await;
    assert_eq!(
        config["rules"][0]["rate_limits"],
        json!({"upload_bytes_per_sec": LIMIT})
    );
    assert!(config["rules"][0]["rate_bytes_per_sec"].is_null());
    let (up, down) = both_ways(entry).await;
    assert!(
        up >= SLOW && down < FAST,
        "upload limit: up {up:?} down {down:?}"
    );

    // Download only: the reverse.
    rule.rate_limits = Some(RateLimits {
        download_bytes_per_sec: Some(LIMIT),
        ..Default::default()
    });
    api.apply(node, json!({ "rules": [rule] })).await;
    let (up, down) = both_ways(entry).await;
    assert!(
        up < FAST && down >= SLOW,
        "download limit: up {up:?} down {down:?}"
    );

    // The server's own upload limit, with no limit on the rule; the
    // combined server limit stays as it was.
    rule.rate_limits = None;
    api.apply(
        node,
        json!({ "rules": [rule], "rate_bytes_per_sec": 64 << 20, "rate_limits": {"upload_bytes_per_sec": LIMIT} }),
    )
    .await;
    let config = api.get(&format!("/nodes/{node}/config")).await;
    assert_eq!(
        (&config["rate_bytes_per_sec"], &config["rate_limits"]),
        (&json!(64 << 20), &json!({"upload_bytes_per_sec": LIMIT}))
    );
    let (up, down) = both_ways(entry).await;
    assert!(
        up >= SLOW && down < FAST,
        "server upload limit: up {up:?} down {down:?}"
    );
    // Leaving the limits out keeps them; null clears them.
    api.apply(node, json!({ "rules": [rule] })).await;
    let config = api.get(&format!("/nodes/{node}/config")).await;
    assert_eq!(
        config["rate_limits"],
        json!({"upload_bytes_per_sec": LIMIT})
    );
    api.apply(node, json!({ "rules": [rule], "rate_limits": null }))
        .await;
    let config = api.get(&format!("/nodes/{node}/config")).await;
    assert!(config.get("rate_limits").is_none(), "{config}");
    assert_eq!(config["rate_bytes_per_sec"], json!(64 << 20));
    let (up, down) = both_ways(entry).await;
    assert!(up < FAST && down < FAST, "cleared: up {up:?} down {down:?}");

    // A burst: 16 KiB/s sustained, 1 MiB/s for a second, so 1008 KiB of
    // credit. Without it 512 KiB would take half a minute.
    rule.rate_bytes_per_sec = Some(16 << 10);
    rule.rate_limits = Some(RateLimits {
        burst: Some(Burst {
            bytes_per_sec: 1 << 20,
            secs: 1,
        }),
        ..Default::default()
    });
    api.apply(node, json!({ "rules": [rule] })).await;
    let capacity: u64 = (1024 - 16) << 10;
    let credit = || async {
        let node = api.node(node).await;
        let bursts = node["stats"]["rate_limits"]["bursts"].clone();
        bursts
            .as_array()
            .into_iter()
            .flatten()
            .find(|b| b["rule_id"] == "limited" && b["direction"] == "combined")
            .map(|b| {
                assert_eq!(b["capacity_bytes"], capacity, "{b}");
                b["credit_bytes"].as_u64().unwrap()
            })
    };
    api.until("a full burst credit", || async {
        credit().await == Some(capacity)
    })
    .await;
    let up = transfer(entry, 512 << 10, 0).await;
    assert!(
        up < Duration::from_secs(3),
        "the burst did not apply: {up:?}"
    );
    // About 496 KiB is left; it refills at 16 KiB/s, half a minute.
    api.until("the burst credit in use", || async {
        credit()
            .await
            .is_some_and(|c| c < capacity && c > 300 << 10)
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_users_upload_and_download_totals_are_split_between_two_servers() {
    let panel = Panel::new().await;
    let (nodes, _agents) = panel.servers(&["osaka", "nagoya"]).await;
    let api = &panel.api;
    let user = panel.admin.id.clone();
    let mut entries = vec![];
    for (index, node) in nodes.iter().enumerate() {
        let rule = forward(&format!("user-rule-{index}"), &user, target().await);
        entries.push(rule.listen);
        api.apply(node, json!({ "rules": [rule] })).await;
    }
    let total = 128u64 << 10;
    let (code, view) = api
        .call(
            reqwest::Method::PUT,
            &format!("/users/{user}/rate"),
            Some(json!({"rate_bytes_per_sec": null, "upload_bytes_per_sec": total})),
        )
        .await;
    assert_eq!(code, 200, "{view}");
    assert_eq!(
        (
            &view["rate_bytes_per_sec"],
            &view["upload_bytes_per_sec"],
            &view["download_bytes_per_sec"]
        ),
        (&Value::Null, &json!(total), &Value::Null)
    );
    // Both agents hold an upload share; shares never exceed the total.
    let held = |lane: &'static str| {
        let user = user.clone();
        async move {
            let view = api.get(&format!("/users/{user}/rate")).await;
            let seats = view[lane].as_array().unwrap().clone();
            let sum: u64 = seats
                .iter()
                .map(|s| s["share_bytes_per_sec"].as_u64().unwrap())
                .sum();
            // Until every server has synced, the view reserves a share for the others.
            let synced = seats.iter().all(|s| s["seen_ms_ago"].is_u64());
            let total = view[lane.replace("nodes", "bytes_per_sec")].as_u64();
            assert!(
                !synced || total.is_none_or(|t| sum <= t),
                "{lane} shares {sum} above the total: {view}"
            );
            (
                seats.len(),
                seats.iter().all(|s| s["enforced_bytes_per_sec"].is_u64()),
                view,
            )
        }
    };
    api.until("both upload shares in force", || async {
        let (count, enforced, view) = held("upload_nodes").await;
        assert!(
            view["nodes"].as_array().unwrap().is_empty()
                && view["download_nodes"].as_array().unwrap().is_empty(),
            "{view}"
        );
        count == 2 && enforced
    })
    .await;
    // Upload through one server is held to at most the user's total while
    // the shares move toward it; its download is not limited.
    let sampling = CancellationToken::new();
    let sampler = {
        let sampling = sampling.clone();
        async move {
            while !sampling.is_cancelled() {
                held("upload_nodes").await;
                sleep(Duration::from_millis(100)).await;
            }
        }
    };
    let ((up, down), ()) = tokio::join!(
        async {
            let up = transfer(entries[0], 512 << 10, 0).await;
            let down = transfer(entries[0], 0, 512 << 10).await;
            sampling.cancel();
            (up, down)
        },
        sampler
    );
    assert!(
        up >= SLOW && down < FAST,
        "user upload total: up {up:?} down {down:?}"
    );

    // A download total next to it; leaving upload out keeps it.
    let (code, view) = api
        .call(
            reqwest::Method::PUT,
            &format!("/users/{user}/rate"),
            Some(json!({"download_bytes_per_sec": total})),
        )
        .await;
    assert_eq!(code, 200, "{view}");
    assert_eq!(view["upload_bytes_per_sec"], json!(total));
    api.until("both download shares in force", || async {
        let (count, enforced, _) = held("download_nodes").await;
        count == 2 && enforced
    })
    .await;
    // A few KiB up stay within the upload share's banked second.
    let (up, down) = (
        transfer(entries[1], 4 << 10, 0).await,
        transfer(entries[1], 0, 512 << 10).await,
    );
    assert!(
        up < FAST && down >= SLOW,
        "user download total: up {up:?} down {down:?}"
    );
    held("upload_nodes").await;
    held("download_nodes").await;

    // null clears both; the agents drop the shares.
    let (code, view) = api
        .call(
            reqwest::Method::PUT,
            &format!("/users/{user}/rate"),
            Some(json!({"upload_bytes_per_sec": null, "download_bytes_per_sec": null})),
        )
        .await;
    assert_eq!(code, 200, "{view}");
    assert!(view["upload_bytes_per_sec"].is_null() && view["download_bytes_per_sec"].is_null());
    let (up, down) = (
        transfer(entries[1], 512 << 10, 0).await,
        transfer(entries[1], 0, 512 << 10).await,
    );
    // The agents may hold the last share until their next sync.
    assert!(
        up < Duration::from_secs(3) && down < Duration::from_secs(3),
        "cleared: up {up:?} down {down:?}"
    );
}

/// One sync as an agent of 0.146.0 or earlier, which reports no rate limits.
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
async fn servers_whose_agent_is_too_old_refuse_the_new_limits_with_409() {
    let panel = Panel::new().await;
    let (api, store, admin) = (&panel.api, &panel.store, &panel.admin);
    let (old, _) = store.create_node(admin, "default", "old").unwrap();
    let (fresh, _) = store.create_node(admin, "default", "fresh").unwrap();
    old_sync(store, &old.id);
    assert_eq!(api.node(&old.id).await["rate_limit_support"], false);
    let target = free_address();
    let mut rule = forward("plain", &admin.id, target);
    let too_old = "the agent on server old is too old for separate upload/download or burst speed limits; upgrade it first";
    let separate = RateLimits {
        download_bytes_per_sec: Some(LIMIT),
        ..Default::default()
    };

    // A rule's limits, the server's own and a burst are refused with the reason.
    let mut limited = rule.clone();
    limited.rate_limits = Some(separate);
    let refused = [
        json!({ "rules": [limited] }),
        json!({ "rules": [rule], "rate_limits": separate }),
        json!({ "rules": [rule], "rate_bytes_per_sec": LIMIT, "rate_limits": {"burst": {"bytes_per_sec": 4 * LIMIT, "secs": 10}} }),
    ];
    for body in &refused {
        let (code, error) = api.publish(&old.id, body.clone()).await;
        assert_eq!(
            (code, error["error"].as_str()),
            (409, Some(too_old)),
            "{body}"
        );
    }
    let (code, error) = api.publish(&fresh.id, json!({ "rules": [limited] })).await;
    assert_eq!(code, 409);
    assert_eq!(
        error["error"],
        "server fresh has not connected to the panel yet; separate upload/download or burst speed limits need its agent to report in first"
    );

    // Combined limits publish as before, and the old agent gets nothing new.
    rule.rate_bytes_per_sec = Some(LIMIT);
    let (code, config) = api
        .publish(
            &old.id,
            json!({ "rules": [rule], "rate_bytes_per_sec": 4 * LIMIT }),
        )
        .await;
    assert_eq!(code, 200, "{config}");
    store.set_user_rate(admin, &admin.id, Some(LIMIT)).unwrap();
    let sent = old_sync(store, &old.id);
    let text = sent["config"].to_string();
    assert!(
        !text.contains("rate_limits") && text.contains("\"rate_bytes_per_sec\":65536"),
        "{text}"
    );
    assert_eq!(
        sent["user_rates"],
        json!([{"tenant_id": "default", "owner_id": admin.id, "rate_bytes_per_sec": LIMIT, "fallback_bytes_per_sec": LIMIT}])
    );
    // The controller asks; an older agent ignores fields it does not know here.
    assert_eq!(sent["rate_limits"], true);

    // A user's upload or download total needs every server carrying their rules.
    let (code, error) = api
        .call(
            reqwest::Method::PUT,
            &format!("/users/{}/rate", admin.id),
            Some(json!({"rate_bytes_per_sec": LIMIT, "upload_bytes_per_sec": LIMIT})),
        )
        .await;
    assert_eq!((code, error["error"].as_str()), (409, Some(too_old)));
    assert!(
        store
            .user_rate(admin, &admin.id)
            .unwrap()
            .upload_bytes_per_sec
            .is_none()
    );
    // Nor can a rule of a user with one move onto such a server.
    let other = store
        .create_user(
            admin,
            "default",
            "alice",
            PASSWORD,
            relay_platform::store::Role::Viewer,
        )
        .unwrap();
    let (code, view) = api
        .call(
            reqwest::Method::PUT,
            &format!("/users/{}/rate", other.id),
            Some(json!({"rate_bytes_per_sec": null, "download_bytes_per_sec": LIMIT})),
        )
        .await;
    assert_eq!(code, 200, "{view}");
    let theirs = forward("alice-rule", &other.id, free_address());
    let (code, error) = api
        .publish(&old.id, json!({ "rules": [rule, theirs] }))
        .await;
    assert_eq!(code, 409);
    assert_eq!(
        error["error"],
        format!("user alice has separate upload/download speed limits: {too_old}")
    );

    // A cross-panel share's upload or download bandwidth needs the server too.
    store.set_feature(admin, "federation", true).unwrap();
    let grant = |name: &str| {
        json!({ "name": name, "node_id": old.id, "public_host": "203.0.113.7", "port_start": 22000,
                "port_end": 22009, "max_rules": 1, "kinds": ["forward"], "allow_sources": ["198.51.100.0/24"],
                "upload_bytes_per_sec": LIMIT })
    };
    let (code, error) = api
        .call(
            reqwest::Method::POST,
            "/federation/grants",
            Some(grant("Proxy")),
        )
        .await;
    assert_eq!((code, error["error"].as_str()), (409, Some(too_old)));

    // Once the agent reports support, the same requests go through.
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
                    rate_limits: Some(RateLimitReport::default()),
                    ..EngineStats::default()
                },
            },
        )
        .unwrap();
    assert_eq!(api.node(&old.id).await["rate_limit_support"], true);
    for body in &refused {
        let (code, error) = api.publish(&old.id, body.clone()).await;
        assert_eq!(code, 200, "{body}: {error}");
    }
    let (code, error) = api
        .publish(&old.id, json!({ "rules": [rule, theirs] }))
        .await;
    assert_eq!(code, 200, "{error}");
    let (code, created) = api
        .call(
            reqwest::Method::POST,
            "/federation/grants",
            Some(grant("Proxy")),
        )
        .await;
    assert_eq!(code, 200, "{created}");
    assert_eq!(created["upload_bytes_per_sec"], json!(LIMIT));
}

#[test]
fn records_and_configs_without_the_new_limits_read_and_write_as_before() {
    // A rule, a configuration and a share as 0.146.0 stored and sent them.
    let mut rule = rule(free_address(), Protocol::Tcp);
    rule.rate_bytes_per_sec = Some(125_000);
    let mut config = config(rule);
    config.rate_bytes_per_sec = Some(1 << 20);
    let text = serde_json::to_string(&config).unwrap();
    assert!(!text.contains("rate_limits"), "{text}");
    let read: NodeConfig = serde_json::from_str(&text).unwrap();
    assert!(read.rate_limits.is_none() && read.rules[0].rate_limits.is_none());
    assert_eq!(serde_json::to_string(&read).unwrap(), text);
    // An empty set of limits is the same as none.
    let mut empty = config.clone();
    empty.rules[0].rate_limits = RateLimits::normalized(Some(RateLimits::default()));
    assert_eq!(serde_json::to_string(&empty).unwrap(), text);

    let old_share = r#"{"tenant_id":"default","owner_id":"admin","rate_bytes_per_sec":65536,"fallback_bytes_per_sec":32768}"#;
    let share: UserShare = serde_json::from_str(old_share).unwrap();
    assert_eq!(
        share.part(RateDirection::Combined),
        Some(SharePart {
            rate_bytes_per_sec: 65536,
            fallback_bytes_per_sec: 32768
        })
    );
    assert_eq!(share.part(RateDirection::Upload), None);
    assert_eq!(serde_json::to_string(&share).unwrap(), old_share);

    let old_report = r#"{"tenant_id":"default","owner_id":"admin","bytes":10,"waited_ms":2,"enforced_bytes_per_sec":65536}"#;
    let report: UserRateReport = serde_json::from_str(old_report).unwrap();
    assert_eq!(serde_json::to_string(&report).unwrap(), old_report);
    let stats = serde_json::to_value(EngineStats::default()).unwrap();
    assert!(stats.get("rate_limits").is_none());

    // The new fields are left out one by one while unset.
    let limits = RateLimits {
        upload_bytes_per_sec: Some(1),
        ..Default::default()
    };
    assert_eq!(
        serde_json::to_string(&limits).unwrap(),
        r#"{"upload_bytes_per_sec":1}"#
    );
}

/// A UDP target replying one byte to a datagram starting with `u`, and
/// 1 KiB to any other.
async fn udp_target() -> SocketAddr {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let address = socket.local_addr().unwrap();
    tokio::spawn(async move {
        let mut buffer = vec![0; 65536];
        while let Ok((size, from)) = socket.recv_from(&mut buffer).await {
            let reply = if size > 0 && buffer[0] == b'u' {
                vec![1]
            } else {
                vec![2; 1024]
            };
            let _ = socket.send_to(&reply, from).await;
        }
    });
    address
}
/// 160 exchanges of 1 KiB up and a byte back (`upload`) or the reverse.
async fn datagrams(entry: SocketAddr, upload: bool) -> Duration {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let request = if upload { vec![b'u'; 1024] } else { vec![b'd'] };
    let started = Instant::now();
    let mut buffer = vec![0; 4096];
    for _ in 0..160 {
        socket.send_to(&request, entry).await.unwrap();
        let size = timeout(Duration::from_secs(5), socket.recv(&mut buffer))
            .await
            .expect("a reply")
            .unwrap();
        assert_eq!(size, if upload { 1 } else { 1024 });
    }
    started.elapsed()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_upload_and_download_limits_count_their_own_direction() {
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut rule = rule(udp_target().await, Protocol::Udp);
    let entry = rule.listen;
    // 160 KiB at 32 KiB/s is 3 s: a bucket holds at least one 64 KiB read.
    rule.rate_limits = Some(RateLimits {
        upload_bytes_per_sec: Some(32 << 10),
        ..Default::default()
    });
    let mut config = config(rule.clone());
    engine.apply(config.clone()).await.unwrap();
    let (up, down) = (datagrams(entry, true).await, datagrams(entry, false).await);
    assert!(
        up >= SLOW && down < FAST,
        "UDP upload limit: up {up:?} down {down:?}"
    );
    rule.rate_limits = Some(RateLimits {
        download_bytes_per_sec: Some(32 << 10),
        ..Default::default()
    });
    config.revision = 2;
    config.rules = vec![rule];
    engine.apply(config).await.unwrap();
    let (up, down) = (datagrams(entry, true).await, datagrams(entry, false).await);
    assert!(
        up < FAST && down >= SLOW,
        "UDP download limit: up {up:?} down {down:?}"
    );
    engine.shutdown().await.unwrap();
}
