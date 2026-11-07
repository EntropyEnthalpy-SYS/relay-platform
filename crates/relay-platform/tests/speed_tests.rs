//! Built-in speed tests: what agents get through sync and when, the API's
//! roles, tenants and refusals, and real agents on loopback measuring
//! between each other, against a local stand-in for Cloudflare's speed
//! service, and along every segment of a two-hop rule, without touching
//! the usage ledger.
mod common;
use common::*;
use relay_platform::{
    agent::{self, AgentOptions},
    api::{self, AppState},
    model::*,
    node::{ForwardingDefaults, NodeSettings, NodeUpdate},
    speed_test::{Directions, Mode, PathTestInput, Report, ServerTestInput, TaskRole, TaskState},
    store::{Actor, Rejection, Role, Scope, Store, write_secret},
    topology::{ConfigBatch, ConfigUpdate},
};
use serde_json::{Value, json};
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::Path,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{Instant, sleep, timeout},
};
use tokio_util::sync::CancellationToken;

fn status<T: std::fmt::Debug>(result: anyhow::Result<T>) -> (u16, String) {
    let error = result.unwrap_err();
    let rejection = error.downcast_ref::<Rejection>().unwrap();
    (rejection.status, rejection.message.clone())
}
fn ledger(db: &Store, node: &str) -> String {
    db.reconcile(
        node,
        ReconcileRequest {
            lease: None,
            ledger_id: None,
            after: None,
            expected_revision: None,
        },
    )
    .unwrap()
    .ledger_id
}
/// One agent report; `None` is an agent older than speed tests.
fn sync(db: &Store, node: &str, report: Option<Report>) -> SyncResponse {
    db.sync(
        node,
        SyncRequest {
            logs: None,
            lease: None,
            budget: None,
            ledger_id: ledger(db, node),
            need_config: false,
            applied_revision: 0,
            apply_error: None,
            usage: vec![],
            stats: EngineStats {
                speed_test: report,
                ..EngineStats::default()
            },
        },
    )
    .unwrap()
}
fn forwarding(db: &Store, admin: &Actor, node: &str, host: &str, start: u16, end: u16) {
    let current = db
        .nodes(admin)
        .unwrap()
        .into_iter()
        .find(|n| n.id == node)
        .unwrap();
    db.update_node(
        admin,
        node,
        NodeUpdate {
            expected_revision: current.profile.revision,
            name: current.name.clone(),
            settings: NodeSettings {
                forwarding: Some(ForwardingDefaults {
                    host: host.into(),
                    listen_ip: None,
                    port_start: start,
                    port_end: end,
                    public_port_start: None,
                }),
                ..Default::default()
            },
        },
    )
    .unwrap();
}
fn server_input(mode: Mode, node: &str, peer: Option<&str>) -> ServerTestInput {
    serde_json::from_value(json!({
        "mode": mode, "node_id": node, "peer_node_id": peer,
        "direction": "both", "duration_secs": 5, "streams": 2,
    }))
    .unwrap()
}

#[test]
fn only_agents_that_report_support_get_tasks_and_tests_needing_others_are_refused() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("controller.db")).unwrap();
    db.set_kind("controller").unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let (new, _) = db.create_node(&admin, "default", "new").unwrap();
    let (old, _) = db.create_node(&admin, "default", "old").unwrap();
    let (fresh, _) = db.create_node(&admin, "default", "fresh").unwrap();
    for (node, port) in [(&new, 21000), (&old, 22000), (&fresh, 23000)] {
        forwarding(&db, &admin, &node.id, "gw.example.net", port, port + 9);
    }
    // This controller always says it takes reports, and sends tasks to no one yet.
    let reply = sync(&db, &old.id, None);
    assert!(reply.speed_test && reply.speed_test_tasks.is_empty());
    let reply = sync(&db, &new.id, Some(Report::default()));
    assert!(reply.speed_test && reply.speed_test_tasks.is_empty());
    let nodes = db.nodes(&admin).unwrap();
    let support = |id: &str| {
        nodes
            .iter()
            .find(|n| n.id == id)
            .unwrap()
            .speed_test_support
    };
    assert!(support(&new.id) && !support(&old.id) && !support(&fresh.id));

    // Old agents and servers that never connected are named with the reason.
    let (code, message) =
        status(db.start_speed_test(&admin, server_input(Mode::Server, &new.id, Some(&old.id))));
    assert_eq!(code, 409);
    assert_eq!(
        message,
        "the agent on server old is too old for speed tests; upgrade it first"
    );
    let (code, message) =
        status(db.start_speed_test(&admin, server_input(Mode::Cloudflare, &old.id, None)));
    assert_eq!((code, message.contains("upgrade it first")), (409, true));
    let (code, message) =
        status(db.start_speed_test(&admin, server_input(Mode::Server, &fresh.id, Some(&new.id))));
    assert_eq!(code, 409);
    assert!(
        message.contains("has not connected to the panel yet"),
        "{message}"
    );

    // Parameters are checked before anything else.
    for bad in [
        json!({"mode": "cloudflare", "node_id": new.id, "direction": "both", "duration_secs": 4}),
        json!({"mode": "cloudflare", "node_id": new.id, "direction": "both", "duration_secs": 61}),
        json!({"mode": "cloudflare", "node_id": new.id, "direction": "up", "streams": 9}),
        json!({"mode": "cloudflare", "node_id": new.id, "direction": "both", "streams": 9}),
        json!({"mode": "cloudflare", "node_id": new.id, "direction": "both", "bytes": 10}),
        json!({"mode": "cloudflare", "node_id": new.id, "direction": "both", "bytes": 2_000_000, "duration_secs": 5}),
        json!({"mode": "cloudflare", "node_id": new.id, "peer_node_id": old.id, "direction": "both"}),
        json!({"mode": "server", "node_id": new.id, "direction": "both"}),
        json!({"mode": "server", "node_id": new.id, "peer_node_id": new.id, "direction": "both"}),
    ] {
        let parsed = serde_json::from_value::<ServerTestInput>(bad.clone());
        if let Ok(input) = parsed {
            assert_eq!(status(db.start_speed_test(&admin, input)).0, 400, "{bad}");
        }
    }

    // A test of a supporting server goes to that agent only, and once it
    // runs the server is busy.
    let started = db
        .start_speed_test(&admin, server_input(Mode::Cloudflare, &new.id, None))
        .unwrap();
    let tasks = sync(&db, &new.id, Some(Report::default())).speed_test_tasks;
    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0].role, TaskRole::Cloudflare);
    assert!(tasks[0].address.is_none() && tasks[0].token.is_none());
    assert!(sync(&db, &old.id, None).speed_test_tasks.is_empty());
    let (code, message) =
        status(db.start_speed_test(&admin, server_input(Mode::Cloudflare, &new.id, None)));
    assert_eq!(
        (code, message.as_str()),
        (409, "server new is already running a speed test")
    );
    // A report of the result ends it, and the task is no longer sent.
    let mut done = relay_platform::speed_test::TaskReport::new(&tasks[0].id);
    done.state = TaskState::Finished;
    sync(&db, &new.id, Some(Report { tasks: vec![done] }));
    let view = db.speed_test(&admin, &started.job.id).unwrap();
    assert_eq!(serde_json::to_value(&view).unwrap()["state"], "finished");
    assert!(
        sync(&db, &new.id, Some(Report::default()))
            .speed_test_tasks
            .is_empty()
    );

    // Reports are bounded like every other part of a sync.
    let mut flood = Report::default();
    for index in 0..9 {
        flood
            .tasks
            .push(relay_platform::speed_test::TaskReport::new(&format!(
                "t{index}"
            )));
    }
    let request = SyncRequest {
        logs: None,
        lease: None,
        budget: None,
        ledger_id: ledger(&db, &new.id),
        need_config: false,
        applied_revision: 0,
        apply_error: None,
        usage: vec![],
        stats: EngineStats {
            speed_test: Some(flood),
            ..EngineStats::default()
        },
    };
    assert_eq!(status(db.sync(&new.id, request)).0, 400);

    // Compatibility in both directions: a new agent's stats without the
    // report carry no new key for a 0.147.0 controller, and a reply from
    // one parses as no tasks and no reporting.
    let stats = serde_json::to_value(EngineStats::default()).unwrap();
    assert!(stats.get("speed_test").is_none());
    let old_reply: SyncResponse = serde_json::from_value(json!({
        "budget": null, "controller_instance": "x", "config": null,
        "acknowledgements": [], "server_time_ms": 1, "rate_limits": true,
    }))
    .unwrap();
    assert!(!old_reply.speed_test && old_reply.speed_test_tasks.is_empty());
    let reply = serde_json::to_value(sync(&db, &old.id, None)).unwrap();
    assert!(
        reply.get("speed_test_tasks").is_none(),
        "omitted when empty"
    );
}

#[test]
fn the_test_port_is_free_and_reached_through_the_nat_mapping() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("controller.db")).unwrap();
    db.set_kind("controller").unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let (a, _) = db.create_node(&admin, "default", "a").unwrap();
    let (b, _) = db.create_node(&admin, "default", "b").unwrap();
    let (c, _) = db.create_node(&admin, "default", "c").unwrap();
    for node in [&a, &b, &c] {
        sync(&db, &node.id, Some(Report::default()));
    }
    // b's local ports 20000–20009 appear as 40000–40009 at gw.example.net,
    // and a rule holds the top of the range.
    forwarding(&db, &admin, &a.id, "a.example.net", 20000, 20009);
    let node = db
        .nodes(&admin)
        .unwrap()
        .into_iter()
        .find(|n| n.id == b.id)
        .unwrap();
    db.update_node(
        &admin,
        &b.id,
        NodeUpdate {
            expected_revision: node.profile.revision,
            name: node.name.clone(),
            settings: NodeSettings {
                forwarding: Some(ForwardingDefaults {
                    host: "gw.example.net".into(),
                    listen_ip: Some("203.0.113.5".parse().unwrap()),
                    port_start: 20000,
                    port_end: 20009,
                    public_port_start: Some(40000),
                }),
                ..Default::default()
            },
        },
    )
    .unwrap();
    let config = db.config(&admin, &b.id, None).unwrap();
    let mut held = rule("192.0.2.50:80".parse().unwrap(), Protocol::Tcp);
    held.listen = "0.0.0.0:20008".parse().unwrap();
    held.listen_end_port = Some(20009);
    held.owner_id = admin.id.clone();
    db.set_config(&admin, &b.id, config.revision, vec![held])
        .unwrap();

    let job = db
        .start_speed_test(&admin, server_input(Mode::Server, &a.id, Some(&b.id)))
        .unwrap()
        .job;
    assert_eq!(job.port, Some(20007));
    let segment = &job.segments[0];
    assert_eq!(segment.listen, Some("203.0.113.5:20007".parse().unwrap()));
    assert_eq!(segment.address, "gw.example.net:40007");
    let tasks = sync(&db, &b.id, Some(Report::default())).speed_test_tasks;
    assert_eq!(tasks.len(), 1);
    assert_eq!(tasks[0].role, TaskRole::Listen);
    assert_eq!(tasks[0].listen, segment.listen);
    let dial = sync(&db, &a.id, Some(Report::default())).speed_test_tasks;
    assert_eq!(dial[0].role, TaskRole::Dial);
    assert_eq!(dial[0].address.as_deref(), Some("gw.example.net:40007"));
    // Both ends get the same random token; it is never shown or audited.
    let token = tasks[0].token.clone().unwrap();
    assert_eq!(dial[0].token.as_deref(), Some(token.as_str()));
    assert_eq!(token.len(), 64);
    let shown = serde_json::to_string(&db.speed_tests(&admin).unwrap()).unwrap();
    assert!(!shown.contains(&token));
    db.cancel_speed_test(&admin, &job.id).unwrap();
    let audit = serde_json::to_string(&db.audit_log(&admin).unwrap()).unwrap();
    assert!(audit.contains("speed_test.start") && audit.contains("speed_test.cancel"));
    assert!(!audit.contains(&token));
    assert!(
        sync(&db, &b.id, Some(Report::default()))
            .speed_test_tasks
            .is_empty()
    );
    assert!(
        db.metadata(&format!("speed_test_token:{}", job.id))
            .unwrap()
            .is_none()
    );

    // A port the administrator picks must be free too.
    let mut input = server_input(Mode::Server, &a.id, Some(&b.id));
    input.port = Some(20009);
    assert_eq!(status(db.start_speed_test(&admin, input)).0, 409);
    let mut input = server_input(Mode::Server, &a.id, Some(&b.id));
    input.port = Some(80);
    assert_eq!(status(db.start_speed_test(&admin, input)).0, 400);
    // Without a forwarding host at either end there is nowhere to dial.
    let (code, message) =
        status(db.start_speed_test(&admin, server_input(Mode::Server, &c.id, Some(&a.id))));
    assert_eq!(code, 409);
    assert!(
        message.contains("server c has no forwarding host"),
        "{message}"
    );
}

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
async fn login(client: &reqwest::Client, origin: &str, username: &str) -> String {
    let body: Value = client
        .post(format!("{origin}/api/v1/auth/login"))
        .json(&json!({"username": username, "password": PASSWORD}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    body["token"].as_str().unwrap().to_string()
}
struct Api {
    client: reqwest::Client,
    origin: String,
}
impl Api {
    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        token: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let request = self
            .client
            .request(method, format!("{}/api/v1{path}", self.origin))
            .bearer_auth(token);
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
    async fn get(&self, path: &str, token: &str) -> Value {
        let (code, body) = self.call(reqwest::Method::GET, path, token, None).await;
        assert_eq!(code, 200, "{path}: {body}");
        body
    }
    /// Waits until the test ends; generous, as debug builds are slow.
    async fn finished(&self, token: &str, id: &str) -> Value {
        let until = Instant::now() + Duration::from_secs(120);
        loop {
            let view = self.get(&format!("/speed-tests/{id}"), token).await;
            if view["state"] != "running" {
                return view;
            }
            assert!(Instant::now() < until, "the test never ended: {view}");
            sleep(Duration::from_millis(200)).await;
        }
    }
    async fn wait_support(&self, token: &str, nodes: &[&str]) {
        let until = Instant::now() + Duration::from_secs(30);
        loop {
            let listed = self.get("/nodes", token).await;
            if nodes.iter().all(|id| {
                listed
                    .as_array()
                    .unwrap()
                    .iter()
                    .any(|n| n["id"] == *id && n["speed_test_support"] == true)
            }) {
                return;
            }
            assert!(Instant::now() < until, "agents never reported support");
            sleep(Duration::from_millis(100)).await;
        }
    }
}

fn agent_options(origin: &str, node: &str, token: &Path) -> AgentOptions {
    AgentOptions {
        controller: origin.into(),
        node_id: node.into(),
        enrollment_token_file: Some(token.into()),
        ca_certificate: None,
        tls_directory: None,
        poll_interval: Duration::from_millis(200),
        controller_addresses: vec![],
        controller_proxy: None,
    }
}
struct Agents(
    Vec<(
        CancellationToken,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    )>,
);
impl Agents {
    async fn start(temp: &Path, origin: &str, nodes: &[(&str, &str)], service: &str) -> Self {
        let mut agents = vec![];
        for (node, enrollment) in nodes {
            let secret = temp.join(format!("{node}.secret"));
            write_secret(&secret, enrollment.as_bytes()).unwrap();
            let db = Store::open(&temp.join(format!("{node}.db"))).unwrap();
            let stop = CancellationToken::new();
            agents.push((
                stop.clone(),
                tokio::spawn(agent::run_with_speed_test_service(
                    db,
                    agent_options(origin, node, &secret),
                    stop,
                    service.to_owned(),
                )),
            ));
        }
        Self(agents)
    }
    async fn stop(self) {
        for (stop, task) in self.0 {
            stop.cancel();
            timeout(Duration::from_secs(15), task)
                .await
                .unwrap()
                .unwrap()
                .unwrap();
        }
    }
}

/// A stand-in for Cloudflare's speed endpoints, counting its requests.
async fn speed_service() -> (String, Arc<AtomicU64>, Arc<AtomicU64>, CancellationToken) {
    use axum::{
        Router,
        extract::{DefaultBodyLimit, Query},
        routing::{get, post},
    };
    let (downloads, uploads) = (Arc::new(AtomicU64::new(0)), Arc::new(AtomicU64::new(0)));
    let (down, up) = (downloads.clone(), uploads.clone());
    let router = Router::new()
        .route(
            "/__down",
            get(move |Query(query): Query<HashMap<String, String>>| {
                let down = down.clone();
                async move {
                    down.fetch_add(1, Ordering::Relaxed);
                    let size: usize = query["bytes"].parse().unwrap();
                    vec![7u8; size.min(25_000_000)]
                }
            }),
        )
        .route(
            "/__up",
            post(move |body: axum::body::Bytes| {
                let up = up.clone();
                async move {
                    up.fetch_add(body.len() as u64, Ordering::Relaxed);
                    "ok"
                }
            }),
        )
        .layer(DefaultBodyLimit::max(16 * 1024 * 1024));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let stop = CancellationToken::new();
    let shutdown = stop.clone();
    tokio::spawn(async move {
        axum::serve(listener, router)
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await
            .unwrap();
    });
    (origin, downloads, uploads, stop)
}

/// Each direction's numbers are plausible for a loopback test.
fn check_results(segment: &Value, directions: &[&str], streams: u64, duration: bool) {
    let results = segment["results"].as_array().unwrap();
    assert_eq!(results.len(), directions.len(), "{segment}");
    for (result, direction) in results.iter().zip(directions) {
        assert_eq!(result["direction"], *direction, "{segment}");
        let (bytes, measured, average, peak) = (
            result["bytes"].as_u64().unwrap(),
            result["measured_ms"].as_u64().unwrap(),
            result["average_bps"].as_u64().unwrap(),
            result["peak_bps"].as_u64().unwrap(),
        );
        assert!(bytes > 0 && average > 0 && peak > 0, "{result}");
        assert!(peak >= average / 2, "{result}");
        if duration {
            // About 5 s after the 2 s warm-up; the window ends with the data.
            assert!((2_000..=5_000).contains(&measured), "{result}");
        } else {
            assert!(measured > 0, "{result}");
        }
        assert_eq!(result["streams"], streams, "{result}");
        assert!(result.get("failed_streams").is_none(), "{result}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_agents_measure_each_other_and_the_public_service_and_stop_when_cancelled() {
    let temp = tempfile::tempdir().unwrap();
    let control = Store::open(&temp.path().join("controller.db")).unwrap();
    control.set_kind("controller").unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    let (address, stop_api) = serve(control.clone()).await;
    let api = Api {
        client: reqwest::Client::builder().no_proxy().build().unwrap(),
        origin: format!("http://{address}"),
    };
    let token = login(&api.client, &api.origin, "admin").await;
    let (a, a_enrollment) = control.create_node(&admin, "default", "alpha").unwrap();
    let (b, b_enrollment) = control.create_node(&admin, "default", "beta").unwrap();
    let (old, _) = control.create_node(&admin, "default", "old").unwrap();
    let (a_port, b_port) = (free_address().port(), free_address().port());
    forwarding(&control, &admin, &a.id, "127.0.0.1", a_port, a_port);
    forwarding(&control, &admin, &b.id, "127.0.0.1", b_port, b_port);
    forwarding(&control, &admin, &old.id, "127.0.0.1", 21000, 21000);
    let (service, downloads, uploads, stop_service) = speed_service().await;
    let agents = Agents::start(
        temp.path(),
        &api.origin,
        &[(&a.id, &a_enrollment), (&b.id, &b_enrollment)],
        &service,
    )
    .await;
    api.wait_support(&token, &[&a.id, &b.id]).await;
    // An agent older than speed tests, still reporting.
    sync(&control, &old.id, None);
    use reqwest::Method;
    let (code, reply) = api
        .call(Method::POST, "/speed-tests", &token, Some(json!({"mode": "server", "node_id": a.id, "peer_node_id": old.id, "direction": "both"})))
        .await;
    assert_eq!(code, 409);
    assert!(
        reply["error"]
            .as_str()
            .unwrap()
            .ends_with("upgrade it first"),
        "{reply}"
    );

    // Server ↔ server, both directions with two streams each.
    let (code, started) = api
        .call(Method::POST, "/speed-tests", &token, Some(json!({"mode": "server", "node_id": a.id, "peer_node_id": b.id, "direction": "both", "duration_secs": 5, "streams": 2})))
        .await;
    assert_eq!(code, 200, "{started}");
    let id = started["id"].as_str().unwrap().to_owned();
    assert_eq!(started["metered"], false);
    assert_eq!(
        started["segments"][0]["address"],
        format!("127.0.0.1:{b_port}")
    );
    // Busy: one test per server at a time.
    let (code, reply) = api
        .call(
            Method::POST,
            "/speed-tests",
            &token,
            Some(json!({"mode": "cloudflare", "node_id": b.id, "direction": "download"})),
        )
        .await;
    assert_eq!(code, 409);
    assert_eq!(
        reply["error"],
        "server beta is already running a speed test"
    );
    // The listener takes only streams that present the test's token.
    let until = Instant::now() + Duration::from_secs(20);
    let mut wrong = loop {
        if let Ok(stream) = TcpStream::connect(("127.0.0.1", b_port)).await {
            break stream;
        }
        assert!(Instant::now() < until, "the listener never opened");
        sleep(Duration::from_millis(50)).await;
    };
    let header = relay_platform::speed_test::header(
        &[0x11; 32],
        relay_platform::speed_test::Direction::Download,
        0,
    )
    .to_vec();
    wrong.write_all(&header).await.unwrap();
    let mut buffer = [0u8; 1024];
    let read = timeout(Duration::from_secs(10), wrong.read(&mut buffer))
        .await
        .unwrap();
    assert!(
        matches!(read, Ok(0) | Err(_)),
        "a wrong token got data: {read:?}"
    );
    let mut garbage = TcpStream::connect(("127.0.0.1", b_port)).await.unwrap();
    garbage.write_all(b"GET / HTTP/1.1\r\n\r\n").await.unwrap();
    let read = timeout(Duration::from_secs(10), garbage.read(&mut buffer))
        .await
        .unwrap();
    assert!(matches!(read, Ok(0) | Err(_)), "{read:?}");
    // Live progress while it runs.
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        let view = api.get(&format!("/speed-tests/{id}"), &token).await;
        if view["progress"]["bytes"].as_u64().is_some_and(|b| b > 0) {
            assert!(view["progress"]["direction"].is_string(), "{view}");
            break;
        }
        assert!(
            Instant::now() < until && view["state"] == "running",
            "no progress: {view}"
        );
        sleep(Duration::from_millis(200)).await;
    }
    let view = api.finished(&token, &id).await;
    assert_eq!(view["state"], "finished", "{view}");
    let segment = &view["segments"][0];
    assert_eq!(segment["state"], "finished", "{view}");
    check_results(segment, &["upload", "download"], 2, true);
    assert!(
        segment["rejected_connections"].as_u64().unwrap() >= 2,
        "{segment}"
    );
    // The listener closed with the test.
    let until = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", b_port)).await.is_ok() {
        assert!(Instant::now() < until, "the test port stayed open");
        sleep(Duration::from_millis(100)).await;
    }

    // Server ↔ the public service, through the test-only stand-in.
    let (code, started) = api
        .call(Method::POST, "/speed-tests", &token, Some(json!({"mode": "cloudflare", "node_id": a.id, "direction": "both", "duration_secs": 5, "streams": 2})))
        .await;
    assert_eq!(code, 200, "{started}");
    assert_eq!(started["segments"][0]["address"], "speed.cloudflare.com");
    let view = api.finished(&token, started["id"].as_str().unwrap()).await;
    assert_eq!(view["state"], "finished", "{view}");
    check_results(&view["segments"][0], &["upload", "download"], 2, true);
    assert!(downloads.load(Ordering::Relaxed) > 0 && uploads.load(Ordering::Relaxed) > 0);

    // Cancelling stops both agents at once.
    let (code, started) = api
        .call(Method::POST, "/speed-tests", &token, Some(json!({"mode": "server", "node_id": b.id, "peer_node_id": a.id, "direction": "upload", "duration_secs": 60, "streams": 1})))
        .await;
    assert_eq!(code, 200, "{started}");
    let id = started["id"].as_str().unwrap().to_owned();
    let until = Instant::now() + Duration::from_secs(30);
    loop {
        let view = api.get(&format!("/speed-tests/{id}"), &token).await;
        if view["progress"]["bytes"].as_u64().is_some_and(|b| b > 0) {
            break;
        }
        assert!(Instant::now() < until, "no progress: {view}");
        sleep(Duration::from_millis(200)).await;
    }
    let (code, cancelled) = api
        .call(Method::DELETE, &format!("/speed-tests/{id}"), &token, None)
        .await;
    assert_eq!(code, 200, "{cancelled}");
    assert_eq!(cancelled["state"], "cancelled");
    assert_eq!(cancelled["segments"][0]["state"], "cancelled");
    let (code, _) = api
        .call(Method::DELETE, &format!("/speed-tests/{id}"), &token, None)
        .await;
    assert_eq!(code, 409);
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        let nodes = api.get("/nodes", &token).await;
        let idle = [&a.id, &b.id].iter().all(|id| {
            let node = nodes
                .as_array()
                .unwrap()
                .iter()
                .find(|n| n["id"] == **id)
                .unwrap();
            node["stats"]["speed_test"]["tasks"].is_null()
        });
        let closed = TcpStream::connect(("127.0.0.1", a_port)).await.is_err();
        if idle && closed {
            break;
        }
        assert!(
            Instant::now() < until,
            "a cancelled test kept running: {nodes}"
        );
        sleep(Duration::from_millis(100)).await;
    }

    // History, and an audit trail without tokens.
    let listed = api.get("/speed-tests", &token).await;
    assert_eq!(listed.as_array().unwrap().len(), 3);
    let audit = serde_json::to_string(&api.get("/audit", &token).await).unwrap();
    for action in ["speed_test.start", "speed_test.finish", "speed_test.cancel"] {
        assert!(audit.contains(action), "{action}");
    }
    // Test traffic never passes a rule: nothing is metered.
    assert!(control.rule_usage(&admin).unwrap().is_empty());
    agents.stop().await;
    stop_service.cancel();
    stop_api.cancel();
}

fn hop(
    id: &str,
    listen: SocketAddr,
    target: SocketAddr,
    via: Option<(&str, &str)>,
    owner: &str,
) -> Rule {
    let mut rule = rule(target, Protocol::Tcp);
    rule.id = id.into();
    rule.name = id.into();
    rule.meter_epoch = format!("{id}-epoch");
    rule.owner_id = owner.into();
    rule.listen = listen;
    rule.advertise = Some(listen.to_string());
    rule.rate_bytes_per_sec = Some(125_000);
    rule.targets[0].via = via.map(|(node, rule)| RuleRef {
        node_id: node.into(),
        rule_id: rule.into(),
    });
    rule
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_path_test_measures_every_segment_of_a_two_hop_rule() {
    let temp = tempfile::tempdir().unwrap();
    let control = Store::open(&temp.path().join("controller.db")).unwrap();
    control.set_kind("controller").unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    control
        .create_user(&admin, "default", "operator", PASSWORD, Role::TenantAdmin)
        .unwrap();
    control
        .create_user(&admin, "default", "readonly", PASSWORD, Role::Viewer)
        .unwrap();
    let other = control.create_tenant(&admin, "other").unwrap();
    control
        .create_user(&admin, &other, "neighbour", PASSWORD, Role::TenantAdmin)
        .unwrap();
    let (address, stop_api) = serve(control.clone()).await;
    let api = Api {
        client: reqwest::Client::builder().no_proxy().build().unwrap(),
        origin: format!("http://{address}"),
    };
    let token = login(&api.client, &api.origin, "admin").await;
    let operator = login(&api.client, &api.origin, "operator").await;
    let viewer = login(&api.client, &api.origin, "readonly").await;
    let neighbour = login(&api.client, &api.origin, "neighbour").await;
    let (reader, _) = control
        .create_api_token(&admin, "reader", &[Scope::Read], 1)
        .unwrap();
    let (writer, _) = control
        .create_api_token(&admin, "writer", &[Scope::NodesWrite], 1)
        .unwrap();
    let mut nodes = vec![];
    for name in ["entry", "relay", "exit"] {
        let (node, enrollment) = control.create_node(&admin, "default", name).unwrap();
        let port = free_address().port();
        forwarding(&control, &admin, &node.id, "127.0.0.1", port, port);
        nodes.push((node.id, enrollment, port));
    }
    let echo = tcp_echo().await;
    let listens: Vec<SocketAddr> = (0..3).map(|_| free_address()).collect();
    let rules = [
        hop(
            "entry-rule",
            listens[0],
            listens[1],
            Some((&nodes[1].0, "relay-rule")),
            &admin.id,
        ),
        hop(
            "relay-rule",
            listens[1],
            listens[2],
            Some((&nodes[2].0, "exit-rule")),
            &admin.id,
        ),
        hop("exit-rule", listens[2], echo.address, None, &admin.id),
    ];
    control
        .publish_configs(
            &admin,
            ConfigBatch {
                updates: nodes
                    .iter()
                    .zip(rules)
                    .map(|((node, _, _), rule)| ConfigUpdate {
                        node_id: node.clone(),
                        expected_revision: 0,
                        rules: vec![rule],
                        rate_bytes_per_sec: None,
                        rate_limits: None,
                    })
                    .collect(),
            },
        )
        .unwrap();
    let agents = Agents::start(
        temp.path(),
        &api.origin,
        &nodes
            .iter()
            .map(|(id, enrollment, _)| (id.as_str(), enrollment.as_str()))
            .collect::<Vec<_>>(),
        "http://127.0.0.1:9",
    )
    .await;
    let ids: Vec<&str> = nodes.iter().map(|(id, _, _)| id.as_str()).collect();
    api.wait_support(&token, &ids).await;
    use reqwest::Method;

    // The plan: two segments, the exit's target, and every limit on the way.
    let query = format!("/speed-tests/path?node_id={}&rule_id=entry-rule", ids[0]);
    let plan = api.get(&query, &operator).await;
    assert!(plan["reason"].is_null(), "{plan}");
    assert_eq!(plan["metered"], false);
    assert_eq!(plan["hops"].as_array().unwrap().len(), 3);
    assert_eq!(plan["segments"].as_array().unwrap().len(), 2);
    assert_eq!(plan["segments"][0]["to_node_id"], ids[1]);
    assert_eq!(plan["segments"][1]["from_node_id"], ids[1]);
    assert_eq!(plan["target"]["address"], echo.address.to_string());
    let limits = plan["limits"].as_array().unwrap();
    assert_eq!(limits.len(), 6, "{plan}");
    assert!(
        limits
            .iter()
            .filter(|l| l["kind"] == "rule")
            .all(|l| l["rate_bytes_per_sec"] == 125_000)
    );
    // Others may not: other tenants do not see the rule, read-only roles
    // and tokens without nodes:write may not start it, and server tests
    // are for system administrators.
    assert_eq!(api.call(Method::GET, &query, &neighbour, None).await.0, 404);
    let body = json!({"node_id": ids[0], "rule_id": "entry-rule", "direction": "upload", "bytes": 20_000_000, "streams": 2});
    assert_eq!(
        api.call(
            Method::POST,
            "/speed-tests/path",
            &viewer,
            Some(body.clone())
        )
        .await
        .0,
        403
    );
    assert_eq!(
        api.call(
            Method::POST,
            "/speed-tests/path",
            &reader,
            Some(body.clone())
        )
        .await
        .0,
        403
    );
    assert_eq!(
        api.call(
            Method::POST,
            "/speed-tests/path",
            &neighbour,
            Some(body.clone())
        )
        .await
        .0,
        404
    );
    let (code, _) = api
        .call(
            Method::POST,
            "/speed-tests",
            &operator,
            Some(json!({"mode": "cloudflare", "node_id": ids[0], "direction": "download"})),
        )
        .await;
    assert_eq!(code, 403);
    let (code, reply) = api
        .call(Method::POST, "/speed-tests/path", &operator, Some(json!({"node_id": ids[0], "rule_id": "entry-rule", "direction": "upload", "streams": 2, "token": "mine"})))
        .await;
    assert_eq!(code, 400, "{reply}");

    // A user who may write every server of the path runs it.
    let (code, started) = api
        .call(
            Method::POST,
            "/speed-tests/path",
            &operator,
            Some(body.clone()),
        )
        .await;
    assert_eq!(code, 200, "{started}");
    let id = started["id"].as_str().unwrap().to_owned();
    assert_eq!(started["kind"], "path");
    assert_eq!(started["segments"].as_array().unwrap().len(), 2);
    // Each segment dials the host its hop's target uses, on the test port.
    assert_eq!(
        started["segments"][0]["address"],
        format!("127.0.0.1:{}", nodes[1].2)
    );
    assert_eq!(
        started["segments"][1]["address"],
        format!("127.0.0.1:{}", nodes[2].2)
    );
    // Once a minute for accounts that are not system administrators.
    let (code, reply) = api
        .call(
            Method::POST,
            "/speed-tests/path",
            &operator,
            Some(body.clone()),
        )
        .await;
    assert!(code == 429 || code == 409, "{code} {reply}");
    let view = api.finished(&operator, &id).await;
    assert_eq!(view["state"], "finished", "{view}");
    for segment in view["segments"].as_array().unwrap() {
        assert_eq!(segment["state"], "finished", "{view}");
        check_results(segment, &["upload"], 2, false);
    }
    let slowest = view["slowest_segment"].as_u64().unwrap();
    assert!(slowest < 2);
    assert_eq!(view["target"]["state"], "finished", "{view}");
    assert!(view["target"]["connect_us"].as_u64().unwrap() > 0);
    assert_eq!(view["limits"].as_array().unwrap().len(), 6);
    let (code, reply) = api
        .call(
            Method::POST,
            "/speed-tests/path",
            &operator,
            Some(body.clone()),
        )
        .await;
    assert_eq!(code, 429, "{reply}");
    assert!(
        reply["error"].as_str().unwrap().starts_with("wait "),
        "{reply}"
    );
    // The tenant sees its path tests; other tenants do not.
    assert_eq!(
        api.get("/speed-tests", &viewer)
            .await
            .as_array()
            .unwrap()
            .len(),
        1
    );
    assert!(
        api.get("/speed-tests", &neighbour)
            .await
            .as_array()
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        api.call(Method::GET, &format!("/speed-tests/{id}"), &neighbour, None)
            .await
            .0,
        404
    );
    assert_eq!(
        api.call(Method::DELETE, &format!("/speed-tests/{id}"), &viewer, None)
            .await
            .0,
        403
    );

    // A token with nodes:write may start and stop one too.
    let long = json!({"node_id": ids[0], "rule_id": "entry-rule", "direction": "both", "duration_secs": 60, "streams": 1});
    let (code, started) = api
        .call(Method::POST, "/speed-tests/path", &writer, Some(long))
        .await;
    assert_eq!(code, 200, "{started}");
    let id = started["id"].as_str().unwrap().to_owned();
    let until = Instant::now() + Duration::from_secs(30);
    while TcpStream::connect(("127.0.0.1", nodes[1].2)).await.is_err() {
        assert!(Instant::now() < until, "the first segment never started");
        sleep(Duration::from_millis(100)).await;
    }
    assert_eq!(
        api.call(Method::DELETE, &format!("/speed-tests/{id}"), &writer, None)
            .await
            .0,
        200
    );
    let until = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(("127.0.0.1", nodes[1].2)).await.is_ok() {
        assert!(Instant::now() < until, "the cancelled listener stayed open");
        sleep(Duration::from_millis(100)).await;
    }

    // Rules that cannot be tested say why.
    let config = control.config(&admin, ids[2], None).unwrap();
    let mut proxy = rule(echo.address, Protocol::Tcp);
    proxy.id = "socks".into();
    proxy.owner_id = admin.id.clone();
    proxy.listen = free_address();
    proxy.targets.clear();
    proxy.inbound_socks5 = Some(serde_json::from_value(json!({})).unwrap());
    let mut rules = config.rules.clone();
    rules.push(proxy);
    control
        .set_config(&admin, ids[2], config.revision, rules)
        .unwrap();
    let plan = api
        .get(
            &format!("/speed-tests/path?node_id={}&rule_id=socks", ids[2]),
            &token,
        )
        .await;
    assert!(
        plan["reason"].as_str().unwrap().contains("no fixed target"),
        "{plan}"
    );
    let (code, reply) = api
        .call(
            Method::POST,
            "/speed-tests/path",
            &token,
            Some(json!({"node_id": ids[2], "rule_id": "socks", "direction": "upload"})),
        )
        .await;
    assert_eq!(code, 409, "{reply}");
    assert_eq!(
        api.call(
            Method::GET,
            &format!("/speed-tests/path?node_id={}&rule_id=missing", ids[2]),
            &token,
            None
        )
        .await
        .0,
        404
    );

    // Nothing reached the rules: no usage, no forwarded bytes.
    sleep(Duration::from_millis(500)).await;
    assert!(
        control
            .rule_usage(&admin)
            .unwrap()
            .iter()
            .all(|u| u.upload_bytes == 0 && u.download_bytes == 0)
    );
    for node in api.get("/nodes", &token).await.as_array().unwrap() {
        assert_eq!(node["stats"]["forwarded_upload_bytes"], 0, "{node}");
        assert_eq!(node["stats"]["forwarded_download_bytes"], 0, "{node}");
    }
    agents.stop().await;
    stop_api.cancel();
}

#[test]
fn inputs_reject_unknown_fields() {
    assert!(
        serde_json::from_value::<PathTestInput>(
            json!({"node_id": "a", "rule_id": "b", "direction": "upload", "url": "http://x"})
        )
        .is_err()
    );
    assert!(serde_json::from_value::<ServerTestInput>(json!({"mode": "cloudflare", "node_id": "a", "direction": "upload", "url": "http://10.0.0.1/"})).is_err());
    let input: ServerTestInput =
        serde_json::from_value(json!({"mode": "cloudflare", "node_id": "a", "direction": "both"}))
            .unwrap();
    assert_eq!((input.streams, input.direction), (4, Directions::Both));
}
