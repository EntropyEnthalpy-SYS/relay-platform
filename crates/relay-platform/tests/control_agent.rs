mod common;
use common::*;
use relay_platform::{
    agent::{self, AgentOptions, controller_url},
    api::{self, AppState},
    model::*,
    store::{Actor, Store, write_secret},
};
use serde_json::{Value, json};
use std::{net::SocketAddr, path::PathBuf, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    task::JoinHandle,
    time::{Instant, sleep, timeout},
};
use tokio_util::sync::CancellationToken;

struct Server {
    address: SocketAddr,
    stop: CancellationToken,
    task: JoinHandle<()>,
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn proxy_settings_roundtrip_http_and_managed_agent_enforces_them() {
    let temp = tempfile::tempdir().unwrap();
    let control = Store::open(&temp.path().join("controller.db")).unwrap();
    control.set_kind("controller").unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    let (node, enrollment) = control
        .create_node(&admin, "default", "proxy-agent")
        .unwrap();
    let (token, _) = control.login("admin", PASSWORD).unwrap();
    let server_instance = server(control.clone(), "127.0.0.1:0".parse().unwrap()).await;
    let origin = format!("http://{}", server_instance.address);
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut r = rule(backend.local_addr().unwrap(), Protocol::Tcp);
    r.inbound_proxy = Some(ProxyInbound {
        version: ProxyAccept::V1,
        trusted_sources: vec!["127.0.0.0/8".parse().unwrap()],
        placement: ProxyPlacement::BeforeTls,
        max_header_bytes: 4096,
    });
    r.targets[0].proxy_protocol = Some(ProxyOutbound {
        version: ProxyVersion::V2,
        placement: ProxyPlacement::BeforeTls,
        checksum: true,
    });
    r.allow_sources = vec!["198.51.100.7/32".parse().unwrap()];
    let address = r.listen;
    let url = format!("{origin}/api/v1/nodes/{}/config", node.id);
    let published: NodeConfig = client
        .put(&url)
        .bearer_auth(&token)
        .json(&json!({"expected_revision":0,"rules":[r.clone()]}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(published.rules[0].inbound_proxy, r.inbound_proxy);
    assert_eq!(
        published.rules[0].targets[0].proxy_protocol,
        r.targets[0].proxy_protocol
    );
    let mut bad = r.clone();
    bad.inbound_proxy.as_mut().unwrap().trusted_sources.clear();
    assert!(
        !client
            .put(&url)
            .bearer_auth(&token)
            .json(&json!({"expected_revision":1,"rules":[bad]}))
            .send()
            .await
            .unwrap()
            .status()
            .is_success()
    );
    let retrieved: NodeConfig = client
        .get(&url)
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(retrieved.revision, 1);
    assert_eq!(retrieved.rules[0], published.rules[0]);
    let token_path = temp.path().join("enroll.secret");
    write_secret(&token_path, enrollment.as_bytes()).unwrap();
    let agent_db = Store::open(&temp.path().join("agent.db")).unwrap();
    let stop = CancellationToken::new();
    let running = tokio::spawn(agent::run(
        agent_db.clone(),
        options(&origin, &node.id, Some(token_path)),
        stop.clone(),
    ));
    wait_applied(&control, &admin, 1).await;
    let target = tokio::spawn(async move {
        let (mut stream, _) = backend.accept().await.unwrap();
        let mut header = [0; 35];
        stream.read_exact(&mut header).await.unwrap();
        let expected: Vec<u8> =
            b"0d0a0d0a000d0a515549540a21110013c6336407cb007109303901bb030004376c844a"
                .as_chunks::<2>()
                .0
                .iter()
                .map(|pair| u8::from_str_radix(std::str::from_utf8(pair).unwrap(), 16).unwrap())
                .collect();
        assert_eq!(header.as_slice(), expected);
        let mut payload = [0; 8];
        stream.read_exact(&mut payload).await.unwrap();
        assert_eq!(&payload, b"real-api");
        stream.write_all(&payload).await.unwrap();
    });
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream
        .write_all(b"PROXY TCP4 198.51.100.7 203.0.113.9 12345 443\r\nreal-api")
        .await
        .unwrap();
    stream.shutdown().await.unwrap();
    let mut reply = vec![];
    timeout(Duration::from_secs(3), stream.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, b"real-api");
    target.await.unwrap();
    wait_usage(&control, &admin, 16).await;
    stop.cancel();
    timeout(Duration::from_secs(3), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        agent_db.agent_config().unwrap().unwrap().rules[0].inbound_proxy,
        r.inbound_proxy
    );
    stop_server(server_instance).await;
}
async fn server(db: Store, bind: SocketAddr) -> Server {
    server_with_router(api::router(AppState::new(db)), bind).await
}
async fn server_with_router(router: axum::Router, bind: SocketAddr) -> Server {
    let listener = TcpListener::bind(bind).await.unwrap();
    let address = listener.local_addr().unwrap();
    let stop = CancellationToken::new();
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
    Server {
        address,
        stop,
        task,
    }
}
async fn stop_server(server: Server) {
    server.stop.cancel();
    timeout(Duration::from_secs(3), server.task)
        .await
        .unwrap()
        .unwrap();
}
fn options(origin: &str, node: &str, token: Option<PathBuf>) -> AgentOptions {
    AgentOptions {
        controller: origin.into(),
        node_id: node.into(),
        enrollment_token_file: token,
        ca_certificate: None,
        tls_directory: None,
        poll_interval: Duration::from_millis(50),
    }
}
async fn wait_applied(db: &Store, actor: &Actor, revision: u64) {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        if db.nodes(actor).unwrap()[0].applied_revision == revision {
            return;
        }
        assert!(
            Instant::now() < until,
            "agent never acknowledged revision {revision}"
        );
        sleep(Duration::from_millis(20)).await;
    }
}
async fn wait_listening(address: SocketAddr) {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        if TcpStream::connect(address).await.is_ok() {
            return;
        }
        assert!(Instant::now() < until, "cached listener never returned");
        sleep(Duration::from_millis(20)).await;
    }
}
async fn wait_usage(db: &Store, actor: &Actor, total: u64) {
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let records = db.reported_usage(actor).unwrap();
        let actual = records
            .iter()
            .map(|r| r["upload_bytes"].as_u64().unwrap() + r["download_bytes"].as_u64().unwrap())
            .sum::<u64>();
        if actual == total {
            return;
        }
        assert!(
            Instant::now() < until,
            "expected {total} bytes, received {actual}"
        );
        sleep(Duration::from_millis(20)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn api_agent_control_outage_restart_and_reconciliation() {
    let temp = tempfile::tempdir().unwrap();
    let control = Store::open(&temp.path().join("control.db")).unwrap();
    control.set_kind("controller").unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    let server_instance = server(control.clone(), "127.0.0.1:0".parse().unwrap()).await;
    let address = server_instance.address;
    let origin = format!("http://{address}");
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let login: Value = client
        .post(format!("{origin}/api/v1/auth/login"))
        .json(&json!({"username":"admin","password":PASSWORD}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = login["token"].as_str().unwrap();
    let created: Value = client
        .post(format!("{origin}/api/v1/nodes"))
        .bearer_auth(token)
        .json(&json!({"name":"local-e2e-agent"}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let node = created["node"]["id"].as_str().unwrap().to_owned();
    let enrollment = created["enrollment_token"].as_str().unwrap();
    let token_path = temp.path().join("enrollment.secret");
    write_secret(&token_path, enrollment.as_bytes()).unwrap();
    let echo = tcp_echo().await;
    let r = rule(echo.address, Protocol::Tcp);
    let forwarding = r.listen;
    let published: NodeConfig = client
        .put(format!("{origin}/api/v1/nodes/{node}/config"))
        .bearer_auth(token)
        .json(&json!({"expected_revision":0,"rules":[r.clone()]}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(published.revision, 1);
    let agent_path = temp.path().join("agent.db");
    let agent_store = Store::open(&agent_path).unwrap();
    let stop = CancellationToken::new();
    let agent_stop = stop.clone();
    let opts = options(&origin, &node, Some(token_path));
    let running = tokio::spawn(agent::run(agent_store, opts, agent_stop));
    wait_applied(&control, &admin, 1).await;
    assert_eq!(exchange(forwarding, b"online").await, b"online");
    wait_usage(&control, &admin, 12).await;
    stop_server(server_instance).await;
    let malformed = axum::Router::new().route(
        "/api/v1/agent/sync",
        axum::routing::post(|| async { "truncated-json" }),
    );
    let malformed_server = server_with_router(malformed, address).await;
    sleep(Duration::from_millis(180)).await;
    assert!(
        !running.is_finished(),
        "a malformed successful response stopped forwarding"
    );
    assert_eq!(exchange(forwarding, b"body").await, b"body");
    stop_server(malformed_server).await;
    assert_eq!(exchange(forwarding, b"offline").await, b"offline");
    stop.cancel();
    timeout(Duration::from_secs(3), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let restored = Store::open(&agent_path).unwrap();
    assert_eq!(restored.agent_usage(false).unwrap()[0].upload_bytes, 17);
    let stop = CancellationToken::new();
    let running = tokio::spawn(agent::run(
        restored,
        options(&origin, &node, None),
        stop.clone(),
    ));
    wait_listening(forwarding).await;
    assert_eq!(exchange(forwarding, b"restart").await, b"restart");
    let server_instance = server(control.clone(), address).await;
    wait_usage(&control, &admin, 48).await;
    sleep(Duration::from_millis(200)).await;
    wait_usage(&control, &admin, 48).await;
    let mut disabled = r;
    disabled.enabled = false;
    control
        .set_config(&admin, &node, 1, vec![disabled])
        .unwrap();
    wait_applied(&control, &admin, 2).await;
    assert!(TcpStream::connect(forwarding).await.is_err());
    stop.cancel();
    timeout(Duration::from_secs(3), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    stop_server(server_instance).await;
}

#[tokio::test]
async fn http_auth_role_and_schema_enforcement() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("control.db")).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let viewer = db
        .create_user(
            &admin,
            "default",
            "viewer",
            PASSWORD,
            relay_platform::store::Role::Viewer,
        )
        .unwrap();
    let (node, _) = db.create_node(&admin, "default", "node").unwrap();
    let s = server(db.clone(), "127.0.0.1:0".parse().unwrap()).await;
    let origin = format!("http://{}", s.address);
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    assert_eq!(
        client
            .get(format!("{origin}/api/v1/nodes"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let wrong = client
        .post(format!("{origin}/api/v1/auth/login"))
        .json(&json!({"username":"viewer","password":"wrong"}))
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 401);
    let auth: Value = client
        .post(format!("{origin}/api/v1/auth/login"))
        .json(&json!({"username":"viewer","password":PASSWORD}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = auth["token"].as_str().unwrap();
    assert_eq!(
        client
            .put(format!("{origin}/api/v1/nodes/{}/config", node.id))
            .bearer_auth(token)
            .json(&json!({"expected_revision":0,"rules":[]}))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let resp = client
        .get(format!("{origin}/api/v1/nodes"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(resp.status(), 200);
    assert_eq!(resp.headers()["cache-control"], "no-store");
    let text = resp.text().await.unwrap();
    assert!(!text.contains("token_hash"));
    assert!(!text.contains("enrollment_hash"));
    db.revoke_sessions(&admin, &viewer.id).unwrap();
    assert_eq!(
        client
            .get(format!("{origin}/api/v1/session"))
            .bearer_auth(token)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let invalid = client
        .post(format!("{origin}/api/v1/agent/enroll"))
        .json(&json!({"node_id":node.id,"enrollment_token":"bad","shell_command":"never"}))
        .send()
        .await
        .unwrap();
    assert_eq!(invalid.status(), 422);
    let html = client.get(format!("{origin}/")).send().await.unwrap();
    assert!(
        html.headers()["content-security-policy"]
            .to_str()
            .unwrap()
            .contains("script-src 'self'")
    );
    assert!(html.text().await.unwrap().contains("自己的控制台"));
    stop_server(s).await;
}

#[test]
fn remote_controller_requires_https_and_never_embeds_credentials() {
    for value in [
        "http://example.com",
        "https://user:password@example.com",
        "https://example.com/path",
        "https://example.com?secret=x",
        "file:///tmp/controller",
    ] {
        assert!(controller_url(value).is_err(), "accepted {value}");
    }
    for value in [
        "https://example.com",
        "http://127.0.0.1:8080",
        "http://[::1]:8080",
    ] {
        controller_url(value).unwrap();
    }
}

#[tokio::test]
async fn enrollment_recovers_after_the_controller_commits_but_response_is_lost() {
    let temp = tempfile::tempdir().unwrap();
    let control = Store::open(&temp.path().join("controller.db")).unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    let (node, token) = control.create_node(&admin, "default", "recovery").unwrap();
    let echo = tcp_echo().await;
    let r = rule(echo.address, Protocol::Tcp);
    let forwarding = r.listen;
    control.set_config(&admin, &node.id, 0, vec![r]).unwrap();
    let db = control.clone();
    let broken = axum::Router::new().route(
        "/api/v1/agent/enroll",
        axum::routing::post(move |axum::Json(input): axum::Json<api::Enrollment>| {
            let db = db.clone();
            async move {
                db.enroll(&input.node_id, &input.enrollment_token, &input.credential)
                    .unwrap();
                "incomplete-response"
            }
        }),
    );
    let first_server = server_with_router(broken, "127.0.0.1:0".parse().unwrap()).await;
    let address = first_server.address;
    let origin = format!("http://{address}");
    let token_path = temp.path().join("enroll.secret");
    write_secret(&token_path, token.as_bytes()).unwrap();
    let agent_db = Store::open(&temp.path().join("agent.db")).unwrap();
    assert!(
        agent::run(
            agent_db.clone(),
            options(&origin, &node.id, Some(token_path.clone())),
            CancellationToken::new()
        )
        .await
        .is_err()
    );
    let pending: Value =
        serde_json::from_str(&agent_db.metadata("agent_credential").unwrap().unwrap()).unwrap();
    assert!(pending["pending_enrollment_token"].is_string());
    std::fs::remove_file(token_path).unwrap();
    stop_server(first_server).await;
    let second_server = server(control.clone(), address).await;
    let stop = CancellationToken::new();
    let running = tokio::spawn(agent::run(
        agent_db.clone(),
        options(&origin, &node.id, None),
        stop.clone(),
    ));
    wait_applied(&control, &admin, 1).await;
    assert_eq!(exchange(forwarding, b"recovered").await, b"recovered");
    let credential: Value =
        serde_json::from_str(&agent_db.metadata("agent_credential").unwrap().unwrap()).unwrap();
    assert!(credential.get("pending_enrollment_token").is_none());
    stop.cancel();
    timeout(Duration::from_secs(3), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    stop_server(second_server).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn restored_backup_waits_for_controller_and_cannot_spend_confirmed_quota_twice() {
    let temp = tempfile::tempdir().unwrap();
    let control = Store::open(&temp.path().join("control.db")).unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    let (node, token) = control
        .create_node(&admin, "default", "backup recovery")
        .unwrap();
    let s = server(control.clone(), "127.0.0.1:0".parse().unwrap()).await;
    let address = s.address;
    let origin = format!("http://{address}");
    let echo = tcp_echo().await;
    let mut r = rule(echo.address, Protocol::Tcp);
    r.quota_bytes = Some(100);
    let forwarding = r.listen;
    control.set_config(&admin, &node.id, 0, vec![r]).unwrap();
    let token_path = temp.path().join("enrollment.secret");
    write_secret(&token_path, token.as_bytes()).unwrap();
    let local = Store::open(&temp.path().join("live.db")).unwrap();
    let stop = CancellationToken::new();
    let running = tokio::spawn(agent::run(
        local.clone(),
        options(&origin, &node.id, Some(token_path)),
        stop.clone(),
    ));
    wait_applied(&control, &admin, 1).await;
    assert_eq!(exchange(forwarding, b"0123456789").await, b"0123456789");
    wait_usage(&control, &admin, 20).await;
    let until = Instant::now() + Duration::from_secs(3);
    while !local.agent_usage(true).unwrap().is_empty() {
        assert!(Instant::now() < until);
        sleep(Duration::from_millis(10)).await;
    }
    let backup_path = temp.path().join("snapshot.db");
    local.backup(&backup_path).unwrap();
    let payload = vec![0x57; 40];
    assert_eq!(exchange(forwarding, &payload).await, payload);
    wait_usage(&control, &admin, 100).await;
    stop.cancel();
    timeout(Duration::from_secs(3), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    stop_server(s).await;
    let restored = Store::open(&backup_path).unwrap();
    assert_eq!(restored.agent_usage(false).unwrap()[0].upload_bytes, 10);
    assert!(restored.recovery_required().unwrap());
    let stop = CancellationToken::new();
    let recovering = tokio::spawn(agent::run(
        restored.clone(),
        options(&origin, &node.id, None),
        stop.clone(),
    ));
    sleep(Duration::from_millis(200)).await;
    assert!(!recovering.is_finished());
    assert!(
        TcpStream::connect(forwarding).await.is_err(),
        "a restored backup must stay closed while the controller is offline"
    );
    let s = server(control.clone(), address).await;
    wait_listening(forwarding).await;
    assert!(exchange(forwarding, b"must-not-pass").await.is_empty());
    let used = restored.agent_usage(false).unwrap();
    assert_eq!(used[0].upload_bytes + used[0].download_bytes, 100);
    assert!(!restored.recovery_required().unwrap());
    stop.cancel();
    timeout(Duration::from_secs(3), recovering)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    stop_server(s).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn running_agent_republishes_acknowledged_counters_after_controller_restore() {
    let temp = tempfile::tempdir().unwrap();
    let control = Store::open(&temp.path().join("control.db")).unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    let (node, token) = control
        .create_node(&admin, "default", "control restore")
        .unwrap();
    let s = server(control.clone(), "127.0.0.1:0".parse().unwrap()).await;
    let address = s.address;
    let origin = format!("http://{address}");
    let echo = tcp_echo().await;
    let r = rule(echo.address, Protocol::Tcp);
    let forwarding = r.listen;
    control.set_config(&admin, &node.id, 0, vec![r]).unwrap();
    let token_path = temp.path().join("enroll.secret");
    write_secret(&token_path, token.as_bytes()).unwrap();
    let local = Store::open(&temp.path().join("agent.db")).unwrap();
    let stop = CancellationToken::new();
    let running = tokio::spawn(agent::run(
        local.clone(),
        options(&origin, &node.id, Some(token_path)),
        stop.clone(),
    ));
    wait_applied(&control, &admin, 1).await;
    let snapshot = temp.path().join("old-controller.db");
    control.backup(&snapshot).unwrap();
    assert_eq!(
        exchange(forwarding, b"already-confirmed").await,
        b"already-confirmed"
    );
    wait_usage(&control, &admin, 34).await;
    sleep(Duration::from_millis(100)).await;
    assert!(local.agent_usage(true).unwrap().is_empty());
    stop_server(s).await;
    let older = Store::open(&snapshot).unwrap();
    assert!(older.reported_usage(&admin).unwrap().is_empty());
    let s = server(older.clone(), address).await;
    wait_usage(&older, &admin, 34).await;
    assert_eq!(
        exchange(forwarding, b"after-restore").await,
        b"after-restore"
    );
    wait_usage(&older, &admin, 60).await;
    stop.cancel();
    timeout(Duration::from_secs(3), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    stop_server(s).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn interrupted_checkpoint_and_failed_activation_never_reopen_restored_cached_listener() {
    use std::sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    };
    let temp = tempfile::tempdir().unwrap();
    let control_path = temp.path().join("controller.db");
    let control = Store::open(&control_path).unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    let (node, token) = control
        .create_node(&admin, "default", "staged recovery")
        .unwrap();
    let credential = relay_platform::store::secret();
    control.enroll(&node.id, &token, &credential).unwrap();
    let echo = tcp_echo().await;
    let r = rule(echo.address, Protocol::Tcp);
    let old_listener = r.listen;
    let cached = control
        .set_config(&admin, &node.id, 0, vec![r.clone()])
        .unwrap();
    let mut raw = rusqlite::Connection::open(&control_path).unwrap();
    let tx = raw.transaction().unwrap();
    for n in 0..257 {
        let epoch = format!("history-{n:03}");
        tx.execute(
            "INSERT INTO rule_epochs(rule_id,meter_epoch) VALUES(?1,?2)",
            rusqlite::params![r.id, epoch],
        )
        .unwrap();
        tx.execute(
            "INSERT INTO usage VALUES(?1,?2,?3,1,2,3,0)",
            rusqlite::params![node.id, r.id, epoch],
        )
        .unwrap();
    }
    tx.commit().unwrap();
    let blocker = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut next_rule = r;
    next_rule.listen = blocker.local_addr().unwrap();
    let new_listener = next_rule.listen;
    control
        .set_config(&admin, &node.id, 1, vec![next_rule])
        .unwrap();
    let interrupted = Arc::new(AtomicBool::new(true));
    let calls = Arc::new(AtomicUsize::new(0));
    let gate = interrupted.clone();
    let requests = calls.clone();
    let app = api::router(AppState::new(control.clone())).layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let gate = gate.clone();
            let requests = requests.clone();
            async move {
                if request.uri().path() == "/api/v1/agent/reconcile"
                    && requests.fetch_add(1, Ordering::SeqCst) > 0
                    && gate.load(Ordering::SeqCst)
                {
                    return axum::response::IntoResponse::into_response(
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                    );
                }
                next.run(request).await
            }
        },
    ));
    let s = server_with_router(app, "127.0.0.1:0".parse().unwrap()).await;
    let origin = format!("http://{}", s.address);
    let live = Store::open(&temp.path().join("live.db")).unwrap();
    live.save_agent_config(&cached).unwrap();
    live.set_metadata(
        "agent_credential",
        &json!({"controller":format!("{origin}/"),"node_id":node.id,"token":credential})
            .to_string(),
    )
    .unwrap();
    let backup_path = temp.path().join("recovered.db");
    live.backup(&backup_path).unwrap();
    let restored = Store::open(&backup_path).unwrap();
    let stop = CancellationToken::new();
    let running = tokio::spawn(agent::run(
        restored.clone(),
        options(&origin, &node.id, None),
        stop.clone(),
    ));
    let until = Instant::now() + Duration::from_secs(5);
    while calls.load(Ordering::SeqCst) < 3 {
        assert!(Instant::now() < until);
        sleep(Duration::from_millis(20)).await;
    }
    assert!(restored.recovery_required().unwrap());
    assert_eq!(restored.agent_usage(false).unwrap().len(), 256);
    assert!(TcpStream::connect(old_listener).await.is_err());
    interrupted.store(false, Ordering::SeqCst);
    let until = Instant::now() + Duration::from_secs(5);
    while control.nodes(&admin).unwrap()[0].apply_error.is_none() {
        assert!(Instant::now() < until);
        sleep(Duration::from_millis(20)).await;
    }
    assert!(restored.recovery_required().unwrap());
    assert_eq!(restored.agent_usage(false).unwrap().len(), 257);
    assert!(
        TcpStream::connect(old_listener).await.is_err(),
        "a failed new bind must not release a restored old listener"
    );
    drop(blocker);
    wait_applied(&control, &admin, 2).await;
    assert!(!restored.recovery_required().unwrap());
    assert_eq!(exchange(new_listener, b"recovered").await, b"recovered");
    stop.cancel();
    timeout(Duration::from_secs(3), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    stop_server(s).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_real_agents_share_user_quota_refill_without_stream_loss_and_return_idle_reservations()
{
    use relay_platform::budget::{Budget, BudgetOverview};
    let temp = tempfile::tempdir().unwrap();
    let control = Store::open(&temp.path().join("control.db")).unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    let s = server(control.clone(), "127.0.0.1:0".parse().unwrap()).await;
    let origin = format!("http://{}", s.address);
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let (token, _) = control.login("admin", PASSWORD).unwrap();
    let quota = 98_304u64;
    let budget:Budget=client.post(format!("{origin}/api/v1/budgets")).bearer_auth(&token).json(&json!({"scope":"user","scope_id":admin.id,"name":"two-node shared quota","limit_bytes":quota,"quantum_bytes":16384})).send().await.unwrap().error_for_status().unwrap().json().await.unwrap();
    let echo = tcp_echo().await;
    let mut addresses = vec![];
    let mut stops = vec![];
    let mut tasks = vec![];
    for n in 0..2 {
        let (node, enrollment) = control
            .create_node(&admin, "default", &format!("budget-{n}"))
            .unwrap();
        let mut r = rule(echo.address, Protocol::Tcp);
        r.id = format!("budget-rule-{n}");
        r.connect_timeout_ms = 1000;
        addresses.push(r.listen);
        let config = control.set_config(&admin, &node.id, 0, vec![r]).unwrap();
        assert_eq!(config.rules[0].budget_ids, vec![budget.id.clone()]);
        let path = temp.path().join(format!("enroll-{n}.secret"));
        write_secret(&path, enrollment.as_bytes()).unwrap();
        let db = Store::open(&temp.path().join(format!("agent-{n}.db"))).unwrap();
        let stop = CancellationToken::new();
        tasks.push(tokio::spawn(agent::run(
            db,
            options(&origin, &node.id, Some(path)),
            stop.clone(),
        )));
        stops.push(stop);
    }
    for address in &addresses {
        wait_listening(*address).await;
    }
    let payload = vec![0xA7; 24_576];
    let (a, b) = tokio::join!(
        exchange(addresses[0], &payload),
        exchange(addresses[1], &payload)
    );
    assert_eq!(a, payload);
    assert_eq!(b, payload);
    wait_usage(&control, &admin, quota).await;
    let overview: BudgetOverview = client
        .get(format!("{origin}/api/v1/budgets"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(overview.budgets[0].consumed_bytes, quota);
    assert_eq!(overview.budgets[0].committed_bytes, quota);
    assert!(exchange(addresses[0], b"exhausted").await.is_empty());
    let updated: Budget = client
        .put(format!("{origin}/api/v1/budgets/{}", budget.id))
        .bearer_auth(&token)
        .json(&json!({"expected_revision":1,"limit_bytes":quota+20,"quantum_bytes":16384}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(updated.revision, 2);
    assert_eq!(exchange(addresses[1], b"topup").await, b"topup");
    for stop in stops {
        stop.cancel();
    }
    for task in tasks {
        timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    let actual = control.budgets(&admin).unwrap().budgets.remove(0);
    assert_eq!(actual.consumed_bytes, quota + 10);
    assert_eq!(
        actual.committed_bytes,
        quota + 10,
        "idle and stopped agents must return unused reservations"
    );
    wait_usage(&control, &admin, quota + 10).await;
    stop_server(s).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_uses_only_its_reserved_budget_during_outage_and_resumes_when_control_returns() {
    use relay_platform::budget::{BudgetScope, NewBudget};
    use tokio::net::UdpSocket;
    let temp = tempfile::tempdir().unwrap();
    let control = Store::open(&temp.path().join("control.db")).unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    control
        .create_budget(
            &admin,
            NewBudget {
                scope: BudgetScope::User,
                scope_id: admin.id.clone(),
                name: "offline quota".into(),
                limit_bytes: 128,
                quantum_bytes: 64,
            },
        )
        .unwrap();
    let s = server(control.clone(), "127.0.0.1:0".parse().unwrap()).await;
    let address = s.address;
    let origin = format!("http://{address}");
    let (node, token) = control
        .create_node(&admin, "default", "UDP budget")
        .unwrap();
    let echo = udp_echo().await;
    let mut r = rule(echo.address, Protocol::Udp);
    r.connect_timeout_ms = 200;
    let forwarding = r.listen;
    control.set_config(&admin, &node.id, 0, vec![r]).unwrap();
    let token_path = temp.path().join("enroll.secret");
    write_secret(&token_path, token.as_bytes()).unwrap();
    let local = Store::open(&temp.path().join("agent.db")).unwrap();
    let stop = CancellationToken::new();
    let running = tokio::spawn(agent::run(
        local.clone(),
        options(&origin, &node.id, Some(token_path)),
        stop.clone(),
    ));
    wait_applied(&control, &admin, 1).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(forwarding).await.unwrap();
    let mut buf = [0; 16];
    socket.send(b"12345678").await.unwrap();
    let n = timeout(Duration::from_secs(2), socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"12345678");
    wait_usage(&control, &admin, 16).await;
    stop_server(s).await;
    for _ in 0..3 {
        socket.send(b"offline!").await.unwrap();
        let n = timeout(Duration::from_secs(2), socket.recv(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], b"offline!");
    }
    socket.send(b"no-more!").await.unwrap();
    assert!(
        timeout(Duration::from_millis(500), socket.recv(&mut buf))
            .await
            .is_err()
    );
    let usage = local.agent_usage(false).unwrap();
    assert_eq!(usage[0].upload_bytes + usage[0].download_bytes, 64);
    let s = server(control.clone(), address).await;
    wait_usage(&control, &admin, 64).await;
    socket.send(b"resumed!").await.unwrap();
    let n = timeout(Duration::from_secs(2), socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"resumed!");
    stop.cancel();
    timeout(Duration::from_secs(3), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let budget = control.budgets(&admin).unwrap().budgets.remove(0);
    assert_eq!(budget.consumed_bytes, 80);
    assert_eq!(budget.committed_bytes, 80);
    stop_server(s).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_larger_than_the_reservation_quantum_preserves_the_whole_datagram() {
    use relay_platform::budget::{BudgetScope, NewBudget};
    use tokio::net::UdpSocket;
    let temp = tempfile::tempdir().unwrap();
    let control = Store::open(&temp.path().join("control.db")).unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    control
        .create_budget(
            &admin,
            NewBudget {
                scope: BudgetScope::User,
                scope_id: admin.id.clone(),
                name: "whole datagrams".into(),
                limit_bytes: 8192,
                quantum_bytes: 64,
            },
        )
        .unwrap();
    let s = server(control.clone(), "127.0.0.1:0".parse().unwrap()).await;
    let origin = format!("http://{}", s.address);
    let (node, token) = control.create_node(&admin, "default", "large UDP").unwrap();
    let echo = udp_echo().await;
    let r = rule(echo.address, Protocol::Udp);
    let forwarding = r.listen;
    control.set_config(&admin, &node.id, 0, vec![r]).unwrap();
    let token_path = temp.path().join("enroll.secret");
    write_secret(&token_path, token.as_bytes()).unwrap();
    let local = Store::open(&temp.path().join("agent.db")).unwrap();
    let stop = CancellationToken::new();
    let running = tokio::spawn(agent::run(
        local.clone(),
        options(&origin, &node.id, Some(token_path)),
        stop.clone(),
    ));
    wait_applied(&control, &admin, 1).await;
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(forwarding).await.unwrap();
    let payload = (0..4096).map(|n| (n % 251) as u8).collect::<Vec<_>>();
    let mut received = vec![0u8; 8192];
    socket.send(&payload).await.unwrap();
    let n = timeout(Duration::from_secs(3), socket.recv(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received[..n], &payload);
    wait_usage(&control, &admin, 8192).await;
    socket.send(b"quota-exhausted").await.unwrap();
    assert!(
        timeout(Duration::from_millis(1200), socket.recv(&mut received))
            .await
            .is_err()
    );
    let usage = local.agent_usage(false).unwrap();
    assert_eq!(
        (usage[0].upload_bytes, usage[0].download_bytes),
        (4096, 4096)
    );
    stop.cancel();
    timeout(Duration::from_secs(3), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let budget = control.budgets(&admin).unwrap().budgets.remove(0);
    assert_eq!(
        (budget.consumed_bytes, budget.committed_bytes),
        (8192, 8192)
    );
    stop_server(s).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn graceful_shutdown_flushes_unbudgeted_usage_before_the_next_heartbeat() {
    let temp = tempfile::tempdir().unwrap();
    let control = Store::open(&temp.path().join("control.db")).unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    let s = server(control.clone(), "127.0.0.1:0".parse().unwrap()).await;
    let origin = format!("http://{}", s.address);
    let (node, token) = control
        .create_node(&admin, "default", "final accounting")
        .unwrap();
    let echo = tcp_echo().await;
    let r = rule(echo.address, Protocol::Tcp);
    let forwarding = r.listen;
    control.set_config(&admin, &node.id, 0, vec![r]).unwrap();
    let token_path = temp.path().join("enroll.secret");
    write_secret(&token_path, token.as_bytes()).unwrap();
    let local = Store::open(&temp.path().join("agent.db")).unwrap();
    let stop = CancellationToken::new();
    let mut opts = options(&origin, &node.id, Some(token_path));
    opts.poll_interval = Duration::from_secs(300);
    let running = tokio::spawn(agent::run(local.clone(), opts, stop.clone()));
    wait_applied(&control, &admin, 1).await;
    assert_eq!(
        exchange(forwarding, b"final-counter").await,
        b"final-counter"
    );
    assert_eq!(local.agent_usage(true).unwrap()[0].upload_bytes, 13);
    assert!(control.reported_usage(&admin).unwrap().is_empty());
    stop.cancel();
    timeout(Duration::from_secs(3), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    wait_usage(&control, &admin, 26).await;
    assert!(local.agent_usage(true).unwrap().is_empty());
    stop_server(s).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn journal_restore_recovers_a_post_backup_node_and_refills_its_live_tcp_session() {
    use relay_platform::{
        budget::{BudgetScope, NewBudget},
        journal::restore_controller,
    };
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    let temp = tempfile::tempdir().unwrap();
    let control = Store::open(&temp.path().join("controller.sqlite")).unwrap();
    let log = temp.path().join("recovery.log");
    control.enable_recovery_log(&log).unwrap();
    control.set_kind("controller").unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    control
        .create_budget(
            &admin,
            NewBudget {
                scope: BudgetScope::User,
                scope_id: admin.id.clone(),
                name: "recoverable quota".into(),
                limit_bytes: 512,
                quantum_bytes: 64,
            },
        )
        .unwrap();
    let backup = temp.path().join("older-than-node.sqlite");
    control.backup(&backup).unwrap();
    let s = server(control.clone(), "127.0.0.1:0".parse().unwrap()).await;
    let address = s.address;
    let origin = format!("http://{address}");
    let (node, token) = control
        .create_node(&admin, "default", "post-backup node")
        .unwrap();
    let echo = tcp_echo().await;
    let r = rule(echo.address, Protocol::Tcp);
    let forwarding = r.listen;
    control.set_config(&admin, &node.id, 0, vec![r]).unwrap();
    let token_path = temp.path().join("enroll.secret");
    write_secret(&token_path, token.as_bytes()).unwrap();
    let local = Store::open(&temp.path().join("agent.sqlite")).unwrap();
    let stop = CancellationToken::new();
    let running = tokio::spawn(agent::run(
        local.clone(),
        options(&origin, &node.id, Some(token_path)),
        stop.clone(),
    ));
    wait_applied(&control, &admin, 1).await;
    let mut stream = TcpStream::connect(forwarding).await.unwrap();
    let mut small = [0; 8];
    stream.write_all(b"before!!").await.unwrap();
    timeout(Duration::from_secs(2), stream.read_exact(&mut small))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&small, b"before!!");
    wait_usage(&control, &admin, 16).await;
    stop_server(s).await;
    drop(control);
    stream.write_all(b"offline!").await.unwrap();
    timeout(Duration::from_secs(2), stream.read_exact(&mut small))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&small, b"offline!");
    let output = temp.path().join("restored");
    let source = backup.clone();
    let journal = log.clone();
    let destination = output.clone();
    let report =
        tokio::task::spawn_blocking(move || restore_controller(&source, &journal, &destination))
            .await
            .unwrap()
            .unwrap();
    assert!(!report.budget_allocation_paused);
    let restored = Store::open(&output.join("controller.sqlite")).unwrap();
    restored
        .enable_recovery_log(&output.join("recovery.log"))
        .unwrap();
    let s = server(restored.clone(), address).await;
    wait_usage(&restored, &admin, 32).await;
    let payload = vec![0x73; 48];
    let mut received = vec![0u8; 48];
    stream.write_all(&payload).await.unwrap();
    timeout(Duration::from_secs(3), stream.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, payload);
    wait_usage(&restored, &admin, 128).await;
    stop.cancel();
    timeout(Duration::from_secs(3), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let budget = restored.budgets(&admin).unwrap().budgets.remove(0);
    assert_eq!((budget.consumed_bytes, budget.committed_bytes), (128, 128));
    stop_server(s).await;
}
