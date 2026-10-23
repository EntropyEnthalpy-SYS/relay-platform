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
