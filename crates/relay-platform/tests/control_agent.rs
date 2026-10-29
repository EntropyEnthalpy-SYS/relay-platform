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
async fn health_policy_and_observations_roundtrip_http_through_real_managed_agent() {
    let temp = tempfile::tempdir().unwrap();
    let mut echo = Some(tcp_echo().await);
    let control = Store::open(&temp.path().join("controller.db")).unwrap();
    control.set_kind("controller").unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    let (node, enrollment) = control
        .create_node(&admin, "default", "health-agent")
        .unwrap();
    let (token, _) = control.login("admin", PASSWORD).unwrap();
    let server_instance = server(control.clone(), "127.0.0.1:0".parse().unwrap()).await;
    let origin = format!("http://{}", server_instance.address);
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let url = format!("{origin}/api/v1/nodes/{}/config", node.id);
    let health_url = format!("{origin}/api/v1/nodes/{}/health", node.id);
    assert_eq!(client.get(&health_url).send().await.unwrap().status(), 401);
    let mut r = rule(echo.as_ref().unwrap().address, Protocol::Tcp);
    r.targets[0].priority = 3;
    r.targets[0].max_sessions = Some(4);
    r.health_check = Some(serde_json::from_value(json!({
        "interval_ms":100, "timeout_ms":60, "healthy_threshold":2,
        "unhealthy_threshold":2, "recovery_delay_ms":250, "max_age_ms":1000,
        "tcp":{"kind":"exchange","request_base64":"UElORw==","expected_base64":"UElORw==","half_close":true}
    })).unwrap());
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
    assert_eq!(
        serde_json::to_value(&published.rules[0].health_check).unwrap(),
        serde_json::to_value(&r.health_check).unwrap()
    );
    assert_eq!(published.rules[0].targets[0].priority, 3);
    let mut bad = r.clone();
    bad.health_check.as_mut().unwrap().timeout_ms = 101;
    assert_eq!(
        client
            .put(&url)
            .bearer_auth(&token)
            .json(&json!({"expected_revision":1,"rules":[bad]}))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    let secret_path = temp.path().join("enroll.secret");
    write_secret(&secret_path, enrollment.as_bytes()).unwrap();
    let agent_db = Store::open(&temp.path().join("agent.db")).unwrap();
    let stop = CancellationToken::new();
    let running = tokio::spawn(agent::run(
        agent_db.clone(),
        options(&origin, &node.id, Some(secret_path)),
        stop.clone(),
    ));
    wait_applied(&control, &admin, 1).await;
    for expected in ["healthy", "unhealthy"] {
        timeout(Duration::from_secs(5), async {
            loop {
                let snapshot: Value = client
                    .get(&health_url)
                    .bearer_auth(&token)
                    .send()
                    .await
                    .unwrap()
                    .error_for_status()
                    .unwrap()
                    .json()
                    .await
                    .unwrap();
                if snapshot["reports"][0]["status"] == expected {
                    assert_eq!(snapshot["reports"][0]["probe_kind"], "tcp_exchange");
                    assert_eq!(snapshot["reports"][0]["eligible"], expected == "healthy");
                    assert_eq!(snapshot["reports"][0]["priority"], 3);
                    assert_eq!(snapshot["reports"][0]["max_sessions"], 4);
                    assert_eq!(snapshot["expected_endpoints"], 1);
                    break;
                }
                sleep(Duration::from_millis(20)).await;
            }
        })
        .await
        .unwrap();
        if expected == "healthy" {
            let mut stream = TcpStream::connect(r.listen).await.unwrap();
            stream.write_all(b"health-api").await.unwrap();
            stream.shutdown().await.unwrap();
            let mut reply = Vec::new();
            timeout(Duration::from_secs(2), stream.read_to_end(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(reply, b"health-api");
            wait_usage(&control, &admin, 20).await;
            // Stop the backend while retaining its address for future probes.
            drop(echo.take());
        }
    }
    wait_usage(&control, &admin, 20).await;
    stop.cancel();
    timeout(Duration::from_secs(3), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        agent_db
            .agent_usage(false)
            .unwrap()
            .iter()
            .map(|r| r.upload_bytes + r.download_bytes)
            .sum::<u64>(),
        20
    );
    stop_server(server_instance).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn websocket_configuration_roundtrips_http_and_managed_agent_both_directions() {
    use relay_platform::{engine::Engine, websocket};
    let temp = tempfile::tempdir().unwrap();
    let echo = tcp_echo().await;
    let ws_in = WebSocketServer {
        path: "/managed".into(),
        host: Some("managed.test".into()),
        allowed_origins: vec![],
    };
    let ws_out = WebSocketClient {
        path: "/managed".into(),
        host: "managed.test".into(),
        origin: None,
    };
    let exit = Engine::new(Store::open(&temp.path().join("exit.db")).unwrap());
    let mut end = rule(echo.address, Protocol::Tcp);
    end.inbound_websocket = Some(ws_in.clone());
    let hop = end.listen;
    exit.apply(config(end)).await.unwrap();
    let control = Store::open(&temp.path().join("controller.db")).unwrap();
    control.set_kind("controller").unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    let (node, enrollment) = control
        .create_node(&admin, "default", "websocket-agent")
        .unwrap();
    let (token, _) = control.login("admin", PASSWORD).unwrap();
    let server_instance = server(control.clone(), "127.0.0.1:0".parse().unwrap()).await;
    let origin = format!("http://{}", server_instance.address);
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let url = format!("{origin}/api/v1/nodes/{}/config", node.id);
    let mut r = rule(hop, Protocol::Tcp);
    r.inbound_websocket = Some(ws_in);
    r.targets[0].websocket = Some(ws_out.clone());
    let listen = r.listen;
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
    assert_eq!(published.rules[0].inbound_websocket, r.inbound_websocket);
    assert_eq!(
        published.rules[0].targets[0].websocket,
        r.targets[0].websocket
    );
    let mut bad = r.clone();
    bad.protocol = Protocol::Udp;
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
    assert_eq!(
        serde_json::to_value(retrieved).unwrap(),
        serde_json::to_value(published).unwrap()
    );
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
    let socket = TcpStream::connect(listen).await.unwrap();
    let mut stream = websocket::connect(Box::new(socket), &ws_out, false, Duration::from_secs(2))
        .await
        .unwrap();
    stream.write_all(b"managed-ws").await.unwrap();
    stream.shutdown().await.unwrap();
    let mut reply = vec![];
    timeout(Duration::from_secs(3), stream.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, b"managed-ws");
    wait_usage(&control, &admin, 20).await;
    stop.cancel();
    timeout(Duration::from_secs(3), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert_eq!(
        agent_db.agent_config().unwrap().unwrap().rules[0].inbound_websocket,
        r.inbound_websocket
    );
    exit.shutdown().await.unwrap();
    stop_server(server_instance).await;
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
        accept_prewarmed: false,
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
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_running_agent_takes_its_user_share_and_then_syncs_every_second() {
    let temp = tempfile::tempdir().unwrap();
    let echo = tcp_echo().await;
    let control = Store::open(&temp.path().join("controller.db")).unwrap();
    control.set_kind("controller").unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    let (node, enrollment) = control.create_node(&admin, "default", "limited").unwrap();
    let mut r = rule(echo.address, Protocol::Tcp);
    r.owner_id = admin.id.clone();
    control.set_config(&admin, &node.id, 0, vec![r]).unwrap();
    let server_instance = server(control.clone(), "127.0.0.1:0".parse().unwrap()).await;
    let secret_path = temp.path().join("enroll.secret");
    write_secret(&secret_path, enrollment.as_bytes()).unwrap();
    let agent_db = Store::open(&temp.path().join("agent.db")).unwrap();
    let stop = CancellationToken::new();
    let mut opts = options(
        &format!("http://{}", server_instance.address),
        &node.id,
        Some(secret_path),
    );
    opts.poll_interval = Duration::from_secs(3);
    let running = tokio::spawn(agent::run(agent_db.clone(), opts, stop.clone()));
    wait_applied(&control, &admin, 1).await;
    control
        .set_user_rate(&admin, &admin.id, Some(1 << 20))
        .unwrap();
    let seat = || control.user_rate(&admin, &admin.id).unwrap().nodes[0].clone();
    // The share goes out at the next ordinary poll...
    let until = Instant::now() + Duration::from_secs(5);
    while seat().seen_ms_ago.is_none() {
        assert!(Instant::now() < until, "no share granted");
        sleep(Duration::from_millis(20)).await;
    }
    let granted = Instant::now();
    // ...and from then on the agent syncs every second, reporting it in force.
    while seat().enforced_bytes_per_sec.is_none() {
        assert!(
            granted.elapsed() < Duration::from_secs(2),
            "agent kept its 3 s poll after taking a share"
        );
        sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(seat().enforced_bytes_per_sec, Some(1 << 20));
    let saved = agent_db.metadata("agent_user_shares").unwrap().unwrap();
    assert!(saved.contains(&admin.id), "{saved}");
    stop.cancel();
    timeout(Duration::from_secs(5), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    stop_server(server_instance).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rejected_config_keeps_the_running_user_share_on_a_managed_agent() {
    let temp = tempfile::tempdir().unwrap();
    let echo = tcp_echo().await;
    let control = Store::open(&temp.path().join("controller.db")).unwrap();
    control.set_kind("controller").unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    let other = control
        .create_user(
            &admin,
            "default",
            "other",
            PASSWORD,
            relay_platform::store::Role::Viewer,
        )
        .unwrap();
    let (node, enrollment) = control.create_node(&admin, "default", "fenced").unwrap();
    let mut r = rule(echo.address, Protocol::Tcp);
    r.owner_id = admin.id.clone();
    let listen = r.listen;
    control
        .set_config(&admin, &node.id, 0, vec![r.clone()])
        .unwrap();
    let server_instance = server(control.clone(), "127.0.0.1:0".parse().unwrap()).await;
    let secret_path = temp.path().join("enroll.secret");
    write_secret(&secret_path, enrollment.as_bytes()).unwrap();
    let agent_db = Store::open(&temp.path().join("agent.db")).unwrap();
    let stop = CancellationToken::new();
    let mut opts = options(
        &format!("http://{}", server_instance.address),
        &node.id,
        Some(secret_path),
    );
    opts.poll_interval = Duration::from_millis(50);
    let running = tokio::spawn(agent::run(agent_db.clone(), opts, stop.clone()));
    wait_applied(&control, &admin, 1).await;
    control
        .set_user_rate(&admin, &admin.id, Some(256 << 10))
        .unwrap();
    let seat = || control.user_rate(&admin, &admin.id).unwrap().nodes[0].clone();
    let until = Instant::now() + Duration::from_secs(5);
    while seat().enforced_bytes_per_sec.is_none() {
        assert!(Instant::now() < until, "agent never enforced the share");
        sleep(Duration::from_millis(20)).await;
    }
    assert_eq!(seat().enforced_bytes_per_sec, Some(256 << 10));

    // Revision 2 moves the rule to another owner on an occupied port. The
    // managed agent must keep revision 1 and its share while retrying.
    let blocker = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    r.id = "replacement".into();
    r.owner_id = other.id;
    r.listen = blocker.local_addr().unwrap();
    control.set_config(&admin, &node.id, 1, vec![r]).unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    loop {
        let node = control.nodes(&admin).unwrap().remove(0);
        if node.apply_error.is_some() {
            assert_eq!(node.applied_revision, 1);
            break;
        }
        assert!(Instant::now() < until, "agent did not reject revision 2");
        sleep(Duration::from_millis(20)).await;
    }
    sleep(Duration::from_millis(1200)).await;
    assert_eq!(
        seat().enforced_bytes_per_sec,
        Some(256 << 10),
        "the failed revision's share list removed the running limit"
    );
    assert_eq!(control.nodes(&admin).unwrap()[0].applied_revision, 1);
    assert!(TcpStream::connect(listen).await.is_ok());

    // Releasing the port lets the retry activate and retire the old share.
    drop(blocker);
    wait_applied(&control, &admin, 2).await;
    let until = Instant::now() + Duration::from_secs(3);
    while !control
        .user_rate(&admin, &admin.id)
        .unwrap()
        .nodes
        .is_empty()
    {
        assert!(Instant::now() < until, "old share was not retired");
        sleep(Duration::from_millis(20)).await;
    }
    stop.cancel();
    timeout(Duration::from_secs(5), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    stop_server(server_instance).await;
}

async fn server(db: Store, bind: SocketAddr) -> Server {
    let stop = CancellationToken::new();
    let router = api::router(AppState::new(db).with_shutdown(stop.clone()));
    server_stopped_by(router, bind, stop).await
}
async fn server_with_router(router: axum::Router, bind: SocketAddr) -> Server {
    server_stopped_by(router, bind, CancellationToken::new()).await
}
async fn server_stopped_by(
    router: axum::Router,
    bind: SocketAddr,
    stop: CancellationToken,
) -> Server {
    let listener = TcpListener::bind(bind).await.unwrap();
    let address = listener.local_addr().unwrap();
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
        .json(&json!({"name":"local-e2e-agent","lease_policy":null}))
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
    let page = html.text().await.unwrap();
    assert!(page.contains("id=\"login-form\""));
    assert!(page.contains("id=\"command-dialog\""));
    assert!(page.contains("id=\"language-toggle\""));
    assert!(page.contains("id=\"login-language-toggle\""));
    for asset in ["app.js", "console-ui.js", "i18n.js", "i18n-en.js"] {
        let response = client
            .get(format!("{origin}/assets/{asset}"))
            .send()
            .await
            .unwrap();
        assert_eq!(response.status(), 200);
        assert_eq!(
            response.headers()["content-type"],
            "text/javascript; charset=utf-8"
        );
        assert!(
            response.headers()["content-security-policy"]
                .to_str()
                .unwrap()
                .contains("script-src 'self'")
        );
        assert!(!response.text().await.unwrap().is_empty());
    }
    stop_server(s).await;
}

#[tokio::test]
async fn http_two_factor_login_and_scoped_api_tokens() {
    use relay_platform::totp;
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
    let call = |method: reqwest::Method, path: &str, token: &str, body: Option<Value>| {
        let request = client
            .request(method, format!("{origin}/api/v1{path}"))
            .bearer_auth(token);
        let request = match body {
            Some(body) => request.json(&body),
            None => request,
        };
        async move {
            let response = request.send().await.unwrap();
            let status = response.status().as_u16();
            (
                status,
                response.json::<Value>().await.unwrap_or(Value::Null),
            )
        }
    };
    let login = |username: &str, code: Option<&str>| {
        let body = json!({"username":username,"password":PASSWORD,"second_factor":code});
        let request = client
            .post(format!("{origin}/api/v1/auth/login"))
            .json(&body);
        async move {
            let response = request.send().await.unwrap();
            let status = response.status().as_u16();
            (status, response.json::<Value>().await.unwrap())
        }
    };
    let step = || relay_platform::model::now_ms() as u64 / 1000 / totp::STEP_SECONDS;
    let code_at = |secret: &str, step: u64| {
        format!(
            "{:06}",
            totp::code(&totp::decode_base32(secret).unwrap(), step)
        )
    };
    use reqwest::Method;

    let session = login("admin", None).await.1["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let (status, _) = call(
        Method::POST,
        "/account/mfa/setup",
        &session,
        Some(json!({"password":"not-the-password"})),
    )
    .await;
    assert_eq!(status, 403);
    let (_, setup) = call(
        Method::POST,
        "/account/mfa/setup",
        &session,
        Some(json!({"password":PASSWORD})),
    )
    .await;
    let secret = setup["secret"].as_str().unwrap().to_owned();
    assert!(setup["otpauth_uri"].as_str().unwrap().contains(&secret));
    assert!(setup["qr_svg"].as_str().unwrap().contains("<svg"));
    // A pending secret does not change login until it is confirmed.
    assert_eq!(login("admin", None).await.0, 200);
    let (status, _) = call(
        Method::POST,
        "/account/mfa/enable",
        &session,
        Some(json!({"code":"000000"})),
    )
    .await;
    assert_eq!(status, 400);
    let enabled_step = step();
    let (status, enabled) = call(
        Method::POST,
        "/account/mfa/enable",
        &session,
        Some(json!({"code":code_at(&secret, enabled_step)})),
    )
    .await;
    assert_eq!(status, 200);
    let recovery: Vec<String> = serde_json::from_value(enabled["recovery_codes"].clone()).unwrap();
    assert_eq!(recovery.len(), 8);

    let (status, body) = login("admin", None).await;
    assert_eq!(
        (status, body["second_factor_required"].clone()),
        (401, json!(true))
    );
    let rejected_login = client
        .post(format!("{origin}/api/v1/auth/login"))
        .json(&json!({"username":"admin","password":"wrong-password-12"}))
        .send()
        .await
        .unwrap();
    assert_eq!(rejected_login.status(), 401);
    assert!(
        rejected_login
            .json::<Value>()
            .await
            .unwrap()
            .get("second_factor_required")
            .is_none()
    );
    // The code that enabled the factor, and anything older, cannot be replayed.
    assert_eq!(
        login("admin", Some(&code_at(&secret, enabled_step)))
            .await
            .0,
        401
    );
    assert_eq!(
        login("admin", Some(&code_at(&secret, enabled_step - 1)))
            .await
            .0,
        401
    );
    let next = code_at(&secret, enabled_step + 1);
    assert_eq!(login("admin", Some(&next)).await.0, 200);
    assert_eq!(login("admin", Some(&next)).await.0, 401);
    let spaced = recovery[0].to_uppercase().replace('-', " ");
    assert_eq!(login("admin", Some(&spaced)).await.0, 200);
    assert_eq!(login("admin", Some(&recovery[0])).await.0, 401);
    let (_, status_body) = call(Method::GET, "/account/mfa", &session, None).await;
    assert_eq!(
        status_body,
        json!({"enabled":true,"pending":false,"recovery_codes_remaining":7})
    );
    let (_, users) = call(Method::GET, "/users", &session, None).await;
    let flags: Vec<(String, bool)> = users
        .as_array()
        .unwrap()
        .iter()
        .map(|u| {
            (
                u["username"].as_str().unwrap().into(),
                u["mfa_enabled"].as_bool().unwrap(),
            )
        })
        .collect();
    assert_eq!(
        flags,
        vec![("admin".into(), true), ("viewer".into(), false)]
    );

    // Read-only token: reads succeed, writes and self-extension do not.
    let (status, created) = call(
        Method::POST,
        "/api-tokens",
        &session,
        Some(json!({"name":"monitoring","scopes":["read"],"expires_in_days":30})),
    )
    .await;
    assert_eq!(status, 200);
    let reader = created["token"].as_str().unwrap().to_owned();
    assert!(reader.starts_with("rpat_"));
    assert_eq!(call(Method::GET, "/nodes", &reader, None).await.0, 200);
    let publish = json!({"expected_revision":0,"rules":[]});
    let config_path = format!("/nodes/{}/config", node.id);
    assert_eq!(
        call(Method::PUT, &config_path, &reader, Some(publish.clone()))
            .await
            .0,
        403
    );
    assert_eq!(
        call(
            Method::POST,
            "/api-tokens",
            &reader,
            Some(json!({"name":"escalate","scopes":["nodes:write"],"expires_in_days":30}))
        )
        .await
        .0,
        403
    );
    assert_eq!(
        call(Method::GET, "/account/mfa", &reader, None).await.0,
        403
    );
    assert_eq!(
        call(
            Method::POST,
            "/tenants",
            &reader,
            Some(json!({"name":"other"}))
        )
        .await
        .0,
        403
    );
    let writer = call(
        Method::POST,
        "/api-tokens",
        &session,
        Some(json!({"name":"deploy","scopes":["nodes:write","read"],"expires_in_days":1})),
    )
    .await
    .1;
    let writer_token = writer["token"].as_str().unwrap().to_owned();
    assert_eq!(
        call(
            Method::PUT,
            &config_path,
            &writer_token,
            Some(publish.clone())
        )
        .await
        .0,
        200
    );
    assert_eq!(
        call(Method::POST, "/budgets", &writer_token, Some(json!({})))
            .await
            .0,
        403
    );
    let (_, listed) = call(Method::GET, "/api-tokens", &session, None).await;
    assert_eq!(listed.as_array().unwrap().len(), 2);
    let text = listed.to_string();
    assert!(!text.contains(&reader) && !text.contains(&reader[5..]));
    let reader_id = created["api_token"]["id"].as_str().unwrap();
    assert_eq!(
        call(
            Method::DELETE,
            &format!("/api-tokens/{reader_id}"),
            &session,
            None
        )
        .await
        .0,
        200
    );
    assert_eq!(call(Method::GET, "/nodes", &reader, None).await.0, 401);
    assert_eq!(
        call(Method::GET, "/nodes", &writer_token, None).await.0,
        200
    );

    // A viewer's write-scoped token stays bounded by the viewer role.
    let viewer_session = login("viewer", None).await.1["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let viewer_token = call(
        Method::POST,
        "/api-tokens",
        &viewer_session,
        Some(json!({"name":"viewer","scopes":["read","nodes:write"],"expires_in_days":7})),
    )
    .await
    .1["token"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        call(Method::GET, "/nodes", &viewer_token, None).await.0,
        200
    );
    assert_eq!(
        call(
            Method::PUT,
            &config_path,
            &viewer_token,
            Some(json!({"expected_revision":1,"rules":[]}))
        )
        .await
        .0,
        403
    );
    // The viewer enables a factor and loses the device; the administrator resets it.
    let viewer_secret = call(
        Method::POST,
        "/account/mfa/setup",
        &viewer_session,
        Some(json!({"password":PASSWORD})),
    )
    .await
    .1["secret"]
        .as_str()
        .unwrap()
        .to_owned();
    assert_eq!(
        call(
            Method::POST,
            "/account/mfa/enable",
            &viewer_session,
            Some(json!({"code":code_at(&viewer_secret, step())}))
        )
        .await
        .0,
        200
    );
    assert_eq!(login("viewer", None).await.0, 401);
    assert_eq!(
        call(
            Method::POST,
            &format!("/users/{}/mfa/reset", viewer.id),
            &viewer_session,
            None
        )
        .await
        .0,
        400
    );
    assert_eq!(
        call(
            Method::POST,
            &format!("/users/{}/mfa/reset", admin.id),
            &viewer_session,
            None
        )
        .await
        .0,
        403
    );
    assert_eq!(
        call(
            Method::POST,
            &format!("/users/{}/mfa/reset", viewer.id),
            &writer_token,
            None
        )
        .await
        .0,
        403
    );
    assert_eq!(
        call(
            Method::POST,
            &format!("/users/{}/mfa/reset", viewer.id),
            &session,
            None
        )
        .await
        .0,
        200
    );
    assert_eq!(
        call(Method::GET, "/session", &viewer_session, None).await.0,
        401
    );
    assert_eq!(
        call(Method::GET, "/nodes", &viewer_token, None).await.0,
        401
    );
    assert_eq!(login("viewer", None).await.0, 200);

    // Disabling needs the password and a current factor.
    let (status, _) = call(
        Method::POST,
        "/account/mfa/disable",
        &session,
        Some(json!({"password":PASSWORD,"code":"123456"})),
    )
    .await;
    assert_eq!(status, 403);
    let (status, _) = call(
        Method::POST,
        "/account/mfa/disable",
        &session,
        Some(json!({"password":PASSWORD,"code":recovery[1]})),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(login("admin", None).await.0, 200);
    let audit: Vec<String> = db
        .audit_log(&admin)
        .unwrap()
        .iter()
        .map(|r| r["action"].as_str().unwrap().to_owned())
        .collect();
    for action in [
        "mfa.enable",
        "mfa.recovery_code_used",
        "api_token.create",
        "api_token.revoke",
        "mfa.reset",
        "mfa.disable",
    ] {
        assert!(
            audit.iter().any(|a| a == action),
            "{action} missing from audit"
        );
    }

    // Ten wrong codes lock the account's second factor even for a correct code.
    let locked_secret = call(
        Method::POST,
        "/account/mfa/setup",
        &viewer_session,
        Some(json!({"password":PASSWORD})),
    )
    .await;
    assert_eq!(
        locked_secret.0, 401,
        "the reset ended the old viewer session"
    );
    let viewer_session = login("viewer", None).await.1["token"]
        .as_str()
        .unwrap()
        .to_owned();
    let viewer_secret = call(
        Method::POST,
        "/account/mfa/setup",
        &viewer_session,
        Some(json!({"password":PASSWORD})),
    )
    .await
    .1["secret"]
        .as_str()
        .unwrap()
        .to_owned();
    let start = step();
    call(
        Method::POST,
        "/account/mfa/enable",
        &viewer_session,
        Some(json!({"code":code_at(&viewer_secret, start)})),
    )
    .await;
    for _ in 0..10 {
        assert_eq!(login("viewer", Some("000000")).await.0, 401);
    }
    assert_eq!(
        login("viewer", Some(&code_at(&viewer_secret, start + 1)))
            .await
            .0,
        429
    );
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
    let nodes: Value = client
        .get(format!("{origin}/api/v1/nodes"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut timeouts = 0;
    for node in nodes.as_array().unwrap() {
        let meter = &node["stats"]["meter"];
        assert!(meter["admission_requests"].as_u64().unwrap() > 0);
        assert!(meter["admission_batches"]["samples"].as_u64().unwrap() > 0);
        assert!(meter["admission_batches"]["max_us"].as_u64().unwrap() > 0);
        assert!(meter["budget_wait"]["samples"].as_u64().unwrap() > 0);
        assert_eq!(meter["budget_waiting"], 0);
        assert_eq!(meter["failed_batches"], 0);
        timeouts += meter["budget_timeouts"].as_u64().unwrap();
    }
    assert!(
        timeouts >= 1,
        "the intentional exhausted request must be observable"
    );
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
async fn published_revision_reaches_a_long_polling_agent_without_waiting_for_the_poll() {
    let temp = tempfile::tempdir().unwrap();
    let control = Store::open(&temp.path().join("control.db")).unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    let s = server(control.clone(), "127.0.0.1:0".parse().unwrap()).await;
    let origin = format!("http://{}", s.address);
    let (node, token) = control.create_node(&admin, "default", "watch").unwrap();
    let echo = tcp_echo().await;
    let first = rule(echo.address, Protocol::Tcp);
    control
        .set_config(&admin, &node.id, 0, vec![first.clone()])
        .unwrap();
    let token_path = temp.path().join("enroll.secret");
    write_secret(&token_path, token.as_bytes()).unwrap();
    let local = Store::open(&temp.path().join("agent.db")).unwrap();
    let stop = CancellationToken::new();
    let mut opts = options(&origin, &node.id, Some(token_path));
    opts.poll_interval = Duration::from_secs(300);
    let running = tokio::spawn(agent::run(local.clone(), opts, stop.clone()));
    wait_applied(&control, &admin, 1).await;
    // Let the agent settle into its long poll before publishing.
    sleep(Duration::from_millis(300)).await;
    let mut second = rule(echo.address, Protocol::Tcp);
    second.id = "second".into();
    control
        .set_config(&admin, &node.id, 1, vec![first, second.clone()])
        .unwrap();
    let published = Instant::now();
    wait_listening(second.listen).await;
    wait_applied(&control, &admin, 2).await;
    assert!(published.elapsed() < Duration::from_secs(2));
    assert_eq!(exchange(second.listen, b"pushed").await, b"pushed");
    stop.cancel();
    timeout(Duration::from_secs(3), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    stop_server(s).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn agent_reports_become_telemetry_visible_only_to_the_owning_tenant() {
    let temp = tempfile::tempdir().unwrap();
    let control = Store::open(&temp.path().join("control.db")).unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    let tenant = control.create_tenant(&admin, "separate").unwrap();
    let outsider = control
        .create_user(
            &admin,
            &tenant,
            "outsider",
            PASSWORD,
            relay_platform::store::Role::TenantAdmin,
        )
        .unwrap();
    let s = server(control.clone(), "127.0.0.1:0".parse().unwrap()).await;
    let origin = format!("http://{}", s.address);
    let (node, token) = control.create_node(&admin, "default", "metered").unwrap();
    let echo = tcp_echo().await;
    let forward = rule(echo.address, Protocol::Tcp);
    control
        .set_config(&admin, &node.id, 0, vec![forward.clone()])
        .unwrap();
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
    wait_listening(forward.listen).await;
    let payload = vec![7u8; 50_000];
    assert_eq!(exchange(forward.listen, &payload).await, payload);

    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let get = |token: String| {
        let request = client
            .get(format!("{origin}/api/v1/telemetry"))
            .bearer_auth(token);
        async move { request.send().await.unwrap().json::<Value>().await.unwrap() }
    };
    let (admin_token, _) = control.login(&admin.username, PASSWORD).unwrap();
    let until = Instant::now() + Duration::from_secs(5);
    let latest = loop {
        let body = get(admin_token.clone()).await;
        assert_eq!(body["nodes"][0]["id"], node.id.as_str());
        let latest = body["nodes"][0]["samples"]
            .as_array()
            .and_then(|s| s.last().cloned())
            .unwrap_or(Value::Null);
        // Both directions of the echo; CPU needs two samples and is only
        // measured on Linux. Other platforms report null resource fields but
        // must still expose the tenant-scoped traffic sample.
        let measured = cfg!(target_os = "linux");
        if latest["forwarded_bytes"].as_u64() >= Some(100_000)
            && (!measured || latest["cpu_percent"].is_number())
        {
            break latest;
        }
        assert!(Instant::now() < until, "no telemetry sample: {body}");
        sleep(Duration::from_millis(50)).await;
    };
    #[cfg(target_os = "linux")]
    {
        assert!(latest["rss_bytes"].as_u64() > Some(0));
        assert!(latest["memory_total_bytes"].as_u64() > Some(0));
    }
    #[cfg(not(target_os = "linux"))]
    {
        // `system.rs` has no /proc outside Linux; the sample keeps explicit
        // nulls instead of failing the portable telemetry path.
        assert!(latest["cpu_percent"].is_null());
        assert!(latest["rss_bytes"].is_null());
        assert!(latest["memory_total_bytes"].is_null());
    }

    let (outside_token, _) = control.login(&outsider.username, PASSWORD).unwrap();
    let hidden = get(outside_token).await;
    assert_eq!(hidden["nodes"], json!([]));
    assert_eq!(hidden["events"], json!([]));

    stop.cancel();
    timeout(Duration::from_secs(3), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
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
    let until = Instant::now() + Duration::from_secs(3);
    while local
        .agent_usage(true)
        .unwrap()
        .first()
        .map(|u| u.upload_bytes)
        != Some(13)
    {
        assert!(
            Instant::now() < until,
            "usage never reached the local ledger"
        );
        sleep(Duration::from_millis(20)).await;
    }
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
async fn graceful_shutdown_reports_zero_active_sessions_even_with_no_pending_usage() {
    let temp = tempfile::tempdir().unwrap();
    let control = Store::open(&temp.path().join("control.db")).unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    let s = server(control.clone(), "127.0.0.1:0".parse().unwrap()).await;
    let origin = format!("http://{}", s.address);
    let (node, token) = control
        .create_node(&admin, "default", "final diagnostics")
        .unwrap();
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
    let connection = TcpStream::connect(forwarding).await.unwrap();
    timeout(Duration::from_secs(3), async {
        while control.nodes(&admin).unwrap()[0].stats.active_tcp != 1 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let occupied = TcpListener::bind(free_address()).await.unwrap();
    let mut bad = local.agent_config().unwrap().unwrap().rules.remove(0);
    bad.listen = occupied.local_addr().unwrap();
    control.set_config(&admin, &node.id, 1, vec![bad]).unwrap();
    timeout(Duration::from_secs(3), async {
        while control.nodes(&admin).unwrap()[0].apply_error.is_none() {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    let apply_error = control.nodes(&admin).unwrap()[0].apply_error.clone();
    assert!(local.agent_usage(true).unwrap().is_empty());
    stop.cancel();
    timeout(Duration::from_secs(3), running)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    assert!(control.nodes(&admin).unwrap()[0].stats.business_idle());
    assert!(local.agent_usage(true).unwrap().is_empty());
    assert_eq!(control.nodes(&admin).unwrap()[0].apply_error, apply_error);
    drop(connection);
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

#[path = "common/tls.rs"]
#[allow(dead_code)]
mod topology_tls;

fn topology_batch(configs: &[NodeConfig]) -> relay_platform::topology::ConfigBatch {
    relay_platform::topology::ConfigBatch {
        updates: configs
            .iter()
            .map(|c| relay_platform::topology::ConfigUpdate {
                node_id: c.node_id.clone(),
                expected_revision: c.revision,
                rules: c.rules.clone(),
                rate_bytes_per_sec: None,
            })
            .collect(),
    }
}
fn topology_link(configs: &mut [NodeConfig], order: &[usize], target: SocketAddr, secure: bool) {
    for c in configs.iter_mut() {
        let r = &mut c.rules[0];
        r.inbound_tls = None;
        r.inbound_websocket = None;
        r.inbound_proxy = None;
        r.targets = rule(target, r.protocol).targets;
    }
    for pair in order.windows(2) {
        let (from, to) = (pair[0], pair[1]);
        let via = RuleRef {
            node_id: configs[to].node_id.clone(),
            rule_id: configs[to].rules[0].id.clone(),
        };
        let address = configs[to].rules[0].advertise.clone().unwrap();
        let placement = if secure {
            ProxyPlacement::InsideTls
        } else {
            ProxyPlacement::BeforeTls
        };
        let source = &mut configs[from].rules[0].targets[0];
        source.address = address;
        source.via = Some(via);
        source.proxy_protocol = Some(ProxyOutbound {
            version: ProxyVersion::V2,
            placement,
            checksum: true,
        });
        if secure {
            source.tls = Some(TlsClient {
                server_name: "localhost".into(),
                ca: Some("root".into()),
                identity: Some("client".into()),
            });
            source.websocket = Some(WebSocketClient {
                path: "/topology".into(),
                host: "relay.test".into(),
                origin: None,
            });
        }
        let dest = &mut configs[to].rules[0];
        dest.inbound_proxy = Some(ProxyInbound {
            version: ProxyAccept::V2,
            placement,
            trusted_sources: vec!["127.0.0.0/8".parse().unwrap()],
            max_header_bytes: 4096,
            accept_prewarmed: false,
        });
        if secure {
            dest.inbound_tls = Some(TlsServer {
                identity: "server".into(),
                client_ca: Some("root".into()),
            });
            dest.inbound_websocket = Some(WebSocketServer {
                path: "/topology".into(),
                host: Some("relay.test".into()),
                allowed_origins: vec![],
            });
        }
    }
}
async fn topology_wait(control: &Store, admin: &Actor, configs: &[NodeConfig], idle: bool) {
    timeout(Duration::from_secs(8), async {
        loop {
            let nodes = control.nodes(admin).unwrap();
            if configs.iter().all(|c| {
                nodes.iter().any(|n| {
                    n.id == c.node_id
                        && n.applied_revision == c.revision
                        && n.apply_error.is_none()
                        && (!idle || (n.stats.active_tcp == 0 && n.stats.active_udp == 0))
                })
            }) {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("topology nodes did not converge");
}
async fn three_agent_topology(secure: bool) {
    use relay_platform::topology::BatchResult;
    use tokio::net::UdpSocket;
    let temp = tempfile::tempdir().unwrap();
    let cert = topology_tls::Certificates::new();
    let (echo, _udp) = if secure {
        (tcp_echo().await, None)
    } else {
        let (tcp, udp) = tcp_udp_echo().await;
        (tcp, Some(udp))
    };
    let control = Store::open(&temp.path().join("controller.db")).unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    let server = server(control.clone(), "127.0.0.1:0".parse().unwrap()).await;
    let origin = format!("http://{}", server.address);
    let (token, _) = control.login("admin", PASSWORD).unwrap();
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let mut configs = vec![];
    let mut locals = vec![];
    let mut agents = vec![];
    for index in 0..3 {
        let (node, enrollment) = control
            .create_node(&admin, "default", &format!("topology-{index}"))
            .unwrap();
        let path = temp.path().join(format!("enroll-{index}.secret"));
        write_secret(&path, enrollment.as_bytes()).unwrap();
        let local = Store::open(&temp.path().join(format!("agent-{index}.db"))).unwrap();
        let stop = CancellationToken::new();
        let mut opt = options(&origin, &node.id, Some(path));
        opt.tls_directory = Some(cert.root.clone());
        let task = tokio::spawn(agent::run(local.clone(), opt, stop.clone()));
        agents.push((stop, task));
        locals.push(local);
        let mut r = rule(
            echo.address,
            if secure {
                Protocol::Tcp
            } else {
                Protocol::Both
            },
        );
        r.id = format!("chain-{index}");
        r.advertise = Some(r.listen.to_string());
        configs.push(NodeConfig {
            api_version: 1,
            node_id: node.id,
            revision: 0,
            rules: vec![r],
            rate_bytes_per_sec: None,
        });
    }
    topology_link(&mut configs, &[0, 1, 2], echo.address, secure);
    let input = topology_batch(&configs);
    let preview: BatchResult = client
        .post(format!("{origin}/api/v1/configurations/preview"))
        .bearer_auth(&token)
        .json(&input)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(preview.changes.len(), 3);
    assert!(
        control
            .nodes(&admin)
            .unwrap()
            .iter()
            .all(|n| n.desired_revision == 0)
    );
    let published: BatchResult = client
        .post(format!("{origin}/api/v1/configurations/publish"))
        .bearer_auth(&token)
        .json(&input)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    configs = published.configs;
    topology_wait(&control, &admin, &configs, false).await;
    let first = configs[0].rules[0].listen;
    let payload: Vec<u8> = (0..65573).map(|i| (i % 251) as u8).collect();
    assert_eq!(exchange(first, &payload).await, payload);
    let mut expected = 6 * payload.len() as u64;
    if !secure {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(first).await.unwrap();
        socket.send(&payload[..4096]).await.unwrap();
        let mut reply = vec![0; 8192];
        let n = timeout(Duration::from_secs(3), socket.recv(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply[..n], &payload[..4096]);
        expected += 6 * 4096;
    }
    // An unrelated listener failure is a node apply failure, not an atomic
    // multi-machine rollout. The graph must show desired versus applied state.
    let occupied = TcpListener::bind(free_address()).await.unwrap();
    let mut bad = configs[2].rules.clone();
    let mut extra = rule(echo.address, Protocol::Tcp);
    extra.id = "occupied".into();
    extra.listen = occupied.local_addr().unwrap();
    bad.push(extra);
    let failed: NodeConfig = client
        .put(format!(
            "{origin}/api/v1/nodes/{}/config",
            configs[2].node_id
        ))
        .bearer_auth(&token)
        .json(&json!({"expected_revision":configs[2].revision,"rules":bad}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    timeout(Duration::from_secs(5), async {
        loop {
            let n = control
                .nodes(&admin)
                .unwrap()
                .into_iter()
                .find(|n| n.id == configs[2].node_id)
                .unwrap();
            if n.apply_error.is_some() {
                assert_eq!(n.applied_revision, configs[2].revision);
                assert_eq!(n.desired_revision, failed.revision);
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(exchange(first, b"alive").await, b"alive");
    expected += 6 * 5;
    let restored: NodeConfig = client
        .put(format!(
            "{origin}/api/v1/nodes/{}/config",
            configs[2].node_id
        ))
        .bearer_auth(&token)
        .json(&json!({"expected_revision":failed.revision,"rules":configs[2].rules}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    configs[2] = restored;
    topology_wait(&control, &admin, &configs, false).await;
    let mut held = TcpStream::connect(first).await.unwrap();
    held.write_all(b"held").await.unwrap();
    let mut held_reply = [0; 4];
    held.read_exact(&mut held_reply).await.unwrap();
    assert_eq!(&held_reply, b"held");
    expected += 6 * 4;
    for c in &mut configs {
        c.rules[0].enabled = false;
    }
    configs = control
        .publish_configs(&admin, topology_batch(&configs))
        .unwrap()
        .configs;
    let _ = timeout(Duration::from_secs(3), held.read(&mut [0; 1]))
        .await
        .unwrap();
    topology_wait(&control, &admin, &configs, true).await;
    topology_link(&mut configs, &[2, 1, 0], echo.address, secure);
    for c in &mut configs {
        c.rules[0].enabled = true;
    }
    configs = control
        .publish_configs(&admin, topology_batch(&configs))
        .unwrap()
        .configs;
    topology_wait(&control, &admin, &configs, false).await;
    assert_eq!(
        exchange(configs[2].rules[0].listen, b"reversed").await,
        b"reversed"
    );
    expected += 6 * 8;
    wait_usage(&control, &admin, expected).await;
    let visible: Value = client
        .get(format!("{origin}/api/v1/topology"))
        .bearer_auth(&token)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(visible["graph"]["edges"].as_array().unwrap().len(), 2);
    for (stop, task) in agents {
        stop.cancel();
        timeout(Duration::from_secs(5), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    wait_usage(&control, &admin, expected).await;
    for local in locals {
        assert_eq!(
            local
                .agent_usage(false)
                .unwrap()
                .iter()
                .map(|r| r.upload_bytes + r.download_bytes)
                .sum::<u64>(),
            expected / 3
        );
    }
    stop_server(server).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_real_agents_topology_tcp_udp_and_stopped_direction_change() {
    three_agent_topology(false).await;
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn three_real_agents_topology_mutual_wss_proxy_and_stopped_direction_change() {
    three_agent_topology(true).await;
}
