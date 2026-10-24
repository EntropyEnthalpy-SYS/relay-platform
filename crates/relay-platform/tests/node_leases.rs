mod common;
use common::*;
use futures_util::StreamExt;
use relay_platform::{
    agent::{self, AgentOptions},
    api::{self, AppState},
    lease::LeasePolicy,
    model::*,
    store::{Actor, Role, Store, secret, write_secret},
};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc,
        atomic::{AtomicBool, AtomicUsize, Ordering},
    },
    time::Duration,
};
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
impl Drop for Server {
    fn drop(&mut self) {
        self.stop.cancel();
        self.task.abort();
    }
}
async fn server(router: axum::Router, address: SocketAddr) -> Server {
    let listener = TcpListener::bind(address).await.unwrap();
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
async fn stop_server(server: &mut Server) {
    server.stop.cancel();
    timeout(Duration::from_secs(3), &mut server.task)
        .await
        .unwrap()
        .unwrap();
}
struct Agent {
    stop: CancellationToken,
    task: JoinHandle<anyhow::Result<()>>,
}
impl Drop for Agent {
    fn drop(&mut self) {
        self.stop.cancel();
        self.task.abort();
    }
}
fn agent(db: Store, origin: &str, node: &str, enrollment: Option<PathBuf>) -> Agent {
    let stop = CancellationToken::new();
    let options = AgentOptions {
        controller: origin.into(),
        node_id: node.into(),
        enrollment_token_file: enrollment,
        ca_certificate: None,
        tls_directory: None,
        poll_interval: Duration::from_millis(50),
    };
    let task = tokio::spawn(agent::run(db, options, stop.clone()));
    Agent { stop, task }
}
async fn stop_agent(agent: &mut Agent) {
    agent.stop.cancel();
    timeout(Duration::from_secs(4), &mut agent.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
}
async fn until(mut predicate: impl FnMut() -> bool) {
    let deadline = Instant::now() + Duration::from_secs(8);
    while !predicate() {
        assert!(Instant::now() < deadline, "condition did not become true");
        sleep(Duration::from_millis(20)).await;
    }
}
fn total(db: &Store, actor: &Actor) -> u64 {
    db.reported_usage(actor)
        .unwrap()
        .iter()
        .map(|r| r["upload_bytes"].as_u64().unwrap() + r["download_bytes"].as_u64().unwrap())
        .sum()
}
fn strict(db: &Store, admin: &Actor) -> (String, String) {
    let (node, token) = db
        .create_node_with_lease(
            admin,
            "default",
            "strict-test",
            Some(LeasePolicy { ttl_ms: 5000 }),
        )
        .unwrap();
    (node.id, token)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn strict_node_api_defaults_permissions_and_proof_enforcement_are_visible() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("controller.sqlite")).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let (admin_token, _) = db.login("admin", PASSWORD).unwrap();
    let viewer = db
        .create_user(&admin, "default", "viewer", PASSWORD, Role::Viewer)
        .unwrap();
    let (viewer_token, _) = db.login(&viewer.username, PASSWORD).unwrap();
    let mut http = server(
        api::router(AppState::new(db.clone())),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await;
    let origin = format!("http://{}/api/v1", http.address);
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let url = format!("{origin}/nodes");
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(&viewer_token)
            .json(&json!({"name":"forbidden"}))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .post(&url)
            .bearer_auth(&admin_token)
            .json(&json!({"name":"bad-ttl","lease_policy":{"ttl_ms":4999}}))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    let node: Value = client
        .post(&url)
        .bearer_auth(&admin_token)
        .json(&json!({"name":"strict-default"}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(node["node"]["lease"]["policy"]["ttl_ms"], 30000);
    let offline: Value = client
        .post(&url)
        .bearer_auth(&admin_token)
        .json(&json!({"name":"explicit-offline","lease_policy":null}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(offline["node"]["lease"]["policy"].is_null());
    let id = node["node"]["id"].as_str().unwrap();
    let credential = secret();
    db.enroll(id, node["enrollment_token"].as_str().unwrap(), &credential)
        .unwrap();
    let reconcile = format!("{origin}/agent/reconcile");
    let checkpoint = json!({"ledger_id":null,"after":null,"expected_revision":null});
    assert_eq!(
        client
            .post(&reconcile)
            .bearer_auth(&credential)
            .json(&checkpoint)
            .send()
            .await
            .unwrap()
            .status(),
        423
    );
    let lease_url = format!("{origin}/agent/lease");
    let owner = secret();
    let claim = json!({"run_id":"run-one","token":owner,"generation":null});
    assert_eq!(
        client
            .post(&lease_url)
            .bearer_auth(&admin_token)
            .json(&claim)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let granted: Value = client
        .post(&lease_url)
        .bearer_auth(&credential)
        .json(&claim)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(granted["required"], true);
    let proof = json!({"run_id":"run-one","token":owner,"generation":granted["generation"]});
    let mut request = checkpoint.clone();
    request["lease"] = proof.clone();
    let page: Value = client
        .post(&reconcile)
        .bearer_auth(&credential)
        .json(&request)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let mut sync = json!({"lease":proof,"ledger_id":page["ledger_id"],"applied_revision":0,"apply_error":null,"usage":[],"stats":EngineStats::default()});
    assert_eq!(
        client
            .post(format!("{origin}/agent/sync"))
            .bearer_auth(&credential)
            .json(&sync)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    sync["lease"]["token"] = json!(secret());
    sync["stats"]["accepted_tcp"] = json!(900);
    assert_eq!(
        client
            .post(format!("{origin}/agent/sync"))
            .bearer_auth(&credential)
            .json(&sync)
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    let visible: String = client
        .get(&url)
        .bearer_auth(&viewer_token)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();
    assert!(!visible.contains(&owner));
    assert!(!visible.contains("token_hash"));
    assert_eq!(
        db.nodes(&admin)
            .unwrap()
            .iter()
            .find(|n| n.id == id)
            .unwrap()
            .stats
            .accepted_tcp,
        0
    );
    stop_server(&mut http).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn cloned_state_waits_through_renewals_then_reconciles_and_takes_over_after_clean_stop() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("controller.sqlite")).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let (node, enrollment) = strict(&db, &admin);
    db.create_budget(
        &admin,
        relay_platform::budget::NewBudget {
            scope: relay_platform::budget::BudgetScope::User,
            scope_id: admin.id.clone(),
            name: "leased-shared".into(),
            limit_bytes: 4096,
            quantum_bytes: 64,
        },
    )
    .unwrap();
    let token = temp.path().join("enrollment.secret");
    write_secret(&token, enrollment.as_bytes()).unwrap();
    let echo = tcp_echo().await;
    let r = rule(echo.address, Protocol::Tcp);
    let listen = r.listen;
    db.set_config(&admin, &node, 0, vec![r]).unwrap();
    let mut http = server(
        api::router(AppState::new(db.clone())),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await;
    let origin = format!("http://{}", http.address);
    let first = Store::open(&temp.path().join("first.sqlite")).unwrap();
    let mut a = agent(first.clone(), &origin, &node, Some(token));
    until(|| db.nodes(&admin).unwrap()[0].applied_revision == 1).await;
    assert_eq!(exchange(listen, b"before-copy").await, b"before-copy");
    until(|| total(&db, &admin) == 22).await;
    let mut keeper = TcpStream::connect(listen).await.unwrap();
    keeper.write_all(b"k").await.unwrap();
    let mut reply = [0; 1];
    keeper.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"k");
    until(|| total(&db, &admin) == 24).await;
    let clone_path = temp.path().join("copy.sqlite");
    first.backup(&clone_path).unwrap();
    let second = Store::open(&clone_path).unwrap();
    assert_eq!(
        first.metadata("agent_credential").unwrap(),
        second.metadata("agent_credential").unwrap()
    );
    let old_run = first.metadata("agent_budget_run").unwrap().unwrap();
    let mut b = agent(second.clone(), &origin, &node, None);
    let mut expected = 24;
    for _ in 0..12 {
        sleep(Duration::from_millis(500)).await;
        assert!(!a.task.is_finished() && !b.task.is_finished());
        assert_eq!(
            db.nodes(&admin).unwrap()[0].lease.holder_run_id.as_deref(),
            Some(old_run.as_str())
        );
        assert_eq!(exchange(listen, b"owner").await, b"owner");
        expected += 10;
    }
    // More than a full TTL elapsed: the original owner's renewal, not a bind
    // conflict, is what keeps the copied process outside the control protocol.
    assert!(second.recovery_required().unwrap());
    assert_eq!(
        second.metadata("agent_budget_run").unwrap().as_deref(),
        Some(old_run.as_str())
    );
    assert_eq!(
        second
            .agent_usage(false)
            .unwrap()
            .iter()
            .map(|u| u.upload_bytes + u.download_bytes)
            .sum::<u64>(),
        24
    );
    stop_agent(&mut a).await;
    until(|| {
        let n = &db.nodes(&admin).unwrap()[0];
        n.lease.active
            && n.lease.holder_run_id.as_deref() != Some(old_run.as_str())
            && n.applied_revision == 1
    })
    .await;
    assert_eq!(exchange(listen, b"replacement").await, b"replacement");
    expected += 22;
    until(|| total(&db, &admin) == expected).await;
    stop_agent(&mut b).await;
    assert_eq!(total(&db, &admin), expected);
    let budget = &db.budgets(&admin).unwrap().budgets[0];
    assert_eq!(budget.consumed_bytes, expected);
    assert_eq!(budget.committed_bytes, expected);
    assert_eq!(
        second
            .agent_usage(false)
            .unwrap()
            .iter()
            .map(|u| u.upload_bytes + u.download_bytes)
            .sum::<u64>(),
        expected
    );
    let final_node = &db.nodes(&admin).unwrap()[0];
    assert!(!final_node.lease.active);
    assert_eq!(final_node.lease.generation, 2);
    assert!(final_node.stats.business_idle());
    stop_server(&mut http).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn stalled_renewal_response_cannot_extend_tcp_or_udp_deadline() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("controller.sqlite")).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let (node, enrollment) = strict(&db, &admin);
    let token = temp.path().join("enrollment.secret");
    write_secret(&token, enrollment.as_bytes()).unwrap();
    let echo = tcp_echo().await;
    let _udp_echo = udp_echo_at(&echo.address.to_string()).await;
    let r = rule(echo.address, Protocol::Both);
    let listen = r.listen;
    db.set_config(&admin, &node, 0, vec![r]).unwrap();
    let hang = Arc::new(AtomicBool::new(false));
    let stalled = Arc::new(AtomicUsize::new(0));
    let gate = hang.clone();
    let counter = stalled.clone();
    let router = api::router(AppState::new(db.clone())).layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let gate = gate.clone();
            let counter = counter.clone();
            async move {
                if request.uri().path() == "/api/v1/agent/lease" && gate.load(Ordering::SeqCst) {
                    counter.fetch_add(1, Ordering::SeqCst);
                    let stream = futures_util::stream::once(async {
                        Ok::<_, std::io::Error>(axum::body::Bytes::from_static(b"{"))
                    })
                    .chain(futures_util::stream::pending());
                    axum::response::Response::new(axum::body::Body::from_stream(stream))
                } else {
                    next.run(request).await
                }
            }
        },
    ));
    let mut http = server(router, "127.0.0.1:0".parse().unwrap()).await;
    let origin = format!("http://{}", http.address);
    let local = Store::open(&temp.path().join("agent.sqlite")).unwrap();
    let mut a = agent(local, &origin, &node, Some(token));
    until(|| db.nodes(&admin).unwrap()[0].applied_revision == 1).await;
    let mut stream = TcpStream::connect(listen).await.unwrap();
    stream.write_all(b"live").await.unwrap();
    let mut bytes = [0; 4];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"live");
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp.send_to(b"live", listen).await.unwrap();
    let mut packet = [0; 32];
    assert_eq!(
        timeout(Duration::from_secs(1), udp.recv_from(&mut packet))
            .await
            .unwrap()
            .unwrap()
            .0,
        4
    );
    hang.store(true, Ordering::SeqCst);
    let began = Instant::now();
    let result = timeout(Duration::from_secs(7), &mut a.task)
        .await
        .unwrap()
        .unwrap();
    assert!(result.unwrap_err().to_string().contains("execution lease"));
    assert!(began.elapsed() < Duration::from_secs(6));
    assert!(stalled.load(Ordering::SeqCst) > 0);
    assert!(TcpStream::connect(listen).await.is_err());
    udp.send_to(b"after", listen).await.unwrap();
    let reply = timeout(Duration::from_millis(150), udp.recv_from(&mut packet)).await;
    assert!(!matches!(reply, Ok(Ok(_))));
    let mut remaining = vec![];
    let ended = timeout(Duration::from_secs(1), stream.read_to_end(&mut remaining))
        .await
        .unwrap();
    assert!(ended.is_err() || remaining.is_empty());
    assert!(db.nodes(&admin).unwrap()[0].stats.business_idle());
    stop_server(&mut http).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn strict_offline_restart_keeps_cached_listeners_closed_until_new_ownership() {
    let temp = tempfile::tempdir().unwrap();
    let control_path = temp.path().join("controller.sqlite");
    let db = Store::open(&control_path).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let (node, enrollment) = strict(&db, &admin);
    let token = temp.path().join("enrollment.secret");
    write_secret(&token, enrollment.as_bytes()).unwrap();
    let echo = tcp_echo().await;
    let r = rule(echo.address, Protocol::Tcp);
    let listen = r.listen;
    db.set_config(&admin, &node, 0, vec![r]).unwrap();
    let mut http = server(
        api::router(AppState::new(db.clone())),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await;
    let address = http.address;
    let origin = format!("http://{address}");
    let local = Store::open(&temp.path().join("agent.sqlite")).unwrap();
    let mut a = agent(local.clone(), &origin, &node, Some(token));
    until(|| db.nodes(&admin).unwrap()[0].applied_revision == 1).await;
    assert_eq!(exchange(listen, b"online").await, b"online");
    until(|| total(&db, &admin) == 12).await;
    stop_server(&mut http).await;
    stop_agent(&mut a).await;
    let mut b = agent(local, &origin, &node, None);
    sleep(Duration::from_millis(300)).await;
    assert!(!b.task.is_finished());
    assert!(TcpStream::connect(listen).await.is_err());
    let recovered = Store::open(&control_path).unwrap();
    let began = Instant::now();
    let mut http = server(api::router(AppState::new(recovered.clone())), address).await;
    sleep(Duration::from_millis(1000)).await;
    assert!(TcpStream::connect(listen).await.is_err());
    until(|| {
        let node = &recovered.nodes(&admin).unwrap()[0];
        node.lease.generation == 2 && node.applied_revision == 1
    })
    .await;
    assert!(began.elapsed() >= Duration::from_millis(4900));
    assert_eq!(exchange(listen, b"resumed").await, b"resumed");
    stop_agent(&mut b).await;
    assert_eq!(total(&recovered, &admin), 26);
    stop_server(&mut http).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn aborting_agent_task_closes_data_plane_without_releasing_ownership_early() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("controller.sqlite")).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let (node, enrollment) = strict(&db, &admin);
    let token = temp.path().join("enrollment.secret");
    write_secret(&token, enrollment.as_bytes()).unwrap();
    let echo = tcp_echo().await;
    let r = rule(echo.address, Protocol::Tcp);
    let listen = r.listen;
    db.set_config(&admin, &node, 0, vec![r]).unwrap();
    let mut http = server(
        api::router(AppState::new(db.clone())),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await;
    let origin = format!("http://{}", http.address);
    let local = Store::open(&temp.path().join("agent.sqlite")).unwrap();
    let mut a = agent(local.clone(), &origin, &node, Some(token));
    until(|| db.nodes(&admin).unwrap()[0].applied_revision == 1).await;
    let mut stream = TcpStream::connect(listen).await.unwrap();
    stream.write_all(b"live").await.unwrap();
    let mut bytes = [0; 4];
    stream.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"live");
    a.task.abort();
    assert!(
        timeout(Duration::from_secs(1), &mut a.task)
            .await
            .unwrap()
            .unwrap_err()
            .is_cancelled()
    );
    let mut remaining = vec![];
    let ended = timeout(Duration::from_secs(1), stream.read_to_end(&mut remaining))
        .await
        .expect("aborted Agent left an active forwarding session");
    assert!(ended.is_err() || remaining.is_empty());
    assert!(
        db.nodes(&admin).unwrap()[0].lease.active,
        "an aborted process must not claim a clean release"
    );
    let mut b = agent(local, &origin, &node, None);
    sleep(Duration::from_millis(300)).await;
    assert!(TcpStream::connect(listen).await.is_err());
    until(|| {
        let n = &db.nodes(&admin).unwrap()[0];
        n.lease.generation == 2 && n.applied_revision == 1
    })
    .await;
    assert_eq!(exchange(listen, b"after").await, b"after");
    stop_agent(&mut b).await;
    assert_eq!(total(&db, &admin), 18);
    stop_server(&mut http).await;
}
