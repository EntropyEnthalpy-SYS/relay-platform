mod common;
#[path = "node_leases/node_profile_integration.rs"]
mod node_profile_integration;
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

fn recovery_budget(db: &Store, admin: &Actor, limit: u64) -> relay_platform::budget::Budget {
    db.create_budget(
        admin,
        relay_platform::budget::NewBudget {
            scope: relay_platform::budget::BudgetScope::User,
            scope_id: admin.id.clone(),
            name: "crash recovery".into(),
            limit_bytes: limit,
            quantum_bytes: 64,
        },
    )
    .unwrap()
}

async fn persistent_exchange(stream: &mut TcpStream, payload: &[u8]) {
    stream.write_all(payload).await.unwrap();
    let mut reply = vec![0; payload.len()];
    timeout(Duration::from_secs(3), stream.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, payload);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn budget_reservation_api_enforces_tenant_session_and_node_recovery_credentials() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("controller.sqlite")).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let budget = recovery_budget(&db, &admin, 64);
    let viewer = db
        .create_user(&admin, "default", "reserve-viewer", PASSWORD, Role::Viewer)
        .unwrap();
    let (viewer_token, _) = db.login(&viewer.username, PASSWORD).unwrap();
    let tenant = db.create_tenant(&admin, "separate").unwrap();
    let outsider = db
        .create_user(&admin, &tenant, "outsider", PASSWORD, Role::TenantAdmin)
        .unwrap();
    let (outside_token, _) = db.login(&outsider.username, PASSWORD).unwrap();
    let mut http = server(
        api::router(AppState::new(db)),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let base = format!("http://{}/api/v1", http.address);
    let url = format!("{base}/budgets/{}/reservations", budget.id);
    assert_eq!(client.get(&url).send().await.unwrap().status(), 401);
    let page: relay_platform::budget::ReservationPage = client
        .get(&url)
        .bearer_auth(&viewer_token)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(page.reservations.is_empty());
    assert_eq!(page.budget_id, budget.id);
    assert_eq!(
        client
            .get(&url)
            .bearer_auth(&outside_token)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    assert_eq!(
        client
            .get(format!("{url}?after=invalid%20cursor"))
            .bearer_auth(&viewer_token)
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(
        client
            .get(format!("{url}?ignored=true"))
            .bearer_auth(&viewer_token)
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    assert_eq!(client.post(format!("{base}/agent/budgets/recover")).bearer_auth(&viewer_token).json(&json!({
        "lease":{"run_id":"run","generation":1,"token":secret()},"run_id":"run","ledger_id":"ledger","claims":[],"requests":[]
    })).send().await.unwrap().status(),401);
    stop_server(&mut http).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn original_state_recovers_after_abort_and_lost_recovery_reply_before_tcp_udp_activation() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("controller.sqlite")).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let (node, enrollment) = strict(&db, &admin);
    recovery_budget(&db, &admin, 64);
    let token = temp.path().join("enrollment.secret");
    write_secret(&token, enrollment.as_bytes()).unwrap();
    let echo = tcp_echo().await;
    let _udp_echo = udp_echo_at(&echo.address.to_string()).await;
    let mut r = rule(echo.address, Protocol::Both);
    r.owner_id = admin.id.clone();
    let listen = r.listen;
    db.set_config(&admin, &node, 0, vec![r]).unwrap();
    let recovery_calls = Arc::new(AtomicUsize::new(0));
    let calls = recovery_calls.clone();
    let block_sync = Arc::new(AtomicBool::new(false));
    let sync_gate = block_sync.clone();
    let router = api::router(AppState::new(db.clone())).layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let calls = calls.clone();
            let sync_gate = sync_gate.clone();
            async move {
                if request.uri().path() == "/api/v1/agent/sync" && sync_gate.load(Ordering::SeqCst)
                {
                    use axum::response::IntoResponse;
                    return (
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        "injected sync outage",
                    )
                        .into_response();
                }
                let recovering = request.uri().path() == "/api/v1/agent/budgets/recover";
                let response = next.run(request).await;
                if recovering && calls.fetch_add(1, Ordering::SeqCst) == 0 {
                    assert!(response.status().is_success());
                    use axum::response::IntoResponse;
                    (
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        "lost successful recovery reply",
                    )
                        .into_response()
                } else {
                    response
                }
            }
        },
    ));
    let mut http = server(router, "127.0.0.1:0".parse().unwrap()).await;
    let origin = format!("http://{}", http.address);
    let local = Store::open(&temp.path().join("agent.sqlite")).unwrap();
    let mut a = agent(local.clone(), &origin, &node, Some(token));
    until(|| db.nodes(&admin).unwrap()[0].applied_revision == 1).await;
    let first_run = db.nodes(&admin).unwrap()[0].lease.holder_run_id.clone();
    let mut stream = TcpStream::connect(listen).await.unwrap();
    persistent_exchange(&mut stream, b"p").await;
    until(|| total(&db, &admin) == 2).await;
    block_sync.store(true, Ordering::SeqCst);
    persistent_exchange(&mut stream, b"live").await;
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut packet = [0; 32];
    udp.send_to(b"ping", listen).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), udp.recv_from(&mut packet))
            .await
            .unwrap()
            .unwrap()
            .0,
        4
    );
    assert_eq!(&packet[..4], b"ping");
    assert_eq!(
        local
            .agent_usage(false)
            .unwrap()
            .iter()
            .map(|u| u.upload_bytes + u.download_bytes)
            .sum::<u64>(),
        18
    );
    assert_eq!(total(&db, &admin), 2);
    assert_eq!(db.budgets(&admin).unwrap().budgets[0].committed_bytes, 64);
    a.task.abort();
    assert!((&mut a.task).await.unwrap_err().is_cancelled());
    block_sync.store(false, Ordering::SeqCst);
    let mut b = agent(local.clone(), &origin, &node, None);
    until(|| recovery_calls.load(Ordering::SeqCst) == 1).await;
    assert_eq!(db.budgets(&admin).unwrap().budgets[0].consumed_bytes, 18);
    assert!(
        TcpStream::connect(listen).await.is_err(),
        "recovery reply loss must not activate cached listeners"
    );
    until(|| {
        let n = &db.nodes(&admin).unwrap()[0];
        n.lease.generation == 2 && n.applied_revision == 1 && n.stats.budget_recovery.is_some()
    })
    .await;
    assert_eq!(db.nodes(&admin).unwrap()[0].lease.holder_run_id, first_run);
    assert_eq!(recovery_calls.load(Ordering::SeqCst), 2);
    let stats = db.nodes(&admin).unwrap()[0]
        .stats
        .budget_recovery
        .clone()
        .unwrap();
    assert_eq!(stats.validated_grants, 1);
    let mut stream = TcpStream::connect(listen).await.unwrap();
    persistent_exchange(&mut stream, &[7; 15]).await;
    udp.send_to(&[9; 8], listen).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), udp.recv_from(&mut packet))
            .await
            .unwrap()
            .unwrap()
            .0,
        8
    );
    assert_eq!(&packet[..8], &[9; 8]);
    until(|| total(&db, &admin) == 64).await;
    stream.write_all(b"x").await.unwrap();
    let mut extra = [0; 1];
    let reply = timeout(Duration::from_millis(300), stream.read(&mut extra)).await;
    assert!(
        !matches!(reply, Ok(Ok(1))),
        "resumption bypassed the shared limit"
    );
    stop_agent(&mut b).await;
    assert_eq!(
        json!(db.nodes(&admin).unwrap()[0].stats.budget_recovery),
        json!(Some(stats)),
        "final stopped heartbeat must retain this process's recovery result"
    );
    let budget = &db.budgets(&admin).unwrap().budgets[0];
    assert_eq!((budget.consumed_bytes, budget.committed_bytes), (64, 64));
    assert_eq!(
        local
            .agent_usage(false)
            .unwrap()
            .iter()
            .map(|r| r.upload_bytes + r.download_bytes)
            .sum::<u64>(),
        64
    );
    stop_server(&mut http).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn failed_budget_recovery_keeps_listeners_and_cleanup_refunds_stopped() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("controller.sqlite")).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let (node, enrollment) = strict(&db, &admin);
    let budget = recovery_budget(&db, &admin, 64);
    let token = temp.path().join("enrollment.secret");
    write_secret(&token, enrollment.as_bytes()).unwrap();
    let echo = tcp_echo().await;
    let mut r = rule(echo.address, Protocol::Tcp);
    r.owner_id = admin.id.clone();
    let listen = r.listen;
    db.set_config(&admin, &node, 0, vec![r]).unwrap();
    let reject = Arc::new(AtomicBool::new(false));
    let gate = reject.clone();
    let router = api::router(AppState::new(db.clone())).layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let gate = gate.clone();
            async move {
                if request.uri().path() == "/api/v1/agent/budgets/recover"
                    && gate.load(Ordering::SeqCst)
                {
                    use axum::response::IntoResponse;
                    (
                        axum::http::StatusCode::CONFLICT,
                        "injected contradictory reservation",
                    )
                        .into_response()
                } else {
                    next.run(request).await
                }
            }
        },
    ));
    let mut http = server(router, "127.0.0.1:0".parse().unwrap()).await;
    let origin = format!("http://{}", http.address);
    let local = Store::open(&temp.path().join("agent.sqlite")).unwrap();
    let mut a = agent(local.clone(), &origin, &node, Some(token));
    until(|| db.nodes(&admin).unwrap()[0].applied_revision == 1).await;
    let mut stream = TcpStream::connect(listen).await.unwrap();
    persistent_exchange(&mut stream, b"unsettled").await;
    until(|| total(&db, &admin) == 18).await;
    reject.store(true, Ordering::SeqCst);
    a.task.abort();
    assert!((&mut a.task).await.unwrap_err().is_cancelled());
    let mut b = agent(local.clone(), &origin, &node, None);
    let error = timeout(Duration::from_secs(8), &mut b.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(error.to_string().contains("rejected budget recovery"));
    assert!(TcpStream::connect(listen).await.is_err());
    assert_eq!(db.budgets(&admin).unwrap().budgets[0].committed_bytes, 64);
    assert_eq!(
        db.budget_reservations(&admin, &budget.id, None)
            .unwrap()
            .reservations
            .len(),
        1
    );
    let state = &db.nodes(&admin).unwrap()[0];
    assert_eq!(state.lease.generation, 2);
    assert!(state.lease.active);
    assert!(state.last_seen_ms.is_none());
    reject.store(false, Ordering::SeqCst);
    let mut c = agent(local, &origin, &node, None);
    until(|| {
        let n = &db.nodes(&admin).unwrap()[0];
        n.lease.generation == 3 && n.applied_revision == 1
    })
    .await;
    assert_eq!(exchange(listen, b"ok").await, b"ok");
    stop_agent(&mut c).await;
    let final_budget = &db.budgets(&admin).unwrap().budgets[0];
    assert_eq!(
        (final_budget.consumed_bytes, final_budget.committed_bytes),
        (22, 22)
    );
    stop_server(&mut http).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn intervening_backup_takeover_prevents_original_state_from_reclaiming_old_reservations() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("controller.sqlite")).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let (node, enrollment) = strict(&db, &admin);
    let budget = recovery_budget(&db, &admin, 128);
    let token = temp.path().join("enrollment.secret");
    write_secret(&token, enrollment.as_bytes()).unwrap();
    let echo = tcp_echo().await;
    let mut r = rule(echo.address, Protocol::Tcp);
    r.owner_id = admin.id.clone();
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
    let first_run = db.nodes(&admin).unwrap()[0].lease.holder_run_id.clone();
    let mut stream = TcpStream::connect(listen).await.unwrap();
    persistent_exchange(&mut stream, b"original").await;
    until(|| total(&db, &admin) == 16 && local.agent_usage(true).unwrap().is_empty()).await;
    let copy_path = temp.path().join("copy.sqlite");
    local.backup(&copy_path).unwrap();
    let copied = Store::open(&copy_path).unwrap();
    a.task.abort();
    assert!((&mut a.task).await.unwrap_err().is_cancelled());
    let mut b = agent(copied, &origin, &node, None);
    until(|| {
        let n = &db.nodes(&admin).unwrap()[0];
        n.lease.generation == 2 && n.applied_revision == 1
    })
    .await;
    assert_ne!(db.nodes(&admin).unwrap()[0].lease.holder_run_id, first_run);
    assert_eq!(exchange(listen, b"ten-bytes!").await, b"ten-bytes!");
    stop_agent(&mut b).await;
    let mut c = agent(local.clone(), &origin, &node, None);
    until(|| {
        let n = &db.nodes(&admin).unwrap()[0];
        n.lease.generation == 3 && n.applied_revision == 1
    })
    .await;
    assert_ne!(db.nodes(&admin).unwrap()[0].lease.holder_run_id, first_run);
    assert!(db.nodes(&admin).unwrap()[0].stats.budget_recovery.is_none());
    assert_eq!(exchange(listen, b"last").await, b"last");
    stop_agent(&mut c).await;
    assert_eq!(total(&db, &admin), 44);
    let final_budget = &db.budgets(&admin).unwrap().budgets[0];
    assert_eq!(
        (final_budget.consumed_bytes, final_budget.committed_bytes),
        (44, 92)
    );
    let remaining = db.budget_reservations(&admin, &budget.id, None).unwrap();
    assert_eq!(remaining.reservations.len(), 1);
    assert_eq!(remaining.reservations[0].outstanding_bytes, 48);
    assert_eq!(Some(remaining.reservations[0].run_id.clone()), first_run);
    stop_server(&mut http).await;
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
