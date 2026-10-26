use super::*;
use axum::response::IntoResponse;
use relay_platform::{
    budget::{BudgetScope, NewBudget},
    credential::{CredentialPhase, CredentialStatus, ReplaceCredential, RevokeCredential},
    lease::LeaseRequest,
};
use std::sync::Mutex;
use tokio::net::UdpSocket;

fn saved(db: &Store) -> Value {
    serde_json::from_str(&db.metadata("agent_credential").unwrap().unwrap()).unwrap()
}
fn revoke(revision: u64) -> RevokeCredential {
    RevokeCredential {
        operation_id: uuid::Uuid::new_v4().to_string(),
        expected_revision: revision,
        reason: "replace lost server".into(),
    }
}
fn ticket(revision: u64) -> ReplaceCredential {
    ReplaceCredential {
        operation_id: uuid::Uuid::new_v4().to_string(),
        expected_revision: revision,
        enrollment_token: secret(),
        valid_for_seconds: 600,
        offline_stop_attested: false,
        lease_policy: None,
    }
}
async fn datagram(socket: &UdpSocket, listen: SocketAddr, payload: &[u8]) {
    socket.send_to(payload, listen).await.unwrap();
    let mut reply = vec![0; payload.len() + 1];
    let n = timeout(Duration::from_secs(3), socket.recv(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply[..n], payload);
}
async fn mutate<T: serde::Serialize>(
    client: &reqwest::Client,
    origin: &str,
    node: &str,
    session: &str,
    action: &str,
    body: &T,
) -> CredentialStatus {
    client
        .post(format!("{origin}/api/v1/nodes/{node}/credential/{action}"))
        .bearer_auth(session)
        .json(body)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap()
}
async fn old_rejected(client: &reqwest::Client, origin: &str, token: &str) {
    let proof = json!({"run_id":"retired-run","generation":1,"token":secret()});
    let cases = [
        (
            "lease",
            json!({"run_id":"retired-run","token":secret(),"generation":null}),
        ),
        (
            "lease/release",
            json!({"proof":proof,"stats":EngineStats::default()}),
        ),
        (
            "reconcile",
            json!({"ledger_id":null,"after":null,"expected_revision":null}),
        ),
        (
            "sync",
            json!({"ledger_id":"retired-ledger","need_config":false,"applied_revision":0,"usage":[],"apply_error":null,"stats":EngineStats::default(),"budget":null}),
        ),
        (
            "budgets/recover",
            json!({"lease":proof,"ledger_id":"retired-ledger","run_id":"retired-run","claims":[],"requests":[]}),
        ),
        (
            "credential/rotate",
            json!({"request_id":"retired-task","expected_revision":1,"credential":secret(),"lease":proof}),
        ),
    ];
    for (path, body) in cases {
        assert_eq!(
            client
                .post(format!("{origin}/api/v1/agent/{path}"))
                .bearer_auth(token)
                .json(&body)
                .send()
                .await
                .unwrap()
                .status(),
            401,
            "{path}"
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn revoked_isolated_agent_stops_before_fresh_identity_takes_over_and_unknown_reservations_stay_committed()
 {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("controller.sqlite")).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let (session, _) = db.login("admin", PASSWORD).unwrap();
    let (node, enrollment) = strict(&db, &admin);
    db.create_budget(
        &admin,
        NewBudget {
            scope: BudgetScope::User,
            scope_id: admin.id.clone(),
            name: "replacement quota".into(),
            limit_bytes: 2048,
            quantum_bytes: 256,
        },
    )
    .unwrap();
    let file = temp.path().join("initial.secret");
    write_secret(&file, enrollment.as_bytes()).unwrap();
    let (echo, _udp) = tcp_udp_echo().await;
    let mut r = rule(echo.address, Protocol::Both);
    r.owner_id = admin.id.clone();
    let listen = r.listen;
    db.set_config(&admin, &node, 0, vec![r]).unwrap();
    let isolated = Arc::new(Mutex::new(None::<String>));
    let gate = isolated.clone();
    let router = api::router(AppState::new(db.clone())).layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let gate = gate.clone();
            async move {
                let blocked = gate.lock().unwrap().as_ref().is_some_and(|old| {
                    request
                        .headers()
                        .get("authorization")
                        .and_then(|v| v.to_str().ok())
                        == Some(old.as_str())
                });
                if blocked {
                    return (
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        "isolated original node",
                    )
                        .into_response();
                }
                next.run(request).await
            }
        },
    ));
    let mut http = server(router, "127.0.0.1:0".parse().unwrap()).await;
    let origin = format!("http://{}", http.address);
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let original = Store::open(&temp.path().join("original.sqlite")).unwrap();
    let mut a = agent(original.clone(), &origin, &node, Some(file));
    until(|| db.nodes(&admin).unwrap()[0].applied_revision == 1).await;
    let mut tcp = TcpStream::connect(listen).await.unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    persistent_exchange(&mut tcp, &[1; 32]).await;
    datagram(&udp, listen, &[2; 16]).await;
    until(|| {
        total(&db, &admin) == 96 && db.budgets(&admin).unwrap().budgets[0].consumed_bytes == 96
    })
    .await;
    let old = saved(&original)["token"].as_str().unwrap().to_owned();
    *isolated.lock().unwrap() = Some(format!("Bearer {old}"));
    persistent_exchange(&mut tcp, &[3; 16]).await;
    datagram(&udp, listen, &[4; 8]).await;
    assert_eq!(
        original
            .agent_usage(false)
            .unwrap()
            .iter()
            .map(|u| u.upload_bytes + u.download_bytes)
            .sum::<u64>(),
        144
    );
    let revoke = revoke(1);
    let state = mutate(&client, &origin, &node, &session, "revoke", &revoke).await;
    assert_eq!(state.phase, CredentialPhase::Revoked);
    assert_eq!(total(&db, &admin), 96);
    assert_eq!(db.budgets(&admin).unwrap().budgets[0].committed_bytes, 256);
    let replacement = ticket(2);
    mutate(&client, &origin, &node, &session, "replace", &replacement).await;
    let file = temp.path().join("replacement.secret");
    write_secret(&file, replacement.enrollment_token.as_bytes()).unwrap();
    let fresh = Store::open(&temp.path().join("fresh.sqlite")).unwrap();
    let mut b = agent(fresh.clone(), &origin, &node, Some(file));
    until(|| {
        fresh
            .metadata("agent_credential")
            .unwrap()
            .is_some_and(|raw| serde_json::from_str::<Value>(&raw).unwrap()["revision"] == 3)
    })
    .await;
    assert!(db.nodes(&admin).unwrap()[0].lease.recovery_wait_ms > 0);
    assert!(fresh.metadata("agent_budget_run").unwrap().is_none());
    let outcome = timeout(Duration::from_secs(7), &mut a.task)
        .await
        .unwrap()
        .unwrap();
    assert!(outcome.is_err());
    let mut one = [0];
    assert!(matches!(
        timeout(Duration::from_secs(1), tcp.read(&mut one)).await,
        Ok(Ok(0)) | Ok(Err(_))
    ));
    drop(tcp);
    drop(udp);
    *isolated.lock().unwrap() = None;
    until(|| {
        let n = &db.nodes(&admin).unwrap()[0];
        n.lease.generation == 3 && n.applied_revision == 1
    })
    .await;
    old_rejected(&client, &origin, &old).await;
    let mut tcp = TcpStream::connect(listen).await.unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    persistent_exchange(&mut tcp, &[5; 32]).await;
    datagram(&udp, listen, &[6; 16]).await;
    assert_eq!(
        mutate(&client, &origin, &node, &session, "revoke", &revoke)
            .await
            .phase,
        CredentialPhase::Active
    );
    assert!(!b.task.is_finished());
    drop(tcp);
    drop(udp);
    stop_agent(&mut b).await;
    let budget = &db.budgets(&admin).unwrap().budgets[0];
    assert_eq!(budget.consumed_bytes, 192);
    assert_eq!(budget.committed_bytes, 352);
    assert_eq!(total(&db, &admin), 192);
    assert_eq!(
        fresh
            .agent_usage(false)
            .unwrap()
            .iter()
            .map(|u| u.upload_bytes + u.download_bytes)
            .sum::<u64>(),
        192
    );
    assert_eq!(db.config(&admin, &node, None).unwrap().revision, 1);
    stop_server(&mut http).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn replacement_recovers_lost_enrollment_reply_and_waits_for_explicit_new_quota_period() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("controller.sqlite")).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let (node, enrollment) = strict(&db, &admin);
    db.enroll(&node, &enrollment, &secret()).unwrap();
    let (echo, _udp) = tcp_udp_echo().await;
    let mut r = rule(echo.address, Protocol::Both);
    r.owner_id = admin.id.clone();
    r.quota_bytes = Some(128);
    let listen = r.listen;
    db.set_config(&admin, &node, 0, vec![r.clone()]).unwrap();
    db.revoke_node_credential(&admin, &node, revoke(1)).unwrap();
    let replacement = ticket(2);
    db.replace_node_credential(&admin, &node, replacement.clone())
        .unwrap();
    let lose = Arc::new(AtomicBool::new(true));
    let once = lose.clone();
    let router = api::router(AppState::new(db.clone())).layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let once = once.clone();
            async move {
                let drop_reply = request.uri().path() == "/api/v1/agent/enroll"
                    && once.swap(false, Ordering::SeqCst);
                let response = next.run(request).await;
                if drop_reply {
                    assert!(response.status().is_success());
                    (
                        axum::http::StatusCode::SERVICE_UNAVAILABLE,
                        "lost replacement enrollment response",
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
    let file = temp.path().join("replacement.secret");
    write_secret(&file, replacement.enrollment_token.as_bytes()).unwrap();
    let local = Store::open(&temp.path().join("fresh.sqlite")).unwrap();
    let mut a = agent(local.clone(), &origin, &node, Some(file));
    assert!(
        timeout(Duration::from_secs(3), &mut a.task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    let pending = saved(&local);
    assert!(pending.get("pending_enrollment_token").is_some());
    let candidate = pending["token"].clone();
    a = agent(local.clone(), &origin, &node, None);
    until(|| saved(&local).get("pending_enrollment_token").is_none()).await;
    assert_eq!(saved(&local)["token"], candidate);
    assert_eq!(saved(&local)["revision"], 3);
    sleep(Duration::from_millis(300)).await;
    assert!(local.metadata("agent_budget_run").unwrap().is_none());
    assert!(TcpStream::connect(listen).await.is_err());
    assert_eq!(
        db.node_credential_status(&admin, &node)
            .unwrap()
            .blocked_quota_periods
            .len(),
        1
    );
    assert!(db.set_config(&admin, &node, 1, vec![r.clone()]).is_err());
    r.meter_epoch = "explicit-new-period".into();
    db.set_config(&admin, &node, 1, vec![r]).unwrap();
    until(|| db.nodes(&admin).unwrap()[0].applied_revision == 2).await;
    let mut tcp = TcpStream::connect(listen).await.unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    persistent_exchange(&mut tcp, &[7; 32]).await;
    datagram(&udp, listen, &[8; 16]).await;
    drop(tcp);
    drop(udp);
    stop_agent(&mut a).await;
    assert_eq!(total(&db, &admin), 96);
    assert_eq!(
        db.reported_usage(&admin).unwrap()[0]["meter_epoch"],
        "explicit-new-period"
    );
    stop_server(&mut http).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offline_instance_is_externally_stopped_before_attested_strict_replacement_runs() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("controller.sqlite")).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let (node, enrollment) = db
        .create_node_with_lease(&admin, "default", "offline", None)
        .unwrap();
    let node = node.id;
    let file = temp.path().join("initial.secret");
    write_secret(&file, enrollment.as_bytes()).unwrap();
    let (echo, _udp) = tcp_udp_echo().await;
    let mut r = rule(echo.address, Protocol::Both);
    r.owner_id = admin.id.clone();
    let listen = r.listen;
    db.set_config(&admin, &node, 0, vec![r]).unwrap();
    let block = Arc::new(AtomicBool::new(false));
    let gate = block.clone();
    let router = api::router(AppState::new(db.clone())).layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let gate = gate.clone();
            async move {
                if gate.load(Ordering::SeqCst) && request.uri().path().starts_with("/api/v1/agent/")
                {
                    return (axum::http::StatusCode::SERVICE_UNAVAILABLE, "offline node")
                        .into_response();
                }
                next.run(request).await
            }
        },
    ));
    let mut http = server(router, "127.0.0.1:0".parse().unwrap()).await;
    let origin = format!("http://{}", http.address);
    let original = Store::open(&temp.path().join("original.sqlite")).unwrap();
    let mut a = agent(original, &origin, &node, Some(file));
    until(|| db.nodes(&admin).unwrap()[0].applied_revision == 1).await;
    let mut tcp = TcpStream::connect(listen).await.unwrap();
    persistent_exchange(&mut tcp, &[1; 8]).await;
    until(|| total(&db, &admin) == 16).await;
    block.store(true, Ordering::SeqCst);
    db.revoke_node_credential(&admin, &node, revoke(1)).unwrap();
    let mut replacement = ticket(2);
    replacement.lease_policy = Some(LeasePolicy { ttl_ms: 5000 });
    assert!(
        db.replace_node_credential(&admin, &node, replacement.clone())
            .is_err()
    );
    persistent_exchange(&mut tcp, &[2; 8]).await;
    assert!(!a.task.is_finished());
    drop(tcp);
    stop_agent(&mut a).await;
    replacement.offline_stop_attested = true;
    db.replace_node_credential(&admin, &node, replacement.clone())
        .unwrap();
    block.store(false, Ordering::SeqCst);
    let file = temp.path().join("replacement.secret");
    write_secret(&file, replacement.enrollment_token.as_bytes()).unwrap();
    let fresh = Store::open(&temp.path().join("fresh.sqlite")).unwrap();
    let mut b = agent(fresh, &origin, &node, Some(file));
    until(|| db.nodes(&admin).unwrap()[0].applied_revision == 1).await;
    assert!(db.nodes(&admin).unwrap()[0].lease.policy.is_some());
    let mut tcp = TcpStream::connect(listen).await.unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    persistent_exchange(&mut tcp, &[3; 8]).await;
    datagram(&udp, listen, &[4; 8]).await;
    drop(tcp);
    drop(udp);
    stop_agent(&mut b).await;
    assert_eq!(total(&db, &admin), 48);
    stop_server(&mut http).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn identity_http_permissions_do_not_leak_tickets_and_retired_state_cannot_restart() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("controller.sqlite")).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let (session, _) = db.login("admin", PASSWORD).unwrap();
    let (node, enrollment) = strict(&db, &admin);
    db.create_user(&admin, "default", "identity-viewer", PASSWORD, Role::Viewer)
        .unwrap();
    let (viewer, _) = db.login("identity-viewer", PASSWORD).unwrap();
    let other = db.create_tenant(&admin, "foreign").unwrap();
    db.create_user(
        &admin,
        &other,
        "identity-foreign",
        PASSWORD,
        Role::TenantAdmin,
    )
    .unwrap();
    let (foreign, _) = db.login("identity-foreign", PASSWORD).unwrap();
    let mut http = controller(db.clone(), "127.0.0.1:0".parse().unwrap()).await;
    let origin = format!("http://{}", http.address);
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let file = temp.path().join("enrollment.secret");
    write_secret(&file, enrollment.as_bytes()).unwrap();
    let original = Store::open(&temp.path().join("original.sqlite")).unwrap();
    let mut a = agent(original.clone(), &origin, &node, Some(file));
    until(|| db.nodes(&admin).unwrap()[0].last_seen_ms.is_some()).await;
    stop_agent(&mut a).await;
    for (action, body) in [
        ("revoke", serde_json::to_value(revoke(1)).unwrap()),
        ("replace", serde_json::to_value(ticket(1)).unwrap()),
    ] {
        for (auth, status) in [(&viewer, 403), (&foreign, 404)] {
            assert_eq!(
                client
                    .post(format!("{origin}/api/v1/nodes/{node}/credential/{action}"))
                    .bearer_auth(auth)
                    .json(&body)
                    .send()
                    .await
                    .unwrap()
                    .status(),
                status
            );
        }
    }
    mutate(&client, &origin, &node, &session, "revoke", &revoke(1)).await;
    let request = ticket(2);
    let status = mutate(&client, &origin, &node, &session, "replace", &request).await;
    let body = serde_json::to_string(&status).unwrap();
    assert_eq!(client.post(format!("{origin}/api/v1/agent/enroll")).json(&json!({"node_id":node,"enrollment_token":request.enrollment_token,"credential":secret()})).send().await.unwrap().status(),426);
    assert!(!body.contains(&request.enrollment_token));
    assert!(!body.contains(&relay_platform::store::token_hash(
        &request.enrollment_token
    )));
    let old = saved(&original)["token"].as_str().unwrap().to_owned();
    old_rejected(&client, &origin, &old).await;
    a = agent(original, &origin, &node, None);
    assert!(
        timeout(Duration::from_secs(3), &mut a.task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    let reply = client
        .post(format!("{origin}/api/v1/agent/lease"))
        .bearer_auth(&session)
        .json(&LeaseRequest {
            run_id: "invalid".into(),
            token: secret(),
            generation: None,
            resume_generation: None,
        })
        .send()
        .await
        .unwrap();
    assert_eq!(reply.status(), 401);
    stop_server(&mut http).await;
}
