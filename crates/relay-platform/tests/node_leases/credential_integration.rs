use super::*;
use axum::response::IntoResponse;
use relay_platform::credential::CredentialStatus;
use tokio::net::UdpSocket;

fn credential(db: &Store) -> Value {
    serde_json::from_str(&db.metadata("agent_credential").unwrap().unwrap()).unwrap()
}
async fn udp_exchange(socket: &UdpSocket, listen: SocketAddr, payload: &[u8]) {
    socket.send_to(payload, listen).await.unwrap();
    let mut reply = vec![0; payload.len() + 1];
    let size = timeout(Duration::from_secs(3), socket.recv(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply[..size], payload);
}
async fn expect_old_rejected(client: &reqwest::Client, origin: &str, old: &str) {
    let lease = json!({"run_id":"old-copy","token":secret(),"generation":null});
    let sync = json!({"ledger_id":"old-ledger","need_config":false,"applied_revision":1,"apply_error":null,"usage":[],"stats":EngineStats::default(),"budget":null});
    for (path, body) in [
        ("lease", lease),
        (
            "reconcile",
            json!({"ledger_id":null,"after":null,"expected_revision":null}),
        ),
        ("sync", sync),
    ] {
        assert_eq!(
            client
                .post(format!("{origin}/api/v1/agent/{path}"))
                .bearer_auth(old)
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
async fn online_rotation_keeps_tcp_udp_budget_and_lease_during_an_old_credential_renewal_race() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("controller.sqlite")).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let (session, _) = db.login("admin", PASSWORD).unwrap();
    let (node, enrollment) = strict(&db, &admin);
    let budget = recovery_budget(&db, &admin, 2048);
    let enrollment_file = temp.path().join("enroll.secret");
    write_secret(&enrollment_file, enrollment.as_bytes()).unwrap();
    let echo = tcp_echo().await;
    let _udp = udp_echo_at(&echo.address.to_string()).await;
    let mut r = rule(echo.address, Protocol::Both);
    r.owner_id = admin.id.clone();
    let listen = r.listen;
    db.set_config(&admin, &node, 0, vec![r]).unwrap();
    let delay_once = Arc::new(AtomicBool::new(false));
    let delayed = Arc::new(AtomicBool::new(false));
    let release = Arc::new(tokio::sync::Notify::new());
    let (gate, observed, ready) = (delay_once.clone(), delayed.clone(), release.clone());
    let router = api::router(AppState::new(db.clone())).layer(axum::middleware::from_fn(
        move |request: axum::extract::Request, next: axum::middleware::Next| {
            let (gate, observed, ready) = (gate.clone(), observed.clone(), ready.clone());
            async move {
                if request.uri().path() == "/api/v1/agent/lease"
                    && gate.swap(false, Ordering::SeqCst)
                {
                    observed.store(true, Ordering::SeqCst);
                    ready.notified().await;
                }
                next.run(request).await
            }
        },
    ));
    let mut http = server(router, "127.0.0.1:0".parse().unwrap()).await;
    let origin = format!("http://{}", http.address);
    let local = Store::open(&temp.path().join("agent.sqlite")).unwrap();
    let mut running = agent(local.clone(), &origin, &node, Some(enrollment_file));
    until(|| db.nodes(&admin).unwrap()[0].applied_revision == 1).await;
    let old = credential(&local)["token"].as_str().unwrap().to_owned();
    let run = db.nodes(&admin).unwrap()[0].lease.holder_run_id.clone();
    let mut tcp = TcpStream::connect(listen).await.unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    persistent_exchange(&mut tcp, &[1; 32]).await;
    udp_exchange(&udp, listen, &[2; 24]).await;
    delay_once.store(true, Ordering::SeqCst);
    until(|| delayed.load(Ordering::SeqCst)).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let path = format!("{origin}/api/v1/nodes/{node}/credential");
    let state: CredentialStatus = client
        .post(format!("{path}/rotate"))
        .bearer_auth(&session)
        .json(&json!({"expected_revision":1}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(state.pending.is_some());
    until(|| credential(&local)["revision"] == 2).await;
    release.notify_one();
    expect_old_rejected(&client, &origin, &old).await;
    persistent_exchange(&mut tcp, &[3; 40]).await;
    udp_exchange(&udp, listen, &[4; 20]).await;
    sleep(Duration::from_millis(3500)).await;
    assert!(
        !running.task.is_finished(),
        "old in-flight renewal must retry the new credential"
    );
    let state = db.node_credential_status(&admin, &node).unwrap();
    assert_eq!(state.revision, 2);
    assert!(state.pending.is_none());
    let now = &db.nodes(&admin).unwrap()[0];
    assert_eq!(now.lease.generation, 1);
    assert_eq!(now.lease.holder_run_id, run);
    assert_eq!(now.desired_revision, 1);
    persistent_exchange(&mut tcp, &[5; 16]).await;
    drop(tcp);
    drop(udp);
    stop_agent(&mut running).await;
    assert_eq!(total(&db, &admin), 264);
    let final_budget = db
        .budgets(&admin)
        .unwrap()
        .budgets
        .into_iter()
        .find(|b| b.id == budget.id)
        .unwrap();
    assert_eq!(final_budget.consumed_bytes, 264);
    assert_eq!(final_budget.committed_bytes, 264);
    // A task queued while the Agent is stopped survives until its next start.
    let second = credential(&local)["token"].as_str().unwrap().to_owned();
    db.request_credential_rotation(&admin, &node, 2).unwrap();
    assert_eq!(
        db.node_credential_status(&admin, &node).unwrap().revision,
        2
    );
    running = agent(local.clone(), &origin, &node, None);
    until(|| credential(&local)["revision"] == 3).await;
    let mut tcp = TcpStream::connect(listen).await.unwrap();
    let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    persistent_exchange(&mut tcp, &[9; 24]).await;
    udp_exchange(&udp, listen, &[10; 16]).await;
    expect_old_rejected(&client, &origin, &second).await;
    drop(tcp);
    drop(udp);
    stop_agent(&mut running).await;
    assert_eq!(total(&db, &admin), 344);
    let final_budget = &db.budgets(&admin).unwrap().budgets[0];
    assert_eq!(final_budget.consumed_bytes, 344);
    assert_eq!(final_budget.committed_bytes, 344);
    stop_server(&mut http).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn rotation_resumes_the_same_durable_candidate_after_abort_before_or_after_controller_commit()
{
    for commit_first in [false, true] {
        let temp = tempfile::tempdir().unwrap();
        let db = Store::open(&temp.path().join("controller.sqlite")).unwrap();
        let admin = db.bootstrap(PASSWORD).unwrap();
        let (node, enrollment) = strict(&db, &admin);
        recovery_budget(&db, &admin, 1024);
        let enrollment_file = temp.path().join("enroll.secret");
        write_secret(&enrollment_file, enrollment.as_bytes()).unwrap();
        let echo = tcp_echo().await;
        let _udp = udp_echo_at(&echo.address.to_string()).await;
        let mut r = rule(echo.address, Protocol::Both);
        r.owner_id = admin.id.clone();
        let listen = r.listen;
        db.set_config(&admin, &node, 0, vec![r]).unwrap();
        let fail = Arc::new(AtomicBool::new(true));
        let calls = Arc::new(AtomicUsize::new(0));
        let (gate, requests) = (fail.clone(), calls.clone());
        let router = api::router(AppState::new(db.clone())).layer(axum::middleware::from_fn(
            move |request: axum::extract::Request, next: axum::middleware::Next| {
                let (gate, requests) = (gate.clone(), requests.clone());
                async move {
                    if request.uri().path() == "/api/v1/agent/credential/rotate"
                        && gate.load(Ordering::SeqCst)
                    {
                        if commit_first {
                            let _ = next.run(request).await;
                        }
                        requests.fetch_add(1, Ordering::SeqCst);
                        return (
                            axum::http::StatusCode::SERVICE_UNAVAILABLE,
                            "injected missing rotation confirmation",
                        )
                            .into_response();
                    }
                    next.run(request).await
                }
            },
        ));
        let mut http = server(router, "127.0.0.1:0".parse().unwrap()).await;
        let origin = format!("http://{}", http.address);
        let local = Store::open(&temp.path().join("agent.sqlite")).unwrap();
        let mut running = agent(local.clone(), &origin, &node, Some(enrollment_file));
        until(|| db.nodes(&admin).unwrap()[0].applied_revision == 1).await;
        let old = credential(&local)["token"].as_str().unwrap().to_owned();
        let mut tcp = TcpStream::connect(listen).await.unwrap();
        persistent_exchange(&mut tcp, &[6; 32]).await;
        let requested = db
            .request_credential_rotation(&admin, &node, 1)
            .unwrap()
            .pending
            .unwrap();
        until(|| calls.load(Ordering::SeqCst) > 0).await;
        let durable = credential(&local);
        let candidate = durable["pending_rotation"]["token"]
            .as_str()
            .unwrap()
            .to_owned();
        assert_eq!(durable["pending_rotation"]["request"]["id"], requested.id);
        assert_eq!(durable["revision"], 1);
        assert_eq!(durable["token"], old);
        assert_eq!(
            db.node_credential_status(&admin, &node).unwrap().revision,
            if commit_first { 2 } else { 1 }
        );
        running.task.abort();
        assert!((&mut running.task).await.unwrap_err().is_cancelled());
        drop(tcp);
        fail.store(false, Ordering::SeqCst);
        running = agent(local.clone(), &origin, &node, None);
        until(|| credential(&local)["revision"] == 2).await;
        assert_eq!(credential(&local)["token"], candidate);
        assert!(credential(&local).get("pending_rotation").is_none());
        until(|| {
            db.nodes(&admin).unwrap()[0].applied_revision == 1
                && db.nodes(&admin).unwrap()[0].lease.generation == 2
        })
        .await;
        let mut tcp = TcpStream::connect(listen).await.unwrap();
        persistent_exchange(&mut tcp, &[7; 24]).await;
        let udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        udp_exchange(&udp, listen, &[8; 16]).await;
        let client = reqwest::Client::builder().no_proxy().build().unwrap();
        expect_old_rejected(&client, &origin, &old).await;
        drop(tcp);
        drop(udp);
        stop_agent(&mut running).await;
        assert_eq!(total(&db, &admin), 144);
        assert_eq!(
            local
                .agent_usage(false)
                .unwrap()
                .iter()
                .map(|u| u.upload_bytes + u.download_bytes)
                .sum::<u64>(),
            144
        );
        let final_budget = &db.budgets(&admin).unwrap().budgets[0];
        assert_eq!(final_budget.consumed_bytes, 144);
        assert_eq!(final_budget.committed_bytes, 144);
        stop_server(&mut http).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn credential_api_is_tenant_scoped_readable_by_viewer_and_rejects_stale_or_invalid_requests()
{
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("controller.sqlite")).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let (node, enrollment) = strict(&db, &admin);
    db.enroll(&node, &enrollment, &secret()).unwrap();
    let (admin_token, _) = db.login("admin", PASSWORD).unwrap();
    db.create_user(&admin, "default", "rotation-viewer", PASSWORD, Role::Viewer)
        .unwrap();
    let (viewer, _) = db.login("rotation-viewer", PASSWORD).unwrap();
    let tenant = db.create_tenant(&admin, "another").unwrap();
    db.create_user(
        &admin,
        &tenant,
        "rotation-foreign",
        PASSWORD,
        Role::TenantAdmin,
    )
    .unwrap();
    let (foreign, _) = db.login("rotation-foreign", PASSWORD).unwrap();
    let mut http = server(
        api::router(AppState::new(db.clone())),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await;
    let url = format!("http://{}/api/v1/nodes/{node}/credential", http.address);
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    assert_eq!(client.get(&url).send().await.unwrap().status(), 401);
    assert_eq!(
        client
            .get(&url)
            .bearer_auth(&viewer)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client
            .get(&url)
            .bearer_auth(&foreign)
            .send()
            .await
            .unwrap()
            .status(),
        404
    );
    for (token, body, status) in [
        (&viewer, json!({"expected_revision":1}), 403),
        (&foreign, json!({"expected_revision":1}), 404),
        (&admin_token, json!({"expected_revision":0}), 409),
        (
            &admin_token,
            json!({"expected_revision":1,"ignored":true}),
            422,
        ),
        (&admin_token, json!({"expected_revision":1}), 200),
        (&admin_token, json!({"expected_revision":1}), 409),
    ] {
        assert_eq!(
            client
                .post(format!("{url}/rotate"))
                .bearer_auth(token)
                .json(&body)
                .send()
                .await
                .unwrap()
                .status(),
            status
        );
    }
    assert_eq!(
        db.node_credential_status(&admin, &node).unwrap().revision,
        1
    );
    assert!(
        db.node_credential_status(&admin, &node)
            .unwrap()
            .pending
            .is_some()
    );
    stop_server(&mut http).await;
}
