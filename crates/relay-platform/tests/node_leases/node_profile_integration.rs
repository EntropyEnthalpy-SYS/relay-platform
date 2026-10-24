use super::*;
use relay_platform::node::{NodeLifecycle, NodeSettings, NodeUpdate};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn profile_http_filter_bulk_and_permissions_preserve_configuration() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("controller.sqlite")).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let (token, _) = db.login("admin", PASSWORD).unwrap();
    db.create_user(&admin, "default", "profile-viewer", PASSWORD, Role::Viewer)
        .unwrap();
    let (viewer, _) = db.login("profile-viewer", PASSWORD).unwrap();
    let tenant = db.create_tenant(&admin, "other").unwrap();
    db.create_user(
        &admin,
        &tenant,
        "profile-outsider",
        PASSWORD,
        Role::TenantAdmin,
    )
    .unwrap();
    let (outsider, _) = db.login("profile-outsider", PASSWORD).unwrap();
    let mut http = server(
        api::router(AppState::new(db.clone())),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await;
    let origin = format!("http://{}/api/v1", http.address);
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let settings = json!({"kinds":["ingress","ix"],"group":"asia","tags":["premium"],"notes":"机柜 B","cost":{"currency":"USD","amount_micros":12345678,"period":"monthly"}});
    let created: Value = client
        .post(format!("{origin}/nodes"))
        .bearer_auth(&token)
        .json(&json!({"name":"profile-alpha","settings":settings}))
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["node"]["id"].as_str().unwrap();
    assert_eq!(created["node"]["profile"]["revision"], 1);
    assert_eq!(
        created["node"]["profile"]["settings"]["cost"]["amount_micros"],
        12345678
    );
    let url = format!("{origin}/nodes/{id}/profile");
    let update = json!({"expected_revision":1,"name":"profile-renamed","settings":settings});
    for (auth, status) in [(&viewer, 403), (&outsider, 404)] {
        assert_eq!(
            client
                .put(&url)
                .bearer_auth(auth)
                .json(&update)
                .send()
                .await
                .unwrap()
                .status(),
            status
        );
    }
    let saved: Value = client
        .put(&url)
        .bearer_auth(&token)
        .json(&update)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(saved["profile"]["revision"], 2);
    assert_eq!(
        client
            .put(&url)
            .bearer_auth(&token)
            .json(&update)
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    let filtered: Vec<Value> = client
        .get(format!("{origin}/nodes"))
        .bearer_auth(&viewer)
        .query(&[
            ("q", "RENAMED"),
            ("kind", "ix"),
            ("group", "asia"),
            ("tag", "premium"),
            ("lifecycle", "active"),
        ])
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(filtered.len(), 1);
    let hidden: Vec<Value> = client
        .get(format!("{origin}/nodes?group=asia"))
        .bearer_auth(&outsider)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(hidden.is_empty());
    assert_eq!(
        client
            .get(format!("{origin}/nodes?unknown=true"))
            .bearer_auth(&token)
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    let (second, _) = db
        .create_node_with_lease(&admin, "default", "second", Some(LeasePolicy::default()))
        .unwrap();
    let mut batch = json!({"updates":[{"node_id":id,"update":{"expected_revision":2,"name":"batch-first","settings":{}}},{"node_id":second.id,"update":{"expected_revision":99,"name":"batch-second","settings":{}}}]});
    let bulk = format!("{origin}/nodes/profiles");
    assert_eq!(
        client
            .post(&bulk)
            .bearer_auth(&token)
            .json(&batch)
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    assert_eq!(
        db.nodes(&admin)
            .unwrap()
            .into_iter()
            .find(|n| n.id == id)
            .unwrap()
            .name,
        "profile-renamed"
    );
    batch["updates"][1]["update"]["expected_revision"] = json!(1);
    let receipts: Vec<Value> = client
        .post(&bulk)
        .bearer_auth(&token)
        .json(&batch)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(receipts.len(), 2);
    assert_eq!(receipts[0]["profile"]["revision"], 3);
    assert_eq!(receipts[1]["profile"]["revision"], 2);
    assert_eq!(db.config(&admin, id, None).unwrap().revision, 0);
    assert_eq!(db.history(&admin, id).unwrap().len(), 1);
    assert_eq!(
        client
            .post(format!("{origin}/nodes"))
            .bearer_auth(&token)
            .json(&json!({"name":"bad-offline","lease_policy":null,"settings":{"enabled":false}}))
            .send()
            .await
            .unwrap()
            .status(),
        400
    );
    stop_server(&mut http).await;
}

fn edit(
    db: &Store,
    actor: &Actor,
    node: &str,
    change: impl FnOnce(&mut NodeSettings),
) -> relay_platform::node::NodeUpdateResult {
    let current = db
        .nodes(actor)
        .unwrap()
        .into_iter()
        .find(|n| n.id == node)
        .unwrap();
    let mut settings = current.profile.settings;
    change(&mut settings);
    db.update_node(
        actor,
        node,
        NodeUpdate {
            expected_revision: current.profile.revision,
            name: current.name,
            settings,
        },
    )
    .unwrap()
}
async fn datagram(socket: &tokio::net::UdpSocket, listen: SocketAddr, bytes: &[u8]) {
    socket.send_to(bytes, listen).await.unwrap();
    let mut packet = [0; 64];
    let size = timeout(Duration::from_secs(2), socket.recv_from(&mut packet))
        .await
        .unwrap()
        .unwrap()
        .0;
    assert_eq!(&packet[..size], bytes);
}
async fn stopped_connections(
    listen: SocketAddr,
    stream: &mut TcpStream,
    udp: &tokio::net::UdpSocket,
) {
    let mut byte = [0];
    assert!(matches!(
        timeout(Duration::from_secs(1), stream.read(&mut byte)).await,
        Ok(Ok(0)) | Ok(Err(_))
    ));
    assert!(TcpStream::connect(listen).await.is_err());
    udp.send_to(b"closed", listen).await.unwrap();
    assert!(
        timeout(Duration::from_millis(250), udp.recv_from(&mut byte))
            .await
            .is_err()
    );
}
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn pause_closes_active_tcp_udp_without_configuration_republish_and_enable_allows_restart() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("controller.sqlite")).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let (node, enrollment) = strict(&db, &admin);
    recovery_budget(&db, &admin, 128);
    let token = temp.path().join("enrollment.secret");
    write_secret(&token, enrollment.as_bytes()).unwrap();
    let (echo, _udp_echo) = tcp_udp_echo().await;
    let mut r = rule(echo.address, Protocol::Both);
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
    let mut stream = TcpStream::connect(listen).await.unwrap();
    persistent_exchange(&mut stream, b"initial!").await;
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    datagram(&udp, listen, b"ping").await;
    edit(&db, &admin, &node, |s| {
        s.group = Some("new-group".into());
        s.notes = "metadata only".into();
    });
    persistent_exchange(&mut stream, b"same").await;
    assert_eq!(db.config(&admin, &node, None).unwrap().revision, 1);
    until(|| total(&db, &admin) == 32).await;
    assert_eq!(
        edit(&db, &admin, &node, |s| s.enabled = false).lifecycle,
        NodeLifecycle::Disabled
    );
    let result = timeout(Duration::from_secs(7), &mut a.task)
        .await
        .unwrap()
        .unwrap();
    assert!(result.is_err());
    stopped_connections(listen, &mut stream, &udp).await;
    let paused = db.nodes(&admin).unwrap().remove(0);
    assert!(!paused.lease.active);
    assert!(paused.stats.business_idle());
    assert_eq!(paused.profile.settings.group.as_deref(), Some("new-group"));
    assert_eq!(total(&db, &admin), 32);
    let budget = &db.budgets(&admin).unwrap().budgets[0];
    assert_eq!((budget.consumed_bytes, budget.committed_bytes), (32, 32));
    edit(&db, &admin, &node, |s| s.enabled = true);
    let mut b = agent(local, &origin, &node, None);
    until(|| {
        let n = &db.nodes(&admin).unwrap()[0];
        n.lease.generation == 2 && n.applied_revision == 1
    })
    .await;
    assert_eq!(exchange(listen, b"again").await, b"again");
    datagram(&udp, listen, b"ok").await;
    stop_agent(&mut b).await;
    assert_eq!(total(&db, &admin), 46);
    assert_eq!(db.config(&admin, &node, None).unwrap().revision, 1);
    stop_server(&mut http).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn expiry_stops_tcp_udp_during_control_outage_and_rejects_expired_restarts() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("controller.sqlite")).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let (node, enrollment) = strict(&db, &admin);
    recovery_budget(&db, &admin, 128);
    let token = temp.path().join("enrollment.secret");
    write_secret(&token, enrollment.as_bytes()).unwrap();
    let (echo, _udp_echo) = tcp_udp_echo().await;
    let mut r = rule(echo.address, Protocol::Both);
    r.owner_id = admin.id.clone();
    let listen = r.listen;
    db.set_config(&admin, &node, 0, vec![r]).unwrap();
    let mut http = server(
        api::router(AppState::new(db.clone())),
        "127.0.0.1:0".parse().unwrap(),
    )
    .await;
    let address = http.address;
    let origin = format!("http://{address}");
    let expires = now_ms() + 7000;
    edit(&db, &admin, &node, |s| s.expires_at_ms = Some(expires));
    let local = Store::open(&temp.path().join("agent.sqlite")).unwrap();
    let mut a = agent(local.clone(), &origin, &node, Some(token));
    until(|| db.nodes(&admin).unwrap()[0].applied_revision == 1).await;
    let mut stream = TcpStream::connect(listen).await.unwrap();
    let udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    persistent_exchange(&mut stream, b"warm").await;
    datagram(&udp, listen, b"warm").await;
    until(|| total(&db, &admin) == 16).await;
    sleep(Duration::from_millis(3700)).await;
    assert!(db.nodes(&admin).unwrap()[0].lease.remaining_ms < 4000);
    stop_server(&mut http).await;
    persistent_exchange(&mut stream, b"offline").await;
    datagram(&udp, listen, b"off").await;
    timeout(Duration::from_secs(6), async {
        loop {
            if TcpStream::connect(listen).await.is_err() {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    assert!(
        now_ms() <= expires + 250,
        "listener continued past the configured expiry"
    );
    stopped_connections(listen, &mut stream, &udp).await;
    assert!(
        timeout(Duration::from_secs(5), &mut a.task)
            .await
            .unwrap()
            .unwrap()
            .is_err()
    );
    if now_ms() < expires {
        sleep(Duration::from_millis((expires - now_ms()) as u64 + 10)).await;
    }
    let mut http = server(api::router(AppState::new(db.clone())), address).await;
    let original_run = local.metadata("agent_budget_run").unwrap();
    let mut expired = agent(local.clone(), &origin, &node, None);
    let error = timeout(Duration::from_secs(3), &mut expired.task)
        .await
        .unwrap()
        .unwrap()
        .unwrap_err();
    assert!(error.to_string().contains("410"));
    assert_eq!(local.metadata("agent_budget_run").unwrap(), original_run);
    assert!(TcpStream::connect(listen).await.is_err());
    assert_eq!(
        db.nodes(&admin).unwrap()[0].lifecycle,
        NodeLifecycle::Expired
    );
    edit(&db, &admin, &node, |s| s.expires_at_ms = None);
    let mut renewed = agent(local.clone(), &origin, &node, None);
    until(|| {
        let n = &db.nodes(&admin).unwrap()[0];
        n.lease.generation == 2 && n.applied_revision == 1
    })
    .await;
    assert_eq!(exchange(listen, b"renewed").await, b"renewed");
    stop_agent(&mut renewed).await;
    assert_eq!(total(&db, &admin), 50);
    let budget = &db.budgets(&admin).unwrap().budgets[0];
    assert_eq!((budget.consumed_bytes, budget.committed_bytes), (50, 50));
    stop_server(&mut http).await;
}
