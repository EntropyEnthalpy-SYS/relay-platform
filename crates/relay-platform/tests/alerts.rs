mod common;
use axum::{Router, extract::State, http::HeaderMap, routing::post};
use common::*;
use relay_platform::{
    agent::{self, AgentOptions},
    alerts,
    api::{self, AppState},
    model::*,
    store::{Role, Scope, Store, write_secret},
};
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    net::TcpListener,
    sync::mpsc,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;

type Received = (Option<String>, String);

async fn receiver() -> (SocketAddr, mpsc::UnboundedReceiver<Received>) {
    let (sender, received) = mpsc::unbounded_channel();
    let router = Router::new()
        .route(
            "/hook",
            post(
                |State(sender): State<mpsc::UnboundedSender<Received>>,
                 headers: HeaderMap,
                 body: String| async move {
                    let signature = headers
                        .get("x-relay-signature")
                        .map(|v| v.to_str().unwrap().to_owned());
                    sender.send((signature, body)).unwrap();
                    "ok"
                },
            ),
        )
        .with_state(sender);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (address, received)
}

/// The text of the next notice, after checking its signature.
async fn next(received: &mut mpsc::UnboundedReceiver<Received>) -> String {
    let (signature, body) = timeout(Duration::from_secs(10), received.recv())
        .await
        .expect("no notice arrived")
        .unwrap();
    let tag = hex(ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"hook-secret"),
        body.as_bytes(),
    )
    .as_ref());
    assert_eq!(signature, Some(format!("sha256={tag}")));
    serde_json::from_str::<Value>(&body).unwrap()["text"]
        .as_str()
        .unwrap()
        .to_owned()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn target_outages_notify_once_per_incident_through_signed_webhooks() {
    let temp = tempfile::tempdir().unwrap();
    let control = Store::open(&temp.path().join("controller.db")).unwrap();
    control.set_kind("controller").unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    let operator = control
        .create_user(&admin, "default", "operator", PASSWORD, Role::TenantAdmin)
        .unwrap();
    let (session, _) = control.login("admin", PASSWORD).unwrap();
    let (operator_session, _) = control.login(&operator.username, PASSWORD).unwrap();
    let (api_token, _) = control
        .create_api_token(&admin, "automation", &[Scope::Read, Scope::NodesWrite], 1)
        .unwrap();

    let stop = CancellationToken::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let router = api::router(AppState::new(control.clone()).with_shutdown(stop.clone()));
    let shutdown = stop.clone();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await
        .unwrap()
    });
    tokio::spawn(alerts::run(
        control.clone(),
        Duration::from_millis(100),
        stop.clone(),
    ));
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let api = |path: &str| format!("{origin}/api/v1/{path}");

    // Only system administrators, in an interactive session, manage alerts.
    let status = |r: reqwest::Response| r.status().as_u16();
    let hook = receiver().await;
    let (hook_address, mut received) = hook;
    let channel = json!({"name":"ops","enabled":true,"min_severity":"warning",
        "target":{"kind":"webhook","url":format!("http://{hook_address}/hook"),"secret":"hook-secret"}});
    let get = client.get(api("alerts"));
    assert_eq!(
        status(get.bearer_auth(&operator_session).send().await.unwrap()),
        200
    );
    let post = client.post(api("alerts/channels")).json(&channel);
    assert_eq!(
        status(post.bearer_auth(&api_token).send().await.unwrap()),
        403
    );
    let created: Value = client
        .post(api("alerts/channels"))
        .bearer_auth(&session)
        .json(&channel)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(created["destination"], "http://127.0.0.1/…");
    assert_eq!(created["secret_set"], true);
    let id = created["id"].as_str().unwrap().to_owned();
    let overview = client
        .get(api("alerts"))
        .bearer_auth(&session)
        .send()
        .await
        .unwrap();
    assert!(!overview.text().await.unwrap().contains("hook-secret"));

    // An edit that leaves the secret blank keeps it; the test message proves it.
    let mut edited = channel.clone();
    edited["name"] = "ops-primary".into();
    edited["target"]["secret"] = "".into();
    let put = client
        .put(api(&format!("alerts/channels/{id}")))
        .json(&edited);
    assert_eq!(status(put.bearer_auth(&session).send().await.unwrap()), 200);
    let test = client.post(api(&format!("alerts/channels/{id}/test")));
    assert_eq!(
        status(test.bearer_auth(&session).send().await.unwrap()),
        200
    );
    assert!(next(&mut received).await.contains("【测试】"));

    // A real agent forwards to a backend that fails and recovers.
    let echo = tcp_echo().await;
    let backend = echo.address;
    let (node, enrollment) = control.create_node(&admin, "default", "edge-01").unwrap();
    let mut r = rule(backend, Protocol::Tcp);
    r.health_check = Some(
        serde_json::from_value(json!({
            "interval_ms":100, "timeout_ms":60, "healthy_threshold":2,
            "unhealthy_threshold":2, "recovery_delay_ms":250, "max_age_ms":1000,
            "tcp":{"kind":"exchange","request_base64":"UElORw==","expected_base64":"UElORw==","half_close":true}
        }))
        .unwrap(),
    );
    control.set_config(&admin, &node.id, 0, vec![r]).unwrap();
    let secret_path = temp.path().join("enroll.secret");
    write_secret(&secret_path, enrollment.as_bytes()).unwrap();
    let agent_db = Store::open(&temp.path().join("agent.db")).unwrap();
    tokio::spawn(agent::run(
        agent_db,
        AgentOptions {
            controller: origin.clone(),
            node_id: node.id.clone(),
            enrollment_token_file: Some(secret_path),
            ca_certificate: None,
            tls_directory: None,
            poll_interval: Duration::from_millis(50),
            controller_addresses: vec![],
            controller_proxy: None,
        },
        stop.clone(),
    ));
    let incidents = || async {
        client
            .get(api("alerts"))
            .bearer_auth(&session)
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()["incidents"]
            .clone()
    };
    let restart = |address: SocketAddr| async move {
        // The aborted echo task releases its port shortly after the drop.
        for _ in 0..100 {
            if let Ok(listener) = TcpListener::bind(address).await {
                drop(listener);
                return tcp_echo_at(&address.to_string(), None).await;
            }
            sleep(Duration::from_millis(20)).await;
        }
        panic!("backend port never came free");
    };
    sleep(Duration::from_millis(800)).await;
    drop(echo);
    let opened = next(&mut received).await;
    assert!(opened.starts_with("【告警·警告】edge-01"), "{opened}");
    assert!(opened.contains(&backend.to_string()), "{opened}");
    let echo = restart(backend).await;
    let resolved = next(&mut received).await;
    assert!(resolved.starts_with("【已恢复】edge-01"), "{resolved}");

    // The same failure again within the hold is one incident and stays quiet.
    drop(echo);
    timeout(Duration::from_secs(10), async {
        while incidents().await["open"][0]["repeats"] != 1 {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the repeated failure never reopened the incident");
    let _echo = restart(backend).await;
    timeout(Duration::from_secs(10), async {
        while incidents().await["open"] != json!([]) {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the incident never resolved");
    sleep(Duration::from_millis(500)).await;
    assert!(received.try_recv().is_err(), "a held repeat was announced");

    let log = incidents().await["deliveries"].clone();
    let kinds: Vec<_> = log
        .as_array()
        .unwrap()
        .iter()
        .map(|d| (d["notice"].as_str().unwrap(), d["status"].as_str().unwrap()))
        .collect();
    assert_eq!(
        kinds,
        [("resolved", "sent"), ("opened", "sent"), ("test", "sent")]
    );

    // Rules come with defaults, all off, and are saved by system
    // administrators only, within their limits.
    let settings = || async {
        client
            .get(api("alerts"))
            .bearer_auth(&session)
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()["settings"]
            .clone()
    };
    let defaults = settings().await["rules"].clone();
    assert_eq!(
        defaults["node_cpu"],
        json!({"enabled": false, "threshold": 90, "checks": 5})
    );
    assert_eq!(
        defaults["dns_sync_failed"],
        json!({"enabled": false, "checks": 1})
    );
    let mut rules = defaults.clone();
    rules["node_cpu"] = json!({"enabled": false, "threshold": 75, "checks": 2});
    let save = |body: Value, token: &str| {
        client
            .put(api("alerts/settings"))
            .bearer_auth(token)
            .json(&body)
            .send()
    };
    assert_eq!(
        status(
            save(json!({"rules": rules}), &operator_session)
                .await
                .unwrap()
        ),
        403
    );
    let mut broken = rules.clone();
    broken["budget_near"]["threshold"] = 0.into();
    assert_eq!(
        status(save(json!({"rules": broken}), &session).await.unwrap()),
        400
    );
    assert_eq!(
        status(save(json!({"rules": rules}), &session).await.unwrap()),
        200
    );

    // Maintenance settings round-trip without touching the saved rules;
    // deleting the channel stops deliveries.
    let until = json!(4_102_444_799_000_i64);
    let put = client
        .put(api("alerts/settings"))
        .json(&json!({"maintenance_until_ms": until}));
    assert_eq!(status(put.bearer_auth(&session).send().await.unwrap()), 200);
    assert_eq!(
        settings().await,
        json!({"maintenance_until_ms": until, "rules": rules})
    );
    let delete = client.delete(api(&format!("alerts/channels/{id}")));
    assert_eq!(
        status(delete.bearer_auth(&session).send().await.unwrap()),
        200
    );
    let test = client.post(api(&format!("alerts/channels/{id}/test")));
    assert_eq!(
        status(test.bearer_auth(&session).send().await.unwrap()),
        404
    );
    stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn resource_alerts_need_consecutive_reports_and_resolve_on_their_own() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("controller.db")).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let (node, token) = db.create_node(&admin, "default", "edge-busy").unwrap();
    db.enroll(&node.id, &token, &relay_platform::store::secret())
        .unwrap();
    let ledger = db
        .reconcile(
            &node.id,
            ReconcileRequest {
                lease: None,
                ledger_id: None,
                after: None,
                expected_revision: None,
            },
        )
        .unwrap()
        .ledger_id;
    let (hook, mut received) = receiver().await;
    db.save_alert_channel(
        &admin,
        None,
        alerts::Channel {
            tenant_id: None,
            id: String::new(),
            name: "ops".into(),
            enabled: true,
            min_severity: relay_platform::telemetry::Severity::Warning,
            target: alerts::Target::Webhook {
                url: format!("http://{hook}/hook"),
                secret: "hook-secret".into(),
            },
        },
    )
    .unwrap();
    let rules = |cpu: bool| alerts::Rules {
        node_cpu: alerts::Rule {
            enabled: cpu,
            threshold: Some(80),
            checks: 3,
        },
        node_memory: alerts::Rule {
            enabled: true,
            threshold: Some(90),
            checks: 2,
        },
        ..alerts::Rules::default()
    };
    db.set_alert_settings(
        &admin,
        alerts::Settings {
            maintenance_until_ms: None,
            rules: Some(rules(true)),
        },
    )
    .unwrap();
    let stop = CancellationToken::new();
    let worker = tokio::spawn(alerts::run(
        db.clone(),
        Duration::from_millis(20),
        stop.clone(),
    ));
    // One agent report, then time for the worker to look at it several times.
    let report = |cpu: f32, available: u64| {
        let db = db.clone();
        let (node, ledger) = (node.id.clone(), ledger.clone());
        async move {
            db.sync(
                &node,
                SyncRequest {
                    logs: None,
                    lease: None,
                    budget: None,
                    ledger_id: ledger,
                    need_config: false,
                    applied_revision: 0,
                    apply_error: None,
                    usage: vec![],
                    stats: EngineStats {
                        system: Some(relay_platform::system::SystemStats {
                            cpu_percent: Some(cpu),
                            memory_total_bytes: Some(1000),
                            memory_available_bytes: Some(available),
                            cpus: 2,
                            ..Default::default()
                        }),
                        ..EngineStats::default()
                    },
                },
            )
            .unwrap();
            sleep(Duration::from_millis(200)).await;
        }
    };
    let open = || {
        let mut kinds: Vec<String> = db
            .alerts()
            .snapshot()
            .open
            .iter()
            .map(|i| i.key.split(':').next().unwrap().to_owned())
            .collect();
        kinds.sort();
        kinds
    };

    // Two reports over 80 % CPU, then one under: nothing yet. Memory is at 50 %.
    report(95.0, 500).await;
    report(95.0, 500).await;
    assert!(open().is_empty(), "{:?}", open());
    report(79.0, 500).await;
    report(95.0, 500).await;
    report(95.0, 500).await;
    assert!(
        open().is_empty(),
        "the count starts again after a low report"
    );
    // The third report in a row opens CPU; memory needs a second one at 95 %.
    report(95.0, 50).await;
    assert_eq!(open(), ["cpu"]);
    report(95.0, 50).await;
    assert_eq!(open(), ["cpu", "memory"]);
    let mut opened = String::new();
    while !(opened.contains("CPU 使用率 95%") && opened.contains("内存使用率 95%")) {
        opened += &next(&mut received).await;
    }
    assert!(opened.contains("edge-busy"), "{opened}");

    // Back under both thresholds: both resolve and the recovery is sent.
    report(10.0, 900).await;
    assert!(open().is_empty());
    let mut resolved = String::new();
    while !(resolved.contains("CPU 使用率回落到 10%") && resolved.contains("内存使用率回落到 10%"))
    {
        resolved += &next(&mut received).await;
    }
    assert!(resolved.starts_with("【已恢复】"), "{resolved}");

    // A switched-off rule opens nothing however long the problem lasts.
    db.set_alert_settings(
        &admin,
        alerts::Settings {
            maintenance_until_ms: None,
            rules: Some(rules(false)),
        },
    )
    .unwrap();
    for _ in 0..5 {
        report(99.0, 900).await;
    }
    assert!(open().is_empty(), "{:?}", open());
    stop.cancel();
    worker.await.unwrap();
}
