mod common;
use common::{PASSWORD, rule};
use relay_platform::{
    api::{self, AppState},
    health::{ProbeKind, Status, TargetHealthReport},
    model::{EngineStats, Protocol},
    store::Store,
};
use serde_json::{Value, json};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

async fn serve(store: Store) -> (SocketAddr, CancellationToken) {
    let stop = CancellationToken::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = api::router(AppState::new(store).with_shutdown(stop.clone()));
    let shutdown = stop.clone();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await
        .unwrap();
    });
    (address, stop)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn prometheus_metrics_expose_node_counters_to_a_viewer() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let budget = store
        .create_budget(
            &admin,
            relay_platform::budget::NewBudget {
                scope: relay_platform::budget::BudgetScope::Tenant,
                scope_id: "default".into(),
                name: "metrics-budget".into(),
                limit_bytes: 10_000,
                quantum_bytes: 1_000,
            },
        )
        .unwrap();
    let budget_id = budget.id.clone();
    let (node, _) = store
        .create_node(&admin, "default", "metrics-node")
        .unwrap();
    let node_id = node.id.clone();
    let revision = store.set_config(&admin, &node.id, 0, vec![]).unwrap();
    store
        .set_config(
            &admin,
            &node.id,
            revision.revision,
            vec![rule("127.0.0.1:9".parse().unwrap(), Protocol::Tcp)],
        )
        .unwrap();
    store
        .create_user(
            &admin,
            "default",
            "viewer",
            PASSWORD,
            relay_platform::store::Role::Viewer,
        )
        .unwrap();
    let db_path = temp.path().join("controller.db");
    let report = TargetHealthReport {
        probe_kind: ProbeKind::TcpConnect,
        rule_id: "rule-metrics".into(),
        target_index: 0,
        listen_port: 9000,
        protocol: Protocol::Tcp,
        target_address: "127.0.0.1:9".into(),
        status: Status::Healthy,
        eligible: true,
        selection_reason: "fixture".into(),
        sample_age_ms: Some(10),
        max_age_ms: 30_000,
        checked_at_ms: Some(1),
        latency_ewma_us: Some(1500),
        window_checks: 5,
        window_failures: 1,
        jitter_us: Some(100),
        consecutive_successes: 4,
        consecutive_failures: 0,
        completed_checks: 5,
        successful_checks: 4,
        last_error: None,
        probe_sent_bytes: 100,
        probe_received_bytes: 200,
        priority: 0,
        active_sessions: 2,
        max_sessions: None,
    };
    let stats = EngineStats {
        target_health: vec![report],
        meter: Some(relay_platform::metrics::MeterStats {
            admission_batches: relay_platform::metrics::TimingStats {
                samples: 1,
                total_us: 20,
                max_us: 20,
            },
            admission_requests: 3,
            failed_batches: 0,
            budget_wait: relay_platform::metrics::TimingStats::default(),
            budget_waiting: 0,
            budget_timeouts: 0,
        }),
        budget_recovery: Some(relay_platform::budget::BudgetRecoveryStats {
            run_id: "fixture".into(),
            at_ms: 1,
            validated_grants: 2,
            recovered_pending_grants: 1,
            cancelled_requests: 0,
            open_grants: 1,
        }),
        system: Some(relay_platform::system::SystemStats {
            cpu_percent: Some(12.5),
            rss_bytes: Some(4096),
            ..Default::default()
        }),
        multipath: Some(relay_platform::multipath::Stats {
            active_sessions: 1,
            active_paths: 2,
            delivered_payload_bytes: 4096,
            ..Default::default()
        }),
        ..Default::default()
    };
    let conn = rusqlite::Connection::open(&db_path).unwrap();
    conn.execute(
        "UPDATE nodes SET stats_json=?1 WHERE id=?2",
        rusqlite::params![serde_json::to_string(&stats).unwrap(), node_id],
    )
    .unwrap();
    let (address, stop) = serve(store).await;
    let origin = format!("http://{address}");
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let login: Value = client
        .post(format!("{origin}/api/v1/auth/login"))
        .json(&json!({"username": "viewer", "password": PASSWORD}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = login["token"].as_str().unwrap();
    let response = client
        .get(format!("{origin}/api/v1/metrics"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert!(
        response.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    let body = response.text().await.unwrap();
    assert!(body.contains("relay_build_info{version=\""));
    assert!(body.contains(&format!("relay_node_up{{node=\"{node_id}\"")));
    assert!(body.contains(&format!("relay_node_active_tcp{{node=\"{node_id}\"}} 0")));
    assert!(body.contains(&format!("relay_node_active_udp{{node=\"{node_id}\"}} 0")));
    assert!(body.contains(&format!(
        "relay_node_accepted_tcp_total{{node=\"{node_id}\"}} 0"
    )));
    assert!(body.contains(&format!(
        "relay_budget{{budget=\"{budget_id}\",tenant=\"default\",scope=\"tenant\",scope_id=\"default\",kind=\"limit_bytes\"}} 10000"
    )));
    stop.cancel();
}
