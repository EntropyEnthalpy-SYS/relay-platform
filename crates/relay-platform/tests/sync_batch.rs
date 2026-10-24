mod common;
use common::*;
use relay_platform::{
    api::{self, AppState},
    budget::*,
    journal::{head_path, restore_controller},
    model::*,
    store::{Actor, Rejection, Role, Store, secret},
};
use std::fs;

struct Fixture {
    tmp: tempfile::TempDir,
    store: Store,
    admin: Actor,
    tokens: Vec<String>,
    nodes: Vec<String>,
    requests: Vec<serde_json::Value>,
}
impl Fixture {
    fn new(fail_second: bool) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("controller.sqlite");
        let store = Store::open(&path).unwrap();
        if fail_second {
            rusqlite::Connection::open(&path).unwrap().execute_batch("CREATE TRIGGER fail_second BEFORE INSERT ON usage WHEN NEW.rule_id='rule-1' BEGIN SELECT RAISE(ABORT,'injected storage failure'); END;").unwrap();
        }
        store
            .enable_recovery_log(&tmp.path().join("recovery.log"))
            .unwrap();
        store.set_kind("controller").unwrap();
        let admin = store.bootstrap(PASSWORD).unwrap();
        let budget = store
            .create_budget(
                &admin,
                NewBudget {
                    scope: BudgetScope::User,
                    scope_id: admin.id.clone(),
                    name: "shared".into(),
                    limit_bytes: 100,
                    quantum_bytes: 40,
                },
            )
            .unwrap();
        let (mut tokens, mut nodes, mut requests) = (vec![], vec![], vec![]);
        for i in 0..4 {
            let (node, enrollment) = store
                .create_node(&admin, "default", &format!("node-{i}"))
                .unwrap();
            let token = secret();
            store.enroll(&node.id, &enrollment, &token).unwrap();
            let mut r = rule("127.0.0.1:9000".parse().unwrap(), Protocol::Tcp);
            r.id = format!("rule-{i}");
            store
                .set_config(&admin, &node.id, 0, vec![r.clone()])
                .unwrap();
            let page = store
                .reconcile(
                    &node.id,
                    ReconcileRequest {
                        lease: None,
                        ledger_id: None,
                        after: None,
                        expected_revision: None,
                    },
                )
                .unwrap();
            requests.push(serde_json::json!({
                "ledger_id":page.ledger_id,"need_config":true,"applied_revision":1,"apply_error":null,
                "usage":[{"rule_id":r.id,"meter_epoch":r.meter_epoch,"sequence":1,"upload_bytes":i+1,"download_bytes":0}],
                "stats":EngineStats::default(),
                "budget":{"run_id":format!("run-{i}"),"settle_only":false,"requests":[{"budget_id":budget.id,"request_id":format!("request-{i}"),"minimum_bytes":1}],"reports":[]}
            }));
            tokens.push(token);
            nodes.push(node.id);
        }
        Self {
            tmp,
            store,
            admin,
            tokens,
            nodes,
            requests,
        }
    }
    fn input(&self, index: usize) -> (String, SyncRequest) {
        (
            self.tokens[index].clone(),
            serde_json::from_value(self.requests[index].clone()).unwrap(),
        )
    }
    fn sequence(&self) -> u64 {
        self.store
            .recovery_log_status()
            .unwrap()
            .head
            .unwrap()
            .sequence
    }
}
fn status(error: &anyhow::Error) -> u16 {
    error.downcast_ref::<Rejection>().unwrap().status
}

#[test]
fn batch_isolates_invalid_requests_and_restores_only_confirmed_changes() {
    let f = Fixture::new(false);
    let backup = f.tmp.path().join("backup.sqlite");
    f.store.backup(&backup).unwrap();
    let sequence = f.sequence();
    let mut bad = f.input(1);
    bad.1.budget.as_mut().unwrap().reports.push(GrantReport {
        grant_id: "unknown".into(),
        consumed_bytes: 1,
        surrender: false,
    });
    let mut unauthorized = f.input(2);
    unauthorized.0 = secret();
    let replies = f
        .store
        .sync_authenticated_batch(vec![f.input(0), bad, unauthorized, f.input(3)])
        .unwrap();
    assert_eq!(f.sequence(), sequence + 1);
    assert_eq!(status(replies[1].as_ref().unwrap_err()), 409);
    assert_eq!(status(replies[2].as_ref().unwrap_err()), 401);
    assert_eq!(
        replies[0]
            .as_ref()
            .unwrap()
            .config
            .as_ref()
            .unwrap()
            .node_id,
        f.nodes[0]
    );
    assert_eq!(
        replies[3]
            .as_ref()
            .unwrap()
            .config
            .as_ref()
            .unwrap()
            .node_id,
        f.nodes[3]
    );
    let usage = f.store.reported_usage(&f.admin).unwrap();
    assert_eq!(usage.len(), 2);
    assert_eq!(
        usage
            .iter()
            .map(|u| u["upload_bytes"].as_u64().unwrap())
            .sum::<u64>(),
        5
    );
    let budgets = serde_json::to_value(f.store.budgets(&f.admin).unwrap()).unwrap();
    assert_eq!(budgets["budgets"][0]["committed_bytes"], 80);
    drop(f.store);
    let output = f.tmp.path().join("restored");
    let report = restore_controller(&backup, &f.tmp.path().join("recovery.log"), &output).unwrap();
    assert_eq!(report.replayed_transactions, 1);
    let restored = Store::open(&output.join("controller.sqlite")).unwrap();
    restored
        .enable_recovery_log(&output.join("recovery.log"))
        .unwrap();
    assert_eq!(restored.reported_usage(&f.admin).unwrap(), usage);
    assert_eq!(
        serde_json::to_value(restored.budgets(&f.admin).unwrap()).unwrap(),
        budgets
    );
}

#[test]
fn duplicate_requests_share_the_same_grant_and_storage_failure_aborts_the_batch() {
    let f = Fixture::new(false);
    let replies = f
        .store
        .sync_authenticated_batch(vec![
            f.input(0),
            f.input(0),
            f.input(1),
            f.input(2),
            f.input(3),
        ])
        .unwrap();
    let ids: Vec<_> = replies
        .iter()
        .map(|r| {
            r.as_ref()
                .unwrap()
                .budget
                .as_ref()
                .unwrap()
                .grants
                .first()
                .map(|g| g.grant_id.clone())
        })
        .collect();
    assert_eq!(ids[0], ids[1]);
    assert_eq!(
        f.store.budgets(&f.admin).unwrap().budgets[0].committed_bytes,
        100
    );
    let failed = Fixture::new(true);
    let sequence = failed.sequence();
    assert!(
        failed
            .store
            .sync_authenticated_batch(vec![failed.input(0), failed.input(1)])
            .is_err()
    );
    assert_eq!(failed.sequence(), sequence);
    assert!(
        failed
            .store
            .reported_usage(&failed.admin)
            .unwrap()
            .is_empty()
    );
    assert_eq!(
        failed.store.budgets(&failed.admin).unwrap().budgets[0].committed_bytes,
        0
    );
}

#[test]
fn failed_journal_confirmation_never_returns_partial_batch_success_and_retries_are_idempotent() {
    let f = Fixture::new(false);
    let log = f.tmp.path().join("recovery.log");
    let head = head_path(&log);
    let saved = fs::read(&head).unwrap();
    fs::remove_file(&head).unwrap();
    fs::create_dir(&head).unwrap();
    assert!(
        f.store
            .sync_authenticated_batch(vec![f.input(0), f.input(1)])
            .is_err()
    );
    assert!(!f.store.recovery_log_status().unwrap().healthy);
    assert!(f.store.sync_authenticated_batch(vec![f.input(0)]).is_err());
    let expected = serde_json::to_value(f.store.budgets(&f.admin).unwrap()).unwrap();
    let inputs = vec![f.input(0), f.input(1)];
    drop(f.store);
    fs::remove_dir(&head).unwrap();
    fs::write(&head, saved).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(&head, fs::Permissions::from_mode(0o600)).unwrap();
    }
    let restored = Store::open(&f.tmp.path().join("controller.sqlite")).unwrap();
    restored.enable_recovery_log(&log).unwrap();
    assert!(
        restored
            .sync_authenticated_batch(inputs)
            .unwrap()
            .iter()
            .all(|r| r.is_ok())
    );
    assert_eq!(
        serde_json::to_value(restored.budgets(&f.admin).unwrap()).unwrap(),
        expected
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_coalesces_requests_preserves_response_identity_and_restricts_metrics() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use http_body_util::BodyExt;
    use tower::ServiceExt;
    let f = Fixture::new(false);
    f.store
        .create_user(&f.admin, "default", "viewer", PASSWORD, Role::Viewer)
        .unwrap();
    let (admin, _) = f.store.login("admin", PASSWORD).unwrap();
    let (viewer, _) = f.store.login("viewer", PASSWORD).unwrap();
    let app = api::router(AppState::new(f.store.clone()));
    let sequence = f.sequence();
    let mut tasks = tokio::task::JoinSet::new();
    for i in 0..4 {
        let router = app.clone();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/agent/sync")
            .header("authorization", format!("Bearer {}", f.tokens[i]))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&f.requests[i]).unwrap()))
            .unwrap();
        tasks.spawn(async move {
            let response = router.oneshot(request).await.unwrap();
            assert_eq!(response.status(), StatusCode::OK);
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            (i, serde_json::from_slice::<SyncResponse>(&bytes).unwrap())
        });
    }
    while let Some(result) = tasks.join_next().await {
        let (index, response) = result.unwrap();
        assert_eq!(response.config.unwrap().node_id, f.nodes[index]);
        for grant in response.budget.unwrap().grants {
            assert_eq!(grant.request_id, format!("request-{index}"));
        }
    }
    for (token, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some(&viewer), StatusCode::FORBIDDEN),
        (Some(&admin), StatusCode::OK),
    ] {
        let mut request = Request::builder().uri("/api/v1/control/metrics");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        let response = app
            .clone()
            .oneshot(request.body(Body::empty()).unwrap())
            .await
            .unwrap();
        assert_eq!(response.status(), expected);
        if expected == StatusCode::OK {
            let bytes = response.into_body().collect().await.unwrap().to_bytes();
            let metrics: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
            assert_eq!(metrics["processed_requests"], 4);
            assert_eq!(metrics["queue_time"]["samples"], 4);
            assert_eq!(metrics["request_time"]["samples"], 4);
            assert_eq!(
                metrics["storage_batch_time"]["samples"],
                metrics["committed_batches"]
            );
            for phase in ["queue_time", "storage_batch_time", "request_time"] {
                assert!(metrics[phase]["max_us"].as_u64().unwrap() > 0);
                assert!(
                    metrics[phase]["total_us"].as_u64().unwrap()
                        >= metrics[phase]["max_us"].as_u64().unwrap()
                );
            }
            assert!(metrics["largest_batch"].as_u64().unwrap() >= 2);
            assert_eq!(
                f.sequence() - sequence,
                metrics["committed_batches"].as_u64().unwrap()
            );
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_overload_is_bounded_and_duplicate_retries_do_not_multiply_credit() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::ServiceExt;
    let f = Fixture::new(false);
    let app = api::router(AppState::new(f.store.clone()));
    let barrier = std::sync::Arc::new(tokio::sync::Barrier::new(129));
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..128 {
        let router = app.clone();
        let gate = barrier.clone();
        let request = Request::builder()
            .method("POST")
            .uri("/api/v1/agent/sync")
            .header("authorization", format!("Bearer {}", f.tokens[0]))
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_vec(&f.requests[0]).unwrap()))
            .unwrap();
        tasks.spawn(async move {
            gate.wait().await;
            router.oneshot(request).await.unwrap().status()
        });
    }
    barrier.wait().await;
    let (mut accepted, mut busy) = (0, 0);
    while let Some(result) = tasks.join_next().await {
        match result.unwrap() {
            StatusCode::OK => accepted += 1,
            StatusCode::TOO_MANY_REQUESTS => busy += 1,
            status => panic!("unexpected overload response: {status}"),
        }
    }
    assert_eq!(accepted + busy, 128);
    assert!(accepted > 0 && busy > 0);
    assert_eq!(
        f.store.budgets(&f.admin).unwrap().budgets[0].committed_bytes,
        40
    );
    assert_eq!(f.store.reported_usage(&f.admin).unwrap().len(), 1);
    let retry = f.store.sync_authenticated_batch(vec![f.input(0)]).unwrap();
    assert!(retry[0].is_ok());
    assert_eq!(
        f.store.budgets(&f.admin).unwrap().budgets[0].committed_bytes,
        40
    );
}
