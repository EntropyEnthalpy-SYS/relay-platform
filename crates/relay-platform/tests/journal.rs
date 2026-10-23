mod common;
use common::*;
use relay_platform::{
    budget::*,
    journal::{head_path, restore_controller},
    model::*,
    store::{Admission, Role, Store, secret},
};
use std::{
    fs,
    io::{Read, Seek, SeekFrom, Write},
};

fn logged(path: &std::path::Path) -> Store {
    let store = Store::open(&path.join("controller.sqlite")).unwrap();
    store
        .enable_recovery_log(&path.join("recovery.log"))
        .unwrap();
    store.set_kind("controller").unwrap();
    store
}

#[test]
fn restore_replays_credentials_configuration_budgets_and_usage_after_an_old_backup() {
    let tmp = tempfile::tempdir().unwrap();
    let store = logged(tmp.path());
    let admin = store.bootstrap(PASSWORD).unwrap();
    let budget = store
        .create_budget(
            &admin,
            NewBudget {
                scope: BudgetScope::User,
                scope_id: admin.id.clone(),
                name: "shared".into(),
                limit_bytes: 1000,
                quantum_bytes: 64,
            },
        )
        .unwrap();
    let backup = tmp.path().join("old.sqlite");
    store.backup(&backup).unwrap();
    let (node, enrollment) = store
        .create_node(&admin, "default", "created after snapshot")
        .unwrap();
    let credential = secret();
    store.enroll(&node.id, &enrollment, &credential).unwrap();
    let r = rule("127.0.0.1:9000".parse().unwrap(), Protocol::Both);
    let config = store
        .set_config(&admin, &node.id, 0, vec![r.clone()])
        .unwrap();
    let local = Store::open(&tmp.path().join("agent.sqlite")).unwrap();
    let page = store
        .reconcile(
            &node.id,
            ReconcileRequest {
                ledger_id: None,
                after: None,
                expected_revision: None,
            },
        )
        .unwrap();
    local.merge_checkpoint(&page, true).unwrap();
    local.save_agent_config(&config).unwrap();
    let run = local.start_budget_run().unwrap();
    let admission = |bytes| Admission {
        rule_id: r.id.clone(),
        meter_epoch: r.meter_epoch.clone(),
        upload: true,
        bytes,
        datagram: false,
    };
    local.admit_batch(&[admission(1)]).unwrap();
    for bytes in [40, 0] {
        let request = SyncRequest {
            ledger_id: page.ledger_id.clone(),
            budget: Some(local.budget_outbox(&run, true).unwrap()),
            need_config: false,
            applied_revision: 1,
            apply_error: None,
            usage: local.agent_usage(true).unwrap(),
            stats: EngineStats::default(),
        };
        let response = store.sync(&node.id, request).unwrap();
        local.acknowledge(&response.acknowledgements).unwrap();
        local
            .accept_budget_reply(&run, response.budget.unwrap())
            .unwrap();
        if bytes > 0 {
            assert_eq!(
                local.admit_batch(&[admission(bytes)]).unwrap(),
                vec![Some(bytes)]
            );
        }
    }
    let mut changed = r;
    changed.quota_bytes = Some(500);
    let desired = store
        .set_config(&admin, &node.id, 1, vec![changed])
        .unwrap();
    let user = store
        .create_user(&admin, "default", "new-user", PASSWORD, Role::Viewer)
        .unwrap();
    let (session, _) = store.login("new-user", PASSWORD).unwrap();
    store.revoke_sessions(&admin, &user.id).unwrap();
    let expected_budgets = serde_json::to_value(store.budgets(&admin).unwrap()).unwrap();
    let expected_usage = store.reported_usage(&admin).unwrap();
    let expected_head = store.recovery_log_status().unwrap().head.unwrap();
    assert!(
        restore_controller(
            &backup,
            &tmp.path().join("recovery.log"),
            &tmp.path().join("while-running")
        )
        .is_err()
    );
    drop(store);
    let output = tmp.path().join("restored");
    let report = restore_controller(&backup, &tmp.path().join("recovery.log"), &output).unwrap();
    assert_eq!(
        report.replayed_transactions,
        expected_head.sequence - report.backup_sequence
    );
    assert!(report.replayed_transactions > 0);
    assert!(!report.budget_allocation_paused);
    let restored = logged(&output);
    assert_eq!(
        restored.recovery_log_status().unwrap().head.unwrap(),
        expected_head
    );
    assert_eq!(restored.authenticate_node(&credential).unwrap(), node.id);
    assert!(restored.authenticate(&session).is_err());
    assert_eq!(
        serde_json::to_value(restored.config(&admin, &node.id, None).unwrap()).unwrap(),
        serde_json::to_value(desired).unwrap()
    );
    assert_eq!(
        serde_json::to_value(restored.budgets(&admin).unwrap()).unwrap(),
        expected_budgets
    );
    assert_eq!(restored.reported_usage(&admin).unwrap(), expected_usage);
    assert_eq!(
        restored.budgets(&admin).unwrap().budgets[0].consumed_bytes,
        40
    );
    restored
        .update_budget(
            &admin,
            &budget.id,
            BudgetUpdate {
                expected_revision: 1,
                limit_bytes: 1500,
                quantum_bytes: 64,
            },
        )
        .unwrap();
    assert_eq!(
        restored.budgets(&admin).unwrap().budgets[0].consumed_bytes,
        40
    );
}

#[test]
fn missing_corrupt_truncated_and_unrelated_logs_never_enable_restored_allocations() {
    let tmp = tempfile::tempdir().unwrap();
    let store = logged(tmp.path());
    store.bootstrap(PASSWORD).unwrap();
    let backup = tmp.path().join("backup.sqlite");
    store.backup(&backup).unwrap();
    let old_head = store.recovery_log_status().unwrap().head.unwrap();
    store.set_metadata("after-backup", "value").unwrap();
    drop(store);
    let source = tmp.path().join("recovery.log");
    let original = fs::read(&source).unwrap();
    let dest = tmp.path().join("output");
    let latest_head = fs::read(head_path(&source)).unwrap();
    fs::remove_file(head_path(&source)).unwrap();
    assert!(restore_controller(&backup, &source, &dest).is_err());
    assert!(!dest.exists());
    fs::write(head_path(&source), &latest_head).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(head_path(&source), fs::Permissions::from_mode(0o600)).unwrap();
    }
    let mut file = fs::OpenOptions::new()
        .write(true)
        .read(true)
        .open(&source)
        .unwrap();
    file.set_len(old_head.committed_bytes).unwrap();
    assert!(restore_controller(&backup, &source, &dest).is_err());
    assert!(!dest.exists());
    fs::write(&source, &original).unwrap();
    file.seek(SeekFrom::Start(190)).unwrap();
    let mut byte = [0];
    file.read_exact(&mut byte).unwrap();
    byte[0] ^= 1;
    file.seek(SeekFrom::Start(190)).unwrap();
    file.write_all(&byte).unwrap();
    assert!(restore_controller(&backup, &source, &dest).is_err());
    assert!(!dest.exists());
    fs::write(&source, &original).unwrap();
    let other = tempfile::tempdir().unwrap();
    let foreign = logged(other.path());
    foreign.bootstrap(PASSWORD).unwrap();
    drop(foreign);
    assert!(restore_controller(&backup, &other.path().join("recovery.log"), &dest).is_err());
    assert!(!dest.exists());
    fs::create_dir(&dest).unwrap();
    fs::write(dest.join("keep"), b"existing user data").unwrap();
    assert!(restore_controller(&backup, &source, &dest).is_err());
    assert_eq!(fs::read(dest.join("keep")).unwrap(), b"existing user data");
}

#[test]
fn manifest_io_failure_poisons_further_writes_and_restart_reconciles_the_commit() {
    let tmp = tempfile::tempdir().unwrap();
    let store = logged(tmp.path());
    store.bootstrap(PASSWORD).unwrap();
    let log = tmp.path().join("recovery.log");
    let head = head_path(&log);
    let saved = tmp.path().join("previous-head.json");
    fs::rename(&head, &saved).unwrap();
    fs::create_dir(&head).unwrap();
    assert!(
        store
            .set_metadata("uncertain", "durably committed")
            .is_err()
    );
    assert!(!store.recovery_log_status().unwrap().healthy);
    assert!(store.set_metadata("must-not-commit", "blocked").is_err());
    assert_eq!(store.metadata("must-not-commit").unwrap(), None);
    drop(store);
    fs::remove_dir(&head).unwrap();
    fs::rename(&saved, &head).unwrap();
    let store = logged(tmp.path());
    assert!(store.recovery_log_status().unwrap().healthy);
    assert_eq!(
        store.metadata("uncertain").unwrap().as_deref(),
        Some("durably committed")
    );
    store.set_metadata("resumed", "ok").unwrap();
}

#[test]
fn initialized_database_rejects_writes_without_its_log_and_stale_state_cannot_rebind() {
    let tmp = tempfile::tempdir().unwrap();
    let store = logged(tmp.path());
    store.bootstrap(PASSWORD).unwrap();
    let backup = tmp.path().join("backup.sqlite");
    store.backup(&backup).unwrap();
    store.set_metadata("new", "data").unwrap();
    drop(store);
    let plain = Store::open(&tmp.path().join("controller.sqlite")).unwrap();
    assert!(plain.set_metadata("bypass", "forbidden").is_err());
    drop(plain);
    let old = Store::open(&backup).unwrap();
    assert!(
        old.enable_recovery_log(&tmp.path().join("new-log"))
            .is_err()
    );
    assert!(
        old.enable_recovery_log(&tmp.path().join("recovery.log"))
            .is_err()
    );
    assert_eq!(old.metadata("new").unwrap(), None);
}

#[tokio::test]
async fn recovery_status_is_admin_only_and_failed_logging_is_unhealthy() {
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use relay_platform::api::{AppState, router};
    use tower::ServiceExt;
    let tmp = tempfile::tempdir().unwrap();
    let store = logged(tmp.path());
    let admin = store.bootstrap(PASSWORD).unwrap();
    store
        .create_user(&admin, "default", "viewer", PASSWORD, Role::Viewer)
        .unwrap();
    let (admin_token, _) = store.login("admin", PASSWORD).unwrap();
    let (viewer_token, _) = store.login("viewer", PASSWORD).unwrap();
    let app = router(AppState::new(store.clone()));
    for (token, expected) in [
        (None, StatusCode::UNAUTHORIZED),
        (Some(viewer_token), StatusCode::FORBIDDEN),
        (Some(admin_token), StatusCode::OK),
    ] {
        let mut request = Request::builder().uri("/api/v1/recovery");
        if let Some(token) = token {
            request = request.header("authorization", format!("Bearer {token}"));
        }
        assert_eq!(
            app.clone()
                .oneshot(request.body(Body::empty()).unwrap())
                .await
                .unwrap()
                .status(),
            expected
        );
    }
    assert_eq!(
        app.clone()
            .oneshot(
                Request::builder()
                    .uri("/healthz")
                    .body(Body::empty())
                    .unwrap()
            )
            .await
            .unwrap()
            .status(),
        StatusCode::OK
    );
    let head = head_path(&tmp.path().join("recovery.log"));
    fs::remove_file(&head).unwrap();
    fs::create_dir(&head).unwrap();
    assert!(store.set_metadata("failure", "injected").is_err());
    assert_eq!(
        app.oneshot(
            Request::builder()
                .uri("/healthz")
                .body(Body::empty())
                .unwrap()
        )
        .await
        .unwrap()
        .status(),
        StatusCode::SERVICE_UNAVAILABLE
    );
}

#[test]
fn empty_initialization_can_rebuild_its_head_but_committed_history_cannot() {
    let tmp = tempfile::tempdir().unwrap();
    let database = tmp.path().join("controller.sqlite");
    let log = tmp.path().join("recovery.log");
    let store = Store::open(&database).unwrap();
    store.enable_recovery_log(&log).unwrap();
    drop(store);
    fs::remove_file(head_path(&log)).unwrap();
    let store = Store::open(&database).unwrap();
    store.enable_recovery_log(&log).unwrap();
    assert_eq!(
        store.recovery_log_status().unwrap().head.unwrap().sequence,
        0
    );
    store.set_kind("controller").unwrap();
    drop(store);
    fs::remove_file(head_path(&log)).unwrap();
    let store = Store::open(&database).unwrap();
    assert!(store.enable_recovery_log(&log).is_err());
}
