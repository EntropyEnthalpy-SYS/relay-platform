mod common;
use common::*;
use relay_platform::{
    model::*,
    store::{Admission, Rejection, Store},
};

fn request() -> ReconcileRequest {
    ReconcileRequest {
        ledger_id: None,
        after: None,
        expected_revision: None,
    }
}
fn sync_request(ledger: &str, usage: Vec<Usage>) -> SyncRequest {
    SyncRequest {
        ledger_id: ledger.into(),
        need_config: false,
        applied_revision: 1,
        apply_error: None,
        usage,
        stats: EngineStats::default(),
    }
}
fn usage(rule: &Rule, sequence: u64, upload: u64, download: u64) -> Usage {
    Usage {
        rule_id: rule.id.clone(),
        meter_epoch: rule.meter_epoch.clone(),
        sequence,
        upload_bytes: upload,
        download_bytes: download,
    }
}
fn admission(rule: &Rule, bytes: usize) -> Admission {
    Admission {
        rule_id: rule.id.clone(),
        meter_epoch: rule.meter_epoch.clone(),
        upload: true,
        bytes,
        datagram: false,
    }
}
fn fixture() -> (tempfile::TempDir, Store, Store, String, Rule) {
    let tmp = tempfile::tempdir().unwrap();
    let controller = Store::open(&tmp.path().join("control.db")).unwrap();
    let admin = controller.bootstrap(PASSWORD).unwrap();
    let (node, _) = controller
        .create_node(&admin, "default", "recovery")
        .unwrap();
    let rule = rule("127.0.0.1:8888".parse().unwrap(), Protocol::Tcp);
    let config = controller
        .set_config(&admin, &node.id, 0, vec![rule.clone()])
        .unwrap();
    let agent = Store::open(&tmp.path().join("agent.db")).unwrap();
    agent.save_agent_config(&config).unwrap();
    (tmp, controller, agent, node.id, rule)
}

#[test]
fn checkpoint_raises_stale_backup_and_lower_controller_checkpoint_replays_local_totals() {
    let (_tmp, control, agent, node, rule) = fixture();
    let page = control.reconcile(&node, request()).unwrap();
    agent.merge_checkpoint(&page, true).unwrap();
    agent.admit_batch(&[admission(&rule, 7)]).unwrap();
    let ack = control
        .sync(
            &node,
            sync_request(&page.ledger_id, agent.agent_usage(true).unwrap()),
        )
        .unwrap();
    agent.acknowledge(&ack.acknowledgements).unwrap();
    assert!(agent.agent_usage(true).unwrap().is_empty());
    control
        .sync(
            &node,
            sync_request(&page.ledger_id, vec![usage(&rule, 4, 50, 30)]),
        )
        .unwrap();
    let higher = control.reconcile(&node, request()).unwrap();
    assert!(
        agent.merge_checkpoint(&higher, false).is_err(),
        "a running agent cannot raise counters under in-flight admissions"
    );
    assert_eq!(agent.agent_usage(false).unwrap()[0].upload_bytes, 7);
    agent.begin_reconcile().unwrap();
    agent.merge_checkpoint(&higher, true).unwrap();
    assert_eq!(agent.agent_usage(false).unwrap()[0].download_bytes, 30);
    assert!(agent.agent_usage(true).unwrap().is_empty());
    // Simulate a controller restored to its earlier acknowledged checkpoint.
    let mut older = higher.clone();
    older.usage = vec![usage(&rule, 1, 7, 0)];
    agent.begin_reconcile().unwrap();
    agent.merge_checkpoint(&older, true).unwrap();
    let pending = agent.agent_usage(true).unwrap();
    assert_eq!(pending[0].sequence, 4);
    assert_eq!(pending[0].upload_bytes, 50);
    // Completely forgotten rows must also be resent, despite prior acknowledgement.
    agent.begin_reconcile().unwrap();
    agent.merge_checkpoint(&page, true).unwrap();
    assert_eq!(agent.agent_usage(true).unwrap()[0].sequence, 4);
}

#[test]
fn conflicting_page_rolls_back_all_rows_and_never_changes_identity() {
    let (_tmp, control, agent, node, rule) = fixture();
    let mut page = control.reconcile(&node, request()).unwrap();
    agent.merge_checkpoint(&page, true).unwrap();
    agent.admit_batch(&[admission(&rule, 7)]).unwrap();
    let mut historical = usage(&rule, 3, 8, 0);
    historical.rule_id = "a-retired-rule".into();
    page.usage = vec![historical, usage(&rule, 1, 8, 0)];
    assert!(agent.merge_checkpoint(&page, true).is_err());
    let rows = agent.agent_usage(false).unwrap();
    assert_eq!(
        rows.len(),
        1,
        "earlier rows of a rejected page must roll back"
    );
    assert_eq!(rows[0].upload_bytes, 7);
    page.usage = vec![usage(&rule, 2, 6, 0)];
    assert!(
        agent.merge_checkpoint(&page, true).is_err(),
        "higher sequence with lower totals is a fork"
    );
    page.usage.clear();
    page.ledger_id = "another-ledger".into();
    assert!(agent.merge_checkpoint(&page, true).is_err());
    let bad = control
        .sync(&node, sync_request("another-ledger", vec![]))
        .unwrap_err();
    assert_eq!(bad.downcast_ref::<Rejection>().unwrap().status, 409);
}

#[test]
fn historical_checkpoints_paginate_past_sync_limit_and_revision_changes_invalidate_cursor() {
    let (tmp, control, agent, node, rule) = fixture();
    // Populate a realistic retired-period history in one fixture transaction.
    // Reconciliation itself uses the public Store API and real SQLite queries.
    let mut db = rusqlite::Connection::open(tmp.path().join("control.db")).unwrap();
    let tx = db.transaction().unwrap();
    for n in 0..1100 {
        let epoch = format!("epoch-{n:04}");
        tx.execute(
            "INSERT INTO rule_epochs(rule_id,meter_epoch) VALUES(?1,?2)",
            rusqlite::params![rule.id, epoch],
        )
        .unwrap();
        tx.execute("INSERT INTO usage(node_id,rule_id,meter_epoch,sequence,upload_bytes,download_bytes,reported_at_ms) VALUES(?1,?2,?3,1,17,19,0)", rusqlite::params![node,rule.id,epoch]).unwrap();
    }
    tx.commit().unwrap();
    let mut query = request();
    let mut total = 0;
    let mut pages = 0;
    let first = control.reconcile(&node, query.clone()).unwrap();
    assert_eq!(first.usage.len(), 256);
    let ledger = first.ledger_id.clone();
    loop {
        let page = control.reconcile(&node, query.clone()).unwrap();
        total += page.usage.len();
        pages += 1;
        agent.merge_checkpoint(&page, true).unwrap();
        if page.next.is_none() {
            assert_eq!(page.config.unwrap().node_id, node);
            break;
        }
        assert!(page.config.is_none());
        query = ReconcileRequest {
            ledger_id: Some(page.ledger_id),
            after: page.next,
            expected_revision: Some(page.revision),
        };
    }
    assert_eq!(total, 1100);
    assert_eq!(agent.agent_usage(false).unwrap().len(), 1100);
    assert_eq!(pages, 5);
    assert!(agent.agent_usage(true).unwrap().is_empty());
    // A rolled-back controller forgot all 1100 rows; drain all pending sync batches.
    agent.begin_reconcile().unwrap();
    let mut replayed = 0;
    loop {
        let batch = agent.agent_usage(true).unwrap();
        if batch.is_empty() {
            break;
        }
        replayed += batch.len();
        let result = control.sync(&node, sync_request(&ledger, batch)).unwrap();
        agent.acknowledge(&result.acknowledgements).unwrap();
    }
    assert_eq!(replayed, 1100);
    let (_, admin) = control.login("admin", PASSWORD).unwrap();
    control.set_config(&admin, &node, 1, vec![]).unwrap();
    let error = control
        .reconcile(
            &node,
            ReconcileRequest {
                ledger_id: Some(ledger),
                after: first.next,
                expected_revision: Some(1),
            },
        )
        .unwrap_err();
    assert_eq!(error.downcast_ref::<Rejection>().unwrap().status, 412);
}

#[test]
fn only_exported_managed_backup_requires_recovery_and_lock_is_exclusive() {
    let (tmp, control, agent, node, _) = fixture();
    let page = control.reconcile(&node, request()).unwrap();
    agent
        .set_metadata("agent_credential", "fixture-private-credential")
        .unwrap();
    agent.merge_checkpoint(&page, true).unwrap();
    agent.finish_reconcile().unwrap();
    let lock = agent.lock_instance().unwrap();
    assert!(agent.lock_instance().is_err());
    let reopened = Store::open(&tmp.path().join("agent.db")).unwrap();
    assert!(reopened.lock_instance().is_err());
    let backup_path = tmp.path().join("backup.db");
    agent.backup(&backup_path).unwrap();
    assert!(!agent.recovery_required().unwrap());
    let backup = Store::open(&backup_path).unwrap();
    assert!(backup.recovery_required().unwrap());
    assert!(backup.metadata("backup_created_at_ms").unwrap().is_some());
    drop(lock);
    reopened.lock_instance().unwrap();
    assert!(
        agent.backup(&backup_path).is_err(),
        "backups must never overwrite an existing destination"
    );
}

#[test]
fn v1_managed_database_migrates_without_silently_reopening_old_quotas() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("legacy.db");
    let legacy = rusqlite::Connection::open(&path).unwrap();
    legacy
        .execute_batch(include_str!("../src/schema.sql"))
        .unwrap();
    legacy.execute_batch("PRAGMA user_version=1; INSERT INTO metadata VALUES('agent_credential','old-private-credential'); INSERT INTO agent_meters VALUES('old-rule','period',0,NULL,NULL,7,7,23,29);").unwrap();
    drop(legacy);
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let migrated = Store::open(&path).unwrap();
    assert!(migrated.recovery_required().unwrap());
    let usage = migrated.agent_usage(false).unwrap();
    assert_eq!(usage[0].sequence, 7);
    assert_eq!(usage[0].upload_bytes + usage[0].download_bytes, 52);
    drop(migrated);
    let reopened = Store::open(&path).unwrap();
    assert!(reopened.recovery_required().unwrap());
}

#[test]
fn unrelated_and_future_databases_are_rejected_without_schema_migration() {
    let tmp = tempfile::tempdir().unwrap();
    let path = tmp.path().join("unrelated.db");
    let db = rusqlite::Connection::open(&path).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    db.execute_batch(
        "CREATE TABLE personal_notes(id INTEGER); INSERT INTO personal_notes VALUES(42);",
    )
    .unwrap();
    assert!(Store::open(&path).is_err());
    assert_eq!(
        db.query_row("SELECT id FROM personal_notes", [], |row| row
            .get::<_, u64>(0))
            .unwrap(),
        42
    );
    db.execute_batch("PRAGMA user_version=99").unwrap();
    assert!(Store::open(&path).is_err());
}
