mod common;
use common::*;
use relay_platform::{
    model::*,
    store::{Admission, Rejection, Role, Store},
};

fn admission(rule: &Rule, upload: bool, bytes: usize, datagram: bool) -> Admission {
    Admission {
        rule_id: rule.id.clone(),
        meter_epoch: rule.meter_epoch.clone(),
        upload,
        bytes,
        datagram,
    }
}
fn rejection<T>(result: anyhow::Result<T>) -> u16 {
    result
        .err()
        .unwrap()
        .downcast_ref::<Rejection>()
        .unwrap()
        .status
}
fn sync(db: &Store, node: &str, usage: Vec<Usage>) -> SyncRequest {
    SyncRequest {
        budget: None,
        ledger_id: db
            .reconcile(
                node,
                ReconcileRequest {
                    ledger_id: None,
                    after: None,
                    expected_revision: None,
                },
            )
            .unwrap()
            .ledger_id,
        need_config: false,
        applied_revision: 0,
        apply_error: None,
        usage,
        stats: EngineStats::default(),
    }
}

#[test]
fn quota_is_shared_across_directions_and_survives_restart() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("agent.db");
    let db = Store::open(&path).unwrap();
    let mut r = rule("127.0.0.1:8888".parse().unwrap(), Protocol::Both);
    r.quota_bytes = Some(100);
    db.save_agent_config(&config(r.clone())).unwrap();
    assert_eq!(
        db.admit_batch(&[
            admission(&r, true, 60, false),
            admission(&r, false, 30, true),
            admission(&r, true, 11, true)
        ])
        .unwrap(),
        vec![Some(60), Some(30), None]
    );
    drop(db);
    let reopened = Store::open(&path).unwrap();
    assert_eq!(
        reopened
            .admit_batch(&[
                admission(&r, true, 20, false),
                admission(&r, false, 1, false)
            ])
            .unwrap(),
        vec![Some(10), None]
    );
    let counters = reopened.agent_usage(false).unwrap();
    assert_eq!(counters[0].upload_bytes, 70);
    assert_eq!(counters[0].download_bytes, 30);
    assert_eq!(counters[0].sequence, 3);
}

#[test]
fn periods_do_not_reset_on_reapply_and_old_periods_cannot_spend() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let r = rule("127.0.0.1:8888".parse().unwrap(), Protocol::Tcp);
    let mut c = config(r.clone());
    db.save_agent_config(&c).unwrap();
    db.admit_batch(&[admission(&r, true, 7, false)]).unwrap();
    db.save_agent_config(&c).unwrap();
    assert_eq!(db.agent_usage(false).unwrap()[0].upload_bytes, 7);
    c.revision = 2;
    c.rules[0].meter_epoch = "epoch-two".into();
    db.save_agent_config(&c).unwrap();
    assert_eq!(
        db.admit_batch(&[
            admission(&r, true, 10, false),
            admission(&c.rules[0], false, 4, false)
        ])
        .unwrap(),
        vec![None, Some(4)]
    );
    let usage = db.agent_usage(false).unwrap();
    assert_eq!(usage.len(), 2);
    assert_eq!(
        usage
            .iter()
            .map(|u| u.upload_bytes + u.download_bytes)
            .sum::<u64>(),
        11
    );
}

#[test]
fn exhausted_expired_and_disabled_rules_reject_empty_datagrams_too() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let mut r = rule("127.0.0.1:8888".parse().unwrap(), Protocol::Udp);
    let mut c = config(r.clone());
    db.save_agent_config(&c).unwrap();
    assert_eq!(
        db.admit_batch(&[admission(&r, true, 0, true)]).unwrap(),
        vec![Some(0)]
    );
    r.quota_bytes = Some(0);
    c.revision = 2;
    c.rules = vec![r.clone()];
    db.save_agent_config(&c).unwrap();
    assert_eq!(
        db.admit_batch(&[admission(&r, true, 0, true)]).unwrap(),
        vec![None]
    );
    r.quota_bytes = None;
    r.expires_at_ms = Some(now_ms() - 1);
    c.revision = 3;
    c.rules = vec![r.clone()];
    db.save_agent_config(&c).unwrap();
    assert_eq!(
        db.admit_batch(&[admission(&r, true, 4, false)]).unwrap(),
        vec![None]
    );
    r.expires_at_ms = None;
    r.enabled = false;
    c.revision = 4;
    c.rules = vec![r.clone()];
    db.save_agent_config(&c).unwrap();
    assert_eq!(
        db.admit_batch(&[admission(&r, true, 1, false)]).unwrap(),
        vec![None]
    );
}

#[test]
fn controller_replay_is_idempotent_and_counter_regression_is_rejected() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("control.db")).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let (node, _) = db.create_node(&admin, "default", "node").unwrap();
    let r = rule("127.0.0.1:8888".parse().unwrap(), Protocol::Tcp);
    db.set_config(&admin, &node.id, 0, vec![r.clone()]).unwrap();
    let u = Usage {
        rule_id: r.id.clone(),
        meter_epoch: r.meter_epoch.clone(),
        sequence: 1,
        upload_bytes: 1_073_741_824,
        download_bytes: 17,
    };
    db.sync(&node.id, sync(&db, &node.id, vec![u.clone()]))
        .unwrap();
    db.sync(&node.id, sync(&db, &node.id, vec![u.clone()]))
        .unwrap();
    let records = db.reported_usage(&admin).unwrap();
    assert_eq!(records.len(), 1);
    assert_eq!(records[0]["upload_bytes"], 1_073_741_824u64);
    let mut changed = u.clone();
    changed.upload_bytes += 1;
    assert_eq!(
        rejection(db.sync(&node.id, sync(&db, &node.id, vec![changed.clone()]))),
        409
    );
    changed.sequence = 2;
    db.sync(&node.id, sync(&db, &node.id, vec![changed]))
        .unwrap();
    assert_eq!(
        rejection(db.sync(&node.id, sync(&db, &node.id, vec![u]))),
        409
    );
    let unknown = Usage {
        rule_id: "someone-elses-rule".into(),
        meter_epoch: "one".into(),
        sequence: 1,
        upload_bytes: 1,
        download_bytes: 0,
    };
    assert_eq!(
        rejection(db.sync(&node.id, sync(&db, &node.id, vec![unknown]))),
        403
    );
}

#[test]
fn authorization_is_enforced_at_store_boundary_and_sessions_revoke() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("control.db")).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let tenant = db.create_tenant(&admin, "Tenant B").unwrap();
    let tenant_admin = db
        .create_user(&admin, &tenant, "tenant-b", PASSWORD, Role::TenantAdmin)
        .unwrap();
    let viewer = db
        .create_user(&admin, "default", "viewer", PASSWORD, Role::Viewer)
        .unwrap();
    let (node, _) = db.create_node(&admin, "default", "private").unwrap();
    assert!(db.nodes(&tenant_admin).unwrap().is_empty());
    assert_eq!(rejection(db.config(&tenant_admin, &node.id, None)), 404);
    assert_eq!(rejection(db.set_config(&viewer, &node.id, 0, vec![])), 403);
    assert_eq!(
        rejection(db.create_user(
            &tenant_admin,
            &tenant,
            "evil-admin",
            PASSWORD,
            Role::SystemAdmin
        )),
        403
    );
    assert_eq!(
        rejection(db.create_node(&tenant_admin, "default", "foreign")),
        403
    );
    let (token, actor) = db.login("viewer", PASSWORD).unwrap();
    assert_eq!(actor.id, viewer.id);
    assert_eq!(db.authenticate(&token).unwrap().id, viewer.id);
    db.revoke_sessions(&admin, &viewer.id).unwrap();
    assert_eq!(rejection(db.authenticate(&token)), 401);
    assert_eq!(rejection(db.login("missing", PASSWORD)), 401);
    assert_eq!(rejection(db.login("admin", "wrong-password-12")), 401);
}

#[test]
fn enrollment_is_single_use_and_configuration_writes_are_optimistic() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("control.db")).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let (node, token) = db.create_node(&admin, "default", "node").unwrap();
    let credential = relay_platform::store::secret();
    db.enroll(&node.id, &token, &credential).unwrap();
    assert_eq!(db.authenticate_node(&credential).unwrap(), node.id);
    // A lost response is retried with the same previously persisted node secret.
    db.enroll(&node.id, &token, &credential).unwrap();
    assert_eq!(
        rejection(db.enroll(&node.id, &token, &relay_platform::store::secret())),
        401
    );
    let r = rule("127.0.0.1:8888".parse().unwrap(), Protocol::Tcp);
    db.set_config(&admin, &node.id, 0, vec![r.clone()]).unwrap();
    assert_eq!(rejection(db.set_config(&admin, &node.id, 0, vec![])), 409);
    assert_eq!(db.config(&admin, &node.id, None).unwrap().rules.len(), 1);
    db.set_config(&admin, &node.id, 1, vec![]).unwrap();
    let u = Usage {
        rule_id: r.id,
        meter_epoch: r.meter_epoch,
        sequence: 1,
        upload_bytes: 9,
        download_bytes: 0,
    };
    db.sync(&node.id, sync(&db, &node.id, vec![u])).unwrap();
    assert_eq!(db.reported_usage(&admin).unwrap()[0]["upload_bytes"], 9);
}

#[test]
fn consistent_backup_restores_config_counters_and_private_permissions() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let r = rule("127.0.0.1:8888".parse().unwrap(), Protocol::Tcp);
    db.save_agent_config(&config(r.clone())).unwrap();
    db.admit_batch(&[admission(&r, true, 34, false)]).unwrap();
    let backup = temp.path().join("backup.db");
    db.backup(&backup).unwrap();
    let restored = Store::open(&backup).unwrap();
    assert_eq!(restored.agent_config().unwrap().unwrap().revision, 1);
    assert_eq!(restored.agent_usage(false).unwrap()[0].upload_bytes, 34);
    assert!(db.backup(&backup).is_err());
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        assert_eq!(
            std::fs::metadata(backup).unwrap().permissions().mode() & 0o777,
            0o600
        );
    }
}

#[test]
fn model_rejects_unknown_options_invalid_targets_and_listener_duplicates() {
    let r = rule("127.0.0.1:8888".parse().unwrap(), Protocol::Tcp);
    let mut json = serde_json::to_value(&r).unwrap();
    json["pretend_mptcp"] = true.into();
    assert!(serde_json::from_value::<Rule>(json).is_err());
    let mut c = config(r);
    let mut other = c.rules[0].clone();
    other.id = "rule-two".into();
    c.rules.push(other);
    assert!(c.validate().is_err());
    for target in [
        "127.0.0.1:0",
        "0.0.0.0:123",
        "host:443/path",
        "::1:443",
        "user@host:22",
        "bad host:443",
    ] {
        assert!(validate_target(target).is_err(), "accepted {target}");
    }
    for target in ["example.com:443", "[::1]:443", "127.0.0.1:80"] {
        validate_target(target).unwrap();
    }
}
