use super::*;
use crate::lease::{LeasePolicy, LeaseProof, LeaseRelease, LeaseRequest};
use crate::node::{CostPeriod, NodeCost, NodeKind, NodeLifecycle, NodeLocation};

struct Fixture {
    tmp: tempfile::TempDir,
    db: Store,
    admin: Actor,
    node: Node,
}
impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let db = Store::open(&tmp.path().join("controller.sqlite")).unwrap();
        db.set_kind("controller").unwrap();
        let admin = db.bootstrap("node-inventory-test-password").unwrap();
        let (node, _) = db
            .create_node_with_lease(
                &admin,
                "default",
                "initial",
                Some(LeasePolicy { ttl_ms: 5000 }),
            )
            .unwrap();
        Self {
            tmp,
            db,
            admin,
            node,
        }
    }
    fn update(&self, settings: NodeSettings) -> NodeUpdate {
        let node = self
            .db
            .nodes(&self.admin)
            .unwrap()
            .into_iter()
            .find(|n| n.id == self.node.id)
            .unwrap();
        NodeUpdate {
            expected_revision: node.profile.revision,
            name: node.name,
            settings,
        }
    }
}
fn denied<T: std::fmt::Debug>(result: Result<T>, status: u16) {
    let error = result.unwrap_err();
    assert_eq!(
        error.downcast_ref::<Rejection>().unwrap().status,
        status,
        "{error}"
    );
}
fn detailed() -> NodeSettings {
    NodeSettings {
        kinds: vec![NodeKind::Ingress, NodeKind::Relay, NodeKind::Ix],
        group: Some("亚洲组".into()),
        tags: vec!["premium".into(), "台北".into()],
        notes: "机柜 B\n第二行".into(),
        cost: Some(NodeCost {
            currency: "USD".into(),
            amount_micros: 12_345_678,
            period: CostPeriod::Monthly,
        }),
        expires_at_ms: Some(now_ms() + 86_400_000),
        location: Some(NodeLocation {
            name: "台北 · 信义".into(),
            latitude_micros: 25_033_000,
            longitude_micros: 121_565_000,
        }),
        ..Default::default()
    }
}
#[test]
fn profile_roundtrip_keeps_exact_cost_and_configuration_revision_and_handles_legacy_nodes() {
    let f = Fixture::new();
    let mut input = f.update(detailed());
    input.name = "改名入口".into();
    let saved = f.db.update_node(&f.admin, &f.node.id, input).unwrap();
    assert_eq!(saved.profile.revision, 2);
    assert_eq!(
        saved.profile.settings.cost.as_ref().unwrap().amount_micros,
        12_345_678
    );
    assert_eq!(f.db.config(&f.admin, &f.node.id, None).unwrap().revision, 0);
    assert_eq!(f.db.history(&f.admin, &f.node.id).unwrap().len(), 1);
    let id = f.node.id.clone();
    let actor = f.admin.clone();
    let path = f.tmp.path().join("controller.sqlite");
    drop(f.db);
    let db = Store::open(&path).unwrap();
    let node = &db.nodes(&actor).unwrap()[0];
    assert_eq!(node.profile, saved.profile);
    assert_eq!(node.name, "改名入口");
    db.0.lock()
        .unwrap()
        .execute("DELETE FROM metadata WHERE key=?1", [key(&id)])
        .unwrap();
    let legacy = db.nodes(&actor).unwrap().remove(0);
    assert_eq!(legacy.profile, NodeProfile::default());
    assert_eq!(legacy.lifecycle, NodeLifecycle::Active);
    let result = db
        .update_node(
            &actor,
            &id,
            NodeUpdate {
                expected_revision: 0,
                name: legacy.name,
                settings: Default::default(),
            },
        )
        .unwrap();
    assert_eq!(result.profile.revision, 1);
}
#[test]
fn filters_and_profile_updates_preserve_tenant_and_read_only_permissions() {
    let f = Fixture::new();
    f.db.update_node(&f.admin, &f.node.id, f.update(detailed()))
        .unwrap();
    let viewer =
        f.db.create_user(
            &f.admin,
            "default",
            "node-viewer",
            "node-inventory-test-password",
            Role::Viewer,
        )
        .unwrap();
    let tenant = f.db.create_tenant(&f.admin, "other").unwrap();
    let other =
        f.db.create_user(
            &f.admin,
            &tenant,
            "node-outsider",
            "node-inventory-test-password",
            Role::TenantAdmin,
        )
        .unwrap();
    let viewer = Actor {
        id: viewer.id,
        tenant_id: viewer.tenant_id,
        username: viewer.username,
        role: viewer.role,
    };
    let other = Actor {
        id: other.id,
        tenant_id: other.tenant_id,
        username: other.username,
        role: other.role,
    };
    denied(
        f.db.update_node(&viewer, &f.node.id, f.update(Default::default())),
        403,
    );
    denied(
        f.db.update_node(&other, &f.node.id, f.update(Default::default())),
        404,
    );
    let filter = NodeFilter {
        q: Some("第二行".into()),
        kind: Some(NodeKind::Ix),
        group: Some("亚洲组".into()),
        tag: Some("premium".into()),
        lifecycle: Some(NodeLifecycle::Active),
    };
    assert_eq!(
        f.db.nodes_filtered(&viewer, filter.clone()).unwrap().len(),
        1
    );
    assert!(f.db.nodes_filtered(&other, filter).unwrap().is_empty());
    let by_location = NodeFilter {
        q: Some("信义".into()),
        ..Default::default()
    };
    assert_eq!(f.db.nodes_filtered(&viewer, by_location).unwrap().len(), 1);
    assert!(
        f.db.nodes_filtered(
            &viewer,
            NodeFilter {
                kind: Some(NodeKind::Nat),
                ..Default::default()
            }
        )
        .unwrap()
        .is_empty()
    );
    denied(
        f.db.nodes_filtered(
            &viewer,
            NodeFilter {
                q: Some(" ".into()),
                ..Default::default()
            },
        ),
        400,
    );
}
#[test]
fn invalid_inventory_and_offline_lifecycle_controls_are_rejected_without_writes() {
    let f = Fixture::new();
    let mut cases = vec![];
    let mut s = detailed();
    s.tags = vec!["dup".into(), "dup".into()];
    cases.push(s);
    let mut s = detailed();
    s.tags = vec!["bad\nline".into()];
    cases.push(s);
    let mut s = detailed();
    s.group = Some(" trailing ".into());
    cases.push(s);
    let mut s = detailed();
    s.kinds = vec![NodeKind::Nat, NodeKind::Nat];
    cases.push(s);
    let mut s = detailed();
    s.cost.as_mut().unwrap().currency = "usd".into();
    cases.push(s);
    let mut s = detailed();
    s.cost.as_mut().unwrap().amount_micros = 9_000_000_000_000_001;
    cases.push(s);
    let mut s = detailed();
    s.notes = "x".repeat(4097);
    cases.push(s);
    let mut s = detailed();
    s.expires_at_ms = Some(0);
    cases.push(s);
    let mut s = detailed();
    s.location.as_mut().unwrap().latitude_micros = 90_000_001;
    cases.push(s);
    let mut s = detailed();
    s.location.as_mut().unwrap().longitude_micros = i32::MIN;
    cases.push(s);
    let mut s = detailed();
    s.location.as_mut().unwrap().name = String::new();
    cases.push(s);
    for settings in cases {
        denied(
            f.db.update_node(&f.admin, &f.node.id, f.update(settings)),
            400,
        );
    }
    assert_eq!(f.db.nodes(&f.admin).unwrap()[0].profile.revision, 1);
    for settings in [
        NodeSettings {
            enabled: false,
            ..Default::default()
        },
        detailed(),
    ] {
        denied(
            f.db.create_node_with_settings(&f.admin, "default", "offline", None, settings),
            400,
        );
    }
    assert_eq!(f.db.nodes(&f.admin).unwrap().len(), 1);
    assert!(serde_json::from_str::<NodeSettings>(r#"{"unknown":true}"#).is_err());
    assert!(
        serde_json::from_str::<NodeSettings>(
            r#"{"cost":{"currency":"USD","amount_micros":1.5,"period":"monthly"}}"#
        )
        .is_err()
    );
}
#[test]
fn concurrent_profile_writers_have_exactly_one_winner() {
    let f = Fixture::new();
    let input = f.update(detailed());
    let barrier = Arc::new(std::sync::Barrier::new(2));
    let tasks = (0..2)
        .map(|i| {
            let (db, actor, node, mut input, barrier) = (
                f.db.clone(),
                f.admin.clone(),
                f.node.id.clone(),
                input.clone(),
                barrier.clone(),
            );
            std::thread::spawn(move || {
                input.name = format!("writer-{i}");
                barrier.wait();
                db.update_node(&actor, &node, input)
            })
        })
        .collect::<Vec<_>>();
    let results = tasks
        .into_iter()
        .map(|t| t.join().unwrap())
        .collect::<Vec<_>>();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    for result in results {
        if result.is_err() {
            denied(result, 409);
        }
    }
    assert_eq!(f.db.nodes(&f.admin).unwrap()[0].profile.revision, 2);
}
#[test]
fn batch_conflicts_duplicate_ids_and_storage_failures_roll_back_every_node_and_audit() {
    let f = Fixture::new();
    let (second, _) =
        f.db.create_node_with_lease(&f.admin, "default", "second", Some(LeasePolicy::default()))
            .unwrap();
    let entries = vec![
        NodeBatchEntry {
            node_id: f.node.id.clone(),
            update: NodeUpdate {
                expected_revision: 1,
                name: "one-new".into(),
                settings: detailed(),
            },
        },
        NodeBatchEntry {
            node_id: second.id.clone(),
            update: NodeUpdate {
                expected_revision: 1,
                name: "two-new".into(),
                settings: detailed(),
            },
        },
    ];
    let mut conflict = entries.clone();
    conflict[1].update.expected_revision = 0;
    denied(f.db.update_nodes(&f.admin, conflict), 409);
    denied(
        f.db.update_nodes(&f.admin, vec![entries[0].clone(), entries[0].clone()]),
        400,
    );
    f.db.0.lock().unwrap().execute_batch("CREATE TRIGGER reject_second_profile BEFORE UPDATE OF name ON nodes WHEN NEW.name='two-new' BEGIN SELECT RAISE(ABORT,'injected second-node failure'); END;").unwrap();
    assert!(f.db.update_nodes(&f.admin, entries.clone()).is_err());
    for node in f.db.nodes(&f.admin).unwrap() {
        assert_eq!(node.profile.revision, 1);
        assert!(!node.name.ends_with("-new"));
    }
    let audits: u64 =
        f.db.0
            .lock()
            .unwrap()
            .query_row(
                "SELECT COUNT(*) FROM audit WHERE action='node.profile.update'",
                [],
                |r| r.get(0),
            )
            .unwrap();
    assert_eq!(audits, 0);
    f.db.0
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER reject_second_profile")
        .unwrap();
    let saved = f.db.update_nodes(&f.admin, entries).unwrap();
    assert_eq!(saved.len(), 2);
    assert!(saved.iter().all(|n| n.profile.revision == 2));
}
#[test]
fn expiry_caps_grants_and_live_edits_cannot_retroactively_shorten_issued_windows() {
    let f = Fixture::new();
    let (node, enrollment) =
        f.db.create_node_with_settings(
            &f.admin,
            "default",
            "short-lived",
            Some(LeasePolicy { ttl_ms: 5000 }),
            NodeSettings {
                expires_at_ms: Some(now_ms() + 1500),
                ..Default::default()
            },
        )
        .unwrap();
    let credential = secret();
    f.db.enroll(&node.id, &enrollment, &credential).unwrap();
    let claim = LeaseRequest {
        run_id: "first".into(),
        token: secret(),
        generation: None,
        resume_generation: None,
    };
    let first = f.db.exchange_lease(&credential, claim.clone()).unwrap();
    assert!(first.valid_for_ms <= 1500 && first.valid_for_ms > 0);
    let repeated = f.db.exchange_lease(&credential, claim.clone()).unwrap();
    assert_eq!(first.generation, repeated.generation);
    assert!(repeated.valid_for_ms <= first.valid_for_ms);
    let mut update = NodeUpdate {
        expected_revision: 1,
        name: node.name.clone(),
        settings: node.profile.settings.clone(),
    };
    update.settings.expires_at_ms = Some(now_ms() + 100);
    denied(f.db.update_node(&f.admin, &node.id, update.clone()), 409);
    update.settings.enabled = false;
    f.db.update_node(&f.admin, &node.id, update).unwrap();
    let paused =
        f.db.nodes(&f.admin)
            .unwrap()
            .into_iter()
            .find(|n| n.id == node.id)
            .unwrap();
    let mut reenable = NodeUpdate {
        expected_revision: paused.profile.revision,
        name: paused.name,
        settings: paused.profile.settings,
    };
    reenable.settings.enabled = true;
    denied(f.db.update_node(&f.admin, &node.id, reenable), 409);
    let mut renewal = claim.clone();
    renewal.generation = first.generation;
    denied(f.db.exchange_lease(&credential, renewal), 403);
    let proof = LeaseProof {
        run_id: claim.run_id,
        token: claim.token,
        generation: first.generation.unwrap(),
    };
    f.db.release_lease(
        &credential,
        LeaseRelease {
            proof,
            stats: EngineStats::default(),
        },
    )
    .unwrap();
    let expired = NodeUpdate {
        expected_revision: 2,
        name: node.name.clone(),
        settings: NodeSettings {
            expires_at_ms: Some(now_ms() - 1),
            ..Default::default()
        },
    };
    assert_eq!(
        f.db.update_node(&f.admin, &node.id, expired)
            .unwrap()
            .lifecycle,
        NodeLifecycle::Expired
    );
    let fresh = LeaseRequest {
        run_id: "second".into(),
        token: secret(),
        generation: None,
        resume_generation: None,
    };
    denied(f.db.exchange_lease(&credential, fresh.clone()), 410);
    f.db.update_node(
        &f.admin,
        &node.id,
        NodeUpdate {
            expected_revision: 3,
            name: node.name,
            settings: Default::default(),
        },
    )
    .unwrap();
    assert_eq!(
        f.db.exchange_lease(&credential, fresh).unwrap().generation,
        Some(2)
    );
}
#[test]
fn old_backup_plus_complete_journal_restores_names_profiles_and_lifecycle_exactly() {
    let f = Fixture::new();
    let log = f.tmp.path().join("recovery.log");
    f.db.enable_recovery_log(&log).unwrap();
    let backup = f.tmp.path().join("backup.sqlite");
    f.db.backup(&backup).unwrap();
    let mut input = f.update(detailed());
    input.name = "journal-renamed".into();
    input.settings.enabled = false;
    let expected = f.db.update_node(&f.admin, &f.node.id, input).unwrap();
    let actor = f.admin.clone();
    drop(f.db);
    let output = f.tmp.path().join("restored");
    let report = crate::journal::restore_controller(&backup, &log, &output).unwrap();
    assert!(report.replayed_transactions > 0);
    let restored = Store::open(&output.join("controller.sqlite")).unwrap();
    let node = restored.nodes(&actor).unwrap().remove(0);
    assert_eq!(node.name, expected.name);
    assert_eq!(node.profile, expected.profile);
    assert_eq!(node.lifecycle, NodeLifecycle::Disabled);
    assert_eq!(node.desired_revision, 0);
}
