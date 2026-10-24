use super::*;
use crate::lease::{LeasePolicy, LeaseProof, LeaseRequest};

struct Fixture {
    tmp: tempfile::TempDir,
    db: Store,
    admin: Actor,
    node: String,
    token: String,
    enrollment: String,
}
impl Fixture {
    fn new(strict: bool) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let db = Store::open(&tmp.path().join("controller.sqlite")).unwrap();
        db.set_kind("controller").unwrap();
        let admin = db.bootstrap("replacement-test-password").unwrap();
        let (node, enrollment) = db
            .create_node_with_lease(
                &admin,
                "default",
                "replace",
                strict.then_some(LeasePolicy { ttl_ms: 5000 }),
            )
            .unwrap();
        let token = secret();
        db.enroll(&node.id, &enrollment, &token).unwrap();
        Self {
            tmp,
            db,
            admin,
            node: node.id,
            token,
            enrollment,
        }
    }
    fn revoke(&self) -> RevokeCredential {
        RevokeCredential {
            operation_id: Uuid::new_v4().to_string(),
            expected_revision: 1,
            reason: "lost server".into(),
        }
    }
    fn ticket(&self, revision: u64) -> ReplaceCredential {
        ReplaceCredential {
            operation_id: Uuid::new_v4().to_string(),
            expected_revision: revision,
            enrollment_token: secret(),
            valid_for_seconds: 600,
            offline_stop_attested: false,
            lease_policy: None,
        }
    }
    fn claim(&self, token: &str) -> Result<LeaseProof> {
        let mut proof = LeaseProof {
            run_id: Uuid::new_v4().to_string(),
            token: secret(),
            generation: 0,
        };
        proof.generation = self
            .db
            .exchange_lease(
                token,
                LeaseRequest {
                    run_id: proof.run_id.clone(),
                    token: proof.token.clone(),
                    generation: None,
                    resume_generation: None,
                },
            )?
            .generation
            .unwrap();
        Ok(proof)
    }
    fn rule(&self) -> Rule {
        serde_json::from_value(serde_json::json!({"id":"replace-rule","tenant_id":"default","owner_id":self.admin.id,"name":"replacement","listen":"127.0.0.1:18001","protocol":"both","targets":[{"address":"127.0.0.1:19001","weight":1}],"meter_epoch":"period-one"})).unwrap()
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

#[test]
fn revocation_retires_all_authentication_and_retains_issued_window_before_replacement() {
    let f = Fixture::new(true);
    let proof = f.claim(&f.token).unwrap();
    f.db.request_credential_rotation(&f.admin, &f.node, 1)
        .unwrap();
    let revoke = f.revoke();
    let state =
        f.db.revoke_node_credential(&f.admin, &f.node, revoke.clone())
            .unwrap();
    assert_eq!(state.phase, CredentialPhase::Revoked);
    assert_eq!(state.revision, 2);
    assert!(state.pending.is_none());
    denied(f.db.authenticate_node(&f.token), 401);
    denied(f.db.enroll(&f.node, &f.enrollment, &secret()), 401);
    let node = &f.db.nodes(&f.admin).unwrap()[0];
    assert!(!node.enrolled);
    assert!(!node.lease.active);
    assert!(node.lease.recovery_wait_ms > 4000);
    assert_eq!(node.lease.generation, proof.generation + 1);
    let ticket = f.ticket(2);
    f.db.replace_node_credential(&f.admin, &f.node, ticket.clone())
        .unwrap();
    let next = secret();
    assert_eq!(
        f.db.enroll_revision(&f.node, &ticket.enrollment_token, &next)
            .unwrap(),
        3
    );
    denied(f.claim(&next), 423);
    denied(
        f.db.exchange_lease(
            &next,
            LeaseRequest {
                run_id: proof.run_id,
                token: secret(),
                generation: None,
                resume_generation: Some(proof.generation),
            },
        ),
        412,
    );
    assert_eq!(
        f.db.enroll_revision(&f.node, &ticket.enrollment_token, &next)
            .unwrap(),
        3
    );
    assert_eq!(
        f.db.revoke_node_credential(&f.admin, &f.node, revoke)
            .unwrap()
            .phase,
        CredentialPhase::Active
    );
    assert_eq!(f.db.authenticate_node(&next).unwrap(), f.node);
    assert_eq!(f.db.config(&f.admin, &f.node, None).unwrap().revision, 0);
}

#[test]
fn replacement_ticket_expiry_reissue_and_lost_response_retries_never_resurrect_old_tickets() {
    let f = Fixture::new(true);
    f.db.revoke_node_credential(&f.admin, &f.node, f.revoke())
        .unwrap();
    let mut first = f.ticket(2);
    first.valid_for_seconds = 1;
    let issued =
        f.db.replace_node_credential(&f.admin, &f.node, first.clone())
            .unwrap();
    assert_eq!(
        f.db.replace_node_credential(&f.admin, &f.node, first.clone())
            .unwrap(),
        issued
    );
    std::thread::sleep(Duration::from_millis(1100));
    denied(
        f.db.enroll(&f.node, &first.enrollment_token, &secret()),
        410,
    );
    assert_eq!(
        f.db.replace_node_credential(&f.admin, &f.node, first.clone())
            .unwrap()
            .replacement
            .unwrap()
            .expires_at_ms,
        issued.replacement.unwrap().expires_at_ms
    );
    let second = f.ticket(3);
    f.db.replace_node_credential(&f.admin, &f.node, second.clone())
        .unwrap();
    denied(
        f.db.enroll(&f.node, &first.enrollment_token, &secret()),
        401,
    );
    let next = secret();
    assert_eq!(
        f.db.enroll_revision(&f.node, &second.enrollment_token, &next)
            .unwrap(),
        4
    );
    assert_eq!(
        f.db.replace_node_credential(&f.admin, &f.node, first.clone())
            .unwrap()
            .revision,
        4
    );
    let mut changed = first;
    changed.enrollment_token = secret();
    denied(
        f.db.replace_node_credential(&f.admin, &f.node, changed),
        409,
    );
    assert_eq!(f.db.authenticate_node(&next).unwrap(), f.node);
}

#[test]
fn offline_replacement_requires_external_stop_attestation_and_adopts_strict_policy() {
    let f = Fixture::new(false);
    let revoked =
        f.db.revoke_node_credential(&f.admin, &f.node, f.revoke())
            .unwrap();
    assert!(!revoked.revocation.unwrap().strict_execution);
    let mut ticket = f.ticket(2);
    ticket.lease_policy = Some(LeasePolicy { ttl_ms: 5000 });
    denied(
        f.db.replace_node_credential(&f.admin, &f.node, ticket.clone()),
        409,
    );
    ticket.offline_stop_attested = true;
    ticket.lease_policy = None;
    denied(
        f.db.replace_node_credential(&f.admin, &f.node, ticket.clone()),
        400,
    );
    ticket.lease_policy = Some(LeasePolicy { ttl_ms: 5000 });
    f.db.0.lock().unwrap().execute_batch("CREATE TRIGGER fail_ticket BEFORE INSERT ON audit WHEN NEW.action='node.identity.replacement' BEGIN SELECT RAISE(ABORT,'injected replacement failure'); END").unwrap();
    assert!(
        f.db.replace_node_credential(&f.admin, &f.node, ticket.clone())
            .is_err()
    );
    assert!(f.db.nodes(&f.admin).unwrap()[0].lease.policy.is_none());
    assert_eq!(
        f.db.node_credential_status(&f.admin, &f.node)
            .unwrap()
            .phase,
        CredentialPhase::Revoked
    );
    f.db.0
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_ticket")
        .unwrap();
    let state =
        f.db.replace_node_credential(&f.admin, &f.node, ticket.clone())
            .unwrap();
    assert!(state.replacement.unwrap().offline_stop_attested);
    let next = secret();
    f.db.enroll(&f.node, &ticket.enrollment_token, &next)
        .unwrap();
    assert!(f.claim(&next).is_ok());
    assert_eq!(
        f.db.nodes(&f.admin).unwrap()[0]
            .lease
            .policy
            .as_ref()
            .unwrap()
            .ttl_ms,
        5000
    );
}

#[test]
fn concurrent_rotation_and_revocation_cannot_retire_a_new_identity_using_an_old_revision() {
    let f = Fixture::new(true);
    let proof = f.claim(&f.token).unwrap();
    let rotation =
        f.db.request_credential_rotation(&f.admin, &f.node, 1)
            .unwrap()
            .pending
            .unwrap();
    let input = crate::credential::RotateCredential {
        request_id: rotation.id,
        expected_revision: 1,
        credential: secret(),
        lease: Some(proof),
    };
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let (db, token, gate) = (f.db.clone(), f.token.clone(), barrier.clone());
    let rotate = std::thread::spawn(move || {
        gate.wait();
        db.rotate_node_credential(&token, input)
    });
    let (db, admin, node, gate) = (
        f.db.clone(),
        f.admin.clone(),
        f.node.clone(),
        barrier.clone(),
    );
    let request = f.revoke();
    let revoke = std::thread::spawn(move || {
        gate.wait();
        db.revoke_node_credential(&admin, &node, request)
    });
    barrier.wait();
    let results = (rotate.join().unwrap(), revoke.join().unwrap());
    assert_ne!(results.0.is_ok(), results.1.is_ok());
    let state = f.db.node_credential_status(&f.admin, &f.node).unwrap();
    assert_eq!(state.revision, 2);
    assert_eq!(
        state.phase,
        if results.0.is_ok() {
            CredentialPhase::Active
        } else {
            CredentialPhase::Revoked
        }
    );
}

#[test]
fn revocation_keeps_usage_and_fences_all_historical_quota_periods_until_explicit_new_period() {
    let f = Fixture::new(true);
    let mut rule = f.rule();
    rule.quota_bytes = Some(1024);
    f.db.set_config(&f.admin, &f.node, 0, vec![rule.clone()])
        .unwrap();
    f.db.0
        .lock()
        .unwrap()
        .execute(
            "INSERT INTO usage VALUES(?1,?2,?3,1,100,0,?4)",
            params![f.node, rule.id, rule.meter_epoch, now_ms()],
        )
        .unwrap();
    rule.meter_epoch = "period-two".into();
    f.db.set_config(&f.admin, &f.node, 1, vec![rule.clone()])
        .unwrap();
    let revoked =
        f.db.revoke_node_credential(&f.admin, &f.node, f.revoke())
            .unwrap();
    assert_eq!(revoked.blocked_quota_periods.len(), 1);
    let ticket = f.ticket(2);
    f.db.replace_node_credential(&f.admin, &f.node, ticket.clone())
        .unwrap();
    let next = secret();
    f.db.enroll(&f.node, &ticket.enrollment_token, &next)
        .unwrap();
    denied(f.claim(&next), 423);
    denied(
        f.db.set_config(&f.admin, &f.node, 2, vec![rule.clone()]),
        409,
    );
    rule.enabled = false;
    f.db.set_config(&f.admin, &f.node, 2, vec![rule.clone()])
        .unwrap();
    assert!(
        f.db.node_credential_status(&f.admin, &f.node)
            .unwrap()
            .blocked_quota_periods
            .is_empty()
    );
    assert!(f.claim(&next).is_ok());
    rule.enabled = true;
    rule.meter_epoch = "period-one".into();
    denied(
        f.db.set_config(&f.admin, &f.node, 3, vec![rule.clone()]),
        409,
    );
    rule.meter_epoch = "explicit-new-period".into();
    f.db.set_config(&f.admin, &f.node, 3, vec![rule]).unwrap();
    let usage = f.db.reported_usage(&f.admin).unwrap();
    assert_eq!(usage.len(), 1);
    assert_eq!(usage[0]["upload_bytes"], 100);
}

#[test]
fn revoked_identity_is_not_topology_stop_confirmation_until_its_window_has_ended() {
    let f = Fixture::new(true);
    let mut rule = f.rule();
    rule.advertise = Some("127.0.0.1:18001".into());
    f.db.set_config(&f.admin, &f.node, 0, vec![rule.clone()])
        .unwrap();
    f.claim(&f.token).unwrap();
    f.db.revoke_node_credential(&f.admin, &f.node, f.revoke())
        .unwrap();
    rule.enabled = false;
    f.db.set_config(&f.admin, &f.node, 1, vec![rule.clone()])
        .unwrap();
    rule.targets[0].address = "127.0.0.1:19002".into();
    denied(
        f.db.set_config(&f.admin, &f.node, 2, vec![rule.clone()]),
        409,
    );
    std::thread::sleep(Duration::from_millis(5100));
    f.db.set_config(&f.admin, &f.node, 2, vec![rule]).unwrap();
    let path = f.tmp.path().join("controller.sqlite");
    drop(f.db);
    let reopened = Store::open(&path).unwrap();
    assert!(reopened.nodes(&f.admin).unwrap()[0].lease.recovery_wait_ms > 4500);
}

#[test]
fn identity_permissions_conflicts_and_operation_ids_prevent_stale_or_cross_tenant_actions() {
    let f = Fixture::new(true);
    let viewer =
        f.db.create_user(
            &f.admin,
            "default",
            "viewer",
            "replacement-test-password",
            Role::Viewer,
        )
        .unwrap();
    let tenant = f.db.create_tenant(&f.admin, "other").unwrap();
    let other =
        f.db.create_user(
            &f.admin,
            &tenant,
            "other",
            "replacement-test-password",
            Role::TenantAdmin,
        )
        .unwrap();
    let request = f.revoke();
    denied(
        f.db.revoke_node_credential(&viewer, &f.node, request.clone()),
        403,
    );
    denied(
        f.db.revoke_node_credential(&other, &f.node, request.clone()),
        404,
    );
    let ticket = f.ticket(1);
    denied(f.db.replace_node_credential(&f.admin, &f.node, ticket), 409);
    f.db.revoke_node_credential(&f.admin, &f.node, request.clone())
        .unwrap();
    let mut different = request;
    different.reason = "different".into();
    denied(
        f.db.revoke_node_credential(&f.admin, &f.node, different),
        409,
    );
    let mut ticket = f.ticket(2);
    denied(
        f.db.replace_node_credential(&viewer, &f.node, ticket.clone()),
        403,
    );
    denied(
        f.db.replace_node_credential(&other, &f.node, ticket.clone()),
        404,
    );
    ticket.enrollment_token = f.token.clone();
    denied(
        f.db.replace_node_credential(&f.admin, &f.node, ticket.clone()),
        409,
    );
    ticket.enrollment_token = f.enrollment.clone();
    denied(f.db.replace_node_credential(&f.admin, &f.node, ticket), 409);
}

#[test]
fn revoke_storage_failure_rolls_back_authentication_lease_cache_and_idempotency_record() {
    let f = Fixture::new(true);
    let proof = f.claim(&f.token).unwrap();
    let request = f.revoke();
    f.db.0.lock().unwrap().execute_batch("CREATE TRIGGER fail_revoke BEFORE INSERT ON audit WHEN NEW.action='node.identity.revoke' BEGIN SELECT RAISE(ABORT,'injected revocation failure'); END").unwrap();
    assert!(
        f.db.revoke_node_credential(&f.admin, &f.node, request.clone())
            .is_err()
    );
    assert_eq!(f.db.authenticate_node(&f.token).unwrap(), f.node);
    let node = &f.db.nodes(&f.admin).unwrap()[0];
    assert!(node.lease.active);
    assert_eq!(node.lease.generation, proof.generation);
    f.db.0
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_revoke")
        .unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let jobs: Vec<_> = (0..2)
        .map(|_| {
            let db = f.db.clone();
            let admin = f.admin.clone();
            let node = f.node.clone();
            let barrier = barrier.clone();
            let mut request = request.clone();
            request.operation_id = Uuid::new_v4().to_string();
            std::thread::spawn(move || {
                barrier.wait();
                db.revoke_node_credential(&admin, &node, request)
            })
        })
        .collect();
    barrier.wait();
    let results: Vec<_> = jobs.into_iter().map(|j| j.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        f.db.node_credential_status(&f.admin, &f.node)
            .unwrap()
            .revision,
        2
    );
}

#[test]
fn journal_recovery_preserves_revocation_replacement_meter_fences_and_operation_retries() {
    let f = Fixture::new(true);
    let log = f.tmp.path().join("recovery.log");
    f.db.enable_recovery_log(&log).unwrap();
    let mut rule = f.rule();
    rule.quota_bytes = Some(1000);
    f.db.set_config(&f.admin, &f.node, 0, vec![rule.clone()])
        .unwrap();
    let backup = f.tmp.path().join("old.sqlite");
    f.db.backup(&backup).unwrap();
    let revoke = f.revoke();
    f.db.revoke_node_credential(&f.admin, &f.node, revoke.clone())
        .unwrap();
    let ticket = f.ticket(2);
    f.db.replace_node_credential(&f.admin, &f.node, ticket.clone())
        .unwrap();
    let next = secret();
    f.db.enroll(&f.node, &ticket.enrollment_token, &next)
        .unwrap();
    let expected = f.db.node_credential_status(&f.admin, &f.node).unwrap();
    let audit = serde_json::to_string(&f.db.audit_log(&f.admin).unwrap()).unwrap();
    for secret in [&f.token, &ticket.enrollment_token, &next] {
        assert!(!audit.contains(secret));
        assert!(!audit.contains(&token_hash(secret)));
    }
    let output = f.tmp.path().join("restored");
    drop(f.db);
    crate::journal::restore_controller(&backup, &log, &output).unwrap();
    let restored = Store::open(&output.join("controller.sqlite")).unwrap();
    restored
        .enable_recovery_log(&output.join("recovery.log"))
        .unwrap();
    assert_eq!(
        restored.node_credential_status(&f.admin, &f.node).unwrap(),
        expected
    );
    denied(restored.authenticate_node(&f.token), 401);
    assert_eq!(restored.authenticate_node(&next).unwrap(), f.node);
    assert_eq!(
        restored
            .revoke_node_credential(&f.admin, &f.node, revoke)
            .unwrap(),
        expected
    );
    assert_eq!(
        restored
            .replace_node_credential(&f.admin, &f.node, ticket)
            .unwrap(),
        expected
    );
    denied(restored.set_config(&f.admin, &f.node, 1, vec![rule]), 409);
}
