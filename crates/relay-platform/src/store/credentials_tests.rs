use super::*;
use crate::lease::{LeasePolicy, LeaseProof, LeaseRequest};

struct Fixture {
    tmp: tempfile::TempDir,
    db: Store,
    admin: Actor,
    node: String,
    token: String,
    proof: Option<LeaseProof>,
}
impl Fixture {
    fn new(strict: bool) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let db = Store::open(&tmp.path().join("controller.sqlite")).unwrap();
        db.set_kind("controller").unwrap();
        let admin = db.bootstrap("credential-test-password").unwrap();
        let (node, enrollment) = db
            .create_node_with_lease(
                &admin,
                "default",
                "rotation",
                strict.then_some(LeasePolicy { ttl_ms: 5000 }),
            )
            .unwrap();
        let token = secret();
        db.enroll(&node.id, &enrollment, &token).unwrap();
        let proof = strict.then(|| {
            let mut proof = LeaseProof {
                run_id: Uuid::new_v4().to_string(),
                generation: 0,
                token: secret(),
            };
            proof.generation = db
                .exchange_lease(
                    &token,
                    LeaseRequest {
                        run_id: proof.run_id.clone(),
                        token: proof.token.clone(),
                        generation: None,
                        resume_generation: None,
                    },
                )
                .unwrap()
                .generation
                .unwrap();
            proof
        });
        Self {
            tmp,
            db,
            admin,
            node: node.id,
            token,
            proof,
        }
    }
    fn requested(&self, revision: u64) -> RotateCredential {
        let state = self
            .db
            .request_credential_rotation(&self.admin, &self.node, revision)
            .unwrap();
        RotateCredential {
            request_id: state.pending.unwrap().id,
            expected_revision: revision,
            credential: secret(),
            lease: self.proof.clone(),
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

#[test]
fn rotation_retires_old_secret_preserves_lease_and_is_idempotent_with_new_secret() {
    let f = Fixture::new(true);
    let input = f.requested(1);
    let receipt =
        f.db.rotate_node_credential(&f.token, input.clone())
            .unwrap();
    assert_eq!(receipt.revision, 2);
    denied(f.db.authenticate_node(&f.token), 401);
    assert_eq!(f.db.authenticate_node(&input.credential).unwrap(), f.node);
    assert_eq!(
        f.db.rotate_node_credential(&input.credential, input.clone())
            .unwrap(),
        receipt
    );
    denied(f.db.rotate_node_credential(&f.token, input.clone()), 401);
    let mut wrong = input.clone();
    wrong.credential = secret();
    denied(f.db.rotate_node_credential(&input.credential, wrong), 409);
    let node = &f.db.nodes(&f.admin).unwrap()[0];
    assert_eq!(node.desired_revision, 0);
    assert_eq!(node.lease.generation, 1);
    assert!(node.lease.active);
    assert_eq!(node.profile.revision, 1);
    // Recovering a prior receipt must not remove a later queued rotation.
    let next = f.requested(2);
    assert_eq!(
        f.db.rotate_node_credential(&input.credential, input.clone())
            .unwrap(),
        receipt
    );
    assert_eq!(
        f.db.node_credential_status(&f.admin, &f.node)
            .unwrap()
            .pending
            .unwrap()
            .id,
        next.request_id
    );
}

#[test]
fn only_authorized_request_and_live_owner_can_replace_a_strict_node_credential() {
    let f = Fixture::new(true);
    let mut input = RotateCredential {
        request_id: Uuid::new_v4().to_string(),
        expected_revision: 1,
        credential: secret(),
        lease: f.proof.clone(),
    };
    denied(f.db.rotate_node_credential(&f.token, input), 409);
    input = f.requested(1);
    input.lease = None;
    denied(f.db.rotate_node_credential(&f.token, input.clone()), 423);
    input.lease = f.proof.clone();
    input.lease.as_mut().unwrap().token = secret();
    denied(f.db.rotate_node_credential(&f.token, input.clone()), 409);
    input.lease = f.proof.clone();
    input.expected_revision = 0;
    denied(f.db.rotate_node_credential(&f.token, input.clone()), 400);
    input.expected_revision = 1;
    input.credential = "invalid".into();
    denied(f.db.rotate_node_credential(&f.token, input), 400);
    assert_eq!(f.db.authenticate_node(&f.token).unwrap(), f.node);
}

#[test]
fn credential_rotation_permissions_revision_conflicts_and_pending_requests_are_enforced() {
    let f = Fixture::new(false);
    let viewer =
        f.db.create_user(
            &f.admin,
            "default",
            "viewer",
            "credential-test-password",
            Role::Viewer,
        )
        .unwrap();
    let tenant = f.db.create_tenant(&f.admin, "foreign").unwrap();
    let other =
        f.db.create_user(
            &f.admin,
            &tenant,
            "other",
            "credential-test-password",
            Role::TenantAdmin,
        )
        .unwrap();
    assert_eq!(
        f.db.node_credential_status(&viewer, &f.node)
            .unwrap()
            .revision,
        1
    );
    denied(f.db.request_credential_rotation(&viewer, &f.node, 1), 403);
    denied(f.db.node_credential_status(&other, &f.node), 404);
    denied(f.db.request_credential_rotation(&other, &f.node, 1), 404);
    denied(f.db.request_credential_rotation(&f.admin, &f.node, 0), 409);
    let (unregistered, _) = f.db.create_node(&f.admin, "default", "new").unwrap();
    denied(
        f.db.request_credential_rotation(&f.admin, &unregistered.id, 0),
        409,
    );
    let input = f.requested(1);
    denied(f.db.request_credential_rotation(&f.admin, &f.node, 1), 409);
    assert_eq!(
        f.db.node_credential_status(&f.admin, &f.node)
            .unwrap()
            .pending
            .unwrap()
            .id,
        input.request_id
    );
    let status =
        serde_json::to_string(&f.db.node_credential_status(&f.admin, &f.node).unwrap()).unwrap();
    let audit = serde_json::to_string(&f.db.audit_log(&f.admin).unwrap()).unwrap();
    for text in [status, audit] {
        assert!(!text.contains(&f.token));
        assert!(!text.contains(&token_hash(&f.token)));
    }
}

#[test]
fn retired_and_other_nodes_credentials_cannot_be_reused_even_for_enrollment() {
    let f = Fixture::new(false);
    let first = f.requested(1);
    f.db.rotate_node_credential(&f.token, first.clone())
        .unwrap();
    let mut next = f.requested(2);
    next.credential = f.token.clone();
    denied(
        f.db.rotate_node_credential(&first.credential, next.clone()),
        409,
    );
    next.credential = first.credential.clone();
    denied(
        f.db.rotate_node_credential(&first.credential, next.clone()),
        409,
    );
    let (other, enrollment) = f.db.create_node(&f.admin, "default", "another").unwrap();
    denied(f.db.enroll(&other.id, &enrollment, &f.token), 409);
    denied(f.db.enroll(&other.id, &enrollment, &first.credential), 409);
    let unique = secret();
    f.db.enroll(&other.id, &enrollment, &unique).unwrap();
    f.db.enroll(&other.id, &enrollment, &unique).unwrap();
    next.credential = unique;
    denied(f.db.rotate_node_credential(&first.credential, next), 409);
}

#[test]
fn concurrent_rotations_have_one_winner_and_database_failure_rolls_back_every_change() {
    let f = Fixture::new(false);
    let input = f.requested(1);
    f.db.0.lock().unwrap().execute_batch("CREATE TRIGGER fail_rotation BEFORE INSERT ON audit WHEN NEW.action='node.credential.rotate' BEGIN SELECT RAISE(ABORT,'injected rotation failure'); END").unwrap();
    assert!(
        f.db.rotate_node_credential(&f.token, input.clone())
            .is_err()
    );
    assert_eq!(f.db.authenticate_node(&f.token).unwrap(), f.node);
    denied(f.db.authenticate_node(&input.credential), 401);
    assert_eq!(
        f.db.node_credential_status(&f.admin, &f.node)
            .unwrap()
            .revision,
        1
    );
    f.db.0
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_rotation")
        .unwrap();
    let barrier = Arc::new(std::sync::Barrier::new(3));
    let jobs: Vec<_> = (0..2)
        .map(|_| {
            let db = f.db.clone();
            let token = f.token.clone();
            let barrier = barrier.clone();
            let mut input = input.clone();
            input.credential = secret();
            std::thread::spawn(move || {
                barrier.wait();
                db.rotate_node_credential(&token, input)
            })
        })
        .collect();
    barrier.wait();
    let results: Vec<_> = jobs.into_iter().map(|job| job.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        f.db.node_credential_status(&f.admin, &f.node)
            .unwrap()
            .revision,
        2
    );
}

#[test]
fn old_backup_with_complete_journal_restores_rotation_and_retired_credential_fence() {
    let f = Fixture::new(false);
    f.db.enable_recovery_log(&f.tmp.path().join("recovery.log"))
        .unwrap();
    let backup = f.tmp.path().join("before.sqlite");
    f.db.backup(&backup).unwrap();
    let input = f.requested(1);
    let receipt =
        f.db.rotate_node_credential(&f.token, input.clone())
            .unwrap();
    let expected = f.db.node_credential_status(&f.admin, &f.node).unwrap();
    let target = f.tmp.path().join("restored");
    drop(f.db);
    crate::journal::restore_controller(&backup, &f.tmp.path().join("recovery.log"), &target)
        .unwrap();
    let restored = Store::open(&target.join("controller.sqlite")).unwrap();
    restored
        .enable_recovery_log(&target.join("recovery.log"))
        .unwrap();
    assert_eq!(
        restored.node_credential_status(&f.admin, &f.node).unwrap(),
        expected
    );
    denied(restored.authenticate_node(&f.token), 401);
    assert_eq!(
        restored
            .rotate_node_credential(&input.credential, input.clone())
            .unwrap(),
        receipt
    );
    assert_eq!(restored.nodes(&f.admin).unwrap()[0].desired_revision, 0);
}
