use super::*;
use crate::budget::BudgetExchange;

#[path = "budget_recovery_tests.rs"]
mod budget_recovery_tests;

struct Fixture {
    _tmp: tempfile::TempDir,
    store: Store,
    admin: Actor,
    node: Node,
    credential: String,
}
impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(&tmp.path().join("controller.sqlite")).unwrap();
        store.set_kind("controller").unwrap();
        let admin = store.bootstrap("lease-test-password-long-enough").unwrap();
        let (node, enrollment) = store
            .create_node_with_lease(
                &admin,
                "default",
                "strict",
                Some(LeasePolicy { ttl_ms: 5000 }),
            )
            .unwrap();
        let credential = secret();
        store.enroll(&node.id, &enrollment, &credential).unwrap();
        Self {
            _tmp: tmp,
            store,
            admin,
            node,
            credential,
        }
    }
    fn claim(&self, run: &str) -> LeaseProof {
        let token = secret();
        let reply = self
            .store
            .exchange_lease(
                &self.credential,
                LeaseRequest {
                    resume_generation: None,
                    run_id: run.into(),
                    token: token.clone(),
                    generation: None,
                },
            )
            .unwrap();
        LeaseProof {
            run_id: run.into(),
            token,
            generation: reply.generation.unwrap(),
        }
    }
    fn checkpoint(&self, proof: Option<LeaseProof>) -> Result<ReconcileResponse> {
        self.store.reconcile(
            &self.node.id,
            ReconcileRequest {
                lease: proof,
                ledger_id: None,
                after: None,
                expected_revision: None,
            },
        )
    }
}
fn status<T: std::fmt::Debug>(result: Result<T>, expected: u16) {
    let error = result.unwrap_err();
    assert_eq!(
        error.downcast_ref::<Rejection>().unwrap().status,
        expected,
        "{error}"
    );
}
fn report(ledger: &str, proof: Option<LeaseProof>) -> SyncRequest {
    SyncRequest {
        lease: proof,
        budget: None,
        ledger_id: ledger.into(),
        need_config: false,
        applied_revision: 0,
        apply_error: None,
        usage: vec![],
        stats: EngineStats::default(),
    }
}
fn expire(store: &Store, node: &str) {
    let mut clocks = store.3.lock().unwrap();
    let past = Instant::now() - Duration::from_secs(1);
    let clock = clocks.nodes.get_mut(node).unwrap();
    clock.expires = past;
    clock.recovery_until = past;
}

#[test]
fn strict_lease_fences_reconciliation_sync_and_budget_run_before_any_write() {
    let f = Fixture::new();
    status(f.checkpoint(None), 423);
    let proof = f.claim("run-a");
    let page = f.checkpoint(Some(proof.clone())).unwrap();
    let mut wrong = proof.clone();
    wrong.token = secret();
    status(f.checkpoint(Some(wrong.clone())), 409);
    let mut input = report(&page.ledger_id, Some(proof.clone()));
    input.stats.accepted_tcp = 7;
    let mut stale = report(&page.ledger_id, Some(wrong));
    stale.stats.accepted_tcp = 900;
    let replies = f
        .store
        .sync_authenticated_batch(vec![
            (f.credential.clone(), input),
            (f.credential.clone(), stale),
        ])
        .unwrap();
    assert!(replies[0].is_ok());
    assert_eq!(
        replies[1]
            .as_ref()
            .unwrap_err()
            .downcast_ref::<Rejection>()
            .unwrap()
            .status,
        409
    );
    assert_eq!(f.store.nodes(&f.admin).unwrap()[0].stats.accepted_tcp, 7);
    let mut input = report(&page.ledger_id, Some(proof.clone()));
    input.budget = Some(BudgetExchange {
        run_id: "different-run".into(),
        settle_only: false,
        requests: vec![],
        reports: vec![],
    });
    status(f.store.sync(&f.node.id, input), 409);
    expire(&f.store, &f.node.id);
    status(
        f.store
            .sync(&f.node.id, report(&page.ledger_id, Some(proof.clone()))),
        409,
    );
    let next = f.claim("run-b");
    assert!(next.generation > proof.generation);
    let fresh = f.store.nodes(&f.admin).unwrap();
    assert!(fresh[0].last_seen_ms.is_none());
    assert_eq!(fresh[0].stats.accepted_tcp, 0);
    status(
        f.store
            .sync(&f.node.id, report(&page.ledger_id, Some(proof))),
        409,
    );
    f.store
        .sync(&f.node.id, report(&page.ledger_id, Some(next)))
        .unwrap();
}

#[test]
fn concurrent_claims_have_one_owner_and_retries_do_not_renew_or_expose_the_secret() {
    let f = Fixture::new();
    let barrier = Arc::new(std::sync::Barrier::new(8));
    let mut threads = vec![];
    for n in 0..8 {
        let db = f.store.clone();
        let credential = f.credential.clone();
        let barrier = barrier.clone();
        threads.push(std::thread::spawn(move || {
            let request = LeaseRequest {
                resume_generation: None,
                run_id: format!("process-{n}"),
                token: secret(),
                generation: None,
            };
            barrier.wait();
            let result = db.exchange_lease(&credential, request.clone());
            (request, result)
        }));
    }
    let outcomes: Vec<_> = threads.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(outcomes.iter().filter(|(_, r)| r.is_ok()).count(), 1);
    for (_, result) in outcomes.iter().filter(|(_, r)| r.is_err()) {
        assert_eq!(
            result
                .as_ref()
                .unwrap_err()
                .downcast_ref::<Rejection>()
                .unwrap()
                .status,
            423
        );
    }
    let (request, first) = outcomes.into_iter().find(|(_, r)| r.is_ok()).unwrap();
    let first = first.unwrap();
    let before = f.store.3.lock().unwrap().nodes[&f.node.id].expires;
    let again = f
        .store
        .exchange_lease(&f.credential, request.clone())
        .unwrap();
    assert_eq!(again.generation, first.generation);
    assert_eq!(f.store.3.lock().unwrap().nodes[&f.node.id].expires, before);
    let proof = LeaseProof {
        run_id: request.run_id,
        token: request.token,
        generation: first.generation.unwrap(),
    };
    assert!(!format!("{proof:?}").contains(&proof.token));
    let visible = serde_json::to_string(&f.store.nodes(&f.admin).unwrap()).unwrap();
    assert!(!visible.contains(&proof.token));
    assert!(!visible.contains(&token_hash(&proof.token)));
    let busy = EngineStats {
        active_tcp: 1,
        ..Default::default()
    };
    status(
        f.store.release_lease(
            &f.credential,
            LeaseRelease {
                proof: proof.clone(),
                stats: busy,
            },
        ),
        409,
    );
    f.store
        .release_lease(
            &f.credential,
            LeaseRelease {
                proof: proof.clone(),
                stats: EngineStats::default(),
            },
        )
        .unwrap();
    let next = f.claim("replacement");
    assert_eq!(next.generation, proof.generation + 1);
    status(
        f.store.release_lease(
            &f.credential,
            LeaseRelease {
                proof,
                stats: EngineStats::default(),
            },
        ),
        409,
    );
}

#[test]
fn restart_and_pre_grant_backup_quarantine_takeover_without_using_wall_time() {
    let f = Fixture::new();
    let backup = f._tmp.path().join("before-grant.sqlite");
    f.store.backup(&backup).unwrap();
    let proof = f.claim("old-live-process");
    let reopened = Store::open(&f._tmp.path().join("controller.sqlite")).unwrap();
    let renewed = reopened
        .exchange_lease(
            &f.credential,
            LeaseRequest {
                resume_generation: None,
                run_id: proof.run_id.clone(),
                token: proof.token.clone(),
                generation: Some(proof.generation),
            },
        )
        .unwrap();
    assert_eq!(renewed.generation, Some(proof.generation));
    status(
        reopened.exchange_lease(
            &f.credential,
            LeaseRequest {
                resume_generation: None,
                run_id: "contender".into(),
                token: secret(),
                generation: None,
            },
        ),
        423,
    );
    let restored = Store::open(&backup).unwrap();
    let contender = LeaseRequest {
        resume_generation: None,
        run_id: "new-process".into(),
        token: secret(),
        generation: None,
    };
    status(
        restored.exchange_lease(&f.credential, contender.clone()),
        423,
    );
    let visible = restored.nodes(&f.admin).unwrap();
    assert!(!visible[0].lease.active);
    assert!(visible[0].lease.recovery_wait_ms > 0);
    expire(&restored, &f.node.id);
    let replacement = restored.exchange_lease(&f.credential, contender).unwrap();
    // A stale backup can reuse a numeric generation. The random proof still fences it.
    assert_eq!(replacement.generation, Some(proof.generation));
    status(
        restored.reconcile(
            &f.node.id,
            ReconcileRequest {
                lease: Some(proof),
                ledger_id: None,
                after: None,
                expected_revision: None,
            },
        ),
        409,
    );
}

#[test]
fn failed_grant_or_release_commit_does_not_publish_a_runtime_owner_change() {
    let f = Fixture::new();
    let fail = "CREATE TRIGGER fail_lease BEFORE UPDATE ON metadata WHEN NEW.key LIKE 'node_lease:%' BEGIN SELECT RAISE(ABORT,'injected lease write failure'); END;";
    f.store.0.lock().unwrap().execute_batch(fail).unwrap();
    assert!(
        f.store
            .exchange_lease(
                &f.credential,
                LeaseRequest {
                    resume_generation: None,
                    run_id: "failed".into(),
                    token: secret(),
                    generation: None
                }
            )
            .is_err()
    );
    assert!(!f.store.nodes(&f.admin).unwrap()[0].lease.active);
    f.store
        .0
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_lease")
        .unwrap();
    let proof = f.claim("accepted");
    assert_eq!(proof.generation, 1);
    f.store.0.lock().unwrap().execute_batch(fail).unwrap();
    assert!(
        f.store
            .release_lease(
                &f.credential,
                LeaseRelease {
                    proof: proof.clone(),
                    stats: EngineStats::default()
                }
            )
            .is_err()
    );
    assert!(f.store.nodes(&f.admin).unwrap()[0].lease.active);
    f.checkpoint(Some(proof.clone())).unwrap();
    status(
        f.store.exchange_lease(
            &f.credential,
            LeaseRequest {
                resume_generation: None,
                run_id: "blocked".into(),
                token: secret(),
                generation: None,
            },
        ),
        423,
    );
    f.store
        .0
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_lease")
        .unwrap();
    f.store
        .release_lease(
            &f.credential,
            LeaseRelease {
                proof,
                stats: EngineStats::default(),
            },
        )
        .unwrap();
    assert_eq!(f.claim("next").generation, 2);
}

#[test]
fn complete_recovery_log_restores_policy_and_owner_without_logging_the_secret() {
    let f = Fixture::new();
    let log = f._tmp.path().join("recovery.log");
    f.store.enable_recovery_log(&log).unwrap();
    let backup = f._tmp.path().join("old.sqlite");
    f.store.backup(&backup).unwrap();
    let proof = f.claim("after-backup");
    f.checkpoint(Some(proof.clone())).unwrap();
    let head = crate::journal::head_path(&log);
    let copied = f._tmp.path().join("copied.log");
    std::fs::copy(&log, &copied).unwrap();
    std::fs::copy(&head, crate::journal::head_path(&copied)).unwrap();
    let destination = f._tmp.path().join("restored");
    crate::journal::restore_controller(&backup, &copied, &destination).unwrap();
    let recovered = Store::open(&destination.join("controller.sqlite")).unwrap();
    recovered
        .enable_recovery_log(&destination.join("recovery.log"))
        .unwrap();
    let reply = recovered
        .exchange_lease(
            &f.credential,
            LeaseRequest {
                resume_generation: None,
                run_id: proof.run_id.clone(),
                token: proof.token.clone(),
                generation: Some(proof.generation),
            },
        )
        .unwrap();
    assert_eq!(reply.generation, Some(proof.generation));
    assert!(recovered.nodes(&f.admin).unwrap()[0].lease.active);
    let bytes = std::fs::read(&copied).unwrap();
    assert!(
        !bytes
            .windows(proof.token.len())
            .any(|w| w == proof.token.as_bytes())
    );
}
