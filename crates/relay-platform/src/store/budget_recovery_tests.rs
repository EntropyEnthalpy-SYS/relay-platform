use super::*;
use crate::budget::*;
use std::collections::HashSet;

struct BudgetFixture {
    f: Fixture,
    agent: Store,
    proof: LeaseProof,
    ledger: String,
    budget: String,
}
impl BudgetFixture {
    fn new(hierarchy: bool) -> Self {
        let f = Fixture::new();
        let budget = f
            .store
            .create_budget(
                &f.admin,
                NewBudget {
                    scope: BudgetScope::User,
                    scope_id: f.admin.id.clone(),
                    name: "resume user".into(),
                    limit_bytes: 65_536,
                    quantum_bytes: 64,
                },
            )
            .unwrap()
            .id;
        if hierarchy {
            f.store
                .create_budget(
                    &f.admin,
                    NewBudget {
                        scope: BudgetScope::Tenant,
                        scope_id: "default".into(),
                        name: "resume tenant".into(),
                        limit_bytes: 65_536,
                        quantum_bytes: 64,
                    },
                )
                .unwrap();
        }
        let rule: Rule = serde_json::from_value(serde_json::json!({
            "id":"resume-rule","tenant_id":"default","owner_id":f.admin.id,"name":"resume",
            "listen":"127.0.0.1:21000","protocol":"tcp","targets":[{"address":"127.0.0.1:21001","weight":1}],"meter_epoch":"resume-meter"
        })).unwrap();
        let config = f
            .store
            .set_config(&f.admin, &f.node.id, 0, vec![rule])
            .unwrap();
        let proof = f.claim("durable-budget-run");
        let page = f.checkpoint(Some(proof.clone())).unwrap();
        let agent = Store::open(&f._tmp.path().join("agent.sqlite")).unwrap();
        agent.set_kind("agent").unwrap();
        agent
            .set_metadata("agent_credential", "test-placeholder")
            .unwrap();
        agent.save_agent_config(&config).unwrap();
        agent.merge_checkpoint(&page, true).unwrap();
        agent
            .begin_budget_run_mode(&proof.run_id, Some(proof.generation))
            .unwrap();
        Self {
            f,
            agent,
            proof,
            ledger: page.ledger_id,
            budget,
        }
    }
    fn admit(&self, bytes: usize) -> AdmissionDecision {
        self.agent
            .admit_batch_detailed(&[Admission {
                rule_id: "resume-rule".into(),
                meter_epoch: "resume-meter".into(),
                upload: true,
                bytes,
                datagram: false,
            }])
            .unwrap()
            .remove(0)
    }
    fn exchange(&self, exchange: BudgetExchange) -> BudgetReply {
        let mut input = report(&self.ledger, Some(self.proof.clone()));
        input.budget = Some(exchange);
        self.f
            .store
            .sync(&self.f.node.id, input)
            .unwrap()
            .budget
            .unwrap()
    }
    fn allocate(&self) {
        self.admit(0);
        let response = self.exchange(self.agent.budget_outbox(&self.proof.run_id, true).unwrap());
        self.agent
            .accept_budget_reply(&self.proof.run_id, response)
            .unwrap();
    }
    fn resume(&mut self) {
        let previous = self.proof.generation;
        assert_eq!(
            self.agent.budget_resume_candidate().unwrap(),
            Some((self.proof.run_id.clone(), previous))
        );
        expire(&self.f.store, &self.f.node.id);
        let token = secret();
        let reply = self
            .f
            .store
            .exchange_lease(
                &self.f.credential,
                LeaseRequest {
                    run_id: self.proof.run_id.clone(),
                    token: token.clone(),
                    generation: None,
                    resume_generation: Some(previous),
                },
            )
            .unwrap();
        self.proof.token = token;
        self.proof.generation = reply.generation.unwrap();
        self.agent
            .resume_budget_run(&self.proof.run_id, self.proof.generation)
            .unwrap();
    }
    fn inputs(&self) -> Vec<BudgetRecoveryRequest> {
        self.agent
            .budget_recovery_batches(&self.proof.run_id)
            .unwrap()
            .into_iter()
            .map(|batch| BudgetRecoveryRequest {
                lease: self.proof.clone(),
                ledger_id: self.ledger.clone(),
                run_id: self.proof.run_id.clone(),
                claims: batch.claims,
                requests: batch.requests,
            })
            .collect()
    }
    fn recover(&self) -> Vec<BudgetReply> {
        self.inputs()
            .into_iter()
            .map(|input| {
                let reply = self
                    .f
                    .store
                    .recover_budget_run(&self.f.credential, input)
                    .unwrap();
                self.agent
                    .accept_budget_reply(&self.proof.run_id, reply.clone())
                    .unwrap();
                reply
            })
            .collect()
    }
}

#[test]
fn resume_requires_continuous_ownership_and_lost_acquisition_reply_is_idempotent() {
    let f = Fixture::new();
    let first = f.claim("run-a");
    let request = LeaseRequest {
        run_id: first.run_id.clone(),
        token: secret(),
        generation: None,
        resume_generation: Some(first.generation),
    };
    status(f.store.exchange_lease(&f.credential, request.clone()), 423);
    expire(&f.store, &f.node.id);
    let resumed = f
        .store
        .exchange_lease(&f.credential, request.clone())
        .unwrap();
    assert_eq!(resumed.generation, Some(2));
    assert_eq!(
        f.store
            .exchange_lease(&f.credential, request.clone())
            .unwrap()
            .generation,
        Some(2)
    );
    expire(&f.store, &f.node.id);
    assert_eq!(
        f.store
            .exchange_lease(&f.credential, request)
            .unwrap()
            .generation,
        Some(3)
    );
    expire(&f.store, &f.node.id);
    f.claim("intervening-run");
    status(
        f.store.exchange_lease(
            &f.credential,
            LeaseRequest {
                run_id: first.run_id,
                token: secret(),
                generation: None,
                resume_generation: Some(3),
            },
        ),
        412,
    );
}

#[test]
fn retained_grants_report_unconfirmed_consumption_then_resume_without_stranding_credit() {
    let mut f = BudgetFixture::new(false);
    f.allocate();
    assert!(matches!(f.admit(17), AdmissionDecision::Admitted(17)));
    status(
        f.f.store
            .recover_budget_run(&f.f.credential, f.inputs().remove(0)),
        409,
    );
    f.resume();
    let reply = f.recover().remove(0);
    assert_eq!(reply.acknowledgements[0].consumed_bytes, 17);
    assert!(!reply.acknowledgements[0].surrender);
    let budget = &f.f.store.budgets(&f.f.admin).unwrap().budgets[0];
    assert_eq!((budget.consumed_bytes, budget.committed_bytes), (17, 64));
    assert!(matches!(f.admit(47), AdmissionDecision::Admitted(47)));
    f.agent.seal_budget_run(&f.proof.run_id).unwrap();
    let input = f.inputs().remove(0);
    let first =
        f.f.store
            .recover_budget_run(&f.f.credential, input.clone())
            .unwrap();
    let retry =
        f.f.store
            .recover_budget_run(&f.f.credential, input)
            .unwrap();
    assert_eq!(
        serde_json::to_value(&first).unwrap(),
        serde_json::to_value(retry).unwrap()
    );
    f.agent.accept_budget_reply(&f.proof.run_id, first).unwrap();
    assert!(f.agent.budget_resume_candidate().unwrap().is_none());
    let budget = &f.f.store.budgets(&f.f.admin).unwrap().budgets[0];
    assert_eq!((budget.consumed_bytes, budget.committed_bytes), (64, 64));
}

#[test]
fn resume_recovers_a_lost_grant_reply_and_cancels_requests_never_allocated() {
    let mut f = BudgetFixture::new(true);
    f.admit(0);
    let mut input = f.agent.budget_outbox(&f.proof.run_id, true).unwrap();
    assert_eq!(input.requests.len(), 2);
    input.requests.truncate(1);
    let lost = f.exchange(input);
    assert_eq!(lost.grants.len(), 1);
    f.resume();
    let reply = f.recover().remove(0);
    assert_eq!((reply.grants.len(), reply.cancelled_requests.len()), (1, 1));
    assert_eq!(reply.grants[0].grant_id, lost.grants[0].grant_id);
    assert_eq!(
        f.f.store
            .budgets(&f.f.admin)
            .unwrap()
            .budgets
            .iter()
            .map(|b| b.committed_bytes)
            .sum::<u64>(),
        64
    );
    assert!(
        f.agent
            .budget_outbox(&f.proof.run_id, false)
            .unwrap()
            .requests
            .is_empty()
    );
    assert!(matches!(f.admit(17), AdmissionDecision::AwaitingBudget));
    let reply = f.exchange(f.agent.budget_outbox(&f.proof.run_id, true).unwrap());
    f.agent.accept_budget_reply(&f.proof.run_id, reply).unwrap();
    assert!(matches!(f.admit(17), AdmissionDecision::Admitted(17)));
}

#[test]
fn pending_recovery_grant_must_belong_to_the_reconciled_ledger() {
    let mut f = BudgetFixture::new(false);
    f.admit(0);
    let lost = f.exchange(f.agent.budget_outbox(&f.proof.run_id, true).unwrap());
    f.resume();
    f.f.store
        .0
        .lock()
        .unwrap()
        .execute(
            "UPDATE budget_grants SET ledger_id='foreign-ledger' WHERE id=?1",
            [&lost.grants[0].grant_id],
        )
        .unwrap();
    status(
        f.f.store
            .recover_budget_run(&f.f.credential, f.inputs().remove(0)),
        409,
    );
    assert_eq!(
        f.f.store.budgets(&f.f.admin).unwrap().budgets[0].committed_bytes,
        64
    );
}

#[test]
fn managed_backup_removes_resume_authority_and_fresh_runs_keep_unknown_credit_isolated() {
    let f = BudgetFixture::new(false);
    f.allocate();
    assert!(f.agent.budget_resume_candidate().unwrap().is_some());
    let path = f.f._tmp.path().join("copy.sqlite");
    f.agent.backup(&path).unwrap();
    let copied = Store::open(&path).unwrap();
    assert!(copied.budget_resume_candidate().unwrap().is_none());
    copied.begin_budget_run_mode("new-run", Some(2)).unwrap();
    let count: u64 = copied
        .0
        .lock()
        .unwrap()
        .query_row(
            "SELECT COUNT(*) FROM agent_budget_grants WHERE state='abandoned'",
            [],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(count, 1);
    assert_eq!(
        f.f.store.budgets(&f.f.admin).unwrap().budgets[0].committed_bytes,
        64
    );
    assert!(f.agent.budget_resume_candidate().unwrap().is_some());
}

#[test]
fn invalid_inventory_or_failed_commit_cannot_partially_report_or_refund() {
    let mut f = BudgetFixture::new(false);
    f.allocate();
    f.admit(17);
    f.resume();
    let input = f.inputs().remove(0);
    let mut invalid = input.clone();
    let mut forged = invalid.claims[0].clone();
    forged.grant.grant_id = "missing-grant".into();
    forged.grant.request_id = "missing-request".into();
    invalid.claims.push(forged);
    status(f.f.store.recover_budget_run(&f.f.credential, invalid), 409);
    assert_eq!(
        f.f.store.budgets(&f.f.admin).unwrap().budgets[0].consumed_bytes,
        0
    );
    f.f.store.0.lock().unwrap().execute_batch("CREATE TRIGGER fail_recovery BEFORE INSERT ON audit WHEN NEW.action='budget.run.recover' BEGIN SELECT RAISE(ABORT,'recovery commit failure'); END;").unwrap();
    assert!(
        f.f.store
            .recover_budget_run(&f.f.credential, input.clone())
            .is_err()
    );
    let budget = &f.f.store.budgets(&f.f.admin).unwrap().budgets[0];
    assert_eq!((budget.consumed_bytes, budget.committed_bytes), (0, 64));
    f.f.store
        .0
        .lock()
        .unwrap()
        .execute_batch("DROP TRIGGER fail_recovery;")
        .unwrap();
    f.f.store
        .recover_budget_run(&f.f.credential, input)
        .unwrap();
    assert_eq!(
        f.f.store.budgets(&f.f.admin).unwrap().budgets[0].consumed_bytes,
        17
    );
}

#[test]
fn stale_claims_paused_controller_and_wrong_identity_never_authorize_reuse() {
    let mut f = BudgetFixture::new(false);
    f.allocate();
    f.admit(17);
    let reply = f.exchange(f.agent.budget_outbox(&f.proof.run_id, false).unwrap());
    f.agent.accept_budget_reply(&f.proof.run_id, reply).unwrap();
    f.resume();
    let input = f.inputs().remove(0);
    let mut stale = input.clone();
    stale.claims[0].consumed_bytes = 0;
    status(f.f.store.recover_budget_run(&f.f.credential, stale), 409);
    let mut wrong = input.clone();
    wrong.lease.token = secret();
    status(f.f.store.recover_budget_run(&f.f.credential, wrong), 409);
    let mut wrong = input.clone();
    wrong.ledger_id = "foreign-ledger".into();
    status(f.f.store.recover_budget_run(&f.f.credential, wrong), 409);
    status(f.f.store.recover_budget_run(&secret(), input.clone()), 401);
    f.f.store
        .set_metadata("budget_allocation_paused", "true")
        .unwrap();
    status(f.f.store.recover_budget_run(&f.f.credential, input), 409);
    let budget = &f.f.store.budgets(&f.f.admin).unwrap().budgets[0];
    assert_eq!((budget.consumed_bytes, budget.committed_bytes), (17, 64));
}

#[test]
fn reservation_inventory_is_paginated_tenant_scoped_and_never_contains_credentials() {
    let f = BudgetFixture::new(false);
    f.exchange(BudgetExchange {
        settle_only: false,
        run_id: f.proof.run_id.clone(),
        reports: vec![],
        requests: (0..201)
            .map(|n| GrantRequest {
                budget_id: f.budget.clone(),
                request_id: format!("request-{n}"),
                minimum_bytes: 1,
            })
            .collect(),
    });
    let mut viewer = f.f.admin.clone();
    viewer.role = Role::Viewer;
    let first =
        f.f.store
            .budget_reservations(&viewer, &f.budget, None)
            .unwrap();
    assert_eq!(first.reservations.len(), 100);
    let second =
        f.f.store
            .budget_reservations(&viewer, &f.budget, first.next.as_deref())
            .unwrap();
    assert_eq!(second.reservations.len(), 100);
    let third =
        f.f.store
            .budget_reservations(&viewer, &f.budget, second.next.as_deref())
            .unwrap();
    assert_eq!(third.reservations.len(), 1);
    assert!(third.next.is_none());
    let ids: HashSet<_> = first
        .reservations
        .iter()
        .chain(&second.reservations)
        .chain(&third.reservations)
        .map(|r| r.grant_id.clone())
        .collect();
    assert_eq!(ids.len(), 201);
    let body = serde_json::to_string(&first).unwrap();
    assert!(!body.contains(&f.f.credential));
    assert!(!body.contains(&f.proof.token));
    assert!(!body.contains("token_hash"));
    viewer.tenant_id = "other".into();
    status(f.f.store.budget_reservations(&viewer, &f.budget, None), 404);
    status(
        f.f.store
            .budget_reservations(&f.f.admin, &f.budget, Some("bad cursor")),
        400,
    );
}
