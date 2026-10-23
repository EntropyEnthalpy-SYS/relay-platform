mod common;
use common::*;
use relay_platform::{
    budget::*,
    model::*,
    store::{Actor, Admission, Rejection, Role, Store},
};

struct Fixture {
    tmp: tempfile::TempDir,
    control: Store,
    admin: Actor,
    nodes: Vec<String>,
    agents: Vec<Store>,
    rules: Vec<Rule>,
    runs: Vec<String>,
    ledgers: Vec<String>,
    user_budget: Budget,
}
impl Fixture {
    fn new(limit: u64, quantum: u64, hierarchy: bool) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let control = Store::open(&tmp.path().join("control.db")).unwrap();
        let admin = control.bootstrap(PASSWORD).unwrap();
        let nodes = (0..2)
            .map(|n| {
                control
                    .create_node(&admin, "default", &format!("node-{n}"))
                    .unwrap()
                    .0
                    .id
            })
            .collect::<Vec<_>>();
        let user_budget = control
            .create_budget(
                &admin,
                NewBudget {
                    scope: BudgetScope::User,
                    scope_id: admin.id.clone(),
                    name: "shared user".into(),
                    limit_bytes: limit,
                    quantum_bytes: quantum,
                },
            )
            .unwrap();
        if hierarchy {
            control
                .create_budget(
                    &admin,
                    NewBudget {
                        scope: BudgetScope::Tenant,
                        scope_id: "default".into(),
                        name: "tenant".into(),
                        limit_bytes: 50,
                        quantum_bytes: 32,
                    },
                )
                .unwrap();
            control
                .create_budget(
                    &admin,
                    NewBudget {
                        scope: BudgetScope::Node,
                        scope_id: nodes[0].clone(),
                        name: "node".into(),
                        limit_bytes: 24,
                        quantum_bytes: 24,
                    },
                )
                .unwrap();
        }
        let mut agents = vec![];
        let mut rules = vec![];
        let mut runs = vec![];
        let mut ledgers = vec![];
        for (n, node) in nodes.iter().enumerate() {
            let mut r = rule("127.0.0.1:8888".parse().unwrap(), Protocol::Both);
            r.id = format!("rule-{n}");
            r.owner_id = admin.id.clone();
            let config = control.set_config(&admin, node, 0, vec![r]).unwrap();
            rules.push(config.rules[0].clone());
            let db = Store::open(&tmp.path().join(format!("agent-{n}.db"))).unwrap();
            db.save_agent_config(&config).unwrap();
            let page = control
                .reconcile(
                    node,
                    ReconcileRequest {
                        ledger_id: None,
                        after: None,
                        expected_revision: None,
                    },
                )
                .unwrap();
            db.merge_checkpoint(&page, true).unwrap();
            ledgers.push(page.ledger_id);
            runs.push(db.start_budget_run().unwrap());
            db.admit_batch(&[admission(&config.rules[0], 0, true)])
                .unwrap();
            agents.push(db);
        }
        Self {
            tmp,
            control,
            admin,
            nodes,
            agents,
            rules,
            runs,
            ledgers,
            user_budget,
        }
    }
    fn request(&self, n: usize, exchange: BudgetExchange) -> SyncRequest {
        SyncRequest {
            budget: Some(exchange),
            ledger_id: self.ledgers[n].clone(),
            need_config: false,
            applied_revision: 1,
            apply_error: None,
            usage: vec![],
            stats: EngineStats::default(),
        }
    }
    fn sync(&self, n: usize) -> BudgetReply {
        let exchange = self.agents[n].budget_outbox(&self.runs[n], true).unwrap();
        let reply = self
            .control
            .sync(&self.nodes[n], self.request(n, exchange))
            .unwrap()
            .budget
            .unwrap();
        self.agents[n]
            .accept_budget_reply(&self.runs[n], reply.clone())
            .unwrap();
        reply
    }
    fn user(&self) -> Budget {
        self.control
            .budgets(&self.admin)
            .unwrap()
            .budgets
            .into_iter()
            .find(|b| b.id == self.user_budget.id)
            .unwrap()
    }
}
fn admission(rule: &Rule, bytes: usize, datagram: bool) -> Admission {
    Admission {
        rule_id: rule.id.clone(),
        meter_epoch: rule.meter_epoch.clone(),
        upload: true,
        bytes,
        datagram,
    }
}
fn status<T>(result: anyhow::Result<T>) -> u16 {
    result
        .err()
        .unwrap()
        .downcast_ref::<Rejection>()
        .unwrap()
        .status
}

#[test]
fn concurrent_nodes_and_replayed_requests_cannot_multiply_a_user_budget() {
    let f = Fixture::new(100, 64, false);
    let exchanges = (0..2)
        .map(|n| f.agents[n].budget_outbox(&f.runs[n], true).unwrap())
        .collect::<Vec<_>>();
    let replies = std::thread::scope(|scope| {
        let handles = (0..2)
            .map(|n| {
                let request = f.request(n, exchanges[n].clone());
                let control = &f.control;
                let node = &f.nodes[n];
                scope.spawn(move || control.sync(node, request).unwrap().budget.unwrap())
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert_eq!(
        replies
            .iter()
            .flat_map(|r| &r.grants)
            .map(|g| g.bytes)
            .sum::<u64>(),
        100
    );
    let mut spent = 0;
    for n in 0..2 {
        let duplicate = f
            .control
            .sync(&f.nodes[n], f.request(n, exchanges[n].clone()))
            .unwrap()
            .budget
            .unwrap();
        assert_eq!(duplicate.grants[0].grant_id, replies[n].grants[0].grant_id);
        f.agents[n]
            .accept_budget_reply(&f.runs[n], duplicate)
            .unwrap();
        spent += f.agents[n]
            .admit_batch(&[admission(&f.rules[n], 100, false)])
            .unwrap()[0]
            .unwrap();
        assert_eq!(
            f.agents[n]
                .admit_batch(&[admission(&f.rules[n], 1, false)])
                .unwrap(),
            vec![None]
        );
        f.sync(n);
    }
    assert_eq!(spent, 100);
    assert_eq!(f.user().committed_bytes, 100);
    assert_eq!(f.user().consumed_bytes, 100);
}

#[test]
fn hierarchical_limits_are_atomic_and_udp_never_partially_consumes_other_scopes() {
    let f = Fixture::new(100, 64, true);
    f.sync(0);
    f.sync(1);
    assert_eq!(f.rules[0].budget_ids.len(), 3);
    assert_eq!(
        f.agents[0]
            .admit_batch(&[
                admission(&f.rules[0], 0, true),
                admission(&f.rules[0], 20, true),
                admission(&f.rules[0], 10, true)
            ])
            .unwrap(),
        vec![Some(0), Some(20), None]
    );
    f.sync(0);
    for budget in f.control.budgets(&f.admin).unwrap().budgets {
        assert_eq!(budget.consumed_bytes, 20);
    }
    assert_eq!(
        f.agents[1]
            .admit_batch(&[admission(&f.rules[1], 100, false)])
            .unwrap(),
        vec![Some(18)]
    );
    assert_eq!(
        f.agents[0]
            .admit_batch(&[admission(&f.rules[0], 100, false)])
            .unwrap(),
        vec![Some(4)]
    );
    f.sync(0);
    f.sync(1);
    let budgets = f.control.budgets(&f.admin).unwrap().budgets;
    assert_eq!(
        budgets
            .iter()
            .find(|b| b.scope == BudgetScope::Node)
            .unwrap()
            .consumed_bytes,
        24
    );
    assert_eq!(
        budgets
            .iter()
            .find(|b| b.scope == BudgetScope::Tenant)
            .unwrap()
            .consumed_bytes,
        42
    );
    assert_eq!(f.user().consumed_bytes, 42);
}

#[test]
fn failed_meter_transaction_rolls_back_reservation_consumption_as_well() {
    let f = Fixture::new(100, 64, false);
    f.sync(0);
    let raw = rusqlite::Connection::open(f.tmp.path().join("agent-0.db")).unwrap();
    raw.execute_batch("CREATE TRIGGER fail_meter BEFORE UPDATE OF upload_bytes ON agent_meters BEGIN SELECT RAISE(ABORT,'injected meter failure'); END;").unwrap();
    assert!(
        f.agents[0]
            .admit_batch(&[admission(&f.rules[0], 10, false)])
            .is_err()
    );
    assert!(f.agents[0].agent_usage(false).unwrap().is_empty());
    f.sync(0);
    assert_eq!(f.user().consumed_bytes, 0);
    raw.execute_batch("DROP TRIGGER fail_meter").unwrap();
    assert_eq!(
        f.agents[0]
            .admit_batch(&[admission(&f.rules[0], 64, false)])
            .unwrap(),
        vec![Some(64)]
    );
}

#[test]
fn invalid_report_rolls_back_other_reports_and_retry_updates_totals_once() {
    let f = Fixture::new(100, 64, false);
    f.sync(0);
    f.agents[0]
        .admit_batch(&[admission(&f.rules[0], 25, false)])
        .unwrap();
    f.agents[0].seal_budget_run(&f.runs[0]).unwrap();
    let closing = f.agents[0].budget_outbox(&f.runs[0], false).unwrap();
    let mut invalid = closing.clone();
    invalid.reports.push(GrantReport {
        grant_id: "unknown-reservation".into(),
        consumed_bytes: 1,
        surrender: false,
    });
    assert_eq!(
        status(f.control.sync(&f.nodes[0], f.request(0, invalid))),
        409
    );
    assert_eq!(f.user().consumed_bytes, 0);
    assert_eq!(f.user().committed_bytes, 64);
    // Simulate losing the successful response and retrying the same outbox.
    for _ in 0..2 {
        f.control
            .sync(&f.nodes[0], f.request(0, closing.clone()))
            .unwrap();
        assert_eq!(f.user().consumed_bytes, 25);
        assert_eq!(f.user().committed_bytes, 25);
    }
    let mut stale = closing.clone();
    stale.reports[0].consumed_bytes = 10;
    stale.reports[0].surrender = false;
    let reply = f
        .control
        .sync(&f.nodes[0], f.request(0, stale))
        .unwrap()
        .budget
        .unwrap();
    assert_eq!(reply.acknowledgements[0].consumed_bytes, 25);
    assert!(reply.acknowledgements[0].surrender);
    let mut conflicting = closing;
    conflicting.reports[0].consumed_bytes = 26;
    assert_eq!(
        status(f.control.sync(&f.nodes[0], f.request(0, conflicting))),
        409
    );
    assert_eq!(f.user().consumed_bytes, 25);
    assert_eq!(f.user().committed_bytes, 25);
}

#[test]
fn graceful_surrender_returns_only_unused_bytes_and_duplicate_surrender_is_idempotent() {
    let f = Fixture::new(100, 64, false);
    f.sync(0);
    f.agents[0]
        .admit_batch(&[admission(&f.rules[0], 25, false)])
        .unwrap();
    f.agents[0].seal_budget_run(&f.runs[0]).unwrap();
    assert_eq!(
        f.agents[0]
            .admit_batch(&[admission(&f.rules[0], 1, false)])
            .unwrap(),
        vec![None]
    );
    let closing = f.agents[0].budget_outbox(&f.runs[0], false).unwrap();
    assert!(closing.reports[0].surrender);
    for _ in 0..2 {
        let response = f
            .control
            .sync(&f.nodes[0], f.request(0, closing.clone()))
            .unwrap()
            .budget
            .unwrap();
        f.agents[0]
            .accept_budget_reply(&f.runs[0], response)
            .unwrap();
        assert_eq!(f.user().committed_bytes, 25);
        assert_eq!(f.user().consumed_bytes, 25);
    }
    assert!(
        f.agents[0]
            .budget_outbox(&f.runs[0], false)
            .unwrap()
            .reports
            .is_empty()
    );
    assert_eq!(f.sync(1).grants[0].bytes, 64);
    assert_eq!(f.user().committed_bytes, 89);
}

#[test]
fn restart_and_old_snapshot_never_reuse_an_older_runs_unspent_grant() {
    let f = Fixture::new(150, 100, false);
    let old_grant = f.sync(0).grants[0].grant_id.clone();
    let path = f.tmp.path().join("snapshot.db");
    f.agents[0].backup(&path).unwrap();
    let restored = Store::open(&path).unwrap();
    let new_run = restored.start_budget_run().unwrap();
    assert_eq!(
        restored
            .admit_batch(&[admission(&f.rules[0], 1, false)])
            .unwrap(),
        vec![None]
    );
    // Even if the old process still exists, its 100-byte reservation stays charged.
    let exchange = restored.budget_outbox(&new_run, true).unwrap();
    assert!(exchange.reports.is_empty());
    let mut request = f.request(0, exchange);
    request.usage.clear();
    let reply = f
        .control
        .sync(&f.nodes[0], request)
        .unwrap()
        .budget
        .unwrap();
    assert_eq!(reply.grants[0].bytes, 50);
    restored.accept_budget_reply(&new_run, reply).unwrap();
    assert_eq!(
        restored
            .admit_batch(&[admission(&f.rules[0], 100, false)])
            .unwrap(),
        vec![Some(50)]
    );
    assert_eq!(
        f.agents[0]
            .admit_batch(&[admission(&f.rules[0], 100, false)])
            .unwrap(),
        vec![Some(100)]
    );
    restored.seal_budget_run(&f.runs[0]).unwrap();
    let old_reports = restored.budget_outbox(&new_run, false).unwrap();
    assert!(
        old_reports
            .reports
            .iter()
            .filter(|r| r.grant_id == old_grant)
            .all(|r| !r.surrender)
    );
    assert_eq!(f.user().committed_bytes, 150);
}

#[test]
fn budget_activation_requires_quiescence_and_published_bindings_cannot_be_removed() {
    let f = Fixture::new(100, 64, false);
    let input = NewBudget {
        scope: BudgetScope::Tenant,
        scope_id: "default".into(),
        name: "tenant".into(),
        limit_bytes: 200,
        quantum_bytes: 64,
    };
    assert_eq!(
        status(f.control.create_budget(&f.admin, input.clone())),
        409
    );
    for n in 0..2 {
        f.control
            .set_config(&f.admin, &f.nodes[n], 1, vec![])
            .unwrap();
    }
    assert_eq!(
        status(f.control.create_budget(&f.admin, input.clone())),
        409,
        "removing a rule without node acknowledgement is not quiescence"
    );
    for n in 0..2 {
        let mut request = f.request(
            n,
            BudgetExchange {
                run_id: f.runs[n].clone(),
                reports: vec![],
                requests: vec![],
            },
        );
        request.applied_revision = 2;
        f.control.sync(&f.nodes[n], request).unwrap();
    }
    let tenant = f.control.create_budget(&f.admin, input).unwrap();
    let mut raw = f.rules[0].clone();
    raw.budget_ids.clear();
    let published = f
        .control
        .set_config(&f.admin, &f.nodes[0], 2, vec![raw])
        .unwrap();
    assert!(published.rules[0].budget_ids.contains(&f.user_budget.id));
    assert!(published.rules[0].budget_ids.contains(&tenant.id));
}

#[test]
fn budget_permissions_revision_conflicts_and_committed_floor_are_enforced() {
    let f = Fixture::new(100, 64, false);
    f.sync(0);
    let viewer = f
        .control
        .create_user(&f.admin, "default", "viewer-budget", PASSWORD, Role::Viewer)
        .unwrap();
    let tenant = f.control.create_tenant(&f.admin, "other").unwrap();
    let foreign = f
        .control
        .create_user(
            &f.admin,
            &tenant,
            "foreign-budget",
            PASSWORD,
            Role::TenantAdmin,
        )
        .unwrap();
    let change = BudgetUpdate {
        expected_revision: 1,
        limit_bytes: 200,
        quantum_bytes: 32,
    };
    assert_eq!(
        status(
            f.control
                .update_budget(&viewer, &f.user_budget.id, change.clone())
        ),
        403
    );
    assert_eq!(
        status(
            f.control
                .update_budget(&foreign, &f.user_budget.id, change.clone())
        ),
        403
    );
    assert!(f.control.budgets(&foreign).unwrap().budgets.is_empty());
    assert_eq!(
        status(f.control.create_budget(
            &foreign,
            NewBudget {
                scope: BudgetScope::Node,
                scope_id: f.nodes[0].clone(),
                name: "foreign".into(),
                limit_bytes: 100,
                quantum_bytes: 1
            }
        )),
        403
    );
    assert_eq!(
        status(f.control.update_budget(
            &f.admin,
            &f.user_budget.id,
            BudgetUpdate {
                limit_bytes: 63,
                ..change.clone()
            }
        )),
        409
    );
    let updated = f
        .control
        .update_budget(&f.admin, &f.user_budget.id, change.clone())
        .unwrap();
    assert_eq!(updated.committed_bytes, 64);
    assert_eq!(updated.revision, 2);
    assert_eq!(
        status(f.control.update_budget(&f.admin, &f.user_budget.id, change)),
        409
    );
}

#[test]
fn restored_controller_cannot_reissue_reservations_forgotten_by_its_backup() {
    let f = Fixture::new(100, 64, false);
    let path = f.tmp.path().join("controller-backup.db");
    f.control.backup(&path).unwrap();
    f.sync(0);
    let restored = Store::open(&path).unwrap();
    assert!(restored.budgets(&f.admin).unwrap().allocation_paused);
    assert!(!f.control.budgets(&f.admin).unwrap().allocation_paused);
    let exchange = f.agents[1].budget_outbox(&f.runs[1], true).unwrap();
    let reply = restored
        .sync(&f.nodes[1], f.request(1, exchange))
        .unwrap()
        .budget
        .unwrap();
    assert!(reply.allocation_paused);
    assert!(reply.grants.is_empty());
    f.agents[0]
        .admit_batch(&[admission(&f.rules[0], 5, false)])
        .unwrap();
    let report = f.agents[0].budget_outbox(&f.runs[0], false).unwrap();
    assert_eq!(
        status(restored.sync(&f.nodes[0], f.request(0, report))),
        409
    );
}

#[test]
fn datagram_larger_than_quantum_requests_enough_credit_without_partial_charges() {
    let f = Fixture::new(8192, 64, false);
    assert_eq!(
        f.agents[0]
            .admit_batch(&[admission(&f.rules[0], 4096, true)])
            .unwrap(),
        vec![None]
    );
    let reply = f.sync(0);
    assert_eq!(reply.grants[0].bytes, 4096);
    assert_eq!(
        f.agents[0]
            .admit_batch(&[admission(&f.rules[0], 4096, true)])
            .unwrap(),
        vec![Some(4096)]
    );
    f.sync(0);
    assert_eq!(f.user().consumed_bytes, 4096);
    assert_eq!(
        f.agents[0]
            .admit_batch(&[admission(&f.rules[0], 4097, true)])
            .unwrap(),
        vec![None]
    );
    f.sync(0);
    assert_eq!(f.user().consumed_bytes, 4096);
}
