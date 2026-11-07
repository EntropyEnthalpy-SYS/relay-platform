//! Traffic reset cycles and automatic top-ups of plan entitlements, driven
//! through the controller's real reservation exchange with two agent stores.
mod common;
use common::*;
use relay_platform::{
    api::{self, AppState},
    budget::*,
    commerce::{
        EntitlementState, EntitlementView, Order, OrderKind, PlanInput, TopUp, TopUpFailureReason,
        TrafficReset,
    },
    model::*,
    store::{Actor, Admission, Rejection, Role, Scope, Store},
};
use serde_json::{Value, json};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

const DAY: i64 = 86_400_000;
/// Per-cycle traffic. Not a multiple of the reservation size, and different
/// from the top-up, so a wrong baseline or a carried-over remainder shows.
const ALLOWANCE: u64 = 1_000;
const QUANTUM: u64 = 64;
const TOP_UP: TopUp = TopUp {
    bytes: 300,
    price_cents: 250,
    max_per_cycle: 3,
};
const PLAN_PRICE: i64 = 500;
const DEPOSIT: i64 = 1_000;

struct Fixture {
    tmp: tempfile::TempDir,
    control: Store,
    admin: Actor,
    buyer: Actor,
    nodes: Vec<String>,
    agents: Vec<Store>,
    rules: Vec<Rule>,
    runs: Vec<String>,
    ledgers: Vec<String>,
    budget: String,
    plan: String,
}
impl Fixture {
    /// A buyer whose user budget hands out 64-byte reservations on two
    /// nodes, a 30-day plan of 1000 bytes with `reset` and `top_up`, and a
    /// wallet of 10.00.
    fn new(reset: TrafficReset, top_up: Option<TopUp>) -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let control = Store::open(&tmp.path().join("control.db")).unwrap();
        control.set_kind("controller").unwrap();
        let admin = control.bootstrap(PASSWORD).unwrap();
        control
            .create_user(&admin, "default", "buyer", PASSWORD, Role::Viewer)
            .unwrap();
        let (_, buyer) = control.login("buyer", PASSWORD).unwrap();
        let nodes = (0..2)
            .map(|n| {
                control
                    .create_node(&admin, "default", &format!("node-{n}"))
                    .unwrap()
                    .0
                    .id
            })
            .collect::<Vec<_>>();
        let budget = control
            .create_budget(
                &admin,
                NewBudget {
                    scope: BudgetScope::User,
                    scope_id: buyer.id.clone(),
                    name: "buyer".into(),
                    limit_bytes: 0,
                    quantum_bytes: QUANTUM,
                },
            )
            .unwrap()
            .id;
        control
            .set_feature(&admin, "plan-entitlements", true)
            .unwrap();
        let plan = control
            .create_commerce_plan(&admin, plan_input(reset, top_up))
            .unwrap()
            .id;
        control
            .adjust_wallet(&admin, &buyer.id, DEPOSIT, "deposit", "test")
            .unwrap();
        let mut agents = vec![];
        let mut rules = vec![];
        let mut runs = vec![];
        let mut ledgers = vec![];
        for (n, node) in nodes.iter().enumerate() {
            let mut r = rule("127.0.0.1:8888".parse().unwrap(), Protocol::Both);
            r.id = format!("rule-{n}");
            r.owner_id = buyer.id.clone();
            let config = control.set_config(&admin, node, 0, vec![r]).unwrap();
            assert_eq!(config.rules[0].budget_ids, vec![budget.clone()]);
            rules.push(config.rules[0].clone());
            let db = Store::open(&tmp.path().join(format!("agent-{n}.db"))).unwrap();
            db.save_agent_config(&config).unwrap();
            let page = control
                .reconcile(
                    node,
                    ReconcileRequest {
                        lease: None,
                        ledger_id: None,
                        after: None,
                        expected_revision: None,
                    },
                )
                .unwrap();
            db.merge_checkpoint(&page, true).unwrap();
            ledgers.push(page.ledger_id);
            runs.push(db.start_budget_run().unwrap());
            // Traffic waiting for a reservation.
            db.admit_batch(&[admission(&config.rules[0], 0)]).unwrap();
            agents.push(db);
        }
        Self {
            tmp,
            control,
            admin,
            buyer,
            nodes,
            agents,
            rules,
            runs,
            ledgers,
            budget,
            plan,
        }
    }
    fn buy(&self) -> Order {
        let order = self.control.create_order(&self.buyer, &self.plan).unwrap();
        self.control.pay_order(&self.buyer, &order.id).unwrap()
    }
    fn view(&self) -> EntitlementView {
        self.control
            .entitlement(&self.buyer, &self.buyer.id)
            .unwrap()
            .expect("entitlement")
    }
    fn budget(&self) -> Budget {
        self.control
            .budgets(&self.admin)
            .unwrap()
            .budgets
            .into_iter()
            .find(|b| b.id == self.budget)
            .unwrap()
    }
    fn remaining(&self) -> u64 {
        let budget = self.budget();
        budget.limit_bytes - budget.committed_bytes
    }
    fn request(&self, n: usize, exchange: BudgetExchange) -> SyncRequest {
        SyncRequest {
            logs: None,
            lease: None,
            budget: Some(exchange),
            ledger_id: self.ledgers[n].clone(),
            need_config: false,
            applied_revision: 1,
            apply_error: None,
            usage: vec![],
            stats: EngineStats::default(),
        }
    }
    /// One agent sync: reports use and asks for a reservation when it needs one.
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
    /// Forwards up to `bytes` on node `n` from what it holds; returns how much.
    fn spend(&self, n: usize, bytes: usize) -> usize {
        self.agents[n]
            .admit_batch(&[admission(&self.rules[n], bytes)])
            .unwrap()[0]
            .unwrap_or(0)
    }
    /// Uses traffic on node `n` until the controller has less than one
    /// reservation left, stopping before the request that would need more.
    fn exhaust(&self, n: usize) {
        self.spend(n, 1 << 20);
        while self.remaining() >= QUANTUM {
            self.sync(n);
            self.spend(n, 1 << 20);
        }
    }
    fn orders(&self, kind: OrderKind) -> Vec<Order> {
        self.control
            .orders(&self.admin)
            .unwrap()
            .into_iter()
            .filter(|o| o.kind == kind)
            .collect()
    }
    fn balance(&self) -> i64 {
        self.control
            .wallet(&self.buyer, &self.buyer.id)
            .unwrap()
            .wallet
            .balance_cents
    }
    fn top_up_entries(&self) -> usize {
        self.control
            .wallet(&self.buyer, &self.buyer.id)
            .unwrap()
            .entries
            .iter()
            .filter(|e| e.reference.starts_with("top_up:"))
            .count()
    }
    fn audits(&self, action: &str) -> Vec<Value> {
        self.control
            .audit_log(&self.admin)
            .unwrap()
            .into_iter()
            .filter(|a| a["action"] == action)
            .collect()
    }
}
fn plan_input(reset: TrafficReset, top_up: Option<TopUp>) -> PlanInput {
    PlanInput {
        name: "Cycle".into(),
        description: String::new(),
        price_cents: PLAN_PRICE,
        duration_days: 30,
        traffic_bytes: Some(ALLOWANCE),
        enabled: true,
        traffic_reset: reset,
        top_up,
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
fn status<T: std::fmt::Debug>(result: anyhow::Result<T>) -> u16 {
    result
        .unwrap_err()
        .downcast_ref::<Rejection>()
        .unwrap()
        .status
}

#[test]
fn billing_cycles_reset_at_paid_period_boundaries_without_carrying_unused_traffic() {
    let f = Fixture::new(TrafficReset::Billing, None);
    f.buy();
    let first = f.view();
    let cycle = first.current_cycle.clone().unwrap();
    let start = cycle.started_at_ms;
    assert_eq!(first.budget.unwrap().limit_bytes, ALLOWANCE);
    assert_eq!(cycle.allowance_bytes, Some(ALLOWANCE));
    assert_eq!(first.entitlement.expires_at_ms, start + 30 * DAY);
    // A single paid period ends at expiry: no reset within it.
    assert_eq!(cycle.next_reset_at_ms, None);
    assert_eq!(cycle.ends_at_ms, start + 30 * DAY);

    // 128 bytes used and reported, another 64-byte reservation held.
    for _ in 0..3 {
        f.sync(0);
        f.spend(0, 64);
    }
    let budget = f.budget();
    assert_eq!((budget.consumed_bytes, budget.committed_bytes), (128, 192));

    // A renewal adds a billing period, not traffic: the next period resets.
    f.buy();
    let renewed = f.view();
    assert_eq!(renewed.budget.unwrap().limit_bytes, ALLOWANCE);
    assert_eq!(renewed.entitlement.expires_at_ms, start + 60 * DAY);
    let cycle = renewed.current_cycle.unwrap();
    assert_eq!(cycle.next_reset_at_ms, Some(start + 30 * DAY));
    assert_eq!(
        (
            cycle.used_bytes,
            cycle.reserved_bytes,
            cycle.remaining_bytes
        ),
        (128, 64, Some(ALLOWANCE - 192))
    );

    assert_eq!(
        f.control
            .sweep_entitlements_at(start + 30 * DAY - 1)
            .unwrap(),
        0
    );
    assert_eq!(
        f.control.sweep_entitlements_at(start + 30 * DAY).unwrap(),
        1
    );
    let reset = f.view();
    let cycle = reset.current_cycle.unwrap();
    assert_eq!(cycle.started_at_ms, start + 30 * DAY);
    // The 808 bytes left unused in the first period are gone; the new period
    // has exactly its allowance, of which the held reservation takes 64.
    assert_eq!(reset.budget.unwrap().limit_bytes, 128 + ALLOWANCE);
    assert_eq!(
        (
            cycle.used_bytes,
            cycle.reserved_bytes,
            cycle.remaining_bytes
        ),
        (0, 64, Some(ALLOWANCE - 64))
    );
    assert_eq!(
        cycle.next_reset_at_ms, None,
        "the plan ends before another reset"
    );
    assert_eq!(cycle.ends_at_ms, start + 60 * DAY);
    assert_eq!(
        reset.entitlement.expires_at_ms,
        start + 60 * DAY,
        "a reset never moves the expiry"
    );
    // Applying the same boundary again changes nothing.
    assert_eq!(
        f.control
            .sweep_entitlements_at(start + 30 * DAY + 3_600_000)
            .unwrap(),
        0
    );
    let audits = f.audits("commerce.entitlement.reset");
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0]["resource"], f.buyer.id.as_str());
    assert_eq!(audits[0]["actor_id"], "system");
    // At the end of the last period the plan expires instead of resetting.
    assert_eq!(
        f.control.sweep_entitlements_at(start + 60 * DAY).unwrap(),
        1
    );
    let lapsed = f.view();
    assert_eq!(lapsed.entitlement.state, EntitlementState::Lapsed);
    assert!(lapsed.current_cycle.is_none());
    assert_eq!(f.audits("commerce.entitlement.reset").len(), 1);
}

#[test]
fn every_n_days_resets_once_for_boundaries_missed_while_down_and_survives_restart() {
    let f = Fixture::new(TrafficReset::EveryDays(7), None);
    f.buy();
    let anchor = f.view().current_cycle.unwrap().started_at_ms;
    assert_eq!(
        f.view().current_cycle.unwrap().next_reset_at_ms,
        Some(anchor + 7 * DAY)
    );
    f.sync(0);
    f.spend(0, 50);
    f.sync(0);
    let used = f.budget().consumed_bytes;
    assert_eq!(used, 50);

    // Down from day 6 to day 23: the boundaries at 7, 14 and 21 make one reset.
    assert_eq!(
        f.control.sweep_entitlements_at(anchor + 6 * DAY).unwrap(),
        0
    );
    assert_eq!(
        f.control.sweep_entitlements_at(anchor + 23 * DAY).unwrap(),
        1
    );
    let view = f.view();
    let cycle = view.current_cycle.unwrap();
    assert_eq!(cycle.started_at_ms, anchor + 21 * DAY);
    assert_eq!(cycle.next_reset_at_ms, Some(anchor + 28 * DAY));
    assert_eq!(view.entitlement.cycles, 2);
    assert_eq!(
        view.entitlement.cycle.as_ref().unwrap().baseline_bytes,
        used
    );
    assert_eq!(view.budget.unwrap().limit_bytes, used + ALLOWANCE);
    assert_eq!(f.audits("commerce.entitlement.reset").len(), 1);
    // Budget alerts judge the current cycle, not the use of earlier cycles.
    let alert = f
        .control
        .alert_budgets()
        .unwrap()
        .into_iter()
        .find(|b| b.id == f.budget)
        .unwrap();
    assert_eq!(
        (alert.limit_bytes, alert.committed_bytes),
        (ALLOWANCE, 2 * QUANTUM - used)
    );

    // A restarted controller reads the same cycle and resets nothing twice.
    let restarted = Store::open(&f.tmp.path().join("control.db")).unwrap();
    assert_eq!(
        restarted.sweep_entitlements_at(anchor + 23 * DAY).unwrap(),
        0
    );
    assert_eq!(
        restarted.sweep_entitlements_at(anchor + 28 * DAY).unwrap(),
        1
    );
    let cycle = f.view().current_cycle.unwrap();
    assert_eq!(cycle.started_at_ms, anchor + 28 * DAY);
    // The next boundary, day 35, is after the 30-day plan ends.
    assert_eq!(cycle.next_reset_at_ms, None);
    assert_eq!(cycle.ends_at_ms, anchor + 30 * DAY);
    assert_eq!(f.view().entitlement.cycles, 3);
}

#[test]
fn reservations_held_across_a_reset_count_against_the_new_cycle() {
    let f = Fixture::new(TrafficReset::EveryDays(7), None);
    f.buy();
    let anchor = f.view().current_cycle.unwrap().started_at_ms;
    // One reservation used up and reported; a second one held, with 36 of
    // its 64 bytes forwarded but not reported yet.
    f.sync(0);
    assert_eq!(f.spend(0, 64), 64);
    assert_eq!(f.sync(0).grants[0].bytes, 64);
    assert_eq!(f.spend(0, 36), 36);
    let budget = f.budget();
    assert_eq!((budget.consumed_bytes, budget.committed_bytes), (64, 128));

    assert_eq!(
        f.control.sweep_entitlements_at(anchor + 7 * DAY).unwrap(),
        1
    );
    let cycle = f.view().current_cycle.unwrap();
    // The held reservation stays committed and is charged to the new cycle.
    assert_eq!(f.budget().limit_bytes, 64 + ALLOWANCE);
    assert_eq!(
        (
            cycle.used_bytes,
            cycle.reserved_bytes,
            cycle.remaining_bytes
        ),
        (0, 64, Some(ALLOWANCE - 64))
    );
    // The agent reports its 36 bytes and returns the unused 28: the new cycle
    // has used 36 and gets exactly the rest of its allowance, no more.
    f.agents[0].seal_budget_run(&f.runs[0]).unwrap();
    let closing = f.agents[0].budget_outbox(&f.runs[0], false).unwrap();
    let reply = f
        .control
        .sync(&f.nodes[0], f.request(0, closing))
        .unwrap()
        .budget
        .unwrap();
    f.agents[0].accept_budget_reply(&f.runs[0], reply).unwrap();
    let budget = f.budget();
    assert_eq!((budget.consumed_bytes, budget.committed_bytes), (100, 100));
    let cycle = f.view().current_cycle.unwrap();
    assert_eq!(
        (
            cycle.used_bytes,
            cycle.reserved_bytes,
            cycle.remaining_bytes
        ),
        (36, 0, Some(ALLOWANCE - 36))
    );
}

#[test]
fn reset_now_starts_a_new_cycle_from_now_for_administrators_only() {
    let f = Fixture::new(TrafficReset::EveryDays(10), Some(TOP_UP));
    f.buy();
    f.control
        .set_auto_top_up(&f.buyer, &f.buyer.id, true)
        .unwrap();
    f.exhaust(0);
    f.sync(0);
    assert_eq!(f.view().current_cycle.unwrap().top_ups, 1);
    let expires = f.view().entitlement.expires_at_ms;
    f.control
        .create_user(&f.admin, "default", "ops", PASSWORD, Role::TenantAdmin)
        .unwrap();
    let (_, ops) = f.control.login("ops", PASSWORD).unwrap();
    assert_eq!(
        status(f.control.reset_entitlement_traffic(&f.buyer, &f.buyer.id)),
        403
    );
    assert_eq!(
        status(f.control.reset_entitlement_traffic(&ops, &f.buyer.id)),
        403
    );

    let before = now_ms();
    let reset = f
        .control
        .reset_entitlement_traffic(&f.admin, &f.buyer.id)
        .unwrap();
    let after = now_ms();
    let cycle = reset.current_cycle.unwrap();
    assert!((before..=after).contains(&cycle.started_at_ms));
    assert_eq!(
        cycle.next_reset_at_ms,
        Some(cycle.started_at_ms + 10 * DAY),
        "an every-N-days cycle counts its days from the manual reset"
    );
    let budget = f.budget();
    assert_eq!(cycle.top_ups, 0);
    assert_eq!(cycle.allowance_bytes, Some(ALLOWANCE));
    assert_eq!(
        reset.entitlement.cycle.as_ref().unwrap().baseline_bytes,
        budget.consumed_bytes
    );
    assert_eq!(
        budget.limit_bytes,
        (budget.consumed_bytes + ALLOWANCE).max(budget.committed_bytes)
    );
    assert_eq!(reset.entitlement.expires_at_ms, expires);
    let audits = f.audits("commerce.entitlement.reset");
    assert_eq!(audits.len(), 1);
    assert_eq!(audits[0]["actor_id"], f.admin.id.as_str());
    assert_eq!(audits[0]["resource"], f.buyer.id.as_str());
    let detail: Value = serde_json::from_str(audits[0]["detail"].as_str().unwrap()).unwrap();
    assert_eq!(detail["manual"], true);
    // The scheduled reset follows the new anchor, not the purchase.
    assert_eq!(
        f.control
            .sweep_entitlements_at(cycle.started_at_ms + 10 * DAY - 1)
            .unwrap(),
        0
    );
    assert_eq!(
        f.control
            .sweep_entitlements_at(cycle.started_at_ms + 10 * DAY)
            .unwrap(),
        1
    );
}

#[test]
fn top_up_buys_once_under_concurrent_reservation_requests_and_replays() {
    let f = Fixture::new(TrafficReset::EveryDays(10), Some(TOP_UP));
    f.buy();
    f.control
        .set_auto_top_up(&f.buyer, &f.buyer.id, true)
        .unwrap();
    let expires = f.view().entitlement.expires_at_ms;
    f.exhaust(0);
    assert_eq!(f.remaining(), ALLOWANCE % QUANTUM);
    let committed = f.budget().committed_bytes;

    // Both nodes ask for a reservation at once; 40 bytes cannot fill either.
    let exchanges = (0..2)
        .map(|n| f.agents[n].budget_outbox(&f.runs[n], true).unwrap())
        .collect::<Vec<_>>();
    let replies = std::thread::scope(|scope| {
        let handles = (0..2)
            .map(|n| {
                let request = f.request(n, exchanges[n].clone());
                let (control, node) = (&f.control, &f.nodes[n]);
                scope.spawn(move || control.sync(node, request).unwrap().budget.unwrap())
            })
            .collect::<Vec<_>>();
        handles
            .into_iter()
            .map(|h| h.join().unwrap())
            .collect::<Vec<_>>()
    });
    assert!(
        replies
            .iter()
            .all(|r| r.grants.len() == 1 && r.grants[0].bytes == QUANTUM)
    );
    let check = |f: &Fixture| {
        assert_eq!(f.orders(OrderKind::TopUp).len(), 1, "one top-up order");
        assert_eq!(f.top_up_entries(), 1, "one wallet debit");
        assert_eq!(f.balance(), DEPOSIT - PLAN_PRICE - TOP_UP.price_cents);
        let view = f.view();
        let cycle = view.current_cycle.unwrap();
        assert_eq!((cycle.top_ups, cycle.top_up_bytes), (1, TOP_UP.bytes));
        assert_eq!(cycle.allowance_bytes, Some(ALLOWANCE + TOP_UP.bytes));
        assert_eq!(view.budget.unwrap().limit_bytes, ALLOWANCE + TOP_UP.bytes);
        assert_eq!(
            view.entitlement.expires_at_ms, expires,
            "a top-up never extends the plan"
        );
    };
    check(&f);
    assert_eq!(f.budget().committed_bytes, committed + 2 * QUANTUM);
    let order = &f.orders(OrderKind::TopUp)[0];
    assert_eq!(order.traffic_bytes, Some(TOP_UP.bytes));
    assert_eq!(order.amount_cents, TOP_UP.price_cents);
    assert_eq!(order.duration_days, 0);
    assert_eq!(order.status, relay_platform::commerce::OrderStatus::Paid);
    assert_eq!(f.audits("commerce.top_up").len(), 1);
    // A top-up order is not refunded through the order path.
    assert_eq!(status(f.control.refund_order(&f.admin, &order.id)), 409);

    // Replayed requests return their reservations and buy nothing, also
    // after a controller restart.
    for control in [
        &f.control,
        &Store::open(&f.tmp.path().join("control.db")).unwrap(),
    ] {
        for n in 0..2 {
            let again = control
                .sync(&f.nodes[n], f.request(n, exchanges[n].clone()))
                .unwrap()
                .budget
                .unwrap();
            assert_eq!(again.grants[0].grant_id, replies[n].grants[0].grant_id);
        }
        check(&f);
    }
}

#[test]
fn top_up_reasons_are_recorded_once_and_never_charge() {
    let f = Fixture::new(TrafficReset::EveryDays(10), Some(TOP_UP));
    f.buy();
    let paid = DEPOSIT - PLAN_PRICE;
    let failure = |f: &Fixture| {
        f.view()
            .current_cycle
            .unwrap()
            .last_failure
            .map(|e| e.reason)
    };
    let alert = |f: &Fixture| {
        f.control
            .alert_budgets()
            .unwrap()
            .into_iter()
            .find(|b| b.id == f.budget)
            .unwrap()
    };

    // Switched off: the last 40 bytes are handed out and nothing is bought.
    f.exhaust(0);
    assert_eq!(f.sync(0).grants[0].bytes, ALLOWANCE % QUANTUM);
    assert_eq!(failure(&f), Some(TopUpFailureReason::SwitchedOff));
    assert_eq!(f.remaining(), 0);
    let budget = alert(&f);
    assert!(
        budget.committed_bytes >= budget.limit_bytes,
        "the exhaustion alert holds"
    );
    assert_eq!(budget.top_up_failure, Some(TopUpFailureReason::SwitchedOff));
    // Repeated requests re-check without writing the same failure again.
    f.spend(0, 1 << 20);
    for _ in 0..3 {
        assert!(f.sync(0).grants.is_empty());
    }
    assert_eq!(f.audits("commerce.top_up.fail").len(), 1);
    assert_eq!((f.balance(), f.top_up_entries()), (paid, 0));

    // Switched on: two top-ups empty the wallet; the third finds 0.00.
    f.control
        .set_auto_top_up(&f.buyer, &f.buyer.id, true)
        .unwrap();
    assert_eq!(failure(&f), None, "switching clears the stale reason");
    for bought in 1..=2 {
        assert_eq!(f.sync(0).grants[0].bytes, QUANTUM);
        assert_eq!(f.view().current_cycle.unwrap().top_ups, bought);
        f.exhaust(0);
    }
    assert_eq!(f.balance(), paid - 2 * TOP_UP.price_cents);
    assert_eq!(f.balance(), 0);
    let left = f.remaining();
    assert_eq!(
        f.sync(0).grants[0].bytes,
        left,
        "what is left is handed out without a purchase"
    );
    assert_eq!(failure(&f), Some(TopUpFailureReason::InsufficientBalance));
    assert_eq!(
        alert(&f).top_up_failure,
        Some(TopUpFailureReason::InsufficientBalance)
    );
    f.spend(0, 1 << 20);
    assert!(f.sync(0).grants.is_empty());
    assert_eq!((f.balance(), f.top_up_entries()), (0, 2));
    assert_eq!(f.audits("commerce.top_up.fail").len(), 2);

    // Money arrives: the next request buys the third top-up, then the cap holds.
    f.control
        .adjust_wallet(&f.admin, &f.buyer.id, DEPOSIT, "deposit-2", "test")
        .unwrap();
    assert_eq!(f.sync(0).grants[0].bytes, QUANTUM);
    assert_eq!(failure(&f), None);
    f.exhaust(0);
    let left = f.remaining();
    assert!(left > 0 && left < QUANTUM);
    assert_eq!(f.sync(0).grants[0].bytes, left);
    assert_eq!(failure(&f), Some(TopUpFailureReason::CapReached));
    let cycle = f.view().current_cycle.unwrap();
    assert_eq!((cycle.top_ups, cycle.top_up_bytes), (3, 3 * TOP_UP.bytes));
    assert_eq!(cycle.remaining_bytes, Some(0));
    assert_eq!(f.budget().limit_bytes, ALLOWANCE + 3 * TOP_UP.bytes);
    assert_eq!(f.balance(), DEPOSIT - TOP_UP.price_cents);
    assert_eq!(
        (f.top_up_entries(), f.orders(OrderKind::TopUp).len()),
        (3, 3)
    );
}

#[test]
fn a_plan_without_top_up_records_why_and_top_ups_clear_at_reset() {
    // No top-up configured.
    let bare = Fixture::new(TrafficReset::EveryDays(10), None);
    bare.buy();
    bare.control
        .set_auto_top_up(&bare.buyer, &bare.buyer.id, true)
        .unwrap();
    bare.exhaust(0);
    bare.sync(0);
    assert_eq!(
        bare.view()
            .current_cycle
            .unwrap()
            .last_failure
            .map(|e| e.reason),
        Some(TopUpFailureReason::NotConfigured)
    );
    assert_eq!(bare.balance(), DEPOSIT - PLAN_PRICE);

    // A top-up belongs to its cycle: the next reset clears it, the expiry stays.
    let f = Fixture::new(TrafficReset::EveryDays(10), Some(TOP_UP));
    f.buy();
    f.control
        .set_auto_top_up(&f.buyer, &f.buyer.id, true)
        .unwrap();
    let view = f.view();
    let (anchor, expires) = (
        view.current_cycle.unwrap().started_at_ms,
        view.entitlement.expires_at_ms,
    );
    f.exhaust(0);
    f.sync(0);
    assert_eq!(f.budget().limit_bytes, ALLOWANCE + TOP_UP.bytes);
    assert_eq!(
        f.control.sweep_entitlements_at(anchor + 10 * DAY).unwrap(),
        1
    );
    let view = f.view();
    let cycle = view.current_cycle.unwrap();
    let budget = f.budget();
    assert_eq!((cycle.top_ups, cycle.top_up_bytes), (0, 0));
    assert_eq!(cycle.allowance_bytes, Some(ALLOWANCE));
    assert_eq!(budget.limit_bytes, budget.consumed_bytes + ALLOWANCE);
    assert_eq!(view.entitlement.expires_at_ms, expires);
    // The new cycle can buy again; its ledger reference is new.
    f.spend(0, 1 << 20);
    f.exhaust(0);
    f.sync(0);
    assert_eq!(f.view().current_cycle.unwrap().top_ups, 1);
    assert_eq!(f.top_up_entries(), 2);
}

#[test]
fn a_cycle_that_ended_before_the_sweep_resets_instead_of_buying_a_top_up() {
    let f = Fixture::new(TrafficReset::EveryDays(10), Some(TOP_UP));
    f.buy();
    f.control
        .set_auto_top_up(&f.buyer, &f.buyer.id, true)
        .unwrap();
    f.exhaust(0);
    // The cycle's ten days end, and the next reservation comes before the
    // minute sweep has run.
    let key = format!("entitlement:{}", f.buyer.id);
    let raw = rusqlite::Connection::open(f.tmp.path().join("control.db")).unwrap();
    let stored: String = raw
        .query_row("SELECT value FROM metadata WHERE key=?1", [&key], |r| {
            r.get(0)
        })
        .unwrap();
    let mut stored: Value = serde_json::from_str(&stored).unwrap();
    for field in ["anchor_ms", "started_at_ms"] {
        let at = stored["cycle"][field].as_i64().unwrap();
        stored["cycle"][field] = json!(at - 10 * DAY - 1);
    }
    raw.execute(
        "UPDATE metadata SET value=?1 WHERE key=?2",
        rusqlite::params![stored.to_string(), key],
    )
    .unwrap();
    let cycles = f.view().entitlement.cycles;

    let reply = f.sync(0);
    assert_eq!(reply.grants[0].bytes, QUANTUM, "the new cycle fills it");
    assert!(f.orders(OrderKind::TopUp).is_empty(), "no top-up bought");
    assert_eq!(f.balance(), DEPOSIT - PLAN_PRICE, "nothing charged");
    let view = f.view();
    assert_eq!(view.entitlement.cycles, cycles + 1);
    let cycle = view.current_cycle.unwrap();
    assert_eq!((cycle.top_ups, cycle.allowance_bytes), (0, Some(ALLOWANCE)));
    assert_eq!(f.audits("commerce.entitlement.reset").len(), 1);
    // The sweep finds nothing left to reset.
    assert_eq!(f.control.sweep_entitlements().unwrap(), 0);
}

#[test]
fn plans_without_reset_keep_one_stacking_allowance() {
    let f = Fixture::new(TrafficReset::None, None);
    f.buy();
    f.buy();
    let view = f.view();
    assert!(view.entitlement.cycle.is_none() && view.current_cycle.is_none());
    assert_eq!(view.budget.unwrap().limit_bytes, 2 * ALLOWANCE);
    // No reset ever, no top-up and no reason recorded when it runs out.
    assert_eq!(
        f.control
            .sweep_entitlements_at(now_ms() + 59 * DAY)
            .unwrap(),
        0
    );
    f.control
        .set_auto_top_up(&f.buyer, &f.buyer.id, true)
        .unwrap();
    f.exhaust(0);
    f.sync(0);
    f.spend(0, 1 << 20);
    assert!(f.sync(0).grants.is_empty());
    assert_eq!(f.remaining(), 0);
    assert_eq!(f.budget().limit_bytes, 2 * ALLOWANCE);
    assert!(f.audits("commerce.top_up.fail").is_empty());
    assert!(f.orders(OrderKind::TopUp).is_empty());
    assert_eq!(f.alert_top_up_failure(), None);
    assert_eq!(
        status(f.control.reset_entitlement_traffic(&f.admin, &f.buyer.id)),
        409
    );
    // While this plan runs, a plan that resets differently cannot be bought.
    let monthly = f
        .control
        .create_commerce_plan(&f.admin, plan_input(TrafficReset::Billing, None))
        .unwrap();
    assert_eq!(status(f.control.create_order(&f.buyer, &monthly.id)), 409);

    // Plans and orders stored before cycles read as plans without reset.
    let path = f.tmp.path().join("control.db");
    rusqlite::Connection::open(&path)
        .unwrap()
        .execute(
            "INSERT INTO metadata(key,value) VALUES('commerce_plan:legacy',?1)",
            [json!({"id":"legacy","name":"Old","description":"","price_cents":1,"duration_days":30,"traffic_bytes":5,"enabled":true,"created_at_ms":1}).to_string()],
        )
        .unwrap();
    let legacy = f
        .control
        .commerce_plans(&f.admin)
        .unwrap()
        .into_iter()
        .find(|p| p.id == "legacy")
        .unwrap();
    assert_eq!(
        (legacy.traffic_reset, legacy.top_up),
        (TrafficReset::None, None)
    );
    assert!(f.orders(OrderKind::Plan).len() == 2);

    // Invalid policies are refused.
    for (reset, top_up) in [
        (TrafficReset::EveryDays(0), None),
        (TrafficReset::EveryDays(367), None),
        (TrafficReset::None, Some(TOP_UP)),
        (
            TrafficReset::Billing,
            Some(TopUp {
                max_per_cycle: 0,
                ..TOP_UP
            }),
        ),
    ] {
        assert_eq!(
            status(
                f.control
                    .create_commerce_plan(&f.admin, plan_input(reset, top_up))
            ),
            400
        );
    }
}
impl Fixture {
    fn alert_top_up_failure(&self) -> Option<TopUpFailureReason> {
        self.control
            .alert_budgets()
            .unwrap()
            .into_iter()
            .find(|b| b.id == self.budget)
            .unwrap()
            .top_up_failure
    }
}

async fn serve(store: Store) -> (SocketAddr, CancellationToken) {
    let stop = CancellationToken::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = api::router(AppState::new(store).with_shutdown(stop.clone()));
    let shutdown = stop.clone();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await
        .unwrap();
    });
    (address, stop)
}
async fn login(client: &reqwest::Client, origin: &str, username: &str) -> String {
    let body: Value = client
        .post(format!("{origin}/api/v1/auth/login"))
        .json(&json!({"username": username, "password": PASSWORD}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    body["token"].as_str().unwrap().into()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn http_routes_let_users_switch_only_their_own_top_up_and_admins_reset() {
    let f = Fixture::new(TrafficReset::EveryDays(10), Some(TOP_UP));
    f.buy();
    let other = f
        .control
        .create_user(&f.admin, "default", "other", PASSWORD, Role::Viewer)
        .unwrap();
    f.control
        .create_user(&f.admin, "default", "ops", PASSWORD, Role::TenantAdmin)
        .unwrap();
    let (token, _) = f
        .control
        .create_api_token(
            &f.admin,
            "automation",
            &[
                Scope::Read,
                Scope::UsersWrite,
                Scope::BudgetsWrite,
                Scope::NodesWrite,
            ],
            1,
        )
        .unwrap();
    let (address, stop) = serve(f.control.clone()).await;
    let origin = format!("http://{address}/api/v1/commerce");
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let buyer = login(&client, &format!("http://{address}"), "buyer").await;
    let others = login(&client, &format!("http://{address}"), "other").await;
    let ops = login(&client, &format!("http://{address}"), "ops").await;
    let admin = login(&client, &format!("http://{address}"), "admin").await;
    let switch = |who: &str, user: &str, enabled: bool| {
        client
            .put(format!("{origin}/entitlements/{user}/auto-top-up"))
            .bearer_auth(who)
            .json(&json!({ "enabled": enabled }))
            .send()
    };
    let reset = |who: &str, user: &str| {
        client
            .post(format!("{origin}/entitlements/{user}/reset"))
            .bearer_auth(who)
            .send()
    };

    // The buyer reads and switches their own plan only.
    let own: Value = client
        .get(format!("{origin}/entitlement"))
        .bearer_auth(&buyer)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let cycle = &own["current_cycle"];
    assert_eq!(cycle["policy"], json!({"every_days": 10}));
    assert_eq!(cycle["allowance_bytes"], ALLOWANCE);
    assert_eq!(cycle["remaining_bytes"], ALLOWANCE);
    assert_eq!(cycle["top_ups"], 0);
    assert_eq!(
        cycle["top_up"],
        json!({"bytes": 300, "price_cents": 250, "max_per_cycle": 3})
    );
    assert_eq!(
        cycle["next_reset_at_ms"].as_i64().unwrap(),
        cycle["started_at_ms"].as_i64().unwrap() + 10 * DAY
    );
    assert_eq!(own["auto_top_up"], false);
    let response = switch(&buyer, &f.buyer.id, true).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(response.json::<Value>().await.unwrap()["auto_top_up"], true);
    assert_eq!(switch(&buyer, &other.id, true).await.unwrap().status(), 403);
    assert_eq!(
        switch(&others, &f.buyer.id, false).await.unwrap().status(),
        403
    );
    assert_eq!(
        switch(&ops, &f.buyer.id, false).await.unwrap().status(),
        403
    );
    // Another user sees no cycle data of the buyer's.
    let theirs: Value = client
        .get(format!("{origin}/entitlement"))
        .bearer_auth(&others)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(theirs, Value::Null);
    assert_eq!(
        client
            .get(format!("{origin}/entitlements"))
            .bearer_auth(&others)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    // Reset is for system administrators; API tokens reach no commerce route.
    assert_eq!(reset(&buyer, &f.buyer.id).await.unwrap().status(), 403);
    assert_eq!(reset(&ops, &f.buyer.id).await.unwrap().status(), 403);
    assert_eq!(reset(&token, &f.buyer.id).await.unwrap().status(), 403);
    assert_eq!(
        switch(&token, &f.buyer.id, false).await.unwrap().status(),
        403
    );
    assert!(f.audits("commerce.entitlement.reset").is_empty());
    assert!(f.view().entitlement.auto_top_up);

    let response = switch(&admin, &f.buyer.id, false).await.unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.json::<Value>().await.unwrap()["auto_top_up"],
        false
    );
    let response = reset(&admin, &f.buyer.id).await.unwrap();
    assert_eq!(response.status(), 200);
    let body: Value = response.json().await.unwrap();
    assert_eq!(body["cycles"], 2);
    assert_eq!(f.audits("commerce.entitlement.reset").len(), 1);
    assert_eq!(f.audits("commerce.entitlement.auto_top_up").len(), 2);

    // Plans carry the policy and top-up; invalid ones are refused.
    let created = client
        .post(format!("{origin}/plans"))
        .bearer_auth(&admin)
        .json(&json!({"name":"Weekly","price_cents":900,"duration_days":28,"traffic_bytes":2048,"traffic_reset":{"every_days":7},"top_up":{"bytes":512,"price_cents":100,"max_per_cycle":2}}))
        .send()
        .await
        .unwrap();
    assert_eq!(created.status(), 200);
    let plan: Value = created.json().await.unwrap();
    assert_eq!(plan["traffic_reset"], json!({"every_days": 7}));
    assert_eq!(plan["top_up"]["bytes"], 512);
    let billing: Value = client
        .put(format!("{origin}/plans/{}", plan["id"].as_str().unwrap()))
        .bearer_auth(&admin)
        .json(&json!({"name":"Weekly","price_cents":900,"duration_days":28,"traffic_bytes":2048,"traffic_reset":"billing"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(billing["traffic_reset"], "billing");
    assert!(billing.get("top_up").is_none());
    for body in [
        json!({"name":"Bad","price_cents":1,"duration_days":1,"traffic_bytes":1,"traffic_reset":{"every_days":0}}),
        json!({"name":"Bad","price_cents":1,"duration_days":1,"traffic_bytes":1,"top_up":{"bytes":1,"price_cents":1,"max_per_cycle":1}}),
    ] {
        assert_eq!(
            client
                .post(format!("{origin}/plans"))
                .bearer_auth(&admin)
                .json(&body)
                .send()
                .await
                .unwrap()
                .status(),
            400
        );
    }
    stop.cancel();
}
