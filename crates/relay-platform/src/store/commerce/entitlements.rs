//! Plan entitlements (optional feature `plan-entitlements`). A paid order
//! raises the buyer's user budget by the plan's traffic until the plan's days
//! run out; expiry freezes the budget and a refund removes the order's share.
//! Traffic already used is never clawed back: a limit never drops below the
//! budget's committed bytes.
//!
//! A plan with a traffic reset policy runs in cycles instead. The budget's
//! counters keep growing; each cycle moves a baseline to the consumed bytes
//! at its start, so the cycle's room is the plan's traffic plus the cycle's
//! top-ups on top of that baseline. Reservations servers hold when a cycle
//! starts stay committed and count against the new cycle: returning their
//! unused part only restores room the new cycle was charged for, so unused
//! traffic never carries over and no held byte is freed.
use super::*;
use crate::budget::{Budget, BudgetScope, NewBudget};
use crate::commerce::{
    CycleView, Entitlement, EntitlementGrant, EntitlementState, EntitlementView, TopUpFailure,
    TopUpFailureReason, TrafficCycle, TrafficReset,
};

const DAY_MS: i64 = 86_400_000;
/// Small reservations keep the overshoot after expiry to about this much per node.
const QUANTUM: u64 = 4 * 1024 * 1024;

fn key(user: &str) -> String {
    format!("entitlement:{user}")
}
fn lapsed_key(budget: &str) -> String {
    format!("entitlement_lapsed:{budget}")
}

/// An expired plan's budget issues no new reservations.
pub(in crate::store) fn plan_lapsed(conn: &Connection, budget: &str) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM metadata WHERE key=?1)",
        [lapsed_key(budget)],
        |r| r.get(0),
    )?)
}
/// A raised limit is the administrator's decision to give room again.
pub(in crate::store) fn clear_lapse(tx: &Transaction<'_>, budget: &str) -> Result<()> {
    tx.execute("DELETE FROM metadata WHERE key=?1", [lapsed_key(budget)])?;
    Ok(())
}
/// Plans that are active or waiting for their budget.
fn live(conn: &Connection) -> Result<Vec<Entitlement>> {
    let mut list = all::<Entitlement>(conn, "entitlement:")?;
    list.retain(|e| e.state != EntitlementState::Lapsed);
    Ok(list)
}
/// The user's plan in any state, for the subscription usage header.
pub(in crate::store) fn plan(conn: &Connection, user: &str) -> Result<Option<Entitlement>> {
    read_json(conn, &key(user))
}
pub(in crate::store) fn live_count(conn: &Connection) -> Result<usize> {
    Ok(live(conn)?.len())
}
pub(in crate::store) fn plan_managed(conn: &Connection, budget: &str) -> Result<bool> {
    Ok(live(conn)?
        .iter()
        .any(|e| e.budget_id.as_deref() == Some(budget)))
}

fn unrevoked(e: &Entitlement) -> impl Iterator<Item = &EntitlementGrant> {
    e.grants.iter().filter(|g| g.revoked_at_ms.is_none())
}
/// The most recent paid order sets each new cycle's traffic and the top-up.
fn latest(e: &Entitlement) -> Option<&EntitlementGrant> {
    unrevoked(e).last()
}
/// The reset policy of the current window. Every order of a window shares it.
fn window_reset(e: &Entitlement) -> TrafficReset {
    e.cycle.as_ref().map_or(TrafficReset::None, |c| c.policy)
}
/// The cycle that limits the user's budget now: an active, unexpired plan
/// that resets and owns that budget.
fn current_cycle<'a>(e: &'a Entitlement, budget: &str, now: i64) -> Option<&'a TrafficCycle> {
    (e.state == EntitlementState::Active
        && e.expires_at_ms > now
        && e.budget_id.as_deref() == Some(budget))
    .then_some(e.cycle.as_ref())
    .flatten()
}

/// The first reset after `after`, if one comes before the plan ends.
fn next_reset(e: &Entitlement, cycle: &TrafficCycle, after: i64) -> Option<i64> {
    let at = match cycle.policy {
        TrafficReset::None => return None,
        TrafficReset::EveryDays(days) => {
            let period = i64::from(days) * DAY_MS;
            cycle.anchor_ms + ((after - cycle.anchor_ms).div_euclid(period) + 1) * period
        }
        // The window began the paid days before its expiry; every paid
        // period ends at a boundary, in the order the periods were bought.
        TrafficReset::Billing => {
            let days: i64 = unrevoked(e).map(|g| i64::from(g.duration_days)).sum();
            let mut at = e.expires_at_ms - days * DAY_MS;
            unrevoked(e).find_map(|g| {
                at += i64::from(g.duration_days) * DAY_MS;
                (at > after).then_some(at)
            })?
        }
    };
    (at < e.expires_at_ms).then_some(at)
}
/// When a cycle is due at `now`, the latest boundary that has passed. Several
/// boundaries missed while the controller was down make one reset.
fn due_reset(e: &Entitlement, now: i64) -> Option<i64> {
    let cycle = e.cycle.as_ref()?;
    let mut start = next_reset(e, cycle, cycle.started_at_ms).filter(|at| *at <= now)?;
    while let Some(at) = next_reset(e, cycle, start).filter(|at| *at <= now) {
        start = at;
    }
    Some(start)
}
/// Starts a cycle at `at` with the latest order's traffic, on top of what the
/// budget has consumed so far. Top-ups and the last failure are cleared.
fn start_cycle(conn: &Connection, e: &mut Entitlement, at: i64, anchor: i64) -> Result<()> {
    let latest = latest(e).context("a traffic cycle needs a paid order")?;
    let (policy, allowance) = (latest.traffic_reset, latest.traffic_bytes);
    let baseline = match e.budget_id.as_deref() {
        Some(id) => budgets::budget(conn, id)?.map_or(0, |b| b.consumed_bytes),
        None => 0,
    };
    e.cycles += 1;
    e.cycle = Some(TrafficCycle {
        policy,
        anchor_ms: anchor,
        started_at_ms: at,
        baseline_bytes: baseline,
        allowance_bytes: allowance,
        top_ups: 0,
        top_up_bytes: 0,
        last_failure: None,
    });
    Ok(())
}

fn target_limit(e: &Entitlement, committed: u64) -> u64 {
    if e.state == EntitlementState::Lapsed {
        return committed;
    }
    if let Some(cycle) = &e.cycle {
        let Some(allowance) = cycle.allowance_bytes else {
            return MAX_COUNTER;
        };
        return cycle
            .baseline_bytes
            .saturating_add(allowance)
            .saturating_add(cycle.top_up_bytes)
            .min(MAX_COUNTER)
            .max(committed);
    }
    let mut total = e.base_bytes;
    for grant in unrevoked(e) {
        let Some(traffic) = grant.traffic_bytes else {
            return MAX_COUNTER;
        };
        total = total.saturating_add(traffic);
    }
    total.min(MAX_COUNTER).max(committed)
}
/// Stores the entitlement and moves its budget to the limit it implies.
fn apply(tx: &Transaction<'_>, e: &Entitlement) -> Result<()> {
    write_json(tx, &key(&e.user_id), e)?;
    let Some(budget) = e.budget_id.as_deref() else {
        return Ok(());
    };
    let Some(current) = budgets::budget(tx, budget)? else {
        return Ok(());
    };
    let limit = target_limit(e, current.committed_bytes);
    if limit != current.limit_bytes {
        tx.execute(
            "UPDATE budgets SET limit_bytes=?1,revision=revision+1 WHERE id=?2",
            params![limit, budget],
        )?;
    }
    if e.state == EntitlementState::Lapsed {
        tx.execute(
            "INSERT OR IGNORE INTO metadata(key,value) VALUES(?1,'true')",
            [lapsed_key(budget)],
        )?;
    } else {
        clear_lapse(tx, budget)?;
    }
    Ok(())
}
/// Gives the entitlement a user budget: adopts the user's existing one, or
/// creates one when the buyer's rules allow it. False while creation must wait.
fn attach_budget(tx: &Transaction<'_>, e: &mut Entitlement, actor_id: &str) -> Result<bool> {
    if e.budget_id.is_some() {
        return Ok(true);
    }
    if let Some(existing) = budgets::user_budget(tx, &e.user_id)? {
        e.base_bytes = existing.limit_bytes;
        // A cycle counts from what the adopted budget has consumed; its
        // earlier limit does not carry into cycles.
        if let Some(cycle) = e.cycle.as_mut() {
            cycle.baseline_bytes = existing.consumed_bytes;
        }
        e.budget_id = Some(existing.id);
        return Ok(true);
    }
    let (tenant, username): (String, String) = tx.query_row(
        "SELECT tenant_id,username FROM users WHERE id=?1",
        [&e.user_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let input = NewBudget {
        scope: BudgetScope::User,
        scope_id: e.user_id.clone(),
        name: format!("Plan · {username}"),
        limit_bytes: 0,
        quantum_bytes: QUANTUM,
    };
    match budgets::insert_budget(tx, &tenant, &input, actor_id) {
        Ok(budget) => {
            e.base_bytes = 0;
            if let Some(cycle) = e.cycle.as_mut() {
                cycle.baseline_bytes = 0;
            }
            e.budget_id = Some(budget.id);
            Ok(true)
        }
        // Enabled rules or a restore quarantine: retried by the sweeper and the buyer's Activate.
        Err(error)
            if error
                .downcast_ref::<Rejection>()
                .is_some_and(|r| r.status == 409) =>
        {
            Ok(false)
        }
        Err(error) => Err(error),
    }
}

/// An unexpired plan keeps one reset policy: a plan that resets differently
/// can be bought once the current one has ended.
pub(super) fn require_same_reset(conn: &Connection, user: &str, reset: TrafficReset) -> Result<()> {
    if !features::enabled(conn, "plan-entitlements")? {
        return Ok(());
    }
    let Some(e) = read_json::<Entitlement>(conn, &key(user))? else {
        return Ok(());
    };
    if e.state != EntitlementState::Lapsed
        && e.expires_at_ms > now_ms()
        && window_reset(&e) != reset
    {
        return reject(
            409,
            "this plan resets traffic differently from your current plan; buy it after the current plan ends",
        );
    }
    Ok(())
}

/// Called in the transaction that marks `order` paid.
pub(in crate::store) fn grant(tx: &Transaction<'_>, order: &Order, actor_id: &str) -> Result<()> {
    if !features::enabled(tx, "plan-entitlements")? {
        return Ok(());
    }
    let now = now_ms();
    let mut e = read_json::<Entitlement>(tx, &key(&order.user_id))?.unwrap_or(Entitlement {
        user_id: order.user_id.clone(),
        state: EntitlementState::AwaitingBudget,
        budget_id: None,
        base_bytes: 0,
        expires_at_ms: now,
        grants: Vec::new(),
        auto_top_up: false,
        cycles: 0,
        cycle: None,
    });
    if e.grants.iter().any(|g| g.order_id == order.id) {
        return Ok(());
    }
    // An order paid after its plan's policy no longer matches the current
    // window (it was created earlier) replaces the window like a renewal
    // after expiry.
    let new_window = e.state == EntitlementState::Lapsed
        || e.expires_at_ms <= now
        || window_reset(&e) != order.traffic_reset;
    if new_window {
        // A new window starts from what is already used; expired plans' traffic does not return.
        e.grants.clear();
        e.expires_at_ms = now;
        if let Some(budget) = e.budget_id.as_deref() {
            e.base_bytes = budgets::budget(tx, budget)?.map_or(0, |b| b.committed_bytes);
        }
    }
    e.expires_at_ms = e
        .expires_at_ms
        .saturating_add(i64::from(order.duration_days) * DAY_MS);
    e.grants.push(EntitlementGrant {
        order_id: order.id.clone(),
        plan_name: order.plan_name.clone(),
        traffic_bytes: order.traffic_bytes,
        duration_days: order.duration_days,
        granted_at_ms: now,
        revoked_at_ms: None,
        traffic_reset: order.traffic_reset,
        top_up: order.top_up,
    });
    // A renewal keeps the running cycle; the latest order's traffic applies from the next reset.
    if new_window {
        if order.traffic_reset.resets() {
            start_cycle(tx, &mut e, now, now)?;
        } else {
            e.cycle = None;
        }
    }
    e.state = if attach_budget(tx, &mut e, actor_id)? {
        EntitlementState::Active
    } else {
        EntitlementState::AwaitingBudget
    };
    apply(tx, &e)?;
    audit(
        tx,
        actor_id,
        "commerce.entitlement.grant",
        &order.id,
        &serde_json::json!({"user_id": e.user_id, "expires_at_ms": e.expires_at_ms}).to_string(),
    )
}
/// Called in the transaction that refunds `order`.
pub(in crate::store) fn revoke(tx: &Transaction<'_>, order: &Order, actor_id: &str) -> Result<()> {
    let Some(mut e) = read_json::<Entitlement>(tx, &key(&order.user_id))? else {
        return Ok(());
    };
    let now = now_ms();
    let Some(grant) = e
        .grants
        .iter_mut()
        .find(|g| g.order_id == order.id && g.revoked_at_ms.is_none())
    else {
        return Ok(());
    };
    grant.revoked_at_ms = Some(now);
    e.expires_at_ms -= i64::from(grant.duration_days) * DAY_MS;
    if e.expires_at_ms <= now || e.grants.iter().all(|g| g.revoked_at_ms.is_some()) {
        e.state = EntitlementState::Lapsed;
    }
    apply(tx, &e)?;
    audit(tx, actor_id, "commerce.entitlement.revoke", &order.id, "{}")
}

/// Buys the plan's top-up when the user's cycle cannot fill the next
/// reservation of `budget`. It runs in the reservation's transaction, which
/// the store serializes, so concurrent requests see one purchase and a
/// rolled-back request charges nothing. A reason is recorded once per change.
/// Returns whether the limit rose.
pub(in crate::store) fn top_up(tx: &Transaction<'_>, budget: &Budget) -> Result<bool> {
    if budget.scope != BudgetScope::User {
        return Ok(false);
    }
    let user = budget.scope_id.as_str();
    let Some(mut e) = read_json::<Entitlement>(tx, &key(user))? else {
        return Ok(false);
    };
    let now = now_ms();
    // A plan without cycles keeps today's behaviour; unlimited cycles never run out.
    if current_cycle(&e, &budget.id, now).is_none_or(|c| c.allowance_bytes.is_none()) {
        return Ok(false);
    }
    // A boundary passed before the minute sweep reached this plan: start the
    // new cycle now rather than buy a top-up that the reset would clear.
    if let Some(start) = due_reset(&e, now) {
        let anchor = e.cycle.as_ref().map_or(start, |c| c.anchor_ms);
        start_cycle(tx, &mut e, start, anchor)?;
        apply(tx, &e)?;
        audit(
            tx,
            "system",
            "commerce.entitlement.reset",
            user,
            &reset_detail(&e, false),
        )?;
        return Ok(true);
    }
    let Some(grant) = latest(&e).cloned() else {
        return Ok(false);
    };
    let mut wallet = read_wallet(tx, user)?;
    let (switched_on, cycle_number) = (e.auto_top_up, e.cycles);
    let cycle = e.cycle.as_mut().context("traffic cycle disappeared")?;
    let config = match grant.top_up {
        None => Err(TopUpFailureReason::NotConfigured),
        Some(_) if !switched_on => Err(TopUpFailureReason::SwitchedOff),
        Some(c) if cycle.top_ups >= c.max_per_cycle => Err(TopUpFailureReason::CapReached),
        Some(c) if wallet.balance_cents < c.price_cents => {
            Err(TopUpFailureReason::InsufficientBalance)
        }
        Some(c) => Ok(c),
    };
    let config = match config {
        Ok(config) => config,
        Err(reason) => {
            // Later requests only re-check; nothing is written until the reason changes.
            if cycle.last_failure.map(|f| f.reason) != Some(reason) {
                cycle.last_failure = Some(TopUpFailure { reason, at_ms: now });
                write_json(tx, &key(user), &e)?;
                audit(
                    tx,
                    "system",
                    "commerce.top_up.fail",
                    user,
                    &serde_json::json!({"reason": reason, "cycle": cycle_number}).to_string(),
                )?;
            }
            return Ok(false);
        }
    };
    cycle.top_ups += 1;
    cycle.top_up_bytes = cycle.top_up_bytes.saturating_add(config.bytes);
    cycle.last_failure = None;
    let number = cycle.top_ups;
    let plan_id = read_order(tx, &grant.order_id)?
        .context("plan order missing")?
        .plan_id;
    let order = Order {
        kind: crate::commerce::OrderKind::TopUp,
        id: Uuid::new_v4().to_string(),
        user_id: user.into(),
        plan_id,
        plan_name: grant.plan_name.clone(),
        subtotal_cents: config.price_cents,
        discount_cents: 0,
        coupon_code: None,
        amount_cents: config.price_cents,
        currency: crate::commerce::CURRENCY.into(),
        duration_days: 0,
        traffic_bytes: Some(config.bytes),
        status: OrderStatus::Paid,
        channel: PaymentChannel::Wallet,
        created_at_ms: now,
        paid_at_ms: Some(now),
        refunded_at_ms: None,
        traffic_reset: TrafficReset::None,
        top_up: None,
    };
    if config.price_cents > 0 {
        wallet.balance_cents -= config.price_cents;
        wallet.updated_at_ms = now;
        write_wallet(tx, &wallet)?;
        // One reference per cycle and top-up: a second charge cannot commit.
        post_ledger(
            tx,
            user,
            -config.price_cents,
            LedgerKind::Purchase,
            &format!("top_up:{user}:{cycle_number}:{number}"),
            &format!("top-up {} · order {}", grant.plan_name, order.id),
        )?;
    }
    write_order(tx, &order)?;
    apply(tx, &e)?;
    audit(
        tx,
        "system",
        "commerce.top_up",
        &order.id,
        &serde_json::json!({"user_id": user, "bytes": config.bytes, "price_cents": config.price_cents, "cycle": cycle_number, "top_up": number}).to_string(),
    )?;
    Ok(true)
}
/// Why the last automatic top-up for `budget` did not run, while its cycle is current.
pub(in crate::store) fn top_up_failure(
    conn: &Connection,
    user: &str,
    budget: &str,
) -> Result<Option<TopUpFailureReason>> {
    let Some(e) = read_json::<Entitlement>(conn, &key(user))? else {
        return Ok(None);
    };
    Ok(current_cycle(&e, budget, now_ms())
        .and_then(|c| c.last_failure)
        .map(|f| f.reason))
}
/// The consumed bytes at the start of the user's current cycle, for the
/// subscription header's per-cycle use.
pub(in crate::store) fn cycle_baseline(
    conn: &Connection,
    user: &str,
    budget: &str,
) -> Result<Option<u64>> {
    let Some(e) = read_json::<Entitlement>(conn, &key(user))? else {
        return Ok(None);
    };
    Ok(current_cycle(&e, budget, now_ms()).map(|c| c.baseline_bytes))
}

fn cycle_view(e: &Entitlement, budget: Option<&Budget>) -> Option<CycleView> {
    if e.state == EntitlementState::Lapsed {
        return None;
    }
    let cycle = e.cycle.as_ref()?;
    let next = next_reset(e, cycle, cycle.started_at_ms);
    let allowance = cycle
        .allowance_bytes
        .map(|bytes| bytes.saturating_add(cycle.top_up_bytes));
    let (consumed, committed, limit) = budget.map_or(
        (cycle.baseline_bytes, cycle.baseline_bytes, MAX_COUNTER),
        |b| (b.consumed_bytes, b.committed_bytes, b.limit_bytes),
    );
    Some(CycleView {
        policy: cycle.policy,
        started_at_ms: cycle.started_at_ms,
        ends_at_ms: next.unwrap_or(e.expires_at_ms),
        next_reset_at_ms: next,
        allowance_bytes: allowance,
        top_up_bytes: cycle.top_up_bytes,
        used_bytes: consumed.saturating_sub(cycle.baseline_bytes),
        reserved_bytes: committed.saturating_sub(consumed),
        remaining_bytes: allowance.map(|allowance| {
            if budget.is_some() {
                limit.saturating_sub(committed)
            } else {
                allowance
            }
        }),
        top_ups: cycle.top_ups,
        top_up: latest(e).and_then(|g| g.top_up),
        last_failure: cycle.last_failure,
    })
}
fn view(conn: &Connection, entitlement: Entitlement) -> Result<EntitlementView> {
    let username = conn
        .query_row(
            "SELECT username FROM users WHERE id=?1",
            [&entitlement.user_id],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or_default();
    let budget = match entitlement.budget_id.as_deref() {
        Some(id) => budgets::budget(conn, id)?,
        None => None,
    };
    Ok(EntitlementView {
        current_cycle: cycle_view(&entitlement, budget.as_ref()),
        entitlement,
        username,
        budget,
    })
}

impl Store {
    pub fn entitlement(&self, actor: &Actor, user: &str) -> Result<Option<EntitlementView>> {
        require_user(actor, user)?;
        let conn = self.0.lock().unwrap();
        read_json::<Entitlement>(&conn, &key(user))?
            .map(|e| view(&conn, e))
            .transpose()
    }
    pub fn entitlements(&self, actor: &Actor) -> Result<Vec<EntitlementView>> {
        require_admin(actor)?;
        let conn = self.0.lock().unwrap();
        all::<Entitlement>(&conn, "entitlement:")?
            .into_iter()
            .map(|e| view(&conn, e))
            .collect()
    }
    /// Retries creating the budget of a paid plan once the buyer's rules are paused.
    pub fn activate_entitlement(&self, actor: &Actor, user: &str) -> Result<EntitlementView> {
        require_user(actor, user)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        features::require(&tx, "plan-entitlements", "Plan entitlements")?;
        let Some(mut e) = read_json::<Entitlement>(&tx, &key(user))? else {
            return reject(404, "no plan to activate");
        };
        if e.state == EntitlementState::AwaitingBudget && e.expires_at_ms > now_ms() {
            if !attach_budget(&tx, &mut e, &actor.id)? {
                return reject(
                    409,
                    "pause your enabled forwarding rules and wait for the servers to confirm, then activate the plan again",
                );
            }
            e.state = EntitlementState::Active;
            apply(&tx, &e)?;
            audit(&tx, &actor.id, "commerce.entitlement.activate", user, "{}")?;
        }
        let result = view(&tx, e)?;
        tx.commit()?;
        Ok(result)
    }
    /// Switches "Top up automatically when used up" for `user`'s plan.
    pub fn set_auto_top_up(
        &self,
        actor: &Actor,
        user: &str,
        enabled: bool,
    ) -> Result<EntitlementView> {
        require_user(actor, user)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        features::require(&tx, "plan-entitlements", "Plan entitlements")?;
        let Some(mut e) = read_json::<Entitlement>(&tx, &key(user))? else {
            return reject(404, "no plan to top up");
        };
        if e.auto_top_up != enabled {
            e.auto_top_up = enabled;
            // The next reservation request decides again under the new setting.
            if let Some(cycle) = e.cycle.as_mut() {
                cycle.last_failure = None;
            }
            write_json(&tx, &key(user), &e)?;
            audit(
                &tx,
                &actor.id,
                "commerce.entitlement.auto_top_up",
                user,
                &serde_json::json!({"enabled": enabled}).to_string(),
            )?;
        }
        let result = view(&tx, e)?;
        tx.commit()?;
        Ok(result)
    }
    /// Starts a new traffic cycle for `user` now. `every_days` cycles count
    /// their days from now; billing cycles still end at the next billing boundary.
    pub fn reset_entitlement_traffic(&self, actor: &Actor, user: &str) -> Result<EntitlementView> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        features::require(&tx, "plan-entitlements", "Plan entitlements")?;
        let Some(mut e) = read_json::<Entitlement>(&tx, &key(user))? else {
            return reject(404, "no plan to reset");
        };
        let now = now_ms();
        if e.state == EntitlementState::Lapsed || e.expires_at_ms <= now {
            return reject(409, "the plan has ended; nothing to reset");
        }
        let Some(cycle) = &e.cycle else {
            return reject(409, "this plan does not reset traffic");
        };
        if budgets::paused(&tx)? {
            return reject(
                409,
                "budget allocation is quarantined after controller restore",
            );
        }
        let anchor = match cycle.policy {
            TrafficReset::EveryDays(_) => now,
            _ => cycle.anchor_ms,
        };
        start_cycle(&tx, &mut e, now, anchor)?;
        apply(&tx, &e)?;
        audit(
            &tx,
            &actor.id,
            "commerce.entitlement.reset",
            user,
            &reset_detail(&e, true),
        )?;
        let result = view(&tx, e)?;
        tx.commit()?;
        Ok(result)
    }
    /// Expires plans whose days have run out, retries plans waiting for a
    /// budget and starts due traffic cycles.
    pub fn sweep_entitlements(&self) -> Result<usize> {
        self.sweep_entitlements_at(now_ms())
    }
    /// [`Store::sweep_entitlements`] as if it ran at `now`, so tests can let days pass.
    #[doc(hidden)]
    pub fn sweep_entitlements_at(&self, now: i64) -> Result<usize> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        // A restored controller resets nothing until its restore lock ends:
        // unknown use is settled against the cycle it happened in.
        let paused = budgets::paused(&tx)?;
        let mut changed = 0;
        for mut e in live(&tx)? {
            let (action, detail) = if e.expires_at_ms <= now {
                e.state = EntitlementState::Lapsed;
                ("commerce.entitlement.expire", "{}".to_owned())
            } else if e.state == EntitlementState::AwaitingBudget
                && attach_budget(&tx, &mut e, "system")?
            {
                e.state = EntitlementState::Active;
                ("commerce.entitlement.activate", "{}".to_owned())
            } else if let Some(start) = due_reset(&e, now).filter(|_| !paused) {
                let anchor = e.cycle.as_ref().map_or(start, |c| c.anchor_ms);
                start_cycle(&tx, &mut e, start, anchor)?;
                ("commerce.entitlement.reset", reset_detail(&e, false))
            } else {
                continue;
            };
            apply(&tx, &e)?;
            audit(&tx, "system", action, &e.user_id, &detail)?;
            changed += 1;
        }
        if changed > 0 {
            tx.commit()?;
        }
        Ok(changed)
    }
}
fn reset_detail(e: &Entitlement, manual: bool) -> String {
    let cycle = e.cycle.as_ref();
    serde_json::json!({
        "manual": manual,
        "cycle": e.cycles,
        "started_at_ms": cycle.map(|c| c.started_at_ms),
        "baseline_bytes": cycle.map(|c| c.baseline_bytes),
    })
    .to_string()
}
