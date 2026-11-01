//! Plan entitlements (optional feature `plan-entitlements`). A paid order
//! raises the buyer's user budget by the plan's traffic until the plan's days
//! run out; expiry freezes the budget and a refund removes the order's share.
//! Traffic already used is never clawed back: a limit never drops below the
//! budget's committed bytes.
use super::*;
use crate::budget::{BudgetScope, NewBudget};
use crate::commerce::{Entitlement, EntitlementGrant, EntitlementState, EntitlementView};

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
pub(in crate::store) fn live_count(conn: &Connection) -> Result<usize> {
    Ok(live(conn)?.len())
}
pub(in crate::store) fn plan_managed(conn: &Connection, budget: &str) -> Result<bool> {
    Ok(live(conn)?
        .iter()
        .any(|e| e.budget_id.as_deref() == Some(budget)))
}

fn target_limit(e: &Entitlement, committed: u64) -> u64 {
    if e.state == EntitlementState::Lapsed {
        return committed;
    }
    let mut total = e.base_bytes;
    for grant in e.grants.iter().filter(|g| g.revoked_at_ms.is_none()) {
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
    });
    if e.grants.iter().any(|g| g.order_id == order.id) {
        return Ok(());
    }
    if e.state == EntitlementState::Lapsed || e.expires_at_ms <= now {
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
    });
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
    /// Expires plans whose days have run out and retries plans waiting for a budget.
    pub fn sweep_entitlements(&self) -> Result<usize> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let now = now_ms();
        let mut changed = 0;
        for mut e in live(&tx)? {
            let action = if e.expires_at_ms <= now {
                e.state = EntitlementState::Lapsed;
                "commerce.entitlement.expire"
            } else if e.state == EntitlementState::AwaitingBudget
                && attach_budget(&tx, &mut e, "system")?
            {
                e.state = EntitlementState::Active;
                "commerce.entitlement.activate"
            } else {
                continue;
            };
            apply(&tx, &e)?;
            audit(&tx, "system", action, &e.user_id, "{}")?;
            changed += 1;
        }
        if changed > 0 {
            tx.commit()?;
        }
        Ok(changed)
    }
}
