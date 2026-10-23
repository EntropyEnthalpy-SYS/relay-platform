use super::*;
use crate::budget::*;
use std::collections::HashSet;

fn paused(conn: &Connection) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT value FROM metadata WHERE key='budget_allocation_paused'",
            [],
            |r| r.get::<_, String>(0),
        )
        .optional()?
        .as_deref()
        == Some("true"))
}
fn policy_valid(limit: u64, quantum: u64) -> Result<()> {
    if limit > MAX_COUNTER || !(1..=64 * 1024 * 1024).contains(&quantum) {
        return reject(
            400,
            "budget limit out of range or quantum outside 1..67108864 bytes",
        );
    }
    Ok(())
}
fn budget_row(r: &rusqlite::Row<'_>) -> rusqlite::Result<Budget> {
    let scope: String = r.get(2)?;
    Ok(Budget {
        id: r.get(0)?,
        tenant_id: r.get(1)?,
        scope: match scope.as_str() {
            "user" => BudgetScope::User,
            "tenant" => BudgetScope::Tenant,
            _ => BudgetScope::Node,
        },
        scope_id: r.get(3)?,
        name: r.get(4)?,
        limit_bytes: r.get(5)?,
        quantum_bytes: r.get(6)?,
        committed_bytes: r.get(7)?,
        revision: r.get(8)?,
        consumed_bytes: r.get(9)?,
    })
}
const BUDGET_SELECT: &str = "SELECT b.id,b.tenant_id,b.scope,b.scope_id,b.name,b.limit_bytes,b.quantum_bytes,b.committed_bytes,b.revision,b.consumed_bytes FROM budgets b";
fn scope_tenant(conn: &Connection, scope: &BudgetScope, id: &str) -> Result<String> {
    let sql = match scope {
        BudgetScope::User => "SELECT tenant_id FROM users WHERE id=?1",
        BudgetScope::Tenant => "SELECT id FROM tenants WHERE id=?1",
        BudgetScope::Node => "SELECT tenant_id FROM nodes WHERE id=?1",
    };
    conn.query_row(sql, [id], |r| r.get(0))
        .optional()?
        .map(Ok)
        .unwrap_or_else(|| reject(404, "budget scope not found"))
}
fn applies(scope: &BudgetScope, id: &str, node: &str, rule: &Rule) -> bool {
    match scope {
        BudgetScope::User => rule.owner_id == id,
        BudgetScope::Tenant => rule.tenant_id == id,
        BudgetScope::Node => node == id,
    }
}
fn require_quiescent(conn: &Connection, scope: &BudgetScope, id: &str) -> Result<()> {
    let mut q=conn.prepare("SELECT n.id,n.desired_revision,n.applied_revision,n.apply_error FROM nodes n WHERE (?1='node' AND n.id=?2) OR (?1='tenant' AND n.tenant_id=?2) OR (?1='user' AND EXISTS(SELECT 1 FROM rule_bindings b WHERE b.node_id=n.id AND b.owner_id=?2))")?;
    let nodes = q
        .query_map(params![scope.as_str(), id], |r| {
            Ok((
                r.get::<_, String>(0)?,
                r.get::<_, u64>(1)?,
                r.get::<_, u64>(2)?,
                r.get::<_, Option<String>>(3)?,
            ))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    for (node, desired, applied, error) in nodes {
        if desired != applied || error.is_some() {
            return reject(
                409,
                "pause affected rules and wait for every affected node to acknowledge before introducing a budget",
            );
        }
        let config: NodeConfig = serde_json::from_str(&conn.query_row(
            "SELECT config_json FROM config_history WHERE node_id=?1 AND revision=?2",
            params![node, desired],
            |r| r.get::<_, String>(0),
        )?)?;
        if config
            .rules
            .iter()
            .any(|r| r.enabled && applies(scope, id, &node, r))
        {
            return reject(
                409,
                "pause affected rules and wait for acknowledgement before introducing a budget",
            );
        }
    }
    Ok(())
}
pub(super) fn bindings(conn: &Connection, node: &str, rule: &Rule) -> Result<Vec<String>> {
    let mut q=conn.prepare("SELECT id FROM budgets WHERE tenant_id=?1 AND ((scope='user' AND scope_id=?2) OR (scope='tenant' AND scope_id=?1) OR (scope='node' AND scope_id=?3)) ORDER BY id")?;
    Ok(
        q.query_map(params![rule.tenant_id, rule.owner_id, node], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?,
    )
}
impl Store {
    pub fn budgets(&self, actor: &Actor) -> Result<BudgetOverview> {
        let conn = self.0.lock().unwrap();
        let mut q = conn.prepare(&format!(
            "{BUDGET_SELECT} WHERE (?1='system_admin' OR b.tenant_id=?2) ORDER BY b.name,b.id"
        ))?;
        let budgets = q
            .query_map(params![actor.role.as_str(), actor.tenant_id], budget_row)?
            .collect::<rusqlite::Result<_>>()?;
        Ok(BudgetOverview {
            allocation_paused: paused(&conn)?,
            budgets,
        })
    }
    pub fn create_budget(&self, actor: &Actor, input: NewBudget) -> Result<Budget> {
        if !actor.may_write() {
            return reject(403, "budget administration requires write access");
        }
        policy_valid(input.limit_bytes, input.quantum_bytes)?;
        if !identifier(&input.scope_id) || input.name.trim().is_empty() || input.name.len() > 120 {
            return reject(400, "invalid budget scope or name");
        }
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let tenant = scope_tenant(&tx, &input.scope, &input.scope_id)?;
        if !actor.permits_tenant(&tenant) {
            return reject(403, "budget belongs to another tenant");
        }
        if paused(&tx)? {
            return reject(
                409,
                "restored controller is quarantined for budget allocation; authoritative reservation recovery is required",
            );
        }
        if tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM budgets WHERE scope=?1 AND scope_id=?2)",
            params![input.scope.as_str(), input.scope_id],
            |r| r.get::<_, bool>(0),
        )? {
            return reject(
                409,
                "scope already has a budget; update its limit without resetting usage",
            );
        }
        require_quiescent(&tx, &input.scope, &input.scope_id)?;
        let id = Uuid::new_v4().to_string();
        tx.execute("INSERT INTO budgets(id,tenant_id,scope,scope_id,name,limit_bytes,quantum_bytes) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![id,tenant,input.scope.as_str(),input.scope_id,input.name,input.limit_bytes,input.quantum_bytes])?;
        audit(
            &tx,
            &actor.id,
            "budget.create",
            &id,
            &serde_json::to_string(&input)?,
        )?;
        let result = tx.query_row(&format!("{BUDGET_SELECT} WHERE b.id=?1"), [&id], budget_row)?;
        tx.commit()?;
        Ok(result)
    }
    pub fn update_budget(&self, actor: &Actor, id: &str, input: BudgetUpdate) -> Result<Budget> {
        policy_valid(input.limit_bytes, input.quantum_bytes)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let old = tx
            .query_row(&format!("{BUDGET_SELECT} WHERE b.id=?1"), [id], budget_row)
            .optional()?;
        let Some(old) = old else {
            return reject(404, "budget not found");
        };
        if !actor.may_write() || !actor.permits_tenant(&old.tenant_id) {
            return reject(403, "insufficient budget scope");
        }
        if paused(&tx)? {
            return reject(
                409,
                "budget allocation is quarantined after controller restore",
            );
        }
        if old.revision != input.expected_revision || old.revision >= MAX_COUNTER {
            return reject(409, "budget changed; reload before saving");
        }
        if input.limit_bytes < old.committed_bytes {
            return reject(
                409,
                "limit cannot be smaller than consumed plus outstanding reservations",
            );
        }
        tx.execute(
            "UPDATE budgets SET limit_bytes=?1,quantum_bytes=?2,revision=revision+1 WHERE id=?3",
            params![input.limit_bytes, input.quantum_bytes, id],
        )?;
        audit(
            &tx,
            &actor.id,
            "budget.update",
            id,
            &serde_json::to_string(&input)?,
        )?;
        let result = tx.query_row(&format!("{BUDGET_SELECT} WHERE b.id=?1"), [id], budget_row)?;
        tx.commit()?;
        Ok(result)
    }
    /// A fresh process never spends an older process's reservation. Uncertain
    /// reservations remain committed at the controller, even if this disk was copied.
    pub fn start_budget_run(&self) -> Result<String> {
        let id = Uuid::new_v4().to_string();
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute(
            "UPDATE agent_budget_grants SET state='abandoned' WHERE state='open'",
            [],
        )?;
        tx.execute("DELETE FROM agent_budget_requests", [])?;
        tx.execute("DELETE FROM agent_budget_demand", [])?;
        tx.execute("INSERT INTO metadata(key,value) VALUES('agent_budget_run',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[&id])?;
        tx.commit()?;
        Ok(id)
    }
    pub fn seal_budget_run(&self, run: &str) -> Result<()> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let current: String = tx.query_row(
            "SELECT value FROM metadata WHERE key='agent_budget_run'",
            [],
            |r| r.get(0),
        )?;
        if current != run {
            return Ok(());
        }
        tx.execute(
            "UPDATE agent_budget_grants SET state='sealed' WHERE run_id=?1 AND state='open'",
            [run],
        )?;
        tx.execute("DELETE FROM agent_budget_demand", [])?;
        tx.commit()?;
        Ok(())
    }
    pub fn budget_outbox(&self, run: &str, allocate: bool) -> Result<BudgetExchange> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let current: String = tx.query_row(
            "SELECT value FROM metadata WHERE key='agent_budget_run'",
            [],
            |r| r.get(0),
        )?;
        ensure!(current == run, "budget run changed");
        let mut q=tx.prepare("SELECT DISTINCT b.budget_id FROM agent_rule_budgets b JOIN agent_meters m ON m.rule_id=b.rule_id AND m.meter_epoch=b.meter_epoch WHERE m.enabled=1")?;
        let active = q
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<HashSet<_>>>()?;
        drop(q);
        let mut q = tx.prepare(
            "SELECT DISTINCT budget_id FROM agent_budget_grants WHERE run_id=?1 AND state='open'",
        )?;
        let held = q
            .query_map([run], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(q);
        for id in held {
            if !active.contains(&id) {
                tx.execute("UPDATE agent_budget_grants SET state='sealed' WHERE budget_id=?1 AND run_id=?2 AND state='open'",params![id,run])?;
            }
        }
        if allocate {
            for id in active {
                let Some(minimum) = tx
                    .query_row(
                        "SELECT minimum_bytes FROM agent_budget_demand WHERE budget_id=?1",
                        [&id],
                        |r| r.get::<_, u64>(0),
                    )
                    .optional()?
                else {
                    continue;
                };
                let(left,largest):(u64,u64)=tx.query_row("SELECT COALESCE(SUM(bytes-consumed_bytes),0),COALESCE(MAX(bytes),0) FROM agent_budget_grants WHERE budget_id=?1 AND run_id=?2 AND state='open' AND bytes>consumed_bytes",params![id,run],|r|Ok((r.get(0)?,r.get(1)?)))?;
                if left < (largest / 2).max(minimum) {
                    tx.execute("INSERT INTO agent_budget_requests(budget_id,request_id,run_id,minimum_bytes) VALUES(?1,?2,?3,?4) ON CONFLICT(budget_id) DO UPDATE SET minimum_bytes=MAX(minimum_bytes,excluded.minimum_bytes)",params![id,Uuid::new_v4().to_string(),run,minimum.saturating_sub(left).max(1)])?;
                }
            }
        }
        let mut q=tx.prepare("SELECT budget_id,request_id,minimum_bytes FROM agent_budget_requests WHERE run_id=?1 ORDER BY budget_id LIMIT 1024")?;
        let requests = q
            .query_map([run], |r| {
                Ok(GrantRequest {
                    budget_id: r.get(0)?,
                    request_id: r.get(1)?,
                    minimum_bytes: r.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(q);
        let mut q=tx.prepare("SELECT id,consumed_bytes,state='sealed' FROM agent_budget_grants WHERE consumed_bytes>ack_consumed OR (state='sealed' AND ack_closed=0) ORDER BY id LIMIT 1024")?;
        let reports = q
            .query_map([], |r| {
                Ok(GrantReport {
                    grant_id: r.get(0)?,
                    consumed_bytes: r.get(1)?,
                    surrender: r.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(q);
        tx.commit()?;
        Ok(BudgetExchange {
            settle_only: !allocate,
            run_id: run.into(),
            requests,
            reports,
        })
    }
    pub fn accept_budget_reply(&self, run: &str, reply: BudgetReply) -> Result<()> {
        ensure!(
            reply.grants.len() <= 1024
                && reply.acknowledgements.len() <= 1024
                && reply.cancelled_requests.len() <= 1024,
            "budget response exceeds limit"
        );
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        for id in &reply.cancelled_requests {
            ensure!(
                identifier(id) && !reply.grants.iter().any(|g| &g.request_id == id),
                "inconsistent reservation cancellation"
            );
            tx.execute(
                "DELETE FROM agent_budget_requests WHERE run_id=?1 AND request_id=?2",
                params![run, id],
            )?;
        }
        for grant in reply.grants {
            ensure!(
                grant.run_id == run
                    && identifier(&grant.grant_id)
                    && identifier(&grant.budget_id)
                    && identifier(&grant.request_id)
                    && grant.bytes > 0
                    && grant.bytes <= MAX_COUNTER,
                "invalid grant"
            );
            let request: Option<String> = tx
                .query_row(
                    "SELECT request_id FROM agent_budget_requests WHERE budget_id=?1 AND run_id=?2",
                    params![grant.budget_id, run],
                    |r| r.get(0),
                )
                .optional()?;
            let old: Option<(String, String, String, u64)> = tx
                .query_row(
                    "SELECT budget_id,run_id,request_id,bytes FROM agent_budget_grants WHERE id=?1",
                    [&grant.grant_id],
                    |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
                )
                .optional()?;
            if let Some(old) = old {
                ensure!(
                    old == (
                        grant.budget_id.clone(),
                        grant.run_id.clone(),
                        grant.request_id.clone(),
                        grant.bytes
                    ),
                    "grant identity changed"
                );
            } else {
                ensure!(
                    request.as_deref() == Some(&grant.request_id),
                    "unsolicited grant"
                );
                tx.execute("INSERT INTO agent_budget_grants(id,budget_id,request_id,run_id,bytes,state) VALUES(?1,?2,?3,?4,?5,'open')",params![grant.grant_id,grant.budget_id,grant.request_id,run,grant.bytes])?;
            }
            tx.execute(
                "DELETE FROM agent_budget_requests WHERE budget_id=?1 AND request_id=?2",
                params![grant.budget_id, grant.request_id],
            )?;
        }
        for ack in reply.acknowledgements {
            let (local, limit, state): (u64, u64, String) = tx.query_row(
                "SELECT consumed_bytes,bytes,state FROM agent_budget_grants WHERE id=?1",
                [&ack.grant_id],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
            ensure!(
                ack.consumed_bytes <= limit && (state != "open" || ack.consumed_bytes <= local),
                "budget acknowledgement conflicts with a running grant"
            );
            ensure!(
                !ack.surrender || state != "open",
                "controller closed a grant not sealed locally"
            );
            tx.execute("UPDATE agent_budget_grants SET consumed_bytes=MAX(consumed_bytes,?1),ack_consumed=MAX(ack_consumed,?1),ack_closed=MAX(ack_closed,?2) WHERE id=?3",params![ack.consumed_bytes,ack.surrender,ack.grant_id])?;
        }
        tx.commit()?;
        self.2.updated.notify_waiters();
        Ok(())
    }
}

pub(super) fn exchange(
    tx: &Transaction<'_>,
    node: &str,
    ledger: &str,
    exchange: BudgetExchange,
) -> Result<BudgetReply> {
    if !identifier(&exchange.run_id)
        || exchange.requests.len() > 1024
        || exchange.reports.len() > 1024
    {
        return reject(400, "invalid budget exchange");
    }
    let mut result = BudgetReply {
        allocation_paused: paused(tx)?,
        ..Default::default()
    };
    for report in exchange.reports {
        let known:Option<(String,u64,u64,bool,String)>=tx.query_row("SELECT budget_id,bytes,consumed_bytes,closed,ledger_id FROM budget_grants WHERE id=?1 AND node_id=?2",params![report.grant_id,node],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?))).optional()?;
        let Some((budget, allocated, previous, closed, known_ledger)) = known else {
            return reject(
                409,
                "reservation is unknown to this controller; authoritative budget recovery required",
            );
        };
        if known_ledger != ledger {
            return reject(403, "reservation belongs to another ledger");
        }
        if report.consumed_bytes > allocated || (closed && report.consumed_bytes > previous) {
            return reject(
                409,
                "reservation consumption exceeds its irreversible boundary",
            );
        }
        let consumed = previous.max(report.consumed_bytes);
        let surrender = closed || report.surrender;
        let refund = if report.surrender && !closed {
            allocated - consumed
        } else {
            0
        };
        if refund > 0 || consumed > previous {
            tx.execute(
                "UPDATE budgets SET committed_bytes=committed_bytes-?1,consumed_bytes=consumed_bytes+?2 WHERE id=?3",
                params![refund, consumed - previous, budget],
            )?;
        }
        tx.execute(
            "UPDATE budget_grants SET consumed_bytes=?1,closed=?2 WHERE id=?3",
            params![consumed, surrender, report.grant_id],
        )?;
        result.acknowledgements.push(GrantReport {
            grant_id: report.grant_id,
            consumed_bytes: consumed,
            surrender,
        });
    }
    let config:NodeConfig=serde_json::from_str(&tx.query_row("SELECT c.config_json FROM config_history c JOIN nodes n ON c.node_id=n.id AND c.revision=n.desired_revision WHERE n.id=?1",[node],|r|r.get::<_,String>(0))?)?;
    let active: HashSet<_> = config
        .rules
        .iter()
        .filter(|r| r.enabled)
        .flat_map(|r| r.budget_ids.iter())
        .collect();
    let tenant: String = tx.query_row("SELECT tenant_id FROM nodes WHERE id=?1", [node], |r| {
        r.get(0)
    })?;
    let mut seen = HashSet::new();
    for request in exchange.requests {
        if request.minimum_bytes > 65536
            || !identifier(&request.budget_id)
            || !identifier(&request.request_id)
            || !seen.insert(request.request_id.clone())
        {
            return reject(400, "invalid or duplicate reservation request");
        }
        let old:Option<(String,String,u64,bool)>=tx.query_row("SELECT id,budget_id,bytes,closed FROM budget_grants WHERE node_id=?1 AND run_id=?2 AND request_id=?3",params![node,exchange.run_id,request.request_id],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?))).optional()?;
        if let Some((id, budget, bytes, closed)) = old {
            if budget != request.budget_id || closed {
                return reject(409, "reservation request identity was reused");
            }
            result.grants.push(Grant {
                grant_id: id,
                budget_id: budget,
                request_id: request.request_id,
                run_id: exchange.run_id.clone(),
                bytes,
            });
            continue;
        }
        let budget = tx
            .query_row(
                &format!("{BUDGET_SELECT} WHERE b.id=?1"),
                [&request.budget_id],
                budget_row,
            )
            .optional()?;
        let Some(budget) = budget else {
            return reject(403, "unknown budget");
        };
        if budget.tenant_id != tenant {
            return reject(403, "budget belongs to another tenant");
        }
        let cancelled:Option<String>=tx.query_row("SELECT budget_id FROM cancelled_budget_requests WHERE node_id=?1 AND run_id=?2 AND request_id=?3",params![node,exchange.run_id,request.request_id],|r|r.get(0)).optional()?;
        if let Some(id) = &cancelled
            && id != &request.budget_id
        {
            return reject(409, "cancelled reservation identity was reused");
        }
        if exchange.settle_only || cancelled.is_some() || !active.contains(&request.budget_id) {
            tx.execute("INSERT OR IGNORE INTO cancelled_budget_requests(node_id,run_id,request_id,budget_id) VALUES(?1,?2,?3,?4)",params![node,exchange.run_id,request.request_id,request.budget_id])?;
            result.cancelled_requests.push(request.request_id);
            continue;
        }
        if result.allocation_paused {
            continue;
        }
        let bytes = (budget.limit_bytes - budget.committed_bytes)
            .min(budget.quantum_bytes.max(request.minimum_bytes));
        if bytes == 0 {
            continue;
        }
        let id = Uuid::new_v4().to_string();
        tx.execute(
            "UPDATE budgets SET committed_bytes=committed_bytes+?1 WHERE id=?2",
            params![bytes, budget.id],
        )?;
        tx.execute("INSERT INTO budget_grants(id,budget_id,node_id,ledger_id,run_id,request_id,bytes) VALUES(?1,?2,?3,?4,?5,?6,?7)",params![id,budget.id,node,ledger,exchange.run_id,request.request_id,bytes])?;
        result.grants.push(Grant {
            grant_id: id,
            budget_id: budget.id,
            request_id: request.request_id,
            run_id: exchange.run_id.clone(),
            bytes,
        });
    }
    Ok(result)
}

pub(super) fn admit(
    tx: &Transaction<'_>,
    request: &Admission,
    rule_allowed: usize,
) -> Result<(Option<usize>, bool)> {
    let mut q=tx.prepare_cached("SELECT budget_id FROM agent_rule_budgets WHERE rule_id=?1 AND meter_epoch=?2 ORDER BY budget_id")?;
    let budgets = q
        .query_map(params![request.rule_id, request.meter_epoch], |r| {
            r.get::<_, String>(0)
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    drop(q);
    for id in &budgets {
        tx.execute("INSERT INTO agent_budget_demand(budget_id,minimum_bytes) VALUES(?1,?2) ON CONFLICT(budget_id) DO UPDATE SET minimum_bytes=MAX(minimum_bytes,excluded.minimum_bytes)",params![id,if request.datagram {request.bytes.max(1)}else{1}])?;
    }
    let mut allowed = rule_allowed as u64;
    let mut sources = Vec::new();
    let mut needs_refill = false;
    for budget in budgets {
        let mut q=tx.prepare_cached("SELECT id,bytes-consumed_bytes,bytes FROM agent_budget_grants WHERE budget_id=?1 AND run_id=(SELECT value FROM metadata WHERE key='agent_budget_run') AND state='open' AND bytes>consumed_bytes ORDER BY id")?;
        let grants = q
            .query_map([budget], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, u64>(1)?,
                    r.get::<_, u64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let available: u64 = grants.iter().map(|(_, remaining, _)| remaining).sum();
        if available == 0 {
            return Ok((None, true));
        }
        allowed = allowed.min(available);
        sources.push((grants, available));
    }
    if request.datagram && allowed < request.bytes as u64 {
        return Ok((None, true));
    }
    for (grants, available) in sources {
        let quantum = grants.iter().map(|(_, _, total)| *total).max().unwrap_or(1);
        needs_refill |= available - allowed < (quantum / 2).max(1);
        let mut remaining = allowed;
        for (id, available, _) in grants {
            let spent = remaining.min(available);
            if spent > 0 {
                tx.execute(
                    "UPDATE agent_budget_grants SET consumed_bytes=consumed_bytes+?1,state=CASE WHEN consumed_bytes+?1=bytes THEN 'sealed' ELSE state END WHERE id=?2",
                    params![spent, id],
                )?;
                remaining -= spent;
            }
            if remaining == 0 {
                break;
            }
        }
        ensure!(
            remaining == 0,
            "budget reservation disappeared during atomic admission"
        );
    }
    Ok((Some(allowed as usize), needs_refill))
}
