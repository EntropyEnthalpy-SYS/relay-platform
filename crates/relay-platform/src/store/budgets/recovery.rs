use super::*;
use crate::budget::{BudgetRecoveryRequest, RecoveryBatch, RecoveryClaim};

const MAX_RECOVERY_ITEMS: usize = 65_536;
const RECOVERY_BATCH_ITEMS: usize = 512;

fn resume_marker(conn: &Connection) -> Result<Option<(String, u64)>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key='agent_budget_resume'",
            [],
            |r| r.get(0),
        )
        .optional()?;
    raw.map(|raw| {
        let marker: (String, u64) = serde_json::from_str(&raw)?;
        ensure!(
            identifier(&marker.0) && marker.1 > 0,
            "invalid durable budget resume marker"
        );
        Ok(marker)
    })
    .transpose()
}

impl Store {
    pub(crate) fn budget_resume_candidate(&self) -> Result<Option<(String, u64)>> {
        let conn = self.0.lock().unwrap();
        let Some(marker) = resume_marker(&conn)? else {
            return Ok(None);
        };
        let current: Option<String> = conn
            .query_row(
                "SELECT value FROM metadata WHERE key='agent_budget_run'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        ensure!(
            current.as_ref() == Some(&marker.0),
            "budget resume marker differs from the current run"
        );
        let outstanding: bool = conn.query_row(
            "SELECT EXISTS(SELECT 1 FROM agent_budget_grants WHERE run_id=?1 AND state IN ('open','sealed') AND ack_closed=0)
             OR EXISTS(SELECT 1 FROM agent_budget_requests WHERE run_id=?1)", [&marker.0], |r| r.get(0),
        )?;
        Ok(outstanding.then_some(marker))
    }

    pub(crate) fn resume_budget_run(&self, run: &str, generation: u64) -> Result<()> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let (old_run, previous) =
            resume_marker(&tx)?.context("budget state has no resume authority")?;
        ensure!(
            old_run == run && generation > previous,
            "budget resume ownership did not advance"
        );
        let current: String = tx.query_row(
            "SELECT value FROM metadata WHERE key='agent_budget_run'",
            [],
            |r| r.get(0),
        )?;
        ensure!(current == run, "budget run changed before recovery");
        let abandoned: bool = tx.query_row("SELECT EXISTS(SELECT 1 FROM agent_budget_grants WHERE run_id=?1 AND state='abandoned')", [run], |r| r.get(0))?;
        ensure!(!abandoned, "an isolated budget run cannot be resumed");
        tx.execute("DELETE FROM agent_budget_demand", [])?;
        tx.execute(
            "UPDATE metadata SET value=?1 WHERE key='agent_budget_resume'",
            [serde_json::to_string(&(run, generation))?],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub(crate) fn budget_recovery_batches(&self, run: &str) -> Result<Vec<RecoveryBatch>> {
        let conn = self.0.lock().unwrap();
        let mut q = conn.prepare(
            "SELECT id,budget_id,request_id,run_id,bytes,consumed_bytes,state FROM agent_budget_grants
             WHERE run_id=?1 AND ack_closed=0 AND state IN ('open','sealed') ORDER BY id LIMIT ?2",
        )?;
        let claims = q
            .query_map(params![run, MAX_RECOVERY_ITEMS + 1], |r| {
                Ok(RecoveryClaim {
                    grant: Grant {
                        grant_id: r.get(0)?,
                        budget_id: r.get(1)?,
                        request_id: r.get(2)?,
                        run_id: r.get(3)?,
                        bytes: r.get(4)?,
                    },
                    consumed_bytes: r.get(5)?,
                    sealed: r.get::<_, String>(6)? == "sealed",
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut q = conn.prepare("SELECT budget_id,request_id,minimum_bytes FROM agent_budget_requests WHERE run_id=?1 ORDER BY budget_id LIMIT ?2")?;
        let requests = q
            .query_map(params![run, MAX_RECOVERY_ITEMS + 1], |r| {
                Ok(GrantRequest {
                    budget_id: r.get(0)?,
                    request_id: r.get(1)?,
                    minimum_bytes: r.get(2)?,
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        ensure!(
            claims.len() <= MAX_RECOVERY_ITEMS && requests.len() <= MAX_RECOVERY_ITEMS,
            "budget recovery exceeds bounded inventory limit"
        );
        let count = claims
            .len()
            .max(requests.len())
            .div_ceil(RECOVERY_BATCH_ITEMS)
            .max(1);
        Ok((0..count)
            .map(|page| RecoveryBatch {
                claims: claims
                    .iter()
                    .skip(page * RECOVERY_BATCH_ITEMS)
                    .take(RECOVERY_BATCH_ITEMS)
                    .cloned()
                    .collect(),
                requests: requests
                    .iter()
                    .skip(page * RECOVERY_BATCH_ITEMS)
                    .take(RECOVERY_BATCH_ITEMS)
                    .cloned()
                    .collect(),
            })
            .collect())
    }

    pub(crate) fn budget_open_grants_in_run(&self, run: &str) -> Result<u64> {
        Ok(self.0.lock().unwrap().query_row(
            "SELECT COUNT(*) FROM agent_budget_grants WHERE run_id=?1 AND state='open' AND consumed_bytes<bytes", [run], |r| r.get(0),
        )?)
    }

    pub fn budget_reservations(
        &self,
        actor: &Actor,
        budget: &str,
        after: Option<&str>,
    ) -> Result<ReservationPage> {
        if !identifier(budget) || after.is_some_and(|id| !identifier(id)) {
            return reject(400, "invalid reservation page identity");
        }
        let conn = self.0.lock().unwrap();
        let tenant: Option<String> = conn
            .query_row("SELECT tenant_id FROM budgets WHERE id=?1", [budget], |r| {
                r.get(0)
            })
            .optional()?;
        if !tenant.is_some_and(|tenant| actor.permits_tenant(&tenant)) {
            return reject(404, "budget not found");
        }
        let mut q = conn.prepare(
            "SELECT g.id,g.node_id,n.name,g.run_id,g.bytes,g.consumed_bytes FROM budget_grants g JOIN nodes n ON n.id=g.node_id
             WHERE g.budget_id=?1 AND g.closed=0 AND g.id>?2 ORDER BY g.id LIMIT 101",
        )?;
        let mut reservations = q
            .query_map(params![budget, after.unwrap_or("")], |r| {
                let allocated_bytes: u64 = r.get(4)?;
                let confirmed_consumed_bytes: u64 = r.get(5)?;
                Ok(ReservationView {
                    grant_id: r.get(0)?,
                    node_id: r.get(1)?,
                    node_name: r.get(2)?,
                    run_id: r.get(3)?,
                    allocated_bytes,
                    confirmed_consumed_bytes,
                    outstanding_bytes: allocated_bytes - confirmed_consumed_bytes,
                    node_lease: Default::default(),
                })
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let next = if reservations.len() > 100 {
            reservations.truncate(100);
            Some(reservations.last().unwrap().grant_id.clone())
        } else {
            None
        };
        let mut clocks = self.3.lock().unwrap();
        for reservation in &mut reservations {
            reservation.node_lease =
                super::super::leases::status(&conn, &mut clocks, &reservation.node_id)?;
        }
        Ok(ReservationPage {
            budget_id: budget.into(),
            reservations,
            next,
        })
    }

    /// Verify every local claim before listeners can reuse a prior run. The
    /// caller holds a fresh, continuous execution lease; managed backups lack
    /// the Agent-side resume marker. Recovery never allocates new reservations.
    pub fn recover_budget_run(
        &self,
        credential: &str,
        input: BudgetRecoveryRequest,
    ) -> Result<BudgetReply> {
        if !identifier(&input.ledger_id)
            || !identifier(&input.run_id)
            || input.claims.len() > RECOVERY_BATCH_ITEMS
            || input.requests.len() > RECOVERY_BATCH_ITEMS
        {
            return reject(400, "invalid budget recovery batch");
        }
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let node = super::super::leases::authenticated(&tx, credential)?;
        let status = super::super::leases::status(&tx, &mut self.3.lock().unwrap(), &node)?;
        if status.policy.is_none() {
            return reject(409, "budget run recovery requires a strict node lease");
        }
        super::super::leases::validate(
            &tx,
            &mut self.3.lock().unwrap(),
            &node,
            Some(&input.lease),
            Some(&input.run_id),
        )?;
        super::super::leases::require_budget_resumption(&tx, &node)?;
        let ledger: Option<String> =
            tx.query_row("SELECT ledger_id FROM nodes WHERE id=?1", [&node], |r| {
                r.get(0)
            })?;
        if ledger.as_deref() != Some(input.ledger_id.as_str()) {
            return reject(409, "budget recovery ledger differs from controller");
        }
        if paused(&tx)? {
            return reject(
                409,
                "budget recovery requires authoritative controller allocation state",
            );
        }
        let mut ids = HashSet::new();
        let mut request_ids = HashSet::new();
        for claim in &input.claims {
            let grant = &claim.grant;
            if grant.run_id != input.run_id
                || !identifier(&grant.grant_id)
                || !identifier(&grant.budget_id)
                || !identifier(&grant.request_id)
                || !ids.insert(grant.grant_id.clone())
                || !request_ids.insert(grant.request_id.clone())
            {
                return reject(400, "invalid or duplicate budget recovery claim");
            }
            let known: Option<(String,String,String,String,u64,u64,bool)> = tx.query_row(
                "SELECT budget_id,ledger_id,run_id,request_id,bytes,consumed_bytes,closed FROM budget_grants WHERE id=?1 AND node_id=?2",
                params![grant.grant_id,node], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?,r.get(5)?,r.get(6)?)),
            ).optional()?;
            let Some((budget, ledger, run, request, bytes, consumed, closed)) = known else {
                return reject(409, "controller does not recognize retained reservation");
            };
            if (budget, ledger, run, request, bytes)
                != (
                    grant.budget_id.clone(),
                    input.ledger_id.clone(),
                    input.run_id.clone(),
                    grant.request_id.clone(),
                    grant.bytes,
                )
                || claim.consumed_bytes < consumed
                || claim.consumed_bytes > bytes
                || (closed && !claim.sealed)
            {
                return reject(
                    409,
                    "retained reservation contradicts the controller; recovery cannot continue",
                );
            }
        }
        for request in &input.requests {
            if !request_ids.insert(request.request_id.clone()) {
                return reject(400, "duplicate recovery request identity");
            }
            let known: Option<(String,String,u64,bool)> = tx.query_row(
                "SELECT ledger_id,budget_id,consumed_bytes,closed FROM budget_grants WHERE node_id=?1 AND run_id=?2 AND request_id=?3",
                params![node,input.run_id,request.request_id], |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?)),
            ).optional()?;
            if known.is_some_and(|(ledger, budget, consumed, closed)| {
                ledger != input.ledger_id || budget != request.budget_id || consumed != 0 || closed
            }) {
                return reject(
                    409,
                    "unaccepted reservation has a conflicting identity, consumption or closed boundary",
                );
            }
        }
        let count = input.claims.len();
        let pending = input.requests.len();
        let reply = exchange(
            &tx,
            &node,
            &input.ledger_id,
            BudgetExchange {
                settle_only: true,
                run_id: input.run_id.clone(),
                requests: input.requests,
                reports: input
                    .claims
                    .into_iter()
                    .map(|claim| GrantReport {
                        grant_id: claim.grant.grant_id,
                        consumed_bytes: claim.consumed_bytes,
                        surrender: claim.sealed,
                    })
                    .collect(),
            },
        )?;
        audit(&tx, &node, "budget.run.recover", &input.run_id, &serde_json::json!({"generation":input.lease.generation,"validated_grants":count,"pending_requests":pending}).to_string())?;
        tx.commit()?;
        Ok(reply)
    }
}
