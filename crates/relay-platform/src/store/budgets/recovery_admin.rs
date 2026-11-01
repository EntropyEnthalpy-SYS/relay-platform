//! Budget disaster recovery (optional feature `budget-recovery`). Two audited,
//! system-administrator actions close what reporting alone cannot: writing off
//! the reservations of a node run that can no longer report, and ending the
//! allocation lock a restore from an old backup leaves behind. Both assume the
//! worst: unknown bytes count as consumed and nothing is refunded. Room comes
//! back only when an administrator raises a limit.
use super::*;

fn receipt_key(operation: &str) -> String {
    format!("budget_recovery_receipt:{operation}")
}
fn read_receipt(conn: &Connection, operation: &str) -> Result<Option<RecoveryReceipt>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            [receipt_key(operation)],
            |r| r.get(0),
        )
        .optional()?;
    Ok(raw.map(|raw| serde_json::from_str(&raw)).transpose()?)
}
fn write_receipt(tx: &Transaction<'_>, receipt: &RecoveryReceipt) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2)",
        params![
            receipt_key(&receipt.operation_id),
            serde_json::to_string(receipt)?
        ],
    )?;
    Ok(())
}
fn require_admin(actor: &Actor) -> Result<()> {
    if actor.role != Role::SystemAdmin {
        return reject(403, "budget recovery requires a system administrator");
    }
    Ok(())
}
fn valid_request(operation: &str, reason: &str) -> Result<()> {
    if !identifier(operation) || reason.trim().is_empty() || reason.len() > 500 {
        return reject(
            400,
            "recovery needs an operation id and a reason of at most 500 bytes",
        );
    }
    Ok(())
}
fn fence(
    conn: &Connection,
    clocks: &mut super::super::leases::LeaseClocks,
    node: &str,
    run: &str,
) -> Result<(RunFence, u64)> {
    let lease = super::super::leases::status(conn, clocks, node)?;
    if lease.policy.is_none() {
        return Ok((RunFence::Unconfirmed, 0));
    }
    Ok(if lease.holder_run_id.as_deref() == Some(run) {
        // The last holder may still renew or resume its own lease.
        if lease.active {
            (RunFence::Current, 0)
        } else {
            (RunFence::Unconfirmed, 0)
        }
    } else if lease.recovery_wait_ms > 0 {
        (RunFence::Waiting, lease.recovery_wait_ms)
    } else {
        (RunFence::Fenced, 0)
    })
}

impl Store {
    pub fn budget_recovery(&self, actor: &Actor) -> Result<BudgetRecoveryView> {
        require_admin(actor)?;
        let conn = self.0.lock().unwrap();
        let enabled = features::enabled(&conn, "budget-recovery")?;
        let allocation_paused = paused(&conn)?;
        let mut q = conn.prepare(&format!("{BUDGET_SELECT} ORDER BY b.name,b.id"))?;
        let budgets = q
            .query_map([], budget_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(|b| QuarantineBudget {
                assumed_bytes: b.limit_bytes - b.committed_bytes,
                id: b.id,
                name: b.name,
                revision: b.revision,
                limit_bytes: b.limit_bytes,
                committed_bytes: b.committed_bytes,
            })
            .collect();
        let mut q = conn.prepare(
            "SELECT g.node_id,n.name,g.run_id,COUNT(*),SUM(g.bytes-g.consumed_bytes) FROM budget_grants g JOIN nodes n ON n.id=g.node_id
             WHERE g.closed=0 GROUP BY g.node_id,g.run_id ORDER BY n.name,g.run_id LIMIT 200",
        )?;
        let open = q
            .query_map([], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                    r.get::<_, u64>(3)?,
                    r.get::<_, u64>(4)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        let mut clocks = self.3.lock().unwrap();
        let mut runs = Vec::with_capacity(open.len());
        for (node_id, node_name, run_id, reservations, outstanding_bytes) in open {
            let (fence, wait_ms) = fence(&conn, &mut clocks, &node_id, &run_id)?;
            runs.push(StuckRun {
                node_id,
                node_name,
                run_id,
                reservations,
                outstanding_bytes,
                fence,
                wait_ms,
            });
        }
        drop(clocks);
        let mut q =
            conn.prepare("SELECT value FROM metadata WHERE key GLOB 'budget_recovery_receipt:*'")?;
        let mut receipts = q
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .iter()
            .map(|raw| serde_json::from_str(raw))
            .collect::<serde_json::Result<Vec<RecoveryReceipt>>>()?;
        receipts.sort_by_key(|r| std::cmp::Reverse(r.at_ms));
        Ok(BudgetRecoveryView {
            enabled,
            allocation_paused,
            budgets,
            runs,
            receipts,
        })
    }

    /// Counts a stopped run's open reservations as fully consumed and closes
    /// them. A late report from a leftover process stays within the closed
    /// boundary, and the run cannot resume unsealed claims.
    pub fn write_off_budget_run(
        &self,
        actor: &Actor,
        node: &str,
        input: RunWriteOff,
    ) -> Result<RecoveryReceipt> {
        require_admin(actor)?;
        valid_request(&input.operation_id, &input.reason)?;
        if !identifier(node) || !identifier(&input.run_id) {
            return reject(400, "invalid node or run identity");
        }
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        features::require(&tx, "budget-recovery", "Budget recovery")?;
        if let Some(receipt) = read_receipt(&tx, &input.operation_id)? {
            if receipt.kind == "write_off"
                && receipt.node_id.as_deref() == Some(node)
                && receipt.run_id.as_deref() == Some(input.run_id.as_str())
            {
                return Ok(receipt);
            }
            return reject(409, "operation id was already used for another recovery");
        }
        if paused(&tx)? {
            return reject(
                409,
                "end the restore lock first; reservations issued after the backup are unknown",
            );
        }
        let (fence, wait_ms) = fence(&tx, &mut self.3.lock().unwrap(), node, &input.run_id)?;
        match fence {
            RunFence::Current => {
                return reject(409, "this run still holds the node's execution lease");
            }
            RunFence::Waiting => {
                return reject(
                    423,
                    format!(
                        "the run's lease window closes in {} s; try again then",
                        wait_ms.div_ceil(1000)
                    ),
                );
            }
            RunFence::Unconfirmed if !input.stopped_confirmed => {
                return reject(
                    409,
                    "confirm that the agent process for this run has stopped before writing it off",
                );
            }
            _ => {}
        }
        let mut q = tx.prepare(
            "SELECT id,budget_id,bytes-consumed_bytes FROM budget_grants WHERE node_id=?1 AND run_id=?2 AND closed=0",
        )?;
        let grants = q
            .query_map(params![node, input.run_id], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, u64>(2)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(q);
        if grants.is_empty() {
            return reject(404, "this run has no open reservations");
        }
        let mut bytes = 0u64;
        for (grant, budget, outstanding) in &grants {
            tx.execute(
                "UPDATE budget_grants SET consumed_bytes=bytes,closed=1 WHERE id=?1",
                [grant],
            )?;
            tx.execute(
                "UPDATE budgets SET consumed_bytes=consumed_bytes+?1 WHERE id=?2",
                params![outstanding, budget],
            )?;
            bytes = bytes.saturating_add(*outstanding);
        }
        let receipt = RecoveryReceipt {
            operation_id: input.operation_id,
            kind: "write_off".into(),
            node_id: Some(node.into()),
            run_id: Some(input.run_id),
            reservations: grants.len() as u64,
            bytes,
            reason: input.reason.trim().into(),
            actor_id: actor.id.clone(),
            at_ms: now_ms(),
        };
        write_receipt(&tx, &receipt)?;
        audit(
            &tx,
            &actor.id,
            "budget.recovery.write_off",
            node,
            &serde_json::to_string(&receipt)?,
        )?;
        tx.commit()?;
        Ok(receipt)
    }

    /// Ends the allocation lock after a restore from an old backup. Every
    /// budget's remaining room is assumed spent by reservations the backup
    /// forgot, so the lock cannot hand out traffic twice.
    pub fn exit_budget_quarantine(
        &self,
        actor: &Actor,
        input: QuarantineExit,
    ) -> Result<RecoveryReceipt> {
        require_admin(actor)?;
        valid_request(&input.operation_id, &input.reason)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        features::require(&tx, "budget-recovery", "Budget recovery")?;
        if let Some(receipt) = read_receipt(&tx, &input.operation_id)? {
            if receipt.kind == "quarantine_exit" {
                return Ok(receipt);
            }
            return reject(409, "operation id was already used for another recovery");
        }
        if !paused(&tx)? {
            return reject(409, "budget allocation is not locked");
        }
        let mut q = tx.prepare(&format!("{BUDGET_SELECT} ORDER BY b.id"))?;
        let budgets = q
            .query_map([], budget_row)?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(q);
        let reviewed: HashMap<&str, u64> = input
            .budgets
            .iter()
            .map(|b| (b.id.as_str(), b.expected_revision))
            .collect();
        if reviewed.len() != input.budgets.len()
            || reviewed.len() != budgets.len()
            || budgets
                .iter()
                .any(|b| reviewed.get(b.id.as_str()) != Some(&b.revision))
        {
            return reject(
                409,
                "budgets changed since they were reviewed; reload and review again",
            );
        }
        let mut bytes = 0u64;
        for budget in &budgets {
            let assumed = budget.limit_bytes - budget.committed_bytes;
            tx.execute(
                "UPDATE budgets SET committed_bytes=limit_bytes,consumed_bytes=consumed_bytes+?1,revision=revision+1 WHERE id=?2",
                params![assumed, budget.id],
            )?;
            bytes = bytes.saturating_add(assumed);
        }
        // Removing the backup markers too keeps a later migration from locking again.
        tx.execute(
            "DELETE FROM metadata WHERE key IN('budget_allocation_paused','backup_created_at_ms','backup_original_budget_pause')",
            [],
        )?;
        let receipt = RecoveryReceipt {
            operation_id: input.operation_id,
            kind: "quarantine_exit".into(),
            node_id: None,
            run_id: None,
            reservations: budgets.len() as u64,
            bytes,
            reason: input.reason.trim().into(),
            actor_id: actor.id.clone(),
            at_ms: now_ms(),
        };
        write_receipt(&tx, &receipt)?;
        audit(
            &tx,
            &actor.id,
            "budget.recovery.quarantine_exit",
            "budgets",
            &serde_json::to_string(&receipt)?,
        )?;
        tx.commit()?;
        Ok(receipt)
    }
}
