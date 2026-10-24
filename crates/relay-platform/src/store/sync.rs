use super::*;

/// Keep each request's atomic boundary while sharing one durable journal commit.
/// Only expected input/auth conflicts are isolated; storage errors abort the batch.
impl Store {
    pub fn sync(&self, node: &str, request: SyncRequest) -> Result<SyncResponse> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let response = apply_sync(&tx, node, request)?;
        tx.commit()?;
        Ok(response)
    }

    pub fn sync_authenticated_batch(
        &self,
        inputs: Vec<(String, SyncRequest)>,
    ) -> Result<Vec<Result<SyncResponse>>> {
        ensure!(
            !inputs.is_empty() && inputs.len() <= 16,
            "sync batch must contain 1..16 requests"
        );
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut responses = Vec::with_capacity(inputs.len());
        for (credential, input) in inputs {
            tx.execute_batch("SAVEPOINT agent_sync_request")?;
            let result = (|| {
                let node: Option<String> = tx
                    .query_row(
                        "SELECT id FROM nodes WHERE token_hash=?1",
                        [token_hash(&credential)],
                        |r| r.get(0),
                    )
                    .optional()?;
                let Some(node) = node else {
                    return reject(401, "node credential invalid");
                };
                apply_sync(&tx, &node, input)
            })();
            if let Err(error) = &result {
                if !error.is::<Rejection>() {
                    return Err(result.unwrap_err());
                }
                tx.execute_batch("ROLLBACK TO agent_sync_request")?;
            }
            tx.execute_batch("RELEASE agent_sync_request")?;
            responses.push(result);
        }
        tx.commit()?;
        Ok(responses)
    }
}

fn apply_sync(tx: &Transaction<'_>, node: &str, request: SyncRequest) -> Result<SyncResponse> {
    if request.usage.len() > 1024 || request.apply_error.as_ref().is_some_and(|e| e.len() > 2048) {
        return reject(400, "sync payload exceeds limits");
    }
    let ledger: Option<String> =
        tx.query_row("SELECT ledger_id FROM nodes WHERE id=?1", [node], |r| {
            r.get(0)
        })?;
    if ledger.as_deref() != Some(request.ledger_id.as_str()) || !identifier(&request.ledger_id) {
        return reject(409, "ledger identity mismatch; reconcile before syncing");
    }
    let desired: u64 = tx.query_row(
        "SELECT desired_revision FROM nodes WHERE id=?1",
        [node],
        |r| r.get(0),
    )?;
    if request.applied_revision > desired {
        return reject(
            409,
            "agent revision exceeds controller; reconcile restored state",
        );
    }
    super::health::validate_reports(tx, node, request.applied_revision, &request.stats)?;
    let mut acknowledgements = vec![];
    for usage in request.usage {
        if usage.sequence == 0
            || usage.sequence > MAX_COUNTER
            || usage
                .upload_bytes
                .checked_add(usage.download_bytes)
                .is_none_or(|n| n > MAX_COUNTER)
        {
            return reject(400, "invalid usage counters");
        }
        let known=tx.query_row("SELECT EXISTS(SELECT 1 FROM rule_epochs e JOIN rule_bindings b ON b.rule_id=e.rule_id WHERE b.node_id=?1 AND e.rule_id=?2 AND e.meter_epoch=?3)",params![node,usage.rule_id,usage.meter_epoch],|r|r.get::<_,bool>(0))?;
        if !known {
            return reject(403, "usage does not belong to this node and period");
        }
        let old=tx.query_row("SELECT sequence,upload_bytes,download_bytes FROM usage WHERE node_id=?1 AND rule_id=?2 AND meter_epoch=?3",params![node,usage.rule_id,usage.meter_epoch],|r|Ok((r.get::<_,u64>(0)?,r.get::<_,u64>(1)?,r.get::<_,u64>(2)?))).optional()?;
        if let Some((seq, up, down)) = old
            && (usage.sequence < seq
                || usage.upload_bytes < up
                || usage.download_bytes < down
                || (usage.sequence == seq
                    && (usage.upload_bytes != up || usage.download_bytes != down)))
        {
            return reject(
                409,
                "usage history conflicts with controller; restore or reconcile agent ledger",
            );
        }
        tx.execute("INSERT INTO usage(node_id,rule_id,meter_epoch,sequence,upload_bytes,download_bytes,reported_at_ms) VALUES(?1,?2,?3,?4,?5,?6,?7) ON CONFLICT(node_id,rule_id,meter_epoch) DO UPDATE SET sequence=excluded.sequence,upload_bytes=excluded.upload_bytes,download_bytes=excluded.download_bytes,reported_at_ms=excluded.reported_at_ms",params![node,usage.rule_id,usage.meter_epoch,usage.sequence,usage.upload_bytes,usage.download_bytes,now_ms()])?;
        acknowledgements.push(UsageAck {
            rule_id: usage.rule_id,
            meter_epoch: usage.meter_epoch,
            sequence: usage.sequence,
        });
    }
    let budget = request
        .budget
        .map(|exchange| budgets::exchange(tx, node, &request.ledger_id, exchange))
        .transpose()?;
    tx.execute("UPDATE nodes SET applied_revision=?1,last_seen_ms=?2,apply_error=?3,stats_json=?4 WHERE id=?5",params![request.applied_revision,now_ms(),request.apply_error,serde_json::to_string(&request.stats)?,node])?;
    let config = if request.need_config || desired != request.applied_revision {
        Some(serde_json::from_str(&tx.query_row(
            "SELECT config_json FROM config_history WHERE node_id=?1 AND revision=?2",
            params![node, desired],
            |r| r.get::<_, String>(0),
        )?)?)
    } else {
        None
    };
    Ok(SyncResponse {
        budget,
        controller_instance: "store-direct".into(),
        config,
        acknowledgements,
        server_time_ms: now_ms(),
    })
}
