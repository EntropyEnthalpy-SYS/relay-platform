use super::*;

pub const CHECKPOINT_PAGE_SIZE: usize = 256;

impl Store {
    /// The returned file owns an OS lock; never unlink the lock file while running.
    pub fn lock_instance(&self) -> Result<fs::File> {
        let path = self.1.with_extension("instance.lock");
        let mut options = fs::OpenOptions::new();
        options.read(true).write(true).create(true).truncate(false);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            options.mode(0o600);
        }
        let lock = options.open(&path)?;
        lock.try_lock().map_err(|error| {
            anyhow::anyhow!(
                "another process is using this state directory, or its lock is unavailable: {error}"
            )
        })?;
        Ok(lock)
    }

    pub fn recovery_required(&self) -> Result<bool> {
        Ok(self.metadata("recovery_required")?.as_deref() == Some("true"))
    }

    /// Controller-side stable keyset pagination. Config changes invalidate the walk.
    pub fn reconcile(&self, node: &str, request: ReconcileRequest) -> Result<ReconcileResponse> {
        if request.ledger_id.as_ref().is_some_and(|id| !identifier(id))
            || request
                .after
                .as_ref()
                .is_some_and(|c| !identifier(&c.rule_id) || !identifier(&c.meter_epoch))
        {
            return reject(400, "invalid reconciliation cursor or ledger identity");
        }
        if request.after.is_some() && request.expected_revision.is_none() {
            return reject(400, "subsequent pages require a revision");
        }
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let (revision, known_ledger): (u64, Option<String>) = tx.query_row(
            "SELECT desired_revision,ledger_id FROM nodes WHERE id=?1",
            [node],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        if request
            .expected_revision
            .is_some_and(|expected| expected != revision)
        {
            return reject(
                412,
                "configuration changed during reconciliation; restart pagination",
            );
        }
        let ledger_id = known_ledger
            .clone()
            .unwrap_or_else(|| Uuid::new_v4().to_string());
        if request
            .ledger_id
            .as_ref()
            .is_some_and(|supplied| supplied != &ledger_id)
        {
            return reject(
                409,
                "ledger identity differs from controller; explicit recovery is required",
            );
        }
        if known_ledger.is_none() {
            tx.execute(
                "UPDATE nodes SET ledger_id=?1 WHERE id=?2",
                params![ledger_id, node],
            )?;
            audit(&tx, node, "ledger.initialize", node, "{}")?;
        }
        let cursor = request.after.unwrap_or(UsageCursor {
            rule_id: String::new(),
            meter_epoch: String::new(),
        });
        let mut query = tx.prepare(
            "SELECT rule_id,meter_epoch,sequence,upload_bytes,download_bytes FROM usage
             WHERE node_id=?1 AND (rule_id,meter_epoch)>(?2,?3)
             ORDER BY rule_id,meter_epoch LIMIT ?4",
        )?;
        let mut usage = query
            .query_map(
                params![
                    node,
                    cursor.rule_id,
                    cursor.meter_epoch,
                    CHECKPOINT_PAGE_SIZE + 1
                ],
                |r| {
                    Ok(Usage {
                        rule_id: r.get(0)?,
                        meter_epoch: r.get(1)?,
                        sequence: r.get(2)?,
                        upload_bytes: r.get(3)?,
                        download_bytes: r.get(4)?,
                    })
                },
            )?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        drop(query);
        let next = if usage.len() > CHECKPOINT_PAGE_SIZE {
            usage.truncate(CHECKPOINT_PAGE_SIZE);
            let last = usage.last().unwrap();
            Some(UsageCursor {
                rule_id: last.rule_id.clone(),
                meter_epoch: last.meter_epoch.clone(),
            })
        } else {
            None
        };
        let config = if next.is_none() {
            Some(serde_json::from_str(&tx.query_row(
                "SELECT config_json FROM config_history WHERE node_id=?1 AND revision=?2",
                params![node, revision],
                |r| r.get::<_, String>(0),
            )?)?)
        } else {
            None
        };
        tx.commit()?;
        Ok(ReconcileResponse {
            node_id: node.into(),
            ledger_id,
            revision,
            usage,
            next,
            config,
        })
    }

    /// A controller restored to an older checkpoint may have forgotten previously
    /// acknowledged counters. Reset only acknowledgements, never the local totals.
    pub fn begin_reconcile(&self) -> Result<()> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        tx.execute("UPDATE agent_meters SET ack_sequence=0", [])?;
        tx.execute(
            "UPDATE agent_budget_grants SET ack_consumed=0,ack_closed=0",
            [],
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn merge_checkpoint(&self, page: &ReconcileResponse, allow_raise: bool) -> Result<()> {
        ensure!(
            identifier(&page.ledger_id),
            "invalid checkpoint ledger identity"
        );
        ensure!(
            page.usage.len() <= CHECKPOINT_PAGE_SIZE,
            "checkpoint page exceeds limit"
        );
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let existing: Option<String> = tx
            .query_row(
                "SELECT value FROM metadata WHERE key='ledger_id'",
                [],
                |r| r.get(0),
            )
            .optional()?;
        ensure!(
            existing.as_ref().is_none_or(|id| id == &page.ledger_id),
            "local ledger identity differs from checkpoint"
        );
        let mut last: Option<UsageCursor> = None;
        for remote in &page.usage {
            ensure!(
                identifier(&remote.rule_id) && identifier(&remote.meter_epoch),
                "invalid checkpoint key"
            );
            ensure!(
                remote.sequence > 0
                    && remote.sequence <= MAX_COUNTER
                    && remote
                        .upload_bytes
                        .checked_add(remote.download_bytes)
                        .is_some_and(|n| n <= MAX_COUNTER),
                "invalid checkpoint counters"
            );
            let cursor = UsageCursor {
                rule_id: remote.rule_id.clone(),
                meter_epoch: remote.meter_epoch.clone(),
            };
            ensure!(
                last.as_ref().is_none_or(|previous| previous < &cursor),
                "checkpoint keys are not strictly increasing"
            );
            last = Some(cursor);
            let local:Option<(u64,u64,u64)>=tx.query_row(
                "SELECT sequence,upload_bytes,download_bytes FROM agent_meters WHERE rule_id=?1 AND meter_epoch=?2",
                params![remote.rule_id,remote.meter_epoch],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?))).optional()?;
            let (seq, up, down) = local.unwrap_or((0, 0, 0));
            if seq == remote.sequence {
                ensure!(
                    up == remote.upload_bytes && down == remote.download_bytes,
                    "same sequence has conflicting cumulative counters"
                );
            } else if seq > remote.sequence {
                ensure!(
                    up >= remote.upload_bytes && down >= remote.download_bytes,
                    "local ledger is not a continuation of the controller checkpoint"
                );
            } else {
                ensure!(
                    allow_raise,
                    "controller ledger is ahead of a running agent; stop and recover before forwarding"
                );
                ensure!(
                    up <= remote.upload_bytes && down <= remote.download_bytes,
                    "controller checkpoint is not a continuation of local history"
                );
            }
            tx.execute(
                "INSERT INTO agent_meters(rule_id,meter_epoch,enabled,quota_bytes,expires_at_ms,sequence,ack_sequence,upload_bytes,download_bytes)
                 VALUES(?1,?2,0,NULL,NULL,?3,?3,?4,?5)
                 ON CONFLICT(rule_id,meter_epoch) DO UPDATE SET
                   sequence=MAX(agent_meters.sequence,excluded.sequence),
                   upload_bytes=MAX(agent_meters.upload_bytes,excluded.upload_bytes),
                   download_bytes=MAX(agent_meters.download_bytes,excluded.download_bytes),
                   ack_sequence=excluded.ack_sequence",
                params![remote.rule_id,remote.meter_epoch,remote.sequence,remote.upload_bytes,remote.download_bytes])?;
        }
        tx.execute("INSERT INTO metadata(key,value) VALUES('ledger_id',?1) ON CONFLICT(key) DO UPDATE SET value=excluded.value",[&page.ledger_id])?;
        tx.commit()?;
        Ok(())
    }

    pub fn finish_reconcile(&self) -> Result<()> {
        ensure!(
            self.metadata("ledger_id")?.is_some(),
            "cannot complete reconciliation without a ledger identity"
        );
        self.set_metadata("recovery_required", "false")
    }
}
