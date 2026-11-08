use super::*;

/// A report rewrites a node's stored status at least this often even when
/// nothing important changed. It stays under the 90 s freshness gates (DNS
/// health, rollouts), which read the stored copy right after a restart.
const STATUS_REFRESH_MS: i64 = 60_000;

/// Keep each request's atomic boundary while sharing one durable journal commit.
/// Only expected input/auth conflicts are isolated; storage errors abort the batch.
impl Store {
    pub fn sync(&self, node: &str, mut request: SyncRequest) -> Result<SyncResponse> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        leases::validate(
            &tx,
            &mut self.3.lock().unwrap(),
            node,
            request.lease.as_ref(),
            request.budget.as_ref().map(|b| b.run_id.as_str()),
        )?;
        // Sessions and block records go to memory, not into the stored stats.
        let connections = request.stats.live_connections.take();
        super::connections::observe(&tx, node, connections.as_ref())?;
        let report = Report::of(&mut request);
        let (mut response, stored_seen, tunnels_changed) = apply_sync(
            &tx, node, request, &self.6, &self.8, &self.3, &self.10, &self.11,
        )?;
        tx.commit()?;
        self.wake_wireguard_watches();
        if tunnels_changed {
            self.2.config.notify_waiters();
        }
        response.log_cursor = Some(report.record(&self.4, node, stored_seen));
        response.authoritative_dns =
            Some(super::dns_authoritative::snapshot(&conn, &self.4, node)?);
        let supported = super::connections::supported(&conn, node)?;
        super::connections::answer(&self.12, node, supported, connections, &mut response);
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
        let mut reports = vec![];
        let mut tunnels_changed = false;
        for (credential, mut input) in inputs {
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
                leases::validate(
                    &tx,
                    &mut self.3.lock().unwrap(),
                    &node,
                    input.lease.as_ref(),
                    input.budget.as_ref().map(|b| b.run_id.as_str()),
                )?;
                let connections = input.stats.live_connections.take();
                super::connections::observe(&tx, &node, connections.as_ref())?;
                let report = Report::of(&mut input);
                let (response, stored_seen, changed) = apply_sync(
                    &tx, &node, input, &self.6, &self.8, &self.3, &self.10, &self.11,
                )?;
                tunnels_changed |= changed;
                reports.push((node, report, stored_seen, responses.len(), connections));
                Ok(response)
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
        self.wake_wireguard_watches();
        if tunnels_changed {
            self.2.config.notify_waiters();
        }
        for (node, report, stored_seen, index, connections) in reports {
            let cursor = report.record(&self.4, &node, stored_seen);
            if let Ok(response) = &mut responses[index] {
                response.log_cursor = Some(cursor);
                response.authoritative_dns =
                    Some(super::dns_authoritative::snapshot(&conn, &self.4, &node)?);
                let supported = super::connections::supported(&conn, &node)?;
                super::connections::answer(&self.12, &node, supported, connections, response);
            }
        }
        Ok(responses)
    }
}

/// What the dashboard keeps from a report, recorded only once it is committed.
struct Report(u64, Option<String>, EngineStats, Option<crate::logs::Batch>);

impl Report {
    /// Takes the log lines out of `request`; they are not part of the sync.
    fn of(request: &mut SyncRequest) -> Self {
        Self(
            request.applied_revision,
            request.apply_error.clone(),
            request.stats.clone(),
            request.logs.take(),
        )
    }

    /// Returns where the controller's copy of the node's log now ends.
    fn record(
        self,
        telemetry: &crate::telemetry::Telemetry,
        node: &str,
        stored_seen: Option<i64>,
    ) -> crate::logs::Cursor {
        telemetry.record(node, self.0, self.1.as_deref(), &self.2);
        telemetry.keep_status(node, stored_seen, &self.2);
        telemetry.add_logs(node, self.3)
    }
}

#[allow(clippy::too_many_arguments)]
fn apply_sync(
    tx: &Transaction<'_>,
    node: &str,
    request: SyncRequest,
    rates: &std::sync::Mutex<super::user_rates::UserRates>,
    traversal: &std::sync::Mutex<crate::wireguard::punch::Traversal>,
    clocks: &std::sync::Mutex<leases::LeaseClocks>,
    tunnel_wakes: &std::sync::Mutex<std::collections::HashSet<String>>,
    speed_tests: &std::sync::Mutex<super::speed_tests::Live>,
) -> Result<(SyncResponse, Option<i64>, bool)> {
    if request.usage.len() > 1024
        || request.stats.user_rates.len() > 1024
        || request.apply_error.as_ref().is_some_and(|e| e.len() > 2048)
        || request
            .stats
            .wireguard
            .as_ref()
            .is_some_and(|r| !r.within_limits())
        || request
            .stats
            .reverse_tunnel
            .as_ref()
            .is_some_and(|r| !r.within_limits())
        || request
            .stats
            .rate_limits
            .as_ref()
            .is_some_and(|r| !r.within_limits())
        || request
            .stats
            .speed_test
            .as_ref()
            .is_some_and(|r| !r.within_limits())
        || request
            .stats
            .firewall
            .as_ref()
            .is_some_and(|r| !r.within_limits())
    {
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
    // Every write is a durable recovery-log record, and heartbeats used to be
    // nearly all of the log. Store the status only when the revision, error or
    // quiescence changes, or once it is STATUS_REFRESH_MS old. Readers take
    // newer reports from telemetry while the row's `last_seen` is still the
    // one returned here.
    let (stored_applied, stored_error, stored_seen, stored_stats): (
        u64,
        Option<String>,
        Option<i64>,
        String,
    ) = tx.query_row(
        "SELECT applied_revision,apply_error,last_seen_ms,stats_json FROM nodes WHERE id=?1",
        [node],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)),
    )?;
    let now = now_ms();
    let quiet = |stats: &EngineStats| stats.business_idle() && stats.active_probes == 0;
    let stored_seen = if stored_applied != request.applied_revision
        || stored_error != request.apply_error
        || stored_seen.is_none_or(|seen| now.saturating_sub(seen) >= STATUS_REFRESH_MS)
        || serde_json::from_str::<EngineStats>(&stored_stats)
            .ok()
            .is_none_or(|stored| {
                quiet(&stored) != quiet(&request.stats)
                    || stored.mptcp_paths != request.stats.mptcp_paths
            }) {
        tx.execute("UPDATE nodes SET applied_revision=?1,last_seen_ms=?2,apply_error=?3,stats_json=?4 WHERE id=?5",params![request.applied_revision,now,request.apply_error,serde_json::to_string(&request.stats)?,node])?;
        Some(now)
    } else {
        stored_seen
    };
    // A tunnel that became ready publishes its public end; this node then
    // gets the new revision with this reply.
    let tunnels_changed = super::reverse_tunnels::observe(
        tx,
        &mut clocks.lock().unwrap(),
        tunnel_wakes,
        node,
        request.stats.reverse_tunnel.as_ref(),
    )?;
    // A segment that ended moves its test on: wake the next segment's agents.
    let speed_tests_changed =
        super::speed_tests::observe(tx, speed_tests, node, request.stats.speed_test.as_ref())?;
    let desired: u64 = tx.query_row(
        "SELECT desired_revision FROM nodes WHERE id=?1",
        [node],
        |r| r.get(0),
    )?;
    let config = if request.need_config || desired != request.applied_revision {
        Some(serde_json::from_str(&tx.query_row(
            "SELECT config_json FROM config_history WHERE node_id=?1 AND revision=?2",
            params![node, desired],
            |r| r.get::<_, String>(0),
        )?)?)
    } else {
        None
    };
    super::rate_limits::observe(tx, node, request.stats.rate_limits.as_ref())?;
    super::egress_proxies::observe(tx, node, request.stats.egress_proxy.as_ref())?;
    super::firewall_sets::observe(tx, node, request.stats.firewall.as_ref())?;
    let firewall = super::firewall_sets::desired(tx, node, request.stats.firewall.as_ref())?;
    let user_rates = super::user_rates::shares(
        tx,
        &mut rates.lock().unwrap(),
        node,
        &request.stats.user_rates,
        super::rate_limits::supported(tx, node)?,
    )?;
    let mut traversal = traversal.lock().unwrap();
    super::wireguard::observe(tx, node, request.stats.wireguard.as_ref(), &mut traversal)?;
    let mptcp_paths = if super::features::enabled(tx, "mptcp-paths")? {
        super::node_profiles::read(tx, node)?
            .settings
            .mptcp_paths
            .unwrap_or_default()
    } else {
        Default::default()
    };
    Ok((
        SyncResponse {
            mptcp_paths: Some(mptcp_paths),
            // Rendered after the commit, from the newest health reports.
            authoritative_dns: None,
            wireguard: Some(super::wireguard::desired(tx, node, &traversal)?),
            reverse_tunnels: Some(super::reverse_tunnels::desired(tx, node)?),
            rate_limits: true,
            speed_test: true,
            speed_test_tasks: super::speed_tests::desired(tx, node)?,
            live_connections: true,
            // Filled in after the commit, from memory.
            live_connection_requests: vec![],
            block_cursor: None,
            egress_proxy: true,
            firewall: Some(serde_json::to_value(firewall)?),
            user_rates: Some(user_rates),
            credential_rotation: super::credentials::read(tx, node)?.pending,
            budget,
            controller_instance: "store-direct".into(),
            config,
            acknowledgements,
            server_time_ms: now_ms(),
            log_cursor: None,
        },
        stored_seen,
        tunnels_changed || speed_tests_changed,
    ))
}
