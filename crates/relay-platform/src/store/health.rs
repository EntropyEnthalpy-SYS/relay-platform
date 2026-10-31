use super::*;
use crate::health::{MAX_ENDPOINTS, Status, TargetHealthReport};
use std::collections::HashSet;

pub(super) fn validate_reports(
    conn: &Connection,
    node: &str,
    revision: u64,
    stats: &EngineStats,
) -> Result<()> {
    if stats.target_health.len() > MAX_ENDPOINTS
        || stats.active_probes > crate::health::MAX_CONCURRENT as u64
    {
        return reject(400, "health report exceeds node limits");
    }
    if stats.target_health.is_empty() {
        return Ok(());
    }
    let config: NodeConfig = serde_json::from_str(&conn.query_row(
        "SELECT config_json FROM config_history WHERE node_id=?1 AND revision=?2",
        params![node, revision],
        |r| r.get::<_, String>(0),
    )?)?;
    let mut seen = HashSet::new();
    for report in &stats.target_health {
        let Some(rule) = config
            .rules
            .iter()
            .find(|rule| rule.id == report.rule_id && rule.enabled)
        else {
            return reject(
                400,
                "health report does not belong to the applied configuration",
            );
        };
        let Some(policy) = &rule.health_check else {
            return reject(400, "health report has no configured check");
        };
        let Some(target) = rule.targets.get(report.target_index) else {
            return reject(400, "health target index is invalid");
        };
        let valid_port = if rule.port_mapping == PortMapping::Offset {
            (rule.listen.port()..=rule.listen_end_port.unwrap_or(rule.listen.port()))
                .contains(&report.listen_port)
        } else {
            report.listen_port == rule.listen.port()
        };
        let valid_protocol = match report.protocol {
            Protocol::Tcp => rule.protocol.tcp(),
            Protocol::Udp => rule.protocol.udp(),
            Protocol::Both => false,
        };
        if !valid_port
            || !valid_protocol
            || !seen.insert((
                &report.rule_id,
                report.target_index,
                report.listen_port,
                report.protocol.tcp(),
            ))
        {
            return reject(400, "invalid or duplicate health endpoint");
        }
        if report.target_address != rule.target_address(report.target_index, report.listen_port)?
            || report.probe_kind != crate::health::probe_kind(policy, report.protocol.tcp())
            || report.max_age_ms != policy.max_age_ms
            || report.priority != target.priority
            || report.max_sessions != target.max_sessions
        {
            return reject(400, "health report differs from configured target policy");
        }
        if (report.eligible && report.status != Status::Healthy)
            || (report.completed_checks == 0
                && (report.status != Status::Unknown
                    || report.sample_age_ms.is_some()
                    || report.checked_at_ms.is_some()))
            || (report.completed_checks > 0
                && (report.sample_age_ms.is_none() || report.checked_at_ms.is_none()))
        {
            return reject(400, "health report has inconsistent observation state");
        }
        if ![
            "unknown",
            "eligible",
            "degraded",
            "draining",
            "standby",
            "unhealthy",
            "recovering",
            "stale",
            "at_capacity",
            "expired",
        ]
        .contains(&report.selection_reason.as_str())
            || report.successful_checks > report.completed_checks
            || report.sample_age_ms.is_some_and(|n| n > MAX_COUNTER)
            || report.latency_ewma_us.is_some_and(|n| n > MAX_COUNTER)
            || [
                report.active_sessions,
                report.completed_checks,
                report.successful_checks,
                report.probe_sent_bytes,
                report.probe_received_bytes,
            ]
            .into_iter()
            .any(|n| n > MAX_COUNTER)
        {
            return reject(400, "invalid health observation counters");
        }
    }
    Ok(())
}

impl Store {
    pub fn node_health(&self, actor: &Actor, node: &str) -> Result<serde_json::Value> {
        let conn = self.0.lock().unwrap();
        require_node(&conn, actor, node, false)?;
        let (applied,desired,last_seen,error,stats):(u64,u64,Option<i64>,Option<String>,String)=conn.query_row("SELECT applied_revision,desired_revision,last_seen_ms,apply_error,stats_json FROM nodes WHERE id=?1",[node],|r|Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
        let (last_seen, stats) = self.4.current(node, last_seen, stats);
        let stats: EngineStats = serde_json::from_str(&stats).unwrap_or_default();
        let config: NodeConfig = serde_json::from_str(&conn.query_row(
            "SELECT config_json FROM config_history WHERE node_id=?1 AND revision=?2",
            params![node, applied],
            |r| r.get::<_, String>(0),
        )?)?;
        let elapsed = last_seen.map(|time| now_ms().saturating_sub(time).max(0) as u64);
        let reports: Vec<TargetHealthReport> = stats
            .target_health
            .into_iter()
            .map(|mut r| {
                r.sample_age_ms = r
                    .sample_age_ms
                    .zip(elapsed)
                    .map(|(age, elapsed)| age.saturating_add(elapsed));
                if elapsed.is_none() || r.sample_age_ms.is_some_and(|age| age > r.max_age_ms) {
                    r.status = Status::Stale;
                    r.eligible = false;
                    r.selection_reason = "stale".into();
                }
                r
            })
            .collect();
        Ok(
            serde_json::json!({"node_id":node,"applied_revision":applied,"desired_revision":desired,"apply_error":error,"last_seen_ms":last_seen,"active_probes":stats.active_probes,"expected_endpoints":config.rules.iter().map(crate::health::endpoint_count).sum::<usize>(),"rule_names":config.rules.iter().map(|r|(r.id.clone(),r.name.clone())).collect::<std::collections::BTreeMap<_,_>>(),"reports":reports}),
        )
    }
}
