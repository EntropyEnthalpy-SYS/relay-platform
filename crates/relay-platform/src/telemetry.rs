//! Controller-side recent history: one sample per node report and incidents
//! derived from changes between reports. Kept in memory for the dashboard, so
//! a controller restart starts empty; the usage ledger stays authoritative.
//! With [`crate::history`] enabled, report figures and connection outcomes
//! are also summed into buckets that are written there every minute.
use crate::{
    health::Status,
    history::{Buckets, History, HopKey, NodeBucket},
    model::{ConnectionCounts, EngineStats, now_ms},
};
use serde::Serialize;
use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
};

pub const WINDOW_MS: i64 = 24 * 60 * 60 * 1000;
const MAX_SAMPLES: usize = 20_000;
const MAX_EVENTS: usize = 500;
/// A report after this much silence is a reconnection.
pub const OFFLINE_AFTER_MS: i64 = 30_000;

#[derive(Clone, Debug, Serialize)]
pub struct Sample {
    pub at_ms: i64,
    /// Forwarded bytes in both directions since the agent process started.
    pub forwarded_bytes: u64,
    pub active_sessions: u64,
    pub failed_connections: u64,
    pub cpu_percent: Option<f32>,
    pub process_cpu_percent: Option<f32>,
    pub rss_bytes: Option<u64>,
    pub memory_total_bytes: Option<u64>,
    pub memory_available_bytes: Option<u64>,
    /// Median of the latest probe latency over currently eligible targets.
    pub probe_latency_us: Option<u64>,
    pub healthy_targets: u32,
    pub probed_targets: u32,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Serialize, serde::Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Severity {
    Info,
    Recovered,
    Warning,
    Critical,
}

#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub id: u64,
    pub at_ms: i64,
    pub node_id: String,
    pub severity: Severity,
    pub kind: &'static str,
    /// What the event is about within the node, stable across reports, so
    /// a later event can close the incident an earlier one opened.
    pub subject: String,
    pub message: String,
}

#[derive(Default)]
struct Track {
    samples: VecDeque<Sample>,
    targets: HashMap<(String, usize, u16, bool), Status>,
    applied: u64,
    apply_error: Option<String>,
    last_seen: Option<i64>,
    /// The latest committed report's stats JSON and the database `last_seen`
    /// it was committed against; sync rewrites that row only on changes or
    /// once a minute.
    status: Option<(Option<i64>, String)>,
    /// The latest report's connection counters, for the change since.
    connections: HashMap<(String, Option<usize>, String), ConnectionCounts>,
}

#[derive(Default)]
struct Inner {
    nodes: HashMap<String, Track>,
    events: VecDeque<Event>,
    next_id: u64,
    /// Bucket sums not yet written to the history database.
    pending: Buckets,
}

#[derive(Default)]
pub struct Telemetry(
    Mutex<Inner>,
    std::sync::OnceLock<History>,
    Mutex<crate::logs::Sources>,
);

impl Telemetry {
    pub fn record(&self, node: &str, applied: u64, apply_error: Option<&str>, stats: &EngineStats) {
        self.record_at(now_ms(), node, applied, apply_error, stats);
    }

    pub fn record_at(
        &self,
        at_ms: i64,
        node: &str,
        applied: u64,
        apply_error: Option<&str>,
        stats: &EngineStats,
    ) {
        let mut inner = self.0.lock().unwrap();
        let Inner {
            nodes,
            events,
            next_id,
            pending,
        } = &mut *inner;
        let track = nodes.entry(node.to_owned()).or_default();
        let mut emit = |severity, kind, subject: String, message: String| {
            *next_id += 1;
            events.push_back(Event {
                id: *next_id,
                at_ms,
                node_id: node.to_owned(),
                severity,
                kind,
                subject,
                message,
            });
            if events.len() > MAX_EVENTS {
                events.pop_front();
            }
        };
        let seen_before = track.last_seen.is_some();
        if let Some(last) = track.last_seen
            && at_ms - last > OFFLINE_AFTER_MS
        {
            emit(
                Severity::Recovered,
                "node_reconnected",
                String::new(),
                format!("节点在 {} 秒无回报后恢复联系", (at_ms - last) / 1000),
            );
        }
        track.last_seen = Some(at_ms);
        let error = apply_error.map(str::to_owned);
        if error != track.apply_error {
            match &error {
                Some(message) => emit(
                    Severity::Critical,
                    "config_rejected",
                    String::new(),
                    format!("节点拒绝新配置，继续运行修订 {applied}：{message}"),
                ),
                None if seen_before => emit(
                    Severity::Recovered,
                    "config_recovered",
                    String::new(),
                    format!("配置错误已解除，正在运行修订 {applied}"),
                ),
                None => {}
            }
        } else if seen_before && error.is_none() && applied > track.applied {
            emit(
                Severity::Info,
                "config_applied",
                String::new(),
                format!("已应用配置修订 {applied}"),
            );
        }
        track.applied = applied;
        track.apply_error = error;

        let mut latencies = vec![];
        let mut healthy = 0;
        let mut current = HashMap::new();
        for report in &stats.target_health {
            let key = (
                report.rule_id.clone(),
                report.target_index,
                report.listen_port,
                report.probe_kind != crate::health::ProbeKind::UdpExchange,
            );
            if report.eligible {
                healthy += 1;
                latencies.extend(report.latency_ewma_us);
            }
            let protocol = if key.3 { "TCP" } else { "UDP" };
            let subject = format!(
                "{}/{}/{}/{}",
                report.rule_id, report.target_index, report.listen_port, protocol
            );
            match (track.targets.get(&key), report.status) {
                // A target already failing when first seen (a new rule, or
                // any rule after a controller restart) is down too, and so is
                // one that failed and began recovering between two reports.
                (
                    Some(Status::Healthy | Status::Unknown) | None,
                    Status::Unhealthy | Status::Stale | Status::Recovering,
                ) => emit(
                    Severity::Warning,
                    "target_down",
                    subject,
                    format!(
                        "规则 {} 的目标 {}（{} 端口 {}）不可用，新连接改用其他目标{}",
                        report.rule_id,
                        report.target_address,
                        protocol,
                        report.listen_port,
                        report
                            .last_error
                            .map(|e| format!("；原因：{}", e.label()))
                            .unwrap_or_default()
                    ),
                ),
                (Some(Status::Unhealthy | Status::Recovering | Status::Stale), Status::Healthy) => {
                    emit(
                        Severity::Recovered,
                        "target_recovered",
                        subject,
                        format!(
                            "规则 {} 的目标 {}（{} 端口 {}）恢复可用",
                            report.rule_id, report.target_address, protocol, report.listen_port
                        ),
                    )
                }
                _ => {}
            }
            current.insert(key, report.status);
        }
        for ((rule, index, port, tcp), status) in &track.targets {
            if !current.contains_key(&(rule.clone(), *index, *port, *tcp))
                && matches!(
                    status,
                    Status::Unhealthy | Status::Recovering | Status::Stale
                )
            {
                let protocol = if *tcp { "TCP" } else { "UDP" };
                emit(
                    Severity::Info,
                    "target_removed",
                    format!("{rule}/{index}/{port}/{protocol}"),
                    format!("规则 {rule} 的目标 {index}（{protocol} 端口 {port}）已从配置移除"),
                );
            }
        }
        track.targets = current;
        latencies.sort_unstable();
        let system = stats.system.as_ref().filter(|s| s.plausible());
        let sample = Sample {
            at_ms,
            forwarded_bytes: stats
                .forwarded_upload_bytes
                .saturating_add(stats.forwarded_download_bytes),
            active_sessions: stats.active_tcp + stats.active_udp,
            failed_connections: stats.failed_connections,
            cpu_percent: system.and_then(|s| s.cpu_percent),
            process_cpu_percent: system.and_then(|s| s.process_cpu_percent),
            rss_bytes: system.and_then(|s| s.rss_bytes),
            memory_total_bytes: system.and_then(|s| s.memory_total_bytes),
            memory_available_bytes: system.and_then(|s| s.memory_available_bytes),
            probe_latency_us: latencies.get(latencies.len() / 2).copied(),
            healthy_targets: healthy,
            probed_targets: stats.target_health.len() as u32,
        };
        if self.1.get().is_some() {
            let at = crate::history::bucket(at_ms);
            // Counters restart from zero with the agent. Without an earlier
            // report since this controller started, the change is unknown.
            let bytes = track.samples.back().map_or(0, |p| {
                sample
                    .forwarded_bytes
                    .checked_sub(p.forwarded_bytes)
                    .unwrap_or(sample.forwarded_bytes)
            });
            pending
                .nodes
                .entry((node.to_owned(), at))
                .or_default()
                .add(&NodeBucket {
                    reports: 1,
                    forwarded_bytes: bytes,
                    sessions_sum: sample.active_sessions,
                    sessions_max: sample.active_sessions,
                    latency_sum_us: sample.probe_latency_us.unwrap_or(0),
                    latency_count: sample.probe_latency_us.is_some().into(),
                    healthy_sum: sample.healthy_targets.into(),
                    probed_sum: sample.probed_targets.into(),
                    cpu_sum: sample.cpu_percent.map_or(0.0, f64::from),
                    cpu_count: sample.cpu_percent.is_some().into(),
                });
            let mut current = HashMap::new();
            for report in &stats.connections {
                let key = (
                    report.rule_id.clone(),
                    report.target_index,
                    report.target_address.clone(),
                );
                let change = match track.connections.get(&key) {
                    Some(earlier) => report.counts.since(earlier),
                    None if seen_before => report.counts,
                    None => ConnectionCounts::default(),
                };
                if change.attempts > 0 {
                    let hop = HopKey {
                        node_id: node.to_owned(),
                        rule_id: key.0.clone(),
                        target_index: key.1,
                        target_address: key.2.clone(),
                    };
                    pending.hops.entry((hop, at)).or_default().add(&change);
                }
                current.insert(key, report.counts);
            }
            track.connections = current;
        }
        track.samples.push_back(sample);
        while track.samples.len() > MAX_SAMPLES
            || track
                .samples
                .front()
                .is_some_and(|s| at_ms - s.at_ms > WINDOW_MS)
        {
            track.samples.pop_front();
        }
    }

    /// Keeps a committed report's stats with the stored `last_seen` they
    /// were committed against.
    pub fn keep_status(&self, node: &str, stored_seen: Option<i64>, stats: &EngineStats) {
        if let (Some(track), Ok(json)) = (
            self.0.lock().unwrap().nodes.get_mut(node),
            serde_json::to_string(stats),
        ) {
            track.status = Some((stored_seen, json));
        }
    }

    /// A node's last report time and stats JSON: the newest committed report
    /// while the stored row is still the one it was committed against, so any
    /// other write to that row (a lease reset, a restore) takes precedence.
    pub fn current(
        &self,
        node: &str,
        last_seen: Option<i64>,
        stats: String,
    ) -> (Option<i64>, String) {
        let inner = self.0.lock().unwrap();
        match inner.nodes.get(node) {
            Some(Track {
                last_seen: Some(seen),
                status: Some((stored, live)),
                ..
            }) if *stored == last_seen => (Some(*seen), live.clone()),
            _ => (last_seen, stats),
        }
    }

    /// The sample of a node's newest report since this controller started.
    pub fn latest(&self, node: &str) -> Option<Sample> {
        self.0
            .lock()
            .unwrap()
            .nodes
            .get(node)?
            .samples
            .back()
            .cloned()
    }

    /// Drops the history of a deleted node.
    pub fn forget(&self, node: &str) {
        let mut inner = self.0.lock().unwrap();
        inner.nodes.remove(node);
        inner.pending.nodes.retain(|(id, _), _| id != node);
        inner.pending.hops.retain(|(hop, _), _| hop.node_id != node);
        self.2.lock().unwrap().forget(node);
    }

    /// Keeps a node's new log lines; returns where its copy now ends.
    pub fn add_logs(&self, node: &str, batch: Option<crate::logs::Batch>) -> crate::logs::Cursor {
        self.2.lock().unwrap().add(node, batch)
    }

    /// Log lines newer than `after` from `source` (every source when `None`),
    /// including the controller's own, with whether older ones were left out
    /// and the newest line id.
    pub fn logs(
        &self,
        source: Option<&str>,
        after: u64,
        limit: usize,
    ) -> (Vec<crate::logs::Kept>, bool, u64) {
        let mut sources = self.2.lock().unwrap();
        sources.add_own();
        let (lines, truncated) = sources.read(source, after, limit);
        (lines, truncated, sources.last_id())
    }

    /// Keeps seven days of buckets in the database at `path` from now on.
    pub fn enable_history(&self, path: &std::path::Path) -> anyhow::Result<()> {
        let history = History::open(path)?;
        anyhow::ensure!(self.1.set(history).is_ok(), "history already enabled");
        Ok(())
    }

    /// Writes and clears the pending buckets.
    pub fn flush_history(&self) -> anyhow::Result<()> {
        let Some(history) = self.1.get() else {
            return Ok(());
        };
        let pending = std::mem::take(&mut self.0.lock().unwrap().pending);
        history.write(&pending, now_ms())
    }

    /// Stored and pending buckets of `nodes` from `since_ms` on, or `None`
    /// when history is not enabled.
    pub fn history(&self, nodes: &[String], since_ms: i64) -> anyhow::Result<Option<Buckets>> {
        let Some(history) = self.1.get() else {
            return Ok(None);
        };
        let mut buckets = history.read(nodes, since_ms)?;
        let inner = self.0.lock().unwrap();
        let wanted = |id: &String, at: i64| at >= since_ms && nodes.contains(id);
        buckets.merge(Buckets {
            nodes: inner
                .pending
                .nodes
                .iter()
                .filter(|((id, at), _)| wanted(id, *at))
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
            hops: inner
                .pending
                .hops
                .iter()
                .filter(|((hop, at), _)| wanted(&hop.node_id, *at))
                .map(|(k, v)| (k.clone(), *v))
                .collect(),
        });
        Ok(Some(buckets))
    }

    /// Every event newer than `after`, oldest first, regardless of tenant.
    pub fn events_after(&self, after: u64) -> Vec<Event> {
        let inner = self.0.lock().unwrap();
        inner
            .events
            .iter()
            .filter(|e| e.id > after)
            .cloned()
            .collect()
    }

    /// Samples and events for the given nodes, oldest first.
    pub fn snapshot(&self, visible: &[String]) -> (HashMap<String, Vec<Sample>>, Vec<Event>) {
        let inner = self.0.lock().unwrap();
        let cutoff = now_ms() - WINDOW_MS;
        let samples = visible
            .iter()
            .filter_map(|id| {
                let track = inner.nodes.get(id)?;
                Some((
                    id.clone(),
                    track
                        .samples
                        .iter()
                        .filter(|s| s.at_ms >= cutoff)
                        .cloned()
                        .collect(),
                ))
            })
            .collect();
        let events = inner
            .events
            .iter()
            .filter(|e| visible.contains(&e.node_id))
            .cloned()
            .collect();
        (samples, events)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::health::{Failure, ProbeKind, TargetHealthReport};
    use crate::model::Protocol;

    fn target(index: usize, status: Status, latency_us: Option<u64>) -> TargetHealthReport {
        TargetHealthReport {
            probe_kind: ProbeKind::TcpConnect,
            rule_id: "web".into(),
            target_index: index,
            listen_port: 8443,
            protocol: Protocol::Tcp,
            target_address: format!("10.0.0.{index}:443"),
            status,
            eligible: status == Status::Healthy,
            selection_reason: String::new(),
            sample_age_ms: None,
            max_age_ms: 10_000,
            checked_at_ms: None,
            latency_ewma_us: latency_us,
            window_checks: 0,
            window_failures: 0,
            jitter_us: None,
            consecutive_successes: 0,
            consecutive_failures: 0,
            completed_checks: 0,
            successful_checks: 0,
            last_error: (status == Status::Unhealthy).then_some(Failure::Timeout),
            probe_sent_bytes: 0,
            probe_received_bytes: 0,
            priority: 0,
            active_sessions: 0,
            max_sessions: None,
        }
    }

    fn stats(targets: Vec<TargetHealthReport>) -> EngineStats {
        EngineStats {
            target_health: targets,
            ..Default::default()
        }
    }

    fn kinds(telemetry: &Telemetry) -> Vec<&'static str> {
        let (_, events) = telemetry.snapshot(&["a".into()]);
        events.iter().map(|e| e.kind).collect()
    }

    #[test]
    fn health_changes_become_incidents_and_latency_is_the_median_of_healthy_targets() {
        let t = Telemetry::default();
        let now = now_ms();
        // A target first seen unhealthy is down from the start.
        t.record_at(
            now,
            "a",
            1,
            None,
            &stats(vec![
                target(0, Status::Healthy, Some(100)),
                target(1, Status::Healthy, Some(900)),
                target(2, Status::Healthy, Some(300)),
                target(3, Status::Unhealthy, Some(5)),
            ]),
        );
        assert_eq!(kinds(&t), ["target_down"]);
        t.record_at(
            now + 5_000,
            "a",
            1,
            None,
            &stats(vec![
                target(0, Status::Unhealthy, Some(100)),
                target(1, Status::Healthy, Some(900)),
                target(2, Status::Healthy, Some(300)),
                target(3, Status::Unhealthy, Some(5)),
            ]),
        );
        t.record_at(
            now + 10_000,
            "a",
            1,
            None,
            &stats(vec![
                target(0, Status::Healthy, Some(100)),
                target(1, Status::Healthy, Some(900)),
                target(2, Status::Healthy, Some(300)),
                target(3, Status::Unhealthy, Some(5)),
            ]),
        );
        assert_eq!(
            kinds(&t),
            ["target_down", "target_down", "target_recovered"]
        );
        let (samples, events) = t.snapshot(&["a".into()]);
        assert!(events[1].message.contains("10.0.0.0:443"));
        assert_eq!(events[1].severity, Severity::Warning);
        assert_eq!(events[1].subject, events[2].subject);
        assert_ne!(events[0].subject, events[1].subject);
        let samples = &samples["a"];
        assert_eq!(samples[0].probe_latency_us, Some(300));
        assert_eq!(
            (samples[0].healthy_targets, samples[0].probed_targets),
            (3, 4)
        );
        assert_eq!(samples[1].probe_latency_us, Some(900));
        // Removing the failing target closes its incident; healthy ones leave quietly.
        t.record_at(now + 15_000, "a", 2, None, &stats(vec![]));
        let (_, events) = t.snapshot(&["a".into()]);
        assert_eq!(events.last().map(|e| e.kind), Some("target_removed"));
        assert_eq!(events.last().unwrap().subject, events[0].subject);
        assert_eq!(
            events.iter().filter(|e| e.kind == "target_removed").count(),
            1
        );
        // An outage shorter than one report interval is first seen as
        // recovering; it still opens an incident before it recovers.
        for (offset, status) in [
            (20_000, Status::Healthy),
            (25_000, Status::Recovering),
            (30_000, Status::Healthy),
        ] {
            let report = stats(vec![target(0, status, Some(100))]);
            t.record_at(now + offset, "a", 2, None, &report);
        }
        let (_, events) = t.snapshot(&["a".into()]);
        let tail: Vec<_> = events[events.len() - 2..].iter().map(|e| e.kind).collect();
        assert_eq!(tail, ["target_down", "target_recovered"]);
    }

    #[test]
    fn configuration_outcomes_are_reported_once_per_change() {
        let t = Telemetry::default();
        let now = now_ms();
        t.record_at(now, "a", 3, None, &stats(vec![]));
        t.record_at(now + 1, "a", 3, Some("port in use"), &stats(vec![]));
        t.record_at(now + 2, "a", 3, Some("port in use"), &stats(vec![]));
        t.record_at(now + 3, "a", 4, None, &stats(vec![]));
        t.record_at(now + 4, "a", 5, None, &stats(vec![]));
        assert_eq!(
            kinds(&t),
            ["config_rejected", "config_recovered", "config_applied"]
        );
    }

    #[test]
    fn old_samples_expire_and_long_silence_is_a_reconnection() {
        let t = Telemetry::default();
        let now = now_ms();
        t.record_at(now - WINDOW_MS - 1, "a", 1, None, &stats(vec![]));
        t.record_at(now - OFFLINE_AFTER_MS, "a", 1, None, &stats(vec![]));
        t.record_at(now, "a", 1, None, &stats(vec![]));
        t.record_at(now, "b", 1, None, &stats(vec![]));
        let (samples, events) = t.snapshot(&["a".into()]);
        assert_eq!(samples["a"].len(), 2);
        assert!(!samples.contains_key("b"));
        // The first gap is over the threshold; the second is exactly at it.
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].kind, "node_reconnected");
    }

    fn traffic(bytes: u64, hops: &[(Option<usize>, u64, u64, u64)]) -> EngineStats {
        let connections = hops
            .iter()
            .map(
                |&(index, attempts, connected, timeout)| crate::model::ConnectionReport {
                    rule_id: "web".into(),
                    target_index: index,
                    target_address: index.map_or(String::new(), |i| format!("10.0.0.{i}:443")),
                    counts: ConnectionCounts {
                        attempts,
                        connected,
                        timeout,
                        ..Default::default()
                    },
                },
            )
            .collect();
        EngineStats {
            forwarded_upload_bytes: bytes,
            connections,
            ..Default::default()
        }
    }

    #[test]
    fn history_sums_changes_between_reports_and_survives_a_controller_restart() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("history.sqlite");
        let t = Telemetry::default();
        t.enable_history(&path).unwrap();
        let at = crate::history::bucket(now_ms());
        // Before a first report the counters' starting point is unknown.
        t.record_at(at, "a", 1, None, &traffic(1_000, &[(Some(0), 10, 9, 1)]));
        t.record_at(
            at + 1,
            "a",
            1,
            None,
            &traffic(1_500, &[(Some(0), 15, 13, 2)]),
        );
        t.flush_history().unwrap();
        // The agent restarted: its counters start again from zero, and a hop
        // seen for the first time counts in full.
        t.record_at(
            at + 2,
            "a",
            1,
            None,
            &traffic(200, &[(Some(0), 3, 3, 0), (None, 2, 2, 0)]),
        );
        t.record_at(at + 3, "b", 1, None, &traffic(0, &[]));
        t.record_at(at + 4, "b", 1, None, &traffic(9, &[(Some(0), 4, 4, 0)]));
        let hop = |b: &Buckets, index: Option<usize>| {
            let found: Vec<_> = b
                .hops
                .iter()
                .filter(|((h, _), _)| h.target_index == index)
                .collect();
            assert_eq!(found.len(), 1);
            assert_eq!(found[0].0.0.node_id, "a");
            *found[0].1
        };
        let both = t.history(&["a".into()], at).unwrap().unwrap();
        let target = hop(&both, Some(0));
        assert_eq!(
            (target.attempts, target.connected, target.timeout),
            (8, 7, 1)
        );
        assert_eq!(hop(&both, None).attempts, 2);
        assert_eq!(both.nodes.len(), 1);
        let node = both.nodes[&("a".to_owned(), at)];
        assert_eq!((node.reports, node.forwarded_bytes), (3, 700));
        // A restarted controller reads what was written; the rest was pending.
        let again = Telemetry::default();
        again.enable_history(&path).unwrap();
        let stored = again.history(&["a".into()], at).unwrap().unwrap();
        let target = hop(&stored, Some(0));
        assert_eq!(
            (target.attempts, target.connected, target.timeout),
            (5, 4, 1)
        );
        assert_eq!(stored.nodes[&("a".to_owned(), at)].forwarded_bytes, 500);
        assert!(
            again
                .history(&["a".into()], at + crate::history::BUCKET_MS)
                .unwrap()
                .unwrap()
                .nodes
                .is_empty()
        );
    }
}
