//! Active, bounded target observations. Selection uses monotonic freshness;
//! controller reports are diagnostics, never a replacement for the usage ledger.
use crate::model::{PortMapping, Protocol, Rule};
use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    sync::{
        Arc, Mutex,
        atomic::{AtomicBool, AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio::time::Instant;
use tokio_util::sync::CancellationToken;

pub const MAX_ENDPOINTS: usize = 256;
pub(crate) const MAX_CONCURRENT: usize = 16;
pub const MAX_PROBE_BYTES: usize = 1024;
fn interval() -> u64 {
    1000
}
fn timeout() -> u64 {
    1000
}
fn failures() -> u16 {
    2
}
fn successes() -> u16 {
    2
}
fn recovery() -> u64 {
    5000
}
fn max_age() -> u64 {
    10000
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct HealthCheck {
    #[serde(default = "interval")]
    pub interval_ms: u64,
    #[serde(default = "timeout")]
    pub timeout_ms: u64,
    #[serde(default = "failures")]
    pub unhealthy_threshold: u16,
    #[serde(default = "successes")]
    pub healthy_threshold: u16,
    #[serde(default = "recovery")]
    pub recovery_delay_ms: u64,
    #[serde(default = "max_age")]
    pub max_age_ms: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tcp: Option<StreamProbe>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub udp: Option<DatagramProbe>,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum StreamProbe {
    /// Includes configured TLS, PROXY and WS setup; does not prove an application reply.
    Connect,
    Exchange {
        request_base64: String,
        expected_base64: String,
        #[serde(default)]
        half_close: bool,
    },
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DatagramProbe {
    pub request_base64: String,
    pub expected_base64: String,
}
pub(crate) fn payload(text: &str, nonempty: bool) -> Result<Vec<u8>> {
    ensure!(text.len() <= 1368, "probe payload exceeds 1024 bytes");
    let bytes = STANDARD.decode(text)?;
    ensure!(
        bytes.len() <= MAX_PROBE_BYTES && (!nonempty || !bytes.is_empty()),
        "invalid probe payload length"
    );
    Ok(bytes)
}
impl HealthCheck {
    pub fn validate(&self, protocol: Protocol) -> Result<()> {
        ensure!(
            (100..=300_000).contains(&self.interval_ms),
            "health interval must be 100..300000 ms"
        );
        ensure!(
            (25..=60_000).contains(&self.timeout_ms) && self.timeout_ms <= self.interval_ms,
            "health timeout must be 25..60000 ms and not exceed interval"
        );
        ensure!(
            (1..=20).contains(&self.unhealthy_threshold)
                && (1..=20).contains(&self.healthy_threshold),
            "health thresholds must be 1..20"
        );
        ensure!(
            self.recovery_delay_ms <= 600_000,
            "health recovery delay exceeds 600000 ms"
        );
        ensure!(
            self.max_age_ms >= self.interval_ms + self.timeout_ms && self.max_age_ms <= 3_600_000,
            "health max age must cover interval plus timeout and be at most one hour"
        );
        ensure!(
            self.tcp.is_some() == protocol.tcp() && self.udp.is_some() == protocol.udp(),
            "health checks must cover exactly the rule's TCP/UDP protocols"
        );
        if let Some(StreamProbe::Exchange {
            request_base64,
            expected_base64,
            ..
        }) = &self.tcp
        {
            payload(request_base64, false)?;
            payload(expected_base64, true)?;
        }
        if let Some(probe) = &self.udp {
            payload(&probe.request_base64, true)?;
            payload(&probe.expected_base64, true)?;
        }
        Ok(())
    }
}

pub(crate) fn endpoint_count(rule: &Rule) -> usize {
    if !rule.enabled || rule.health_check.is_none() {
        return 0;
    }
    let ports = if rule.port_mapping == PortMapping::Offset {
        usize::from(rule.listen_end_port.unwrap_or(rule.listen.port()) - rule.listen.port()) + 1
    } else {
        1
    };
    ports
        * rule.targets.len()
        * (usize::from(rule.protocol.tcp()) + usize::from(rule.protocol.udp()))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Status {
    Unknown,
    Healthy,
    Unhealthy,
    Recovering,
    Stale,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Failure {
    Dns,
    Transport,
    Timeout,
    Io,
    UnexpectedResponse,
    Expired,
}
impl Failure {
    /// Wording shared with the console's health page.
    pub fn label(self) -> &'static str {
        match self {
            Self::Dns => "域名解析失败",
            Self::Transport => "连接、握手或路径检查失败",
            Self::Timeout => "探测超时",
            Self::Io => "收发失败",
            Self::UnexpectedResponse => "回复不符或提前关闭",
            Self::Expired => "规则已到期",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProbeKind {
    TcpConnect,
    TcpExchange,
    UdpExchange,
}
pub(crate) fn probe_kind(policy: &HealthCheck, tcp: bool) -> ProbeKind {
    if !tcp {
        ProbeKind::UdpExchange
    } else if matches!(policy.tcp, Some(StreamProbe::Connect)) {
        ProbeKind::TcpConnect
    } else {
        ProbeKind::TcpExchange
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TargetHealthReport {
    pub probe_kind: ProbeKind,
    pub rule_id: String,
    pub target_index: usize,
    pub listen_port: u16,
    pub protocol: Protocol,
    pub target_address: String,
    pub status: Status,
    pub eligible: bool,
    pub selection_reason: String,
    pub sample_age_ms: Option<u64>,
    pub max_age_ms: u64,
    pub checked_at_ms: Option<i64>,
    pub latency_ewma_us: Option<u64>,
    /// Probes in the recent window (at most `QUALITY_WINDOW`) and how many failed.
    #[serde(default)]
    pub window_checks: u32,
    #[serde(default)]
    pub window_failures: u32,
    /// Mean absolute difference between consecutive successful probe
    /// latencies in the window; a failure in between breaks the pair.
    #[serde(default)]
    pub jitter_us: Option<u64>,
    pub consecutive_successes: u16,
    pub consecutive_failures: u16,
    pub completed_checks: u64,
    pub successful_checks: u64,
    pub last_error: Option<Failure>,
    pub probe_sent_bytes: u64,
    pub probe_received_bytes: u64,
    pub priority: u16,
    pub active_sessions: u64,
    pub max_sessions: Option<u32>,
}

/// Probe outcomes kept for loss and jitter.
pub const QUALITY_WINDOW: usize = 20;
/// Selection cost of a lost probe: the initial TCP retransmission timeout
/// (RFC 6298, 2.1), which a lost SYN or SYN-ACK adds to connection setup.
const LOSS_PENALTY_US: u64 = 1_000_000;
/// Selection uses the median of this many newest successful probes: one slow
/// reply does not move it, a change lasting three probes does.
const SELECTION_SAMPLES: usize = 5;

struct Sample {
    status: Status,
    /// Latest outcomes, oldest first: the latency of a success, `None` for a failure.
    recent: std::collections::VecDeque<Option<u64>>,
    checked: Option<Instant>,
    checked_at_ms: Option<i64>,
    recovery_since: Option<Instant>,
    /// Accepted at least once since probing began. Until then there is no
    /// outage to guard against, so the first acceptance skips the recovery
    /// delay even after failed probes (a downstream relay still starting).
    accepted: bool,
    consecutive_successes: u16,
    consecutive_failures: u16,
    completed: u64,
    successful: u64,
    latency: Option<u64>,
    error: Option<Failure>,
}
pub(crate) struct Observation {
    policy: HealthCheck,
    sample: Mutex<Sample>,
    sent: AtomicU64,
    received: AtomicU64,
    changed: tokio::sync::watch::Sender<()>,
    invalid: AtomicBool,
}
impl Observation {
    fn new(policy: HealthCheck) -> Self {
        Self {
            policy,
            sample: Mutex::new(Sample {
                status: Status::Unknown,
                recent: Default::default(),
                checked: None,
                checked_at_ms: None,
                recovery_since: None,
                accepted: false,
                consecutive_successes: 0,
                consecutive_failures: 0,
                completed: 0,
                successful: 0,
                latency: None,
                error: None,
            }),
            sent: AtomicU64::new(0),
            received: AtomicU64::new(0),
            changed: tokio::sync::watch::channel(()).0,
            invalid: AtomicBool::new(false),
        }
    }
    pub fn traffic(&self, sent: bool, bytes: usize) {
        let counter = if sent { &self.sent } else { &self.received };
        let mut current = counter.load(Ordering::Relaxed);
        loop {
            match counter.compare_exchange_weak(
                current,
                current.saturating_add(bytes as u64),
                Ordering::Relaxed,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(next) => current = next,
            }
        }
    }
    pub fn observe(&self, result: std::result::Result<u64, Failure>) {
        self.observe_at(Instant::now(), crate::model::now_ms(), result);
    }
    fn observe_at(&self, now: Instant, timestamp: i64, result: std::result::Result<u64, Failure>) {
        let mut s = self.sample.lock().unwrap();
        if s.checked.is_some_and(|at| {
            now.duration_since(at) > Duration::from_millis(self.policy.max_age_ms)
        }) {
            s.status = Status::Unhealthy;
            s.consecutive_successes = 0;
            s.consecutive_failures = 0;
            s.recovery_since = None;
        }
        s.checked = Some(now);
        s.checked_at_ms = Some(timestamp);
        s.completed = s.completed.saturating_add(1);
        if s.recent.len() == QUALITY_WINDOW {
            s.recent.pop_front();
        }
        s.recent.push_back(result.ok());
        match result {
            Ok(latency) => {
                s.successful = s.successful.saturating_add(1);
                s.consecutive_failures = 0;
                s.consecutive_successes = s.consecutive_successes.saturating_add(1);
                s.error = None;
                s.latency = Some(s.latency.map_or(latency, |old| {
                    old.saturating_mul(7).saturating_add(latency) / 8
                }));
                if s.status != Status::Healthy
                    && s.consecutive_successes >= self.policy.healthy_threshold
                {
                    if !s.accepted {
                        s.status = Status::Healthy;
                    } else {
                        let since = *s.recovery_since.get_or_insert(now);
                        s.status = if now.duration_since(since)
                            >= Duration::from_millis(self.policy.recovery_delay_ms)
                        {
                            Status::Healthy
                        } else {
                            Status::Recovering
                        };
                    }
                    s.accepted |= s.status == Status::Healthy;
                }
            }
            Err(error) => {
                s.error = Some(error);
                s.consecutive_successes = 0;
                s.recovery_since = None;
                s.consecutive_failures = s.consecutive_failures.saturating_add(1);
                if s.consecutive_failures >= self.policy.unhealthy_threshold
                    || s.status == Status::Recovering
                {
                    s.status = Status::Unhealthy;
                }
            }
        }
        drop(s);
        self.changed.send_replace(());
    }
    fn status_at(&self, s: &Sample, now: Instant) -> Status {
        if self.invalid.load(Ordering::Acquire) {
            return Status::Unknown;
        }
        if s.checked.is_some_and(|at| {
            now.duration_since(at) > Duration::from_millis(self.policy.max_age_ms)
        }) {
            Status::Stale
        } else {
            s.status
        }
    }
    /// Delay until the next probe: a quarter of the interval (at least
    /// 100 ms) before the first acceptance and while a healthy target is
    /// failing, so acceptance and removal settle sooner; the interval otherwise.
    pub(crate) fn probe_period(&self) -> Duration {
        let interval = Duration::from_millis(self.policy.interval_ms);
        let s = self.sample.lock().unwrap();
        if !s.accepted || (s.status == Status::Healthy && s.consecutive_failures > 0) {
            (interval / 4).max(Duration::from_millis(100)).min(interval)
        } else {
            interval
        }
    }
    /// How long the next probe may wait for its reply. A healthy target with
    /// at least five recent replies gets twice its slowest one (at least
    /// 250 ms, at most `timeout_ms`), so a target that goes silent on a fast
    /// path is removed in about a second instead of after two full timeouts.
    /// Unknown, failing-over and recovering targets wait the full timeout.
    pub(crate) fn probe_timeout(&self) -> Duration {
        let full = Duration::from_millis(self.policy.timeout_ms);
        let s = self.sample.lock().unwrap();
        let replies = s.recent.iter().flatten();
        if s.status != Status::Healthy || replies.clone().count() < 5 {
            return full;
        }
        let slowest = replies.max().copied().unwrap_or_default();
        Duration::from_micros(slowest.saturating_mul(2))
            .max(Duration::from_millis(250))
            .min(full)
    }
    /// Latency for selection: the median of the newest successful probes
    /// plus the expected cost of the recent failure rate, so a fast path that
    /// drops probes ranks behind a clean one.
    pub(crate) fn selection_latency_us(&self) -> Option<u64> {
        let s = self.sample.lock().unwrap();
        let (checks, failures, _) = quality(&s.recent);
        let mut newest: Vec<u64> = s
            .recent
            .iter()
            .rev()
            .flatten()
            .take(SELECTION_SAMPLES)
            .copied()
            .collect();
        newest.sort_unstable();
        let median = *newest.get(newest.len() / 2)?;
        Some(median + failures as u64 * LOSS_PENALTY_US / checks.max(1) as u64)
    }
    /// Losing probes while still eligible; see `degraded`.
    pub(crate) fn degraded(&self) -> bool {
        let s = self.sample.lock().unwrap();
        let (checks, failures, _) = quality(&s.recent);
        degraded(checks, failures)
    }
    pub fn eligible(&self) -> bool {
        let s = self.sample.lock().unwrap();
        self.status_at(&s, Instant::now()) == Status::Healthy
    }
    pub async fn wait_unavailable(&self) {
        let mut changed = self.changed.subscribe();
        loop {
            let deadline = {
                let s = self.sample.lock().unwrap();
                if self.status_at(&s, Instant::now()) != Status::Healthy {
                    return;
                }
                s.checked.unwrap() + Duration::from_millis(self.policy.max_age_ms + 1)
            };
            tokio::select! {_=tokio::time::sleep_until(deadline)=>{},_=changed.changed()=>{}}
        }
    }
    fn report(&self, rule: &Rule, key: Key, active: u64) -> TargetHealthReport {
        let s = self.sample.lock().unwrap();
        let (window_checks, window_failures, jitter_us) = quality(&s.recent);
        let now = Instant::now();
        let status = self.status_at(&s, now);
        let target = &rule.targets[key.index];
        let full = target.max_sessions.is_some_and(|n| active >= u64::from(n));
        let expired = rule
            .expires_at_ms
            .is_some_and(|e| e <= crate::model::now_ms());
        let reason = if expired {
            "expired"
        } else if full {
            "at_capacity"
        } else {
            match status {
                Status::Unknown => "unknown",
                Status::Healthy if target.draining => "draining",
                Status::Healthy
                    if rule.balance != crate::model::Balance::LowestLatency
                        && degraded(window_checks, window_failures) =>
                {
                    "degraded"
                }
                Status::Healthy => "eligible",
                Status::Unhealthy => "unhealthy",
                Status::Recovering => "recovering",
                Status::Stale => "stale",
            }
        };
        TargetHealthReport {
            probe_kind: probe_kind(&self.policy, key.tcp),
            rule_id: rule.id.clone(),
            target_index: key.index,
            listen_port: key.port,
            protocol: if key.tcp {
                Protocol::Tcp
            } else {
                Protocol::Udp
            },
            target_address: rule
                .target_address(key.index, key.port)
                .expect("validated target mapping"),
            status,
            eligible: status == Status::Healthy && !full && !expired,
            selection_reason: reason.into(),
            sample_age_ms: s
                .checked
                .map(|at| now.duration_since(at).as_millis().min(u128::from(u64::MAX)) as u64),
            max_age_ms: self.policy.max_age_ms,
            checked_at_ms: s.checked_at_ms,
            latency_ewma_us: s.latency,
            window_checks,
            window_failures,
            jitter_us,
            consecutive_successes: s.consecutive_successes,
            consecutive_failures: s.consecutive_failures,
            completed_checks: s.completed,
            successful_checks: s.successful,
            last_error: s.error,
            probe_sent_bytes: self.sent.load(Ordering::Relaxed),
            probe_received_bytes: self.received.load(Ordering::Relaxed),
            priority: target.priority,
            active_sessions: active,
            max_sessions: target.max_sessions,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub(crate) struct Key {
    pub index: usize,
    pub port: u16,
    pub tcp: bool,
}
pub(crate) struct HealthSet {
    pub stop: CancellationToken,
    pub points: HashMap<Key, Arc<Observation>>,
    base_port: u16,
    offset: bool,
}
impl HealthSet {
    pub fn cancel(&self) {
        self.stop.cancel();
        for point in self.points.values() {
            point.invalid.store(true, Ordering::Release);
            point.changed.send_replace(());
        }
    }
    pub fn new(rule: &Rule) -> Option<Arc<Self>> {
        let policy = rule.health_check.as_ref()?;
        let mut points = HashMap::new();
        let offset = rule.port_mapping == PortMapping::Offset;
        let end = if offset {
            rule.listen_end_port.unwrap_or(rule.listen.port())
        } else {
            rule.listen.port()
        };
        for port in rule.listen.port()..=end {
            for index in 0..rule.targets.len() {
                for tcp in [true, false] {
                    if (tcp && rule.protocol.tcp()) || (!tcp && rule.protocol.udp()) {
                        points.insert(
                            Key { index, port, tcp },
                            Arc::new(Observation::new(policy.clone())),
                        );
                    }
                }
            }
        }
        Some(Arc::new(Self {
            stop: CancellationToken::new(),
            points,
            base_port: rule.listen.port(),
            offset,
        }))
    }
    pub fn point(&self, index: usize, port: u16, tcp: bool) -> &Arc<Observation> {
        &self.points[&Key {
            index,
            port: if self.offset { port } else { self.base_port },
            tcp,
        }]
    }
    pub fn reports(
        &self,
        rule: &Rule,
        active: &[Arc<std::sync::atomic::AtomicUsize>],
    ) -> Vec<TargetHealthReport> {
        let mut points: Vec<_> = self.points.iter().collect();
        points.sort_by_key(|(k, _)| (k.index, k.port, k.tcp));
        points
            .into_iter()
            .map(|(key, point)| {
                point.report(rule, *key, active[key.index].load(Ordering::Relaxed) as u64)
            })
            .collect()
    }
}

/// At least 2 failures making up at least 10% of the recent window. Weighted,
/// source-hash and least-connections balancing put such targets behind clean
/// targets of the same priority.
fn degraded(checks: u32, failures: u32) -> bool {
    failures >= 2 && failures * 10 >= checks
}

/// Checks, failures and jitter over the recent window.
fn quality(recent: &std::collections::VecDeque<Option<u64>>) -> (u32, u32, Option<u64>) {
    let failures = recent.iter().filter(|o| o.is_none()).count() as u32;
    let steps: Vec<u64> = recent
        .iter()
        .zip(recent.iter().skip(1))
        .filter_map(|pair| match pair {
            (Some(a), Some(b)) => Some(a.abs_diff(*b)),
            _ => None,
        })
        .collect();
    let jitter = (!steps.is_empty()).then(|| steps.iter().sum::<u64>() / steps.len() as u64);
    (recent.len() as u32, failures, jitter)
}

#[cfg(test)]
mod tests {
    use super::*;
    fn policy() -> HealthCheck {
        serde_json::from_value(serde_json::json!({"interval_ms":100,"timeout_ms":50,"unhealthy_threshold":2,"healthy_threshold":2,"recovery_delay_ms":250,"max_age_ms":1000,"tcp":{"kind":"connect"}})).unwrap()
    }
    #[test]
    fn thresholds_and_recovery_delay_require_sustained_success() {
        let observation = Observation::new(policy());
        let start = Instant::now();
        let status = |at| {
            let s = observation.sample.lock().unwrap();
            observation.status_at(&s, at)
        };
        observation.observe_at(start, 1, Ok(100));
        assert_eq!(status(start), Status::Unknown);
        observation.observe_at(start + Duration::from_millis(100), 2, Ok(100));
        assert_eq!(status(start + Duration::from_millis(100)), Status::Healthy);
        observation.observe_at(
            start + Duration::from_millis(200),
            3,
            Err(Failure::UnexpectedResponse),
        );
        assert_eq!(status(start + Duration::from_millis(200)), Status::Healthy);
        observation.observe_at(start + Duration::from_millis(300), 4, Err(Failure::Timeout));
        assert_eq!(
            status(start + Duration::from_millis(300)),
            Status::Unhealthy
        );
        for ms in [400, 500] {
            observation.observe_at(start + Duration::from_millis(ms), 5, Ok(100));
        }
        assert_eq!(
            status(start + Duration::from_millis(500)),
            Status::Recovering
        );
        observation.observe_at(start + Duration::from_millis(600), 6, Err(Failure::Io));
        assert_eq!(
            status(start + Duration::from_millis(600)),
            Status::Unhealthy
        );
        for ms in [700, 800, 900, 1000] {
            observation.observe_at(start + Duration::from_millis(ms), 7, Ok(100));
        }
        assert_eq!(
            status(start + Duration::from_millis(1000)),
            Status::Recovering
        );
        observation.observe_at(start + Duration::from_millis(1100), 8, Ok(100));
        assert_eq!(status(start + Duration::from_millis(1100)), Status::Healthy);
    }
    #[test]
    fn a_target_never_accepted_yet_skips_the_recovery_delay() {
        // A downstream relay still starting fails the first probes. Its first
        // acceptance waits only for the success threshold; later outages wait
        // for the recovery delay as before.
        let observation = Observation::new(policy());
        let start = Instant::now();
        let at = |ms| start + Duration::from_millis(ms);
        let status = |ms| {
            let s = observation.sample.lock().unwrap();
            observation.status_at(&s, at(ms))
        };
        observation.observe_at(at(0), 1, Err(Failure::Io));
        observation.observe_at(at(100), 2, Err(Failure::Io));
        assert_eq!(status(100), Status::Unhealthy);
        observation.observe_at(at(200), 3, Ok(100));
        assert_eq!(status(200), Status::Unhealthy);
        observation.observe_at(at(300), 4, Ok(100));
        assert_eq!(status(300), Status::Healthy);
        observation.observe_at(at(400), 5, Err(Failure::Io));
        observation.observe_at(at(500), 6, Err(Failure::Io));
        observation.observe_at(at(600), 7, Ok(100));
        observation.observe_at(at(700), 8, Ok(100));
        assert_eq!(status(700), Status::Recovering);
    }
    #[test]
    fn one_slow_probe_does_not_move_selection_but_a_lasting_change_does() {
        let observation = Observation::new(policy());
        let start = Instant::now();
        let mut at = 0;
        let mut probe = |latency: u64| {
            at += 100;
            observation.observe_at(start + Duration::from_millis(at), 1, Ok(latency));
            observation.selection_latency_us().unwrap()
        };
        for _ in 0..5 {
            probe(50_000);
        }
        // A single 2 s reply would have added 244 ms to a 1/8 EWMA.
        assert_eq!(probe(2_000_000), 50_000);
        for _ in 0..5 {
            assert_eq!(probe(50_000), 50_000);
        }
        // The path becomes 300 ms slower and stays so.
        assert_eq!(probe(350_000), 50_000);
        assert_eq!(probe(350_000), 50_000);
        assert_eq!(probe(350_000), 350_000);
    }
    #[test]
    fn loss_and_jitter_come_from_the_recent_window_and_loss_costs_selection() {
        let observation = Observation::new(policy());
        let start = Instant::now();
        for (i, outcome) in [
            Ok(10_000),
            Ok(14_000),
            Err(Failure::Timeout),
            Ok(12_000),
            Ok(17_000),
        ]
        .into_iter()
        .enumerate()
        {
            observation.observe_at(start + Duration::from_millis(100 * i as u64), 1, outcome);
        }
        let s = observation.sample.lock().unwrap();
        // Pairs (10, 14) and (12, 17): the failure breaks (14, 12).
        assert_eq!(quality(&s.recent), (5, 1, Some(4_500)));
        drop(s);
        // The median of 10, 14, 12 and 17 ms, plus a fifth of the 1 s penalty
        // for one failure in five probes.
        assert_eq!(observation.selection_latency_us(), Some(14_000 + 200_000));
        // Only the newest QUALITY_WINDOW outcomes count.
        for i in 0..QUALITY_WINDOW as u64 {
            observation.observe_at(start + Duration::from_millis(600 + 100 * i), 1, Ok(10_000));
        }
        let s = observation.sample.lock().unwrap();
        assert_eq!(quality(&s.recent), (QUALITY_WINDOW as u32, 0, Some(0)));
    }
    #[test]
    fn healthy_targets_get_a_probe_timeout_from_their_slowest_recent_reply() {
        let mut slow = policy();
        (slow.interval_ms, slow.timeout_ms, slow.max_age_ms) = (1000, 1000, 3000);
        let observation = Observation::new(slow);
        let start = Instant::now();
        let mut ms = 0;
        let mut observe = |outcome| {
            ms += 100;
            observation.observe_at(start + Duration::from_millis(ms), 1, outcome);
            observation.probe_timeout().as_millis()
        };
        // Healthy after two replies, but four are too few to judge.
        for _ in 0..3 {
            assert_eq!(observe(Ok(3_000)), 1000);
        }
        assert_eq!(observe(Ok(3_000)), 1000);
        assert_eq!(observe(Ok(3_000)), 250);
        assert_eq!(observe(Ok(400_000)), 800);
        assert_eq!(observe(Ok(700_000)), 1000);
        // A single failure keeps the short limit for the confirming probe.
        for _ in 0..QUALITY_WINDOW {
            observe(Ok(3_000));
        }
        assert_eq!(observe(Err(Failure::Timeout)), 250);
        // A removed target waits the full timeout so a slow path can recover.
        assert_eq!(observe(Err(Failure::Timeout)), 1000);
        assert_eq!(observe(Ok(3_000)), 1000);
    }
    #[test]
    fn stale_success_does_not_immediately_reactivate_a_target() {
        let observation = Observation::new(policy());
        let start = Instant::now();
        observation.observe_at(start, 1, Ok(100));
        observation.observe_at(start, 1, Ok(200));
        {
            let s = observation.sample.lock().unwrap();
            assert_eq!(s.latency, Some(112));
            assert_eq!(
                observation.status_at(&s, start + Duration::from_millis(1001)),
                Status::Stale
            );
        }
        observation.observe_at(start + Duration::from_millis(1001), 2, Ok(300));
        let s = observation.sample.lock().unwrap();
        assert_eq!(s.status, Status::Unhealthy);
        assert_eq!(s.consecutive_successes, 1);
    }
    #[tokio::test]
    async fn stale_or_invalidated_observation_retires_waiting_udp_session() {
        let mut p = policy();
        p.max_age_ms = 150;
        p.healthy_threshold = 1;
        let observation = Observation::new(p);
        observation.observe(Ok(100));
        assert!(observation.eligible());
        tokio::time::timeout(Duration::from_millis(400), observation.wait_unavailable())
            .await
            .unwrap();
        assert!(!observation.eligible());
        observation.invalid.store(true, Ordering::Release);
        observation.observe(Ok(1));
        assert!(!observation.eligible());
    }
}
