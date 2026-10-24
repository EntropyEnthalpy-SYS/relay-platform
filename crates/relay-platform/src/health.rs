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
    5000
}
fn timeout() -> u64 {
    2000
}
fn failures() -> u16 {
    3
}
fn successes() -> u16 {
    2
}
fn recovery() -> u64 {
    5000
}
fn max_age() -> u64 {
    20000
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

struct Sample {
    status: Status,
    checked: Option<Instant>,
    checked_at_ms: Option<i64>,
    recovery_since: Option<Instant>,
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
                checked: None,
                checked_at_ms: None,
                recovery_since: None,
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
                    if s.status == Status::Unknown {
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
