use anyhow::{Result, bail, ensure};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{
    collections::HashSet,
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

pub const API_VERSION: u32 = 1;
pub const MAX_RULES: usize = 512;
pub const MAX_COUNTER: u64 = i64::MAX as u64;

pub fn now_ms() -> i64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap_or_default()
        .as_millis() as i64
}

pub fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 80
        && value
            .bytes()
            .all(|c| c.is_ascii_alphanumeric() || b"_-".contains(&c))
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Protocol {
    Tcp,
    Udp,
    Both,
}

impl Protocol {
    pub fn tcp(self) -> bool {
        matches!(self, Self::Tcp | Self::Both)
    }
    pub fn udp(self) -> bool {
        matches!(self, Self::Udp | Self::Both)
    }
}

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Balance {
    #[default]
    WeightedRoundRobin,
    SourceHash,
    LeastConnections,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Target {
    /// Socket address or DNS name:port. IPv6 literals require brackets.
    pub address: String,
    #[serde(default = "one")]
    pub weight: u16,
}
fn one() -> u16 {
    1
}
fn connect_timeout() -> u64 {
    5_000
}
fn idle_timeout() -> u64 {
    120
}
fn max_connections() -> u32 {
    4_096
}
fn udp_sessions() -> u32 {
    1_024
}
fn enabled() -> bool {
    true
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub id: String,
    pub tenant_id: String,
    pub owner_id: String,
    pub name: String,
    pub listen: SocketAddr,
    pub protocol: Protocol,
    pub targets: Vec<Target>,
    #[serde(default)]
    pub balance: Balance,
    #[serde(default = "enabled")]
    pub enabled: bool,
    #[serde(default = "connect_timeout")]
    pub connect_timeout_ms: u64,
    #[serde(default = "idle_timeout")]
    pub idle_timeout_secs: u64,
    #[serde(default = "max_connections")]
    pub max_connections: u32,
    #[serde(default = "udp_sessions")]
    pub udp_max_sessions: u32,
    /// Combined admitted application payload bytes, upload + download.
    pub quota_bytes: Option<u64>,
    /// Unix milliseconds. Enforcement is local to the agent.
    pub expires_at_ms: Option<i64>,
    /// Combined application bytes/second, shared by every session in this rule.
    pub rate_bytes_per_sec: Option<u64>,
    /// A new explicit billing period gets a new identifier. Never inferred from wall time.
    pub meter_epoch: String,
    #[serde(default)]
    pub allow_sources: Vec<IpNet>,
    #[serde(default)]
    pub deny_sources: Vec<IpNet>,
}

impl Rule {
    pub fn validate(&self) -> Result<()> {
        for (name, value) in [
            ("id", &self.id),
            ("tenant_id", &self.tenant_id),
            ("owner_id", &self.owner_id),
            ("meter_epoch", &self.meter_epoch),
        ] {
            ensure!(identifier(value), "invalid {name}");
        }
        ensure!(
            !self.name.trim().is_empty() && self.name.len() <= 120,
            "name must contain 1..120 bytes"
        );
        ensure!(
            self.listen.port() != 0,
            "listen port 0 is not a stable configuration"
        );
        ensure!(
            !self.listen.ip().is_multicast(),
            "multicast listeners are unsupported"
        );
        ensure!(
            !self.targets.is_empty() && self.targets.len() <= 32,
            "requires 1..32 targets"
        );
        let mut targets = HashSet::new();
        for target in &self.targets {
            validate_target(&target.address)?;
            ensure!(
                target.weight > 0 && target.weight <= 1000,
                "target weight must be 1..1000"
            );
            ensure!(targets.insert(&target.address), "duplicate target");
            ensure!(
                target.address != self.listen.to_string(),
                "direct forwarding loop"
            );
        }
        ensure!(
            (100..=60_000).contains(&self.connect_timeout_ms),
            "connect timeout must be 100..60000 ms"
        );
        ensure!(
            (1..=86_400).contains(&self.idle_timeout_secs),
            "idle timeout must be 1..86400 seconds"
        );
        ensure!(
            (1..=1_000_000).contains(&self.max_connections),
            "invalid connection limit"
        );
        ensure!(
            (1..=100_000).contains(&self.udp_max_sessions),
            "invalid UDP session limit"
        );
        ensure!(
            self.quota_bytes.is_none_or(|q| q <= MAX_COUNTER),
            "quota exceeds database range"
        );
        ensure!(
            self.rate_bytes_per_sec
                .is_none_or(|q| (1..=1_000_000_000_000).contains(&q)),
            "invalid byte rate"
        );
        ensure!(
            self.allow_sources.len() <= 256 && self.deny_sources.len() <= 256,
            "too many source networks"
        );
        Ok(())
    }

    pub fn permits(&self, ip: std::net::IpAddr) -> bool {
        let ip = match ip {
            std::net::IpAddr::V6(v) => v.to_ipv4_mapped().map(std::net::IpAddr::V4).unwrap_or(ip),
            _ => ip,
        };
        !self.deny_sources.iter().any(|n| n.contains(&ip))
            && (self.allow_sources.is_empty() || self.allow_sources.iter().any(|n| n.contains(&ip)))
    }
}

pub fn validate_target(address: &str) -> Result<()> {
    ensure!(
        address.len() <= 300 && !address.contains(['/', '\\', '@', ' ', '\n', '\r']),
        "invalid target address"
    );
    if let Ok(addr) = address.parse::<SocketAddr>() {
        ensure!(
            addr.port() != 0 && !addr.ip().is_unspecified() && !addr.ip().is_multicast(),
            "invalid target IP/port"
        );
        return Ok(());
    }
    let Some((host, port)) = address.rsplit_once(':') else {
        bail!("target requires host:port");
    };
    ensure!(
        port.parse::<u16>().is_ok_and(|p| p != 0),
        "invalid target port"
    );
    ensure!(!host.is_empty() && host.len() <= 253, "invalid target host");
    for label in host.trim_end_matches('.').split('.') {
        ensure!(
            !label.is_empty()
                && label.len() <= 63
                && !label.starts_with('-')
                && !label.ends_with('-')
                && label
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b == b'-'),
            "invalid DNS target; use bracketed IPv6 literals"
        );
    }
    Ok(())
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeConfig {
    pub api_version: u32,
    pub node_id: String,
    pub revision: u64,
    pub rules: Vec<Rule>,
}

impl NodeConfig {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            self.api_version == API_VERSION,
            "unsupported config schema version"
        );
        ensure!(identifier(&self.node_id), "invalid node_id");
        ensure!(self.revision <= MAX_COUNTER, "revision out of range");
        ensure!(self.rules.len() <= MAX_RULES, "too many rules");
        let mut ids = HashSet::new();
        let mut listeners = HashSet::new();
        for rule in &self.rules {
            rule.validate()?;
            ensure!(ids.insert(&rule.id), "duplicate rule id");
            if rule.enabled {
                for protocol in [true, false] {
                    if (protocol && rule.protocol.tcp()) || (!protocol && rule.protocol.udp()) {
                        ensure!(
                            listeners.insert((rule.listen, protocol)),
                            "duplicate listener"
                        );
                    }
                }
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Usage {
    pub rule_id: String,
    pub meter_epoch: String,
    pub sequence: u64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct UsageAck {
    pub rule_id: String,
    pub meter_epoch: String,
    pub sequence: u64,
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EngineStats {
    pub active_tcp: u64,
    pub active_udp: u64,
    pub accepted_tcp: u64,
    pub rejected_connections: u64,
    pub failed_connections: u64,
    pub dropped_datagrams: u64,
    pub forwarded_upload_bytes: u64,
    pub forwarded_download_bytes: u64,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SyncRequest {
    #[serde(default)]
    pub need_config: bool,
    pub applied_revision: u64,
    pub apply_error: Option<String>,
    pub usage: Vec<Usage>,
    pub stats: EngineStats,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct SyncResponse {
    pub config: Option<NodeConfig>,
    pub acknowledgements: Vec<UsageAck>,
    pub server_time_ms: i64,
}
