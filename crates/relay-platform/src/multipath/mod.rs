//! The independently specified relay-multipath-v1 stream transport.
//! It requires authenticated outer streams. It is not kernel MPTCP.
mod driver;
mod handshake;
#[cfg(test)]
mod tests;
mod wire;

use crate::model::{OutboundBind, PortMapping, Protocol, Rule};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::sync::atomic::{AtomicU64, Ordering};

pub(crate) use driver::{Path, bridge};
pub(crate) use handshake::{Client, Server};
pub const CHUNK_BYTES: usize = 16 * 1024;
pub const MAX_PATHS: usize = 8;
pub const APP_BUFFER_BYTES: usize = 64 * 1024;

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Mode {
    #[default]
    Stripe,
    Replicate,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Limits {
    #[serde(default = "window")]
    pub window_frames: u16,
    #[serde(default = "sessions")]
    pub max_sessions: u16,
    #[serde(default = "retransmit")]
    pub retransmit_ms: u64,
    #[serde(default = "stall")]
    pub stall_timeout_ms: u64,
}
fn window() -> u16 {
    64
}
fn sessions() -> u16 {
    64
}
fn retransmit() -> u64 {
    500
}
fn stall() -> u64 {
    30_000
}
impl Default for Limits {
    fn default() -> Self {
        Self {
            window_frames: window(),
            max_sessions: sessions(),
            retransmit_ms: retransmit(),
            stall_timeout_ms: stall(),
        }
    }
}
impl Limits {
    pub fn payload_bound(&self) -> u64 {
        2 * u64::from(self.max_sessions) * u64::from(self.window_frames) * CHUNK_BYTES as u64
    }
    fn validate(&self) -> Result<()> {
        ensure!(
            (4..=256).contains(&self.window_frames),
            "multipath window must be 4..256 frames"
        );
        ensure!(
            (1..=1024).contains(&self.max_sessions),
            "multipath sessions must be 1..1024"
        );
        ensure!(
            (50..=10_000).contains(&self.retransmit_ms),
            "multipath retransmission must be 50..10000 ms"
        );
        ensure!(
            (1000..=120_000).contains(&self.stall_timeout_ms)
                && self.stall_timeout_ms >= 4 * self.retransmit_ms,
            "multipath stall timeout must be 1000..120000 ms and at least four retransmission intervals"
        );
        ensure!(
            self.payload_bound() <= 256 * 1024 * 1024,
            "multipath reserved send/reorder windows exceed 256 MiB per side of a rule"
        );
        Ok(())
    }
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default)]
    pub limits: Limits,
    #[serde(default = "paths")]
    pub max_paths: u8,
    #[serde(default)]
    pub allow_replication: bool,
}
fn paths() -> u8 {
    4
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PathConfig {
    pub upload_weight: u16,
    pub download_weight: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub outbound_bind: Option<OutboundBind>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ClientConfig {
    #[serde(default)]
    pub limits: Limits,
    #[serde(default)]
    pub mode: Mode,
    /// Initial setup requirement. A running session may continue with fewer paths.
    pub min_paths: u8,
    /// Positional mapping to Rule.targets, never a list of sequential hops.
    pub paths: Vec<PathConfig>,
}

pub(crate) fn validate_rule(rule: &Rule) -> Result<()> {
    if rule.inbound_multipath.is_none() && rule.outbound_multipath.is_none() {
        return Ok(());
    }
    ensure!(
        rule.protocol == Protocol::Tcp,
        "multipath supports TCP streams only"
    );
    ensure!(
        rule.port_mapping == PortMapping::Fixed,
        "multipath requires fixed port mapping"
    );
    if let Some(server) = &rule.inbound_multipath {
        server.limits.validate()?;
        ensure!(
            (1..=MAX_PATHS as u8).contains(&server.max_paths),
            "multipath max_paths must be 1..8"
        );
        ensure!(
            rule.inbound_tls
                .as_ref()
                .is_some_and(|tls| tls.client_ca.is_some()),
            "multipath input requires mutually authenticated TLS"
        );
    }
    if let Some(client) = &rule.outbound_multipath {
        client.limits.validate()?;
        ensure!(
            !client.paths.is_empty()
                && client.paths.len() <= MAX_PATHS
                && client.paths.len() == rule.targets.len(),
            "multipath requires one path policy per target, at most eight"
        );
        ensure!(
            client.min_paths > 0 && usize::from(client.min_paths) <= client.paths.len(),
            "multipath min_paths must fit the configured paths"
        );
        ensure!(
            client.paths.iter().any(|p| p.upload_weight > 0)
                && client.paths.iter().any(|p| p.download_weight > 0),
            "multipath requires at least one path in each direction"
        );
        for path in &client.paths {
            ensure!(
                path.upload_weight <= 1000
                    && path.download_weight <= 1000
                    && (path.upload_weight > 0 || path.download_weight > 0),
                "multipath path weights must be 0..1000 with at least one enabled direction"
            );
            if let Some(bind) = &path.outbound_bind {
                crate::model::validate_bind(bind)?;
            }
        }
        let first = rule.targets[0].tls.as_ref();
        ensure!(
            first.is_some_and(|tls| tls.identity.is_some()),
            "multipath output requires a TLS client identity"
        );
        ensure!(
            rule.targets.iter().all(|t| t.tls.as_ref() == first),
            "all multipath paths require the same TLS identity, trust and server name"
        );
        ensure!(
            rule.targets.iter().all(|t| t.priority == 0),
            "multipath uses directional path weights; target standby priority is unsupported"
        );
        if let Some(reference) = rule.targets.iter().find_map(|t| t.via.as_ref()) {
            ensure!(
                rule.targets
                    .iter()
                    .all(|t| t.via.as_ref() == Some(reference)),
                "all declared multipath paths must reference the same aggregation rule"
            );
        }
    }
    Ok(())
}

#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Stats {
    pub active_sessions: u64,
    pub active_paths: u64,
    pub sessions: u64,
    pub failed_paths: u64,
    pub sent_payload_bytes: u64,
    pub replicated_payload_bytes: u64,
    pub retransmitted_payload_bytes: u64,
    pub received_payload_bytes: u64,
    pub duplicate_payload_bytes: u64,
    pub delivered_payload_bytes: u64,
    pub framing_sent_bytes: u64,
    /// Max for any single session, not a process-wide allocation measurement.
    pub peak_reorder_bytes: u64,
    pub peak_send_window_bytes: u64,
    /// Physical payload by positional path slot, summed over this process.
    pub path_sent_payload_bytes: [u64; MAX_PATHS],
}
#[derive(Default)]
pub(crate) struct Counters {
    active_sessions: AtomicU64,
    active_paths: AtomicU64,
    sessions: AtomicU64,
    failed_paths: AtomicU64,
    sent_payload_bytes: AtomicU64,
    replicated_payload_bytes: AtomicU64,
    retransmitted_payload_bytes: AtomicU64,
    received_payload_bytes: AtomicU64,
    duplicate_payload_bytes: AtomicU64,
    delivered_payload_bytes: AtomicU64,
    framing_sent_bytes: AtomicU64,
    peak_reorder_bytes: AtomicU64,
    peak_send_window_bytes: AtomicU64,
    path_sent_payload_bytes: [AtomicU64; MAX_PATHS],
}
impl Counters {
    pub(crate) fn snapshot(&self) -> Stats {
        macro_rules! get {
            ($field:ident) => {
                self.$field.load(Ordering::Relaxed)
            };
        }
        Stats {
            active_sessions: get!(active_sessions),
            active_paths: get!(active_paths),
            sessions: get!(sessions),
            failed_paths: get!(failed_paths),
            sent_payload_bytes: get!(sent_payload_bytes),
            replicated_payload_bytes: get!(replicated_payload_bytes),
            retransmitted_payload_bytes: get!(retransmitted_payload_bytes),
            received_payload_bytes: get!(received_payload_bytes),
            duplicate_payload_bytes: get!(duplicate_payload_bytes),
            delivered_payload_bytes: get!(delivered_payload_bytes),
            framing_sent_bytes: get!(framing_sent_bytes),
            peak_reorder_bytes: get!(peak_reorder_bytes),
            peak_send_window_bytes: get!(peak_send_window_bytes),
            path_sent_payload_bytes: std::array::from_fn(|i| {
                self.path_sent_payload_bytes[i].load(Ordering::Relaxed)
            }),
        }
    }
}
