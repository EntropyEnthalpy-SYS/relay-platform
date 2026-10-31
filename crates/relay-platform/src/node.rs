//! Operator-owned node inventory and lifecycle settings, separate from routing.
use crate::store::reject;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};

/// Operator-confirmed defaults for new rules, never a rewrite of existing routes.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct ForwardingDefaults {
    pub host: String,
    pub listen_ip: Option<IpAddr>,
    pub port_start: u16,
    pub port_end: u16,
    /// A contiguous provider NAT mapping; omitted means identical public ports.
    pub public_port_start: Option<u16>,
}
impl Default for ForwardingDefaults {
    fn default() -> Self {
        Self {
            host: String::new(),
            listen_ip: None,
            port_start: 20000,
            port_end: 29999,
            public_port_start: None,
        }
    }
}
impl ForwardingDefaults {
    pub fn canonical_host(&self) -> String {
        let host = self.host.trim_start_matches('[').trim_end_matches(']');
        host.parse::<IpAddr>().map_or_else(
            |_| host.trim_end_matches('.').to_ascii_lowercase(),
            |ip| crate::model::canonical_ip(ip).to_string(),
        )
    }
    pub fn endpoint(&self, port: u16) -> String {
        let host = self.canonical_host();
        if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        }
    }
    pub fn bind_ip(&self) -> IpAddr {
        self.listen_ip
            .unwrap_or_else(|| match self.canonical_host().parse::<IpAddr>() {
                Ok(ip) if ip.is_loopback() => ip,
                Ok(IpAddr::V6(_)) => IpAddr::V6(Ipv6Addr::UNSPECIFIED),
                _ if self.canonical_host() == "localhost" => IpAddr::V4(Ipv4Addr::LOCALHOST),
                _ => IpAddr::V4(Ipv4Addr::UNSPECIFIED),
            })
    }
    pub fn public_port(&self, port: u16) -> u16 {
        self.public_port_start.unwrap_or(self.port_start) + (port - self.port_start)
    }
    pub fn validate(&self) -> Result<()> {
        if self.host.is_empty()
            || self.host != self.host.trim()
            || (self.host.contains(['[', ']'])
                && !(self.host.starts_with('[')
                    && self.host.ends_with(']')
                    && self.host[1..self.host.len() - 1]
                        .parse::<Ipv6Addr>()
                        .is_ok()))
            || crate::model::validate_target(&self.endpoint(1)).is_err()
            || self.canonical_host().parse::<IpAddr>().is_ok_and(|ip| {
                ip.is_unspecified() || ip.is_multicast() || ip == Ipv4Addr::BROADCAST
            })
            || self.listen_ip.is_some_and(|ip| {
                let ip = crate::model::canonical_ip(ip);
                ip.is_multicast() || ip == Ipv4Addr::BROADCAST
            })
        {
            return reject(
                400,
                "forwarding address requires a reachable IP or hostname without a port, URL or credentials",
            );
        }
        if self.port_start < 1024
            || self.port_end < self.port_start
            || self.public_port_start == Some(0)
            || u32::from(self.public_port_start.unwrap_or(self.port_start))
                + u32::from(self.port_end - self.port_start)
                > u32::from(u16::MAX)
        {
            return reject(400, "invalid forwarding port range or public NAT mapping");
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointHop {
    pub node_id: String,
    #[serde(default)]
    pub listen: Option<SocketAddr>,
    #[serde(default)]
    pub advertise: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct EndpointRequest {
    pub hops: Vec<EndpointHop>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct AllocatedEndpoint {
    pub node_id: String,
    pub listen: Option<SocketAddr>,
    pub advertise: Option<String>,
    pub source: String,
    pub defaults: Option<ForwardingDefaults>,
    pub error: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EndpointAllocation {
    pub endpoints: Vec<AllocatedEndpoint>,
    /// The exact configurations used for allocation; publish with these revisions.
    pub configs: Vec<crate::model::NodeConfig>,
}

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Ingress,
    Relay,
    Egress,
    Ix,
    Nat,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CostPeriod {
    Monthly,
    Yearly,
    OneTime,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NodeCost {
    pub currency: String,
    /// Millionths of the named currency unit; never a binary floating amount.
    pub amount_micros: u64,
    pub period: CostPeriod,
}
/// Where the operator says a node is. Only the panel map reads it; routing never does.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NodeLocation {
    pub name: String,
    /// Millionths of a degree, so saved profiles compare exactly.
    pub latitude_micros: i32,
    pub longitude_micros: i32,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct NodeSettings {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub forwarding: Option<ForwardingDefaults>,
    /// Omitted when unset so profiles without a location stay readable by 0.127.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub location: Option<NodeLocation>,
    pub kinds: Vec<NodeKind>,
    pub group: Option<String>,
    pub tags: Vec<String>,
    pub notes: String,
    pub cost: Option<NodeCost>,
    pub enabled: bool,
    pub expires_at_ms: Option<i64>,
}
impl Default for NodeSettings {
    fn default() -> Self {
        Self {
            forwarding: None,
            location: None,
            kinds: vec![],
            group: None,
            tags: vec![],
            notes: String::new(),
            cost: None,
            enabled: true,
            expires_at_ms: None,
        }
    }
}
fn label(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty()
        && value == value.trim()
        && value.len() <= maximum
        && !value.chars().any(char::is_control)
}
pub fn validate_name(name: &str) -> Result<()> {
    if !label(name, 120) {
        return reject(
            400,
            "node name must contain 1..120 bytes without surrounding whitespace or control characters",
        );
    }
    Ok(())
}
impl NodeSettings {
    pub fn validate(&self) -> Result<()> {
        if let Some(forwarding) = &self.forwarding {
            forwarding.validate()?;
        }
        if self.kinds.len() > 5
            || self
                .kinds
                .iter()
                .enumerate()
                .any(|(i, kind)| self.kinds[..i].contains(kind))
            || self.group.as_ref().is_some_and(|group| !label(group, 64))
            || self.tags.len() > 32
            || self.tags.iter().any(|tag| !label(tag, 64))
            || self.tags.iter().collect::<HashSet<_>>().len() != self.tags.len()
            || self.notes.len() > 4096
            || self
                .notes
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
        {
            return reject(400, "invalid node kinds, group, tags or notes");
        }
        if self.location.as_ref().is_some_and(|location| {
            !label(&location.name, 64)
                || !(-90_000_000..=90_000_000).contains(&location.latitude_micros)
                || !(-180_000_000..=180_000_000).contains(&location.longitude_micros)
        }) {
            return reject(
                400,
                "location requires a 1..64 byte name, latitude within 90 degrees and longitude within 180 degrees",
            );
        }
        if self.cost.as_ref().is_some_and(|cost| {
            cost.currency.len() != 3
                || !cost.currency.bytes().all(|b| b.is_ascii_uppercase())
                || cost.amount_micros > 9_000_000_000_000_000
        }) {
            return reject(
                400,
                "cost requires a three-uppercase-letter currency and at most 9000000000000000 millionths",
            );
        }
        if self
            .expires_at_ms
            .is_some_and(|time| !(1..=253_402_300_799_999).contains(&time))
        {
            return reject(400, "node expiry timestamp must be within years 1970..9999");
        }
        Ok(())
    }
    pub fn lifecycle(&self, now_ms: i64) -> NodeLifecycle {
        if !self.enabled {
            NodeLifecycle::Disabled
        } else if self.expires_at_ms.is_some_and(|expiry| expiry <= now_ms) {
            NodeLifecycle::Expired
        } else {
            NodeLifecycle::Active
        }
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NodeProfile {
    pub revision: u64,
    pub updated_at_ms: Option<i64>,
    pub settings: NodeSettings,
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeLifecycle {
    #[default]
    Active,
    Disabled,
    Expired,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeUpdate {
    pub expected_revision: u64,
    pub name: String,
    pub settings: NodeSettings,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeBatchEntry {
    pub node_id: String,
    pub update: NodeUpdate,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeUpdateResult {
    pub node_id: String,
    pub name: String,
    pub profile: NodeProfile,
    pub lifecycle: NodeLifecycle,
}
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeFilter {
    pub q: Option<String>,
    pub kind: Option<NodeKind>,
    pub group: Option<String>,
    pub tag: Option<String>,
    pub lifecycle: Option<NodeLifecycle>,
}
impl NodeFilter {
    pub fn validate(&self) -> Result<()> {
        if self.q.as_ref().is_some_and(|q| !label(q, 120))
            || self.group.as_ref().is_some_and(|group| !label(group, 64))
            || self.tag.as_ref().is_some_and(|tag| !label(tag, 64))
        {
            return reject(400, "invalid node filter");
        }
        Ok(())
    }
    pub fn matches(&self, node: &crate::store::Node) -> bool {
        let settings = &node.profile.settings;
        self.kind.is_none_or(|kind| settings.kinds.contains(&kind))
            && self
                .group
                .as_ref()
                .is_none_or(|group| settings.group.as_ref() == Some(group))
            && self
                .tag
                .as_ref()
                .is_none_or(|tag| settings.tags.contains(tag))
            && self.lifecycle.is_none_or(|state| node.lifecycle == state)
            && self.q.as_ref().is_none_or(|q| {
                let q = q.to_lowercase();
                [&node.id, &node.name, &settings.notes]
                    .into_iter()
                    .chain(settings.tags.iter())
                    .chain(settings.group.iter())
                    .chain(settings.location.iter().map(|location| &location.name))
                    .any(|text| text.to_lowercase().contains(&q))
            })
    }
}
