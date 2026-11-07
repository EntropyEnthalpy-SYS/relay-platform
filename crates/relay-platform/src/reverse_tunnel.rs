//! Reverse tunnels managed from the panel (反向隧道 / NAT 穿透).
//!
//! A public server accepts clients on a public port; a private server that
//! cannot accept inbound connections keeps an outbound tunnel to the public
//! server and connects each client to a target it can reach. The public end
//! is an ordinary rule on the public server (`rt-…`), so metering, source
//! ACLs, limits and the usage pages are the rule's own; its one target
//! carries [`Rule::reverse_tunnel`], which makes the engine open a path
//! through the tunnel instead of dialing. The tunnel itself is the mux
//! protocol of [`crate::reverse_mux::managed`].
use crate::model::{Protocol, Rule, Target, canonical_ip, validate_target};
use crate::store::reject;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};

/// The tunnel port when none is given, shared by every tunnel on a server.
pub const DEFAULT_TUNNEL_PORT: u16 = 29123;
/// Rule ids of tunnels' public ends start with this.
pub const RULE_PREFIX: &str = "rt-";
/// Most tunnels one agent reports.
pub const MAX_REPORTED: usize = 1024;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TunnelProtocol {
    Tcp,
    Udp,
    TcpUdp,
}
impl TunnelProtocol {
    pub fn tcp(self) -> bool {
        matches!(self, Self::Tcp | Self::TcpUdp)
    }
    pub fn udp(self) -> bool {
        matches!(self, Self::Udp | Self::TcpUdp)
    }
    pub fn rule(self) -> Protocol {
        match self {
            Self::Tcp => Protocol::Tcp,
            Self::Udp => Protocol::Udp,
            Self::TcpUdp => Protocol::Both,
        }
    }
}

/// A tunnel as stored in metadata `reverse_tunnel:<id>`. Its token is kept
/// apart, in `reverse_tunnel_token:<id>`, and never leaves the controller
/// except to the tunnel's two agents.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ReverseTunnel {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub public_node_id: String,
    pub private_node_id: String,
    pub public_port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_ip: Option<IpAddr>,
    pub protocol: TunnelProtocol,
    /// `host:port` as the private server sees it.
    pub target: String,
    /// Where the public server listens for tunnel connections.
    pub tunnel_port: u16,
    pub enabled: bool,
    /// The account that owns the public end's rule and its traffic.
    pub owner_id: String,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}

/// Create and edit input.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TunnelInput {
    pub name: String,
    pub public_node_id: String,
    pub private_node_id: String,
    pub public_port: u16,
    #[serde(default)]
    pub listen_ip: Option<IpAddr>,
    pub protocol: TunnelProtocol,
    pub target: String,
    #[serde(default)]
    pub tunnel_port: Option<u16>,
    #[serde(default)]
    pub enabled: Option<bool>,
}
impl TunnelInput {
    /// Checks what needs no database: 400 on failure.
    pub fn validate(&self) -> Result<()> {
        if self.name.trim().is_empty() || self.name.len() > 120 {
            return reject(400, "tunnel name must contain 1..120 bytes");
        }
        if self.public_node_id == self.private_node_id {
            return reject(
                400,
                "the public and the private server must be different servers",
            );
        }
        let tunnel_port = self.tunnel_port.unwrap_or(DEFAULT_TUNNEL_PORT);
        if self.public_port == 0 || tunnel_port == 0 {
            return reject(400, "ports must be 1..65535");
        }
        if self.public_port == tunnel_port {
            return reject(
                400,
                "the public port is for users and the tunnel port for the private server; they must differ",
            );
        }
        if validate_target(&self.target).is_err() {
            return reject(
                400,
                "the target must be host:port, for example 127.0.0.1:8080 or 192.168.10.20:8080",
            );
        }
        if let Some(ip) = self.listen_ip
            && (ip.is_multicast() || canonical_ip(ip) != ip)
        {
            return reject(
                400,
                "the listen IP must be a unicast address of the public server",
            );
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum State {
    /// Not sent yet, or sent and the private server has not connected.
    Waiting,
    Connected,
    Error,
    Disabled,
}

#[derive(Clone, Debug, Serialize)]
pub struct TunnelView {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub public_node_id: String,
    pub private_node_id: String,
    pub public_port: u16,
    pub listen_ip: Option<IpAddr>,
    pub protocol: TunnelProtocol,
    pub target: String,
    pub tunnel_port: u16,
    pub enabled: bool,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub public_node_name: Option<String>,
    pub private_node_name: Option<String>,
    /// The server was deleted.
    pub public_missing: bool,
    pub private_missing: bool,
    pub state: State,
    /// Why the tunnel is waiting or failed.
    pub reason: Option<String>,
    /// While connected: when the tunnel connection was established
    /// (controller clock) and how long ago that was.
    pub connected_since_ms: Option<i64>,
    pub connected_for_secs: Option<u64>,
    /// Address users connect to, when the public server's address is known.
    pub entry: Option<String>,
    /// The public end's rule on the public server, once it exists.
    pub rule_id: Option<String>,
    /// Traffic of the public end's current meter period.
    pub upload_bytes: u64,
    pub download_bytes: u64,
}

/// What one agent should run, sent with every sync. Unknown fields are
/// ignored so later controllers can add some without breaking older agents.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Desired {
    /// This server is the public end of a tunnel: make the tunnel key.
    pub key: bool,
    /// Public end: tunnel listeners and the tunnels each admits.
    pub listeners: Vec<Listener>,
    /// Private end: tunnels to keep.
    pub dials: Vec<Dial>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Listener {
    pub listen: SocketAddr,
    pub tunnels: Vec<Admitted>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Admitted {
    pub id: String,
    pub token: String,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Dial {
    pub id: String,
    /// `host:port` of the public server's tunnel listener.
    pub server: String,
    /// SHA-256 of the public server's tunnel certificate, pinned.
    pub fingerprint: String,
    pub token: String,
    pub target: String,
    pub protocol: TunnelProtocol,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Role {
    Public,
    Private,
}
/// What the agent reports. Sent only to a controller that sent a
/// [`Desired`], as older controllers reject unknown statistics; controllers
/// ignore unknown fields inside it.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Report {
    /// Capability: the agent serves and dials panel-managed tunnels.
    pub managed: bool,
    /// SHA-256 of the agent's tunnel certificate, once it made its key.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub fingerprint: Option<String>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub tunnels: Vec<TunnelReport>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TunnelReport {
    pub id: String,
    pub role: Role,
    /// Seconds since the tunnel was attached on its current connection.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub connected_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
impl Report {
    pub fn within_limits(&self) -> bool {
        self.fingerprint.as_ref().is_none_or(|f| f.len() <= 64)
            && self.tunnels.len() <= MAX_REPORTED
            && self
                .tunnels
                .iter()
                .all(|t| t.id.len() <= 80 && t.error.as_ref().is_none_or(|e| e.len() <= 512))
    }
}

/// Rule fields the rule editor may change on a tunnel's public end; every
/// other field comes from the tunnel.
const EDITABLE: [&str; 11] = [
    "allow_sources",
    "deny_sources",
    "rate_bytes_per_sec",
    "rate_limits",
    "max_connections",
    "udp_max_sessions",
    "quota_bytes",
    "expires_at_ms",
    "idle_timeout_secs",
    "connect_timeout_ms",
    "budget_ids",
];

/// The public end of `tunnel` on its public server. `base` is the rule as
/// it is now (or as an edit sent it): its id, meter period and the
/// editable fields stay; a new public port starts a new meter period.
/// Without a base the rule is new. `default_ip` is the listen IP when the
/// tunnel names none.
pub fn render(tunnel: &ReverseTunnel, base: Option<&Rule>, default_ip: IpAddr) -> Rule {
    let mut value = serde_json::json!({
        "id": format!("{RULE_PREFIX}{}", uuid::Uuid::new_v4()),
        "tenant_id": tunnel.tenant_id,
        "owner_id": tunnel.owner_id,
        "name": tunnel.name,
        "listen": SocketAddr::new(tunnel.listen_ip.unwrap_or(default_ip), tunnel.public_port),
        "protocol": tunnel.protocol.rule(),
        "targets": [Target {
            address: tunnel.target.clone(),
            via: None,
            weight: 1,
            priority: 0,
            max_sessions: None,
            tls: None,
            proxy_protocol: None,
            websocket: None,
            prewarm: None,
            draining: false,
            paused: false,
            paused_until_ms: None,
        }],
        "reverse_tunnel": tunnel.id,
        "enabled": tunnel.enabled,
        "quota_bytes": null,
        "expires_at_ms": null,
        "rate_bytes_per_sec": null,
        "meter_epoch": uuid::Uuid::new_v4().to_string(),
    });
    if let Some(base) = base {
        let previous = serde_json::to_value(base).unwrap_or_default();
        value["id"] = base.id.clone().into();
        if base.listen.port() == tunnel.public_port {
            value["meter_epoch"] = base.meter_epoch.clone().into();
        }
        for key in EDITABLE {
            if let Some(field) = previous.get(key) {
                value[key] = field.clone();
            }
        }
    }
    serde_json::from_value(value).expect("a rendered tunnel rule is a valid rule")
}

/// The fields of a tunnel's public end that only the tunnel decides, so an
/// edit of the rule can be compared with the tunnel. The listen IP follows
/// the server's forwarding settings when the tunnel names none, so only
/// the port counts.
pub fn owned(rule: &Rule) -> serde_json::Value {
    let mut value = serde_json::to_value(rule).unwrap_or_default();
    if let Some(object) = value.as_object_mut() {
        for key in EDITABLE
            .iter()
            .chain(&["id", "meter_epoch", "owner_id", "tenant_id", "listen"])
        {
            object.remove(*key);
        }
        object.insert("listen_port".into(), rule.listen.port().into());
    }
    value
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tunnel() -> ReverseTunnel {
        ReverseTunnel {
            id: "t1".into(),
            tenant_id: "default".into(),
            name: "Home web".into(),
            public_node_id: "pub".into(),
            private_node_id: "priv".into(),
            public_port: 18080,
            listen_ip: None,
            protocol: TunnelProtocol::TcpUdp,
            target: "127.0.0.1:8080".into(),
            tunnel_port: DEFAULT_TUNNEL_PORT,
            enabled: true,
            owner_id: "admin".into(),
            created_at_ms: 1,
            updated_at_ms: 1,
        }
    }

    #[test]
    fn a_rendered_rule_keeps_its_identity_and_editable_fields() {
        let fresh = render(&tunnel(), None, "0.0.0.0".parse().unwrap());
        fresh.validate().unwrap();
        assert!(fresh.id.starts_with(RULE_PREFIX));
        assert_eq!(fresh.reverse_tunnel.as_deref(), Some("t1"));
        assert_eq!(fresh.protocol, Protocol::Both);
        assert_eq!(fresh.listen, "0.0.0.0:18080".parse().unwrap());
        let mut edited = fresh.clone();
        edited.rate_bytes_per_sec = Some(1_000_000);
        edited.allow_sources = vec!["203.0.113.0/24".parse().unwrap()];
        edited.max_connections = 7;
        let mut changed = tunnel();
        changed.target = "192.168.10.20:8080".into();
        let again = render(&changed, Some(&edited), "0.0.0.0".parse().unwrap());
        assert_eq!(
            (again.id.as_str(), again.meter_epoch.as_str()),
            (fresh.id.as_str(), fresh.meter_epoch.as_str())
        );
        assert_eq!(again.rate_bytes_per_sec, Some(1_000_000));
        assert_eq!(again.max_connections, 7);
        assert_eq!(again.targets[0].address, "192.168.10.20:8080");
        assert_ne!(owned(&again), owned(&edited), "the target is the tunnel's");
        changed.public_port = 18081;
        let moved = render(&changed, Some(&again), "0.0.0.0".parse().unwrap());
        assert_eq!(moved.id, fresh.id);
        assert_ne!(
            moved.meter_epoch, fresh.meter_epoch,
            "a new port, a new period"
        );
        // A rule edit that changes only editable fields owns nothing new.
        let mut limited = moved.clone();
        limited.deny_sources = vec!["198.51.100.7/32".parse().unwrap()];
        assert_eq!(owned(&limited), owned(&moved));
        limited.enabled = false;
        assert_ne!(owned(&limited), owned(&moved));
    }

    #[test]
    fn input_is_checked_before_the_database() {
        let input = |public: &str, port: u16, tunnel_port: Option<u16>, target: &str| TunnelInput {
            name: "x".into(),
            public_node_id: public.into(),
            private_node_id: "b".into(),
            public_port: port,
            listen_ip: None,
            protocol: TunnelProtocol::Tcp,
            target: target.into(),
            tunnel_port,
            enabled: None,
        };
        assert!(input("a", 18080, None, "127.0.0.1:8080").validate().is_ok());
        for bad in [
            input("b", 18080, None, "127.0.0.1:8080"),
            input("a", 29123, None, "127.0.0.1:8080"),
            input("a", 18080, Some(18080), "127.0.0.1:8080"),
            input("a", 0, None, "127.0.0.1:8080"),
            input("a", 18080, None, "127.0.0.1"),
            input("a", 18080, None, "http://example.com:80"),
        ] {
            let error = bad.validate().unwrap_err();
            assert_eq!(
                error
                    .downcast_ref::<crate::store::Rejection>()
                    .unwrap()
                    .status,
                400
            );
        }
    }
}
