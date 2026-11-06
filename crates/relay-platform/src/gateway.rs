//! Typed, fail-closed protocol gateways backed by one pinned sing-box process.
//! Every destination uses an authenticated loopback SOCKS bridge in this Engine.
use crate::{
    model::{NodeConfig, Protocol, Rule, identifier, validate_target},
    socks5,
};
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use serde::{Deserialize, Serialize};
use serde_json::json;
use std::{
    collections::HashMap,
    net::SocketAddr,
    path::{Path, PathBuf},
    sync::{Arc, Mutex},
    time::Duration,
};
use tokio::{
    io::AsyncReadExt,
    process::{Child, Command},
    sync::oneshot,
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

pub const ENGINE_VERSION: &str = "1.14.4";
pub const MAX_GATEWAYS: usize = 64;

#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum WireProtocol {
    Vless {
        uuid: String,
        #[serde(default)]
        vision: bool,
    },
    Hysteria2 {
        password: String,
        /// QUIC obfuscation; clients need the same type and password.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        obfs: Option<Obfuscation>,
        /// The reply to HTTP/3 requests that fail authentication. Without it
        /// the engine answers 404.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        masquerade: Option<Masquerade>,
    },
    Tuic {
        uuid: String,
        password: String,
        #[serde(default, skip_serializing_if = "CongestionControl::is_default")]
        congestion_control: CongestionControl,
        /// QUIC 0-RTT: faster reconnects, but early data can be replayed.
        #[serde(default, skip_serializing_if = "std::ops::Not::not")]
        zero_rtt_handshake: bool,
    },
    AnyTls {
        password: String,
    },
    Trojan {
        password: String,
    },
    Vmess {
        uuid: String,
    },
}
impl WireProtocol {
    pub fn kind(&self) -> &'static str {
        match self {
            Self::Vless { .. } => "vless",
            Self::Hysteria2 { .. } => "hysteria2",
            Self::Tuic { .. } => "tuic",
            Self::AnyTls { .. } => "anytls",
            Self::Trojan { .. } => "trojan",
            Self::Vmess { .. } => "vmess",
        }
    }
    pub fn uses_udp_socket(&self) -> bool {
        matches!(self, Self::Hysteria2 { .. } | Self::Tuic { .. })
    }
}
impl std::fmt::Debug for WireProtocol {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct(self.kind())
            .field("credentials", &"[REDACTED]")
            .finish()
    }
}
/// The congestion controls sing-box TUIC accepts (`cubic`, `new_reno`, `bbr`).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CongestionControl {
    Cubic,
    NewReno,
    #[default]
    Bbr,
}
impl CongestionControl {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Cubic => "cubic",
            Self::NewReno => "new_reno",
            Self::Bbr => "bbr",
        }
    }
    fn is_default(&self) -> bool {
        *self == Self::default()
    }
}
/// Hysteria2 obfuscation, written as sing-box writes it:
/// `{"type":"salamander","password":"…"}`.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Obfuscation {
    Salamander { password: String },
}
/// A built-in Hysteria2 masquerade, answered by the engine itself. The
/// engine's file and reverse-proxy masquerades are not offered: one serves
/// node files, the other dials from the engine directly, outside the metered
/// bridge and the destination ACL.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Masquerade {
    /// sing-box `{"type":"string","status_code":…,"content":…}`.
    #[serde(rename = "string")]
    Fixed {
        status_code: u16,
        #[serde(default, skip_serializing_if = "String::is_empty")]
        content: String,
    },
}
pub const MAX_SHORT_IDS: usize = 16;
pub const MAX_TIME_DIFFERENCE_SECS: u32 = 3600;
#[derive(Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "type", rename_all = "snake_case", deny_unknown_fields)]
pub enum Security {
    Certificate {
        identity: String,
        #[serde(default, skip_serializing_if = "Option::is_none")]
        server_name: Option<String>,
    },
    Reality {
        server_name: String,
        handshake: String,
        private_key: String,
        /// The short ID clients receive in exports and share links.
        short_id: String,
        /// Further short IDs the server also accepts, e.g. one per group of
        /// clients, so one can be withdrawn without changing the others.
        #[serde(default, skip_serializing_if = "Vec::is_empty")]
        extra_short_ids: Vec<String>,
        /// Reject clients whose clock differs from the node's by more than
        /// this. Unset leaves the engine's check off.
        #[serde(default, skip_serializing_if = "Option::is_none")]
        max_time_difference_secs: Option<u32>,
    },
}
impl std::fmt::Debug for Security {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Certificate {
                identity,
                server_name,
            } => f
                .debug_struct("Certificate")
                .field("identity", identity)
                .field("server_name", server_name)
                .finish(),
            Self::Reality {
                server_name,
                handshake,
                ..
            } => f
                .debug_struct("Reality")
                .field("server_name", server_name)
                .field("handshake", handshake)
                .field("credentials", &"[REDACTED]")
                .finish(),
        }
    }
}
pub fn reality_public_key(private_key: &str) -> Result<String> {
    let key: [u8; 32] = URL_SAFE_NO_PAD
        .decode(private_key)?
        .try_into()
        .map_err(|_| anyhow::anyhow!("Reality private key requires 32 bytes"))?;
    Ok(URL_SAFE_NO_PAD.encode(x25519_dalek::x25519(
        key,
        x25519_dalek::X25519_BASEPOINT_BYTES,
    )))
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub listen: SocketAddr,
    pub protocol: WireProtocol,
    pub security: Security,
    #[serde(default)]
    pub allow_private_destinations: bool,
}
impl Config {
    pub fn validate(&self, rule: &Rule) -> Result<()> {
        ensure!(
            self.listen.port() > 0 && !self.listen.ip().is_multicast(),
            "invalid gateway listener"
        );
        ensure!(
            rule.listen.ip().is_loopback() && rule.listen_end_port.is_none(),
            "gateway bridge requires one literal loopback listener"
        );
        ensure!(rule.protocol.tcp(), "gateway bridge requires TCP control");
        ensure!(
            !matches!(self.protocol, WireProtocol::AnyTls { .. }) || rule.protocol == Protocol::Tcp,
            "AnyTLS gateway currently supports TCP payloads only"
        );
        ensure!(
            rule.inbound_socks5.is_none()
                && rule.inbound_shadowsocks.is_none()
                && rule.inbound_http_connect.is_none()
                && rule.inbound_http2_connect.is_none()
                && rule.inbound_tls.is_none()
                && rule.inbound_proxy.is_none()
                && rule.inbound_websocket.is_none()
                && rule.inbound_multipath.is_none()
                && rule.outbound_multipath.is_none(),
            "gateway cannot combine other inbound transports"
        );
        ensure!(
            rule.advertise.is_none() && rule.health_check.is_none(),
            "gateway bridges cannot be advertised or probed as fixed-target relays"
        );
        ensure!(
            rule.mptcp_inbound() == crate::mptcp::Mode::Off,
            "gateway's local bridge uses ordinary TCP; MPTCP may be selected for outbound destinations"
        );
        let uuid = |value: &str| -> Result<()> {
            let parsed = uuid::Uuid::parse_str(value).context("invalid protocol UUID")?;
            ensure!(!parsed.is_nil(), "protocol UUID must not be nil");
            Ok(())
        };
        let password = |value: &str| -> Result<()> {
            ensure!(
                (16..=256).contains(&value.len()) && !value.chars().any(char::is_control),
                "protocol password requires 16..256 bytes without control characters"
            );
            Ok(())
        };
        match &self.protocol {
            WireProtocol::Vless { uuid: id, .. } | WireProtocol::Vmess { uuid: id } => uuid(id)?,
            WireProtocol::Tuic {
                uuid: id,
                password: p,
                ..
            } => {
                uuid(id)?;
                password(p)?;
            }
            WireProtocol::Hysteria2 {
                password: p,
                obfs,
                masquerade,
            } => {
                password(p)?;
                if let Some(Obfuscation::Salamander { password: key }) = obfs {
                    password(key).context("Hysteria2 obfuscation password")?;
                }
                if let Some(Masquerade::Fixed {
                    status_code,
                    content,
                }) = masquerade
                {
                    ensure!(
                        (200..=599).contains(status_code),
                        "masquerade status code must be 200..599"
                    );
                    ensure!(
                        content.len() <= 4096
                            && !content
                                .chars()
                                .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t')),
                        "masquerade content must be 0..4096 bytes without control characters other than line breaks and tabs"
                    );
                }
            }
            WireProtocol::AnyTls { password: p } | WireProtocol::Trojan { password: p } => {
                password(p)?
            }
        }
        match &self.security {
            Security::Certificate {
                identity,
                server_name,
            } => {
                ensure!(identifier(identity), "invalid gateway TLS identity");
                if let Some(name) = server_name {
                    crate::subscription::normalize_host(name)?;
                }
            }
            Security::Reality {
                server_name,
                handshake,
                private_key,
                short_id,
                extra_short_ids,
                max_time_difference_secs,
            } => {
                ensure!(
                    matches!(self.protocol, WireProtocol::Vless { .. }),
                    "Reality requires VLESS"
                );
                validate_target(handshake)?;
                validate_target(&format!("{server_name}:443"))?;
                ensure!(
                    URL_SAFE_NO_PAD.decode(private_key)?.len() == 32,
                    "Reality private key requires 32 bytes"
                );
                ensure!(
                    extra_short_ids.len() < MAX_SHORT_IDS,
                    "Reality accepts at most {MAX_SHORT_IDS} short IDs"
                );
                let mut seen = std::collections::HashSet::new();
                for id in std::iter::once(short_id).chain(extra_short_ids) {
                    ensure!(
                        !id.is_empty()
                            && id.len() <= 16
                            && id.len().is_multiple_of(2)
                            && id.bytes().all(|b| b.is_ascii_hexdigit()),
                        "Reality short ID requires 2..16 hexadecimal digits"
                    );
                    ensure!(
                        seen.insert(id.to_ascii_lowercase()),
                        "Reality short IDs must be unique"
                    );
                }
                ensure!(
                    max_time_difference_secs
                        .is_none_or(|secs| (1..=MAX_TIME_DIFFERENCE_SECS).contains(&secs)),
                    "Reality clock difference limit must be 1..={MAX_TIME_DIFFERENCE_SECS} seconds"
                );
            }
        }
        Ok(())
    }

    /// The engine inbound for this gateway, without its TLS block.
    fn engine_inbound(&self, rule: &Rule, tag: &str) -> serde_json::Value {
        let mut inbound = json!({"type":self.protocol.kind(), "tag":tag, "listen":self.listen.ip().to_string(), "listen_port":self.listen.port(), "tcp_fast_open":false});
        let user = match &self.protocol {
            WireProtocol::Vless { uuid, vision } => {
                json!({"name":rule.id,"uuid":uuid,"flow":if *vision {"xtls-rprx-vision"} else {""}})
            }
            WireProtocol::Vmess { uuid } => json!({"name":rule.id,"uuid":uuid,"alterId":0}),
            WireProtocol::Tuic { uuid, password, .. } => {
                json!({"name":rule.id,"uuid":uuid,"password":password})
            }
            WireProtocol::Hysteria2 { password, .. }
            | WireProtocol::AnyTls { password }
            | WireProtocol::Trojan { password } => json!({"name":rule.id,"password":password}),
        };
        inbound["users"] = json!([user]);
        if self.protocol.uses_udp_socket() {
            inbound["max_concurrent_streams"] = rule.max_connections.min(128).into();
            inbound["initial_packet_size"] = 1200.into();
        }
        match &self.protocol {
            WireProtocol::Hysteria2 {
                obfs, masquerade, ..
            } => {
                inbound["ignore_client_bandwidth"] = true.into();
                if let Some(Obfuscation::Salamander { password }) = obfs {
                    inbound["obfs"] = json!({"type":"salamander","password":password});
                }
                if let Some(Masquerade::Fixed {
                    status_code,
                    content,
                }) = masquerade
                {
                    inbound["masquerade"] =
                        json!({"type":"string","status_code":status_code,"content":content});
                }
            }
            WireProtocol::Tuic {
                congestion_control,
                zero_rtt_handshake,
                ..
            } => {
                inbound["congestion_control"] = congestion_control.as_str().into();
                inbound["zero_rtt_handshake"] = (*zero_rtt_handshake).into();
            }
            _ => {}
        }
        inbound
    }

    /// The engine's server TLS block. `detour` is the metered bridge that
    /// carries Reality's camouflage handshake.
    fn engine_tls(&self, tls: Option<&Path>, detour: &str) -> Result<serde_json::Value> {
        Ok(match &self.security {
            Security::Certificate { identity, .. } => {
                let (certificate, key) = crate::transport::identity_pem(tls, identity)?;
                let mut value = json!({"enabled":true,"min_version":"1.3","certificate":[certificate],"key":[key]});
                if self.protocol.uses_udp_socket() {
                    value["alpn"] = json!(["h3"]);
                }
                value
            }
            Security::Reality {
                server_name,
                handshake,
                private_key,
                short_id,
                extra_short_ids,
                max_time_difference_secs,
            } => {
                let (host, port) = handshake
                    .rsplit_once(':')
                    .context("Reality handshake requires a port")?;
                let short_ids: Vec<&String> =
                    std::iter::once(short_id).chain(extra_short_ids).collect();
                // Reality can forward an unauthenticated TLS connection to
                // the camouflage server. Meter and constrain this path too;
                // a direct handshake dialer would bypass native budgets.
                let mut reality = json!({"enabled":true,"handshake":{"server":host.trim_matches(['[',']']),"server_port":port.parse::<u16>()?,"detour":detour},"private_key":private_key,"short_id":short_ids});
                if let Some(secs) = max_time_difference_secs {
                    reality["max_time_difference"] = format!("{secs}s").into();
                }
                json!({"enabled":true,"server_name":server_name,"reality":reality})
            }
        })
    }

    /// Client-only material. Server private keys, bridge credentials, and local
    /// certificate paths never leave the node in a client export.
    pub fn client_outbound(&self, host: &str, tag: &str) -> Result<serde_json::Value> {
        let host = crate::subscription::normalize_host(host)?;
        let mut value = json!({"type":self.protocol.kind(),"tag":tag,"server":host,"server_port":self.listen.port()});
        match &self.protocol {
            WireProtocol::Vless { uuid, vision } => {
                value["uuid"] = uuid.clone().into();
                if *vision {
                    value["flow"] = "xtls-rprx-vision".into();
                }
            }
            WireProtocol::Vmess { uuid } => {
                value["uuid"] = uuid.clone().into();
                value["security"] = "auto".into();
            }
            WireProtocol::Tuic {
                uuid,
                password,
                congestion_control,
                zero_rtt_handshake,
            } => {
                value["uuid"] = uuid.clone().into();
                value["password"] = password.clone().into();
                value["congestion_control"] = congestion_control.as_str().into();
                if *zero_rtt_handshake {
                    value["zero_rtt_handshake"] = true.into();
                }
            }
            WireProtocol::Hysteria2 { password, obfs, .. } => {
                value["password"] = password.clone().into();
                if let Some(Obfuscation::Salamander { password }) = obfs {
                    value["obfs"] = json!({"type":"salamander","password":password});
                }
            }
            WireProtocol::AnyTls { password } | WireProtocol::Trojan { password } => {
                value["password"] = password.clone().into();
            }
        }
        value["tls"] = match &self.security {
            Security::Certificate { server_name, .. } => {
                json!({"enabled":true,"server_name":server_name.as_deref().unwrap_or(&host)})
            }
            // A client presents one short ID: the first.
            Security::Reality {
                server_name,
                private_key,
                short_id,
                ..
            } => {
                json!({"enabled":true,"server_name":server_name,"utls":{"enabled":true,"fingerprint":"chrome"},"reality":{"enabled":true,"public_key":reality_public_key(private_key)?,"short_id":short_id}})
            }
        };
        if self.protocol.uses_udp_socket() {
            value["tls"]["alpn"] = json!(["h3"]);
            // QUIC's minimum payload fits IPv6's minimum path MTU too. Larger
            // initial defaults can fail before PMTU discovery behind tunnels.
            value["initial_packet_size"] = 1200.into();
        }
        Ok(value)
    }

    pub fn mihomo_proxy(&self, host: &str, name: &str, udp: bool) -> Result<serde_json::Value> {
        let outbound = self.client_outbound(host, name)?;
        let mut value = json!({"name":name,"type":self.protocol.kind(),"server":outbound["server"],"port":self.listen.port(),"udp":udp});
        for key in ["uuid", "password", "flow"] {
            if let Some(field) = outbound.get(key) {
                value[key] = field.clone();
            }
        }
        if matches!(
            self.protocol,
            WireProtocol::Vless { .. } | WireProtocol::Vmess { .. }
        ) {
            value["tls"] = true.into();
            value["servername"] = outbound["tls"]["server_name"].clone();
        } else {
            value["sni"] = outbound["tls"]["server_name"].clone();
        }
        if matches!(self.protocol, WireProtocol::Vmess { .. }) {
            value["alterId"] = 0.into();
            value["cipher"] = "auto".into();
        }
        if self.protocol.uses_udp_socket() {
            value["alpn"] = json!(["h3"]);
        }
        match &self.protocol {
            WireProtocol::Tuic {
                congestion_control,
                zero_rtt_handshake,
                ..
            } => {
                value["congestion-controller"] = congestion_control.as_str().into();
                if *zero_rtt_handshake {
                    value["reduce-rtt"] = true.into();
                }
            }
            WireProtocol::Hysteria2 {
                obfs: Some(Obfuscation::Salamander { password }),
                ..
            } => {
                value["obfs"] = "salamander".into();
                value["obfs-password"] = password.clone().into();
            }
            _ => {}
        }
        if let Some(reality) = outbound["tls"].get("reality") {
            value["client-fingerprint"] = "chrome".into();
            value["reality-opts"] =
                json!({"public-key":reality["public_key"],"short-id":reality["short_id"]});
        }
        Ok(value)
    }

    /// A share link in the scheme clients commonly import: `vless://`,
    /// `vmess://` (v2rayN JSON), `trojan://`, `hysteria2://` and `tuic://`.
    /// It carries the same client material as a subscription export, never
    /// the Reality private key. AnyTLS has no widely used scheme: `None`.
    pub fn share_link(&self, host: &str, port: u16, name: &str) -> Result<Option<String>> {
        use crate::subscription::percent;
        ensure!(port != 0, "share link port must be 1..65535");
        let outbound = self.client_outbound(host, name)?;
        let host = outbound["server"].as_str().expect("normalized host");
        let address = if host.contains(':') {
            format!("[{host}]:{port}")
        } else {
            format!("{host}:{port}")
        };
        let sni = outbound["tls"]["server_name"].as_str().unwrap_or(host);
        let mut query = vec![];
        let link = match &self.protocol {
            WireProtocol::Vless { uuid, vision } => {
                query.push(("encryption", "none".to_owned()));
                query.push(("type", "tcp".to_owned()));
                if *vision {
                    query.push(("flow", "xtls-rprx-vision".to_owned()));
                }
                match &outbound["tls"]["reality"] {
                    serde_json::Value::Object(reality) => {
                        query.push(("security", "reality".to_owned()));
                        query.push(("sni", sni.to_owned()));
                        query.push(("fp", "chrome".to_owned()));
                        for (key, field) in [("pbk", "public_key"), ("sid", "short_id")] {
                            query.push((key, reality[field].as_str().unwrap_or("").to_owned()));
                        }
                    }
                    _ => {
                        query.push(("security", "tls".to_owned()));
                        query.push(("sni", sni.to_owned()));
                    }
                }
                format!("vless://{}@{address}", percent(uuid))
            }
            WireProtocol::Vmess { uuid } => {
                let document = json!({"v":"2","ps":name,"add":host,"port":port.to_string(),"id":uuid,"aid":"0","scy":"auto","net":"tcp","type":"none","host":"","path":"","tls":"tls","sni":sni});
                return Ok(Some(format!(
                    "vmess://{}",
                    base64::engine::general_purpose::STANDARD.encode(document.to_string())
                )));
            }
            WireProtocol::Trojan { password } => {
                query.push(("security", "tls".to_owned()));
                query.push(("sni", sni.to_owned()));
                query.push(("type", "tcp".to_owned()));
                format!("trojan://{}@{address}", percent(password))
            }
            WireProtocol::Hysteria2 { password, obfs, .. } => {
                query.push(("sni", sni.to_owned()));
                if let Some(Obfuscation::Salamander { password }) = obfs {
                    query.push(("obfs", "salamander".to_owned()));
                    query.push(("obfs-password", password.clone()));
                }
                format!("hysteria2://{}@{address}/", percent(password))
            }
            WireProtocol::Tuic {
                uuid,
                password,
                congestion_control,
                ..
            } => {
                query.push(("sni", sni.to_owned()));
                query.push(("alpn", "h3".to_owned()));
                query.push(("congestion_control", congestion_control.as_str().to_owned()));
                format!("tuic://{}:{}@{address}", percent(uuid), percent(password))
            }
            WireProtocol::AnyTls { .. } => return Ok(None),
        };
        let query: Vec<String> = query
            .into_iter()
            .map(|(key, value)| format!("{key}={}", percent(&value)))
            .collect();
        Ok(Some(format!(
            "{link}?{}#{}",
            query.join("&"),
            percent(name)
        )))
    }
}

#[derive(Clone, Default, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub gateways: usize,
    pub running: bool,
    pub restarts: u64,
    pub last_error: Option<String>,
    pub engine_version: String,
    #[serde(default)]
    pub process_id: Option<u32>,
}
pub(crate) type Metrics = Arc<Mutex<Snapshot>>;

/// A private immutable generation. Files are removed only after its process exits.
pub(crate) struct Plan {
    directory: PathBuf,
    pub auth: HashMap<String, socks5::ServerConfig>,
    count: usize,
}
impl Drop for Plan {
    fn drop(&mut self) {
        let _ = std::fs::remove_file(self.directory.join("config.json"));
        let _ = std::fs::remove_dir(&self.directory);
    }
}
impl Plan {
    pub async fn prepare(
        config: &NodeConfig,
        tls: Option<&Path>,
        executable: &Path,
    ) -> Result<Option<Arc<Self>>> {
        let rules: Vec<_> = config
            .rules
            .iter()
            .filter(|r| r.enabled && r.protocol_gateway.is_some())
            .collect();
        if rules.is_empty() {
            return Ok(None);
        }
        ensure!(
            rules.len() <= MAX_GATEWAYS,
            "at most 64 protocol gateways per node"
        );
        ensure!(
            executable.is_absolute(),
            "RELAY_PROTOCOL_ENGINE must be an absolute path"
        );
        let meta = std::fs::symlink_metadata(executable)
            .context("protocol engine executable unavailable")?;
        ensure!(
            meta.is_file() && !meta.file_type().is_symlink(),
            "protocol engine must be a regular executable file"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            ensure!(
                meta.permissions().mode() & 0o022 == 0,
                "protocol engine must not be writable by group or others"
            );
        }
        let mut command = Command::new(executable);
        command
            .arg("version")
            .kill_on_drop(true)
            .stderr(std::process::Stdio::null());
        let version = tokio::time::timeout(Duration::from_secs(5), command.output()).await??;
        ensure!(
            version.status.success()
                && String::from_utf8_lossy(&version.stdout).lines().next()
                    == Some(&format!("sing-box version {ENGINE_VERSION}")),
            "protocol engine must be sing-box {ENGINE_VERSION}"
        );
        let mut inbounds = vec![];
        let mut outbounds = vec![];
        let mut route = vec![];
        let mut auth = HashMap::new();
        for rule in &rules {
            let gateway = rule.protocol_gateway.as_ref().expect("filtered");
            gateway.validate(rule)?;
            let tag = format!("in-{}", rule.id);
            let out = format!("meter-{}", rule.id);
            let credential = crate::store::secret();
            auth.insert(
                rule.id.clone(),
                socks5::ServerConfig {
                    username: Some(rule.id.clone()),
                    password: Some(credential.clone()),
                    allow_private_destinations: gateway.allow_private_destinations,
                },
            );
            let mut inbound = gateway.engine_inbound(rule, &tag);
            inbound["tls"] = gateway.engine_tls(tls, &out)?;
            inbounds.push(inbound);
            outbounds.push(json!({"type":"socks","tag":out,"server":rule.listen.ip().to_string(),"server_port":rule.listen.port(),"version":"5","username":rule.id,"password":credential,"udp_over_tcp":false}));
            if !rule.deny_sources.is_empty() {
                route.push(
                    json!({"inbound":[tag],"source_ip_cidr":rule.deny_sources,"action":"reject"}),
                );
            }
            if !rule.allow_sources.is_empty() {
                route.push(json!({"type":"logical","mode":"and","rules":[{"inbound":[tag]},{"source_ip_cidr":rule.allow_sources,"invert":true}],"action":"reject"}));
            }
            if rule.protocol == Protocol::Tcp {
                route.push(json!({"inbound":[tag],"network":"udp","action":"reject"}));
            }
            route.push(json!({"inbound":[tag],"action":"route","outbound":out}));
        }
        route.push(json!({"action":"reject"}));
        let document = json!({"log":{"level":"info","timestamp":false,"disabled":false},"inbounds":inbounds,"outbounds":outbounds,"route":{"rules":route}});
        let directory =
            std::env::temp_dir().join(format!("relay-gateway-{}", uuid::Uuid::new_v4()));
        let mut builder = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            builder.mode(0o700);
        }
        builder.create(&directory)?;
        let plan = Arc::new(Self {
            directory,
            auth,
            count: rules.len(),
        });
        crate::store::write_secret(
            &plan.directory.join("config.json"),
            &serde_json::to_vec(&document)?,
        )?;
        let mut check = Command::new(executable);
        check
            .arg("check")
            .arg("-c")
            .arg(plan.directory.join("config.json"))
            .kill_on_drop(true)
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null());
        ensure!(
            tokio::time::timeout(Duration::from_secs(10), check.status())
                .await??
                .success(),
            "protocol engine rejected the generated configuration"
        );
        Ok(Some(plan))
    }
    fn spawn(&self, executable: &Path) -> Result<Child> {
        let mut command = Command::new(executable);
        command
            .arg("run")
            .arg("-c")
            .arg(self.directory.join("config.json"))
            .env("GOMEMLIMIT", "96MiB")
            .env("GOMAXPROCS", "1")
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::piped())
            .kill_on_drop(true);
        #[cfg(target_os = "linux")]
        {
            let parent = std::process::id() as nix::libc::pid_t;
            // Async-signal-safe syscalls only, in the child after fork. Check the
            // parent again to close the race where it died before prctl.
            unsafe {
                command.pre_exec(move || {
                    if nix::libc::prctl(nix::libc::PR_SET_PDEATHSIG, nix::libc::SIGKILL) != 0 {
                        return Err(std::io::Error::last_os_error());
                    }
                    if nix::libc::getppid() != parent {
                        return Err(std::io::Error::other("parent exited"));
                    }
                    Ok(())
                });
            }
        }
        command.spawn().context("cannot start protocol engine")
    }
    pub async fn start(self: &Arc<Self>, executable: PathBuf, metrics: Metrics) -> Result<Running> {
        let child = self.spawn(&executable)?;
        let stop = CancellationToken::new();
        let (ready_tx, ready_rx) = oneshot::channel();
        let plan = self.clone();
        let signal = stop.clone();
        let task = tokio::spawn(async move {
            monitor(plan, executable, metrics, child, signal, ready_tx).await;
        });
        let mut running = Running {
            plan: self.clone(),
            stop,
            task: Some(task),
        };
        match tokio::time::timeout(Duration::from_secs(10), ready_rx).await {
            Ok(Ok(())) => Ok(running),
            _ => {
                running.stop().await;
                bail!("protocol engine failed to become ready within 10 seconds")
            }
        }
    }
}

pub(crate) struct Running {
    pub plan: Arc<Plan>,
    stop: CancellationToken,
    task: Option<JoinHandle<()>>,
}
impl Drop for Running {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(task) = &self.task {
            task.abort();
        }
    }
}
impl Running {
    pub async fn stop(&mut self) {
        self.stop.cancel();
        if let Some(task) = self.task.take() {
            let _ = task.await;
        }
    }
}
async fn monitor(
    plan: Arc<Plan>,
    executable: PathBuf,
    metrics: Metrics,
    mut child: Child,
    stop: CancellationToken,
    ready: oneshot::Sender<()>,
) {
    let mut first_ready = Some(ready);
    let mut failures = 0u32;
    loop {
        let mut stderr = child.stderr.take().expect("piped stderr");
        let (seen_tx, seen_rx) = oneshot::channel();
        let reader = tokio::spawn(async move {
            let mut sender = Some(seen_tx);
            let mut carry = Vec::new();
            let mut bytes = [0u8; 4096];
            while let Ok(n) = stderr.read(&mut bytes).await {
                if n == 0 {
                    break;
                }
                carry.extend_from_slice(&bytes[..n]);
                if sender.is_some()
                    && String::from_utf8_lossy(&carry).contains("sing-box started (")
                {
                    let _ = sender.take().unwrap().send(());
                }
                if carry.len() > 128 {
                    carry.drain(..carry.len() - 128);
                }
            }
        });
        let ready = tokio::select! { biased; _ = stop.cancelled() => false, result = tokio::time::timeout(Duration::from_secs(10), seen_rx) => matches!(result, Ok(Ok(()))) };
        if ready {
            {
                let mut m = metrics.lock().unwrap();
                m.gateways = plan.count;
                m.running = true;
                m.process_id = child.id();
                m.engine_version = ENGINE_VERSION.into();
                m.last_error = None;
            }
            if let Some(sender) = first_ready.take() {
                let _ = sender.send(());
            }
            tokio::select! { biased; _ = stop.cancelled() => {}, _ = child.wait() => {} }
        }
        let _ = child.kill().await;
        reader.abort();
        let _ = reader.await;
        {
            let mut m = metrics.lock().unwrap();
            m.running = false;
            m.process_id = None;
            if !stop.is_cancelled() {
                m.last_error = Some("protocol engine stopped; restart pending".into());
            }
        }
        if stop.is_cancelled() || first_ready.is_some() {
            return;
        }
        failures = failures.saturating_add(1);
        loop {
            let delay = Duration::from_secs(1u64 << failures.min(5));
            tokio::select! { biased; _ = stop.cancelled() => return, _ = tokio::time::sleep(delay) => {} }
            match plan.spawn(&executable) {
                Ok(next) => {
                    child = next;
                    metrics.lock().unwrap().restarts += 1;
                    break;
                }
                Err(_) => {
                    failures = failures.saturating_add(1);
                    metrics.lock().unwrap().last_error =
                        Some("protocol engine restart failed".into());
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::Value;

    const UUID: &str = "bf000d23-0752-40b4-affe-68f7707a9661";
    const PASSWORD: &str = "p@ss:word/#?&=+ 1234";

    fn rule_json(gateway: Value) -> Value {
        json!({"id":"gw","tenant_id":"t","owner_id":"o","name":"Gateway","listen":"127.0.0.1:9000","protocol":"tcp","targets":[],"meter_epoch":"e","max_connections":512,"protocol_gateway":gateway})
    }
    fn rule(gateway: Value) -> Rule {
        serde_json::from_value(rule_json(gateway)).unwrap()
    }
    fn certificate(protocol: Value) -> Value {
        json!({"listen":"0.0.0.0:443","protocol":protocol,"security":{"type":"certificate","identity":"server","server_name":"relay.example"}})
    }
    fn reality(security: Value) -> Value {
        let mut value = json!({"type":"reality","server_name":"www.example.com","handshake":"www.example.com:443","private_key":URL_SAFE_NO_PAD.encode([7u8; 32])});
        value
            .as_object_mut()
            .unwrap()
            .extend(security.as_object().unwrap().clone());
        json!({"listen":"[::]:8443","protocol":{"type":"vless","uuid":UUID,"vision":true},"security":value})
    }
    /// A gateway as the panel and API send it, checked as the controller does.
    fn config(gateway: Value) -> Config {
        let rule = rule(gateway);
        let config = rule.protocol_gateway.clone().unwrap();
        config.validate(&rule).unwrap();
        config
    }
    fn rejected(gateway: Value) -> bool {
        match serde_json::from_value::<Rule>(rule_json(gateway)) {
            Ok(rule) => rule
                .protocol_gateway
                .as_ref()
                .unwrap()
                .validate(&rule)
                .is_err(),
            Err(_) => true,
        }
    }

    #[test]
    fn hysteria2_obfuscation_and_masquerade_use_engine_option_names() {
        let gateway = config(certificate(json!({"type":"hysteria2","password":PASSWORD,
            "obfs":{"type":"salamander","password":"obfuscation-password-1"},
            "masquerade":{"type":"string","status_code":404,"content":"<h1>Not Found</h1>"}})));
        // sing-box 1.14.4 option/hysteria2.go: Hysteria2Obfs and the
        // Hysteria2MasqueradeString variant.
        let inbound = gateway.engine_inbound(&rule(Value::Null), "in");
        assert_eq!(
            inbound["obfs"],
            json!({"type":"salamander","password":"obfuscation-password-1"})
        );
        assert_eq!(
            inbound["masquerade"],
            json!({"type":"string","status_code":404,"content":"<h1>Not Found</h1>"})
        );
        let client = gateway.client_outbound("relay.example", "hy2").unwrap();
        assert_eq!(client["obfs"], inbound["obfs"]);
        assert!(client.get("masquerade").is_none(), "a server-only option");
        let mihomo = gateway.mihomo_proxy("relay.example", "hy2", true).unwrap();
        assert_eq!(mihomo["obfs"], "salamander");
        assert_eq!(mihomo["obfs-password"], "obfuscation-password-1");

        let plain = config(certificate(json!({"type":"hysteria2","password":PASSWORD})));
        let inbound = plain.engine_inbound(&rule(Value::Null), "in");
        for value in [
            inbound,
            plain.client_outbound("relay.example", "hy2").unwrap(),
            plain.mihomo_proxy("relay.example", "hy2", true).unwrap(),
        ] {
            assert!(value.get("obfs").is_none() && value.get("masquerade").is_none());
        }
        // Configs that do not use the options serialize as before, so agents
        // without them still accept them.
        assert_eq!(
            serde_json::to_value(&plain.protocol).unwrap(),
            json!({"type":"hysteria2","password":PASSWORD})
        );
    }

    #[test]
    fn tuic_congestion_control_and_zero_rtt_reach_engine_and_clients() {
        for (name, zero_rtt) in [("cubic", true), ("new_reno", false), ("bbr", true)] {
            let gateway = config(certificate(
                json!({"type":"tuic","uuid":UUID,"password":PASSWORD,
                "congestion_control":name,"zero_rtt_handshake":zero_rtt}),
            ));
            let inbound = gateway.engine_inbound(&rule(Value::Null), "in");
            assert_eq!(inbound["congestion_control"], name);
            assert_eq!(inbound["zero_rtt_handshake"], zero_rtt);
            let client = gateway.client_outbound("relay.example", "tuic").unwrap();
            assert_eq!(client["congestion_control"], name);
            assert_eq!(
                client["zero_rtt_handshake"].as_bool().unwrap_or(false),
                zero_rtt
            );
            let mihomo = gateway.mihomo_proxy("relay.example", "tuic", true).unwrap();
            assert_eq!(mihomo["congestion-controller"], name);
            assert_eq!(mihomo["reduce-rtt"].as_bool().unwrap_or(false), zero_rtt);
        }
        // Today's behaviour stays the default: BBR without 0-RTT, and the
        // stored rule does not change shape.
        let default = config(certificate(
            json!({"type":"tuic","uuid":UUID,"password":PASSWORD}),
        ));
        let inbound = default.engine_inbound(&rule(Value::Null), "in");
        assert_eq!(inbound["congestion_control"], "bbr");
        assert_eq!(inbound["zero_rtt_handshake"], false);
        assert!(
            default
                .mihomo_proxy("relay.example", "tuic", true)
                .unwrap()
                .get("reduce-rtt")
                .is_none()
        );
        assert_eq!(
            serde_json::to_value(&default.protocol).unwrap(),
            json!({"type":"tuic","uuid":UUID,"password":PASSWORD})
        );
        assert!(rejected(certificate(
            json!({"type":"tuic","uuid":UUID,"password":PASSWORD,"congestion_control":"brutal"})
        )));
    }

    #[test]
    fn reality_takes_several_short_ids_and_a_clock_difference_limit() {
        let gateway = config(reality(
            json!({"short_id":"0123","extra_short_ids":["AA","fedcba9876543210"],"max_time_difference_secs":90}),
        ));
        let tls = gateway.engine_tls(None, "meter-gw").unwrap();
        assert_eq!(
            tls["reality"]["short_id"],
            json!(["0123", "AA", "fedcba9876543210"])
        );
        // badoption.Duration: a Go duration string.
        assert_eq!(tls["reality"]["max_time_difference"], "90s");
        assert_eq!(tls["reality"]["handshake"]["detour"], "meter-gw");
        // A client presents one short ID, the first.
        let client = gateway.client_outbound("relay.example", "vless").unwrap();
        assert_eq!(client["tls"]["reality"]["short_id"], "0123");
        let mihomo = gateway
            .mihomo_proxy("relay.example", "vless", true)
            .unwrap();
        assert_eq!(mihomo["reality-opts"]["short-id"], "0123");

        let single = config(reality(json!({"short_id":"0123"})));
        let tls = single.engine_tls(None, "meter-gw").unwrap();
        assert_eq!(tls["reality"]["short_id"], json!(["0123"]));
        assert!(tls["reality"].get("max_time_difference").is_none());
        assert_eq!(
            serde_json::to_value(&single.security).unwrap(),
            reality(json!({"short_id":"0123"}))["security"]
        );

        let sixteen: Vec<String> = (1..16).map(|n| format!("{n:02x}")).collect();
        assert!(!rejected(reality(
            json!({"short_id":"00","extra_short_ids":sixteen})
        )));
        let seventeen: Vec<String> = (1..17).map(|n| format!("{n:02x}")).collect();
        for invalid in [
            json!({"short_id":"00","extra_short_ids":seventeen}),
            json!({"short_id":"aa","extra_short_ids":["AA"]}),
            json!({"short_id":"aa","extra_short_ids":["abc"]}),
            json!({"short_id":"aa","max_time_difference_secs":0}),
            json!({"short_id":"aa","max_time_difference_secs":3601}),
        ] {
            assert!(rejected(reality(invalid.clone())), "{invalid}");
        }
    }

    #[test]
    fn invalid_hysteria2_options_are_rejected() {
        let hysteria = |extra: Value| {
            let mut protocol = json!({"type":"hysteria2","password":PASSWORD});
            protocol
                .as_object_mut()
                .unwrap()
                .extend(extra.as_object().unwrap().clone());
            certificate(protocol)
        };
        for invalid in [
            json!({"obfs":{"type":"salamander","password":"short"}}),
            // Only salamander is offered; gecko needs packet sizes Relay does not expose.
            json!({"obfs":{"type":"gecko","password":"obfuscation-password-1"}}),
            json!({"obfs":{"type":"salamander"}}),
            json!({"masquerade":{"type":"string","status_code":199}}),
            json!({"masquerade":{"type":"string","status_code":600}}),
            json!({"masquerade":{"type":"string","status_code":200,"content":"x".repeat(4097)}}),
            // The engine's file and reverse-proxy masquerades bypass the bridge.
            json!({"masquerade":{"type":"proxy","url":"http://127.0.0.1:8080"}}),
            json!({"masquerade":{"type":"file","directory":"/etc"}}),
            json!({"masquerade":"http://127.0.0.1:8080"}),
        ] {
            assert!(rejected(hysteria(invalid.clone())), "{invalid}");
        }
        assert!(!rejected(hysteria(
            json!({"masquerade":{"type":"string","status_code":200}})
        )));
    }

    fn parse(link: &str) -> (reqwest::Url, std::collections::HashMap<String, String>) {
        let url = reqwest::Url::parse(link).unwrap();
        let query = url.query_pairs().into_owned().collect();
        (url, query)
    }
    fn decode(value: &str) -> String {
        let bytes = value.as_bytes();
        let mut out = vec![];
        let mut i = 0;
        while i < bytes.len() {
            if bytes[i] == b'%' {
                out.push(u8::from_str_radix(&value[i + 1..i + 3], 16).unwrap());
                i += 3;
            } else {
                out.push(bytes[i]);
                i += 1;
            }
        }
        String::from_utf8(out).unwrap()
    }

    #[test]
    fn share_links_parse_to_the_client_fields() {
        let private = URL_SAFE_NO_PAD.encode([7u8; 32]);
        let vless = config(reality(
            json!({"short_id":"0123","extra_short_ids":["aa"],"max_time_difference_secs":60}),
        ));
        let link = vless
            .share_link("2001:db8::1", 8443, "Tokyo · VLESS")
            .unwrap()
            .unwrap();
        assert!(
            !link.contains(&private),
            "the Reality private key stays on the node"
        );
        let (url, query) = parse(&link);
        assert_eq!(url.scheme(), "vless");
        assert_eq!(url.username(), UUID);
        assert_eq!(url.host_str(), Some("[2001:db8::1]"));
        assert_eq!(url.port(), Some(8443));
        assert_eq!(query["security"], "reality");
        assert_eq!(query["encryption"], "none");
        assert_eq!(query["type"], "tcp");
        assert_eq!(query["flow"], "xtls-rprx-vision");
        assert_eq!(query["sni"], "www.example.com");
        assert_eq!(query["fp"], "chrome");
        assert_eq!(query["pbk"], reality_public_key(&private).unwrap());
        assert_eq!(query["sid"], "0123");
        assert_eq!(decode(url.fragment().unwrap()), "Tokyo · VLESS");

        let tls = config(certificate(
            json!({"type":"vless","uuid":UUID,"vision":false}),
        ));
        let (_, query) = parse(&tls.share_link("203.0.113.7", 443, "v").unwrap().unwrap());
        assert_eq!(query["security"], "tls");
        assert_eq!(query["sni"], "relay.example");
        assert!(!query.contains_key("flow") && !query.contains_key("pbk"));

        let trojan = config(certificate(json!({"type":"trojan","password":PASSWORD})));
        let (url, query) = parse(
            &trojan
                .share_link("edge.example", 443, "t")
                .unwrap()
                .unwrap(),
        );
        assert_eq!(url.scheme(), "trojan");
        assert_eq!(decode(url.username()), PASSWORD);
        assert_eq!(
            (url.host_str(), url.port()),
            (Some("edge.example"), Some(443))
        );
        assert_eq!(query["security"], "tls");
        assert_eq!(query["sni"], "relay.example");

        let hysteria = config(certificate(json!({"type":"hysteria2","password":PASSWORD,
            "obfs":{"type":"salamander","password":"obfs&pass=word 12345"}})));
        let link = hysteria
            .share_link("edge.example", 443, "h")
            .unwrap()
            .unwrap();
        assert!(link.starts_with("hysteria2://"));
        let (url, query) = parse(&link);
        assert_eq!(decode(url.username()), PASSWORD);
        assert_eq!(url.path(), "/");
        assert_eq!(query["sni"], "relay.example");
        assert_eq!(query["obfs"], "salamander");
        assert_eq!(query["obfs-password"], "obfs&pass=word 12345");
        let plain = config(certificate(json!({"type":"hysteria2","password":PASSWORD})));
        let (_, query) = parse(&plain.share_link("edge.example", 443, "h").unwrap().unwrap());
        assert!(!query.contains_key("obfs"));

        let tuic = config(certificate(
            json!({"type":"tuic","uuid":UUID,"password":PASSWORD,
            "congestion_control":"cubic","zero_rtt_handshake":true}),
        ));
        let (url, query) = parse(&tuic.share_link("edge.example", 8443, "q").unwrap().unwrap());
        assert_eq!(url.scheme(), "tuic");
        assert_eq!(url.username(), UUID);
        assert_eq!(decode(url.password().unwrap()), PASSWORD);
        assert_eq!(url.port(), Some(8443));
        assert_eq!(query["congestion_control"], "cubic");
        assert_eq!(query["alpn"], "h3");
        assert_eq!(query["sni"], "relay.example");

        let vmess = config(certificate(json!({"type":"vmess","uuid":UUID})));
        let link = vmess
            .share_link("edge.example", 443, "Osaka")
            .unwrap()
            .unwrap();
        let document: Value = serde_json::from_slice(
            &base64::engine::general_purpose::STANDARD
                .decode(link.strip_prefix("vmess://").unwrap())
                .unwrap(),
        )
        .unwrap();
        assert_eq!(
            document,
            json!({"v":"2","ps":"Osaka","add":"edge.example","port":"443","id":UUID,"aid":"0","scy":"auto","net":"tcp","type":"none","host":"","path":"","tls":"tls","sni":"relay.example"})
        );

        let any = config(certificate(json!({"type":"any_tls","password":PASSWORD})));
        assert!(any.share_link("edge.example", 443, "a").unwrap().is_none());
        assert!(tuic.share_link("https://edge.example", 443, "q").is_err());
        assert!(tuic.share_link("edge.example", 0, "q").is_err());
    }
}
