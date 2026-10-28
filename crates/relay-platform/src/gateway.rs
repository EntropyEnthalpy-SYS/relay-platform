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
    },
    Tuic {
        uuid: String,
        password: String,
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
        short_id: String,
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
            } => {
                uuid(id)?;
                password(p)?;
            }
            WireProtocol::Hysteria2 { password: p }
            | WireProtocol::AnyTls { password: p }
            | WireProtocol::Trojan { password: p } => password(p)?,
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
                    !short_id.is_empty()
                        && short_id.len() <= 16
                        && short_id.len().is_multiple_of(2)
                        && short_id.bytes().all(|b| b.is_ascii_hexdigit()),
                    "Reality short ID requires 2..16 hexadecimal digits"
                );
            }
        }
        Ok(())
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
            WireProtocol::Tuic { uuid, password } => {
                value["uuid"] = uuid.clone().into();
                value["password"] = password.clone().into();
                value["congestion_control"] = "bbr".into();
            }
            WireProtocol::Hysteria2 { password }
            | WireProtocol::AnyTls { password }
            | WireProtocol::Trojan { password } => {
                value["password"] = password.clone().into();
            }
        }
        value["tls"] = match &self.security {
            Security::Certificate { server_name, .. } => {
                json!({"enabled":true,"server_name":server_name.as_deref().unwrap_or(&host)})
            }
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
        if matches!(self.protocol, WireProtocol::Tuic { .. }) {
            value["congestion-controller"] = "bbr".into();
        }
        if let Some(reality) = outbound["tls"].get("reality") {
            value["client-fingerprint"] = "chrome".into();
            value["reality-opts"] =
                json!({"public-key":reality["public_key"],"short-id":reality["short_id"]});
        }
        Ok(value)
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
            let mut inbound = json!({"type":gateway.protocol.kind(), "tag":tag, "listen":gateway.listen.ip().to_string(), "listen_port":gateway.listen.port(), "tcp_fast_open":false});
            let user = match &gateway.protocol {
                WireProtocol::Vless { uuid, vision } => {
                    json!({"name":rule.id,"uuid":uuid,"flow":if *vision {"xtls-rprx-vision"} else {""}})
                }
                WireProtocol::Vmess { uuid } => json!({"name":rule.id,"uuid":uuid,"alterId":0}),
                WireProtocol::Tuic { uuid, password } => {
                    json!({"name":rule.id,"uuid":uuid,"password":password})
                }
                WireProtocol::Hysteria2 { password }
                | WireProtocol::AnyTls { password }
                | WireProtocol::Trojan { password } => json!({"name":rule.id,"password":password}),
            };
            inbound["users"] = json!([user]);
            if gateway.protocol.uses_udp_socket() {
                inbound["max_concurrent_streams"] = rule.max_connections.min(128).into();
                inbound["initial_packet_size"] = 1200.into();
            }
            if matches!(gateway.protocol, WireProtocol::Hysteria2 { .. }) {
                inbound["ignore_client_bandwidth"] = true.into();
            }
            if matches!(gateway.protocol, WireProtocol::Tuic { .. }) {
                inbound["congestion_control"] = "bbr".into();
                inbound["zero_rtt_handshake"] = false.into();
            }
            inbound["tls"] = match &gateway.security {
                Security::Certificate { identity, .. } => {
                    let (certificate, key) = crate::transport::identity_pem(tls, identity)?;
                    let mut value = json!({"enabled":true,"min_version":"1.3","certificate":[certificate],"key":[key]});
                    if gateway.protocol.uses_udp_socket() {
                        value["alpn"] = json!(["h3"]);
                    }
                    value
                }
                Security::Reality {
                    server_name,
                    handshake,
                    private_key,
                    short_id,
                } => {
                    let (host, port) = handshake
                        .rsplit_once(':')
                        .context("Reality handshake requires a port")?;
                    // Reality can forward an unauthenticated TLS connection to
                    // the camouflage server. Meter and constrain this path too;
                    // a direct handshake dialer would bypass native budgets.
                    json!({"enabled":true,"server_name":server_name,"reality":{"enabled":true,"handshake":{"server":host.trim_matches(['[',']']),"server_port":port.parse::<u16>()?,"detour":out},"private_key":private_key,"short_id":[short_id]}})
                }
            };
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
