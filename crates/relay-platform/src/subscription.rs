//! Client subscription rendering. A subscription is a named snapshot of the
//! rules a user owns, rendered for common clients. It never contains controller
//! credentials; the public token is an independent, revocable subscription key.
use crate::model::{Rule, now_ms};
use anyhow::{Context as _, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const TOKEN_PREFIX: &str = "rsub_";
pub const MAX_SUBSCRIPTIONS: usize = 20;
pub const MAX_EXPIRY_DAYS: u32 = 3650;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
    SingBox,
    V2ray,
    Clash,
    Surge,
    Shadowrocket,
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Template {
    /// Prefix for client-visible entry names.
    pub name_prefix: String,
    /// Replace the address clients dial. Useful for a NAT/public hostname.
    pub host: Option<String>,
    /// Include only nodes carrying at least one of these tags.
    pub node_tags: Vec<String>,
    /// Advertise UDP support in generated clients.
    pub udp: bool,
    /// The user's own proxies. Clients reach each one through this
    /// subscription's relay entries: client → relay node → upstream → site.
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub upstreams: Vec<Upstream>,
}
impl Default for Template {
    fn default() -> Self {
        Self {
            name_prefix: String::new(),
            host: None,
            node_tags: vec![],
            udp: true,
            upstreams: vec![],
        }
    }
}
pub const MAX_UPSTREAMS: usize = 8;
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum UpstreamKind {
    Socks5,
    Shadowsocks,
}
/// A proxy the user already has, exported as a client entry that dials it
/// through the relay entries (mihomo `dialer-proxy`, sing-box `detour`,
/// Surge `underlying-proxy`). The relay nodes only see an ordinary
/// connection to `server:port`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Upstream {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: UpstreamKind,
    pub server: String,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    /// Shadowsocks only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub method: Option<crate::shadowsocks::Method>,
}
impl Upstream {
    fn validate(&self) -> Result<()> {
        ensure!(
            label(&self.name, 64),
            "upstream proxy names must be 1..64 bytes without surrounding whitespace or control characters"
        );
        normalize_host(&self.server)?;
        ensure!(self.port != 0, "upstream proxy port must be 1..65535");
        let credential = |value: &Option<String>| {
            value
                .as_deref()
                .is_none_or(|v| !v.is_empty() && v.len() <= 255 && !v.chars().any(char::is_control))
        };
        ensure!(
            credential(&self.username) && credential(&self.password),
            "upstream proxy usernames and passwords must be 1..255 bytes without control characters"
        );
        match self.kind {
            UpstreamKind::Socks5 => ensure!(
                self.method.is_none() && self.username.is_some() == self.password.is_some(),
                "a SOCKS5 upstream takes a username and password together, or neither, and no method"
            ),
            UpstreamKind::Shadowsocks => {
                let (Some(method), Some(password), None) =
                    (self.method, &self.password, &self.username)
                else {
                    bail!("a Shadowsocks upstream needs a method and password, and no username");
                };
                crate::shadowsocks::ServerConfig {
                    method,
                    password: password.clone(),
                    allow_private_destinations: false,
                    udp_over_tcp: false,
                }
                .key()?;
            }
        }
        Ok(())
    }
}
fn label(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty()
        && value == value.trim()
        && value.len() <= maximum
        && !value.chars().any(char::is_control)
}
fn hostname(value: &str) -> bool {
    if value.len() > 253 || value.ends_with('.') {
        return false;
    }
    value.split('.').all(|part| {
        !part.is_empty()
            && part.len() <= 63
            && part
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            && !part.starts_with('-')
            && !part.ends_with('-')
    })
}
/// A client-facing host: hostname, IPv4, or IPv6 with optional brackets.
pub(crate) fn normalize_host(raw: &str) -> Result<String> {
    let raw = raw.trim();
    ensure!(
        !raw.is_empty()
            && raw.len() <= 253
            && !raw
                .chars()
                .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '/' | '@' | '#' | '?')),
        "subscription host must be a hostname or IP address"
    );
    let bare = raw
        .strip_prefix('[')
        .and_then(|value| value.strip_suffix(']'))
        .unwrap_or(raw);
    if let Ok(ip) = bare.parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    ensure!(hostname(bare), "subscription host is not a valid hostname");
    Ok(bare.to_ascii_lowercase())
}
impl Template {
    pub fn validate(&self) -> Result<()> {
        if self.name_prefix.len() > 64 || self.name_prefix.chars().any(char::is_control) {
            bail!("subscription name prefix must be 0..64 bytes without control characters");
        }
        if let Some(host) = &self.host {
            normalize_host(host)?;
        }
        if self.node_tags.len() > 16 || self.node_tags.iter().any(|tag| !label(tag, 64)) || {
            let mut seen = std::collections::HashSet::new();
            self.node_tags.iter().any(|tag| !seen.insert(tag.as_str()))
        } {
            bail!("subscription node tags must be 0..16 unique labels");
        }
        ensure!(
            self.upstreams.len() <= MAX_UPSTREAMS,
            "a subscription takes at most {MAX_UPSTREAMS} upstream proxies"
        );
        let mut names = std::collections::HashSet::new();
        for upstream in &self.upstreams {
            upstream
                .validate()
                .with_context(|| format!("upstream proxy “{}”", upstream.name))?;
            ensure!(
                names.insert(upstream.name.as_str()),
                "upstream proxy names must be unique"
            );
        }
        Ok(())
    }
}

pub const MAX_ALLOW_SOURCES: usize = 64;
pub const MAX_ROTATION_GRACE_MINUTES: u32 = 1440;

/// What an owner chooses for a link. Creating and editing take the same
/// settings; the token, owner and usage counters are not among them.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Settings {
    pub name: String,
    pub format: Format,
    pub template: Template,
    /// Networks that may fetch the public link; empty allows every source.
    pub allow_sources: Vec<IpNet>,
}
impl Settings {
    pub fn new(name: &str, format: Format, template: Template) -> Self {
        Self {
            name: name.into(),
            format,
            template,
            allow_sources: vec![],
        }
    }
    pub fn validate(&self) -> Result<()> {
        self.template.validate()?;
        ensure!(
            self.allow_sources.len() <= MAX_ALLOW_SOURCES,
            "a subscription takes at most {MAX_ALLOW_SOURCES} allowed source networks"
        );
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Subscription {
    pub id: String,
    pub tenant_id: String,
    pub owner_id: String,
    pub name: String,
    pub format: Format,
    pub template: Template,
    pub token_hash: String,
    pub created_at_ms: i64,
    pub expires_at_ms: Option<i64>,
    pub last_used_ms: Option<i64>,
    pub uses: u64,
    /// Fetches from other sources look like an unknown token.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub allow_sources: Vec<IpNet>,
    /// The token replaced by the last rotation, valid until
    /// `previous_token_expires_at_ms`. Only its hash is kept.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_token_hash: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub previous_token_expires_at_ms: Option<i64>,
}
impl Subscription {
    pub fn permits_source(&self, source: IpAddr) -> bool {
        let source = match source {
            IpAddr::V6(v6) => v6.to_ipv4_mapped().map(IpAddr::V4).unwrap_or(source),
            v4 => v4,
        };
        self.allow_sources.is_empty() || self.allow_sources.iter().any(|n| n.contains(&source))
    }
    /// Whether `hash` opens this subscription at `now`: the current token,
    /// or the previous one inside its grace period.
    pub fn accepts(&self, hash: &str, now: i64) -> bool {
        self.token_hash == hash
            || (self.previous_token_hash.as_deref() == Some(hash)
                && self
                    .previous_token_expires_at_ms
                    .is_some_and(|until| now < until))
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct SubscriptionView {
    pub id: String,
    pub owner_id: String,
    pub name: String,
    pub format: Format,
    pub template: Template,
    pub created_at_ms: i64,
    pub expires_at_ms: Option<i64>,
    pub last_used_ms: Option<i64>,
    pub uses: u64,
    pub allow_sources: Vec<IpNet>,
    /// While set and in the future, the link before the last rotation still works.
    pub previous_token_expires_at_ms: Option<i64>,
}
impl From<&Subscription> for SubscriptionView {
    fn from(value: &Subscription) -> Self {
        Self {
            id: value.id.clone(),
            owner_id: value.owner_id.clone(),
            name: value.name.clone(),
            format: value.format,
            template: value.template.clone(),
            created_at_ms: value.created_at_ms,
            expires_at_ms: value.expires_at_ms,
            last_used_ms: value.last_used_ms,
            uses: value.uses,
            allow_sources: value.allow_sources.clone(),
            previous_token_expires_at_ms: value
                .previous_token_hash
                .as_ref()
                .and(value.previous_token_expires_at_ms),
        }
    }
}

/// The parts of `Subscription-Userinfo` Relay can fill truthfully; the
/// header leaves out the others.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Usage {
    /// Bytes the owner's user budget has consumed. Budgets count both
    /// directions together, so this is reported as `download` and `upload`
    /// is left out.
    pub used_bytes: Option<u64>,
    /// The user budget's limit.
    pub total_bytes: Option<u64>,
    /// When the owner's plan entitlement ends.
    pub expires_at_ms: Option<i64>,
}
impl Usage {
    /// `download=…; total=…; expire=…` with `expire` in Unix seconds, or
    /// `None` when nothing is known.
    pub fn header(&self) -> Option<String> {
        let mut parts = vec![];
        if let Some(used) = self.used_bytes {
            parts.push(format!("download={used}"));
        }
        if let Some(total) = self.total_bytes {
            parts.push(format!("total={total}"));
        }
        if let Some(expiry) = self.expires_at_ms {
            parts.push(format!("expire={}", expiry.div_euclid(1000)));
        }
        (!parts.is_empty()).then(|| parts.join("; "))
    }
}

/// One rule that may become a subscription entry, with its node context.
#[derive(Clone, Debug)]
pub struct Candidate {
    pub node_name: String,
    pub node_tags: Vec<String>,
    pub rule: Rule,
}
#[derive(Clone, Debug, Serialize)]
pub struct Entry {
    pub name: String,
    pub host: String,
    pub port: u16,
    pub method: String,
    pub password: String,
    pub udp: bool,
    /// An upstream proxy that clients reach through the relay entries.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub chained: bool,
    #[serde(skip)]
    udp_over_tcp: bool,
    #[serde(skip)]
    outbound: Option<serde_json::Value>,
    #[serde(skip)]
    upstream: Option<Upstream>,
}
/// Client configs share one namespace for proxies and groups.
fn free_name(base: &str, taken: &[&str]) -> String {
    let mut name = base.to_owned();
    while taken.contains(&name.as_str()) {
        name.push('_');
    }
    name
}
/// The default selection lists the user's chained proxies first, then the
/// relay entries; the chain's first hop selects among the relay entries.
struct Groups {
    main: String,
    via: String,
}
impl Groups {
    fn new(names: &[&str]) -> Self {
        let main = free_name("Relay", names);
        let via = free_name("Relay entry", &[names, &[main.as_str()]].concat());
        Self { main, via }
    }
}
fn selection<'a>(entries: &'a [Entry], names: &'a [String]) -> (Vec<&'a str>, Vec<&'a str>) {
    let chained = entries.iter().zip(names).filter(|(e, _)| e.chained);
    let front: Vec<&str> = entries
        .iter()
        .zip(names)
        .filter(|(e, _)| !e.chained)
        .map(|(_, n)| n.as_str())
        .collect();
    let main = chained
        .map(|(_, n)| n.as_str())
        .chain(front.iter().copied())
        .collect();
    (main, front)
}
#[derive(Clone, Debug, Serialize)]
pub struct Skipped {
    pub rule_id: String,
    pub rule_name: String,
    pub reason: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct Rendered {
    pub content: String,
    pub content_type: &'static str,
    pub entries: Vec<Entry>,
    pub skipped: Vec<Skipped>,
    #[serde(skip)]
    format: Format,
    /// Filled for public fetches; see [`Usage`].
    #[serde(skip)]
    pub usage: Usage,
}
impl Rendered {
    /// Surge keeps a profile updated only while its first line names the URL
    /// it came from; other formats are refreshed by the client's own setting.
    pub fn with_update_url(mut self, url: &str) -> Self {
        if self.format == Format::Surge {
            self.content.insert_str(
                0,
                &format!("#!MANAGED-CONFIG {url} interval=86400 strict=false\n"),
            );
        }
        self
    }
}

pub(crate) fn percent(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(byte as char);
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}
fn client_name(template: &Template, node: &str, rule: &str, port: u16, multiple: bool) -> String {
    let base = if template.name_prefix.is_empty() {
        format!("{node} · {rule}")
    } else {
        format!("{}{node} · {rule}", template.name_prefix)
    };
    if multiple {
        format!("{base} ({port})")
    } else {
        base
    }
}
fn surge_name(name: &str) -> String {
    name.replace([',', '\n', '\r'], " ").trim().to_owned()
}
fn uri(entry: &Entry) -> String {
    let userinfo = if entry.method.starts_with("2022-") {
        format!("{}:{}", percent(&entry.method), percent(&entry.password))
    } else {
        general_purpose::URL_SAFE_NO_PAD.encode(format!("{}:{}", entry.method, entry.password))
    };
    let host = if entry.host.contains(':') && !entry.host.starts_with('[') {
        format!("[{}]", entry.host)
    } else {
        entry.host.clone()
    };
    format!(
        "ss://{userinfo}@{host}:{}#{}",
        entry.port,
        percent(&entry.name)
    )
}
fn unique_names(entries: &mut [Entry]) {
    let mut counts = std::collections::HashMap::<String, usize>::new();
    for entry in entries {
        let seen = counts.entry(entry.name.clone()).or_insert(0);
        if *seen > 0 {
            entry.name = format!("{} #{}", entry.name, *seen + 1);
        }
        if let Some(outbound) = &mut entry.outbound {
            let key = if outbound.get("tag").is_some() {
                "tag"
            } else {
                "name"
            };
            outbound[key] = entry.name.clone().into();
        }
        *seen += 1;
    }
}
fn clash(entries: &[Entry]) -> Result<String> {
    use serde_yaml::{Mapping, Value};
    let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
    let groups = Groups::new(&names.iter().map(String::as_str).collect::<Vec<_>>());
    let mut proxies = vec![];
    for entry in entries {
        if let Some(proxy) = &entry.outbound {
            proxies.push(serde_yaml::to_value(proxy)?);
            continue;
        }
        let socks = entry.upstream.as_ref().map(|u| u.kind) == Some(UpstreamKind::Socks5);
        let mut proxy = Mapping::new();
        proxy.insert(Value::from("name"), Value::from(entry.name.clone()));
        proxy.insert(
            Value::from("type"),
            Value::from(if socks { "socks5" } else { "ss" }),
        );
        proxy.insert(Value::from("server"), Value::from(entry.host.clone()));
        proxy.insert(Value::from("port"), Value::from(entry.port));
        if socks {
            if let Some(Upstream {
                username: Some(user),
                password: Some(pass),
                ..
            }) = &entry.upstream
            {
                proxy.insert(Value::from("username"), Value::from(user.clone()));
                proxy.insert(Value::from("password"), Value::from(pass.clone()));
            }
        } else {
            proxy.insert(Value::from("cipher"), Value::from(entry.method.clone()));
            proxy.insert(Value::from("password"), Value::from(entry.password.clone()));
        }
        proxy.insert(Value::from("udp"), Value::from(entry.udp));
        if entry.udp_over_tcp {
            proxy.insert(Value::from("udp-over-tcp"), Value::from(true));
            proxy.insert(Value::from("udp-over-tcp-version"), Value::from(2));
        }
        if entry.chained {
            proxy.insert(Value::from("dialer-proxy"), Value::from(groups.via.clone()));
        }
        proxies.push(Value::Mapping(proxy));
    }
    let (main, front) = selection(entries, &names);
    let group = |name: &str, members: Vec<&str>| {
        let mut group = Mapping::new();
        group.insert(Value::from("name"), Value::from(name));
        group.insert(Value::from("type"), Value::from("select"));
        group.insert(
            Value::from("proxies"),
            Value::Sequence(members.into_iter().map(Value::from).collect()),
        );
        Value::Mapping(group)
    };
    let mut proxy_groups = vec![group(&groups.main, main)];
    if entries.iter().any(|e| e.chained) {
        proxy_groups.push(group(&groups.via, front));
    }
    let mut root = Mapping::new();
    root.insert(Value::from("proxies"), Value::Sequence(proxies));
    root.insert(Value::from("proxy-groups"), Value::Sequence(proxy_groups));
    root.insert(
        Value::from("rules"),
        Value::Sequence(vec![Value::from(format!("MATCH,{}", groups.main))]),
    );
    Ok(serde_yaml::to_string(&Value::Mapping(root))?)
}
fn surge(entries: &[Entry]) -> String {
    let mut names = Vec::with_capacity(entries.len());
    let mut counts = std::collections::HashMap::<String, usize>::new();
    for entry in entries {
        let mut name = surge_name(&entry.name);
        let seen = counts.entry(name.clone()).or_insert(0);
        if *seen > 0 {
            name = format!("{name} #{}", *seen + 1);
        }
        *seen += 1;
        names.push(name);
    }
    let groups = Groups::new(&names.iter().map(String::as_str).collect::<Vec<_>>());
    let mut taken = [names.as_slice(), &[groups.main.clone(), groups.via.clone()]].concat();
    let mut group = |base: &str| {
        let name = free_name(base, &taken.iter().map(String::as_str).collect::<Vec<_>>());
        taken.push(name.clone());
        name
    };
    let (auto, fallback, china) = (group("Auto"), group("Fallback"), group("Mainland China"));
    // A complete profile: Surge's Rule, Global and Direct outbound modes all
    // work on it as is. LAN and Apple system traffic stay direct, mainland
    // China defaults to direct through a group the user can switch, and the
    // rest goes to the main group.
    let mut out = String::from(
        "# Relay subscription\n[General]\nloglevel = notify\ndns-server = system\n\
         skip-proxy = 127.0.0.1, 192.168.0.0/16, 10.0.0.0/8, 172.16.0.0/12, 100.64.0.0/10, 169.254.0.0/16, localhost, *.local\n\
         exclude-simple-hostnames = true\n\
         internet-test-url = http://www.apple.com/library/test/success.html\n\
         proxy-test-url = http://www.gstatic.com/generate_204\n[Proxy]\n",
    );
    for (entry, name) in entries.iter().zip(&names) {
        let host = if entry.host.contains(':') && !entry.host.starts_with('[') {
            format!("[{}]", entry.host)
        } else {
            entry.host.clone()
        };
        let protocol = match &entry.upstream {
            Some(Upstream {
                kind: UpstreamKind::Socks5,
                username: Some(user),
                password: Some(pass),
                ..
            }) => {
                format!("socks5, {host}, {}, {user}, {pass}", entry.port)
            }
            Some(Upstream {
                kind: UpstreamKind::Socks5,
                ..
            }) => format!("socks5, {host}, {}", entry.port),
            _ => format!(
                "ss, {host}, {}, encrypt-method={}, password={}",
                entry.port, entry.method, entry.password
            ),
        };
        out.push_str(&format!("{name} = {protocol}, udp-relay={}", entry.udp));
        if entry.chained {
            out.push_str(&format!(", underlying-proxy={}", groups.via));
        }
        out.push('\n');
    }
    let (main, front) = selection(entries, &names);
    // The user's chained proxies come first, so they stay the default; without
    // them the default is the fastest relay entry.
    let chained = &main[..main.len() - front.len()];
    let front = front.join(", ");
    let choices = [chained, &[auto.as_str(), fallback.as_str()]].concat();
    out.push_str(&format!(
        "[Proxy Group]\n{} = select, {}, {front}\n{auto} = url-test, {front}\n{fallback} = fallback, {front}\n",
        groups.main,
        choices.join(", ")
    ));
    if !chained.is_empty() {
        out.push_str(&format!("{} = select, {front}\n", groups.via));
    }
    out.push_str(&format!(
        "{china} = select, DIRECT, {main}\n[Rule]\nRULE-SET,SYSTEM,DIRECT\nRULE-SET,LAN,DIRECT\n\
         DOMAIN-SUFFIX,cn,{china}\nGEOIP,CN,{china}\nFINAL,{main},dns-failed\n",
        main = groups.main
    ));
    out
}

/// Renders a stable snapshot of the candidate rules. Disabled rules and
/// non-Shadowsocks inbounds become explicit `skipped` reasons rather than
/// silently disappearing from a preview.
pub fn render(format: Format, template: &Template, candidates: &[Candidate]) -> Result<Rendered> {
    template.validate()?;
    let mut entries = vec![];
    let mut skipped = vec![];
    for candidate in candidates {
        let rule = &candidate.rule;
        if !rule.enabled {
            skipped.push(Skipped {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                reason: "rule is disabled".into(),
            });
            continue;
        }
        if !template.node_tags.is_empty()
            && !template
                .node_tags
                .iter()
                .any(|tag| candidate.node_tags.contains(tag))
        {
            skipped.push(Skipped {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                reason: "node tag is not selected".into(),
            });
            continue;
        }
        if let Some(gateway) = &rule.protocol_gateway {
            let skip = |reason: &str| Skipped {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                reason: reason.into(),
            };
            if !matches!(format, Format::SingBox | Format::Clash) {
                skipped.push(skip(
                    "managed protocol gateways require sing_box or Clash/mihomo subscription format",
                ));
                continue;
            }
            let host = if let Some(host) = &template.host {
                normalize_host(host)?
            } else if !gateway.listen.ip().is_unspecified() {
                gateway.listen.ip().to_string()
            } else {
                skipped.push(skip(
                    "gateway listener is wildcard; set a public template host",
                ));
                continue;
            };
            let name = client_name(
                template,
                &candidate.node_name,
                &rule.name,
                gateway.listen.port(),
                false,
            );
            let udp = template.udp && rule.protocol.udp();
            let mut outbound = if format == Format::Clash {
                gateway.mihomo_proxy(&host, &name, udp)?
            } else {
                gateway.client_outbound(&host, &name)?
            };
            if format == Format::SingBox
                && !udp
                && !matches!(
                    gateway.protocol,
                    crate::gateway::WireProtocol::AnyTls { .. }
                )
            {
                outbound["network"] = "tcp".into();
            }
            entries.push(Entry {
                name,
                host,
                port: gateway.listen.port(),
                method: gateway.protocol.kind().into(),
                password: String::new(),
                udp,
                udp_over_tcp: false,
                outbound: Some(outbound),
                chained: false,
                upstream: None,
            });
            continue;
        }
        let Some(shadowsocks) = &rule.inbound_shadowsocks else {
            skipped.push(Skipped {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                reason: "not a Shadowsocks inbound; a subscription client needs a proxy protocol"
                    .into(),
            });
            continue;
        };
        if !template.node_tags.is_empty()
            && !template
                .node_tags
                .iter()
                .any(|tag| candidate.node_tags.contains(tag))
        {
            skipped.push(Skipped {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                reason: "node tag is not selected".into(),
            });
            continue;
        }
        if format == Format::Surge
            && shadowsocks
                .password
                .chars()
                .any(|c| matches!(c, ',' | '\n' | '\r'))
        {
            skipped.push(Skipped {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                reason: "Surge cannot represent a comma or newline in the password".into(),
            });
            continue;
        }
        let start = rule.listen.port();
        let end = rule.listen_end_port.unwrap_or(start);
        let width = end.saturating_sub(start);
        let (advertise_host, advertise_port) = match &rule.advertise {
            Some(value) => {
                let (host, port) = crate::topology::endpoint(value)?;
                (Some(host), port)
            }
            None => (None, 0),
        };
        let override_host = match &template.host {
            Some(value) => Some(normalize_host(value)?),
            None => None,
        };
        let host = if let Some(host) = override_host {
            host
        } else if let Some(host) = advertise_host.as_deref() {
            host.to_owned()
        } else if !rule.listen.ip().is_unspecified() {
            rule.listen.ip().to_string()
        } else {
            skipped.push(Skipped {
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
                reason: "listener is wildcard and has no advertise or template host".into(),
            });
            continue;
        };
        for offset in 0..=width {
            let port = if advertise_host.is_some() {
                let Some(port) = advertise_port.checked_add(offset) else {
                    skipped.push(Skipped {
                        rule_id: rule.id.clone(),
                        rule_name: rule.name.clone(),
                        reason: "advertised port range overflows 65535".into(),
                    });
                    continue;
                };
                port
            } else {
                let Some(port) = start.checked_add(offset) else {
                    break;
                };
                port
            };
            entries.push(Entry {
                name: client_name(template, &candidate.node_name, &rule.name, port, width > 0),
                host: host.clone(),
                port,
                method: method_name(shadowsocks.method),
                password: shadowsocks.password.clone(),
                udp: template.udp
                    && (rule.protocol.udp()
                        || (shadowsocks.udp_over_tcp
                            && matches!(format, Format::SingBox | Format::Clash))),
                udp_over_tcp: template.udp && shadowsocks.udp_over_tcp,
                outbound: None,
                chained: false,
                upstream: None,
            });
        }
    }
    let relay_entries = entries.len();
    for upstream in &template.upstreams {
        let skip = |reason: &str| Skipped {
            rule_id: format!("upstream:{}", upstream.name),
            rule_name: upstream.name.clone(),
            reason: reason.into(),
        };
        if !matches!(format, Format::SingBox | Format::Clash | Format::Surge) {
            skipped.push(skip(
                "this format cannot express a proxy chain; use sing_box, Clash/mihomo or Surge",
            ));
            continue;
        }
        if relay_entries == 0 {
            skipped.push(skip("no relay node entry to connect through"));
            continue;
        }
        if format == Format::Surge
            && [&upstream.username, &upstream.password]
                .into_iter()
                .flatten()
                .any(|value| value.contains(','))
        {
            skipped.push(skip(
                "Surge cannot represent a comma in the upstream username or password",
            ));
            continue;
        }
        entries.push(Entry {
            name: upstream.name.clone(),
            host: normalize_host(&upstream.server)?,
            port: upstream.port,
            method: upstream
                .method
                .map(method_name)
                .unwrap_or_else(|| "socks5".into()),
            password: upstream.password.clone().unwrap_or_default(),
            udp: template.udp,
            chained: true,
            udp_over_tcp: false,
            outbound: None,
            upstream: Some(upstream.clone()),
        });
    }
    unique_names(&mut entries);
    let content_type = match format {
        Format::Clash => "text/yaml; charset=utf-8",
        Format::SingBox => "application/json; charset=utf-8",
        _ => "text/plain; charset=utf-8",
    };
    let content = match format {
        Format::SingBox => {
            let names: Vec<String> = entries.iter().map(|e| e.name.clone()).collect();
            // Selector names cannot collide with an arbitrary user-facing rule label.
            let groups = Groups::new(&names.iter().map(String::as_str).collect::<Vec<_>>());
            let mut outbounds: Vec<_> = entries.iter().map(|entry| entry.outbound.clone().unwrap_or_else(|| {
                let mut value = match &entry.upstream {
                    Some(upstream) if upstream.kind == UpstreamKind::Socks5 => {
                        let mut value = serde_json::json!({"type":"socks","tag":entry.name,"server":entry.host,"server_port":entry.port,"version":"5"});
                        if let (Some(user), Some(pass)) = (&upstream.username, &upstream.password) {
                            value["username"] = user.clone().into();
                            value["password"] = pass.clone().into();
                        }
                        value
                    }
                    _ => serde_json::json!({"type":"shadowsocks","tag":entry.name,"server":entry.host,"server_port":entry.port,"method":entry.method,"password":entry.password}),
                };
                if !entry.udp { value["network"] = "tcp".into(); }
                else if entry.udp_over_tcp { value["udp_over_tcp"] = serde_json::json!({"enabled":true,"version":2}); }
                // A detour replaces every other dial field, udp_fragment included.
                else if !entry.chained { value["udp_fragment"] = true.into(); }
                if entry.chained { value["detour"] = groups.via.clone().into(); }
                value
            })).collect();
            if entries.is_empty() {
                serde_json::to_string_pretty(
                    &serde_json::json!({"outbounds":[],"route":{"rules":[{"action":"reject"}]}}),
                )?
            } else {
                let (main, front) = selection(&entries, &names);
                outbounds.push(
                    serde_json::json!({"type":"selector","tag":groups.main,"outbounds":main}),
                );
                if entries.iter().any(|e| e.chained) {
                    outbounds.push(
                        serde_json::json!({"type":"selector","tag":groups.via,"outbounds":front}),
                    );
                }
                serde_json::to_string_pretty(
                    &serde_json::json!({"outbounds":outbounds,"route":{"final":groups.main}}),
                )?
            }
        }
        Format::Clash => clash(&entries)?,
        Format::Surge => surge(&entries),
        Format::V2ray => {
            let lines: Vec<String> = entries.iter().map(uri).collect();
            general_purpose::STANDARD.encode(lines.join("\n"))
        }
        Format::Shadowrocket => entries.iter().map(uri).collect::<Vec<_>>().join("\n"),
    };
    Ok(Rendered {
        content,
        content_type,
        entries,
        skipped,
        format,
        usage: Usage::default(),
    })
}
fn method_name(method: crate::shadowsocks::Method) -> String {
    serde_json::to_value(method)
        .ok()
        .and_then(|value| value.as_str().map(str::to_owned))
        .unwrap_or_else(|| format!("{method:?}"))
}

pub fn token() -> String {
    use rand::RngCore;
    let mut raw = [0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut raw);
    format!(
        "{TOKEN_PREFIX}{}",
        raw.iter().map(|b| format!("{b:02x}")).collect::<String>()
    )
}
pub fn token_hash(value: &str) -> String {
    use sha2::{Digest, Sha256};
    format!("{:x}", Sha256::digest(value.as_bytes()))
}
pub fn expiry(now: i64, days: u32) -> Result<i64> {
    ensure!(
        (1..=MAX_EXPIRY_DAYS).contains(&days),
        "subscription expiry must be 1..={MAX_EXPIRY_DAYS} days"
    );
    Ok(now.saturating_add(i64::from(days) * 86_400_000))
}
pub fn now() -> i64 {
    now_ms()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::model::{Protocol, Rule};

    fn rule() -> Rule {
        Rule {
            protocol_gateway: None,
            mptcp: None,
            inbound_multipath: None,
            outbound_multipath: None,
            health_check: None,
            budget_ids: vec![],
            id: "ss-rule".into(),
            tenant_id: "default".into(),
            owner_id: "user".into(),
            name: "Tokyo".into(),
            listen: "0.0.0.0:8388".parse().unwrap(),
            listen_end_port: None,
            port_mapping: crate::model::PortMapping::Fixed,
            outbound_bind: None,
            dns_cache: None,
            protocol: Protocol::Both,
            inbound_tls: None,
            inbound_proxy: None,
            inbound_websocket: None,
            inbound_shadowsocks: Some(crate::shadowsocks::ServerConfig {
                method: crate::shadowsocks::Method::Blake3Aes256Gcm,
                password: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".into(),
                allow_private_destinations: false,
                udp_over_tcp: false,
            }),
            inbound_socks5: None,
            inbound_http_connect: None,
            inbound_http2_connect: None,
            advertise: Some("edge.example.com:9000".into()),
            targets: vec![],
            balance: crate::model::Balance::WeightedRoundRobin,
            enabled: true,
            connect_timeout_ms: 1000,
            idle_timeout_secs: 10,
            max_connections: 128,
            udp_max_sessions: 64,
            quota_bytes: None,
            expires_at_ms: None,
            rate_bytes_per_sec: None,
            rate_limits: None,
            meter_epoch: "epoch".into(),
            allow_sources: vec![],
            allow_destinations: vec![],
            deny_destinations: vec![],
            allow_destination_ports: vec![],
            deny_destination_ports: vec![],
            deny_sources: vec![],
            reverse_tunnel: None,
        }
    }
    fn candidates() -> Vec<Candidate> {
        vec![Candidate {
            node_name: "edge".into(),
            node_tags: vec!["prod".into()],
            rule: rule(),
        }]
    }

    #[test]
    fn native_udp_profiles_allow_fragmentation_without_changing_tcp_only_profiles() {
        for udp in [true, false] {
            let template = Template {
                udp,
                ..Default::default()
            };
            let result = render(Format::SingBox, &template, &candidates()).unwrap();
            let value: serde_json::Value = serde_json::from_str(&result.content).unwrap();
            if udp {
                assert_eq!(value["outbounds"][0]["udp_fragment"], true);
            } else {
                assert!(value["outbounds"][0].get("udp_fragment").is_none());
            }
        }
    }

    #[test]
    fn optional_uot_is_exported_only_in_formats_that_represent_it() {
        let mut candidate = candidates().remove(0);
        candidate
            .rule
            .inbound_shadowsocks
            .as_mut()
            .unwrap()
            .udp_over_tcp = true;
        let sing = render(Format::SingBox, &Template::default(), &[candidate.clone()]).unwrap();
        let json: serde_json::Value = serde_json::from_str(&sing.content).unwrap();
        assert_eq!(json["outbounds"][0]["udp_over_tcp"]["version"], 2);
        let clash = render(Format::Clash, &Template::default(), &[candidate.clone()]).unwrap();
        assert!(clash.content.contains("udp-over-tcp: true"));
        let no_udp = Template {
            udp: false,
            ..Default::default()
        };
        let sing = render(Format::SingBox, &no_udp, &[candidate]).unwrap();
        let json: serde_json::Value = serde_json::from_str(&sing.content).unwrap();
        assert_eq!(json["outbounds"][0]["network"], "tcp");
        assert!(json["outbounds"][0].get("udp_over_tcp").is_none());
    }

    #[test]
    fn renders_each_format_and_keeps_skipped_rules_visible() {
        let template = Template {
            name_prefix: "Relay ".into(),
            host: None,
            node_tags: vec!["prod".into()],
            udp: true,
            upstreams: vec![],
        };
        let mut candidates = candidates();
        let mut plain = rule();
        plain.id = "plain".into();
        plain.inbound_shadowsocks = None;
        plain.targets.push(crate::model::Target {
            priority: 0,
            max_sessions: None,
            address: "127.0.0.1:9".into(),
            weight: 1,
            tls: None,
            proxy_protocol: None,
            websocket: None,
            via: None,
            prewarm: None,
            draining: false,
            paused: false,
            paused_until_ms: None,
        });
        candidates.push(Candidate {
            node_name: "edge".into(),
            node_tags: vec!["prod".into()],
            rule: plain,
        });
        let clash = render(Format::Clash, &template, &candidates).unwrap();
        let parsed: serde_yaml::Value = serde_yaml::from_str(&clash.content).unwrap();
        assert_eq!(parsed["proxies"][0]["server"], "edge.example.com");
        assert_eq!(parsed["proxies"][0]["port"], 9000);
        assert_eq!(parsed["proxies"][0]["cipher"], "2022-blake3-aes-256-gcm");
        assert_eq!(parsed["proxies"][0]["udp"], true);
        assert_eq!(clash.entries.len(), 1);
        assert_eq!(clash.skipped.len(), 1);
        assert!(clash.skipped[0].reason.contains("not a Shadowsocks"));

        let v2ray = render(Format::V2ray, &template, &candidates).unwrap();
        let lines = String::from_utf8(
            general_purpose::STANDARD
                .decode(v2ray.content.as_bytes())
                .unwrap(),
        )
        .unwrap();
        assert!(lines.starts_with("ss://2022-blake3-aes-256-gcm:"));
        assert!(lines.contains("@edge.example.com:9000#Relay%20edge%20%C2%B7%20Tokyo"));

        let surge = render(Format::Surge, &template, &candidates).unwrap();
        assert!(
            surge
                .content
                .contains("Relay edge · Tokyo = ss, edge.example.com, 9000")
        );
        assert!(surge.content.contains("udp-relay=true"));
        assert!(surge.skipped[0].reason.contains("not a Shadowsocks"));
        // A complete profile: Surge has no MATCH rule, and FINAL must come last.
        assert!(
            surge
                .content
                .starts_with("# Relay subscription\n[General]\n")
        );
        assert!(
            surge.content.ends_with(
                "[Proxy Group]\nRelay = select, Auto, Fallback, Relay edge · Tokyo\n\
             Auto = url-test, Relay edge · Tokyo\nFallback = fallback, Relay edge · Tokyo\n\
             Mainland China = select, DIRECT, Relay\n[Rule]\nRULE-SET,SYSTEM,DIRECT\n\
             RULE-SET,LAN,DIRECT\nDOMAIN-SUFFIX,cn,Mainland China\nGEOIP,CN,Mainland China\n\
             FINAL,Relay,dns-failed\n"
            ),
            "{}",
            surge.content
        );
        let url = "https://panel.example.com/sub/rsub_1";
        assert!(surge.clone().with_update_url(url).content.starts_with(
            "#!MANAGED-CONFIG https://panel.example.com/sub/rsub_1 interval=86400 strict=false\n# Relay subscription\n"
        ));
        assert_eq!(v2ray.clone().with_update_url(url).content, v2ray.content);
    }

    #[test]
    fn labels_and_hosts_are_validated_and_wildcards_are_skipped() {
        let template = Template {
            node_tags: vec!["no".into()],
            ..Template::default()
        };
        let rendered = render(Format::V2ray, &template, &candidates()).unwrap();
        assert!(rendered.entries.is_empty());
        assert!(rendered.skipped[0].reason.contains("node tag"));
        assert!(normalize_host("2001:db8::1").is_ok());
        assert!(normalize_host("https://edge.example").is_err());
        assert!(normalize_host("edge example").is_err());
        let mut wildcard = rule();
        wildcard.advertise = None;
        let candidate = vec![Candidate {
            node_name: "edge".into(),
            node_tags: vec![],
            rule: wildcard,
        }];
        let rendered = render(Format::V2ray, &Template::default(), &candidate).unwrap();
        assert!(rendered.entries.is_empty());
        assert!(rendered.skipped[0].reason.contains("wildcard"));
    }

    #[test]
    fn port_ranges_expand_and_names_stay_unique() {
        let mut rule = rule();
        rule.listen = "0.0.0.0:9000".parse().unwrap();
        rule.listen_end_port = Some(9002);
        rule.advertise = Some("edge.example.com:19000".into());
        let rendered = render(
            Format::Shadowrocket,
            &Template::default(),
            &[Candidate {
                node_name: "edge".into(),
                node_tags: vec![],
                rule,
            }],
        )
        .unwrap();
        assert_eq!(rendered.entries.len(), 3);
        assert_eq!(rendered.entries[0].port, 19000);
        assert_eq!(rendered.entries[2].port, 19002);
        assert_eq!(rendered.entries.len(), 3);
        for entry in &rendered.entries {
            assert!(entry.name.contains("(1900"));
        }
    }

    fn upstreams() -> Vec<Upstream> {
        vec![
            Upstream {
                name: "Home".into(),
                kind: UpstreamKind::Socks5,
                server: "home.example.net".into(),
                port: 1080,
                username: Some("alice".into()),
                password: Some("s3cret".into()),
                method: None,
            },
            // Named like the default group, so the groups have to move aside.
            Upstream {
                name: "Relay".into(),
                kind: UpstreamKind::Shadowsocks,
                server: "203.0.113.9".into(),
                port: 8388,
                username: None,
                password: Some("pw".into()),
                method: Some(crate::shadowsocks::Method::Aes256Gcm),
            },
        ]
    }

    #[test]
    fn upstreams_chain_through_relay_entries_in_formats_that_express_it() {
        let template = Template {
            upstreams: upstreams(),
            ..Default::default()
        };
        let front = "edge · Tokyo";

        let clash = render(Format::Clash, &template, &candidates()).unwrap();
        assert_eq!(clash.entries.iter().filter(|e| e.chained).count(), 2);
        let parsed: serde_yaml::Value = serde_yaml::from_str(&clash.content).unwrap();
        let proxies = parsed["proxies"].as_sequence().unwrap();
        assert_eq!(proxies.len(), 3);
        assert!(
            proxies[0].get("dialer-proxy").is_none(),
            "relay entries dial directly"
        );
        let home = &proxies[1];
        assert_eq!(home["type"], "socks5");
        assert_eq!(home["server"], "home.example.net");
        assert_eq!(home["port"], 1080);
        assert_eq!(home["username"], "alice");
        assert_eq!(home["password"], "s3cret");
        assert_eq!(proxies[2]["type"], "ss");
        assert_eq!(proxies[2]["cipher"], "aes-256-gcm");
        let via = home["dialer-proxy"].as_str().unwrap();
        assert_eq!(proxies[2]["dialer-proxy"], via);
        let groups = parsed["proxy-groups"].as_sequence().unwrap();
        let members = |name: &str| -> Vec<String> {
            let group = groups.iter().find(|g| g["name"] == name).unwrap();
            group["proxies"]
                .as_sequence()
                .unwrap()
                .iter()
                .map(|v| v.as_str().unwrap().to_owned())
                .collect()
        };
        let main = parsed["rules"][0]
            .as_str()
            .unwrap()
            .strip_prefix("MATCH,")
            .unwrap();
        assert!(
            !proxies
                .iter()
                .any(|p| p["name"] == main || p["name"] == via),
            "groups and proxies share one namespace"
        );
        assert_eq!(members(main), ["Home", "Relay", front]);
        assert_eq!(members(via), [front]);

        let sing = render(Format::SingBox, &template, &candidates()).unwrap();
        let json: serde_json::Value = serde_json::from_str(&sing.content).unwrap();
        let outbounds = json["outbounds"].as_array().unwrap();
        let tagged = |tag: &str| outbounds.iter().find(|o| o["tag"] == tag).unwrap();
        let home = tagged("Home");
        assert_eq!(home["type"], "socks");
        assert_eq!(home["version"], "5");
        assert_eq!(home["username"], "alice");
        assert!(home.get("udp_fragment").is_none());
        let via = home["detour"].as_str().unwrap();
        assert_eq!(tagged("Relay")["type"], "shadowsocks");
        assert_eq!(tagged("Relay")["detour"], via);
        assert!(tagged(front).get("detour").is_none());
        assert_eq!(tagged(via)["type"], "selector");
        assert_eq!(tagged(via)["outbounds"], serde_json::json!([front]));
        let main = json["route"]["final"].as_str().unwrap();
        assert_eq!(
            tagged(main)["outbounds"],
            serde_json::json!(["Home", "Relay", front])
        );

        let surge = render(Format::Surge, &template, &candidates()).unwrap();
        for line in [
            "\nHome = socks5, home.example.net, 1080, alice, s3cret, udp-relay=true, underlying-proxy=Relay entry\n",
            "\nRelay = ss, 203.0.113.9, 8388, encrypt-method=aes-256-gcm, password=pw, udp-relay=true, underlying-proxy=Relay entry\n",
            "[Proxy Group]\nRelay_ = select, Home, Relay, Auto, Fallback, edge · Tokyo\nAuto = url-test, edge · Tokyo\n\
             Fallback = fallback, edge · Tokyo\nRelay entry = select, edge · Tokyo\nMainland China = select, DIRECT, Relay_\n\
             [Rule]\nRULE-SET,SYSTEM,DIRECT\nRULE-SET,LAN,DIRECT\nDOMAIN-SUFFIX,cn,Mainland China\nGEOIP,CN,Mainland China\n\
             FINAL,Relay_,dns-failed\n",
        ] {
            assert!(surge.content.contains(line), "{}", surge.content);
        }

        for format in [Format::V2ray, Format::Shadowrocket] {
            let rendered = render(format, &template, &candidates()).unwrap();
            assert_eq!(rendered.entries.len(), 1);
            assert_eq!(rendered.skipped.len(), 2);
            assert!(
                rendered
                    .skipped
                    .iter()
                    .all(|s| s.reason.contains("proxy chain"))
            );
        }
        let alone = render(Format::Clash, &template, &[]).unwrap();
        assert!(alone.entries.is_empty());
        assert_eq!(alone.skipped.len(), 2);
        assert!(
            alone
                .skipped
                .iter()
                .all(|s| s.reason.contains("no relay node entry"))
        );
    }

    #[test]
    fn upstream_proxies_are_validated() {
        // Field names as API clients send them in POST /subscriptions.
        let key = general_purpose::STANDARD.encode([7u8; 16]);
        let parsed: Template = serde_json::from_value(serde_json::json!({"upstreams": [
            {"name": "Home", "type": "socks5", "server": "home.example.net", "port": 1080},
            {"name": "Office", "type": "shadowsocks", "server": "[2001:db8::7]", "port": 8388,
             "method": "2022-blake3-aes-128-gcm", "password": key},
        ]}))
        .unwrap();
        parsed.validate().unwrap();
        assert!(
            serde_json::from_value::<Template>(serde_json::json!({"upstreams": [
                {"name": "X", "type": "socks5", "server": "x.example", "port": 1, "uuid": "u"}
            ]}))
            .is_err()
        );
        // Records without upstreams stay readable by earlier releases.
        assert!(
            !serde_json::to_string(&Template::default())
                .unwrap()
                .contains("upstreams")
        );
        let rejected = |index: usize, change: fn(&mut Upstream)| {
            let mut template = Template {
                upstreams: upstreams(),
                ..Default::default()
            };
            template.validate().unwrap();
            change(&mut template.upstreams[index]);
            template.validate().is_err()
        };
        assert!(rejected(0, |u| u.password = None));
        assert!(rejected(0, |u| u.method =
            Some(crate::shadowsocks::Method::Aes256Gcm)));
        assert!(rejected(0, |u| u.server = "https://home.example.net".into()));
        assert!(rejected(0, |u| u.port = 0));
        assert!(rejected(0, |u| u.name = "Home ".into()));
        assert!(rejected(0, |u| u.username = Some("a\nb".into())));
        assert!(rejected(1, |u| u.method = None));
        assert!(rejected(1, |u| u.username = Some("bob".into())));
        assert!(rejected(1, |u| {
            u.method = Some(crate::shadowsocks::Method::Blake3Aes256Gcm)
        }));
        assert!(rejected(1, |u| u.name = "Home".into()));
        let too_many = Template {
            upstreams: (0..=MAX_UPSTREAMS)
                .map(|i| Upstream {
                    name: format!("p{i}"),
                    ..upstreams().remove(0)
                })
                .collect(),
            ..Default::default()
        };
        assert!(too_many.validate().is_err());
    }

    #[test]
    fn stored_records_load_unchanged_and_grace_ends_at_its_deadline() {
        // A record written before source lists and rotation grace existed.
        let stored = serde_json::json!({"id":"s","tenant_id":"default","owner_id":"admin","name":"phone","format":"v2ray","template":{"name_prefix":"","host":null,"node_tags":[],"udp":true},"token_hash":"aa","created_at_ms":1,"expires_at_ms":null,"last_used_ms":null,"uses":0});
        let mut record: Subscription = serde_json::from_value(stored.clone()).unwrap();
        assert_eq!(
            serde_json::to_value(&record).unwrap(),
            stored,
            "records that use neither feature keep their stored shape"
        );
        assert!(record.permits_source("198.51.100.1".parse().unwrap()));
        assert!(!record.accepts("bb", 0));
        record.previous_token_hash = Some("bb".into());
        record.previous_token_expires_at_ms = Some(1_000);
        assert!(record.accepts("aa", 5_000));
        assert!(record.accepts("bb", 999) && !record.accepts("bb", 1_000));
        assert!(!record.accepts("cc", 0));
        record.allow_sources = vec!["203.0.113.0/24".parse().unwrap()];
        assert!(record.permits_source("::ffff:203.0.113.1".parse().unwrap()));
        assert!(!record.permits_source("203.0.114.1".parse().unwrap()));

        assert_eq!(Usage::default().header(), None);
        let usage = Usage {
            used_bytes: Some(0),
            total_bytes: None,
            expires_at_ms: Some(1_999),
        };
        assert_eq!(usage.header().as_deref(), Some("download=0; expire=1"));
    }

    #[test]
    fn tokens_are_prefixed_hashed_and_expire() {
        let token = token();
        assert!(token.starts_with(TOKEN_PREFIX) && token.len() == TOKEN_PREFIX.len() + 64);
        assert_eq!(token_hash(&token).len(), 64);
        assert!(expiry(now(), 1).unwrap() > now());
        assert!(expiry(now(), 0).is_err());
        assert!(expiry(now(), MAX_EXPIRY_DAYS + 1).is_err());
    }
}
