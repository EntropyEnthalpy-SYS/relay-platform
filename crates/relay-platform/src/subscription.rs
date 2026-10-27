//! Client subscription rendering. A subscription is a named snapshot of the
//! rules a user owns, rendered for common clients. It never contains controller
//! credentials; the public token is an independent, revocable subscription key.
use crate::model::{Rule, now_ms};
use anyhow::{Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose};
use serde::{Deserialize, Serialize};
use std::net::IpAddr;

pub const TOKEN_PREFIX: &str = "rsub_";
pub const MAX_SUBSCRIPTIONS: usize = 20;
pub const MAX_EXPIRY_DAYS: u32 = 3650;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Format {
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
}
impl Default for Template {
    fn default() -> Self {
        Self {
            name_prefix: String::new(),
            host: None,
            node_tags: vec![],
            udp: true,
        }
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
        }
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
}

fn percent(value: &str) -> String {
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
        *seen += 1;
    }
}
fn clash(entries: &[Entry]) -> Result<String> {
    use serde_yaml::{Mapping, Value};
    let mut proxies = vec![];
    for entry in entries {
        let mut proxy = Mapping::new();
        proxy.insert(Value::from("name"), Value::from(entry.name.clone()));
        proxy.insert(Value::from("type"), Value::from("ss"));
        proxy.insert(Value::from("server"), Value::from(entry.host.clone()));
        proxy.insert(Value::from("port"), Value::from(entry.port));
        proxy.insert(Value::from("cipher"), Value::from(entry.method.clone()));
        proxy.insert(Value::from("password"), Value::from(entry.password.clone()));
        proxy.insert(Value::from("udp"), Value::from(entry.udp));
        proxies.push(Value::Mapping(proxy));
    }
    let names: Vec<Value> = entries
        .iter()
        .map(|entry| Value::from(entry.name.clone()))
        .collect();
    let mut group = Mapping::new();
    group.insert(Value::from("name"), Value::from("Relay"));
    group.insert(Value::from("type"), Value::from("select"));
    group.insert(Value::from("proxies"), Value::Sequence(names));
    let mut root = Mapping::new();
    root.insert(Value::from("proxies"), Value::Sequence(proxies));
    root.insert(
        Value::from("proxy-groups"),
        Value::Sequence(vec![Value::Mapping(group)]),
    );
    root.insert(
        Value::from("rules"),
        Value::Sequence(vec![Value::from("MATCH,Relay")]),
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
    let mut out = String::from("# Relay subscription\n[Proxy]\n");
    for (entry, name) in entries.iter().zip(&names) {
        out.push_str(&format!(
            "{} = ss, {}, {}, encrypt-method={}, password={}, udp-relay={}\n",
            name,
            if entry.host.contains(':') && !entry.host.starts_with('[') {
                format!("[{}]", entry.host)
            } else {
                entry.host.clone()
            },
            entry.port,
            entry.method,
            entry.password,
            entry.udp
        ));
    }
    out.push_str("[Proxy Group]\nRelay = select");
    for name in &names {
        out.push_str(", ");
        out.push_str(name);
    }
    out.push_str("\n[Rule]\nMATCH,Relay\n");
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
                udp: template.udp && rule.protocol.udp(),
            });
        }
    }
    unique_names(&mut entries);
    let content_type = match format {
        Format::Clash => "text/yaml; charset=utf-8",
        _ => "text/plain; charset=utf-8",
    };
    let content = match format {
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
            }),
            inbound_socks5: None,
            inbound_http_connect: None,
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
            meter_epoch: "epoch".into(),
            allow_sources: vec![],
            allow_destinations: vec![],
            deny_destinations: vec![],
            allow_destination_ports: vec![],
            deny_destination_ports: vec![],
            deny_sources: vec![],
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
    fn renders_each_format_and_keeps_skipped_rules_visible() {
        let template = Template {
            name_prefix: "Relay ".into(),
            host: None,
            node_tags: vec!["prod".into()],
            udp: true,
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
