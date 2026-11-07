//! Cross-panel sharing. An owner panel shares ports on one of its nodes with
//! another panel: a share fixes the node, a port range, how many rules and of
//! which kinds, the bandwidth, traffic and expiry, and which sources and
//! destinations its rules may use. The receiving panel redeems a one-time
//! invite for its own secret and asks for rules inside the share. The owner
//! renders every rule itself from the share, so a receiver can never widen
//! it, and revoking removes the rules from the node, whose engine then closes
//! their listeners. Agents need nothing new: shared rules are ordinary rules
//! with a rate, a budget, an expiry and source and destination lists. The
//! receiver pulls and the owner never calls it, so a receiving panel can sit
//! behind NAT.
use crate::model::{Protocol, RateLimits, Rule, identifier, validate_target};
use anyhow::{Context, Result, anyhow, ensure};
use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
use ipnet::IpNet;
use serde::{Deserialize, Serialize};
use std::{collections::HashSet, net::IpAddr, time::Duration};

pub const INVITE_PREFIX: &str = "relay-invite:v1:";
pub const INVITE_TTL_MS: i64 = 24 * 3600 * 1000;
pub const MAX_GRANTS: usize = 64;
pub const MAX_RULES: u16 = 32;
pub const MAX_PORTS: u32 = 1000;
/// Shared rules on the owner's nodes have ids with this prefix; nothing else may.
pub const RULE_PREFIX: &str = "fed-";
const METHOD: crate::shadowsocks::Method = crate::shadowsocks::Method::Blake3Aes128Gcm;
/// Destinations a shared rule may not reach unless the owner allows it: the
/// node itself and private networks behind it.
pub const PRIVATE: &[&str] = &[
    "0.0.0.0/8",
    "10.0.0.0/8",
    "100.64.0.0/10",
    "127.0.0.0/8",
    "169.254.0.0/16",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "::1/128",
    "fc00::/7",
    "fe80::/10",
];

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    /// Fixed targets, reachable only from the share's sources.
    Forward,
    /// A Shadowsocks 2022 server with a key the owner makes.
    Shadowsocks,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum State {
    Active,
    Paused,
    Revoked,
}

/// One share, kept by the owner.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Grant {
    pub id: String,
    pub name: String,
    pub node_id: String,
    /// Where the receiver's users connect: the node's public name or address.
    pub public_host: String,
    pub listen_ip: IpAddr,
    pub port_start: u16,
    pub port_end: u16,
    pub max_rules: u16,
    pub kinds: Vec<Kind>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rate_bytes_per_sec: Option<u64>,
    /// Upload and download limits of every rule of the share, and of the
    /// share's account across them, like `rate_bytes_per_sec`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_bytes_per_sec: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_bytes_per_sec: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub quota_bytes: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub expires_at_ms: Option<i64>,
    #[serde(default)]
    pub allow_sources: Vec<IpNet>,
    #[serde(default)]
    pub allow_destinations: Vec<String>,
    #[serde(default)]
    pub deny_destinations: Vec<String>,
    #[serde(default)]
    pub allow_private_destinations: bool,
    pub state: State,
    /// The disabled account that owns the share's rules, so its budget and
    /// rate apply to them.
    pub user_id: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_id: Option<String>,
    /// Changes whenever the receiver's view changes; rule writes name it.
    pub revision: u64,
    /// Rule ids are never reused, so usage history stays with its rule.
    pub next_rule: u64,
    #[serde(default)]
    pub rules: Vec<SharedRule>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub invite: Option<Invite>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub link: Option<Link>,
    /// The node revision that carries the newest rendering of the share.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub published_revision: Option<u64>,
    /// The node revision without the share's rules; once the node applies
    /// it, the old credentials no longer work there.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_revision: Option<u64>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct SharedRule {
    pub id: String,
    pub name: String,
    pub kind: Kind,
    pub protocol: Protocol,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<String>,
    /// Shadowsocks only: the base64 key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}
/// Secret hashes are stored but never shown: views clear them, and an empty
/// hash is left out.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Invite {
    pub id: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub secret_sha256: String,
    pub expires_at_ms: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Link {
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub secret_sha256: String,
    pub panel_id: String,
    pub redeemed_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_seen_ms: Option<i64>,
    /// The newest statement the receiver confirmed.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ack: Option<Statement>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantInput {
    pub name: String,
    /// Fixed once the share exists.
    #[serde(default)]
    pub node_id: Option<String>,
    pub public_host: String,
    #[serde(default)]
    pub listen_ip: Option<String>,
    pub port_start: u16,
    pub port_end: u16,
    pub max_rules: u16,
    pub kinds: Vec<Kind>,
    #[serde(default)]
    pub rate_bytes_per_sec: Option<u64>,
    #[serde(default)]
    pub upload_bytes_per_sec: Option<u64>,
    #[serde(default)]
    pub download_bytes_per_sec: Option<u64>,
    #[serde(default)]
    pub quota_bytes: Option<u64>,
    #[serde(default)]
    pub expires_at_ms: Option<i64>,
    #[serde(default)]
    pub allow_sources: Vec<String>,
    #[serde(default)]
    pub allow_destinations: Vec<String>,
    #[serde(default)]
    pub deny_destinations: Vec<String>,
    #[serde(default)]
    pub allow_private_destinations: bool,
}

/// A rule the receiver asks for. Everything else comes from the share.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RuleRequest {
    /// An existing rule's id keeps its id and key.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub id: Option<String>,
    pub name: String,
    pub kind: Kind,
    pub protocol: Protocol,
    pub port: u16,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub targets: Vec<String>,
}

/// Traffic the owner metered for a share, from its node's durable counters.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Statement {
    pub as_of_ms: i64,
    pub upload_bytes: u64,
    pub download_bytes: u64,
}
impl Statement {
    pub fn total(&self) -> u64 {
        self.upload_bytes.saturating_add(self.download_bytes)
    }
}

/// What the receiving panel sees of a share. Unknown fields are ignored, so
/// a newer owner can add some.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Shared {
    pub grant_id: String,
    pub owner_panel_id: String,
    pub name: String,
    pub public_host: String,
    pub port_start: u16,
    pub port_end: u16,
    pub max_rules: u16,
    pub kinds: Vec<Kind>,
    #[serde(default)]
    pub rate_bytes_per_sec: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub upload_bytes_per_sec: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub download_bytes_per_sec: Option<u64>,
    #[serde(default)]
    pub quota_bytes: Option<u64>,
    #[serde(default)]
    pub quota_used_bytes: Option<u64>,
    #[serde(default)]
    pub expires_at_ms: Option<i64>,
    #[serde(default)]
    pub allow_sources: Vec<IpNet>,
    pub state: State,
    pub revision: u64,
    #[serde(default)]
    pub rules: Vec<SharedRule>,
    /// The node runs the newest rules.
    #[serde(default)]
    pub applied: bool,
    #[serde(default)]
    pub statement: Statement,
}

/// One share received from another panel.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Remote {
    pub id: String,
    pub owner_url: String,
    pub owner_panel_id: String,
    pub grant_id: String,
    /// Sent to the owner on every request, so it is kept reversibly and only
    /// system administrators read it; views clear it.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub secret: String,
    pub label: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shared: Option<Shared>,
    /// The highest traffic the owner has reported; owner counters never go
    /// down, so a lower statement means the owner restored older data.
    #[serde(default)]
    pub high: Statement,
    #[serde(default)]
    pub rollback: bool,
    #[serde(default)]
    pub revoked: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_synced_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub added_at_ms: i64,
}

/// A share as the owner's panel lists it.
#[derive(Clone, Debug, Serialize)]
pub struct GrantView {
    #[serde(flatten)]
    pub grant: Grant,
    pub node_name: String,
    pub statement: Statement,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub quota_used_bytes: Option<u64>,
    /// The node runs the share's newest rules (or, once revoked, none).
    pub applied: bool,
    /// The receiver confirmed more traffic than the owner now records, so
    /// the owner's data was probably restored from an older backup.
    pub ack_mismatch: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct View {
    pub enabled: bool,
    pub panel_id: String,
    pub grants: Vec<GrantView>,
    pub remotes: Vec<Remote>,
}

/// A new invite code, shown once.
#[derive(Debug, Serialize)]
pub struct Issued {
    pub code: String,
    pub expires_at_ms: i64,
}
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RemoteInput {
    pub invite: String,
    #[serde(default)]
    pub label: String,
}

#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RedeemRequest {
    pub invite_id: String,
    pub invite_secret: String,
    pub panel_id: String,
}
#[derive(Debug, Serialize, Deserialize)]
pub struct Redeemed {
    pub secret: String,
    pub shared: Shared,
}
#[derive(Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RulesRequest {
    pub expected_revision: u64,
    pub rules: Vec<RuleRequest>,
}

#[derive(Serialize, Deserialize)]
struct Code {
    u: String,
    i: String,
    s: String,
}
/// `relay-invite:v1:` and the owner's address, the invite id and its secret.
pub fn invite_code(owner_url: &str, id: &str, secret: &str) -> String {
    let code = Code {
        u: owner_url.into(),
        i: id.into(),
        s: secret.into(),
    };
    format!(
        "{INVITE_PREFIX}{}",
        URL_SAFE_NO_PAD.encode(serde_json::to_vec(&code).expect("invite serializes"))
    )
}
/// The owner's address, the invite id and its secret.
pub fn parse_invite(code: &str) -> Result<(reqwest::Url, String, String)> {
    let wrong = || {
        anyhow!(
            "this is not a Relay invite code; copy the whole code that starts with {INVITE_PREFIX}"
        )
    };
    let body = code.trim().strip_prefix(INVITE_PREFIX).ok_or_else(wrong)?;
    let code: Code = URL_SAFE_NO_PAD
        .decode(body)
        .ok()
        .and_then(|bytes| serde_json::from_slice(&bytes).ok())
        .ok_or_else(wrong)?;
    ensure!(
        identifier(&code.i) && code.s.len() == 64,
        "the invite code is damaged"
    );
    Ok((crate::agent::controller_url(&code.u)?, code.i, code.s))
}

/// A share's address for users: a host name, or an IP address without port.
pub fn public_host(text: &str) -> Result<String> {
    let text = text.trim().trim_end_matches('.').to_ascii_lowercase();
    if let Ok(ip) = text.trim_matches(['[', ']']).parse::<IpAddr>() {
        return Ok(ip.to_string());
    }
    let labels: Vec<&str> = text.split('.').collect();
    ensure!(
        text.len() <= 253
            && labels.len() >= 2
            && labels.iter().all(|l| {
                (1..=63).contains(&l.len())
                    && !l.starts_with('-')
                    && !l.ends_with('-')
                    && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            }),
        "the public address must be the node's host name or IP address, without a port"
    );
    Ok(text)
}

/// The node rule for one shared rule.
pub fn render(grant: &Grant, rule: &SharedRule, tenant: &str) -> Rule {
    let mut deny = grant.deny_destinations.clone();
    if !grant.allow_private_destinations {
        deny.extend(PRIVATE.iter().map(|p| p.to_string()));
    }
    let shadowsocks = (rule.kind == Kind::Shadowsocks)
        .then(|| serde_json::json!({"method": METHOD, "password": rule.password, "allow_private_destinations": grant.allow_private_destinations}));
    serde_json::from_value(serde_json::json!({
        "id": rule.id,
        "tenant_id": tenant,
        "owner_id": grant.user_id,
        "name": format!("{} · {}", grant.name, rule.name),
        "listen": std::net::SocketAddr::new(grant.listen_ip, rule.port),
        "protocol": rule.protocol,
        "inbound_shadowsocks": shadowsocks,
        "targets": rule.targets.iter().map(|t| serde_json::json!({"address": t})).collect::<Vec<_>>(),
        "enabled": grant.state == State::Active,
        "expires_at_ms": grant.expires_at_ms,
        "rate_bytes_per_sec": grant.rate_bytes_per_sec,
        "rate_limits": RateLimits::normalized(Some(RateLimits {
            upload_bytes_per_sec: grant.upload_bytes_per_sec,
            download_bytes_per_sec: grant.download_bytes_per_sec,
            ..Default::default()
        })),
        "meter_epoch": format!("fed-{}", grant.id),
        "allow_sources": grant.allow_sources,
        "allow_destinations": grant.allow_destinations,
        "deny_destinations": deny,
    }))
    .expect("a shared rule is a valid rule")
}

/// Why a receiver's rules were refused: `Wider` asks for more than the share
/// allows (403); `Invalid` is malformed (400).
#[derive(Debug)]
pub enum Refusal {
    Wider(String),
    Invalid(String),
}
/// The share's rules after the receiver's request. Existing rules keep their
/// id and key; new ones get fresh ones. `key` makes a Shadowsocks key.
pub fn requested_rules(
    grant: &mut Grant,
    requests: Vec<RuleRequest>,
    key: impl Fn() -> String,
) -> std::result::Result<Vec<SharedRule>, Refusal> {
    use Refusal::*;
    if requests.len() > usize::from(grant.max_rules) {
        return Err(Wider(format!(
            "the share allows at most {} rule(s)",
            grant.max_rules
        )));
    }
    let mut ports = HashSet::new();
    let mut rules = vec![];
    for request in requests {
        let name = request.name.trim().to_string();
        if name.is_empty() || name.chars().count() > 64 {
            return Err(Invalid("a rule name needs 1..64 characters".into()));
        }
        if !grant.kinds.contains(&request.kind) {
            return Err(Wider(format!(
                "the share does not allow {} rules",
                match request.kind {
                    Kind::Forward => "forwarding",
                    Kind::Shadowsocks => "Shadowsocks",
                }
            )));
        }
        if !(grant.port_start..=grant.port_end).contains(&request.port) {
            return Err(Wider(format!(
                "port {} is outside the shared range {}–{}",
                request.port, grant.port_start, grant.port_end
            )));
        }
        if !ports.insert(request.port) {
            return Err(Invalid(format!("port {} is used twice", request.port)));
        }
        let targets: Vec<String> = request
            .targets
            .iter()
            .map(|t| t.trim().to_string())
            .collect();
        match request.kind {
            Kind::Forward => {
                if targets.is_empty() || targets.len() > 8 {
                    return Err(Invalid("a forwarding rule needs 1..8 targets".into()));
                }
                for target in &targets {
                    validate_target(target)
                        .map_err(|e| Invalid(format!("target {target}: {e:#}")))?;
                }
            }
            Kind::Shadowsocks => {
                if !targets.is_empty() {
                    return Err(Invalid(
                        "a Shadowsocks rule has no targets; each client names its destination"
                            .into(),
                    ));
                }
                if request.protocol == Protocol::Udp {
                    return Err(Invalid("Shadowsocks needs TCP".into()));
                }
            }
        }
        let existing = request.id.as_ref().and_then(|id| {
            grant
                .rules
                .iter()
                .find(|r| &r.id == id && r.kind == request.kind)
        });
        let id = match existing {
            Some(rule) => rule.id.clone(),
            None => {
                grant.next_rule += 1;
                format!("{RULE_PREFIX}{}-{}", grant.id, grant.next_rule)
            }
        };
        let password = (request.kind == Kind::Shadowsocks).then(|| {
            existing
                .and_then(|r| r.password.clone())
                .unwrap_or_else(&key)
        });
        rules.push(SharedRule {
            id,
            name,
            kind: request.kind,
            protocol: request.protocol,
            port: request.port,
            targets,
            password,
        });
    }
    Ok(rules)
}

/// A new Shadowsocks 2022 key for the method shared rules use.
pub fn shadowsocks_key() -> String {
    let mut key = [0u8; 16];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
    base64::engine::general_purpose::STANDARD.encode(key)
}

/// Checks the owner's limits on a share.
pub fn check_input(input: &GrantInput) -> Result<()> {
    let name = input.name.trim();
    ensure!(
        !name.is_empty() && name.chars().count() <= 64,
        "the name needs 1..64 characters"
    );
    ensure!(
        input.port_start >= 1 && input.port_start <= input.port_end,
        "choose a port range such as 20000–20009"
    );
    ensure!(
        u32::from(input.port_end - input.port_start) < MAX_PORTS,
        "a share covers at most {MAX_PORTS} ports"
    );
    ensure!(
        (1..=MAX_RULES).contains(&input.max_rules)
            && u32::from(input.max_rules) <= u32::from(input.port_end - input.port_start) + 1,
        "allow 1..{MAX_RULES} rules, and no more than the range has ports"
    );
    let kinds: HashSet<_> = input.kinds.iter().collect();
    ensure!(
        !kinds.is_empty() && kinds.len() == input.kinds.len(),
        "choose forwarding, Shadowsocks or both, each once"
    );
    ensure!(
        input.allow_sources.len() <= 64
            && input.allow_destinations.len() <= 64
            && input.deny_destinations.len() <= 64,
        "at most 64 entries per list"
    );
    for source in &input.allow_sources {
        source
            .trim()
            .parse::<IpNet>()
            .or_else(|_| source.trim().parse::<IpAddr>().map(IpNet::from))
            .with_context(|| format!("{source} is not an IP address or range"))?;
    }
    ensure!(
        !input.kinds.contains(&Kind::Forward) || !input.allow_sources.is_empty(),
        "forwarding needs the source addresses that may connect; anyone could use it otherwise"
    );
    crate::destination_acl::DestinationPolicy::parse(
        &input.allow_destinations,
        &input.deny_destinations,
    )?;
    for rate in [
        input.rate_bytes_per_sec,
        input.upload_bytes_per_sec,
        input.download_bytes_per_sec,
    ] {
        ensure!(
            rate.is_none_or(|r| {
                (crate::store::MIN_USER_RATE..=crate::store::MAX_USER_RATE).contains(&r)
            }),
            "the bandwidth must be at least 1 KiB/s"
        );
    }
    ensure!(
        input.quota_bytes.is_none_or(|q| q >= 1 << 20),
        "the traffic limit must be at least 1 MiB"
    );
    Ok(())
}
pub fn sources(input: &GrantInput) -> Vec<IpNet> {
    input
        .allow_sources
        .iter()
        .filter_map(|s| {
            s.trim()
                .parse::<IpNet>()
                .ok()
                .or_else(|| s.trim().parse::<IpAddr>().ok().map(IpNet::from))
        })
        .collect()
}

/// A receiver's request to the owner failed: `revoked` when the owner no
/// longer accepts this share's secret.
#[derive(Clone, Debug)]
pub struct PeerError {
    pub revoked: bool,
    /// The owner's HTTP status, when it answered.
    pub status: Option<u16>,
    pub message: String,
}
impl std::fmt::Display for PeerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.message)
    }
}

pub fn client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(15))
        .redirect(reqwest::redirect::Policy::none())
        .build()
        .expect("sharing HTTP client")
}
async fn answer<T: serde::de::DeserializeOwned>(
    response: reqwest::Result<reqwest::Response>,
) -> std::result::Result<T, PeerError> {
    let failed = |message: String| PeerError {
        revoked: false,
        status: None,
        message,
    };
    let response = response.map_err(|e| failed(format!("the owner panel is unreachable: {e}")))?;
    let status = response.status();
    let body = response
        .bytes()
        .await
        .map_err(|e| failed(format!("the owner panel's reply broke off: {e}")))?;
    if body.len() > 1 << 20 {
        return Err(failed("the owner panel's reply is too large".into()));
    }
    if !status.is_success() {
        let message = serde_json::from_slice::<serde_json::Value>(&body)
            .ok()
            .and_then(|v| v["error"].as_str().map(str::to_string))
            .unwrap_or_else(|| format!("HTTP {status}"));
        return Err(PeerError {
            revoked: status == reqwest::StatusCode::UNAUTHORIZED,
            status: Some(status.as_u16()),
            message: format!("the owner panel refused: {message}"),
        });
    }
    serde_json::from_slice(&body).map_err(|e| failed(format!("unreadable reply: {e}")))
}
fn peer(owner: &str, path: &str) -> String {
    format!(
        "{}/api/v1/federation/peer/{path}",
        owner.trim_end_matches('/')
    )
}
pub async fn redeem(
    client: &reqwest::Client,
    owner: &str,
    request: &RedeemRequest,
) -> std::result::Result<Redeemed, PeerError> {
    answer(
        client
            .post(peer(owner, "redeem"))
            .json(request)
            .send()
            .await,
    )
    .await
}
pub async fn fetch(
    client: &reqwest::Client,
    remote: &Remote,
) -> std::result::Result<Shared, PeerError> {
    answer(
        client
            .get(peer(&remote.owner_url, "grant"))
            .bearer_auth(&remote.secret)
            .send()
            .await,
    )
    .await
}
pub async fn put_rules(
    client: &reqwest::Client,
    remote: &Remote,
    request: &RulesRequest,
) -> std::result::Result<Shared, PeerError> {
    answer(
        client
            .put(peer(&remote.owner_url, "grant/rules"))
            .bearer_auth(&remote.secret)
            .json(request)
            .send()
            .await,
    )
    .await
}
pub async fn ack(
    client: &reqwest::Client,
    remote: &Remote,
    statement: &Statement,
) -> std::result::Result<serde_json::Value, PeerError> {
    answer(
        client
            .post(peer(&remote.owner_url, "grant/ack"))
            .bearer_auth(&remote.secret)
            .json(statement)
            .send()
            .await,
    )
    .await
}

/// Pulls one received share and confirms its statement to the owner.
pub async fn sync(
    store: &crate::store::Store,
    client: &reqwest::Client,
    id: &str,
) -> Result<Remote> {
    let db = store.clone();
    let remote_id = id.to_string();
    let remote =
        tokio::task::spawn_blocking(move || db.federation_remote_access(&remote_id)).await??;
    let outcome = fetch(client, &remote).await;
    if let Ok(shared) = &outcome {
        let _ = ack(client, &remote, &shared.statement).await;
    }
    let db = store.clone();
    let remote_id = id.to_string();
    tokio::task::spawn_blocking(move || db.record_federation_remote(&remote_id, outcome)).await?
}

/// Pulls every received share once per `tick`.
pub async fn run(
    store: crate::store::Store,
    tick: Duration,
    stop: tokio_util::sync::CancellationToken,
) {
    let client = client();
    let mut interval = tokio::time::interval(tick);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            _ = stop.cancelled() => return,
            _ = interval.tick() => {}
        }
        let db = store.clone();
        let Ok(Ok(ids)) = tokio::task::spawn_blocking(move || db.federation_remote_ids()).await
        else {
            continue;
        };
        for id in ids {
            if let Err(error) = sync(&store, &client, &id).await {
                tracing::warn!(%error, remote = %id, "shared resource not synchronized");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn grant() -> Grant {
        Grant {
            id: "0f1e2d3c-0000-4000-8000-000000000000".into(),
            name: "Tokyo".into(),
            node_id: "node".into(),
            public_host: "tyo.example.com".into(),
            listen_ip: "0.0.0.0".parse().unwrap(),
            port_start: 20000,
            port_end: 20009,
            max_rules: 2,
            kinds: vec![Kind::Shadowsocks],
            rate_bytes_per_sec: Some(1 << 20),
            upload_bytes_per_sec: None,
            download_bytes_per_sec: None,
            quota_bytes: None,
            expires_at_ms: Some(1_900_000_000_000),
            allow_sources: vec!["198.51.100.0/24".parse().unwrap()],
            allow_destinations: vec![],
            deny_destinations: vec!["example.org".into()],
            allow_private_destinations: false,
            state: State::Active,
            user_id: "share-user".into(),
            budget_id: None,
            revision: 1,
            next_rule: 0,
            rules: vec![],
            invite: None,
            link: None,
            published_revision: None,
            revoked_revision: None,
            created_at_ms: 0,
            updated_at_ms: 0,
        }
    }
    fn request(kind: Kind, port: u16) -> RuleRequest {
        RuleRequest {
            id: None,
            name: format!("rule {port}"),
            kind,
            protocol: Protocol::Tcp,
            port,
            targets: if kind == Kind::Forward {
                vec!["203.0.113.9:443".into()]
            } else {
                vec![]
            },
        }
    }

    #[test]
    fn invite_codes_round_trip_and_reject_damage() {
        let secret = "ab".repeat(32);
        let code = invite_code("https://panel.example.com/", "invite-1", &secret);
        assert!(code.starts_with(INVITE_PREFIX));
        let (url, id, parsed) = parse_invite(&format!("  {code}\n")).unwrap();
        assert_eq!(
            (url.as_str(), id.as_str(), parsed.as_str()),
            ("https://panel.example.com/", "invite-1", secret.as_str())
        );
        assert!(parse_invite(&code[..code.len() - 4]).is_err());
        assert!(parse_invite("relay-invite:v2:abc").is_err());
        // Plain HTTP only on loopback, as for agents.
        let insecure = invite_code("http://panel.example.com/", "invite-1", &secret);
        assert!(parse_invite(&insecure).is_err());
        assert!(parse_invite(&invite_code("http://127.0.0.1:9/", "i", &secret)).is_ok());
    }

    #[test]
    fn requests_cannot_widen_the_share() {
        let mut g = grant();
        let key = || "KEY".to_string();
        for (requests, why) in [
            (
                vec![request(Kind::Shadowsocks, 20000); 3],
                "at most 2 rule(s)",
            ),
            (
                vec![request(Kind::Forward, 20000)],
                "does not allow forwarding",
            ),
            (
                vec![request(Kind::Shadowsocks, 20010)],
                "outside the shared range",
            ),
        ] {
            match requested_rules(&mut g, requests, key) {
                Err(Refusal::Wider(message)) => assert!(message.contains(why), "{message}"),
                other => panic!("{other:?}"),
            }
        }
        let twice = vec![
            request(Kind::Shadowsocks, 20001),
            request(Kind::Shadowsocks, 20001),
        ];
        assert!(matches!(
            requested_rules(&mut g, twice, key),
            Err(Refusal::Invalid(_))
        ));
    }

    #[test]
    fn rendered_rules_carry_every_limit_and_keep_ids_and_keys() {
        const KEY_1: &str = "AAAAAAAAAAAAAAAAAAAAAA==";
        const KEY_2: &str = "AQEBAQEBAQEBAQEBAQEBAQ==";
        let mut g = grant();
        let first = requested_rules(&mut g, vec![request(Kind::Shadowsocks, 20003)], || {
            KEY_1.into()
        })
        .unwrap();
        assert_eq!(first[0].id, format!("fed-{}-1", g.id));
        g.rules = first.clone();
        // The same rule named again keeps its key; a new one gets a new id.
        let mut again = request(Kind::Shadowsocks, 20004);
        again.id = Some(first[0].id.clone());
        let next = requested_rules(
            &mut g,
            vec![again, request(Kind::Shadowsocks, 20005)],
            || KEY_2.into(),
        )
        .unwrap();
        assert_eq!(
            next.iter()
                .map(|r| (r.id.clone(), r.port, r.password.clone().unwrap()))
                .collect::<Vec<_>>(),
            [
                (first[0].id.clone(), 20004, KEY_1.into()),
                (format!("fed-{}-2", g.id), 20005, KEY_2.into()),
            ]
        );
        let rule = render(&g, &next[0], "tenant");
        rule.validate().unwrap();
        assert_eq!(
            (
                rule.owner_id.as_str(),
                rule.listen.to_string(),
                rule.rate_bytes_per_sec,
                rule.expires_at_ms,
                rule.enabled
            ),
            (
                "share-user",
                "0.0.0.0:20004".into(),
                Some(1 << 20),
                Some(1_900_000_000_000),
                true
            )
        );
        assert_eq!(rule.allow_sources, g.allow_sources);
        assert!(rule.deny_destinations.contains(&"example.org".to_string()));
        assert!(rule.deny_destinations.contains(&"127.0.0.0/8".to_string()));
        let shadowsocks = rule.inbound_shadowsocks.unwrap();
        assert!(!shadowsocks.allow_private_destinations && shadowsocks.password == KEY_1);
        g.state = State::Paused;
        g.allow_private_destinations = true;
        let paused = render(&g, &next[0], "tenant");
        assert!(!paused.enabled && !paused.deny_destinations.contains(&"10.0.0.0/8".into()));
        assert!(
            paused
                .inbound_shadowsocks
                .unwrap()
                .allow_private_destinations
        );
    }
}
