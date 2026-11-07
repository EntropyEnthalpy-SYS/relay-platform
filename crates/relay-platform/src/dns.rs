//! DNS provider records, observation/apply reconciliation and DDNS.
//!
//! Provider credentials are reversible by nature (the controller must call the
//! provider API), so they live in metadata and are visible only to system
//! administrators. Reads return a redacted view. This module deliberately does
//! not claim DNS propagation: it records what the provider API accepted.
use crate::store::Store;
use anyhow::{Context, Result, bail, ensure};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashMap, HashSet},
    fmt,
    net::{IpAddr, Ipv4Addr, Ipv6Addr},
    sync::{Arc, Mutex},
    time::Duration,
};

/// Upper bound of a zone's `failover_confirm_secs`.
pub const MAX_FAILOVER_CONFIRM_SECS: u32 = 1800;
/// Confirmation window of zones created without an explicit value.
pub const DEFAULT_FAILOVER_CONFIRM_SECS: u32 = 60;
/// Webhook request timeout without an explicit `timeout_secs`.
pub const WEBHOOK_DEFAULT_TIMEOUT_SECS: u32 = 15;
/// Upper bound of a webhook provider's `timeout_secs`.
pub const WEBHOOK_MAX_TIMEOUT_SECS: u32 = 30;
/// Shortest webhook secret, in UTF-8 bytes.
pub const WEBHOOK_MIN_SECRET_BYTES: usize = 32;
/// Most zones one webhook provider lists.
pub const WEBHOOK_MAX_ZONES: usize = 100;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Cloudflare,
    /// A receiver of signed record-set webhooks (ZeroForwarder DNS webhook
    /// protocol v1, as publicly documented); see [`Webhook`].
    Webhook,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Provider {
    pub id: String,
    pub name: String,
    pub kind: ProviderKind,
    /// API base, normally https://api.cloudflare.com/client/v4; for a webhook
    /// the receiver URL, used exactly as given. Loopback HTTP is allowed for
    /// local fixtures; other plaintext endpoints are rejected.
    pub endpoint: String,
    /// API token; for a webhook the HMAC secret (at least 32 bytes).
    pub token: String,
    /// Lowest TTL the provider accepts. Records with a lower TTL are published
    /// with this value; TTL 1 (Cloudflare "automatic") is never raised.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub min_ttl: Option<u32>,
    /// Webhook: zones the receiver manages, sent in the connection test. A
    /// webhook provider's zones must be in this list.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub zones: Vec<String>,
    /// Webhook: seconds one request may take, 1..=30.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u32>,
    pub created_at_ms: i64,
}
/// Settings only webhook providers take; `None` keeps the current value, or
/// the default on creation.
#[derive(Clone, Debug, Default)]
pub struct WebhookSettings {
    pub zones: Option<Vec<String>>,
    pub timeout_secs: Option<u32>,
}
#[derive(Clone, Debug, Serialize)]
pub struct ProviderView {
    pub id: String,
    pub name: String,
    pub kind: ProviderKind,
    pub endpoint: String,
    pub token_set: bool,
    pub min_ttl: Option<u32>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub zones: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub timeout_secs: Option<u32>,
    pub created_at_ms: i64,
}
impl From<&Provider> for ProviderView {
    fn from(value: &Provider) -> Self {
        Self {
            id: value.id.clone(),
            name: value.name.clone(),
            kind: value.kind,
            endpoint: value.endpoint.clone(),
            token_set: !value.token.is_empty(),
            min_ttl: value.min_ttl,
            zones: value.zones.clone(),
            timeout_secs: value.timeout_secs,
            created_at_ms: value.created_at_ms,
        }
    }
}
/// A zone the provider credentials can see, returned by the connection test.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ProviderZone {
    pub id: String,
    pub name: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct ProviderTest {
    pub ok: bool,
    pub zones: Vec<ProviderZone>,
    /// True when the provider has more zones than one test lists.
    pub truncated: bool,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ZoneMode {
    /// Read the provider and report differences; never write.
    Observe,
    /// Create/update/delete managed records.
    Apply,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Zone {
    pub id: String,
    pub provider_id: String,
    /// Provider zone name or ID, used as the API path component.
    pub name: String,
    pub mode: ZoneMode,
    /// Do not remove the last N enabled records during a reconcile.
    pub min_keep: u32,
    /// Seconds a health-gated record must fail continuously before it is
    /// removed, and pass continuously before it is restored. Zones stored
    /// before this field existed read 0, their earlier immediate behaviour.
    #[serde(default)]
    pub failover_confirm_secs: u32,
    pub created_at_ms: i64,
}
/// A zone with the controller's last evaluation of it.
#[derive(Clone, Debug, Serialize)]
pub struct ZoneView {
    #[serde(flatten)]
    pub zone: Zone,
    pub status: ZoneStatus,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Trigger {
    /// `reconcile`, DDNS or another operator request.
    Manual,
    /// The controller's background synchroniser.
    Automatic,
}
/// Process-local evaluation state of a zone; it is not persisted.
#[derive(Clone, Debug, Default, Serialize)]
pub struct ZoneStatus {
    pub last_evaluated_ms: Option<i64>,
    pub last_trigger: Option<Trigger>,
    pub last_automatic_ms: Option<i64>,
    /// Why the last evaluation failed as a whole (for example the provider
    /// could not be listed). Per-record errors stay on the record.
    pub last_error: Option<String>,
    /// `TYPE name` groups whose health removals the mass-failure guard paused.
    pub guarded: Vec<String>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum RecordState {
    /// At the provider and wanted there.
    Published,
    /// Health gate failing; still published until the window elapses.
    PendingRemove,
    /// Health gate passing again; published once the window elapses.
    PendingRestore,
    /// Removed (or never published) because the health gate fails.
    Removed,
    /// Disabled and not at the provider.
    Disabled,
    /// Should be removed, but `min_keep` holds it.
    HeldMinKeep,
    /// Health removal paused because most values of the name fail at once.
    HeldGuard,
    /// Observe mode: what apply mode would do.
    WouldCreate,
    WouldUpdate,
    WouldRemove,
    /// The provider rejected the write; see `last_error`.
    Error,
}
/// Why a record is (not) published, as of the last evaluation.
#[derive(Clone, Debug, Serialize)]
pub struct RecordStatus {
    pub state: RecordState,
    pub evaluated_at_ms: i64,
    /// Health-gate result at that evaluation; `None` without a gate.
    pub healthy: Option<bool>,
    /// Start of the current continuous healthy or failing streak.
    pub since_ms: Option<i64>,
    /// When a pending removal or restoration becomes due.
    pub due_at_ms: Option<i64>,
    /// TTL sent to the provider after the provider minimum.
    pub published_ttl: u32,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum RecordType {
    A,
    Aaaa,
    Cname,
}
impl RecordType {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::A => "A",
            Self::Aaaa => "AAAA",
            Self::Cname => "CNAME",
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct HealthGate {
    pub node_id: String,
    pub rule_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub zone_id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: RecordType,
    pub content: String,
    pub ttl: u32,
    #[serde(default)]
    pub proxied: bool,
    pub enabled: bool,
    /// Optional entry-health gate: remove this record while the linked node
    /// rule has no fresh, eligible healthy target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<HealthGate>,
    /// Provider's record ID once created or imported.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub provider_record_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_observed: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_error: Option<String>,
    pub updated_at_ms: i64,
}
#[derive(Clone, Debug, Serialize)]
pub struct RecordView {
    pub id: String,
    pub zone_id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: RecordType,
    pub content: String,
    pub ttl: u32,
    pub proxied: bool,
    pub enabled: bool,
    pub health: Option<HealthGate>,
    pub provider_record_id: Option<String>,
    pub last_observed: Option<String>,
    pub last_error: Option<String>,
    pub updated_at_ms: i64,
    /// Last evaluation in this controller process; `None` until evaluated.
    pub status: Option<RecordStatus>,
}
impl From<&Record> for RecordView {
    fn from(value: &Record) -> Self {
        Self {
            id: value.id.clone(),
            zone_id: value.zone_id.clone(),
            name: value.name.clone(),
            record_type: value.record_type,
            content: value.content.clone(),
            ttl: value.ttl,
            proxied: value.proxied,
            enabled: value.enabled,
            health: value.health.clone(),
            provider_record_id: value.provider_record_id.clone(),
            last_observed: value.last_observed.clone(),
            last_error: value.last_error.clone(),
            updated_at_ms: value.updated_at_ms,
            status: None,
        }
    }
}

/// TTL sent to the provider: TTL 1 is Cloudflare's "automatic" value and is
/// always accepted, so it is kept; any other TTL is raised to the minimum.
pub fn published_ttl(ttl: u32, min_ttl: Option<u32>) -> u32 {
    if ttl == 1 {
        1
    } else {
        ttl.max(min_ttl.unwrap_or(0))
    }
}
/// Cloudflare reports proxied records with TTL 1 ("automatic") whatever TTL
/// was sent, so that is not a difference worth a write.
fn ttl_matches(remote: u32, published: u32, proxied: bool) -> bool {
    remote == published || (proxied && remote == 1)
}

pub fn validate_endpoint(raw: &str) -> Result<String> {
    Ok(endpoint_url(raw)?.as_str().trim_end_matches('/').to_owned())
}
/// A webhook URL follows the endpoint rules but is kept as given: the
/// receiver's path may need its trailing slash.
pub fn validate_webhook_url(raw: &str) -> Result<String> {
    Ok(endpoint_url(raw)?.into())
}
fn endpoint_url(raw: &str) -> Result<Url> {
    let url = Url::parse(raw).context("DNS provider endpoint must be an absolute URL")?;
    let host = url
        .host_str()
        .context("DNS provider endpoint needs a host")?;
    let loopback = host == "localhost" || host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback());
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && loopback),
        "DNS provider endpoint must use HTTPS (HTTP is only allowed for loopback fixtures)"
    );
    ensure!(
        url.username().is_empty() && url.password().is_none(),
        "DNS provider endpoint must not contain credentials"
    );
    ensure!(
        url.query().is_none() && url.fragment().is_none(),
        "DNS provider endpoint must not contain a query or fragment"
    );
    Ok(url)
}
/// A webhook zone is a DNS name (never a provider ID), compared and sent in
/// lower case without a trailing dot.
pub fn webhook_zone_name(value: &str) -> Result<String> {
    let name = value
        .strip_suffix('.')
        .unwrap_or(value)
        .to_ascii_lowercase();
    ensure!(
        name.len() <= 253
            && name.split('.').all(|label| {
                (1..=63).contains(&label.len())
                    && label
                        .bytes()
                        .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_')
            }),
        "DNS webhook zone must be a DNS name such as example.com: {value}"
    );
    Ok(name)
}
/// The name a webhook record set is sent under: the record's fully qualified
/// name in lower case without a trailing dot, the zone itself or inside it.
pub fn webhook_record_name(zone: &str, name: &str) -> Result<String> {
    let zone = webhook_zone_name(zone)?;
    let fqdn = name.strip_suffix('.').unwrap_or(name).to_ascii_lowercase();
    ensure!(
        fqdn == zone || fqdn.ends_with(&format!(".{zone}")),
        "DNS webhook record names must be fully qualified names inside the zone {zone}: {name}"
    );
    Ok(fqdn)
}
pub fn validate_zone_name(value: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > 253
        || value.trim() != value
        || value
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || matches!(c, '/' | '?' | '#'))
    {
        bail!("DNS zone name must be a provider zone ID or DNS name");
    }
    Ok(())
}
pub fn validate_record(record_type: RecordType, name: &str, content: &str, ttl: u32) -> Result<()> {
    if name.is_empty()
        || name.len() > 253
        || name.trim() != name
        || name
            .chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == '/')
    {
        bail!("DNS record name must be 1..253 bytes without whitespace, control characters or '/'");
    }
    if !(1..=86_400).contains(&ttl) {
        bail!("DNS TTL must be 1..=86400 seconds");
    }
    match record_type {
        RecordType::A => {
            content
                .parse::<Ipv4Addr>()
                .context("A record content must be an IPv4 address")?;
        }
        RecordType::Aaaa => {
            content
                .parse::<Ipv6Addr>()
                .context("AAAA record content must be an IPv6 address")?;
        }
        RecordType::Cname => {
            if content.is_empty()
                || content.len() > 253
                || content.trim() != content
                || content
                    .chars()
                    .any(|c| c.is_control() || c.is_whitespace() || c == '/')
            {
                bail!("CNAME content must be a hostname");
            }
        }
    }
    Ok(())
}
pub fn validate_health(gate: Option<&HealthGate>) -> Result<()> {
    if let Some(gate) = gate {
        for (value, what) in [
            (&gate.node_id, "health node ID"),
            (&gate.rule_id, "health rule ID"),
        ] {
            if value.is_empty() || value.len() > 128 || value.chars().any(char::is_control) {
                bail!("{what} must be 1..128 bytes without control characters");
            }
        }
    }
    Ok(())
}
pub fn validate_comment(value: Option<&str>) -> Result<()> {
    if value.is_some_and(|value| value.len() > 100 || value.chars().any(char::is_control)) {
        bail!("DNS comment must be at most 100 bytes without control characters");
    }
    Ok(())
}
pub fn comment(record_id: &str) -> String {
    format!("relay:{record_id}")
}

#[derive(Clone, Debug, Deserialize)]
struct ApiError {
    code: u64,
    message: String,
}
#[derive(Clone, Debug, Deserialize)]
struct Envelope<T> {
    result: T,
    #[serde(default)]
    result_info: Option<ResultInfo>,
}
#[derive(Clone, Debug, Deserialize)]
struct ResultInfo {
    #[serde(default)]
    total_pages: u64,
}
#[derive(Clone, Debug, Deserialize, PartialEq, Eq)]
pub struct RemoteRecord {
    pub id: String,
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: String,
    pub content: String,
    pub ttl: u32,
    #[serde(default)]
    pub proxied: bool,
    #[serde(default)]
    pub comment: Option<String>,
}
pub struct Cloudflare {
    http: reqwest::Client,
    base: String,
    token: String,
}
impl Cloudflare {
    pub fn new(http: reqwest::Client, provider: &Provider) -> Result<Self> {
        ensure!(
            provider.kind == ProviderKind::Cloudflare,
            "unsupported DNS provider kind"
        );
        ensure!(!provider.token.is_empty(), "DNS provider token is empty");
        let base = validate_endpoint(&provider.endpoint)?;
        Ok(Self {
            http,
            base,
            token: provider.token.clone(),
        })
    }
    fn url(&self, zone: &str, suffix: &str) -> Result<Url> {
        validate_zone_name(zone)?;
        Url::parse(&format!("{}/zones/{}{suffix}", self.base, zone))
            .context("invalid DNS provider URL")
    }
    async fn call_envelope<T: for<'de> Deserialize<'de>>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<Envelope<T>> {
        let response = request
            .bearer_auth(&self.token)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .context("DNS provider request failed")?;
        let status = response.status();
        let body: serde_json::Value = response
            .json()
            .await
            .with_context(|| format!("DNS provider returned a non-JSON response ({status})"))?;
        // Failures carry `result: null`; read the errors before the result type.
        if !status.is_success() || body.get("success").and_then(|v| v.as_bool()) != Some(true) {
            let errors: Vec<ApiError> = body
                .get("errors")
                .and_then(|errors| serde_json::from_value(errors.clone()).ok())
                .unwrap_or_default();
            let message = errors.first().map_or_else(
                || status.to_string(),
                |error| format!("{} ({})", error.message, error.code),
            );
            // The message is shown and stored; never let an echoed token through.
            let message = message.replace(&self.token, "[redacted]");
            bail!("DNS provider rejected the request: {message}");
        }
        serde_json::from_value(body).context("DNS provider returned an unexpected response")
    }
    async fn call<T: for<'de> Deserialize<'de>>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T> {
        Ok(self.call_envelope(request).await?.result)
    }

    pub async fn list(&self, zone: &str) -> Result<Vec<RemoteRecord>> {
        let mut records = Vec::new();
        for page in 1..=50u64 {
            let url = self.url(zone, &format!("/dns_records?per_page=100&page={page}"))?;
            let envelope: Envelope<Vec<RemoteRecord>> =
                self.call_envelope(self.http.get(url)).await?;
            let pages = envelope
                .result_info
                .as_ref()
                .map(|info| info.total_pages.max(1))
                .unwrap_or(1);
            records.extend(envelope.result);
            if page >= pages {
                return Ok(records);
            }
        }
        bail!("DNS provider returned more than 50 record pages")
    }
    /// Zones the credentials can see; this is the connection test. Stops after
    /// 20 pages of 50 and reports whether more exist.
    pub async fn zones(&self) -> Result<(Vec<ProviderZone>, bool)> {
        let mut zones = Vec::new();
        for page in 1..=20u64 {
            let url = Url::parse(&format!("{}/zones?per_page=50&page={page}", self.base))
                .context("invalid DNS provider URL")?;
            let envelope: Envelope<Vec<ProviderZone>> =
                self.call_envelope(self.http.get(url)).await?;
            let pages = envelope
                .result_info
                .as_ref()
                .map(|info| info.total_pages.max(1))
                .unwrap_or(1);
            zones.extend(envelope.result);
            if page >= pages {
                return Ok((zones, false));
            }
        }
        Ok((zones, true))
    }
    pub async fn create(&self, zone: &str, record: &Record, ttl: u32) -> Result<RemoteRecord> {
        let url = self.url(zone, "/dns_records")?;
        self.call(self.http.post(url).json(&serde_json::json!({
            "type": record.record_type.as_str(),
            "name": record.name,
            "content": record.content,
            "ttl": ttl,
            "proxied": record.proxied,
            "comment": comment(&record.id),
        })))
        .await
    }
    pub async fn update(
        &self,
        zone: &str,
        remote_id: &str,
        record: &Record,
        ttl: u32,
    ) -> Result<RemoteRecord> {
        let url = self.url(zone, &format!("/dns_records/{remote_id}"))?;
        self.call(self.http.put(url).json(&serde_json::json!({
            "type": record.record_type.as_str(),
            "name": record.name,
            "content": record.content,
            "ttl": ttl,
            "proxied": record.proxied,
            "comment": comment(&record.id),
        })))
        .await
    }
    pub async fn delete(&self, zone: &str, remote_id: &str) -> Result<()> {
        let url = self.url(zone, &format!("/dns_records/{remote_id}"))?;
        let _: serde_json::Value = self.call(self.http.delete(url)).await?;
        Ok(())
    }
}

/// A receiver's refusal of one webhook request.
#[derive(Debug)]
pub struct WebhookRejected {
    pub status: u16,
    pub message: String,
    /// The receiver's generation, sent with a stale-generation 409.
    pub watermark: Option<u64>,
}
impl fmt::Display for WebhookRejected {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.message)
    }
}
impl std::error::Error for WebhookRejected {}

/// `sha256=` and the lower-case hex HMAC-SHA256, keyed with the secret's
/// UTF-8 bytes, of the timestamp, a dot and the raw body.
fn webhook_signature(secret: &str, timestamp: &str, body: &[u8]) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let mut context = ring::hmac::Context::with_key(&key);
    context.update(timestamp.as_bytes());
    context.update(b".");
    context.update(body);
    let hex: String = context
        .sign()
        .as_ref()
        .iter()
        .map(|b| format!("{b:02x}"))
        .collect();
    format!("sha256={hex}")
}
/// A value as sent in a set: IP addresses in canonical form, so that equal
/// addresses deduplicate; CNAME targets in lower case without a trailing dot.
fn webhook_value(record_type: RecordType, content: &str) -> String {
    match record_type {
        RecordType::A => content
            .parse::<Ipv4Addr>()
            .map_or_else(|_| content.to_owned(), |ip| ip.to_string()),
        RecordType::Aaaa => content
            .parse::<Ipv6Addr>()
            .map_or_else(|_| content.to_owned(), |ip| ip.to_string()),
        RecordType::Cname => content
            .strip_suffix('.')
            .unwrap_or(content)
            .to_ascii_lowercase(),
    }
}

/// Signed record-set webhook, following the public description of the
/// ZeroForwarder DNS webhook protocol v1: every request is a JSON `POST` to
/// one URL with `X-ZFC-Event`, `X-ZFC-Delivery` (new UUID per request),
/// `X-ZFC-Timestamp` (Unix seconds) and `X-ZFC-Signature`. Only a 2xx other
/// than 202 counts as applied; redirects are never followed, so the signed
/// body is never replayed to another URL.
pub struct Webhook {
    http: reqwest::Client,
    url: String,
    secret: String,
    /// The provider ID: the stable `source` of generations and sets.
    source: String,
    timeout_secs: u32,
}
impl Webhook {
    pub fn new(provider: &Provider) -> Result<Self> {
        ensure!(
            provider.kind == ProviderKind::Webhook,
            "unsupported DNS provider kind"
        );
        ensure!(
            provider.token.len() >= WEBHOOK_MIN_SECRET_BYTES,
            "DNS webhook secret must be at least {WEBHOOK_MIN_SECRET_BYTES} bytes"
        );
        let timeout_secs = provider
            .timeout_secs
            .unwrap_or(WEBHOOK_DEFAULT_TIMEOUT_SECS)
            .clamp(1, WEBHOOK_MAX_TIMEOUT_SECS);
        // Its own client whatever the caller uses: no redirects, own timeout.
        let http = reqwest::Client::builder()
            .redirect(reqwest::redirect::Policy::none())
            .timeout(Duration::from_secs(timeout_secs.into()))
            .build()
            .context("DNS webhook HTTP client")?;
        Ok(Self {
            http,
            url: validate_webhook_url(&provider.endpoint)?,
            secret: provider.token.clone(),
            source: provider.id.clone(),
            timeout_secs,
        })
    }
    async fn send(&self, event: &str, body: &serde_json::Value) -> Result<()> {
        let body = serde_json::to_vec(body)?;
        let timestamp = (crate::model::now_ms() / 1000).to_string();
        let signature = webhook_signature(&self.secret, &timestamp, &body);
        let response = self
            .http
            .post(&self.url)
            .header(reqwest::header::CONTENT_TYPE, "application/json")
            .header("X-ZFC-Event", event)
            .header("X-ZFC-Delivery", uuid::Uuid::new_v4().to_string())
            .header("X-ZFC-Timestamp", &timestamp)
            .header("X-ZFC-Signature", signature)
            .body(body)
            .send()
            .await
            .map_err(|error| {
                if error.is_timeout() {
                    anyhow::anyhow!(
                        "DNS webhook {event} got no answer within {} s; the receiver may still apply it",
                        self.timeout_secs
                    )
                } else {
                    anyhow::Error::new(error).context(format!("DNS webhook {event} failed"))
                }
            })?;
        let status = response.status();
        if status.is_success() && status != reqwest::StatusCode::ACCEPTED {
            return Ok(());
        }
        let (detail, watermark) = if status == reqwest::StatusCode::ACCEPTED {
            ("accepted without applying it; a receiver must answer 2xx only after the change is applied".to_owned(), None)
        } else if status.is_redirection() {
            (
                "redirects are not followed; configure the receiver's final URL".to_owned(),
                None,
            )
        } else {
            receiver_detail(&read_bounded(response, 4096).await)
        };
        let message = format!("DNS webhook rejected the {event}: HTTP {status} {detail}")
            .trim_end()
            .replace(&self.secret, "[redacted]");
        Err(WebhookRejected {
            status: status.as_u16(),
            message,
            watermark,
        }
        .into())
    }
    /// Connection test: a signed `ping` with a throwaway `source`, listing the
    /// configured zones. It does not prove that the receiver may write DNS.
    pub async fn ping(&self, zones: &[String]) -> Result<()> {
        let body = serde_json::json!({
            "version": 1,
            "source": uuid::Uuid::new_v4().to_string(),
            "event": "ping",
            "zones": zones,
        });
        self.send("ping", &body).await
    }
}
/// At most `limit` bytes of a response body; a failed read ends it.
async fn read_bounded(mut response: reqwest::Response, limit: usize) -> Vec<u8> {
    let mut body = Vec::new();
    while body.len() < limit {
        let Ok(Some(chunk)) = response.chunk().await else {
            break;
        };
        body.extend_from_slice(&chunk[..chunk.len().min(limit - body.len())]);
    }
    body
}
/// The receiver's reason, from the `error`, `code`, `message`, `detail` and
/// `watermark` fields of a JSON body or else its text, on one line of at most
/// 300 characters; and the watermark (receiver generation) if it sent one.
fn receiver_detail(body: &[u8]) -> (String, Option<u64>) {
    let (text, watermark) = match serde_json::from_slice::<serde_json::Value>(body) {
        Ok(serde_json::Value::Object(fields)) => {
            let field = |name: &str| match fields.get(name) {
                Some(serde_json::Value::String(value)) => Some(value.clone()),
                Some(serde_json::Value::Number(value)) => Some(value.to_string()),
                _ => None,
            };
            let mut parts: Vec<String> = ["error", "code", "message", "detail"]
                .into_iter()
                .filter_map(field)
                .collect();
            let watermark = field("watermark");
            if let Some(watermark) = &watermark {
                parts.push(format!("receiver generation {watermark}"));
            }
            (
                parts.join(": "),
                watermark.and_then(|value| value.parse().ok()),
            )
        }
        _ => (String::from_utf8_lossy(body).into_owned(), None),
    };
    let text = text
        .chars()
        .map(|c| if c.is_control() { ' ' } else { c })
        .take(300)
        .collect::<String>();
    (text.trim().to_owned(), watermark)
}

/// What a webhook receiver acknowledged for one Relay record.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct WebhookEntry {
    pub name: String,
    #[serde(rename = "type")]
    pub record_type: RecordType,
    pub content: String,
    pub ttl: u32,
}
/// A zone's acknowledged entries by record ID.
pub type WebhookState = BTreeMap<String, WebhookEntry>;
type SetKey = (RecordType, String);

/// Webhook delivery state of one provider in this process: the generation
/// the receiver accepted and the last `seq` sent in it.
#[derive(Default)]
struct WebhookSession {
    generation: Option<u64>,
    seq: u64,
}

/// A webhook provider bound to one zone for a pass. A webhook cannot be read
/// back, so the provider's records are what the receiver acknowledged, kept
/// with the zone. Each record change sends the complete value set of the
/// record's name and type, with the lowest TTL of its values (RFC 2181 5.2).
pub struct WebhookZone {
    hook: Webhook,
    store: Store,
    zone_id: String,
    zone: String,
    entries: Mutex<WebhookState>,
}
impl WebhookZone {
    pub fn new(store: &Store, provider: &Provider, zone: &Zone) -> Result<Self> {
        let name = webhook_zone_name(&zone.name)?;
        ensure!(
            provider.zones.contains(&name),
            "zone {name} is not in the DNS webhook provider's zone list"
        );
        Ok(Self {
            hook: Webhook::new(provider)?,
            store: store.clone(),
            zone_id: zone.id.clone(),
            zone: name,
            entries: Mutex::new(store.dns_webhook_state(&zone.id)?),
        })
    }
    fn key(&self, entry: &WebhookEntry) -> Result<SetKey> {
        Ok((
            entry.record_type,
            webhook_record_name(&self.zone, &entry.name)?,
        ))
    }
    fn list(&self) -> Vec<RemoteRecord> {
        self.entries
            .lock()
            .unwrap()
            .iter()
            .map(|(id, entry)| acknowledged(id, entry.clone()))
            .collect()
    }
    /// Moves record `id` to `next` (`None` removes it): the set it leaves is
    /// sent first, then the set it joins, and each accepted set is kept, so a
    /// failure leaves the record out of DNS rather than in two sets.
    async fn write(&self, id: &str, next: Option<WebhookEntry>) -> Result<()> {
        let current = self.entries.lock().unwrap().get(id).cloned();
        let joins = next.as_ref().map(|entry| self.key(entry)).transpose()?;
        if let Some(current) = current {
            let leaves = self.key(&current)?;
            if joins.as_ref() != Some(&leaves) {
                self.apply(id, None, &leaves, current.ttl).await?;
            }
        }
        if let (Some(entry), Some(key)) = (next, joins) {
            let ttl = entry.ttl;
            self.apply(id, Some(entry), &key, ttl).await?;
        }
        Ok(())
    }
    /// Sends `key`'s set with record `id` set to `entry`, then keeps it.
    async fn apply(
        &self,
        id: &str,
        entry: Option<WebhookEntry>,
        key: &SetKey,
        empty_ttl: u32,
    ) -> Result<()> {
        let mut entries = self.entries.lock().unwrap().clone();
        match entry {
            Some(entry) => entries.insert(id.to_owned(), entry),
            None => entries.remove(id),
        };
        let members: Vec<&WebhookEntry> = entries
            .values()
            .filter(|entry| self.key(entry).is_ok_and(|other| other == *key))
            .collect();
        let values: BTreeSet<String> = members
            .iter()
            .map(|entry| webhook_value(entry.record_type, &entry.content))
            .collect();
        ensure!(
            key.0 != RecordType::Cname || values.len() <= 1,
            "CNAME {} can have only one target",
            key.1
        );
        let ttl = members
            .iter()
            .map(|entry| entry.ttl)
            .min()
            .unwrap_or(empty_ttl);
        self.put(key, values.into_iter().collect(), ttl).await?;
        self.store.set_dns_webhook_state(&self.zone_id, &entries)?;
        *self.entries.lock().unwrap() = entries;
        Ok(())
    }
    async fn put(&self, key: &SetKey, values: Vec<String>, ttl: u32) -> Result<()> {
        let session = self.store.dns_runtime().webhook_session(&self.hook.source);
        let mut session = session.lock().await;
        let generation = match session.generation {
            Some(generation) => generation,
            None => self.start(&mut session).await?,
        };
        session.seq += 1;
        let body = serde_json::json!({
            "version": 1,
            "source": self.hook.source,
            "event": "record_set.put",
            "generation": generation.to_string(),
            "zone": self.zone,
            "name": key.1,
            "type": key.0.as_str(),
            "ttl": ttl,
            "values": values,
            "seq": session.seq.to_string(),
        });
        let sent = self.hook.send("record_set.put", &body).await;
        if let Err(error) = &sent
            && error
                .downcast_ref::<WebhookRejected>()
                .is_some_and(|rejected| rejected.status == 409)
        {
            // Another generation or version is current at the receiver:
            // start a new generation before the next write.
            session.generation = None;
        }
        sent
    }
    /// Starts a generation one above the last one persisted, or above the
    /// receiver's when it reports a higher one (a restored database).
    async fn start(&self, session: &mut WebhookSession) -> Result<u64> {
        let mut floor = 0;
        loop {
            let generation = self
                .store
                .dns_webhook_generation(&self.hook.source, floor)?;
            let body = serde_json::json!({
                "version": 1,
                "source": self.hook.source,
                "event": "generation.start",
                "generation": generation.to_string(),
            });
            let Err(error) = self.hook.send("generation.start", &body).await else {
                session.generation = Some(generation);
                session.seq = 0;
                return Ok(generation);
            };
            match error.downcast_ref::<WebhookRejected>() {
                Some(rejected) if rejected.status == 409 && floor == 0 => {
                    match rejected.watermark {
                        Some(watermark) if watermark >= generation => {
                            floor = watermark.saturating_add(1);
                        }
                        _ => return Err(error),
                    }
                }
                _ => return Err(error),
            }
        }
    }
}
fn webhook_entry(record: &Record, ttl: u32) -> WebhookEntry {
    WebhookEntry {
        name: record.name.clone(),
        record_type: record.record_type,
        content: record.content.clone(),
        ttl,
    }
}
fn acknowledged(id: &str, entry: WebhookEntry) -> RemoteRecord {
    RemoteRecord {
        id: id.to_owned(),
        name: entry.name,
        record_type: entry.record_type.as_str().into(),
        content: entry.content,
        ttl: entry.ttl,
        proxied: false,
        comment: Some(comment(id)),
    }
}

/// The provider API of one zone's pass.
pub enum Client {
    Cloudflare(Cloudflare),
    Webhook(Box<WebhookZone>),
}
impl Client {
    pub fn new(
        store: &Store,
        http: reqwest::Client,
        provider: &Provider,
        zone: &Zone,
    ) -> Result<Self> {
        Ok(match provider.kind {
            ProviderKind::Cloudflare => Self::Cloudflare(Cloudflare::new(http, provider)?),
            ProviderKind::Webhook => {
                Self::Webhook(Box::new(WebhookZone::new(store, provider, zone)?))
            }
        })
    }
    pub async fn list(&self, zone: &str) -> Result<Vec<RemoteRecord>> {
        match self {
            Self::Cloudflare(client) => client.list(zone).await,
            Self::Webhook(client) => Ok(client.list()),
        }
    }
    pub async fn create(&self, zone: &str, record: &Record, ttl: u32) -> Result<RemoteRecord> {
        match self {
            Self::Cloudflare(client) => client.create(zone, record, ttl).await,
            Self::Webhook(client) => {
                let entry = webhook_entry(record, ttl);
                client.write(&record.id, Some(entry.clone())).await?;
                Ok(acknowledged(&record.id, entry))
            }
        }
    }
    pub async fn update(
        &self,
        zone: &str,
        remote_id: &str,
        record: &Record,
        ttl: u32,
    ) -> Result<RemoteRecord> {
        match self {
            Self::Cloudflare(client) => client.update(zone, remote_id, record, ttl).await,
            Self::Webhook(client) => {
                let entry = webhook_entry(record, ttl);
                client.write(remote_id, Some(entry.clone())).await?;
                Ok(acknowledged(remote_id, entry))
            }
        }
    }
    pub async fn delete(&self, zone: &str, remote_id: &str) -> Result<()> {
        match self {
            Self::Cloudflare(client) => client.delete(zone, remote_id).await,
            Self::Webhook(client) => client.write(remote_id, None).await,
        }
    }
}

/// Connection test. Cloudflare lists the zones the token can see; a webhook
/// receives a signed `ping`, and the result lists the provider's configured
/// zones. 400 for an unusable configuration, 502 when the provider fails.
pub async fn test_provider(http: reqwest::Client, provider: &Provider) -> Result<ProviderTest> {
    let failed = |error: anyhow::Error| crate::store::Rejection {
        status: 502,
        message: format!("DNS provider test failed: {error:#}"),
    };
    let invalid = |error: anyhow::Error| crate::store::Rejection {
        status: 400,
        message: format!("{error:#}"),
    };
    match provider.kind {
        ProviderKind::Cloudflare => {
            let client = Cloudflare::new(http, provider).map_err(invalid)?;
            let (zones, truncated) = client.zones().await.map_err(failed)?;
            Ok(ProviderTest {
                ok: true,
                zones,
                truncated,
            })
        }
        ProviderKind::Webhook => {
            let hook = Webhook::new(provider).map_err(invalid)?;
            hook.ping(&provider.zones).await.map_err(failed)?;
            Ok(ProviderTest {
                ok: true,
                zones: provider
                    .zones
                    .iter()
                    .map(|zone| ProviderZone {
                        id: zone.clone(),
                        name: zone.clone(),
                    })
                    .collect(),
                truncated: false,
            })
        }
    }
}

/// Provider HTTP client. The timeout bounds how long one pass can hold a
/// zone's sync lock.
pub fn http_client() -> reqwest::Client {
    reqwest::Client::builder()
        .timeout(Duration::from_secs(30))
        .build()
        .expect("DNS provider HTTP client")
}

#[derive(Clone, Debug, Serialize)]
pub struct Action {
    pub record_id: String,
    pub action: String,
    pub detail: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct ReconcileResult {
    pub zone_id: String,
    pub mode: ZoneMode,
    pub observed: usize,
    pub created: u64,
    pub updated: u64,
    pub deleted: u64,
    pub unchanged: u64,
    pub kept: u64,
    /// Health changes still inside the zone's confirmation window.
    pub pending: u64,
    /// Health removals paused by the mass-failure guard.
    pub guarded: u64,
    pub errors: u64,
    pub actions: Vec<Action>,
}

/// Confirmation state of one record's health gate.
#[derive(Clone, Debug, PartialEq, Eq)]
struct GateState {
    gate: HealthGate,
    /// Latest sample.
    ok: bool,
    /// Start of the current run of equal samples.
    since_ms: i64,
    /// Decision the reconcile acts on: publish (true) or remove (false).
    confirmed: bool,
}
impl GateState {
    /// Advances the state by one health sample. `published` says whether the
    /// provider has the record now. A new state starts from that, so after a
    /// controller restart every window starts again from what is published.
    /// When the sample agrees with the provider nothing has to be written and
    /// the decision follows at once (a held record that recovers is simply
    /// kept; a record that is already gone stays gone). Otherwise the sample
    /// must hold for the whole window.
    fn step(
        previous: Option<&Self>,
        gate: &HealthGate,
        ok: bool,
        published: bool,
        now: i64,
        window_ms: i64,
    ) -> Self {
        let mut state = match previous {
            Some(state) if state.gate == *gate => state.clone(),
            _ => Self {
                gate: gate.clone(),
                ok,
                since_ms: now,
                confirmed: published,
            },
        };
        if state.ok != ok {
            state.ok = ok;
            state.since_ms = now;
        }
        if ok == published || now.saturating_sub(state.since_ms) >= window_ms {
            state.confirmed = ok;
        }
        state
    }
}

/// In-memory DNS state of this controller process: per-zone sync locks, the
/// health-gate confirmation windows and the last evaluation of every zone and
/// record. It is deliberately not persisted: after a restart each window
/// starts again from what the provider publishes, so a restart can delay a
/// removal or restoration but never cause one, and the periodic pass does not
/// rewrite metadata (and the recovery log) when nothing changed.
#[derive(Default)]
pub struct Runtime {
    locks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<()>>>>,
    state: Mutex<RuntimeState>,
    /// Webhook sessions by provider ID; a restart starts a new generation.
    webhooks: Mutex<HashMap<String, Arc<tokio::sync::Mutex<WebhookSession>>>>,
}
#[derive(Default)]
struct RuntimeState {
    zones: HashMap<String, ZoneStatus>,
    gates: HashMap<String, GateState>,
    records: HashMap<String, RecordStatus>,
}
impl Runtime {
    /// Lock held for a whole read-decide-write pass over one zone, shared by
    /// manual, DDNS, record deletion and automatic synchronisation, so two
    /// passes never act on the same provider listing.
    pub fn zone_lock(&self, zone_id: &str) -> Arc<tokio::sync::Mutex<()>> {
        self.locks
            .lock()
            .unwrap()
            .entry(zone_id.to_owned())
            .or_default()
            .clone()
    }
    /// A provider's webhook session, held across each request so that the
    /// zones of one receiver send one generation and one `seq` order.
    fn webhook_session(&self, provider_id: &str) -> Arc<tokio::sync::Mutex<WebhookSession>> {
        self.webhooks
            .lock()
            .unwrap()
            .entry(provider_id.to_owned())
            .or_default()
            .clone()
    }
    pub fn zone_view(&self, zone: Zone) -> ZoneView {
        let status = self
            .state
            .lock()
            .unwrap()
            .zones
            .get(&zone.id)
            .cloned()
            .unwrap_or_default();
        ZoneView { zone, status }
    }
    pub fn record_status(&self, record_id: &str) -> Option<RecordStatus> {
        self.state.lock().unwrap().records.get(record_id).cloned()
    }
    pub fn forget_record(&self, record_id: &str) {
        let mut state = self.state.lock().unwrap();
        state.gates.remove(record_id);
        state.records.remove(record_id);
    }
    /// Applies one health sample per gated record (`None` drops the state of
    /// a record without a gate) and returns the gated records' states.
    fn gates(&self, samples: Vec<Sample>, now: i64, window_ms: i64) -> HashMap<String, GateState> {
        let mut state = self.state.lock().unwrap();
        let mut gates = HashMap::new();
        for (id, sample, published) in samples {
            let Some((gate, ok)) = sample else {
                state.gates.remove(&id);
                continue;
            };
            let next = GateState::step(state.gates.get(&id), &gate, ok, published, now, window_ms);
            state.gates.insert(id.clone(), next.clone());
            gates.insert(id, next);
        }
        gates
    }
    fn evaluated(
        &self,
        zone_id: &str,
        trigger: Trigger,
        now: i64,
        error: Option<String>,
        outcome: Option<Outcome>,
    ) {
        let mut state = self.state.lock().unwrap();
        let zone = state.zones.entry(zone_id.to_owned()).or_default();
        zone.last_evaluated_ms = Some(now);
        zone.last_trigger = Some(trigger);
        if trigger == Trigger::Automatic {
            zone.last_automatic_ms = Some(now);
        }
        zone.last_error = error.map(|error| error.chars().take(512).collect());
        if let Some((guarded, records)) = outcome {
            zone.guarded = guarded;
            state.records.extend(records);
        }
    }
    /// Drops the state of deleted zones and records.
    fn retain(&self, zones: &HashSet<String>, records: &HashSet<String>) {
        let mut state = self.state.lock().unwrap();
        state.zones.retain(|id, _| zones.contains(id));
        state.gates.retain(|id, _| records.contains(id));
        state.records.retain(|id, _| records.contains(id));
        drop(state);
        self.locks
            .lock()
            .unwrap()
            .retain(|id, lock| zones.contains(id) || Arc::strong_count(lock) > 1);
    }
}

/// Reconciles one zone at an operator's request (reconcile route, DDNS).
pub async fn reconcile(
    store: &Store,
    http: &reqwest::Client,
    zone_id: &str,
) -> Result<ReconcileResult> {
    reconcile_as(store, http, zone_id, Trigger::Manual).await
}
/// Reconciles one zone. `observe` never writes the provider; `apply` writes
/// managed records. Records are matched by provider ID first, then by
/// type/name/comment, so a lost local provider ID is recovered without
/// touching foreign records. The zone's lock is held for the whole pass, and
/// the outcome is kept as the zone's and records' status.
pub async fn reconcile_as(
    store: &Store,
    http: &reqwest::Client,
    zone_id: &str,
    trigger: Trigger,
) -> Result<ReconcileResult> {
    let runtime = store.dns_runtime();
    let lock = runtime.zone_lock(zone_id);
    let _pass = lock.lock().await;
    let now = crate::model::now_ms();
    match evaluate(store, http, zone_id, now).await {
        Ok((result, outcome)) => {
            runtime.evaluated(zone_id, trigger, now, None, Some(outcome));
            Ok(result)
        }
        Err(error) => {
            runtime.evaluated(zone_id, trigger, now, Some(format!("{error:#}")), None);
            Err(error)
        }
    }
}

/// Record ID, its gate with this pass's health result (`None` without a
/// gate), and whether the provider has the record.
type Sample = (String, Option<(HealthGate, bool)>, bool);
/// Names paused by the mass-failure guard and each record's status.
type Outcome = (Vec<String>, Vec<(String, RecordStatus)>);
type Evaluation = (ReconcileResult, Outcome);
fn group_key(record: &Record) -> (RecordType, String) {
    (record.record_type, record.name.to_ascii_lowercase())
}
async fn evaluate(
    store: &Store,
    http: &reqwest::Client,
    zone_id: &str,
    now: i64,
) -> Result<Evaluation> {
    let zone = store.dns_zone_raw(zone_id)?;
    let provider = store.dns_provider_raw(&zone.provider_id)?;
    let records = store.dns_records_for_zone(zone_id)?;
    let client = Client::new(store, http.clone(), &provider, &zone)?;
    let remote = client.list(&zone.name).await?;
    let window_ms = i64::from(zone.failover_confirm_secs) * 1000;
    let mut actions = vec![];
    let mut result = ReconcileResult {
        zone_id: zone.id.clone(),
        mode: zone.mode,
        observed: remote.len(),
        created: 0,
        updated: 0,
        deleted: 0,
        unchanged: 0,
        kept: 0,
        pending: 0,
        guarded: 0,
        errors: 0,
        actions: vec![],
    };
    let matched: Vec<Option<&RemoteRecord>> = records
        .iter()
        .map(|record| {
            record
                .provider_record_id
                .as_deref()
                .and_then(|id| remote.iter().find(|remote| remote.id == id))
                .or_else(|| {
                    remote.iter().find(|remote| {
                        remote
                            .record_type
                            .eq_ignore_ascii_case(record.record_type.as_str())
                            && remote.name.eq_ignore_ascii_case(&record.name)
                            && remote.comment.as_deref() == Some(comment(&record.id).as_str())
                    })
                })
        })
        .collect();
    let mut samples = Vec::with_capacity(records.len());
    for (record, remote_record) in records.iter().zip(&matched) {
        let sample = match &record.health {
            Some(gate) => Some((gate.clone(), store.dns_health_ok(gate)?)),
            None => None,
        };
        samples.push((record.id.clone(), sample, remote_record.is_some()));
    }
    let gates = store.dns_runtime().gates(samples, now, window_ms);
    // Records that stay (or become) published, for `min_keep`.
    let effective = records
        .iter()
        .filter(|record| record.enabled && gates.get(&record.id).is_none_or(|gate| gate.confirmed))
        .count();
    // Mass-failure guard: when more than half of the health-gated values of
    // one name and type fail in the same sample, the cause is more likely the
    // monitoring or control link than the entries, so removals are paused.
    let mut groups: HashMap<(RecordType, String), (usize, usize)> = HashMap::new();
    for record in records.iter().filter(|record| record.enabled) {
        if let Some(gate) = gates.get(&record.id) {
            let group = groups.entry(group_key(record)).or_default();
            group.0 += 1;
            group.1 += usize::from(!gate.ok);
        }
    }
    let guarded: HashSet<(RecordType, String)> = groups
        .into_iter()
        .filter(|(_, (total, failing))| *total >= 2 && failing * 2 > *total)
        .map(|(key, _)| key)
        .collect();
    let mut guarded_names: Vec<String> = guarded
        .iter()
        .map(|(record_type, name)| format!("{} {name}", record_type.as_str()))
        .collect();
    guarded_names.sort();
    let mut statuses = Vec::with_capacity(records.len());
    for (record, remote_record) in records.iter().zip(matched) {
        let gate = gates.get(&record.id);
        let ttl = match provider.kind {
            ProviderKind::Cloudflare => published_ttl(record.ttl, provider.min_ttl),
            // TTL 1 means "automatic" only at Cloudflare.
            ProviderKind::Webhook => record.ttl.max(provider.min_ttl.unwrap_or(0)),
        };
        let label = format!("{} {}", record.record_type.as_str(), record.name);
        // The latest sample differs from the decision: inside the window.
        let pending = gate.filter(|gate| record.enabled && gate.ok != gate.confirmed);
        let streak = |gate: &GateState| now.saturating_sub(gate.since_ms) / 1000;
        let mut status = RecordStatus {
            state: RecordState::Published,
            evaluated_at_ms: now,
            healthy: gate.map(|gate| gate.ok),
            since_ms: gate.map(|gate| gate.since_ms),
            due_at_ms: pending.map(|gate| gate.since_ms.saturating_add(window_ms)),
            published_ttl: ttl,
        };
        let blocked_by_health = record.enabled && gate.is_some_and(|gate| !gate.confirmed);
        if !record.enabled || blocked_by_health {
            let observe_action = if blocked_by_health {
                "would-health-remove"
            } else {
                "would-delete"
            };
            let apply_action = if blocked_by_health {
                "health-remove"
            } else {
                "delete"
            };
            let reason = if blocked_by_health {
                "health gate has no fresh eligible healthy target"
            } else {
                "disabled"
            };
            if let Some(remote_record) = remote_record {
                if blocked_by_health && guarded.contains(&group_key(record)) {
                    result.guarded += 1;
                    status.state = RecordState::HeldGuard;
                    actions.push(Action {
                        record_id: record.id.clone(),
                        action: "guard".into(),
                        detail: format!(
                            "{label} {} kept: more than half of the health-gated {label} values fail at once, so removals are paused",
                            record.content
                        ),
                    });
                } else if zone.mode == ZoneMode::Observe {
                    result.deleted += 1;
                    status.state = RecordState::WouldRemove;
                    actions.push(Action {
                        record_id: record.id.clone(),
                        action: observe_action.into(),
                        detail: format!("{label} {} would be removed: {reason}", record.content),
                    });
                } else if effective >= zone.min_keep as usize {
                    match client.delete(&zone.name, &remote_record.id).await {
                        Ok(()) => {
                            result.deleted += 1;
                            status.state = if blocked_by_health {
                                RecordState::Removed
                            } else {
                                RecordState::Disabled
                            };
                            actions.push(Action {
                                record_id: record.id.clone(),
                                action: apply_action.into(),
                                detail: format!("removed {label}: {reason}"),
                            });
                            if let Err(error) = store.dns_record_removed(&record.id) {
                                result.errors += 1;
                                actions.push(Action {
                                    record_id: record.id.clone(),
                                    action: "error".into(),
                                    detail: error.to_string(),
                                });
                            }
                        }
                        Err(error) => {
                            result.errors += 1;
                            status.state = RecordState::Error;
                            let _ = store.dns_record_failed(&record.id, &error.to_string());
                            actions.push(Action {
                                record_id: record.id.clone(),
                                action: "error".into(),
                                detail: error.to_string(),
                            });
                        }
                    }
                } else {
                    result.kept += 1;
                    status.state = RecordState::HeldMinKeep;
                    actions.push(Action {
                        record_id: record.id.clone(),
                        action: "keep".into(),
                        detail: format!(
                            "managed record kept to satisfy min_keep={} ({reason})",
                            zone.min_keep
                        ),
                    });
                }
            } else if !record.enabled {
                status.state = RecordState::Disabled;
            } else if let Some(gate) = pending {
                result.pending += 1;
                status.state = RecordState::PendingRestore;
                actions.push(Action {
                    record_id: record.id.clone(),
                    action: "pending-restore".into(),
                    detail: format!(
                        "{label} healthy for {}s; restored after {}s",
                        streak(gate),
                        zone.failover_confirm_secs
                    ),
                });
            } else {
                status.state = RecordState::Removed;
            }
            statuses.push((record.id.clone(), status));
            continue;
        }
        let needs_update = remote_record.is_some_and(|remote| {
            remote.record_type != record.record_type.as_str()
                || remote.name != record.name
                || remote.content != record.content
                || !ttl_matches(remote.ttl, ttl, record.proxied)
                || remote.proxied != record.proxied
                || remote.comment.as_deref() != Some(comment(&record.id).as_str())
        });
        if let Some(remote_record) = remote_record {
            if !needs_update {
                result.unchanged += 1;
                let _ = store.dns_record_synced(
                    &record.id,
                    Some(&remote_record.id),
                    Some(&remote_record.content),
                );
            } else if zone.mode == ZoneMode::Apply {
                match client
                    .update(&zone.name, &remote_record.id, record, ttl)
                    .await
                {
                    Ok(updated) => {
                        result.updated += 1;
                        actions.push(Action {
                            record_id: record.id.clone(),
                            action: "update".into(),
                            detail: format!("{label} -> {}", record.content),
                        });
                        let _ = store.dns_record_synced(
                            &record.id,
                            Some(&updated.id),
                            Some(&updated.content),
                        );
                    }
                    Err(error) => {
                        result.errors += 1;
                        status.state = RecordState::Error;
                        let _ = store.dns_record_failed(&record.id, &error.to_string());
                        actions.push(Action {
                            record_id: record.id.clone(),
                            action: "error".into(),
                            detail: error.to_string(),
                        });
                    }
                }
            } else {
                result.updated += 1;
                status.state = RecordState::WouldUpdate;
                actions.push(Action {
                    record_id: record.id.clone(),
                    action: "would-update".into(),
                    detail: format!("{label} -> {}", record.content),
                });
                let _ = store.dns_record_synced(
                    &record.id,
                    Some(&remote_record.id),
                    Some(&remote_record.content),
                );
            }
        } else if zone.mode == ZoneMode::Apply {
            match client.create(&zone.name, record, ttl).await {
                Ok(created) => {
                    result.created += 1;
                    actions.push(Action {
                        record_id: record.id.clone(),
                        action: "create".into(),
                        detail: format!("{label} -> {}", record.content),
                    });
                    let _ = store.dns_record_synced(
                        &record.id,
                        Some(&created.id),
                        Some(&created.content),
                    );
                }
                Err(error) => {
                    result.errors += 1;
                    status.state = RecordState::Error;
                    let _ = store.dns_record_failed(&record.id, &error.to_string());
                    actions.push(Action {
                        record_id: record.id.clone(),
                        action: "error".into(),
                        detail: error.to_string(),
                    });
                }
            }
        } else {
            result.created += 1;
            status.state = RecordState::WouldCreate;
            actions.push(Action {
                record_id: record.id.clone(),
                action: "would-create".into(),
                detail: format!("{label} -> {}", record.content),
            });
        }
        if let Some(gate) = pending {
            result.pending += 1;
            if status.state == RecordState::Published {
                status.state = RecordState::PendingRemove;
            }
            actions.push(Action {
                record_id: record.id.clone(),
                action: "pending-remove".into(),
                detail: format!(
                    "{label} health gate failing for {}s; removed after {}s",
                    streak(gate),
                    zone.failover_confirm_secs
                ),
            });
        }
        statuses.push((record.id.clone(), status));
    }
    result.actions = actions;
    Ok((result, (guarded_names, statuses)))
}

/// Background synchroniser: evaluates every zone each `tick`. Observe zones
/// only read the provider and keep the result as status; apply zones also
/// write. A pass writes the provider or the database only for a difference.
/// The first pass waits `startup_grace` so that agents can report after a
/// controller restart before their health gates are judged.
pub async fn run(
    store: Store,
    tick: Duration,
    startup_grace: Duration,
    stop: tokio_util::sync::CancellationToken,
) {
    let http = http_client();
    tokio::select! {
        biased;
        _ = stop.cancelled() => return,
        _ = tokio::time::sleep(startup_grace) => {}
    }
    let mut interval = tokio::time::interval(tick);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            _ = stop.cancelled() => return,
            _ = interval.tick() => {}
        }
        let db = store.clone();
        let (zones, records) = match tokio::task::spawn_blocking(move || db.dns_ids()).await {
            Ok(Ok(ids)) => ids,
            Ok(Err(error)) => {
                tracing::warn!(%error, "DNS zones unavailable for automatic sync");
                continue;
            }
            Err(_) => return,
        };
        store.dns_runtime().retain(
            &zones.iter().cloned().collect(),
            &records.into_iter().collect(),
        );
        for zone in &zones {
            let pass = tokio::select! {
                biased;
                _ = stop.cancelled() => return,
                pass = reconcile_as(&store, &http, zone, Trigger::Automatic) => pass,
            };
            match pass {
                Ok(result) if result.errors > 0 => {
                    tracing::warn!(zone = %zone, errors = result.errors, "DNS records not synchronized");
                }
                Ok(result)
                    if result.created + result.updated + result.deleted > 0
                        && result.mode == ZoneMode::Apply =>
                {
                    tracing::info!(
                        zone = %zone,
                        created = result.created,
                        updated = result.updated,
                        deleted = result.deleted,
                        "DNS zone synchronized automatically"
                    );
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::warn!(zone = %zone, error = %format!("{error:#}"), "DNS zone not synchronized");
                }
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gate(rule: &str) -> HealthGate {
        HealthGate {
            node_id: "node".into(),
            rule_id: rule.into(),
        }
    }
    /// Feeds `samples` (time ms, healthy) and returns the decision after each.
    fn decisions(published: bool, window_ms: i64, samples: &[(i64, bool)]) -> Vec<bool> {
        let gate = gate("a");
        let mut state: Option<GateState> = None;
        let mut published = published;
        samples
            .iter()
            .map(|&(now, ok)| {
                let next = GateState::step(state.as_ref(), &gate, ok, published, now, window_ms);
                // The reconcile follows the decision.
                published = next.confirmed;
                state = Some(next);
                published
            })
            .collect()
    }

    #[test]
    fn a_zero_window_follows_every_sample() {
        assert_eq!(
            decisions(true, 0, &[(0, false), (1, true), (2, false)]),
            [false, true, false]
        );
    }

    #[test]
    fn removal_and_restoration_need_an_unbroken_window() {
        // Published, failing from 0: removed only at 60 s.
        assert_eq!(
            decisions(
                true,
                60_000,
                &[
                    (0, false),
                    (30_000, false),
                    (59_999, false),
                    (60_000, false)
                ]
            ),
            [true, true, true, false]
        );
        // One healthy sample restarts the failing run.
        assert_eq!(
            decisions(
                true,
                60_000,
                &[
                    (0, false),
                    (30_000, true),
                    (40_000, false),
                    (90_000, false),
                    (100_000, false)
                ]
            ),
            [true, true, true, true, false]
        );
        // Absent and healthy (after a removal or a restart): restored at 60 s.
        assert_eq!(
            decisions(
                false,
                60_000,
                &[
                    (0, true),
                    (30_000, false),
                    (40_000, true),
                    (90_000, true),
                    (100_000, true)
                ]
            ),
            [false, false, false, false, true]
        );
    }

    #[test]
    fn agreeing_samples_decide_at_once_and_a_new_gate_starts_over() {
        // A record held at the provider (min_keep, guard) that recovers stays.
        let held = GateState {
            gate: gate("a"),
            ok: false,
            since_ms: 0,
            confirmed: false,
        };
        let next = GateState::step(Some(&held), &gate("a"), true, true, 1_000, 60_000);
        assert!(next.confirmed);
        // A changed gate does not inherit the previous run.
        let next = GateState::step(Some(&held), &gate("b"), false, true, 120_000, 60_000);
        assert!(next.confirmed);
        assert_eq!(next.since_ms, 120_000);
    }

    #[test]
    fn webhook_signature_covers_timestamp_dot_and_raw_body() {
        // Expected value from Python's hmac/hashlib, not from this code.
        let body = br#"{"event":"ping","source":"s","version":1,"zones":["example.com"]}"#;
        assert_eq!(
            webhook_signature("0123456789abcdef0123456789abcdef", "1767225600", body),
            "sha256=d5462f66f3358c44c39a7b58b38cd41d1cccaf261af445200781311813e60483"
        );
    }

    #[test]
    fn webhook_names_values_and_receiver_errors() {
        assert_eq!(
            webhook_record_name("Example.COM.", "Edge.example.com.").unwrap(),
            "edge.example.com"
        );
        assert_eq!(
            webhook_record_name("example.com", "example.com").unwrap(),
            "example.com"
        );
        // A suffix match without a label boundary is outside the zone.
        assert!(webhook_record_name("example.com", "badexample.com").is_err());
        assert!(webhook_record_name("example.com", "edge").is_err());
        assert!(webhook_zone_name("example..com").is_err());
        assert!(webhook_zone_name("").is_err());
        assert_eq!(
            webhook_value(RecordType::Aaaa, "2001:DB8:0::1"),
            "2001:db8::1"
        );
        assert_eq!(
            webhook_value(RecordType::Cname, "Edge.Example.NET."),
            "edge.example.net"
        );
        let (detail, watermark) = receiver_detail(
            br#"{"error":"stale_generation","message":"line one\nline two","watermark":"12"}"#,
        );
        assert_eq!(
            detail,
            "stale_generation: line one line two: receiver generation 12"
        );
        assert_eq!(watermark, Some(12));
        assert_eq!(
            receiver_detail(b"adapter unavailable\n"),
            ("adapter unavailable".to_owned(), None)
        );
    }

    #[test]
    fn published_ttl_honours_the_minimum_but_keeps_automatic() {
        assert_eq!(published_ttl(30, Some(60)), 60);
        assert_eq!(published_ttl(120, Some(60)), 120);
        assert_eq!(published_ttl(1, Some(60)), 1);
        assert_eq!(published_ttl(30, None), 30);
        assert!(ttl_matches(1, 300, true));
        assert!(!ttl_matches(1, 300, false));
    }
}
