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
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum ProviderKind {
    Cloudflare,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Provider {
    pub id: String,
    pub name: String,
    pub kind: ProviderKind,
    /// API base, normally https://api.cloudflare.com/client/v4. Loopback HTTP is
    /// allowed for local fixtures; other plaintext endpoints are rejected.
    pub endpoint: String,
    pub token: String,
    pub created_at_ms: i64,
}
#[derive(Clone, Debug, Serialize)]
pub struct ProviderView {
    pub id: String,
    pub name: String,
    pub kind: ProviderKind,
    pub endpoint: String,
    pub token_set: bool,
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
            created_at_ms: value.created_at_ms,
        }
    }
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
    pub created_at_ms: i64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    pub provider_record_id: Option<String>,
    pub last_observed: Option<String>,
    pub last_error: Option<String>,
    pub updated_at_ms: i64,
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
            provider_record_id: value.provider_record_id.clone(),
            last_observed: value.last_observed.clone(),
            last_error: value.last_error.clone(),
            updated_at_ms: value.updated_at_ms,
        }
    }
}

pub fn validate_endpoint(raw: &str) -> Result<String> {
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
    Ok(url.as_str().trim_end_matches('/').to_owned())
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
    success: bool,
    #[serde(default)]
    errors: Vec<ApiError>,
    result: T,
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
    async fn call<T: for<'de> Deserialize<'de>>(
        &self,
        request: reqwest::RequestBuilder,
    ) -> Result<T> {
        let response = request
            .bearer_auth(&self.token)
            .header(reqwest::header::ACCEPT, "application/json")
            .send()
            .await
            .context("DNS provider request failed")?;
        let status = response.status();
        let body: Envelope<T> = response
            .json()
            .await
            .context("DNS provider returned a non-JSON response")?;
        if !body.success || !status.is_success() {
            let message = body.errors.first().map_or_else(
                || status.to_string(),
                |error| format!("{} ({})", error.message, error.code),
            );
            bail!("DNS provider rejected the request: {message}");
        }
        Ok(body.result)
    }
    pub async fn list(&self, zone: &str) -> Result<Vec<RemoteRecord>> {
        let url = self.url(zone, "/dns_records?per_page=100")?;
        self.call(self.http.get(url)).await
    }
    pub async fn create(&self, zone: &str, record: &Record) -> Result<RemoteRecord> {
        let url = self.url(zone, "/dns_records")?;
        self.call(self.http.post(url).json(&serde_json::json!({
            "type": record.record_type.as_str(),
            "name": record.name,
            "content": record.content,
            "ttl": record.ttl,
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
    ) -> Result<RemoteRecord> {
        let url = self.url(zone, &format!("/dns_records/{remote_id}"))?;
        self.call(self.http.put(url).json(&serde_json::json!({
            "type": record.record_type.as_str(),
            "name": record.name,
            "content": record.content,
            "ttl": record.ttl,
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
    pub errors: u64,
    pub actions: Vec<Action>,
}
/// Reconciles one zone. `observe` never writes the provider; `apply` writes
/// managed records. Records are matched by provider ID first, then by
/// type/name/comment, so a lost local provider ID is recovered without
/// touching foreign records.
pub async fn reconcile(
    store: &Store,
    http: &reqwest::Client,
    zone_id: &str,
) -> Result<ReconcileResult> {
    let zone = store.dns_zone_raw(zone_id)?;
    let provider = store.dns_provider_raw(&zone.provider_id)?;
    let records = store.dns_records_for_zone(zone_id)?;
    let client = Cloudflare::new(http.clone(), &provider)?;
    let remote = client.list(&zone.name).await?;
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
        errors: 0,
        actions: vec![],
    };
    let enabled = records.iter().filter(|record| record.enabled).count();
    for mut record in records {
        let remote_record = record
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
            });
        if !record.enabled {
            if let Some(remote_record) = remote_record {
                if zone.mode == ZoneMode::Observe {
                    result.deleted += 1;
                    actions.push(Action {
                        record_id: record.id.clone(),
                        action: "would-delete".into(),
                        detail: format!(
                            "disabled {} {} would be deleted",
                            record.record_type.as_str(),
                            record.name
                        ),
                    });
                } else if enabled >= zone.min_keep as usize {
                    match client.delete(&zone.name, &remote_record.id).await {
                        Ok(()) => {
                            result.deleted += 1;
                            actions.push(Action {
                                record_id: record.id.clone(),
                                action: "delete".into(),
                                detail: format!(
                                    "deleted disabled {} {}",
                                    record.record_type.as_str(),
                                    record.name
                                ),
                            });
                            if let Err(error) = store.dns_record_removed(&record.id) {
                                result.errors += 1;
                                result.actions.push(Action {
                                    record_id: record.id,
                                    action: "error".into(),
                                    detail: error.to_string(),
                                });
                            }
                        }
                        Err(error) => {
                            result.errors += 1;
                            let _ = store.dns_record_failed(&record.id, &error.to_string());
                            actions.push(Action {
                                record_id: record.id,
                                action: "error".into(),
                                detail: error.to_string(),
                            });
                        }
                    }
                } else {
                    result.kept += 1;
                    actions.push(Action {
                        record_id: record.id.clone(),
                        action: "keep".into(),
                        detail: format!(
                            "disabled managed record kept to satisfy min_keep={}",
                            zone.min_keep
                        ),
                    });
                }
            }
            continue;
        }
        let needs_update = remote_record.is_some_and(|remote| {
            remote.record_type != record.record_type.as_str()
                || remote.name != record.name
                || remote.content != record.content
                || remote.ttl != record.ttl
                || remote.proxied != record.proxied
                || remote.comment.as_deref() != Some(comment(&record.id).as_str())
        });
        if let Some(remote_record) = remote_record {
            record.last_observed = Some(remote_record.content.clone());
            if !needs_update {
                result.unchanged += 1;
                let _ = store.dns_record_synced(
                    &record.id,
                    Some(&remote_record.id),
                    Some(&remote_record.content),
                );
                continue;
            }
            if zone.mode == ZoneMode::Apply {
                match client.update(&zone.name, &remote_record.id, &record).await {
                    Ok(updated) => {
                        result.updated += 1;
                        actions.push(Action {
                            record_id: record.id.clone(),
                            action: "update".into(),
                            detail: format!(
                                "{} {} -> {}",
                                record.record_type.as_str(),
                                record.name,
                                record.content
                            ),
                        });
                        let _ = store.dns_record_synced(
                            &record.id,
                            Some(&updated.id),
                            Some(&updated.content),
                        );
                    }
                    Err(error) => {
                        result.errors += 1;
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
                actions.push(Action {
                    record_id: record.id.clone(),
                    action: "would-update".into(),
                    detail: format!(
                        "{} {} -> {}",
                        record.record_type.as_str(),
                        record.name,
                        record.content
                    ),
                });
                let _ = store.dns_record_synced(
                    &record.id,
                    Some(&remote_record.id),
                    Some(&remote_record.content),
                );
            }
        } else if zone.mode == ZoneMode::Apply {
            match client.create(&zone.name, &record).await {
                Ok(created) => {
                    result.created += 1;
                    actions.push(Action {
                        record_id: record.id.clone(),
                        action: "create".into(),
                        detail: format!(
                            "{} {} -> {}",
                            record.record_type.as_str(),
                            record.name,
                            record.content
                        ),
                    });
                    let _ = store.dns_record_synced(
                        &record.id,
                        Some(&created.id),
                        Some(&created.content),
                    );
                }
                Err(error) => {
                    result.errors += 1;
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
            actions.push(Action {
                record_id: record.id.clone(),
                action: "would-create".into(),
                detail: format!(
                    "{} {} -> {}",
                    record.record_type.as_str(),
                    record.name,
                    record.content
                ),
            });
        }
    }
    result.actions = actions;
    Ok(result)
}
