//! DNS provider, zone and managed-record persistence. Records live in metadata
//! so the schema and recovery journal stay unchanged; provider tokens are
//! reversible and therefore restricted to system administrators.
use super::*;
use crate::dns::{
    HealthGate, Provider, ProviderKind, ProviderView, Record, RecordType, RecordView,
    WebhookSettings, WebhookState, Zone, ZoneMode,
};
use std::collections::BTreeSet;

fn provider_key(id: &str) -> String {
    format!("dns_provider:{id}")
}
fn zone_key(id: &str) -> String {
    format!("dns_zone:{id}")
}
fn record_key(id: &str) -> String {
    format!("dns_record:{id}")
}
/// What a webhook receiver acknowledged for a zone's records.
fn webhook_zone_key(id: &str) -> String {
    format!("dns_webhook_zone:{id}")
}
/// The last webhook generation a provider started.
fn webhook_source_key(id: &str) -> String {
    format!("dns_webhook_source:{id}")
}
fn invalid(error: anyhow::Error) -> Result<String> {
    reject(400, format!("{error:#}"))
}
/// Applies webhook settings and checks the kind-specific rules: a webhook
/// needs a secret of at least 32 bytes, 1..=100 zones and a 1..=30 s timeout,
/// and its URL may serve one provider only; Cloudflare takes neither.
fn webhook_settings(
    conn: &Connection,
    provider: &mut Provider,
    settings: WebhookSettings,
) -> Result<()> {
    if provider.kind == ProviderKind::Cloudflare {
        if settings.zones.is_some() || settings.timeout_secs.is_some() {
            return reject(
                400,
                "zones and timeout_secs apply to webhook providers only",
            );
        }
        return Ok(());
    }
    if let Some(zones) = settings.zones {
        let zones: BTreeSet<String> = zones
            .iter()
            .map(|zone| crate::dns::webhook_zone_name(zone).or_else(invalid))
            .collect::<Result<_>>()?;
        provider.zones = zones.into_iter().collect();
    }
    if let Some(value) = settings.timeout_secs {
        provider.timeout_secs = Some(value);
    }
    let timeout = provider
        .timeout_secs
        .get_or_insert(crate::dns::WEBHOOK_DEFAULT_TIMEOUT_SECS);
    if !(1..=crate::dns::WEBHOOK_MAX_TIMEOUT_SECS).contains(timeout) {
        return reject(400, "DNS webhook timeout_secs must be 1..=30");
    }
    if provider.zones.is_empty() || provider.zones.len() > crate::dns::WEBHOOK_MAX_ZONES {
        return reject(400, "a DNS webhook provider needs 1..=100 zones");
    }
    if provider.token.len() < crate::dns::WEBHOOK_MIN_SECRET_BYTES {
        return reject(400, "DNS webhook secret must be at least 32 bytes");
    }
    if all::<Provider>(conn, "dns_provider:")?.iter().any(|other| {
        other.id != provider.id
            && other.kind == ProviderKind::Webhook
            && other.endpoint == provider.endpoint
    }) {
        return reject(409, "another DNS webhook provider already uses this URL");
    }
    Ok(())
}
/// A webhook zone must be one of its provider's zones, and only once: the
/// receiver keeps one value set per zone, name and type.
fn check_webhook_zone(
    conn: &Connection,
    provider: &Provider,
    name: &str,
    zone_id: Option<&str>,
) -> Result<()> {
    if provider.kind != ProviderKind::Webhook {
        return Ok(());
    }
    let name = crate::dns::webhook_zone_name(name).or_else(invalid)?;
    if !provider.zones.contains(&name) {
        return reject(
            400,
            format!("zone {name} is not in the DNS webhook provider's zone list"),
        );
    }
    if all::<Zone>(conn, "dns_zone:")?.iter().any(|zone| {
        zone.provider_id == provider.id
            && Some(zone.id.as_str()) != zone_id
            && crate::dns::webhook_zone_name(&zone.name).is_ok_and(|other| other == name)
    }) {
        return reject(
            409,
            format!("the DNS webhook provider already has zone {name}"),
        );
    }
    Ok(())
}
/// Webhook records are named inside their zone and cannot be proxied.
fn check_webhook_record(conn: &Connection, zone: &Zone, record: &Record) -> Result<()> {
    let provider = read_provider(conn, &zone.provider_id)?.context("DNS provider not found")?;
    if provider.kind != ProviderKind::Webhook {
        return Ok(());
    }
    if record.proxied {
        return reject(400, "DNS webhook records cannot be proxied");
    }
    crate::dns::webhook_record_name(&zone.name, &record.name).or_else(invalid)?;
    Ok(())
}
fn require_admin(actor: &Actor) -> Result<()> {
    if actor.role != Role::SystemAdmin {
        return reject(403, "DNS management requires a system administrator");
    }
    Ok(())
}
/// `min_ttl` input: 0 means "no minimum".
fn parse_min_ttl(value: u32) -> Result<Option<u32>> {
    if value > 86_400 {
        return reject(
            400,
            "DNS provider min_ttl must be 0 (none) or 1..=86400 seconds",
        );
    }
    Ok((value > 0).then_some(value))
}
fn failover_confirm(value: u32) -> Result<u32> {
    if value > crate::dns::MAX_FAILOVER_CONFIRM_SECS {
        return reject(
            400,
            format!(
                "DNS failover_confirm_secs must be 0..={}",
                crate::dns::MAX_FAILOVER_CONFIRM_SECS
            ),
        );
    }
    Ok(value)
}
fn label(value: &str, maximum: usize, what: &str) -> Result<()> {
    if value.is_empty()
        || value.len() > maximum
        || value.trim() != value
        || value.chars().any(char::is_control)
    {
        return reject(
            400,
            format!(
                "{what} must contain 1..{maximum} bytes without surrounding whitespace or control characters"
            ),
        );
    }
    Ok(())
}
fn read_provider(conn: &Connection, id: &str) -> Result<Option<Provider>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            [provider_key(id)],
            |r| r.get(0),
        )
        .optional()?;
    Ok(raw.map(|value| serde_json::from_str(&value)).transpose()?)
}
fn write_provider(tx: &Transaction<'_>, provider: &Provider) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![provider_key(&provider.id), serde_json::to_string(provider)?],
    )?;
    Ok(())
}
fn read_zone(conn: &Connection, id: &str) -> Result<Option<Zone>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            [zone_key(id)],
            |r| r.get(0),
        )
        .optional()?;
    Ok(raw.map(|value| serde_json::from_str(&value)).transpose()?)
}
fn write_zone(tx: &Transaction<'_>, zone: &Zone) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![zone_key(&zone.id), serde_json::to_string(zone)?],
    )?;
    Ok(())
}
fn read_record(conn: &Connection, id: &str) -> Result<Option<Record>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            [record_key(id)],
            |r| r.get(0),
        )
        .optional()?;
    Ok(raw.map(|value| serde_json::from_str(&value)).transpose()?)
}
fn write_record(tx: &Transaction<'_>, record: &Record) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![record_key(&record.id), serde_json::to_string(record)?],
    )?;
    Ok(())
}
fn read_webhook_state(conn: &Connection, zone_id: &str) -> Result<WebhookState> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            [webhook_zone_key(zone_id)],
            |r| r.get(0),
        )
        .optional()?;
    Ok(raw
        .map(|value| serde_json::from_str(&value))
        .transpose()?
        .unwrap_or_default())
}
fn all<T: serde::de::DeserializeOwned>(conn: &Connection, prefix: &str) -> Result<Vec<T>> {
    let mut q = conn.prepare("SELECT value FROM metadata WHERE key GLOB ?1 ORDER BY key")?;
    let rows: Vec<String> = q
        .query_map([format!("{prefix}*")], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    rows.into_iter()
        .map(|value| serde_json::from_str(&value).context("invalid stored DNS record"))
        .collect()
}
/// Health gate: a record is active only while its linked node has a fresh
/// applied observation with at least one eligible healthy target for the
/// rule. Unknown, stale, disabled or absent nodes fail closed.
pub(super) fn health_ok(
    conn: &Connection,
    telemetry: &crate::telemetry::Telemetry,
    gate: &HealthGate,
) -> Result<bool> {
    let row: Option<(Option<i64>, String)> = conn
        .query_row(
            "SELECT last_seen_ms,COALESCE(stats_json,'{}') FROM nodes WHERE id=?1",
            [&gate.node_id],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )
        .optional()?;
    let Some((last_seen, stats)) = row else {
        return Ok(false);
    };
    let (last_seen, stats) = telemetry.current(&gate.node_id, last_seen, stats);
    if super::node_profiles::read(conn, &gate.node_id)?
        .settings
        .lifecycle(now_ms())
        != crate::node::NodeLifecycle::Active
        || last_seen.is_none_or(|seen| now_ms().saturating_sub(seen) > 90_000)
    {
        return Ok(false);
    }
    let stats: EngineStats =
        serde_json::from_str(&stats).context("invalid node health statistics")?;
    Ok(stats.target_health.iter().any(|report| {
        report.rule_id == gate.rule_id
            && report.eligible
            && report.status == crate::health::Status::Healthy
    }))
}
#[derive(Clone, Debug)]
pub struct NewDnsRecord {
    pub name: String,
    pub record_type: RecordType,
    pub content: String,
    pub ttl: u32,
    pub proxied: bool,
    pub health: Option<HealthGate>,
}
#[derive(Clone, Debug, Default)]
pub struct DnsRecordPatch {
    pub name: Option<String>,
    pub content: Option<String>,
    pub ttl: Option<u32>,
    pub proxied: Option<bool>,
    pub enabled: Option<bool>,
    /// `Some` replaces the gate; `None` leaves it unchanged.
    pub health: Option<HealthGate>,
    /// Explicitly remove the health gate when true.
    pub clear_health: bool,
}
impl Store {
    pub fn dns_providers(&self, actor: &Actor) -> Result<Vec<ProviderView>> {
        require_admin(actor)?;
        let conn = self.0.lock().unwrap();
        Ok(all::<Provider>(&conn, "dns_provider:")?
            .iter()
            .map(ProviderView::from)
            .collect())
    }
    pub fn dns_provider(&self, actor: &Actor, id: &str) -> Result<ProviderView> {
        require_admin(actor)?;
        let conn = self.0.lock().unwrap();
        read_provider(&conn, id)?
            .map(|provider| ProviderView::from(&provider))
            .context("DNS provider not found")
    }
    pub(crate) fn dns_provider_raw(&self, id: &str) -> Result<Provider> {
        let conn = self.0.lock().unwrap();
        read_provider(&conn, id)?.context("DNS provider not found")
    }
    #[allow(clippy::too_many_arguments)]
    pub fn create_dns_provider(
        &self,
        actor: &Actor,
        name: &str,
        kind: ProviderKind,
        endpoint: &str,
        token: &str,
        min_ttl: u32,
        webhook: WebhookSettings,
    ) -> Result<ProviderView> {
        require_admin(actor)?;
        label(name, 120, "DNS provider name")?;
        let endpoint = match kind {
            ProviderKind::Cloudflare => crate::dns::validate_endpoint(endpoint)?,
            ProviderKind::Webhook => crate::dns::validate_webhook_url(endpoint).or_else(invalid)?,
        };
        if token.is_empty() || token.len() > 4096 || token.chars().any(char::is_control) {
            return reject(
                400,
                "DNS provider token must be 1..4096 bytes without control characters",
            );
        }
        let mut provider = Provider {
            id: Uuid::new_v4().to_string(),
            name: name.into(),
            kind,
            endpoint,
            token: token.into(),
            min_ttl: parse_min_ttl(min_ttl)?,
            zones: vec![],
            timeout_secs: None,
            created_at_ms: now_ms(),
        };
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        webhook_settings(&tx, &mut provider, webhook)?;
        write_provider(&tx, &provider)?;
        audit(
            &tx,
            &actor.id,
            "dns.provider.create",
            &provider.id,
            &serde_json::json!({"name":provider.name,"kind":provider.kind,"endpoint":provider.endpoint,"min_ttl":provider.min_ttl,"zones":provider.zones,"timeout_secs":provider.timeout_secs}).to_string(),
        )?;
        tx.commit()?;
        Ok(ProviderView::from(&provider))
    }
    #[allow(clippy::too_many_arguments)]
    pub fn update_dns_provider(
        &self,
        actor: &Actor,
        id: &str,
        name: Option<&str>,
        endpoint: Option<&str>,
        token: Option<&str>,
        min_ttl: Option<u32>,
        webhook: WebhookSettings,
    ) -> Result<ProviderView> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut provider = read_provider(&tx, id)?.context("DNS provider not found")?;
        if let Some(value) = min_ttl {
            provider.min_ttl = parse_min_ttl(value)?;
        }
        if let Some(value) = name {
            label(value, 120, "DNS provider name")?;
            provider.name = value.into();
        }
        if let Some(value) = endpoint {
            provider.endpoint = match provider.kind {
                ProviderKind::Cloudflare => crate::dns::validate_endpoint(value)?,
                ProviderKind::Webhook => {
                    crate::dns::validate_webhook_url(value).or_else(invalid)?
                }
            };
        }
        if let Some(value) = token {
            if value.is_empty() || value.len() > 4096 || value.chars().any(char::is_control) {
                return reject(
                    400,
                    "DNS provider token must be 1..4096 bytes without control characters",
                );
            }
            provider.token = value.into();
        }
        webhook_settings(&tx, &mut provider, webhook)?;
        write_provider(&tx, &provider)?;
        audit(&tx, &actor.id, "dns.provider.update", &provider.id, "{}")?;
        tx.commit()?;
        Ok(ProviderView::from(&provider))
    }
    pub fn delete_dns_provider(&self, actor: &Actor, id: &str) -> Result<()> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let provider = read_provider(&tx, id)?.context("DNS provider not found")?;
        let zones: i64 = tx.query_row(
            "SELECT COUNT(*) FROM metadata WHERE key GLOB 'dns_zone:*' AND json_extract(value,'$.provider_id')=?1",
            [&provider.id],
            |r| r.get(0),
        )?;
        if zones > 0 {
            return reject(
                409,
                "delete or move zones before deleting this DNS provider",
            );
        }
        tx.execute("DELETE FROM metadata WHERE key=?1", [provider_key(id)])?;
        tx.execute(
            "DELETE FROM metadata WHERE key=?1",
            [webhook_source_key(id)],
        )?;
        audit(&tx, &actor.id, "dns.provider.delete", id, "{}")?;
        tx.commit()?;
        Ok(())
    }

    pub fn dns_zones(&self, actor: &Actor) -> Result<Vec<Zone>> {
        require_admin(actor)?;
        let conn = self.0.lock().unwrap();
        all::<Zone>(&conn, "dns_zone:")
    }
    pub fn dns_zone(&self, actor: &Actor, id: &str) -> Result<Zone> {
        require_admin(actor)?;
        let conn = self.0.lock().unwrap();
        read_zone(&conn, id)?.context("DNS zone not found")
    }
    pub(crate) fn dns_zone_raw(&self, id: &str) -> Result<Zone> {
        let conn = self.0.lock().unwrap();
        read_zone(&conn, id)?.context("DNS zone not found")
    }
    pub fn create_dns_zone(
        &self,
        actor: &Actor,
        provider_id: &str,
        name: &str,
        mode: ZoneMode,
        min_keep: u32,
        failover_confirm_secs: u32,
    ) -> Result<Zone> {
        require_admin(actor)?;
        crate::dns::validate_zone_name(name)?;
        if min_keep > 1000 {
            return reject(400, "DNS min_keep must be 0..1000");
        }
        let failover_confirm_secs = failover_confirm(failover_confirm_secs)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let provider = read_provider(&tx, provider_id)?.context("DNS provider not found")?;
        check_webhook_zone(&tx, &provider, name, None)?;
        let zone = Zone {
            id: Uuid::new_v4().to_string(),
            provider_id: provider_id.into(),
            name: name.into(),
            mode,
            min_keep,
            failover_confirm_secs,
            created_at_ms: now_ms(),
        };
        write_zone(&tx, &zone)?;
        audit(&tx, &actor.id, "dns.zone.create", &zone.id, &serde_json::json!({"provider_id":provider_id,"name":name,"mode":mode,"min_keep":min_keep,"failover_confirm_secs":failover_confirm_secs}).to_string())?;
        tx.commit()?;
        Ok(zone)
    }
    pub fn update_dns_zone(
        &self,
        actor: &Actor,
        id: &str,
        name: Option<&str>,
        mode: Option<ZoneMode>,
        min_keep: Option<u32>,
        failover_confirm_secs: Option<u32>,
    ) -> Result<Zone> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut zone = read_zone(&tx, id)?.context("DNS zone not found")?;
        if let Some(value) = failover_confirm_secs {
            zone.failover_confirm_secs = failover_confirm(value)?;
        }
        if let Some(value) = name {
            crate::dns::validate_zone_name(value)?;
            let provider =
                read_provider(&tx, &zone.provider_id)?.context("DNS provider not found")?;
            check_webhook_zone(&tx, &provider, value, Some(&zone.id))?;
            // The receiver keeps acknowledged sets under the old zone name.
            if provider.kind == ProviderKind::Webhook
                && crate::dns::webhook_zone_name(value).ok()
                    != crate::dns::webhook_zone_name(&zone.name).ok()
                && !read_webhook_state(&tx, &zone.id)?.is_empty()
            {
                return reject(
                    409,
                    "remove this zone's records from the webhook receiver before renaming it",
                );
            }
            zone.name = value.into();
        }
        if let Some(value) = mode {
            zone.mode = value;
        }
        if let Some(value) = min_keep {
            if value > 1000 {
                return reject(400, "DNS min_keep must be 0..1000");
            }
            zone.min_keep = value;
        }
        write_zone(&tx, &zone)?;
        audit(&tx, &actor.id, "dns.zone.update", &zone.id, "{}")?;
        tx.commit()?;
        Ok(zone)
    }
    pub fn delete_dns_zone(&self, actor: &Actor, id: &str) -> Result<()> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let zone = read_zone(&tx, id)?.context("DNS zone not found")?;
        let records: i64 = tx.query_row(
            "SELECT COUNT(*) FROM metadata WHERE key GLOB 'dns_record:*' AND json_extract(value,'$.zone_id')=?1",
            [&zone.id],
            |r| r.get(0),
        )?;
        if records > 0 {
            return reject(409, "delete DNS records before deleting this zone");
        }
        tx.execute("DELETE FROM metadata WHERE key=?1", [zone_key(id)])?;
        tx.execute("DELETE FROM metadata WHERE key=?1", [webhook_zone_key(id)])?;
        audit(&tx, &actor.id, "dns.zone.delete", id, "{}")?;
        tx.commit()?;
        Ok(())
    }

    /// Process-local DNS sync state (locks, confirmation windows, status).
    pub fn dns_runtime(&self) -> &crate::dns::Runtime {
        &self.9
    }
    fn dns_record_view(&self, record: &Record) -> RecordView {
        let mut view = RecordView::from(record);
        view.status = self.9.record_status(&record.id);
        view
    }
    /// Zone and record IDs for the background synchroniser.
    pub(crate) fn dns_ids(&self) -> Result<(Vec<String>, Vec<String>)> {
        let conn = self.0.lock().unwrap();
        let zones = all::<Zone>(&conn, "dns_zone:")?;
        let records = all::<Record>(&conn, "dns_record:")?;
        Ok((
            zones.into_iter().map(|zone| zone.id).collect(),
            records.into_iter().map(|record| record.id).collect(),
        ))
    }
    pub fn dns_records(&self, actor: &Actor, zone_id: &str) -> Result<Vec<RecordView>> {
        require_admin(actor)?;
        let records = {
            let conn = self.0.lock().unwrap();
            read_zone(&conn, zone_id)?.context("DNS zone not found")?;
            all::<Record>(&conn, "dns_record:")?
        };
        Ok(records
            .iter()
            .filter(|record| record.zone_id == zone_id)
            .map(|record| self.dns_record_view(record))
            .collect())
    }
    pub(crate) fn dns_records_for_zone(&self, zone_id: &str) -> Result<Vec<Record>> {
        let conn = self.0.lock().unwrap();
        Ok(all::<Record>(&conn, "dns_record:")?
            .into_iter()
            .filter(|record| record.zone_id == zone_id)
            .collect())
    }
    pub(crate) fn dns_record_raw(&self, id: &str) -> Result<Record> {
        let conn = self.0.lock().unwrap();
        read_record(&conn, id)?.context("DNS record not found")
    }
    pub fn dns_record(&self, actor: &Actor, id: &str) -> Result<RecordView> {
        require_admin(actor)?;
        self.dns_record_raw(id)
            .map(|record| self.dns_record_view(&record))
    }
    pub fn create_dns_record(
        &self,
        actor: &Actor,
        zone_id: &str,
        input: NewDnsRecord,
    ) -> Result<RecordView> {
        require_admin(actor)?;
        crate::dns::validate_record(input.record_type, &input.name, &input.content, input.ttl)?;
        crate::dns::validate_health(input.health.as_ref())?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        if input.health.is_some() {
            features::require(&tx, "dns-health", "DNS health gating")?;
        }
        let zone = read_zone(&tx, zone_id)?.context("DNS zone not found")?;
        let record = Record {
            id: Uuid::new_v4().to_string(),
            zone_id: zone.id.clone(),
            name: input.name.clone(),
            record_type: input.record_type,
            content: input.content.clone(),
            ttl: input.ttl,
            proxied: input.proxied,
            enabled: true,
            health: input.health,
            provider_record_id: None,
            last_observed: None,
            last_error: None,
            updated_at_ms: now_ms(),
        };
        check_webhook_record(&tx, &zone, &record)?;
        write_record(&tx, &record)?;
        audit(&tx, &actor.id, "dns.record.create", &record.id, &serde_json::json!({"zone_id":record.zone_id,"name":input.name,"type":input.record_type,"content":input.content}).to_string())?;
        tx.commit()?;
        Ok(RecordView::from(&record))
    }
    pub fn update_dns_record(
        &self,
        actor: &Actor,
        id: &str,
        patch: DnsRecordPatch,
    ) -> Result<RecordView> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut record = read_record(&tx, id)?.context("DNS record not found")?;
        if let Some(value) = patch.name {
            record.name = value;
        }
        if let Some(value) = patch.content {
            record.content = value;
        }
        if let Some(value) = patch.ttl {
            record.ttl = value;
        }
        if let Some(value) = patch.proxied {
            record.proxied = value;
        }
        if let Some(value) = patch.enabled {
            record.enabled = value;
        }
        if patch.clear_health {
            record.health = None;
        } else if let Some(value) = patch.health {
            features::require(&tx, "dns-health", "DNS health gating")?;
            record.health = Some(value);
        }
        crate::dns::validate_record(
            record.record_type,
            &record.name,
            &record.content,
            record.ttl,
        )?;
        let zone = read_zone(&tx, &record.zone_id)?.context("DNS zone not found")?;
        check_webhook_record(&tx, &zone, &record)?;
        record.updated_at_ms = now_ms();
        write_record(&tx, &record)?;
        audit(&tx, &actor.id, "dns.record.update", &record.id, "{}")?;
        tx.commit()?;
        Ok(self.dns_record_view(&record))
    }
    /// Removes the local record and returns it so the caller can delete the
    /// provider record if the zone is in apply mode.
    pub fn delete_dns_record(&self, actor: &Actor, id: &str) -> Result<Record> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let record = read_record(&tx, id)?.context("DNS record not found")?;
        tx.execute("DELETE FROM metadata WHERE key=?1", [record_key(id)])?;
        audit(&tx, &actor.id, "dns.record.delete", id, "{}")?;
        tx.commit()?;
        self.9.forget_record(id);
        Ok(record)
    }
    pub(crate) fn dns_health_ok(&self, gate: &HealthGate) -> Result<bool> {
        health_ok(&self.0.lock().unwrap(), &self.4, gate)
    }
    pub fn dns_record_synced(
        &self,
        id: &str,
        provider_id: Option<&str>,
        observed: Option<&str>,
    ) -> Result<()> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut record = read_record(&tx, id)?.context("DNS record not found")?;
        // The background pass confirms unchanged records every tick; do not
        // rewrite metadata (and the recovery log) for that.
        if record.last_error.is_none()
            && provider_id.is_none_or(|value| record.provider_record_id.as_deref() == Some(value))
            && observed.is_none_or(|value| record.last_observed.as_deref() == Some(value))
        {
            return Ok(());
        }
        if let Some(value) = provider_id {
            record.provider_record_id = Some(value.into());
        }
        if let Some(value) = observed {
            record.last_observed = Some(value.into());
        }
        record.last_error = None;
        record.updated_at_ms = now_ms();
        write_record(&tx, &record)?;
        tx.commit()?;
        Ok(())
    }
    pub fn dns_record_failed(&self, id: &str, error: &str) -> Result<()> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut record = read_record(&tx, id)?.context("DNS record not found")?;
        let error: String = error.chars().take(512).collect();
        if record.last_error.as_deref() == Some(error.as_str()) {
            return Ok(());
        }
        record.last_error = Some(error);
        record.updated_at_ms = now_ms();
        write_record(&tx, &record)?;
        tx.commit()?;
        Ok(())
    }
    /// What the zone's webhook receiver acknowledged, by record ID.
    pub(crate) fn dns_webhook_state(&self, zone_id: &str) -> Result<WebhookState> {
        read_webhook_state(&self.0.lock().unwrap(), zone_id)
    }
    pub(crate) fn set_dns_webhook_state(&self, zone_id: &str, state: &WebhookState) -> Result<()> {
        let conn = self.0.lock().unwrap();
        if state.is_empty() {
            conn.execute(
                "DELETE FROM metadata WHERE key=?1",
                [webhook_zone_key(zone_id)],
            )?;
        } else {
            conn.execute(
                "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
                params![webhook_zone_key(zone_id), serde_json::to_string(state)?],
            )?;
        }
        Ok(())
    }
    /// Records and returns a provider's next webhook generation: one above
    /// the last, and at least `floor`. Kept before it is sent, so that a
    /// generation is never offered twice.
    pub(crate) fn dns_webhook_generation(&self, provider_id: &str, floor: u64) -> Result<u64> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let last: u64 = tx
            .query_row(
                "SELECT value FROM metadata WHERE key=?1",
                [webhook_source_key(provider_id)],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .map(|value| value.parse())
            .transpose()
            .context("invalid stored DNS webhook generation")?
            .unwrap_or(0);
        let next = last.saturating_add(1).max(floor);
        // Generations are decimal strings of 1..=i64::MAX.
        ensure!(
            next <= i64::MAX as u64,
            "DNS webhook generations are exhausted"
        );
        tx.execute(
            "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![webhook_source_key(provider_id), next.to_string()],
        )?;
        tx.commit()?;
        Ok(next)
    }
    pub fn dns_record_removed(&self, id: &str) -> Result<()> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut record = read_record(&tx, id)?.context("DNS record not found")?;
        record.provider_record_id = None;
        record.last_observed = None;
        record.updated_at_ms = now_ms();
        write_record(&tx, &record)?;
        tx.commit()?;
        Ok(())
    }
}
