//! DNS provider, zone and managed-record persistence. Records live in metadata
//! so the schema and recovery journal stay unchanged; provider tokens are
//! reversible and therefore restricted to system administrators.
use super::*;
use crate::dns::{
    HealthGate, Provider, ProviderKind, ProviderView, Record, RecordType, RecordView, Zone,
    ZoneMode,
};

fn provider_key(id: &str) -> String {
    format!("dns_provider:{id}")
}
fn zone_key(id: &str) -> String {
    format!("dns_zone:{id}")
}
fn record_key(id: &str) -> String {
    format!("dns_record:{id}")
}
fn require_admin(actor: &Actor) -> Result<()> {
    if actor.role != Role::SystemAdmin {
        return reject(403, "DNS management requires a system administrator");
    }
    Ok(())
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
fn all<T: serde::de::DeserializeOwned>(conn: &Connection, prefix: &str) -> Result<Vec<T>> {
    let mut q = conn.prepare("SELECT value FROM metadata WHERE key GLOB ?1 ORDER BY key")?;
    let rows: Vec<String> = q
        .query_map([format!("{prefix}*")], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    rows.into_iter()
        .map(|value| serde_json::from_str(&value).context("invalid stored DNS record"))
        .collect()
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
    pub fn create_dns_provider(
        &self,
        actor: &Actor,
        name: &str,
        kind: ProviderKind,
        endpoint: &str,
        token: &str,
    ) -> Result<ProviderView> {
        require_admin(actor)?;
        label(name, 120, "DNS provider name")?;
        let endpoint = crate::dns::validate_endpoint(endpoint)?;
        if token.is_empty() || token.len() > 4096 || token.chars().any(char::is_control) {
            return reject(
                400,
                "DNS provider token must be 1..4096 bytes without control characters",
            );
        }
        let provider = Provider {
            id: Uuid::new_v4().to_string(),
            name: name.into(),
            kind,
            endpoint,
            token: token.into(),
            created_at_ms: now_ms(),
        };
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        write_provider(&tx, &provider)?;
        audit(
            &tx,
            &actor.id,
            "dns.provider.create",
            &provider.id,
            &serde_json::json!({"name":provider.name,"kind":provider.kind,"endpoint":provider.endpoint}).to_string(),
        )?;
        tx.commit()?;
        Ok(ProviderView::from(&provider))
    }
    pub fn update_dns_provider(
        &self,
        actor: &Actor,
        id: &str,
        name: Option<&str>,
        endpoint: Option<&str>,
        token: Option<&str>,
    ) -> Result<ProviderView> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut provider = read_provider(&tx, id)?.context("DNS provider not found")?;
        if let Some(value) = name {
            label(value, 120, "DNS provider name")?;
            provider.name = value.into();
        }
        if let Some(value) = endpoint {
            provider.endpoint = crate::dns::validate_endpoint(value)?;
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
    ) -> Result<Zone> {
        require_admin(actor)?;
        crate::dns::validate_zone_name(name)?;
        if min_keep > 1000 {
            return reject(400, "DNS min_keep must be 0..1000");
        }
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        read_provider(&tx, provider_id)?.context("DNS provider not found")?;
        let zone = Zone {
            id: Uuid::new_v4().to_string(),
            provider_id: provider_id.into(),
            name: name.into(),
            mode,
            min_keep,
            created_at_ms: now_ms(),
        };
        write_zone(&tx, &zone)?;
        audit(&tx, &actor.id, "dns.zone.create", &zone.id, &serde_json::json!({"provider_id":provider_id,"name":name,"mode":mode,"min_keep":min_keep}).to_string())?;
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
    ) -> Result<Zone> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut zone = read_zone(&tx, id)?.context("DNS zone not found")?;
        if let Some(value) = name {
            crate::dns::validate_zone_name(value)?;
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
        audit(&tx, &actor.id, "dns.zone.delete", id, "{}")?;
        tx.commit()?;
        Ok(())
    }

    pub fn dns_records(&self, actor: &Actor, zone_id: &str) -> Result<Vec<RecordView>> {
        require_admin(actor)?;
        let conn = self.0.lock().unwrap();
        read_zone(&conn, zone_id)?.context("DNS zone not found")?;
        Ok(all::<Record>(&conn, "dns_record:")?
            .iter()
            .filter(|record| record.zone_id == zone_id)
            .map(RecordView::from)
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
            .map(|record| RecordView::from(&record))
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
        let zone = read_zone(&tx, zone_id)?.context("DNS zone not found")?;
        read_provider(&tx, &zone.provider_id)?.context("DNS provider not found")?;
        let record = Record {
            id: Uuid::new_v4().to_string(),
            zone_id: zone.id,
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
            record.health = Some(value);
        }
        crate::dns::validate_record(
            record.record_type,
            &record.name,
            &record.content,
            record.ttl,
        )?;
        record.updated_at_ms = now_ms();
        write_record(&tx, &record)?;
        audit(&tx, &actor.id, "dns.record.update", &record.id, "{}")?;
        tx.commit()?;
        Ok(RecordView::from(&record))
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
        Ok(record)
    }
    /// Health gate: a record is active only while its linked node has a fresh
    /// applied observation with at least one eligible healthy target for the
    /// rule. Unknown, stale, disabled or absent nodes fail closed.
    pub(crate) fn dns_health_ok(&self, gate: &HealthGate) -> Result<bool> {
        let conn = self.0.lock().unwrap();
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
        if super::node_profiles::read(&conn, &gate.node_id)?
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
    pub fn dns_record_synced(
        &self,
        id: &str,
        provider_id: Option<&str>,
        observed: Option<&str>,
    ) -> Result<()> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut record = read_record(&tx, id)?.context("DNS record not found")?;
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
        record.last_error = Some(error.chars().take(512).collect());
        record.updated_at_ms = now_ms();
        write_record(&tx, &record)?;
        tx.commit()?;
        Ok(())
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
