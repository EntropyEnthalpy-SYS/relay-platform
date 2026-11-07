//! Alert channels and settings in `metadata`, so the schema, backups and the
//! recovery journal stay at schema v4. Only system administrators manage them.
use super::*;
use crate::alerts::{Channel, ChannelView, MAX_CHANNELS, Settings};

const CHANNELS: &str = "alert_channels";
const SETTINGS: &str = "alert_settings";

fn read<T: serde::de::DeserializeOwned + Default>(conn: &Connection, key: &str) -> Result<T> {
    let value: Option<String> = conn
        .query_row("SELECT value FROM metadata WHERE key=?1", [key], |r| {
            r.get(0)
        })
        .optional()?;
    Ok(value
        .map(|s| serde_json::from_str(&s))
        .transpose()?
        .unwrap_or_default())
}
fn write<T: Serialize>(tx: &Transaction<'_>, key: &str, value: &T) -> Result<()> {
    tx.execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, serde_json::to_string(value)?])?;
    Ok(())
}
fn require_admin(actor: &Actor) -> Result<()> {
    if actor.role != Role::SystemAdmin {
        return reject(403, "system administrator required");
    }
    Ok(())
}

/// A node as the alert worker sees it.
pub struct AlertNode {
    pub tenant_id: String,
    pub id: String,
    pub name: String,
    pub last_seen_ms: Option<i64>,
    /// Enrolled and allowed to run, so silence is a problem.
    pub watched: bool,
    /// The node profile's expiry.
    pub expires_at_ms: Option<i64>,
    /// The newest report's resources; none before a report reaches this controller.
    pub usage: Option<crate::telemetry::Sample>,
}
/// A shared budget as the alert worker sees it. A plan budget that resets
/// reports its current cycle: both byte counts start at the cycle's baseline.
pub struct AlertBudget {
    pub tenant_id: String,
    pub id: String,
    pub name: String,
    pub limit_bytes: u64,
    pub committed_bytes: u64,
    /// Why a plan's automatic top-up for this budget's cycle did not run.
    pub top_up_failure: Option<crate::commerce::TopUpFailureReason>,
}
/// A managed DNS record as the alert worker sees it. Records belong to no tenant.
pub struct AlertDnsRecord {
    pub id: String,
    /// The record's name and type.
    pub name: String,
    /// Why the last provider sync failed.
    pub error: Option<String>,
}

impl Store {
    pub fn alerts(&self) -> Arc<crate::alerts::Alerts> {
        self.5.clone()
    }
    pub fn telemetry_events_after(&self, after: u64) -> Vec<crate::telemetry::Event> {
        self.4.events_after(after)
    }
    pub fn alert_config(&self) -> Result<(Settings, Vec<Channel>)> {
        let conn = self.0.lock().unwrap();
        Ok((read(&conn, SETTINGS)?, read(&conn, CHANNELS)?))
    }
    pub fn alert_nodes(&self) -> Result<Vec<AlertNode>> {
        let conn = self.0.lock().unwrap();
        let mut q = conn
            .prepare("SELECT id,name,last_seen_ms,token_hash IS NOT NULL,tenant_id FROM nodes")?;
        let rows: Vec<(String, String, Option<i64>, bool, String)> = q
            .query_map([], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<rusqlite::Result<_>>()?;
        let now = now_ms();
        rows.into_iter()
            .map(|(id, name, last_seen_ms, enrolled, tenant_id)| {
                let profile = node_profiles::read(&conn, &id)?.settings;
                let active = profile.lifecycle(now) == crate::node::NodeLifecycle::Active;
                Ok(AlertNode {
                    tenant_id,
                    watched: enrolled && active,
                    last_seen_ms: self.4.current(&id, last_seen_ms, String::new()).0,
                    expires_at_ms: profile.expires_at_ms,
                    usage: self.4.latest(&id),
                    id,
                    name,
                })
            })
            .collect()
    }
    pub fn alert_budgets(&self) -> Result<Vec<AlertBudget>> {
        let conn = self.0.lock().unwrap();
        let mut q = conn.prepare(
            "SELECT tenant_id,id,name,limit_bytes,committed_bytes,scope,scope_id FROM budgets",
        )?;
        let rows = q
            .query_map([], |r| {
                Ok((
                    AlertBudget {
                        tenant_id: r.get(0)?,
                        id: r.get(1)?,
                        name: r.get(2)?,
                        limit_bytes: r.get(3)?,
                        committed_bytes: r.get(4)?,
                        top_up_failure: None,
                    },
                    r.get::<_, String>(5)? == "user",
                    r.get::<_, String>(6)?,
                ))
            })?
            .collect::<rusqlite::Result<Vec<_>>>()?;
        rows.into_iter()
            .map(|(mut budget, user, scope_id)| {
                if user {
                    // A plan that resets is judged on its current cycle, not
                    // on the counters of every cycle before it.
                    if let Some(baseline) =
                        super::commerce::cycle_baseline(&conn, &scope_id, &budget.id)?
                    {
                        budget.limit_bytes = budget.limit_bytes.saturating_sub(baseline);
                        budget.committed_bytes = budget.committed_bytes.saturating_sub(baseline);
                    }
                    budget.top_up_failure =
                        super::commerce::top_up_failure(&conn, &scope_id, &budget.id)?;
                }
                Ok(budget)
            })
            .collect()
    }
    /// Read straight from the stored records, so the alert worker depends
    /// on nothing but their id, name, type and last error.
    pub fn alert_dns_records(&self) -> Result<Vec<AlertDnsRecord>> {
        #[derive(Deserialize)]
        struct Stored {
            id: String,
            name: String,
            #[serde(rename = "type", default)]
            record_type: String,
            #[serde(default)]
            last_error: Option<String>,
        }
        let conn = self.0.lock().unwrap();
        let mut q = conn.prepare("SELECT value FROM metadata WHERE key GLOB 'dns_record:*'")?;
        let rows: Vec<String> = q
            .query_map([], |r| r.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        Ok(rows
            .iter()
            .filter_map(|value| serde_json::from_str::<Stored>(value).ok())
            .map(|record| AlertDnsRecord {
                name: format!("{} {}", record.name, record.record_type)
                    .trim_end()
                    .to_string(),
                id: record.id,
                error: record.last_error,
            })
            .collect())
    }
    pub fn alert_overview(&self, actor: &Actor) -> Result<serde_json::Value> {
        if actor.role == Role::Viewer {
            return reject(403, "tenant administrator required");
        }
        let conn = self.0.lock().unwrap();
        let mut settings: Settings = read(&conn, SETTINGS)?;
        // Shown in full, with the defaults of rules never saved.
        settings.rules.get_or_insert_default();
        let channels: Vec<Channel> = read(&conn, CHANNELS)?;
        let admin = actor.role == Role::SystemAdmin;
        let views: Vec<ChannelView> = channels
            .iter()
            .filter(|c| admin || c.tenant_id.as_deref() == Some(&actor.tenant_id))
            .map(|c| {
                let mut v = c.view();
                if !admin {
                    v.smtp = None;
                }
                v
            })
            .collect();
        let mut incidents = self.5.snapshot();
        if !admin {
            // The tenant's nodes and budgets, by owner key.
            let mut q = conn.prepare(
                "SELECT id FROM nodes WHERE tenant_id=?1 UNION ALL SELECT 'budget:'||id FROM budgets WHERE tenant_id=?1",
            )?;
            let nodes: std::collections::HashSet<String> = q
                .query_map([&actor.tenant_id], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?;
            let permitted = |i: &crate::alerts::Incident| {
                i.tenant_id == actor.tenant_id && nodes.contains(&i.node_id)
            };
            incidents.open.retain(permitted);
            incidents.resolved.retain(permitted);
            incidents.deliveries.retain(|d| {
                d.tenant_id.as_deref() == Some(&actor.tenant_id)
                    && views.iter().any(|c| c.id == d.channel_id)
            });
        }
        Ok(
            serde_json::json!({"settings": settings, "channels": views, "incidents": incidents, "can_manage": admin}),
        )
    }
    /// Rechecked before every asynchronous attempt, including retries.
    pub fn alert_delivery_permitted(
        &self,
        channel: &Channel,
        ownership: &[(String, String)],
    ) -> Result<bool> {
        let conn = self.0.lock().unwrap();
        let channels: Vec<Channel> = read(&conn, CHANNELS)?;
        if !channel.enabled || !channels.iter().any(|c| c == channel) {
            return Ok(false);
        }
        for (owner, tenant) in ownership {
            if channel.tenant_id.as_ref().is_some_and(|t| t != tenant) {
                return Ok(false);
            }
            let current: Option<String> = if let Some(id) = owner.strip_prefix("budget:") {
                conn.query_row("SELECT tenant_id FROM budgets WHERE id=?1", [id], |r| {
                    r.get(0)
                })
                .optional()?
            } else if owner.starts_with("dns_record:") {
                // The owner key is the record's metadata key; records have no tenant.
                conn.query_row("SELECT '' FROM metadata WHERE key=?1", [owner], |r| {
                    r.get(0)
                })
                .optional()?
            } else {
                conn.query_row("SELECT tenant_id FROM nodes WHERE id=?1", [owner], |r| {
                    r.get(0)
                })
                .optional()?
            };
            if current.as_ref() != Some(tenant) {
                return Ok(false);
            }
        }
        Ok(true)
    }
    /// Saves the settings; without `rules` the saved rules stay.
    pub fn set_alert_settings(&self, actor: &Actor, mut settings: Settings) -> Result<()> {
        require_admin(actor)?;
        if let Some(Err(error)) = settings.rules.as_ref().map(|r| r.validate()) {
            return reject(400, error.to_string());
        }
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        if settings.rules.is_none() {
            settings.rules = read::<Settings>(&tx, SETTINGS)?.rules;
        }
        write(&tx, SETTINGS, &settings)?;
        audit(
            &tx,
            &actor.id,
            "alerts.settings",
            "alerts",
            &serde_json::to_string(&settings)?,
        )?;
        tx.commit()?;
        Ok(())
    }
    /// Creates a channel, or replaces one keeping secrets the input left blank.
    pub fn save_alert_channel(
        &self,
        actor: &Actor,
        id: Option<&str>,
        mut channel: Channel,
    ) -> Result<ChannelView> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        if let Some(tenant) = &channel.tenant_id {
            let exists: bool = tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM tenants WHERE id=?1)",
                [tenant],
                |r| r.get(0),
            )?;
            if !exists {
                return reject(400, "alert tenant not found");
            }
        }
        let mut channels: Vec<Channel> = read(&tx, CHANNELS)?;
        match id {
            Some(id) => {
                let Some(position) = channels.iter().position(|c| c.id == id) else {
                    return reject(404, "alert channel not found");
                };
                channel.id = id.into();
                channel.keep_secrets_from(&channels[position]);
                if let Err(error) = channel.validate() {
                    return reject(400, error.to_string());
                }
                channels[position] = channel.clone();
            }
            None => {
                if channels.len() >= MAX_CHANNELS {
                    return reject(409, "at most 20 alert channels");
                }
                channel.id = Uuid::new_v4().to_string();
                if let Err(error) = channel.validate() {
                    return reject(400, error.to_string());
                }
                channels.push(channel.clone());
            }
        }
        write(&tx, CHANNELS, &channels)?;
        let view = channel.view();
        audit(
            &tx,
            &actor.id,
            if id.is_some() {
                "alerts.channel.update"
            } else {
                "alerts.channel.create"
            },
            &view.id,
            &serde_json::to_string(&view)?,
        )?;
        tx.commit()?;
        Ok(view)
    }
    pub fn delete_alert_channel(&self, actor: &Actor, id: &str) -> Result<()> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut channels: Vec<Channel> = read(&tx, CHANNELS)?;
        let before = channels.len();
        channels.retain(|c| c.id != id);
        if channels.len() == before {
            return reject(404, "alert channel not found");
        }
        write(&tx, CHANNELS, &channels)?;
        audit(&tx, &actor.id, "alerts.channel.delete", id, "{}")?;
        tx.commit()?;
        Ok(())
    }
    pub fn alert_channel(&self, actor: &Actor, id: &str) -> Result<Channel> {
        require_admin(actor)?;
        let (_, channels) = self.alert_config()?;
        match channels.into_iter().find(|c| c.id == id) {
            Some(channel) => Ok(channel),
            None => reject(404, "alert channel not found"),
        }
    }
}
