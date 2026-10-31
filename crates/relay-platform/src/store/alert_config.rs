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
                let active = node_profiles::read(&conn, &id)?.settings.lifecycle(now)
                    == crate::node::NodeLifecycle::Active;
                Ok(AlertNode {
                    tenant_id,
                    watched: enrolled && active,
                    last_seen_ms: self.4.current(&id, last_seen_ms, String::new()).0,
                    id,
                    name,
                })
            })
            .collect()
    }
    pub fn alert_overview(&self, actor: &Actor) -> Result<serde_json::Value> {
        if actor.role == Role::Viewer {
            return reject(403, "tenant administrator required");
        }
        let conn = self.0.lock().unwrap();
        let settings: Settings = read(&conn, SETTINGS)?;
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
            let mut q = conn.prepare("SELECT id FROM nodes WHERE tenant_id=?1")?;
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
        for (node, tenant) in ownership {
            if channel.tenant_id.as_ref().is_some_and(|t| t != tenant) {
                return Ok(false);
            }
            let current: Option<String> = conn
                .query_row("SELECT tenant_id FROM nodes WHERE id=?1", [node], |r| {
                    r.get(0)
                })
                .optional()?;
            if current.as_ref() != Some(tenant) {
                return Ok(false);
            }
        }
        Ok(true)
    }
    pub fn set_alert_settings(&self, actor: &Actor, settings: Settings) -> Result<()> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
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
