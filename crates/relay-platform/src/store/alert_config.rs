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
        let mut q =
            conn.prepare("SELECT id,name,last_seen_ms,token_hash IS NOT NULL FROM nodes")?;
        let rows: Vec<(String, String, Option<i64>, bool)> = q
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?;
        let now = now_ms();
        rows.into_iter()
            .map(|(id, name, last_seen_ms, enrolled)| {
                let active = node_profiles::read(&conn, &id)?.settings.lifecycle(now)
                    == crate::node::NodeLifecycle::Active;
                Ok(AlertNode {
                    watched: enrolled && active,
                    id,
                    name,
                    last_seen_ms,
                })
            })
            .collect()
    }
    pub fn alert_overview(&self, actor: &Actor) -> Result<serde_json::Value> {
        require_admin(actor)?;
        let (settings, channels) = self.alert_config()?;
        let views: Vec<ChannelView> = channels.iter().map(Channel::view).collect();
        Ok(serde_json::json!({
            "settings": settings,
            "channels": views,
            "incidents": self.5.snapshot(),
        }))
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
