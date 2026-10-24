use super::*;
use crate::node::{
    NodeBatchEntry, NodeFilter, NodeProfile, NodeSettings, NodeUpdate, NodeUpdateResult,
};
use std::collections::HashSet;

fn key(node: &str) -> String {
    format!("node_profile:{node}")
}
pub(super) fn read(conn: &Connection, node: &str) -> Result<NodeProfile> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            [key(node)],
            |r| r.get(0),
        )
        .optional()?;
    let profile: NodeProfile = value
        .map(|s| serde_json::from_str(&s))
        .transpose()?
        .unwrap_or_default();
    ensure!(
        profile.revision <= MAX_COUNTER,
        "invalid node profile revision"
    );
    profile.settings.validate()?;
    Ok(profile)
}
pub(super) fn write(tx: &Transaction<'_>, node: &str, profile: &NodeProfile) -> Result<()> {
    tx.execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![key(node),serde_json::to_string(profile)?])?;
    Ok(())
}
pub(super) fn validate_policy(
    settings: &NodeSettings,
    policy: Option<&crate::lease::LeasePolicy>,
) -> Result<()> {
    settings.validate()?;
    if policy.is_none() && (!settings.enabled || settings.expires_at_ms.is_some()) {
        return reject(
            400,
            "node pause and expiry require a strict execution lease; offline nodes cannot guarantee remote shutdown",
        );
    }
    Ok(())
}
impl Store {
    pub fn nodes_filtered(&self, actor: &Actor, filter: NodeFilter) -> Result<Vec<Node>> {
        filter.validate()?;
        Ok(self
            .nodes(actor)?
            .into_iter()
            .filter(|node| filter.matches(node))
            .collect())
    }
    pub fn update_node(
        &self,
        actor: &Actor,
        node: &str,
        update: NodeUpdate,
    ) -> Result<NodeUpdateResult> {
        Ok(self
            .update_nodes(
                actor,
                vec![NodeBatchEntry {
                    node_id: node.into(),
                    update,
                }],
            )?
            .remove(0))
    }
    pub fn update_nodes(
        &self,
        actor: &Actor,
        entries: Vec<NodeBatchEntry>,
    ) -> Result<Vec<NodeUpdateResult>> {
        if entries.is_empty() || entries.len() > 100 {
            return reject(400, "node profile batch must contain 1..100 nodes");
        }
        let mut ids = HashSet::new();
        for entry in &entries {
            if !identifier(&entry.node_id) || !ids.insert(entry.node_id.as_str()) {
                return reject(400, "invalid or duplicate node identity");
            }
            crate::node::validate_name(&entry.update.name)?;
            entry.update.settings.validate()?;
        }
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut clocks = self.3.lock().unwrap();
        let mut results = Vec::with_capacity(entries.len());
        for entry in entries {
            require_node(&tx, actor, &entry.node_id, true)?;
            let old = read(&tx, &entry.node_id)?;
            if old.revision != entry.update.expected_revision {
                return reject(
                    409,
                    format!(
                        "node {} profile changed; reload before saving",
                        entry.node_id
                    ),
                );
            }
            let lease = leases::status(&tx, &mut clocks, &entry.node_id)?;
            let now = clocks.policy_now_ms();
            validate_policy(&entry.update.settings, lease.policy.as_ref())?;
            if entry.update.settings.enabled
                && lease.active
                && (!old.settings.enabled
                    || entry.update.settings.expires_at_ms != old.settings.expires_at_ms)
                && entry
                    .update
                    .settings
                    .expires_at_ms
                    .is_some_and(|expiry| expiry < now.saturating_add(lease.remaining_ms as i64))
            {
                return reject(
                    409,
                    format!(
                        "node {} expiry precedes an already granted execution window; pause and wait for release, or choose a later expiry",
                        entry.node_id
                    ),
                );
            }
            let profile = NodeProfile {
                revision: old
                    .revision
                    .checked_add(1)
                    .filter(|n| *n <= MAX_COUNTER)
                    .context("node profile revision exhausted")?,
                updated_at_ms: Some(now),
                settings: entry.update.settings,
            };
            let old_name: String = tx.query_row(
                "SELECT name FROM nodes WHERE id=?1",
                [&entry.node_id],
                |r| r.get(0),
            )?;
            tx.execute(
                "UPDATE nodes SET name=?1 WHERE id=?2",
                params![entry.update.name, entry.node_id],
            )?;
            write(&tx, &entry.node_id, &profile)?;
            audit(&tx, &actor.id, "node.profile.update", &entry.node_id, &serde_json::json!({"before":{"name":old_name,"profile":old},"after":{"name":entry.update.name,"profile":profile}}).to_string())?;
            results.push(NodeUpdateResult {
                node_id: entry.node_id,
                name: entry.update.name,
                lifecycle: profile.settings.lifecycle(now),
                profile,
            });
        }
        tx.commit()?;
        Ok(results)
    }
}

#[cfg(test)]
#[path = "node_profiles_tests.rs"]
mod tests;
