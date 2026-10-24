use super::*;
use crate::topology::{self, BatchResult, ConfigBatch, ConfigChange, ConfigUpdate, RuleChange};
use std::collections::{BTreeMap, BTreeSet};

fn all_configs(conn: &Connection) -> Result<BTreeMap<String, NodeConfig>> {
    let mut query = conn.prepare("SELECT c.config_json FROM config_history c JOIN nodes n ON n.id=c.node_id AND n.desired_revision=c.revision ORDER BY n.id")?;
    let values = query.query_map([], |row| row.get::<_, String>(0))?;
    let mut configs = BTreeMap::new();
    for value in values {
        let config: NodeConfig = serde_json::from_str(&value?)?;
        configs.insert(config.node_id.clone(), config);
    }
    Ok(configs)
}
fn bad_input(error: anyhow::Error) -> anyhow::Error {
    Rejection {
        status: 400,
        message: error.to_string(),
    }
    .into()
}
fn quiescent(conn: &Connection, clocks: &mut leases::LeaseClocks, node: &str) -> Result<bool> {
    let (enrolled, desired, applied, error, stats): (bool,u64,u64,Option<String>,String) = conn.query_row(
        "SELECT token_hash IS NOT NULL,desired_revision,applied_revision,apply_error,stats_json FROM nodes WHERE id=?1", [node],
        |r| Ok((r.get(0)?,r.get(1)?,r.get(2)?,r.get(3)?,r.get(4)?)))?;
    if !enrolled {
        if credentials::read(conn, node)?.revocation.is_some() {
            let status = leases::status(conn, clocks, node)?;
            return Ok(status.policy.is_some() && !status.active && status.recovery_wait_ms == 0);
        }
        return Ok(true);
    }
    let Ok(stats) = serde_json::from_str::<EngineStats>(&stats) else {
        return Ok(false);
    };
    Ok(desired == applied && error.is_none() && stats.business_idle() && stats.active_probes == 0)
}
fn retirement_barrier(
    conn: &Connection,
    clocks: &mut leases::LeaseClocks,
    old: &NodeConfig,
    new: &NodeConfig,
) -> Result<()> {
    for previous in &old.rules {
        let next = new.rules.iter().find(|r| r.id == previous.id);
        if !topology::participates(previous) && next.is_none_or(|r| !topology::participates(r)) {
            continue;
        }
        let structural = next
            .is_none_or(|r| topology::route_signature(r) != topology::route_signature(previous));
        let reused_listener = new.rules.iter().any(|r| {
            r.id != previous.id
                && r.enabled
                && ((r.protocol.tcp() && previous.protocol.tcp())
                    || (r.protocol.udp() && previous.protocol.udp()))
                && r.listen.is_ipv4() == previous.listen.is_ipv4()
                && (r.listen.ip() == previous.listen.ip()
                    || r.listen.ip().is_unspecified()
                    || previous.listen.ip().is_unspecified())
                && r.listen.port() <= previous.listen_end_port.unwrap_or(previous.listen.port())
                && previous.listen.port() <= r.listen_end_port.unwrap_or(r.listen.port())
        });
        if structural && previous.enabled {
            return reject(
                409,
                "stop topology rules without rewiring them before changing or removing their routes",
            );
        }
        if !previous.enabled
            && (structural || reused_listener || next.is_some_and(|r| r.enabled))
            && !quiescent(conn, clocks, &old.node_id)?
        {
            return reject(
                409,
                "topology stop is not confirmed: wait for this node to apply the disabled configuration and report zero active sessions",
            );
        }
    }
    Ok(())
}
fn prepare(
    conn: &Connection,
    clocks: &mut leases::LeaseClocks,
    actor: &Actor,
    batch: ConfigBatch,
) -> Result<BatchResult> {
    if !actor.may_write() {
        return reject(403, "read-only role cannot publish configuration");
    }
    if batch.updates.is_empty() || batch.updates.len() > 64 {
        return reject(400, "a configuration batch requires 1..64 nodes");
    }
    let mut current = all_configs(conn)?;
    let mut seen = BTreeSet::new();
    let mut configs = Vec::new();
    let mut changes = Vec::new();
    for update in batch.updates {
        if !seen.insert(update.node_id.clone()) {
            return reject(400, "duplicate node in configuration batch");
        }
        let tenant = require_node(conn, actor, &update.node_id, true)?;
        let old = current
            .get(&update.node_id)
            .context("node configuration missing")?;
        if old.revision != update.expected_revision {
            return reject(409, "configuration changed; reload before saving");
        }
        if update.expected_revision >= MAX_COUNTER {
            return reject(400, "revision out of range");
        }
        let mut config = NodeConfig {
            api_version: API_VERSION,
            node_id: update.node_id,
            revision: update.expected_revision + 1,
            rules: update.rules,
        };
        config.validate().map_err(bad_input)?;
        for rule in &mut config.rules {
            credentials::require_meter_period(conn, &config.node_id, rule)?;
            if rule.tenant_id != tenant {
                return reject(403, "rule tenant does not match node");
            }
            if !conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM users WHERE id=?1 AND tenant_id=?2)",
                params![rule.owner_id, tenant],
                |r| r.get::<_, bool>(0),
            )? {
                return reject(403, "rule owner must belong to node tenant");
            }
            let bound: Option<(String, String)> = conn
                .query_row(
                    "SELECT node_id,owner_id FROM rule_bindings WHERE rule_id=?1",
                    [&rule.id],
                    |r| Ok((r.get(0)?, r.get(1)?)),
                )
                .optional()?;
            if bound.is_some_and(|(n, o)| n != config.node_id || o != rule.owner_id) {
                return reject(
                    409,
                    "rule identity already belongs to another node or owner",
                );
            }
            rule.budget_ids = budgets::bindings(conn, &config.node_id, rule)?;
        }
        retirement_barrier(conn, clocks, old, &config)?;
        let mut change = ConfigChange {
            node_id: config.node_id.clone(),
            from_revision: old.revision,
            to_revision: config.revision,
            added: vec![],
            removed: vec![],
            modified: vec![],
            rule_changes: vec![],
        };
        for rule in &config.rules {
            match old.rules.iter().find(|r| r.id == rule.id) {
                None => change.added.push(rule.id.clone()),
                Some(previous) if previous != rule => change.modified.push(rule.id.clone()),
                _ => {}
            }
        }
        for rule in &old.rules {
            if !config.rules.iter().any(|r| r.id == rule.id) {
                change.removed.push(rule.id.clone());
            }
        }
        for id in change
            .added
            .iter()
            .chain(&change.modified)
            .chain(&change.removed)
        {
            change.rule_changes.push(RuleChange {
                rule_id: id.clone(),
                before: old.rules.iter().find(|r| &r.id == id).cloned(),
                after: config.rules.iter().find(|r| &r.id == id).cloned(),
            });
        }
        changes.push(change);
        current.insert(config.node_id.clone(), config.clone());
        configs.push(config);
    }
    topology::validate(&current.into_values().collect::<Vec<_>>()).map_err(bad_input)?;
    Ok(BatchResult { configs, changes })
}
impl Store {
    pub fn preview_configs(&self, actor: &Actor, batch: ConfigBatch) -> Result<BatchResult> {
        let conn = self.0.lock().unwrap();
        prepare(&conn, &mut self.3.lock().unwrap(), actor, batch)
    }
    pub fn publish_configs(&self, actor: &Actor, batch: ConfigBatch) -> Result<BatchResult> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let result = prepare(&tx, &mut self.3.lock().unwrap(), actor, batch)?;
        for config in &result.configs {
            for rule in &config.rules {
                tx.execute("INSERT OR IGNORE INTO rule_bindings(rule_id,node_id,tenant_id,owner_id) VALUES(?1,?2,?3,?4)",params![rule.id,config.node_id,rule.tenant_id,rule.owner_id])?;
                tx.execute(
                    "INSERT OR IGNORE INTO rule_epochs(rule_id,meter_epoch) VALUES(?1,?2)",
                    params![rule.id, rule.meter_epoch],
                )?;
            }
            if tx.execute(
                "UPDATE nodes SET desired_revision=?1 WHERE id=?2 AND desired_revision=?3",
                params![config.revision, config.node_id, config.revision - 1],
            )? != 1
            {
                return reject(409, "configuration changed; reload before saving");
            }
            tx.execute("INSERT INTO config_history(node_id,revision,config_json,actor_id,created_at_ms) VALUES(?1,?2,?3,?4,?5)",params![config.node_id,config.revision,serde_json::to_string(config)?,actor.id,now_ms()])?;
            audit(
                &tx,
                &actor.id,
                "config.publish",
                &config.node_id,
                &serde_json::json!({"revision":config.revision,"rules":config.rules.len()})
                    .to_string(),
            )?;
        }
        if result.configs.len() > 1 {
            audit(
                &tx,
                &actor.id,
                "config.batch_publish",
                "nodes",
                &serde_json::to_string(&result.changes.iter().map(|c|serde_json::json!({"node_id":c.node_id,"from_revision":c.from_revision,"to_revision":c.to_revision,"added":c.added,"removed":c.removed,"modified":c.modified})).collect::<Vec<_>>())?,
            )?;
        }
        tx.commit()?;
        Ok(result)
    }
    pub fn topology(&self, actor: &Actor) -> Result<serde_json::Value> {
        // Both snapshots are collected under the same lock, including status.
        let conn = self.0.lock().unwrap();
        let all = all_configs(&conn)?;
        let mut q = conn.prepare("SELECT id,name,tenant_id,desired_revision,applied_revision,last_seen_ms,apply_error,stats_json,token_hash IS NOT NULL FROM nodes WHERE (?1='system_admin' OR tenant_id=?2) ORDER BY id")?;
        let nodes = q.query_map(params![actor.role.as_str(),actor.tenant_id],|r| Ok(serde_json::json!({"id":r.get::<_,String>(0)?,"name":r.get::<_,String>(1)?,"tenant_id":r.get::<_,String>(2)?,"desired_revision":r.get::<_,u64>(3)?,"applied_revision":r.get::<_,u64>(4)?,"last_seen_ms":r.get::<_,Option<i64>>(5)?,"apply_error":r.get::<_,Option<String>>(6)?,"stats":serde_json::from_str::<EngineStats>(&r.get::<_,String>(7)?).unwrap_or_default(),"enrolled":r.get::<_,bool>(8)?})))?.collect::<rusqlite::Result<Vec<_>>>()?;
        let configs: Vec<_> = nodes
            .iter()
            .map(|node| all[node["id"].as_str().unwrap()].clone())
            .collect();
        let graph = topology::validate(&configs)?;
        Ok(
            serde_json::json!({"nodes":nodes,"configs":configs,"graph":graph,"activation":"asynchronous-per-node"}),
        )
    }
    pub fn set_config(
        &self,
        actor: &Actor,
        node: &str,
        expected: u64,
        rules: Vec<Rule>,
    ) -> Result<NodeConfig> {
        Ok(self
            .publish_configs(
                actor,
                ConfigBatch {
                    updates: vec![ConfigUpdate {
                        node_id: node.into(),
                        expected_revision: expected,
                        rules,
                    }],
                },
            )?
            .configs
            .remove(0))
    }
}
