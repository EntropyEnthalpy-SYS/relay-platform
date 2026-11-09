use super::*;
use crate::topology::{self, BatchResult, ConfigBatch, ConfigChange, ConfigUpdate, RuleChange};
use std::collections::{BTreeMap, BTreeSet};

pub(super) fn all_configs(conn: &Connection) -> Result<BTreeMap<String, NodeConfig>> {
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
pub(super) fn quiescent(
    conn: &Connection,
    clocks: &mut leases::LeaseClocks,
    node: &str,
) -> Result<bool> {
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
/// Rules a chain refresh puts back as they were before it began, by node
/// and rule id, with the route each had then. Only that restore passes any:
/// [`prepare`] and [`publish_in`], which every other publish uses, pass none.
pub(super) type Restorable = BTreeMap<(String, String), serde_json::Value>;
fn retirement_barrier(
    conn: &Connection,
    clocks: &mut leases::LeaseClocks,
    old: &NodeConfig,
    new: &NodeConfig,
    restorable: &Restorable,
) -> Result<()> {
    let mut checks = vec![];
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
        checks.push((previous, next, structural, reused_listener));
    }
    // A restore may enable a stopped rule again without the idle check only
    // when this server's update adds no rule, removes none (of any kind),
    // reroutes nothing and takes no listener, and the rule has exactly the
    // route it had before.
    let only_toggles = !restorable.is_empty()
        && new.rules.len() == old.rules.len()
        && new
            .rules
            .iter()
            .all(|r| old.rules.iter().any(|p| p.id == r.id))
        && checks
            .iter()
            .all(|(_, _, structural, reused)| !structural && !reused);
    for (previous, next, structural, reused_listener) in checks {
        if structural && previous.enabled {
            return reject(
                409,
                "stop topology rules without rewiring them before changing or removing their routes",
            );
        }
        if !previous.enabled && (structural || reused_listener || next.is_some_and(|r| r.enabled)) {
            let restored = only_toggles
                && next.is_some_and(|r| {
                    restorable.get(&(old.node_id.clone(), r.id.clone()))
                        == Some(&topology::route_signature(r))
                });
            if !restored && !quiescent(conn, clocks, &old.node_id)? {
                return reject(
                    409,
                    "topology stop is not confirmed: wait for this node to apply the disabled configuration and report zero active sessions",
                );
            }
        }
    }
    Ok(())
}
/// The name and address of a rule of `config` that an agent would refuse
/// ([`crate::engine::kind_change`]) while it runs the configuration
/// published last, `old`, or one it may still run instead: any from the last
/// it reported applying on. A restarted agent has reported none until its
/// first sync and may run any it was ever given; one that never connected
/// runs none, though a server whose credential was revoked before any agent
/// connected is taken as one whose agent did ([`leases::ever_held`]).
fn kind_change(
    conn: &Connection,
    old: &NodeConfig,
    config: &NodeConfig,
) -> Result<Option<(String, std::net::SocketAddr)>> {
    if let Some((rule, address)) = crate::engine::kind_change(&old.rules, &config.rules) {
        return Ok(Some((rule.name.clone(), address)));
    }
    // A rule that listens as it did in `old` is refused by an earlier
    // configuration only where `old` is too, and an agent running that one
    // refuses `old` already: only rules turned on or moved are looked up.
    let moved: Vec<Rule> = config
        .rules
        .iter()
        .filter(|spec| {
            spec.enabled
                && !old
                    .rules
                    .iter()
                    .any(|r| r.id == spec.id && crate::engine::listens_as(r, spec))
        })
        .cloned()
        .collect();
    if moved.is_empty() {
        return Ok(None);
    }
    let (reported, applied): (bool, u64) = conn.query_row(
        "SELECT last_seen_ms IS NOT NULL,applied_revision FROM nodes WHERE id=?1",
        [&config.node_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let from = if reported {
        applied
    } else if leases::ever_held(conn, &config.node_id)? {
        0
    } else {
        return Ok(None);
    };
    // A history has thousands of configurations: each is read for the id,
    // state and gateway of its rules alone, and whole only where one of
    // those may be found ([`crate::engine::may_change_kind`]). An ordinary
    // rule is refused only where it was a gateway, so for those alone only
    // configurations holding a gateway are read at all.
    #[derive(Deserialize)]
    struct Held {
        #[serde(default)]
        rules: Vec<HeldRule>,
    }
    #[derive(Deserialize)]
    struct HeldRule {
        id: String,
        enabled: Option<bool>,
        protocol_gateway: Option<crate::gateway::Config>,
    }
    let gateways = moved.iter().any(|r| r.protocol_gateway.is_some());
    let mut query = conn.prepare(
        "SELECT config_json FROM config_history WHERE node_id=?1 AND revision>=?2 AND revision<?3 AND (?4 OR instr(config_json,'\"protocol_gateway\"')>0)",
    )?;
    let mut rows = query.query(params![config.node_id, from, old.revision, gateways])?;
    while let Some(row) = rows.next()? {
        let json = row.get_ref(0)?.as_str()?;
        if let Ok(held) = serde_json::from_str::<Held>(json)
            && !held.rules.iter().any(|earlier| {
                earlier.enabled != Some(false)
                    && moved.iter().any(|spec| {
                        spec.id == earlier.id
                            && crate::engine::may_change_kind(
                                earlier.protocol_gateway.as_ref(),
                                spec,
                            )
                    })
            })
        {
            continue;
        }
        let earlier: NodeConfig = serde_json::from_str(json)?;
        if let Some((rule, address)) = crate::engine::kind_change(&earlier.rules, &moved) {
            return Ok(Some((rule.name.clone(), address)));
        }
    }
    Ok(None)
}
pub(super) fn prepare(
    conn: &Connection,
    clocks: &mut leases::LeaseClocks,
    actor: &Actor,
    batch: ConfigBatch,
) -> Result<BatchResult> {
    prepare_with(conn, clocks, actor, batch, &Restorable::new())
}
/// [`prepare`], letting the rules of `restorable` be enabled again without
/// the stop barrier's idle check (see [`retirement_barrier`]).
pub(super) fn prepare_with(
    conn: &Connection,
    clocks: &mut leases::LeaseClocks,
    actor: &Actor,
    batch: ConfigBatch,
    restorable: &Restorable,
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
            rate_bytes_per_sec: update.rate_bytes_per_sec.unwrap_or(old.rate_bytes_per_sec),
            rate_limits: RateLimits::normalized(update.rate_limits.unwrap_or(old.rate_limits)),
        };
        // An empty set is no limit, and is left out for older agents.
        for rule in &mut config.rules {
            rule.rate_limits = RateLimits::normalized(rule.rate_limits);
        }
        federation::merge(conn, &config.node_id, &tenant, &mut config.rules)?;
        reverse_tunnels::merge(conn, &config.node_id, &mut config.rules)?;
        config.validate().map_err(bad_input)?;
        // The agent would refuse it and keep running the old configuration.
        if let Some((name, address)) = kind_change(conn, old, &config)? {
            return reject(
                409,
                format!(
                    "rule {name} listens on {address}: disable it, publish that and wait until the server applies it before turning it into a protocol gateway there or back"
                ),
            );
        }
        rate_limits::require(conn, &config)?;
        egress_proxies::require(conn, &config)?;
        firewall_sets::require(conn, &tenant, &config)?;
        if config
            .rules
            .iter()
            .any(|rule| rule.mptcp.is_some_and(|m| m != Default::default()))
        {
            features::require(conn, "mptcp", "MPTCP")?;
        }
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
        retirement_barrier(conn, clocks, old, &config, restorable)?;
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
/// Publishes `batch` inside `tx`; the caller commits and wakes agent watches.
pub(super) fn publish_in(
    tx: &Transaction<'_>,
    clocks: &mut leases::LeaseClocks,
    actor: &Actor,
    batch: ConfigBatch,
) -> Result<BatchResult> {
    publish_in_with(tx, clocks, actor, batch, &Restorable::new())
}
/// [`publish_in`] with the exemption of [`prepare_with`].
pub(super) fn publish_in_with(
    tx: &Transaction<'_>,
    clocks: &mut leases::LeaseClocks,
    actor: &Actor,
    batch: ConfigBatch,
    restorable: &Restorable,
) -> Result<BatchResult> {
    let result = prepare_with(tx, clocks, actor, batch, restorable)?;
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
            tx,
            &actor.id,
            "config.publish",
            &config.node_id,
            &serde_json::json!({"revision":config.revision,"rules":config.rules.len()}).to_string(),
        )?;
    }
    if result.configs.len() > 1 {
        audit(
            tx,
            &actor.id,
            "config.batch_publish",
            "nodes",
            &serde_json::to_string(&result.changes.iter().map(|c|serde_json::json!({"node_id":c.node_id,"from_revision":c.from_revision,"to_revision":c.to_revision,"added":c.added,"removed":c.removed,"modified":c.modified})).collect::<Vec<_>>())?,
        )?;
    }
    Ok(result)
}
impl Store {
    pub fn preview_configs(&self, actor: &Actor, batch: ConfigBatch) -> Result<BatchResult> {
        let conn = self.0.lock().unwrap();
        prepare(&conn, &mut self.3.lock().unwrap(), actor, batch)
    }
    pub fn publish_configs(&self, actor: &Actor, batch: ConfigBatch) -> Result<BatchResult> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let result = publish_in(&tx, &mut self.3.lock().unwrap(), actor, batch)?;
        tx.commit()?;
        self.2.config.notify_waiters();
        Ok(result)
    }
    /// Maintenance for `node`: sets `draining` on every target that routes
    /// through it, publishing each upstream node that changes in one batch.
    pub fn drain_node(&self, actor: &Actor, node: &str, draining: bool) -> Result<BatchResult> {
        let updates = {
            let conn = self.0.lock().unwrap();
            require_node(&conn, actor, node, true)?;
            let mut referenced = false;
            let mut updates = vec![];
            for config in all_configs(&conn)?.into_values() {
                let mut rules = config.rules;
                let mut changed = false;
                for target in rules.iter_mut().flat_map(|r| &mut r.targets) {
                    if target.via.as_ref().is_some_and(|via| via.node_id == node) {
                        referenced = true;
                        changed |= target.draining != draining;
                        target.draining = draining;
                    }
                }
                if changed {
                    updates.push(ConfigUpdate {
                        node_id: config.node_id,
                        expected_revision: config.revision,
                        rules,
                        rate_bytes_per_sec: None,
                        rate_limits: None,
                    });
                }
            }
            if !referenced {
                return reject(409, "no rule routes through this node");
            }
            updates
        };
        if updates.is_empty() {
            return Ok(BatchResult {
                configs: vec![],
                changes: vec![],
            });
        }
        // Publishing rechecks each expected revision under its own lock.
        self.publish_configs(actor, ConfigBatch { updates })
    }
    pub fn topology(&self, actor: &Actor) -> Result<serde_json::Value> {
        // Both snapshots are collected under the same lock, including status.
        let conn = self.0.lock().unwrap();
        let all = all_configs(&conn)?;
        let mut q = conn.prepare("SELECT id,name,tenant_id,desired_revision,applied_revision,last_seen_ms,apply_error,stats_json,token_hash IS NOT NULL FROM nodes WHERE (?1='system_admin' OR tenant_id=?2) ORDER BY id")?;
        let mut nodes = q.query_map(params![actor.role.as_str(),actor.tenant_id],|r| { let id: String = r.get(0)?; let (last_seen, stats) = self.4.current(&id, r.get(5)?, r.get(7)?); Ok(serde_json::json!({"id":id,"name":r.get::<_,String>(1)?,"tenant_id":r.get::<_,String>(2)?,"desired_revision":r.get::<_,u64>(3)?,"applied_revision":r.get::<_,u64>(4)?,"last_seen_ms":last_seen,"apply_error":r.get::<_,Option<String>>(6)?,"stats":serde_json::from_str::<EngineStats>(&stats).unwrap_or_default(),"enrolled":r.get::<_,bool>(8)?})) })?.collect::<rusqlite::Result<Vec<_>>>()?;
        for node in &mut nodes {
            let profile = node_profiles::read(&conn, node["id"].as_str().unwrap())?;
            node["lifecycle"] = serde_json::to_value(profile.settings.lifecycle(now_ms()))?;
            node["profile"] = serde_json::to_value(profile)?;
        }
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
        self.set_config_with_rate(actor, node, expected, rules, None)
    }
    /// `rate_bytes_per_sec`: `None` keeps the node cap, `Some(None)` clears it.
    pub fn set_config_with_rate(
        &self,
        actor: &Actor,
        node: &str,
        expected: u64,
        rules: Vec<Rule>,
        rate_bytes_per_sec: Option<Option<u64>>,
    ) -> Result<NodeConfig> {
        self.set_config_with_limits(actor, node, expected, rules, rate_bytes_per_sec, None)
    }
    /// Like [`Self::set_config_with_rate`], with the node's upload, download
    /// and burst limits: `None` keeps them, `Some(None)` clears them.
    pub fn set_config_with_limits(
        &self,
        actor: &Actor,
        node: &str,
        expected: u64,
        rules: Vec<Rule>,
        rate_bytes_per_sec: Option<Option<u64>>,
        rate_limits: Option<Option<RateLimits>>,
    ) -> Result<NodeConfig> {
        Ok(self
            .publish_configs(
                actor,
                ConfigBatch {
                    updates: vec![ConfigUpdate {
                        node_id: node.into(),
                        expected_revision: expected,
                        rules,
                        rate_bytes_per_sec,
                        rate_limits,
                    }],
                },
            )?
            .configs
            .remove(0))
    }
}

#[cfg(test)]
mod restore_exemption_tests {
    //! What [`prepare_with`] lets a chain refresh's restore do that nothing
    //! else may: enable a stopped rule again, with its old route, while its
    //! server still has sessions. Everything else stays as [`prepare`].
    use super::*;
    use crate::chain::{BuildInput, ChainInput, GroupInput, Layer};
    use crate::model::{Balance, EngineStats, Protocol, ReconcileRequest, SyncRequest};
    use crate::node::{ForwardingDefaults, NodeSettings};

    struct Setup {
        _temp: tempfile::TempDir,
        store: Store,
        admin: Actor,
        /// Entry server, relay server.
        nodes: Vec<String>,
        /// Two forwardings' entry rules on the entry server.
        entries: Vec<String>,
    }
    impl Setup {
        fn new() -> Self {
            let temp = tempfile::tempdir().unwrap();
            let store = Store::open(&temp.path().join("controller.db")).unwrap();
            store.set_kind("controller").unwrap();
            let admin = store.bootstrap("restore exemption password 1").unwrap();
            let mut nodes = vec![];
            for index in 0..2u16 {
                let port = 31000 + 100 * index;
                let settings = NodeSettings {
                    forwarding: Some(ForwardingDefaults {
                        host: format!("srv{index}.example.net"),
                        listen_ip: None,
                        port_start: port,
                        port_end: port + 49,
                        public_port_start: None,
                    }),
                    ..Default::default()
                };
                let (node, token) = store
                    .create_node_with_settings(
                        &admin,
                        "default",
                        &format!("srv-{index}"),
                        None,
                        settings,
                    )
                    .unwrap();
                store.enroll(&node.id, &token, &secret()).unwrap();
                nodes.push(node.id);
            }
            let group = store
                .create_endpoint_group(
                    &admin,
                    GroupInput {
                        name: "Relays".into(),
                        description: String::new(),
                        members: vec![nodes[1].clone()],
                    },
                )
                .unwrap();
            let chain = store
                .create_chain(
                    &admin,
                    ChainInput {
                        name: "Path".into(),
                        enabled: true,
                        layers: vec![Layer {
                            group_id: group.id,
                            balance: Balance::WeightedRoundRobin,
                        }],
                    },
                )
                .unwrap();
            let mut entries = vec![];
            for name in ["A", "B"] {
                let applied = store
                    .apply_chain(
                        &admin,
                        &chain.id,
                        BuildInput {
                            entry_node_id: nodes[0].clone(),
                            name: name.into(),
                            protocol: Protocol::Tcp,
                            target: "192.0.2.80:443".into(),
                            entry_port: None,
                            owner_id: None,
                            expected_revisions: None,
                        },
                    )
                    .unwrap();
                entries.push(applied.entry_rule_id);
            }
            Setup {
                _temp: temp,
                store,
                admin,
                nodes,
                entries,
            }
        }
        fn config(&self) -> NodeConfig {
            self.store
                .config(&self.admin, &self.nodes[0], None)
                .unwrap()
        }
        /// The entry server's agent applied its configuration and has
        /// `active` sessions.
        fn report(&self, active: u64) {
            let node = &self.nodes[0];
            let ledger_id = self
                .store
                .reconcile(
                    node,
                    ReconcileRequest {
                        lease: None,
                        ledger_id: None,
                        after: None,
                        expected_revision: None,
                    },
                )
                .unwrap()
                .ledger_id;
            self.store
                .sync(
                    node,
                    SyncRequest {
                        logs: None,
                        lease: None,
                        budget: None,
                        ledger_id,
                        need_config: false,
                        applied_revision: self.config().revision,
                        apply_error: None,
                        usage: vec![],
                        stats: EngineStats {
                            active_tcp: active,
                            ..Default::default()
                        },
                    },
                )
                .unwrap();
        }
        /// Publishes the entry server's rules as `change` leaves them.
        fn publish(&self, change: impl FnOnce(&mut Vec<Rule>)) {
            let config = self.config();
            let mut rules = config.rules;
            change(&mut rules);
            self.store
                .set_config(&self.admin, &self.nodes[0], config.revision, rules)
                .unwrap();
        }
        /// Checks the entry server's rules as `change` leaves them, as
        /// `actor`, letting `restorable` be enabled without the idle check.
        fn check(
            &self,
            actor: &Actor,
            restorable: &Restorable,
            change: impl FnOnce(&mut Vec<Rule>),
        ) -> std::result::Result<(), (u16, String)> {
            let config = self.config();
            let mut rules = config.rules;
            change(&mut rules);
            let conn = self.store.0.lock().unwrap();
            let mut clocks = self.store.3.lock().unwrap();
            let batch = ConfigBatch {
                updates: vec![ConfigUpdate {
                    node_id: self.nodes[0].clone(),
                    expected_revision: config.revision,
                    rules,
                    rate_bytes_per_sec: None,
                    rate_limits: None,
                }],
            };
            match prepare_with(&conn, &mut clocks, actor, batch, restorable) {
                Ok(_) => Ok(()),
                Err(error) => {
                    let rejection = error.downcast_ref::<Rejection>().unwrap();
                    Err((rejection.status, rejection.message.clone()))
                }
            }
        }
        fn rule<'a>(&self, rules: &'a mut [Rule], index: usize) -> &'a mut Rule {
            rules
                .iter_mut()
                .find(|r| r.id == self.entries[index])
                .unwrap()
        }
        /// Rule `index` (0 for A) keyed for the exemption with `route`.
        fn restorable(&self, index: usize, route: serde_json::Value) -> Restorable {
            [((self.nodes[0].clone(), self.entries[index].clone()), route)]
                .into_iter()
                .collect()
        }
    }

    #[test]
    fn only_enabling_a_stopped_rule_with_its_old_route_skips_the_idle_check() {
        let s = Setup::new();
        s.report(0);
        // A is stopped; the server then reports a session of another rule.
        s.publish(|rules| s.rule(rules, 0).enabled = false);
        s.report(1);
        let route = topology::route_signature(s.rule(&mut s.config().rules, 0));
        let exempt = s.restorable(0, route.clone());
        let busy = |result: std::result::Result<(), (u16, String)>| {
            let (status, message) = result.unwrap_err();
            assert_eq!(status, 409);
            assert!(
                message.contains("topology stop is not confirmed"),
                "{message}"
            );
        };
        // Enabling A again and disabling B, as a restore does on one server:
        // refused without the exemption, allowed with it.
        let toggle = |rules: &mut Vec<Rule>| {
            s.rule(rules, 0).enabled = true;
            s.rule(rules, 1).enabled = false;
        };
        busy(s.check(&s.admin, &Restorable::new(), toggle));
        s.check(&s.admin, &exempt, toggle).unwrap();
        // Another route than the recorded one, the rule rerouted in the same
        // update, another rule added, or the key of another server: refused.
        let other_route = {
            let mut moved = s.rule(&mut s.config().rules, 0).clone();
            moved.listen.set_port(moved.listen.port() + 40);
            topology::route_signature(&moved)
        };
        busy(s.check(&s.admin, &s.restorable(0, other_route), toggle));
        busy(s.check(&s.admin, &exempt, |rules| {
            let rule = s.rule(rules, 0);
            rule.enabled = true;
            rule.listen.set_port(rule.listen.port() + 40);
        }));
        busy(s.check(&s.admin, &exempt, |rules| {
            s.rule(rules, 0).enabled = true;
            let mut extra = s.rule(rules, 1).clone();
            extra.id = "extra".into();
            extra.meter_epoch = "extra-epoch".into();
            extra.advertise = None;
            extra.targets[0].via = None;
            extra.targets[0].address = "192.0.2.81:443".into();
            extra.listen.set_port(extra.listen.port() + 30);
            rules.push(extra);
        }));
        // A rule outside the topology removed in the same update: no longer
        // only toggles either, so refused.
        s.publish(|rules| {
            let mut plain = s.rule(rules, 1).clone();
            plain.id = "plain".into();
            plain.meter_epoch = "plain-epoch".into();
            plain.advertise = None;
            plain.targets[0].via = None;
            plain.targets[0].address = "192.0.2.82:443".into();
            plain.listen.set_port(plain.listen.port() + 31);
            rules.push(plain);
        });
        busy(s.check(&s.admin, &exempt, |rules| {
            s.rule(rules, 0).enabled = true;
            rules.retain(|r| r.id != "plain");
        }));
        s.publish(|rules| rules.retain(|r| r.id != "plain"));
        let elsewhere: Restorable = [((s.nodes[1].clone(), s.entries[0].clone()), route)]
            .into_iter()
            .collect();
        busy(s.check(&s.admin, &elsewhere, toggle));
        // B stopped too, then removed while A is enabled: a structural change
        // on the server, so the idle check applies to A again.
        s.publish(|rules| s.rule(rules, 1).enabled = false);
        s.report(1);
        let entries = s.entries.clone();
        busy(s.check(&s.admin, &exempt, |rules| {
            rules.retain(|r| r.id != entries[1]);
            s.rule(rules, 0).enabled = true;
        }));
        // Every other check still runs: a read-only actor is refused.
        let viewer = Actor {
            id: "viewer".into(),
            tenant_id: "default".into(),
            username: "viewer".into(),
            role: Role::Viewer,
        };
        assert_eq!(
            s.check(&viewer, &exempt, |rules| s.rule(rules, 0).enabled = true)
                .unwrap_err()
                .0,
            403
        );
        s.check(&s.admin, &exempt, |rules| s.rule(rules, 0).enabled = true)
            .unwrap();
        // Once idle, the ordinary check passes without it.
        s.report(0);
        s.check(&s.admin, &Restorable::new(), |rules| {
            s.rule(rules, 0).enabled = true
        })
        .unwrap();
        // The topology is still validated with it: A's next hop on the relay
        // disabled meanwhile, enabling A is refused with the exemption on the
        // busy server, as it is without it on an idle one.
        let via = s.rule(&mut s.config().rules, 0).targets[0]
            .via
            .clone()
            .unwrap();
        let relay = s.store.config(&s.admin, &via.node_id, None).unwrap();
        let mut rules = relay.rules;
        rules
            .iter_mut()
            .find(|r| r.id == via.rule_id)
            .unwrap()
            .enabled = false;
        s.store
            .set_config(&s.admin, &via.node_id, relay.revision, rules)
            .unwrap();
        for (restorable, active) in [(&exempt, 1), (&Restorable::new(), 0)] {
            s.report(active);
            let (_, message) = s
                .check(&s.admin, restorable, |rules| {
                    s.rule(rules, 0).enabled = true
                })
                .unwrap_err();
            assert!(message.contains("disabled next hop"), "{message}");
        }
    }
}
