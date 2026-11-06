//! Shared rules in metadata (`shared_rule:<id>`), so the schema and recovery
//! log stay unchanged. Member rules are ordinary rules on their nodes; every
//! change is one configuration batch, published in the same transaction
//! that writes the record.
use super::*;
use crate::node::ForwardingDefaults;
use crate::shared_rule::{
    FromRuleInput, LineError, LineErrors, MAX_LINES, Member, MemberView, Precheck, PrecheckInput,
    PrecheckLine, SharedRule, SharedRuleInput, SharedRuleView, drift,
};
use crate::topology::{ConfigBatch, ConfigUpdate};
use std::collections::{BTreeSet, HashSet};
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

/// Automatic ports come from here when a node has no forwarding defaults.
const DEFAULT_PORTS: (u16, u16) = (20000, 29999);
const ONLINE_MS: i64 = 90_000;

type Configs = BTreeMap<String, NodeConfig>;

fn key(id: &str) -> String {
    format!("shared_rule:{id}")
}
fn all(conn: &Connection) -> Result<Vec<SharedRule>> {
    let mut q = conn.prepare("SELECT value FROM metadata WHERE key GLOB 'shared_rule:*'")?;
    let rows: Vec<String> = q
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    rows.into_iter()
        .map(|value| serde_json::from_str(&value).context("invalid stored shared rule"))
        .collect()
}
fn write(tx: &Transaction<'_>, record: &SharedRule) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key(&record.id), serde_json::to_string(record)?],
    )?;
    Ok(())
}
/// The record when it exists and belongs to a tenant the actor can see.
fn visible(conn: &Connection, actor: &Actor, id: &str) -> Result<SharedRule> {
    let raw: Option<String> = conn
        .query_row("SELECT value FROM metadata WHERE key=?1", [key(id)], |r| {
            r.get(0)
        })
        .optional()?;
    match raw.map(|value| serde_json::from_str::<SharedRule>(&value)) {
        Some(record) => {
            let record = record?;
            if actor.permits_tenant(&record.tenant_id) {
                Ok(record)
            } else {
                reject(404, "shared rule not found")
            }
        }
        None => reject(404, "shared rule not found"),
    }
}
fn writer(actor: &Actor) -> Result<()> {
    if !actor.may_write() {
        return reject(403, "read-only role cannot change shared rules");
    }
    Ok(())
}
fn check_name(name: &str) -> Result<()> {
    if name.trim().is_empty() || name.len() > 120 {
        return reject(400, "shared rule name must contain 1..120 bytes");
    }
    Ok(())
}
/// Shared rules have one listen port and no per-node bridge.
fn check_rule(rule: &Rule, port: Option<u16>) -> Result<()> {
    if port == Some(0) {
        return reject(400, "listen port must be 1..65535");
    }
    if rule
        .listen_end_port
        .is_some_and(|end| end != rule.listen.port())
    {
        return reject(400, "a shared rule listens on a single port, not a range");
    }
    if rule.protocol_gateway.is_some() {
        return reject(
            400,
            "managed protocol gateways need a private port per server and cannot be shared rules",
        );
    }
    Ok(())
}
/// Checks the requested lines and returns their common tenant.
fn lines(conn: &Connection, actor: &Actor, node_ids: &[String]) -> Result<String> {
    if node_ids.is_empty() || node_ids.len() > MAX_LINES {
        return reject(400, format!("a shared rule needs 1..{MAX_LINES} lines"));
    }
    let mut seen = HashSet::new();
    let mut tenant: Option<String> = None;
    for node in node_ids {
        if !seen.insert(node.as_str()) {
            return reject(400, "each line must be a different server");
        }
        let next = require_node(conn, actor, node, true)?;
        if tenant.as_ref().is_some_and(|current| *current != next) {
            return reject(400, "all lines must belong to the same tenant");
        }
        tenant = Some(next);
    }
    Ok(tenant.unwrap_or_default())
}
fn forwarding(conn: &Connection, node: &str) -> Result<Option<ForwardingDefaults>> {
    Ok(node_profiles::read(conn, node)?.settings.forwarding)
}
fn port_range(forwarding: Option<&ForwardingDefaults>) -> (u16, u16) {
    forwarding.map_or(DEFAULT_PORTS, |f| (f.port_start, f.port_end))
}
/// The listen host of a new line, as endpoint allocation chooses it.
fn bind_ip(forwarding: Option<&ForwardingDefaults>) -> IpAddr {
    forwarding.map_or(
        IpAddr::V4(Ipv4Addr::UNSPECIFIED),
        ForwardingDefaults::bind_ip,
    )
}
/// Some rule other than `except`, or a cross-panel share, already holds `port`
/// on this node, on any address and whether enabled or not.
fn taken(config: &NodeConfig, reserved: &[(u16, u16)], port: u16, except: Option<&str>) -> bool {
    config.rules.iter().any(|rule| {
        Some(rule.id.as_str()) != except
            && ((rule.listen.port()..=rule.listen_end_port.unwrap_or(rule.listen.port()))
                .contains(&port)
                || rule
                    .protocol_gateway
                    .as_ref()
                    .is_some_and(|gateway| gateway.listen.port() == port))
    }) || reserved
        .iter()
        .any(|(start, end)| (*start..=*end).contains(&port))
}
fn entry(forwarding: Option<&ForwardingDefaults>, rule: &Rule) -> Option<String> {
    let port = rule.listen.port();
    if let Some(defaults) = forwarding {
        let public = if (defaults.port_start..=defaults.port_end).contains(&port) {
            defaults.public_port(port)
        } else {
            port
        };
        return Some(defaults.endpoint(public));
    }
    if let Some(address) = &rule.advertise {
        return Some(address.clone());
    }
    (!rule.listen.ip().is_unspecified()).then(|| rule.listen.to_string())
}
fn member_rule<'a>(configs: &'a Configs, member: &Member) -> Option<&'a Rule> {
    configs
        .get(&member.node_id)?
        .rules
        .iter()
        .find(|rule| rule.id == member.rule_id)
}
/// Members whose node and rule still exist.
fn present(record: &SharedRule, configs: &Configs) -> Vec<Member> {
    record
        .members
        .iter()
        .filter(|member| member_rule(configs, member).is_some())
        .cloned()
        .collect()
}

/// What every line should run.
struct Desired<'a> {
    name: &'a str,
    port: u16,
    common: &'a Rule,
    owner: &'a str,
    tenant: &'a str,
}
struct Plan {
    updates: Vec<ConfigUpdate>,
    members: Vec<Member>,
    conflicts: Vec<LineError>,
}
/// The batch that makes `node_ids` the lines of a shared rule whose current
/// lines are `existing`: existing lines keep their rule id, owner, listen
/// host and advertised address, and their meter epoch unless the port
/// changes; new lines get a fresh rule; lines left out lose their rule.
/// Nodes whose rules would not change are left out of the batch.
fn plan(
    conn: &Connection,
    configs: &Configs,
    existing: &[Member],
    node_ids: &[String],
    desired: &Desired<'_>,
) -> Result<Plan> {
    let wanted: HashSet<&str> = node_ids.iter().map(String::as_str).collect();
    let mut result = Plan {
        updates: vec![],
        members: vec![],
        conflicts: vec![],
    };
    for member in existing
        .iter()
        .filter(|m| !wanted.contains(m.node_id.as_str()))
    {
        let config = &configs[&member.node_id];
        result.updates.push(ConfigUpdate {
            node_id: member.node_id.clone(),
            expected_revision: config.revision,
            rules: config
                .rules
                .iter()
                .filter(|rule| rule.id != member.rule_id)
                .cloned()
                .collect(),
            rate_bytes_per_sec: None,
        });
    }
    let order = existing
        .iter()
        .map(|m| m.node_id.as_str())
        .filter(|node| wanted.contains(node))
        .chain(
            node_ids
                .iter()
                .map(String::as_str)
                .filter(|node| !existing.iter().any(|m| m.node_id == *node)),
        );
    for node in order {
        let config = configs.get(node).context("node configuration missing")?;
        let previous = existing
            .iter()
            .find(|m| m.node_id == node)
            .and_then(|m| member_rule(configs, m));
        let defaults = forwarding(conn, node)?;
        let mut rule = desired.common.clone();
        rule.name = desired.name.to_owned();
        rule.tenant_id = desired.tenant.to_owned();
        rule.listen_end_port = None;
        if let Some(previous) = previous {
            rule.id = previous.id.clone();
            rule.owner_id = previous.owner_id.clone();
            rule.advertise = previous.advertise.clone();
            rule.budget_ids = previous.budget_ids.clone();
            rule.listen = SocketAddr::new(previous.listen.ip(), desired.port);
            // Counters belong to a port; a new port starts a new period.
            rule.meter_epoch = if previous.listen.port() == desired.port {
                previous.meter_epoch.clone()
            } else {
                Uuid::new_v4().to_string()
            };
        } else {
            rule.id = Uuid::new_v4().to_string();
            rule.owner_id = desired.owner.to_owned();
            rule.advertise = None;
            rule.budget_ids = vec![];
            rule.listen = SocketAddr::new(bind_ip(defaults.as_ref()), desired.port);
            rule.meter_epoch = Uuid::new_v4().to_string();
        }
        let reserved = federation::reserved_ports(conn, node)?;
        if taken(
            config,
            &reserved,
            desired.port,
            previous.map(|p| p.id.as_str()),
        ) {
            result.conflicts.push(LineError {
                node_id: node.to_owned(),
                error: format!("port {} is already used on this server", desired.port),
            });
        }
        result.members.push(Member {
            node_id: node.to_owned(),
            rule_id: rule.id.clone(),
        });
        if previous == Some(&rule) {
            continue;
        }
        let rules = match previous {
            Some(previous) => config
                .rules
                .iter()
                .map(|r| {
                    if r.id == previous.id {
                        rule.clone()
                    } else {
                        r.clone()
                    }
                })
                .collect(),
            None => config.rules.iter().cloned().chain([rule]).collect(),
        };
        result.updates.push(ConfigUpdate {
            node_id: node.to_owned(),
            expected_revision: config.revision,
            rules,
            rate_bytes_per_sec: None,
        });
    }
    Ok(result)
}
fn port_conflict(conflicts: Vec<LineError>, port: u16) -> anyhow::Error {
    anyhow::Error::from(Rejection {
        status: 409,
        message: format!(
            "port {port} is already used on {} of the selected servers",
            conflicts.len()
        ),
    })
    .context(LineErrors(conflicts))
}
/// Publishes `updates` as one batch inside `tx`. A refused batch is checked
/// node by node so the error names the lines that caused it.
fn publish(
    tx: &Transaction<'_>,
    clocks: &mut leases::LeaseClocks,
    actor: &Actor,
    updates: Vec<ConfigUpdate>,
) -> Result<()> {
    if updates.is_empty() {
        return Ok(());
    }
    let batch = ConfigBatch {
        updates: updates.clone(),
    };
    let Err(error) = topology::publish_in(tx, clocks, actor, batch) else {
        return Ok(());
    };
    if error.downcast_ref::<Rejection>().is_none() {
        return Err(error);
    }
    let mut lines = vec![];
    for update in updates {
        let node_id = update.node_id.clone();
        let single = ConfigBatch {
            updates: vec![update],
        };
        if let Err(problem) = topology::prepare(tx, clocks, actor, single) {
            lines.push(LineError {
                node_id,
                error: problem.to_string(),
            });
        }
    }
    Err(if lines.is_empty() {
        error
    } else {
        error.context(LineErrors(lines))
    })
}
/// The owner of new lines: the request's, or the caller.
fn owner<'a>(rule: &'a Rule, actor: &'a Actor) -> &'a str {
    if rule.owner_id.is_empty() {
        &actor.id
    } else {
        &rule.owner_id
    }
}
fn node_name(conn: &Connection, node: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row("SELECT name FROM nodes WHERE id=?1", [node], |r| r.get(0))
        .optional()?)
}
fn view(conn: &Connection, configs: &Configs, record: &SharedRule) -> Result<SharedRuleView> {
    let reference = record
        .members
        .iter()
        .find_map(|member| member_rule(configs, member));
    let mut all_drift = BTreeSet::new();
    let mut members = Vec::with_capacity(record.members.len());
    for member in &record.members {
        let rule = member_rule(configs, member);
        let lines = match (reference, rule) {
            (Some(reference), Some(rule)) => drift(reference, rule),
            _ => vec![],
        };
        all_drift.extend(lines.iter().cloned());
        members.push(MemberView {
            node_id: member.node_id.clone(),
            rule_id: member.rule_id.clone(),
            node_name: node_name(conn, &member.node_id)?,
            missing: rule.is_none(),
            entry: match rule {
                Some(rule) => entry(forwarding(conn, &member.node_id)?.as_ref(), rule),
                None => None,
            },
            rule: rule.cloned(),
            drift: lines,
        });
    }
    Ok(SharedRuleView {
        id: record.id.clone(),
        tenant_id: record.tenant_id.clone(),
        name: record.name.clone(),
        listen_port: record.listen_port,
        created_at_ms: record.created_at_ms,
        updated_at_ms: record.updated_at_ms,
        members,
        drift: all_drift.into_iter().collect(),
    })
}

impl Store {
    pub fn shared_rules(&self, actor: &Actor) -> Result<Vec<SharedRuleView>> {
        let conn = self.0.lock().unwrap();
        let configs = topology::all_configs(&conn)?;
        let mut records = all(&conn)?;
        records.retain(|record| actor.permits_tenant(&record.tenant_id));
        records.sort_by(|a, b| (&a.name, &a.id).cmp(&(&b.name, &b.id)));
        records
            .iter()
            .map(|record| view(&conn, &configs, record))
            .collect()
    }
    /// Checks a port on every line without reserving it. Without a port it
    /// picks the lowest one inside every line's forwarding range that no
    /// line uses.
    pub fn precheck_shared_rule(&self, actor: &Actor, input: PrecheckInput) -> Result<Precheck> {
        writer(actor)?;
        check_rule(&input.rule, input.listen_port)?;
        let conn = self.0.lock().unwrap();
        let tenant = lines(&conn, actor, &input.node_ids)?;
        let configs = topology::all_configs(&conn)?;
        let existing = match &input.id {
            Some(id) => {
                let record = visible(&conn, actor, id)?;
                if record.tenant_id != tenant {
                    return reject(400, "all lines must belong to the same tenant");
                }
                present(&record, &configs)
            }
            None => vec![],
        };
        let own = |node: &str| {
            existing
                .iter()
                .find(|m| m.node_id == node)
                .map(|m| m.rule_id.as_str())
        };
        let mut nodes = Vec::with_capacity(input.node_ids.len());
        for node in &input.node_ids {
            let (name, last_seen, stats): (String, Option<i64>, String) = conn.query_row(
                "SELECT name,last_seen_ms,stats_json FROM nodes WHERE id=?1",
                [node],
                |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
            )?;
            let (last_seen, _) = self.4.current(node, last_seen, stats);
            let range = port_range(forwarding(&conn, node)?.as_ref());
            let reserved = federation::reserved_ports(&conn, node)?;
            nodes.push((node, name, last_seen, range, reserved));
        }
        let port = input.listen_port.or_else(|| {
            let start = nodes.iter().map(|n| n.3.0).max()?;
            let end = nodes.iter().map(|n| n.3.1).min()?;
            (start..=end).find(|port| {
                nodes.iter().all(|(node, _, _, _, reserved)| {
                    !taken(&configs[*node], reserved, *port, own(node))
                })
            })
        });
        let now = now_ms();
        let mut result = Precheck {
            listen_port: port,
            ok: port.is_some(),
            error: None,
            lines: vec![],
        };
        let mut updates = vec![];
        if let Some(port) = port {
            let reference = existing.first().and_then(|m| member_rule(&configs, m));
            // A form can be checked before it has a name.
            let name = if input.rule.name.trim().is_empty() {
                "Shared rule"
            } else {
                &input.rule.name
            };
            let desired = Desired {
                name,
                port,
                common: &input.rule,
                owner: reference.map_or_else(|| owner(&input.rule, actor), |r| &r.owner_id),
                tenant: &tenant,
            };
            updates = plan(&conn, &configs, &existing, &input.node_ids, &desired)?.updates;
        } else {
            result.error = Some(
                "no port inside the common forwarding range of the selected servers is free on all of them"
                    .into(),
            );
        }
        let mut clocks = self.3.lock().unwrap();
        for (node, name, last_seen, (start, end), reserved) in nodes {
            let mut line = PrecheckLine {
                node_id: node.clone(),
                node_name: name,
                online: last_seen.is_some_and(|seen| now.saturating_sub(seen) <= ONLINE_MS),
                in_range: port.is_some_and(|port| (start..=end).contains(&port)),
                port_start: start,
                port_end: end,
                port_free: port
                    .is_some_and(|port| !taken(&configs[node], &reserved, port, own(node))),
                valid: port.is_some(),
                error: None,
            };
            if let Some(update) = updates.iter().find(|u| &u.node_id == node) {
                let single = ConfigBatch {
                    updates: vec![update.clone()],
                };
                if let Err(error) = topology::prepare(&conn, &mut clocks, actor, single) {
                    line.valid = false;
                    line.error = Some(error.to_string());
                }
            }
            result.ok &= line.port_free && line.valid;
            result.lines.push(line);
        }
        if !updates.is_empty() {
            let batch = ConfigBatch { updates };
            if let Err(error) = topology::prepare(&conn, &mut clocks, actor, batch) {
                result.ok = false;
                result.error = Some(error.to_string());
            }
        }
        Ok(result)
    }
    pub fn create_shared_rule(
        &self,
        actor: &Actor,
        input: SharedRuleInput,
    ) -> Result<SharedRuleView> {
        writer(actor)?;
        check_name(&input.name)?;
        check_rule(&input.rule, Some(input.listen_port))?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let tenant = lines(&tx, actor, &input.node_ids)?;
        let configs = topology::all_configs(&tx)?;
        let desired = Desired {
            name: &input.name,
            port: input.listen_port,
            common: &input.rule,
            owner: owner(&input.rule, actor),
            tenant: &tenant,
        };
        let plan = plan(&tx, &configs, &[], &input.node_ids, &desired)?;
        if !plan.conflicts.is_empty() {
            return Err(port_conflict(plan.conflicts, input.listen_port));
        }
        let now = now_ms();
        let record = SharedRule {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant,
            name: input.name.clone(),
            listen_port: input.listen_port,
            members: plan.members,
            created_at_ms: now,
            updated_at_ms: now,
        };
        publish(&tx, &mut self.3.lock().unwrap(), actor, plan.updates)?;
        write(&tx, &record)?;
        audit(
            &tx,
            &actor.id,
            "shared_rule.create",
            &record.id,
            &serde_json::json!({"name":record.name,"listen_port":record.listen_port,"members":record.members}).to_string(),
        )?;
        tx.commit()?;
        self.2.config.notify_waiters();
        view(&conn, &topology::all_configs(&conn)?, &record)
    }
    /// Turns an existing rule into the first line of a new shared rule and
    /// copies it to `add_node_ids` on the same port.
    pub fn extend_rule(&self, actor: &Actor, input: FromRuleInput) -> Result<SharedRuleView> {
        writer(actor)?;
        if input.add_node_ids.is_empty() {
            return reject(400, "choose at least one server to add");
        }
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        require_node(&tx, actor, &input.node_id, true)?;
        let configs = topology::all_configs(&tx)?;
        let source = Member {
            node_id: input.node_id.clone(),
            rule_id: input.rule_id.clone(),
        };
        let Some(rule) = member_rule(&configs, &source).cloned() else {
            return reject(404, "rule not found");
        };
        if rule.id.starts_with(crate::federation::RULE_PREFIX) {
            return reject(400, "rules of a cross-panel share cannot be shared rules");
        }
        check_rule(&rule, None)?;
        if all(&tx)?
            .iter()
            .any(|record| record.members.contains(&source))
        {
            return reject(409, "this rule already belongs to a shared rule");
        }
        let node_ids: Vec<String> = std::iter::once(input.node_id.clone())
            .chain(input.add_node_ids)
            .collect();
        let tenant = lines(&tx, actor, &node_ids)?;
        let desired = Desired {
            name: &rule.name,
            port: rule.listen.port(),
            common: &rule,
            owner: &rule.owner_id,
            tenant: &tenant,
        };
        let plan = plan(&tx, &configs, &[source], &node_ids, &desired)?;
        if !plan.conflicts.is_empty() {
            return Err(port_conflict(plan.conflicts, rule.listen.port()));
        }
        let now = now_ms();
        let record = SharedRule {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant,
            name: rule.name.clone(),
            listen_port: rule.listen.port(),
            members: plan.members,
            created_at_ms: now,
            updated_at_ms: now,
        };
        publish(&tx, &mut self.3.lock().unwrap(), actor, plan.updates)?;
        write(&tx, &record)?;
        audit(
            &tx,
            &actor.id,
            "shared_rule.create",
            &record.id,
            &serde_json::json!({"name":record.name,"listen_port":record.listen_port,"members":record.members,"from_rule":rule.id}).to_string(),
        )?;
        tx.commit()?;
        self.2.config.notify_waiters();
        view(&conn, &topology::all_configs(&conn)?, &record)
    }
    pub fn update_shared_rule(
        &self,
        actor: &Actor,
        id: &str,
        input: SharedRuleInput,
    ) -> Result<SharedRuleView> {
        writer(actor)?;
        check_name(&input.name)?;
        check_rule(&input.rule, Some(input.listen_port))?;
        if input.node_ids.is_empty() {
            return reject(
                400,
                "a shared rule keeps at least one line; delete it to remove every line",
            );
        }
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut record = visible(&tx, actor, id)?;
        let tenant = lines(&tx, actor, &input.node_ids)?;
        if tenant != record.tenant_id {
            return reject(400, "all lines must belong to the same tenant");
        }
        let configs = topology::all_configs(&tx)?;
        let existing = present(&record, &configs);
        let first_owner = existing
            .first()
            .and_then(|m| member_rule(&configs, m))
            .map(|rule| rule.owner_id.clone());
        let desired = Desired {
            name: &input.name,
            port: input.listen_port,
            common: &input.rule,
            owner: first_owner
                .as_deref()
                .unwrap_or_else(|| owner(&input.rule, actor)),
            tenant: &tenant,
        };
        let plan = plan(&tx, &configs, &existing, &input.node_ids, &desired)?;
        if !plan.conflicts.is_empty() {
            return Err(port_conflict(plan.conflicts, input.listen_port));
        }
        let removed: Vec<&Member> = existing
            .iter()
            .filter(|m| !plan.members.contains(m))
            .collect();
        let detail = serde_json::json!({"name":input.name,"listen_port":input.listen_port,"previous_port":record.listen_port,"members":plan.members,"removed":removed}).to_string();
        let published = !plan.updates.is_empty();
        publish(&tx, &mut self.3.lock().unwrap(), actor, plan.updates)?;
        record.name = input.name;
        record.listen_port = input.listen_port;
        record.members = plan.members;
        record.updated_at_ms = now_ms();
        write(&tx, &record)?;
        audit(&tx, &actor.id, "shared_rule.update", &record.id, &detail)?;
        tx.commit()?;
        if published {
            self.2.config.notify_waiters();
        }
        view(&conn, &topology::all_configs(&conn)?, &record)
    }
    /// Disables (`paused`) or enables every line in one batch.
    pub fn pause_shared_rule(
        &self,
        actor: &Actor,
        id: &str,
        paused: bool,
    ) -> Result<SharedRuleView> {
        writer(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut record = visible(&tx, actor, id)?;
        let configs = topology::all_configs(&tx)?;
        record.members = present(&record, &configs);
        let mut updates = vec![];
        for member in &record.members {
            let config = &configs[&member.node_id];
            if member_rule(&configs, member).is_some_and(|rule| rule.enabled != paused) {
                continue;
            }
            updates.push(ConfigUpdate {
                node_id: member.node_id.clone(),
                expected_revision: config.revision,
                rules: config
                    .rules
                    .iter()
                    .map(|rule| {
                        let mut rule = rule.clone();
                        if rule.id == member.rule_id {
                            rule.enabled = !paused;
                        }
                        rule
                    })
                    .collect(),
                rate_bytes_per_sec: None,
            });
        }
        let published = !updates.is_empty();
        publish(&tx, &mut self.3.lock().unwrap(), actor, updates)?;
        record.updated_at_ms = now_ms();
        write(&tx, &record)?;
        audit(
            &tx,
            &actor.id,
            "shared_rule.pause",
            &record.id,
            &serde_json::json!({"paused":paused}).to_string(),
        )?;
        tx.commit()?;
        if published {
            self.2.config.notify_waiters();
        }
        view(&conn, &topology::all_configs(&conn)?, &record)
    }
    /// Deletes every line's rule in one batch and the record; with
    /// `keep_rules` only the record goes and the rules stay as ordinary rules.
    pub fn delete_shared_rule(&self, actor: &Actor, id: &str, keep_rules: bool) -> Result<()> {
        writer(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let record = visible(&tx, actor, id)?;
        let configs = topology::all_configs(&tx)?;
        let members = present(&record, &configs);
        if !keep_rules {
            let updates = members
                .iter()
                .map(|member| {
                    let config = &configs[&member.node_id];
                    ConfigUpdate {
                        node_id: member.node_id.clone(),
                        expected_revision: config.revision,
                        rules: config
                            .rules
                            .iter()
                            .filter(|rule| rule.id != member.rule_id)
                            .cloned()
                            .collect(),
                        rate_bytes_per_sec: None,
                    }
                })
                .collect();
            publish(&tx, &mut self.3.lock().unwrap(), actor, updates)?;
        }
        tx.execute("DELETE FROM metadata WHERE key=?1", [key(&record.id)])?;
        audit(
            &tx,
            &actor.id,
            "shared_rule.delete",
            &record.id,
            &serde_json::json!({"name":record.name,"keep_rules":keep_rules,"members":members})
                .to_string(),
        )?;
        tx.commit()?;
        if !keep_rules && !members.is_empty() {
            self.2.config.notify_waiters();
        }
        Ok(())
    }
}
