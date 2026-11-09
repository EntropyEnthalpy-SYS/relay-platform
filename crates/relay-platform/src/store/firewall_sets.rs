//! Firewall rule sets on the controller, in metadata (`firewall_set:<id>`),
//! so the schema and recovery log stay unchanged. A server's own bindings
//! are kept in `firewall_binding:<node id>`; a rule's binding is its
//! `firewall_inbound_set` field and travels with its configuration.
//!
//! Agents get the sets their server uses with every sync, as a policy and
//! its hash, rather than in a configuration revision: editing a set reaches
//! every server it is bound to without publishing them again, and a watch
//! wake makes them sync at once. The agent reports the hash it applied,
//! kept in `firewall_applied:<node id>` when it changes.
//!
//! Agents older than rule sets ignore the policy and reject a rule with
//! `firewall_inbound_set`, so binding a set to a server, or publishing a
//! rule bound to one, is refused (409) until the server's agent reported
//! support, kept in `firewall_node:<node id>`, as for egress proxies. Every
//! publish path goes through [`require`].
//!
//! Its value is `1`, or `{"covers":[...]}` when the agent also holds
//! protocol gateways' clients ([`firewall::COVERS_GATEWAY_INBOUND`]) or its
//! reverse tunnels' targets ([`firewall::COVERS_REVERSE_PRIVATE_OUTBOUND`])
//! to the sets; it follows the agent's latest report, so a downgraded
//! agent loses them. A binding, gateway or tunnel that would leave one of
//! these paths outside the sets is refused (409) on an agent without the
//! path; one from before the controller upgrade keeps running and the
//! server's status names it in `uncovered`.
use super::*;
use crate::firewall::{
    self, BindingRef, Desired, Direction, Layer, Layers, NodeStatus, Policy, PolicyState, Report,
    Scope, ServerBinding, SetInput, SetView, Stored, TestAnswer, TestInput, TestLayer, TestResult,
};
use std::collections::{BTreeSet, HashMap, HashSet};
use std::net::{IpAddr, SocketAddr};

fn key(id: &str) -> String {
    format!("firewall_set:{id}")
}
fn binding_key(node: &str) -> String {
    format!("firewall_binding:{node}")
}
fn node_key(node: &str) -> String {
    format!("firewall_node:{node}")
}
fn applied_key(node: &str) -> String {
    format!("firewall_applied:{node}")
}
fn get(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row("SELECT value FROM metadata WHERE key=?1", [key], |r| {
            r.get(0)
        })
        .optional()?)
}
fn put(tx: &Transaction<'_>, key: &str, value: &str) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, value],
    )?;
    Ok(())
}
fn load(conn: &Connection, id: &str) -> Result<Option<Stored>> {
    get(conn, &key(id))?
        .map(|value| serde_json::from_str(&value).context("invalid stored firewall rule set"))
        .transpose()
}
fn all(conn: &Connection) -> Result<Vec<Stored>> {
    let mut q = conn.prepare("SELECT value FROM metadata WHERE key GLOB 'firewall_set:*'")?;
    let rows: Vec<String> = q
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let mut sets: Vec<Stored> = rows
        .into_iter()
        .map(|value| serde_json::from_str(&value).context("invalid stored firewall rule set"))
        .collect::<Result<_>>()?;
    sets.sort_by(|a, b| (&a.name, &a.id).cmp(&(&b.name, &b.id)));
    Ok(sets)
}
fn visible_to(actor: &Actor, set: &Stored) -> bool {
    actor.role == Role::SystemAdmin
        || (set.scope == Scope::Tenant && set.tenant_id.as_deref() == Some(&actor.tenant_id))
}
fn visible(conn: &Connection, actor: &Actor, id: &str) -> Result<Stored> {
    match load(conn, id)? {
        Some(set) if visible_to(actor, &set) => Ok(set),
        _ => reject(404, "firewall rule set not found"),
    }
}
fn writable(actor: &Actor, set: &Stored) -> Result<()> {
    if !actor.may_write() {
        return reject(403, "read-only role cannot change firewall rule sets");
    }
    if set.scope == Scope::System && actor.role != Role::SystemAdmin {
        return reject(404, "firewall rule set not found");
    }
    Ok(())
}
fn bad(error: anyhow::Error) -> anyhow::Error {
    Rejection {
        status: 400,
        message: error.to_string(),
    }
    .into()
}

/// A server's own bindings.
fn binding(conn: &Connection, node: &str) -> Result<ServerBinding> {
    Ok(get(conn, &binding_key(node))?
        .map(|value| serde_json::from_str(&value))
        .transpose()?
        .unwrap_or_default())
}
/// The rules of `node`'s desired configuration; only read when one of them
/// is bound to a set.
fn desired_rules(conn: &Connection, node: &str) -> Result<Vec<Rule>> {
    let json: Option<String> = conn
        .query_row(
            "SELECT c.config_json FROM config_history c JOIN nodes n ON n.id=c.node_id AND n.desired_revision=c.revision WHERE n.id=?1 AND instr(c.config_json,'\"firewall_inbound_set\"')>0",
            [node],
            |r| r.get(0),
        )
        .optional()?;
    Ok(match json {
        Some(json) => serde_json::from_str::<NodeConfig>(&json)?.rules,
        None => vec![],
    })
}
/// The policy `node` gets with `rules` as its configuration: its server
/// bindings and every set they or the rules use.
fn policy_for(conn: &Connection, node: &str, rules: &[Rule]) -> Result<Policy> {
    let binding = binding(conn, node)?;
    let ids: BTreeSet<&str> = [&binding.inbound_set_id, &binding.outbound_set_id]
        .into_iter()
        .flatten()
        .map(String::as_str)
        .chain(
            rules
                .iter()
                .filter_map(|r| r.firewall_inbound_set.as_deref()),
        )
        .collect();
    let mut sets = vec![];
    for id in ids {
        if let Some(set) = load(conn, id)? {
            sets.push(set.spec());
        }
    }
    Ok(Policy {
        server_inbound: binding.inbound_set_id,
        server_outbound: binding.outbound_set_id,
        sets,
    })
}
pub(super) fn policy(conn: &Connection, node: &str) -> Result<Policy> {
    policy_for(conn, node, &desired_rules(conn, node)?)
}
fn check_size(conn: &Connection, node: &str, policy: &Policy) -> Result<()> {
    if serde_json::to_vec(policy)?.len() > firewall::MAX_POLICY_BYTES {
        let name: String =
            conn.query_row("SELECT name FROM nodes WHERE id=?1", [node], |r| r.get(0))?;
        return reject(
            400,
            format!(
                "the rule sets used on server {name} exceed {} KiB together; use fewer or smaller sets",
                firewall::MAX_POLICY_BYTES / 1024
            ),
        );
    }
    Ok(())
}

/// Whether `node`'s agent reported that it enforces rule sets.
pub(super) fn supported(conn: &Connection, node: &str) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM metadata WHERE key=?1)",
        [node_key(node)],
        |r| r.get(0),
    )?)
}
/// Why `node` cannot take rule sets, if it cannot.
fn unsupported(conn: &Connection, node: &str) -> Result<Option<String>> {
    if supported(conn, node)? {
        return Ok(None);
    }
    let (name, seen): (String, Option<i64>) = conn.query_row(
        "SELECT name,last_seen_ms FROM nodes WHERE id=?1",
        [node],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(Some(match seen {
        None => format!(
            "server {name} has not connected to the panel yet; firewall rule sets need its agent to report in first"
        ),
        Some(_) => format!(
            "the agent on server {name} is too old for firewall rule sets; upgrade it first"
        ),
    }))
}

/// The paths beyond its own rules that `node`'s agent last reported it
/// holds to rule sets.
fn covers(conn: &Connection, node: &str) -> Result<Vec<String>> {
    #[derive(Deserialize)]
    struct Coverage {
        covers: Vec<String>,
    }
    Ok(get(conn, &node_key(node))?
        .and_then(|value| serde_json::from_str::<Coverage>(&value).ok())
        .map(|coverage| coverage.covers)
        .unwrap_or_default())
}
fn node_name(conn: &Connection, node: &str) -> Result<String> {
    Ok(conn.query_row("SELECT name FROM nodes WHERE id=?1", [node], |r| r.get(0))?)
}
/// The refusal of a protocol gateway, or of a server inbound set over one,
/// on a server whose agent does not hold gateways to the sets.
fn gateways_uncovered(conn: &Connection, node: &str) -> Result<String> {
    Ok(format!(
        "the agent on server {} does not apply firewall rule sets to protocol gateways; upgrade it first",
        node_name(conn, node)?
    ))
}
/// The refusal of a reverse tunnel, or of a server outbound set over one,
/// on a private server whose agent does not hold its dials to the set.
fn reverse_uncovered(conn: &Connection, node: &str) -> Result<String> {
    Ok(format!(
        "the agent on server {} does not apply its outbound firewall rule set to reverse tunnels; upgrade it first",
        node_name(conn, node)?
    ))
}
/// Enabled protocol gateways of `rules`.
fn gateways(rules: &[Rule]) -> BTreeSet<&str> {
    rules
        .iter()
        .filter(|r| r.enabled && r.protocol_gateway.is_some())
        .map(|r| r.id.as_str())
        .collect()
}
/// The enabled protocol gateways of `node`'s desired configuration; only
/// read when its configuration has one.
fn desired_gateways(conn: &Connection, node: &str) -> Result<BTreeSet<String>> {
    let json: Option<String> = conn
        .query_row(
            "SELECT c.config_json FROM config_history c JOIN nodes n ON n.id=c.node_id AND n.desired_revision=c.revision WHERE n.id=?1 AND instr(c.config_json,'\"protocol_gateway\"')>0",
            [node],
            |r| r.get(0),
        )
        .optional()?;
    Ok(match json {
        Some(json) => gateways(&serde_json::from_str::<NodeConfig>(&json)?.rules)
            .into_iter()
            .map(str::to_owned)
            .collect(),
        None => BTreeSet::new(),
    })
}
/// Whether `node` is the private end of an enabled reverse tunnel.
fn dials_tunnels(conn: &Connection, node: &str) -> Result<bool> {
    Ok(super::reverse_tunnels::all(conn)?
        .iter()
        .any(|t| t.enabled && t.private_node_id == node))
}
/// Refuses an enabled reverse tunnel whose private server binds an outbound
/// set its agent does not hold the tunnel's target to.
pub(super) fn require_tunnel(conn: &Connection, private_node: &str) -> Result<()> {
    if binding(conn, private_node)?.outbound_set_id.is_some()
        && !covers(conn, private_node)?
            .iter()
            .any(|c| c == firewall::COVERS_REVERSE_PRIVATE_OUTBOUND)
    {
        return reject(409, reverse_uncovered(conn, private_node)?);
    }
    Ok(())
}

/// Keeps that `node`'s agent enforces rule sets and the paths it covers,
/// written when they change, and the policy it confirmed, written when it
/// changes. A sync without a report confirms nothing: the agent was
/// downgraded, or starts afresh and reports from its next sync on.
pub(super) fn observe(tx: &Transaction<'_>, node: &str, report: Option<&Report>) -> Result<()> {
    let Some(report) = report else {
        tx.execute("DELETE FROM metadata WHERE key=?1", [applied_key(node)])?;
        return Ok(());
    };
    let support = if report.covers.is_empty() {
        "1".to_owned()
    } else {
        serde_json::json!({ "covers": report.covers }).to_string()
    };
    if get(tx, &node_key(node))?.as_deref() != Some(support.as_str()) {
        put(tx, &node_key(node), &support)?;
    }
    let value = serde_json::to_string(report)?;
    if get(tx, &applied_key(node))?.as_deref() != Some(value.as_str()) {
        put(tx, &applied_key(node), &value)?;
    }
    Ok(())
}
fn applied(conn: &Connection, node: &str) -> Result<Report> {
    Ok(get(conn, &applied_key(node))?
        .and_then(|value| serde_json::from_str(&value).ok())
        .unwrap_or_default())
}

/// What a sync reply carries: the hash, and the policy unless the agent
/// reported it applied that hash.
pub(super) fn desired(conn: &Connection, node: &str, report: Option<&Report>) -> Result<Desired> {
    let policy = policy(conn, node)?;
    let hash = policy.hash();
    let current = report.is_some_and(|r| r.applied_hash.as_deref() == Some(hash.as_str()));
    Ok(Desired {
        policy: (!current).then_some(policy),
        hash,
    })
}

/// Refuses a configuration whose rules use sets the server cannot take:
/// a set that is missing or another tenant's (404), an outbound one (400),
/// any set on a server whose agent has not reported support (409), and a
/// protocol gateway bound to a set, or newly enabled on a server with an
/// inbound set, when the agent does not hold gateways to sets (409).
pub(super) fn require(conn: &Connection, tenant: &str, config: &NodeConfig) -> Result<()> {
    let mut bound = false;
    let mut gateway_bound = false;
    for rule in &config.rules {
        let Some(id) = &rule.firewall_inbound_set else {
            continue;
        };
        bound = true;
        let set = match load(conn, id)? {
            Some(set) if set.scope == Scope::Tenant && set.tenant_id.as_deref() == Some(tenant) => {
                set
            }
            _ => return reject(404, format!("firewall rule set {id} not found")),
        };
        if set.direction != Direction::Inbound {
            return reject(
                400,
                format!(
                    "rule {}: rule set {} is an outbound set; a rule takes an inbound set",
                    rule.name, set.name
                ),
            );
        }
        gateway_bound |= rule.protocol_gateway.is_some();
    }
    if bound && let Some(reason) = unsupported(conn, &config.node_id)? {
        return reject(409, reason);
    }
    let enabled = gateways(&config.rules);
    if !enabled.is_empty()
        && !covers(conn, &config.node_id)?
            .iter()
            .any(|c| c == firewall::COVERS_GATEWAY_INBOUND)
    {
        // A gateway already published stays: refusing it would stop every
        // publish to this server until its agent is upgraded.
        let added = || -> Result<bool> {
            let current = desired_gateways(conn, &config.node_id)?;
            Ok(enabled.iter().any(|id| !current.contains(*id)))
        };
        if gateway_bound || (binding(conn, &config.node_id)?.inbound_set_id.is_some() && added()?) {
            return reject(409, gateways_uncovered(conn, &config.node_id)?);
        }
    }
    if bound {
        check_size(
            conn,
            &config.node_id,
            &policy_for(conn, &config.node_id, &config.rules)?,
        )?;
    }
    Ok(())
}

/// Every place each set is in use, from server bindings and the desired
/// configurations.
fn bindings(conn: &Connection) -> Result<HashMap<String, Vec<BindingRef>>> {
    let mut found: HashMap<String, Vec<BindingRef>> = HashMap::new();
    let names: HashMap<String, String> = {
        let mut q = conn.prepare("SELECT id,name FROM nodes")?;
        q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
            .collect::<rusqlite::Result<_>>()?
    };
    let name = |node: &str| names.get(node).cloned().unwrap_or_else(|| node.to_owned());
    let mut q = conn.prepare(
        "SELECT substr(key,18),value FROM metadata WHERE key GLOB 'firewall_binding:*' ORDER BY key",
    )?;
    let rows: Vec<(String, String)> = q
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    for (node, value) in rows {
        let binding: ServerBinding = serde_json::from_str(&value)?;
        for (id, layer) in [
            (binding.inbound_set_id, Layer::ServerInbound),
            (binding.outbound_set_id, Layer::ServerOutbound),
        ] {
            if let Some(id) = id {
                found.entry(id).or_default().push(BindingRef {
                    layer,
                    node_id: node.clone(),
                    node_name: name(&node),
                    rule_id: None,
                    rule_name: None,
                });
            }
        }
    }
    for config in topology::all_configs(conn)?.into_values() {
        for rule in &config.rules {
            if let Some(id) = &rule.firewall_inbound_set {
                found.entry(id.clone()).or_default().push(BindingRef {
                    layer: Layer::RuleInbound,
                    node_id: config.node_id.clone(),
                    node_name: name(&config.node_id),
                    rule_id: Some(rule.id.clone()),
                    rule_name: Some(rule.name.clone()),
                });
            }
        }
    }
    Ok(found)
}
/// The servers that use `id`, to wake.
fn users(conn: &Connection, id: &str) -> Result<BTreeSet<String>> {
    Ok(bindings(conn)?
        .remove(id)
        .unwrap_or_default()
        .into_iter()
        .map(|b| b.node_id)
        .collect())
}

fn status(conn: &Connection, node: &str, last_seen: Option<i64>, now: i64) -> Result<NodeStatus> {
    let binding = binding(conn, node)?;
    let rules = desired_rules(conn, node)?;
    let policy = policy_for(conn, node, &rules)?;
    let desired_hash = policy.hash();
    let report = applied(conn, node)?;
    let supported = supported(conn, node)?;
    let name = |id: &Option<String>| -> Result<Option<String>> {
        Ok(match id {
            Some(id) => load(conn, id)?.map(|s| s.name),
            None => None,
        })
    };
    let unused = policy.server_inbound.is_none()
        && policy.server_outbound.is_none()
        && policy.sets.is_empty();
    let state = if report.applied_hash.as_deref() == Some(desired_hash.as_str()) {
        PolicyState::Applied
    } else if unused && !supported {
        PolicyState::Unused
    } else if last_seen.is_none() {
        PolicyState::NotConnected
    } else if !supported {
        PolicyState::TooOld
    } else if last_seen.is_some_and(|seen| now - seen > crate::telemetry::OFFLINE_AFTER_MS) {
        PolicyState::Offline
    } else {
        PolicyState::Waiting
    };
    let covered = covers(conn, node)?;
    let mut uncovered = vec![];
    if (binding.inbound_set_id.is_some()
        || rules
            .iter()
            .any(|r| r.protocol_gateway.is_some() && r.firewall_inbound_set.is_some()))
        && !covered
            .iter()
            .any(|c| c == firewall::COVERS_GATEWAY_INBOUND)
        && !desired_gateways(conn, node)?.is_empty()
    {
        uncovered.push(firewall::UNCOVERED_GATEWAYS.to_owned());
    }
    if binding.outbound_set_id.is_some()
        && !covered
            .iter()
            .any(|c| c == firewall::COVERS_REVERSE_PRIVATE_OUTBOUND)
        && dials_tunnels(conn, node)?
    {
        uncovered.push(firewall::UNCOVERED_REVERSE_TUNNELS.to_owned());
    }
    Ok(NodeStatus {
        uncovered,
        inbound_set_name: name(&binding.inbound_set_id)?,
        outbound_set_name: name(&binding.outbound_set_id)?,
        inbound_set_id: binding.inbound_set_id,
        outbound_set_id: binding.outbound_set_id,
        rule_bindings: rules
            .iter()
            .filter(|r| r.firewall_inbound_set.is_some())
            .count(),
        desired_hash,
        applied_hash: report.applied_hash,
        error: report.error,
        state,
    })
}
/// Fills in each node's support and policy state.
pub(super) fn annotate(conn: &Connection, nodes: &mut [Node]) -> Result<()> {
    let now = now_ms();
    for node in nodes {
        node.firewall_support = supported(conn, &node.id)?;
        node.firewall = Some(status(conn, &node.id, node.last_seen_ms, now)?);
    }
    Ok(())
}

/// Whether `node`'s watch should answer at once because its policy changed;
/// answers yes once.
pub(super) fn take_wake(wake: &Mutex<HashSet<String>>, node: &str) -> bool {
    wake.lock().unwrap().remove(node)
}

fn view(set: Stored, bindings: &mut HashMap<String, Vec<BindingRef>>) -> SetView {
    SetView {
        bindings: bindings.remove(&set.id).unwrap_or_default(),
        set,
    }
}

/// The host of a tester destination: an IP (brackets optional) or a name.
fn test_host(destination: &str) -> Result<(String, Option<IpAddr>)> {
    let host = crate::destination_acl::normalize_host(destination);
    if let Ok(ip) = host.parse::<IpAddr>() {
        return Ok((host, Some(ip)));
    }
    if !crate::destination_acl::valid_hostname(&host) {
        return reject(400, "the destination must be a domain or an IP address");
    }
    Ok((host, None))
}
/// Refuses a set larger than a server's whole policy may be.
fn check_set_size(set: &Stored) -> Result<()> {
    if serde_json::to_vec(&set.spec())?.len() > firewall::MAX_POLICY_BYTES {
        return reject(
            400,
            format!(
                "a rule set is at most {} KiB; use fewer rules or entries",
                firewall::MAX_POLICY_BYTES / 1024
            ),
        );
    }
    Ok(())
}
/// The rules of `node`'s desired configuration.
fn node_rules(conn: &Connection, node: &str) -> Result<Vec<Rule>> {
    let json: String = conn
        .query_row(
            "SELECT c.config_json FROM config_history c JOIN nodes n ON n.id=c.node_id AND n.desired_revision=c.revision WHERE n.id=?1",
            [node],
            |r| r.get(0),
        )
        .optional()?
        .context("node configuration missing")?;
    Ok(serde_json::from_str::<NodeConfig>(&json)?.rules)
}

impl Store {
    fn wake_firewall<'a>(&self, nodes: impl IntoIterator<Item = &'a String>) {
        let mut woken = self.13.lock().unwrap();
        let mut any = false;
        for node in nodes {
            woken.insert(node.clone());
            any = true;
        }
        drop(woken);
        if any {
            self.2.config.notify_waiters();
        }
    }
    pub fn firewall_sets(&self, actor: &Actor) -> Result<Vec<SetView>> {
        let conn = self.0.lock().unwrap();
        let mut bindings = bindings(&conn)?;
        Ok(all(&conn)?
            .into_iter()
            .filter(|set| visible_to(actor, set))
            .map(|set| view(set, &mut bindings))
            .collect())
    }
    pub fn firewall_set(&self, actor: &Actor, id: &str) -> Result<SetView> {
        let conn = self.0.lock().unwrap();
        let set = visible(&conn, actor, id)?;
        Ok(view(set, &mut bindings(&conn)?))
    }
    pub fn create_firewall_set(&self, actor: &Actor, input: SetInput) -> Result<SetView> {
        if !actor.may_write() {
            return reject(403, "read-only role cannot change firewall rule sets");
        }
        firewall::validate_name(&input.name).map_err(bad)?;
        firewall::validate_rules(input.direction, &input.rules).map_err(bad)?;
        let scope = input.scope.unwrap_or(Scope::Tenant);
        let tenant_id = match scope {
            Scope::System if actor.role != Role::SystemAdmin => {
                return reject(403, "only system administrators keep system rule sets");
            }
            Scope::System if input.tenant_id.is_some() => {
                return reject(400, "a system rule set belongs to no tenant");
            }
            Scope::System => None,
            Scope::Tenant => {
                let tenant = input.tenant_id.unwrap_or_else(|| actor.tenant_id.clone());
                if !actor.permits_tenant(&tenant) {
                    return reject(404, "tenant not found");
                }
                Some(tenant)
            }
        };
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        if let Some(tenant) = &tenant_id
            && !tx.query_row(
                "SELECT EXISTS(SELECT 1 FROM tenants WHERE id=?1)",
                [tenant],
                |r| r.get::<_, bool>(0),
            )?
        {
            return reject(404, "tenant not found");
        }
        if all(&tx)?
            .iter()
            .filter(|set| set.tenant_id == tenant_id)
            .count()
            >= firewall::MAX_SETS
        {
            return reject(
                409,
                match tenant_id {
                    Some(_) => format!(
                        "at most {} firewall rule sets per tenant; delete one first",
                        firewall::MAX_SETS
                    ),
                    None => format!(
                        "at most {} system firewall rule sets; delete one first",
                        firewall::MAX_SETS
                    ),
                },
            );
        }
        let now = now_ms();
        let set = Stored {
            id: Uuid::new_v4().to_string(),
            scope,
            tenant_id,
            name: input.name,
            direction: input.direction,
            default_action: input.default_action,
            rules: input.rules,
            revision: 1,
            created_at_ms: now,
            updated_at_ms: now,
        };
        check_set_size(&set)?;
        put(&tx, &key(&set.id), &serde_json::to_string(&set)?)?;
        audit(
            &tx,
            &actor.id,
            "firewall_set.create",
            &set.id,
            &serde_json::json!({"name": set.name, "direction": set.direction, "rules": set.rules.len()})
                .to_string(),
        )?;
        tx.commit()?;
        Ok(SetView {
            set,
            bindings: vec![],
        })
    }
    pub fn update_firewall_set(&self, actor: &Actor, id: &str, input: SetInput) -> Result<SetView> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let old = visible(&tx, actor, id)?;
        writable(actor, &old)?;
        if input.direction != old.direction {
            return reject(400, "the direction of a rule set cannot change");
        }
        if input.scope.is_some_and(|scope| scope != old.scope)
            || input
                .tenant_id
                .as_ref()
                .is_some_and(|tenant| old.tenant_id.as_ref() != Some(tenant))
        {
            return reject(400, "the scope and tenant of a rule set cannot change");
        }
        if input
            .expected_revision
            .is_some_and(|revision| revision != old.revision)
        {
            return reject(409, "the rule set changed; reload before saving");
        }
        firewall::validate_name(&input.name).map_err(bad)?;
        firewall::validate_rules(old.direction, &input.rules).map_err(bad)?;
        let set = Stored {
            name: input.name,
            default_action: input.default_action,
            rules: input.rules,
            revision: old.revision.saturating_add(1),
            updated_at_ms: now_ms(),
            ..old.clone()
        };
        check_set_size(&set)?;
        put(&tx, &key(&set.id), &serde_json::to_string(&set)?)?;
        let woken = users(&tx, id)?;
        for node in &woken {
            check_size(&tx, node, &policy(&tx, node)?)?;
        }
        audit(
            &tx,
            &actor.id,
            "firewall_set.update",
            id,
            &serde_json::json!({"before": {"name": old.name, "default_action": old.default_action, "rules": old.rules.len()}, "after": {"name": set.name, "default_action": set.default_action, "rules": set.rules.len()}, "servers": woken.len()})
                .to_string(),
        )?;
        tx.commit()?;
        let mut bindings = bindings(&conn)?;
        drop(conn);
        self.wake_firewall(&woken);
        Ok(view(set, &mut bindings))
    }
    pub fn delete_firewall_set(&self, actor: &Actor, id: &str) -> Result<()> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let set = visible(&tx, actor, id)?;
        writable(actor, &set)?;
        let used = bindings(&tx)?.remove(id).unwrap_or_default();
        if !used.is_empty() {
            let list: Vec<String> = used
                .iter()
                .map(|b| match (&b.rule_name, b.layer) {
                    (Some(rule), _) => format!("rule {rule} on server {}", b.node_name),
                    (None, Layer::ServerOutbound) => format!("server {} (outbound)", b.node_name),
                    (None, _) => format!("server {} (inbound)", b.node_name),
                })
                .collect();
            return reject(
                409,
                format!(
                    "rule set {} is still bound: {}; remove these bindings first",
                    set.name,
                    list.join(", ")
                ),
            );
        }
        tx.execute("DELETE FROM metadata WHERE key=?1", [key(id)])?;
        audit(
            &tx,
            &actor.id,
            "firewall_set.delete",
            id,
            &serde_json::json!({"name": set.name}).to_string(),
        )?;
        tx.commit()?;
        Ok(())
    }
    /// A server's bindings and policy state.
    pub fn node_firewall(&self, actor: &Actor, node: &str) -> Result<NodeStatus> {
        let conn = self.0.lock().unwrap();
        require_node(&conn, actor, node, false)?;
        let stored: Option<i64> =
            conn.query_row("SELECT last_seen_ms FROM nodes WHERE id=?1", [node], |r| {
                r.get(0)
            })?;
        let (last_seen, _) = self.4.current(node, stored, String::new());
        status(&conn, node, last_seen, now_ms())
    }
    /// Binds system sets to a server (system administrators only). A
    /// binding needs an agent that reported support; unbinding does not.
    pub fn bind_node_firewall(
        &self,
        actor: &Actor,
        node: &str,
        input: ServerBinding,
    ) -> Result<NodeStatus> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        require_node(&tx, actor, node, true)?;
        if actor.role != Role::SystemAdmin {
            return reject(403, "only system administrators bind rule sets to servers");
        }
        for (id, direction) in [
            (&input.inbound_set_id, Direction::Inbound),
            (&input.outbound_set_id, Direction::Outbound),
        ] {
            let Some(id) = id else { continue };
            let Some(set) = load(&tx, id)? else {
                return reject(404, format!("firewall rule set {id} not found"));
            };
            if set.scope != Scope::System {
                return reject(
                    400,
                    format!(
                        "rule set {} belongs to a tenant; servers take system rule sets",
                        set.name
                    ),
                );
            }
            if set.direction != direction {
                return reject(
                    400,
                    format!(
                        "rule set {} is an {} set; bind it as the server's {} set",
                        set.name,
                        match set.direction {
                            Direction::Inbound => "inbound",
                            Direction::Outbound => "outbound",
                        },
                        match set.direction {
                            Direction::Inbound => "inbound",
                            Direction::Outbound => "outbound",
                        }
                    ),
                );
            }
        }
        let old = binding(&tx, node)?;
        let adds = (input.inbound_set_id.is_some() && input.inbound_set_id != old.inbound_set_id)
            || (input.outbound_set_id.is_some() && input.outbound_set_id != old.outbound_set_id);
        if adds && let Some(reason) = unsupported(&tx, node)? {
            return reject(409, reason);
        }
        let covered = covers(&tx, node)?;
        if input.inbound_set_id.is_some()
            && input.inbound_set_id != old.inbound_set_id
            && !covered
                .iter()
                .any(|c| c == firewall::COVERS_GATEWAY_INBOUND)
            && !desired_gateways(&tx, node)?.is_empty()
        {
            return reject(409, gateways_uncovered(&tx, node)?);
        }
        if input.outbound_set_id.is_some()
            && input.outbound_set_id != old.outbound_set_id
            && !covered
                .iter()
                .any(|c| c == firewall::COVERS_REVERSE_PRIVATE_OUTBOUND)
            && dials_tunnels(&tx, node)?
        {
            return reject(409, reverse_uncovered(&tx, node)?);
        }
        if input == ServerBinding::default() {
            tx.execute("DELETE FROM metadata WHERE key=?1", [binding_key(node)])?;
        } else {
            put(&tx, &binding_key(node), &serde_json::to_string(&input)?)?;
        }
        check_size(&tx, node, &policy(&tx, node)?)?;
        audit(
            &tx,
            &actor.id,
            "node.firewall.bind",
            node,
            &serde_json::json!({"before": old, "after": input}).to_string(),
        )?;
        tx.commit()?;
        let stored: Option<i64> =
            conn.query_row("SELECT last_seen_ms FROM nodes WHERE id=?1", [node], |r| {
                r.get(0)
            })?;
        let (last_seen, _) = self.4.current(node, stored, String::new());
        let status = status(&conn, node, last_seen, now_ms())?;
        drop(conn);
        self.wake_firewall([&node.to_owned()]);
        Ok(status)
    }
    /// Which rule of which set answers, layer by layer, and the decision,
    /// evaluated as the agent does. A binding is answered with the server's
    /// desired policy.
    pub fn test_firewall(&self, actor: &Actor, input: TestInput) -> Result<TestResult> {
        let conn = self.0.lock().unwrap();
        let outbound = match (&input.source, &input.destination) {
            (Some(_), None) => false,
            (None, Some(_)) => true,
            _ => {
                return reject(
                    400,
                    "give a source address (inbound) or a destination and port (outbound)",
                );
            }
        };
        let destination = match &input.destination {
            Some(destination) => {
                let (host, literal) = test_host(destination)?;
                let Some(port) = input.port.filter(|p| *p != 0) else {
                    return reject(400, "an outbound test needs a destination port (1-65535)");
                };
                Some((host, literal.or(input.address), port))
            }
            None => {
                if input.port.is_some() || input.address.is_some() {
                    return reject(400, "an inbound test takes only a source address");
                }
                None
            }
        };
        let direction = if outbound {
            Direction::Outbound
        } else {
            Direction::Inbound
        };
        match (&input.set_id, &input.node_id) {
            (Some(id), None) => {
                if input.rule_id.is_some() {
                    return reject(400, "a rule is tested through its server: give node_id");
                }
                let set = visible(&conn, actor, id)?;
                if set.direction != direction {
                    return reject(
                        400,
                        match set.direction {
                            Direction::Inbound => "this is an inbound set: give a source address",
                            Direction::Outbound => {
                                "this is an outbound set: give a destination and port"
                            }
                        },
                    );
                }
                let compiled = firewall::Compiled::new(&set.spec()).map_err(bad)?;
                let verdict = match (&input.source, &destination) {
                    (Some(source), _) => compiled.source(*source),
                    (None, Some((host, Some(address), port))) => {
                        compiled.destination(host, *address, *port)
                    }
                    (None, Some((host, None, port))) => compiled.destination_name(host, *port),
                    (None, None) => unreachable!("checked above"),
                };
                let outcome = firewall::Outcome {
                    layer: Layer::ServerInbound,
                    set_id: set.id.clone(),
                    set_name: Some(set.name.clone()),
                    verdict: Some(verdict),
                };
                let mut layer = TestLayer::of(&outcome);
                layer.layer = "set".into();
                Ok(TestResult::new(direction, vec![layer], None))
            }
            (None, Some(node)) => {
                require_node(&conn, actor, node, false)?;
                let rules = node_rules(&conn, node)?;
                let rule = match &input.rule_id {
                    Some(id) => match rules.iter().find(|r| &r.id == id) {
                        Some(rule) => Some(rule.clone()),
                        None => return reject(404, "rule not found on this server"),
                    },
                    None => None,
                };
                // A gateway's public listener judges its clients with
                // these layers only on an agent that says so.
                if rule.as_ref().is_some_and(|r| r.protocol_gateway.is_some())
                    && !covers(&conn, node)?
                        .iter()
                        .any(|c| c == firewall::COVERS_GATEWAY_INBOUND)
                {
                    return reject(409, gateways_uncovered(&conn, node)?);
                }
                let policy = policy_for(&conn, node, &rules)?;
                let hash = policy.hash();
                let layers = Layers::new(&policy);
                let mut tested = vec![];
                if let Some(source) = input.source {
                    let rule_set = rule
                        .as_ref()
                        .and_then(|r| r.firewall_inbound_set.as_deref());
                    tested.extend(layers.inbound(rule_set, source).map(|o| TestLayer::of(&o)));
                    if let Some(rule) = &rule {
                        let ip = canonical_ip(source);
                        let denied = rule.deny_sources.iter().find(|n| n.contains(&ip));
                        let (result, detail) = if rule.permits(source) {
                            (TestAnswer::Allow, None)
                        } else if let Some(network) = denied {
                            (
                                TestAnswer::Deny,
                                Some(format!("matches deny-list network {network}")),
                            )
                        } else {
                            (TestAnswer::Deny, Some("not in the allow list".into()))
                        };
                        tested.push(rule_lists(result, detail));
                    }
                } else if let Some((host, address, port)) = &destination {
                    tested.extend(
                        layers
                            .outbound(host, *address, *port)
                            .map(|o| TestLayer::of(&o)),
                    );
                    if let Some(rule) = &rule {
                        let acl = crate::destination_acl::DestinationPolicy::parse_with_ports(
                            &rule.allow_destinations,
                            &rule.deny_destinations,
                            &rule.allow_destination_ports,
                            &rule.deny_destination_ports,
                        )
                        .map_err(bad)?;
                        let result = match address {
                            Some(address) => {
                                if acl
                                    .filter_sockets(host, [SocketAddr::new(*address, *port)])
                                    .is_empty()
                                {
                                    TestAnswer::Deny
                                } else {
                                    TestAnswer::Allow
                                }
                            }
                            None => match acl.decide_name(host, *port) {
                                Some(true) => TestAnswer::Allow,
                                Some(false) => TestAnswer::Deny,
                                None => TestAnswer::NeedsAddress,
                            },
                        };
                        let detail = (result == TestAnswer::Deny)
                            .then(|| "destination denied by rule policy".to_owned());
                        tested.push(rule_lists(result, detail));
                    }
                }
                // A tenant learns what a system set (or any set it cannot
                // see) decided, not which set or rule it was.
                if actor.role != Role::SystemAdmin {
                    for layer in &mut tested {
                        let Some(id) = &layer.set_id else { continue };
                        if load(&conn, id)?.is_some_and(|set| visible_to(actor, &set)) {
                            continue;
                        }
                        layer.set_id = None;
                        layer.set_name = None;
                        layer.rule_index = None;
                        layer.default_action = false;
                        layer.detail = Some("a rule set outside your tenant decides".into());
                    }
                }
                Ok(TestResult::new(direction, tested, Some(hash)))
            }
            _ => reject(400, "give either set_id or node_id"),
        }
    }
}
fn rule_lists(result: TestAnswer, detail: Option<String>) -> TestLayer {
    TestLayer {
        layer: "rule_lists".into(),
        set_id: None,
        set_name: None,
        rule_index: None,
        default_action: false,
        result,
        detail,
    }
}
