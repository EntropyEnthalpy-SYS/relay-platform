//! Endpoint groups (`endpoint_group:<id>`), saved chains
//! (`forwarding_chain:<id>`) and the forwardings built from them
//! (`chain_use:<entry rule id>`) in metadata, so the schema and recovery log
//! stay unchanged. Building a forwarding allocates endpoints and publishes
//! every server in one configuration batch inside the transaction that
//! records the use.
use super::shared_rules::node_name;
use super::*;
use crate::chain::{
    BuildInput, Chain, ChainApplied, ChainInput, ChainPlan, ChainRef, ChainUse, ChainView,
    EndpointGroup, GroupInput, GroupView, Hop, HopView, Layer, LayerChange, LayerView, MAX_LAYERS,
    MAX_MEMBERS, MemberView, PlannedHop, UseView,
};
use crate::node::{EndpointHop, EndpointRequest};
use crate::shared_rule::{LineError, LineErrors};
use crate::topology::{ConfigBatch, ConfigUpdate};
use serde::de::DeserializeOwned;
use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;

/// Every server of a forwarding is published in one batch.
const MAX_SERVERS: usize = 64;
const GROUP: &str = "endpoint_group:";
const CHAIN: &str = "forwarding_chain:";
const USE: &str = "chain_use:";

type Configs = BTreeMap<String, NodeConfig>;

/// Records under `prefix`, keyed by the rest of their metadata key.
fn load<T: DeserializeOwned>(conn: &Connection, prefix: &str) -> Result<Vec<(String, T)>> {
    let mut q =
        conn.prepare("SELECT key,value FROM metadata WHERE key GLOB ?1||'*' ORDER BY key")?;
    let rows: Vec<(String, String)> = q
        .query_map([prefix], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    rows.into_iter()
        .map(|(key, value)| {
            let record = serde_json::from_str(&value)
                .with_context(|| format!("invalid stored record {key}"))?;
            Ok((key[prefix.len()..].to_owned(), record))
        })
        .collect()
}
fn get<T: DeserializeOwned>(conn: &Connection, key: &str) -> Result<Option<T>> {
    let raw: Option<String> = conn
        .query_row("SELECT value FROM metadata WHERE key=?1", [key], |r| {
            r.get(0)
        })
        .optional()?;
    raw.map(|value| serde_json::from_str(&value).with_context(|| format!("invalid stored {key}")))
        .transpose()
}
fn put<T: Serialize>(tx: &Transaction<'_>, key: &str, record: &T) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, serde_json::to_string(record)?],
    )?;
    Ok(())
}
fn all_groups(conn: &Connection) -> Result<Vec<EndpointGroup>> {
    Ok(load(conn, GROUP)?.into_iter().map(|(_, g)| g).collect())
}
fn all_chains(conn: &Connection) -> Result<Vec<Chain>> {
    Ok(load(conn, CHAIN)?.into_iter().map(|(_, c)| c).collect())
}
fn writer(actor: &Actor, what: &str) -> Result<()> {
    if !actor.may_write() {
        return reject(403, format!("read-only role cannot change {what}"));
    }
    Ok(())
}
fn check_name(name: &str, what: &str) -> Result<()> {
    if name.trim().is_empty() || name.len() > 120 {
        return reject(400, format!("{what} name must contain 1..120 bytes"));
    }
    Ok(())
}
fn visible_group(conn: &Connection, actor: &Actor, id: &str) -> Result<EndpointGroup> {
    match get::<EndpointGroup>(conn, &format!("{GROUP}{id}"))? {
        Some(group) if actor.permits_tenant(&group.tenant_id) => Ok(group),
        _ => reject(404, "endpoint group not found"),
    }
}
fn visible_chain(conn: &Connection, actor: &Actor, id: &str) -> Result<Chain> {
    match get::<Chain>(conn, &format!("{CHAIN}{id}"))? {
        Some(chain) if actor.permits_tenant(&chain.tenant_id) => Ok(chain),
        _ => reject(404, "forwarding chain not found"),
    }
}
fn label(conn: &Connection, node: &str) -> Result<String> {
    Ok(node_name(conn, node)?.unwrap_or_else(|| node.to_owned()))
}
/// Checks a group's servers and returns their tenant.
fn check_members(conn: &Connection, actor: &Actor, members: &[String]) -> Result<String> {
    if members.is_empty() || members.len() > MAX_MEMBERS {
        return reject(
            400,
            format!("an endpoint group needs 1..{MAX_MEMBERS} servers"),
        );
    }
    let mut seen = HashSet::new();
    let mut tenant: Option<String> = None;
    for node in members {
        if !seen.insert(node.as_str()) {
            return reject(400, "each server can be in a group only once");
        }
        let next = require_node(conn, actor, node, true)?;
        if tenant.as_ref().is_some_and(|current| *current != next) {
            return reject(400, "all servers of a group must belong to the same tenant");
        }
        tenant = Some(next);
    }
    Ok(tenant.unwrap_or_default())
}
/// The first server found in two layers, with both layer numbers from 1.
fn overlap(layers: &[Vec<String>]) -> Option<(&str, usize, usize)> {
    let mut seen: BTreeMap<&str, usize> = BTreeMap::new();
    for (index, members) in layers.iter().enumerate() {
        for node in members {
            if let Some(first) = seen.insert(node, index + 1) {
                return Some((node.as_str(), first, index + 1));
            }
        }
    }
    None
}
/// Checks a chain's layers and returns its tenant, the tenant of its groups.
fn check_layers(conn: &Connection, actor: &Actor, layers: &[Layer]) -> Result<String> {
    if layers.is_empty() || layers.len() > MAX_LAYERS {
        return reject(400, format!("a chain needs 1..{MAX_LAYERS} layers"));
    }
    let mut seen = HashSet::new();
    let mut tenant: Option<String> = None;
    let mut members = Vec::with_capacity(layers.len());
    for layer in layers {
        if !seen.insert(layer.group_id.as_str()) {
            return reject(400, "an endpoint group can be only one layer of a chain");
        }
        let group = visible_group(conn, actor, &layer.group_id)?;
        if tenant
            .as_ref()
            .is_some_and(|current| *current != group.tenant_id)
        {
            return reject(400, "all groups of a chain must belong to the same tenant");
        }
        tenant = Some(group.tenant_id);
        members.push(group.members);
    }
    if let Some((node, first, second)) = overlap(&members) {
        return reject(
            400,
            format!(
                "server {} is in layer {first} and layer {second}; a server can be in only one layer of a chain",
                label(conn, node)?
            ),
        );
    }
    Ok(tenant.unwrap_or_default())
}
fn member_views(conn: &Connection, members: &[String]) -> Result<Vec<MemberView>> {
    members
        .iter()
        .map(|node| {
            let name = node_name(conn, node)?;
            Ok(MemberView {
                node_id: node.clone(),
                missing: name.is_none(),
                node_name: name,
            })
        })
        .collect()
}
fn group_view(conn: &Connection, chains: &[Chain], group: &EndpointGroup) -> Result<GroupView> {
    Ok(GroupView {
        id: group.id.clone(),
        tenant_id: group.tenant_id.clone(),
        name: group.name.clone(),
        description: group.description.clone(),
        members: member_views(conn, &group.members)?,
        used_by: chains
            .iter()
            .filter(|chain| chain.layers.iter().any(|layer| layer.group_id == group.id))
            .map(|chain| ChainRef {
                id: chain.id.clone(),
                name: chain.name.clone(),
            })
            .collect(),
        created_at_ms: group.created_at_ms,
        updated_at_ms: group.updated_at_ms,
    })
}
fn rule_of<'a>(configs: &'a Configs, node: &str, rule: &str) -> Option<&'a Rule> {
    configs.get(node)?.rules.iter().find(|r| r.id == rule)
}
/// Per layer, the group's servers now against the servers the forwarding
/// was built with; order changes are not changes.
fn changes(chain: &Chain, groups: &[EndpointGroup], record: &ChainUse) -> Vec<LayerChange> {
    (0..chain.layers.len().max(record.layers.len()))
        .filter_map(|index| {
            let current: Vec<&String> = chain
                .layers
                .get(index)
                .and_then(|layer| groups.iter().find(|g| g.id == layer.group_id))
                .map_or_else(Vec::new, |group| group.members.iter().collect());
            let built: Vec<&String> = record
                .layers
                .get(index)
                .map_or_else(Vec::new, |hops| hops.iter().map(|h| &h.node_id).collect());
            let added: Vec<String> = current
                .iter()
                .filter(|node| !built.contains(node))
                .map(|node| (*node).clone())
                .collect();
            let removed: Vec<String> = built
                .iter()
                .filter(|node| !current.contains(node))
                .map(|node| (*node).clone())
                .collect();
            (!added.is_empty() || !removed.is_empty()).then_some(LayerChange {
                layer: index + 1,
                added,
                removed,
            })
        })
        .collect()
}
fn use_view(
    conn: &Connection,
    configs: &Configs,
    groups: &[EndpointGroup],
    chain: &Chain,
    entry_rule_id: &str,
    record: &ChainUse,
) -> Result<UseView> {
    let entry = rule_of(configs, &record.entry_node_id, entry_rule_id);
    let mut layers = Vec::with_capacity(record.layers.len());
    for hops in &record.layers {
        let mut views = Vec::with_capacity(hops.len());
        for hop in hops {
            views.push(HopView {
                node_id: hop.node_id.clone(),
                rule_id: hop.rule_id.clone(),
                node_name: node_name(conn, &hop.node_id)?,
                missing: rule_of(configs, &hop.node_id, &hop.rule_id).is_none(),
            });
        }
        layers.push(views);
    }
    let changes = changes(chain, groups, record);
    Ok(UseView {
        entry_rule_id: entry_rule_id.to_owned(),
        entry_node_id: record.entry_node_id.clone(),
        entry_node_name: node_name(conn, &record.entry_node_id)?,
        name: entry.map(|rule| rule.name.clone()),
        missing: entry.is_none(),
        layers,
        out_of_date: !changes.is_empty(),
        changes,
    })
}
fn chain_view(
    conn: &Connection,
    configs: &Configs,
    groups: &[EndpointGroup],
    uses: &[(String, ChainUse)],
    chain: &Chain,
) -> Result<ChainView> {
    let mut layers = Vec::with_capacity(chain.layers.len());
    for layer in &chain.layers {
        let group = groups.iter().find(|g| g.id == layer.group_id);
        layers.push(LayerView {
            group_id: layer.group_id.clone(),
            group_name: group.map(|g| g.name.clone()),
            balance: layer.balance,
            members: member_views(conn, group.map_or(&[][..], |g| &g.members))?,
        });
    }
    let uses = uses
        .iter()
        .filter(|(_, record)| record.chain_id == chain.id)
        .map(|(rule, record)| use_view(conn, configs, groups, chain, rule, record))
        .collect::<Result<_>>()?;
    Ok(ChainView {
        id: chain.id.clone(),
        tenant_id: chain.tenant_id.clone(),
        name: chain.name.clone(),
        enabled: chain.enabled,
        layers,
        uses,
        created_at_ms: chain.created_at_ms,
        updated_at_ms: chain.updated_at_ms,
    })
}
fn view_of(conn: &Connection, chain: &Chain) -> Result<ChainView> {
    chain_view(
        conn,
        &topology::all_configs(conn)?,
        &all_groups(conn)?,
        &load(conn, USE)?,
        chain,
    )
}

/// A forwarding built from a chain, not yet published.
struct Built {
    entry_rule_id: String,
    hops: Vec<PlannedHop>,
    batch: ConfigBatch,
    record: ChainUse,
}
fn endpoint_error(error: &str, port: Option<u16>) -> (bool, String) {
    match error {
        "address_required" => (
            false,
            "this server has no forwarding address; set its connection defaults first".into(),
        ),
        "ports_exhausted" => (
            true,
            "no free port is left in this server's forwarding range".into(),
        ),
        "port_in_use" => (
            true,
            format!(
                "port {} is already used on this server",
                port.unwrap_or_default()
            ),
        ),
        other => (false, other.into()),
    }
}
/// The rules a forwarding from `chain` needs: each server of the last layer
/// targets `input.target`; each server of an earlier layer, and the entry,
/// targets every server of the next layer through `via`, chosen by the next
/// layer's balance. Endpoints come from endpoint allocation; nothing is
/// written.
fn build(conn: &Connection, actor: &Actor, chain: &Chain, input: &BuildInput) -> Result<Built> {
    if !chain.enabled {
        return reject(
            409,
            "this chain is disabled; enable it before building a forwarding from it",
        );
    }
    let name = input.name.trim();
    if name.is_empty() || name.len() > 100 {
        return reject(400, "forwarding name must contain 1..100 bytes");
    }
    validate_target(&input.target).map_err(|error| Rejection {
        status: 400,
        message: format!("invalid target: {error}"),
    })?;
    if input.entry_port == Some(0) {
        return reject(400, "entry port must be 1..65535");
    }
    if input.protocol != Protocol::Tcp
        && chain
            .layers
            .iter()
            .any(|layer| layer.balance == Balance::LowestLatency)
    {
        return reject(
            400,
            "lowest-latency layers are measured with a TCP connect probe; use protocol tcp or another balance mode",
        );
    }
    if require_node(conn, actor, &input.entry_node_id, true)? != chain.tenant_id {
        return reject(400, "the entry server must belong to the chain's tenant");
    }
    let groups = all_groups(conn)?;
    let mut layers: Vec<Vec<String>> = Vec::with_capacity(chain.layers.len());
    for (index, layer) in chain.layers.iter().enumerate() {
        let Some(group) = groups.iter().find(|g| g.id == layer.group_id) else {
            return reject(
                409,
                "a group of this chain no longer exists; edit the chain",
            );
        };
        for node in &group.members {
            if *node == input.entry_node_id {
                return reject(
                    400,
                    format!(
                        "the entry server is in layer {} (group {}); choose an entry outside the chain",
                        index + 1,
                        group.name
                    ),
                );
            }
            if node_name(conn, node)?.is_none() {
                return reject(
                    409,
                    format!(
                        "a server of group {} no longer exists; edit the group",
                        group.name
                    ),
                );
            }
        }
        layers.push(group.members.clone());
    }
    let servers = 1 + layers.iter().map(Vec::len).sum::<usize>();
    if servers > MAX_SERVERS {
        return reject(
            400,
            format!(
                "this forwarding would change {servers} servers; at most {MAX_SERVERS} can be published together"
            ),
        );
    }

    // Endpoints in path order: the entry, then each layer in group order.
    let mut request = EndpointRequest {
        hops: std::iter::once(&input.entry_node_id)
            .chain(layers.iter().flatten())
            .map(|node| EndpointHop {
                node_id: node.clone(),
                listen: None,
                advertise: None,
            })
            .collect(),
    };
    let mut allocation = endpoint_allocation::allocate(conn, actor, &request, MAX_SERVERS)?;
    if let Some(port) = input.entry_port {
        // The chosen port is a manual endpoint on the entry's own address.
        let Some(defaults) = allocation.endpoints[0].defaults.clone() else {
            return reject(
                400,
                "the entry server has no forwarding address; set its connection defaults first",
            );
        };
        let public = if (defaults.port_start..=defaults.port_end).contains(&port) {
            defaults.public_port(port)
        } else {
            port
        };
        request.hops[0].listen = Some(SocketAddr::new(defaults.bind_ip(), port));
        request.hops[0].advertise = Some(defaults.endpoint(public));
        allocation = endpoint_allocation::allocate(conn, actor, &request, MAX_SERVERS)?;
    }
    let mut problems = vec![];
    let mut conflict = false;
    for endpoint in &allocation.endpoints {
        if let Some(error) = &endpoint.error {
            let (busy, message) = endpoint_error(error, input.entry_port);
            conflict |= busy;
            problems.push((
                label(conn, &endpoint.node_id)?,
                endpoint.node_id.clone(),
                message,
            ));
        }
    }
    if !problems.is_empty() {
        let summary: Vec<String> = problems
            .iter()
            .map(|(server, _, message)| format!("{server}: {message}"))
            .collect();
        return Err(anyhow::Error::from(Rejection {
            status: if conflict { 409 } else { 400 },
            message: format!("cannot allocate endpoints: {}", summary.join("; ")),
        })
        .context(LineErrors(
            problems
                .into_iter()
                .map(|(_, node_id, error)| LineError { node_id, error })
                .collect(),
        )));
    }

    let owner = input.owner_id.clone().unwrap_or_else(|| actor.id.clone());
    let entry_rule_id = Uuid::new_v4().to_string();
    let ids: Vec<Vec<String>> = layers
        .iter()
        .map(|members| members.iter().map(|_| Uuid::new_v4().to_string()).collect())
        .collect();
    // Position of each layer's first server in the allocation.
    let starts: Vec<usize> = layers
        .iter()
        .scan(1, |next, members| {
            let start = *next;
            *next += members.len();
            Some(start)
        })
        .collect();
    let advertise = |layer: usize, member: usize| {
        allocation.endpoints[starts[layer] + member]
            .advertise
            .clone()
            .unwrap_or_default()
    };
    let next_hops = |layer: usize| -> Vec<serde_json::Value> {
        layers[layer]
            .iter()
            .enumerate()
            .map(|(member, node)| {
                serde_json::json!({
                    "address": advertise(layer, member),
                    "via": {"node_id": node, "rule_id": ids[layer][member]},
                    "weight": 1,
                })
            })
            .collect()
    };
    let mut hops = vec![];
    let mut updates = vec![];
    let mut add = |position: usize,
                   layer: usize,
                   rule_id: &str,
                   targets: Vec<serde_json::Value>,
                   balance: Balance|
     -> Result<()> {
        let endpoint = &allocation.endpoints[position];
        let config = &allocation.configs[position];
        let listen = endpoint
            .listen
            .context("allocated endpoint has no listener")?;
        let address = endpoint.advertise.clone().unwrap_or_default();
        let mut rule = serde_json::json!({
            "id": rule_id, "tenant_id": chain.tenant_id, "owner_id": owner,
            "name": format!("{name} · {}", layer + 1), "listen": listen, "advertise": address,
            "protocol": input.protocol, "targets": targets, "balance": balance, "enabled": true,
            "meter_epoch": Uuid::new_v4().to_string(),
            "quota_bytes": null, "expires_at_ms": null, "rate_bytes_per_sec": null,
        });
        if balance == Balance::LowestLatency {
            rule["health_check"] = serde_json::json!({"tcp": {"kind": "connect"}});
        }
        let rule: Rule = serde_json::from_value(rule)?;
        let mut rules = config.rules.clone();
        rules.push(rule);
        updates.push(ConfigUpdate {
            node_id: config.node_id.clone(),
            expected_revision: config.revision,
            rules,
            rate_bytes_per_sec: None,
        });
        hops.push(PlannedHop {
            layer,
            node_id: config.node_id.clone(),
            node_name: label(conn, &config.node_id)?,
            rule_id: rule_id.to_owned(),
            listen,
            advertise: address,
        });
        Ok(())
    };
    add(0, 0, &entry_rule_id, next_hops(0), chain.layers[0].balance)?;
    for (layer, rule_ids) in ids.iter().enumerate() {
        let (targets, balance) = match chain.layers.get(layer + 1) {
            Some(next) => (next_hops(layer + 1), next.balance),
            None => (
                vec![serde_json::json!({"address": input.target, "weight": 1})],
                Balance::default(),
            ),
        };
        for (member, rule_id) in rule_ids.iter().enumerate() {
            add(
                starts[layer] + member,
                layer + 1,
                rule_id,
                targets.clone(),
                balance,
            )?;
        }
    }
    if let Some(expected) = &input.expected_revisions {
        let stale: Vec<LineError> = updates
            .iter()
            .filter(|update| expected.get(&update.node_id) != Some(&update.expected_revision))
            .map(|update| LineError {
                node_id: update.node_id.clone(),
                error: "configuration changed since the plan".into(),
            })
            .collect();
        if !stale.is_empty() || expected.len() != updates.len() {
            return Err(anyhow::Error::from(Rejection {
                status: 409,
                message: "configuration changed since the plan; plan again".into(),
            })
            .context(LineErrors(stale)));
        }
    }
    Ok(Built {
        entry_rule_id,
        hops,
        batch: ConfigBatch { updates },
        record: ChainUse {
            chain_id: chain.id.clone(),
            entry_node_id: input.entry_node_id.clone(),
            layers: layers
                .iter()
                .zip(&ids)
                .map(|(members, ids)| {
                    members
                        .iter()
                        .zip(ids)
                        .map(|(node_id, rule_id)| Hop {
                            node_id: node_id.clone(),
                            rule_id: rule_id.clone(),
                        })
                        .collect()
                })
                .collect(),
        },
    })
}

impl Store {
    pub fn endpoint_groups(&self, actor: &Actor) -> Result<Vec<GroupView>> {
        let conn = self.0.lock().unwrap();
        let chains = all_chains(&conn)?;
        let mut groups = all_groups(&conn)?;
        groups.retain(|group| actor.permits_tenant(&group.tenant_id));
        groups.sort_by(|a, b| (&a.name, &a.id).cmp(&(&b.name, &b.id)));
        groups
            .iter()
            .map(|group| group_view(&conn, &chains, group))
            .collect()
    }
    pub fn create_endpoint_group(&self, actor: &Actor, input: GroupInput) -> Result<GroupView> {
        writer(actor, "endpoint groups")?;
        check_name(&input.name, "endpoint group")?;
        if input.description.len() > 2000 {
            return reject(400, "description must be at most 2000 bytes");
        }
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let tenant = check_members(&tx, actor, &input.members)?;
        let now = now_ms();
        let group = EndpointGroup {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant,
            name: input.name,
            description: input.description,
            members: input.members,
            created_at_ms: now,
            updated_at_ms: now,
        };
        put(&tx, &format!("{GROUP}{}", group.id), &group)?;
        audit(
            &tx,
            &actor.id,
            "endpoint_group.create",
            &group.id,
            &serde_json::json!({"name":group.name,"members":group.members}).to_string(),
        )?;
        tx.commit()?;
        group_view(&conn, &[], &group)
    }
    /// Changes a group's servers. Forwardings already built keep their rules
    /// and are reported out of date; a change that would put a server in two
    /// layers of a chain using the group is refused.
    pub fn update_endpoint_group(
        &self,
        actor: &Actor,
        id: &str,
        input: GroupInput,
    ) -> Result<GroupView> {
        writer(actor, "endpoint groups")?;
        check_name(&input.name, "endpoint group")?;
        if input.description.len() > 2000 {
            return reject(400, "description must be at most 2000 bytes");
        }
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut group = visible_group(&tx, actor, id)?;
        if check_members(&tx, actor, &input.members)? != group.tenant_id {
            return reject(
                400,
                "all servers of a group must belong to the group's tenant",
            );
        }
        let groups = all_groups(&tx)?;
        let chains = all_chains(&tx)?;
        for chain in chains
            .iter()
            .filter(|chain| chain.layers.iter().any(|layer| layer.group_id == group.id))
        {
            let layers: Vec<Vec<String>> = chain
                .layers
                .iter()
                .map(|layer| {
                    if layer.group_id == group.id {
                        input.members.clone()
                    } else {
                        groups
                            .iter()
                            .find(|g| g.id == layer.group_id)
                            .map(|g| g.members.clone())
                            .unwrap_or_default()
                    }
                })
                .collect();
            if let Some((node, first, second)) = overlap(&layers) {
                return reject(
                    409,
                    format!(
                        "server {} would be in layer {first} and layer {second} of chain {}",
                        label(&tx, node)?,
                        chain.name
                    ),
                );
            }
        }
        let detail = serde_json::json!({"name":input.name,"members":input.members,"previous_members":group.members}).to_string();
        group.name = input.name;
        group.description = input.description;
        group.members = input.members;
        group.updated_at_ms = now_ms();
        put(&tx, &format!("{GROUP}{}", group.id), &group)?;
        audit(&tx, &actor.id, "endpoint_group.update", &group.id, &detail)?;
        tx.commit()?;
        group_view(&conn, &chains, &group)
    }
    pub fn delete_endpoint_group(&self, actor: &Actor, id: &str) -> Result<()> {
        writer(actor, "endpoint groups")?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let group = visible_group(&tx, actor, id)?;
        if let Some(chain) = all_chains(&tx)?
            .into_iter()
            .find(|chain| chain.layers.iter().any(|layer| layer.group_id == group.id))
        {
            return reject(
                409,
                format!(
                    "chain {} uses this group; remove it from the chain first",
                    chain.name
                ),
            );
        }
        tx.execute(
            "DELETE FROM metadata WHERE key=?1",
            [format!("{GROUP}{id}")],
        )?;
        audit(
            &tx,
            &actor.id,
            "endpoint_group.delete",
            &group.id,
            &serde_json::json!({"name":group.name,"members":group.members}).to_string(),
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn chains(&self, actor: &Actor) -> Result<Vec<ChainView>> {
        let conn = self.0.lock().unwrap();
        let configs = topology::all_configs(&conn)?;
        let groups = all_groups(&conn)?;
        let uses = load(&conn, USE)?;
        let mut chains = all_chains(&conn)?;
        chains.retain(|chain| actor.permits_tenant(&chain.tenant_id));
        chains.sort_by(|a, b| (&a.name, &a.id).cmp(&(&b.name, &b.id)));
        chains
            .iter()
            .map(|chain| chain_view(&conn, &configs, &groups, &uses, chain))
            .collect()
    }
    pub fn create_chain(&self, actor: &Actor, input: ChainInput) -> Result<ChainView> {
        writer(actor, "forwarding chains")?;
        check_name(&input.name, "chain")?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let tenant = check_layers(&tx, actor, &input.layers)?;
        let now = now_ms();
        let chain = Chain {
            id: Uuid::new_v4().to_string(),
            tenant_id: tenant,
            name: input.name,
            enabled: input.enabled,
            layers: input.layers,
            created_at_ms: now,
            updated_at_ms: now,
        };
        put(&tx, &format!("{CHAIN}{}", chain.id), &chain)?;
        audit(
            &tx,
            &actor.id,
            "forwarding_chain.create",
            &chain.id,
            &serde_json::json!({"name":chain.name,"enabled":chain.enabled,"layers":chain.layers})
                .to_string(),
        )?;
        tx.commit()?;
        view_of(&conn, &chain)
    }
    /// Changes the chain's record only; forwardings built from it keep their
    /// rules. Uses whose entry rule is gone are forgotten.
    pub fn update_chain(&self, actor: &Actor, id: &str, input: ChainInput) -> Result<ChainView> {
        writer(actor, "forwarding chains")?;
        check_name(&input.name, "chain")?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut chain = visible_chain(&tx, actor, id)?;
        if check_layers(&tx, actor, &input.layers)? != chain.tenant_id {
            return reject(
                400,
                "all groups of a chain must belong to the chain's tenant",
            );
        }
        let configs = topology::all_configs(&tx)?;
        for (rule, record) in load::<ChainUse>(&tx, USE)? {
            if record.chain_id == chain.id
                && rule_of(&configs, &record.entry_node_id, &rule).is_none()
            {
                tx.execute(
                    "DELETE FROM metadata WHERE key=?1",
                    [format!("{USE}{rule}")],
                )?;
            }
        }
        chain.name = input.name;
        chain.enabled = input.enabled;
        chain.layers = input.layers;
        chain.updated_at_ms = now_ms();
        put(&tx, &format!("{CHAIN}{}", chain.id), &chain)?;
        audit(
            &tx,
            &actor.id,
            "forwarding_chain.update",
            &chain.id,
            &serde_json::json!({"name":chain.name,"enabled":chain.enabled,"layers":chain.layers})
                .to_string(),
        )?;
        tx.commit()?;
        view_of(&conn, &chain)
    }
    /// Deletes the chain and its record of uses; rules built from it stay.
    pub fn delete_chain(&self, actor: &Actor, id: &str) -> Result<()> {
        writer(actor, "forwarding chains")?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let chain = visible_chain(&tx, actor, id)?;
        let mut forgotten = 0;
        for (rule, record) in load::<ChainUse>(&tx, USE)? {
            if record.chain_id == chain.id {
                tx.execute(
                    "DELETE FROM metadata WHERE key=?1",
                    [format!("{USE}{rule}")],
                )?;
                forgotten += 1;
            }
        }
        tx.execute(
            "DELETE FROM metadata WHERE key=?1",
            [format!("{CHAIN}{id}")],
        )?;
        audit(
            &tx,
            &actor.id,
            "forwarding_chain.delete",
            &chain.id,
            &serde_json::json!({"name":chain.name,"uses":forgotten}).to_string(),
        )?;
        tx.commit()?;
        Ok(())
    }
    /// The batch a forwarding from the chain would publish, checked like a
    /// configuration preview; nothing is written or reserved.
    pub fn plan_chain(&self, actor: &Actor, id: &str, input: BuildInput) -> Result<ChainPlan> {
        writer(actor, "forwardings")?;
        let conn = self.0.lock().unwrap();
        let chain = visible_chain(&conn, actor, id)?;
        let built = build(&conn, actor, &chain, &input)?;
        let preview = topology::prepare(
            &conn,
            &mut self.3.lock().unwrap(),
            actor,
            built.batch.clone(),
        )?;
        Ok(ChainPlan {
            entry_rule_id: built.entry_rule_id,
            hops: built.hops,
            batch: built.batch,
            preview,
        })
    }
    /// Builds and publishes a forwarding from the chain in one batch and
    /// records the use, all in one transaction: every server changes or none.
    pub fn apply_chain(&self, actor: &Actor, id: &str, input: BuildInput) -> Result<ChainApplied> {
        writer(actor, "forwardings")?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let chain = visible_chain(&tx, actor, id)?;
        let built = build(&tx, actor, &chain, &input)?;
        let published = topology::publish_in(&tx, &mut self.3.lock().unwrap(), actor, built.batch)?;
        put(&tx, &format!("{USE}{}", built.entry_rule_id), &built.record)?;
        audit(
            &tx,
            &actor.id,
            "forwarding_chain.apply",
            &chain.id,
            &serde_json::json!({"name":input.name.trim(),"entry_node_id":input.entry_node_id,"entry_rule_id":built.entry_rule_id,"layers":built.record.layers}).to_string(),
        )?;
        tx.commit()?;
        self.2.config.notify_waiters();
        Ok(ChainApplied {
            entry_rule_id: built.entry_rule_id,
            hops: built.hops,
            published,
        })
    }
}
