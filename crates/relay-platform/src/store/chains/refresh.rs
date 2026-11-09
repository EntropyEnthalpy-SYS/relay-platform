//! Refreshing a forwarding built from a chain to its groups' current
//! members (see [`crate::chain::RefreshPhase`]): the preview, the
//! confirmation, each later step and automatic refresh. The state lives in
//! metadata (`chain_refresh:<entry rule id>` and the use record) and every
//! publish goes through `publish_in`, so the topology stop barrier, the
//! capability checks for older agents and the permission checks all apply.
use super::*;
use crate::chain::{
    AgentState, AutoSync, AutoSyncInput, CancelInput, MAX_REFRESH_TIMEOUT_SECS,
    MIN_REFRESH_TIMEOUT_SECS, NodeProblem, PausedTarget, REFRESH_TIMEOUT_SECS, Refresh,
    RefreshCommit, RefreshInput, RefreshOutcome, RefreshPhase, RefreshPlan, RefreshPlanInput,
    RefreshProblem, RefreshStep, RefreshView, Rewire, ServerChange, ServerState, Unresolved,
};
use crate::journal::LoggedConnection;
use crate::topology::{BatchResult, RuleChange};
use std::collections::BTreeSet;

pub(super) const REFRESH: &str = "chain_refresh:";
const ONLINE_MS: i64 = 90_000;
/// An automatic refresh that failed or could not start waits this long
/// before the next try, doubled each time; after `AUTO_MAX_FAILURES` in a
/// row automatic refresh turns itself off.
const AUTO_BACKOFF_MS: i64 = 5 * 60_000;
const AUTO_MAX_FAILURES: u32 = 3;
const SYSTEM: &str = "chain-refresh";
/// Agents get at least this long after a rewire to confirm it, even when it
/// was published just before the deadline.
const CONFIRM_GRACE_MS: i64 = 60_000;
/// A refused restore is tried again as soon as anything its checks read
/// changed (see [`retry_key`]), and otherwise at most this often.
const RESTORE_RETRY_MS: i64 = 30_000;

/// What reading a refresh needs besides the database.
pub(super) struct Live<'a> {
    pub clocks: &'a mut leases::LeaseClocks,
    pub telemetry: &'a crate::telemetry::Telemetry,
}

fn refresh_key(entry: &str) -> String {
    format!("{REFRESH}{entry}")
}
fn key(node: &str, rule: &str) -> String {
    format!("{node}/{rule}")
}
fn reference(node: &str, rule: &str) -> RuleRef {
    RuleRef {
        node_id: node.into(),
        rule_id: rule.into(),
    }
}
fn hop_ref(hop: &Hop) -> RuleRef {
    reference(&hop.node_id, &hop.rule_id)
}
fn problem(node: Option<&str>, rule: Option<&str>, message: impl Into<String>) -> RefreshProblem {
    RefreshProblem {
        node_id: node.map(str::to_owned),
        rule_id: rule.map(str::to_owned),
        message: message.into(),
    }
}
fn node_problem(node: &str, error: impl Into<String>) -> NodeProblem {
    NodeProblem {
        node_id: node.into(),
        error: error.into(),
    }
}
fn timeout_secs(value: Option<u64>) -> Result<u64> {
    let value = value.unwrap_or(REFRESH_TIMEOUT_SECS);
    if !(MIN_REFRESH_TIMEOUT_SECS..=MAX_REFRESH_TIMEOUT_SECS).contains(&value) {
        return reject(
            400,
            format!("timeout_secs must be {MIN_REFRESH_TIMEOUT_SECS}..{MAX_REFRESH_TIMEOUT_SECS}"),
        );
    }
    Ok(value)
}
fn message(error: &anyhow::Error) -> String {
    match error.downcast_ref::<Rejection>() {
        Some(rejection) => rejection.message.clone(),
        None => error.to_string(),
    }
}
fn lines(error: &anyhow::Error) -> Vec<NodeProblem> {
    error
        .downcast_ref::<LineErrors>()
        .map(|lines| {
            lines
                .0
                .iter()
                .map(|line| node_problem(&line.node_id, line.error.clone()))
                .collect()
        })
        .unwrap_or_default()
}
/// Settings a refresh cannot copy to a new server, because they belong to
/// one server or need settings on the next hop it does not make.
fn unsupported(rule: &Rule) -> Option<&'static str> {
    if rule.protocol_gateway.is_some() {
        Some("a managed protocol gateway")
    } else if rule.mptcp.is_some() {
        Some("MPTCP")
    } else if rule.inbound_multipath.is_some() || rule.outbound_multipath.is_some() {
        Some("multipath")
    } else if rule.outbound_bind.is_some() {
        Some("an outbound bind address")
    } else if rule.inbound_tls.is_some() {
        Some("TLS")
    } else if rule.inbound_proxy.is_some() {
        Some("the PROXY protocol")
    } else if rule.inbound_websocket.is_some() {
        Some("WebSocket")
    } else if rule.inbound_shadowsocks.is_some()
        || rule.inbound_socks5.is_some()
        || rule.inbound_http_connect.is_some()
        || rule.inbound_http2_connect.is_some()
    {
        Some("a proxy service")
    } else if rule.egress_proxy.is_some() {
        Some("an egress proxy")
    } else if rule.reverse_tunnel.is_some() {
        Some("a reverse tunnel")
    } else if rule.listen_end_port.is_some() || rule.port_mapping != PortMapping::Fixed {
        Some("a port range")
    } else {
        None
    }
}
fn unsupported_target(target: &Target) -> Option<&'static str> {
    if target.tls.is_some() {
        Some("TLS")
    } else if target.websocket.is_some() {
        Some("WebSocket")
    } else if target.proxy_protocol.is_some() {
        Some("the PROXY protocol")
    } else if target.prewarm.is_some() {
        Some("pre-warmed connections")
    } else {
        None
    }
}
/// A next hop like `template`, towards `address` through `via`.
fn next_hop(template: &Target, address: String, via: RuleRef) -> Target {
    Target {
        address,
        via: Some(via),
        draining: false,
        paused: false,
        paused_until_ms: None,
        ..template.clone()
    }
}

struct NodeRow {
    enrolled: bool,
    desired: u64,
    applied: u64,
    error: Option<String>,
    last_seen: Option<i64>,
    stats: String,
}
fn node_row(conn: &Connection, node: &str) -> Result<Option<NodeRow>> {
    Ok(conn
        .query_row(
            "SELECT token_hash IS NOT NULL,desired_revision,applied_revision,apply_error,last_seen_ms,stats_json FROM nodes WHERE id=?1",
            [node],
            |r| {
                Ok(NodeRow {
                    enrolled: r.get(0)?,
                    desired: r.get(1)?,
                    applied: r.get(2)?,
                    error: r.get(3)?,
                    last_seen: r.get(4)?,
                    stats: r.get(5)?,
                })
            },
        )
        .optional()?)
}
/// A server now: `idle` is the stop barrier's own test.
fn server_state(conn: &Connection, live: &mut Live<'_>, node: &str) -> Result<ServerState> {
    let name = node_name(conn, node)?;
    let Some(row) = node_row(conn, node)? else {
        return Ok(ServerState {
            node_id: node.into(),
            node_name: None,
            enrolled: false,
            online: false,
            last_seen_ms: None,
            desired_revision: 0,
            applied_revision: 0,
            apply_error: Some("the server was deleted".into()),
            active_tcp: 0,
            active_udp: 0,
            active_probes: 0,
            idle: true,
        });
    };
    let (seen, stats) = live
        .telemetry
        .current(node, row.last_seen, row.stats.clone());
    let stats: EngineStats = serde_json::from_str(&stats).unwrap_or_default();
    Ok(ServerState {
        node_id: node.into(),
        node_name: name,
        enrolled: row.enrolled,
        online: seen.is_some_and(|seen| now_ms().saturating_sub(seen) <= ONLINE_MS),
        last_seen_ms: seen,
        desired_revision: row.desired,
        applied_revision: row.applied,
        apply_error: row.error,
        active_tcp: stats.active_tcp,
        active_udp: stats.active_udp,
        active_probes: stats.active_probes,
        idle: topology::quiescent(conn, live.clocks, node)?,
    })
}
/// How far `node` is with `revision`: `applied`, `pending`, `failed` (with
/// its error), `not_enrolled` or `deleted`.
fn apply_state(
    conn: &Connection,
    node: &str,
    revision: u64,
) -> Result<(&'static str, Option<String>)> {
    Ok(match node_row(conn, node)? {
        None => ("deleted", None),
        Some(row) if !row.enrolled => ("not_enrolled", None),
        Some(row) if row.applied >= revision => ("applied", None),
        Some(row) if row.error.is_some() => ("failed", row.error),
        Some(_) => ("pending", None),
    })
}
fn busy(state: &ServerState) -> String {
    if !state.online && state.enrolled {
        "offline".into()
    } else if state.applied_revision != state.desired_revision {
        format!(
            "has not applied revision {} yet (applied {})",
            state.desired_revision, state.applied_revision
        )
    } else if let Some(error) = &state.apply_error {
        format!("reports an apply error: {error}")
    } else {
        format!(
            "{} TCP and {} UDP sessions, {} probes on its rules",
            state.active_tcp, state.active_udp, state.active_probes
        )
    }
}

/// Everything a refresh would do, planned from the current state.
#[derive(Default)]
struct Planned {
    up_to_date: bool,
    token: String,
    revisions: BTreeMap<String, u64>,
    changes: Vec<LayerChange>,
    conflicts: Vec<RefreshProblem>,
    warnings: Vec<RefreshProblem>,
    notes: Vec<String>,
    layers: Vec<Vec<Hop>>,
    hops: Vec<PlannedHop>,
    added: Vec<RuleRef>,
    add_batch: Option<ConfigBatch>,
    rewired: Vec<Rewire>,
    stopped: Vec<RuleRef>,
    quiet: Vec<String>,
    /// Servers of `quiet` that also carry enabled rules of other
    /// forwardings: a warning when confirmed, a conflict for automatic runs.
    shared: Vec<RefreshProblem>,
    /// Servers that would pause or get a new rule whose agent connected but
    /// has not reported it can take paused targets (see
    /// [`pause_unsupported`]): the preview and the confirmation are refused,
    /// an automatic run fails.
    too_old: Vec<RefreshProblem>,
    /// Such servers that never connected: refused the same way, but an
    /// automatic run waits for them instead of failing.
    unseen: Vec<RefreshProblem>,
    removed: Vec<RuleRef>,
    result: Vec<ServerChange>,
    preview: Option<BatchResult>,
}
/// Why `node`'s agent cannot be trusted to pause targets, if it cannot.
/// Agents older than 0.142.0 reject a configuration with paused targets, and
/// no agent reports its version or that ability. The conservative stand-in
/// is the reverse tunnel ability the controller records in
/// `reverse_tunnel_node:<id>` (see `store::reverse_tunnels`): every agent
/// since 0.145.0 reports it on each sync, whatever its host, so 0.142.0 to
/// 0.144.x count as too old too. Like other abilities it is written once,
/// so a later downgrade is not seen. `role` says what the refresh does on
/// the server; the result says whether it ever connected, and why not.
fn pause_unsupported(conn: &Connection, node: &str, role: &str) -> Result<Option<(bool, String)>> {
    let reported: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM metadata WHERE key='reverse_tunnel_node:'||?1)",
        [node],
        |r| r.get(0),
    )?;
    if reported {
        return Ok(None);
    }
    let server = label(conn, node)?;
    Ok(Some(
        match node_row(conn, node)?.and_then(|row| row.last_seen) {
            None => (
                false,
                format!(
                    "a refresh {role} server {server}, which has not connected to the panel yet; its agent (0.145.0 or later) must report in first"
                ),
            ),
            Some(_) => (
                true,
                format!(
                    "a refresh {role} server {server}, whose agent has not reported it can take paused targets: it is too old (upgrade the agent to 0.145.0 or later) or connected moments ago (wait for its next sync); then preview again"
                ),
            ),
        },
    ))
}
/// Refuses (409) a refresh with servers in [`Planned::too_old`] or
/// [`Planned::unseen`], naming each.
fn refuse_too_old(planned: &Planned) -> Result<()> {
    let gated: Vec<&RefreshProblem> = planned.too_old.iter().chain(&planned.unseen).collect();
    if gated.is_empty() {
        return Ok(());
    }
    let lines: Vec<LineError> = gated
        .iter()
        .filter_map(|c| {
            c.node_id.as_ref().map(|node| LineError {
                node_id: node.clone(),
                error: c.message.clone(),
            })
        })
        .collect();
    Err(anyhow::Error::from(Rejection {
        status: 409,
        message: format!(
            "this forwarding cannot be refreshed until these agents report they can take paused targets: {}",
            gated
                .iter()
                .map(|c| c.message.clone())
                .collect::<Vec<_>>()
                .join("; ")
        ),
    })
    .context(LineErrors(lines)))
}
/// Covers everything a preview depends on, including the last refresh, so
/// only a repeated confirmation of the same preview matches a refresh that
/// already started.
fn token(
    chain: &Chain,
    members: &[Vec<String>],
    entry: &str,
    record: &ChainUse,
    revisions: &BTreeMap<String, u64>,
    last: Option<&str>,
) -> String {
    let value = serde_json::json!({"layers": chain.layers, "members": members, "entry": entry,
        "use": record.layers, "revisions": revisions, "last_refresh": last});
    format!("{:x}", Sha256::digest(value.to_string()))
}
/// The targets of every rule of `stopped` paused until `until`, and which
/// ones that pauses.
fn pause_updates(
    configs: &Configs,
    stopped: &[RuleRef],
    until: i64,
) -> (Vec<ConfigUpdate>, Vec<PausedTarget>) {
    let mut paused = vec![];
    let updates = edit(configs, |node, rule| {
        if !stopped.contains(&reference(node, &rule.id)) {
            return false;
        }
        let mut changed = false;
        for target in rule.targets.iter_mut().filter(|t| !t.paused) {
            target.paused = true;
            target.paused_until_ms = Some(until);
            paused.push(PausedTarget {
                node_id: node.into(),
                rule_id: rule.id.clone(),
                address: target.address.clone(),
                via: target.via.clone(),
            });
            changed = true;
        }
        changed
    });
    (updates, paused)
}
/// One update per server where `change` changed some rule.
fn edit(configs: &Configs, mut change: impl FnMut(&str, &mut Rule) -> bool) -> Vec<ConfigUpdate> {
    let mut updates = vec![];
    for config in configs.values() {
        let mut rules = config.rules.clone();
        let mut changed = false;
        for rule in &mut rules {
            changed |= change(&config.node_id, rule);
        }
        if changed {
            updates.push(ConfigUpdate {
                node_id: config.node_id.clone(),
                expected_revision: config.revision,
                rules,
                rate_bytes_per_sec: None,
                rate_limits: None,
            });
        }
    }
    updates
}
/// Resumes the targets `op` paused, found again in `rule`.
fn resume(op: &Refresh, node: &str, rule: &mut Rule) -> bool {
    let mut changed = false;
    for target in &mut rule.targets {
        let ours = op.paused.iter().any(|p| {
            p.node_id == node
                && p.rule_id == rule.id
                && p.address == target.address
                && p.via == target.via
        });
        if ours && target.paused {
            target.paused = false;
            target.paused_until_ms = None;
            changed = true;
        }
    }
    changed
}

/// Plans a refresh of the use `record` (entry rule `entry`) of `chain`.
/// Nothing is written; `until` is when its pause would end.
fn plan(
    conn: &Connection,
    clocks: &mut leases::LeaseClocks,
    actor: &Actor,
    chain: &Chain,
    entry: &str,
    record: &ChainUse,
    until: i64,
) -> Result<Planned> {
    let configs = topology::all_configs(conn)?;
    let groups = all_groups(conn)?;
    let mut p = Planned {
        changes: changes(chain, &groups, record),
        ..Default::default()
    };
    if !chain.enabled {
        p.conflicts.push(problem(
            None,
            None,
            "the chain is disabled; enable it to refresh forwardings built from it",
        ));
    }
    let entry_node = record.entry_node_id.as_str();
    let mut involved: BTreeSet<String> = std::iter::once(entry_node.to_owned())
        .chain(
            record
                .layers
                .iter()
                .flatten()
                .map(|hop| hop.node_id.clone()),
        )
        .collect();
    if chain.layers.len() != record.layers.len() {
        p.conflicts.push(problem(
            None,
            None,
            format!(
                "the chain now has {} layers and this forwarding {}; a refresh changes the servers of its layers, not their number. Build a new forwarding from the chain instead",
                chain.layers.len(),
                record.layers.len()
            ),
        ));
    }
    let mut current: Vec<Vec<String>> = vec![];
    for (index, layer) in chain.layers.iter().enumerate() {
        let Some(group) = groups.iter().find(|g| g.id == layer.group_id) else {
            p.conflicts.push(problem(
                None,
                None,
                format!(
                    "the group of layer {} no longer exists; edit the chain",
                    index + 1
                ),
            ));
            current.push(vec![]);
            continue;
        };
        for node in &group.members {
            if node_name(conn, node)?.is_none() {
                p.conflicts.push(problem(
                    Some(node),
                    None,
                    format!(
                        "a server of group {} no longer exists; edit the group",
                        group.name
                    ),
                ));
            } else if node == entry_node {
                p.conflicts.push(problem(
                    Some(node),
                    None,
                    format!(
                        "the entry server is now in layer {} (group {}); a server cannot be the entry and a layer",
                        index + 1,
                        group.name
                    ),
                ));
            }
            involved.insert(node.clone());
        }
        current.push(group.members.clone());
    }
    let entry_rule = rule_of(&configs, entry_node, entry).cloned();
    if entry_rule.is_none() {
        p.conflicts.push(problem(
            Some(entry_node),
            Some(entry),
            "the entry rule of this forwarding no longer exists",
        ));
    }
    for node in &involved {
        if let Some(config) = configs.get(node) {
            p.revisions.insert(node.clone(), config.revision);
        }
    }
    let last = self::current(conn, entry)?.map(|op| op.id);
    p.token = token(
        chain,
        &current,
        entry,
        record,
        &p.revisions,
        last.as_deref(),
    );
    p.up_to_date = p.changes.is_empty();
    if p.up_to_date || !p.conflicts.is_empty() {
        return Ok(p);
    }
    let entry_rule = entry_rule.unwrap();
    let old = &record.layers;
    let n = old.len();
    let rule = |hop: &Hop| rule_of(&configs, &hop.node_id, &hop.rule_id);
    let kept: Vec<Vec<&Hop>> = old
        .iter()
        .zip(&current)
        .map(|(hops, members)| {
            hops.iter()
                .filter(|h| members.contains(&h.node_id))
                .collect()
        })
        .collect();
    let removed: Vec<Vec<&Hop>> = old
        .iter()
        .zip(&current)
        .map(|(hops, members)| {
            hops.iter()
                .filter(|h| !members.contains(&h.node_id))
                .collect()
        })
        .collect();
    let fresh: Vec<Vec<String>> = current
        .iter()
        .zip(old)
        .map(|(members, hops)| {
            members
                .iter()
                .filter(|m| !hops.iter().any(|h| &h.node_id == *m))
                .cloned()
                .collect()
        })
        .collect();
    let changed: Vec<bool> = (0..n)
        .map(|i| !fresh[i].is_empty() || !removed[i].is_empty())
        .collect();
    // Layers count from 1; the entry is layer 0. Every rule above the
    // deepest changed layer stops: those whose next hops change, and
    // everything that routes to them.
    let deepest = changed.iter().rposition(|c| *c).unwrap() + 1;
    let conflict = |p: &mut Planned, node: &str, rule: Option<&str>, message: String| {
        p.conflicts.push(problem(Some(node), rule, message));
    };

    if !entry_rule.enabled {
        conflict(
            &mut p,
            entry_node,
            Some(entry),
            format!(
                "the entry rule {} is disabled; a refresh updates only a forwarding whose rules are all enabled",
                entry_rule.name
            ),
        );
    }
    for (index, hops) in kept.iter().enumerate() {
        for hop in hops {
            let server = label(conn, &hop.node_id)?;
            match rule(hop) {
                None => conflict(
                    &mut p,
                    &hop.node_id,
                    Some(&hop.rule_id),
                    format!(
                        "the rule of {server} in layer {} was deleted outside the chain; remove the server from the group or build a new forwarding",
                        index + 1
                    ),
                ),
                Some(found) if !found.enabled => conflict(
                    &mut p,
                    &hop.node_id,
                    Some(&hop.rule_id),
                    format!(
                        "rule {} on {server} is disabled; a refresh updates only a forwarding whose rules are all enabled",
                        found.name
                    ),
                ),
                _ => {}
            }
        }
    }
    // Rules whose next hops change keep every other target; they must still
    // route to each server that stays in the next layer.
    let mut pending: Vec<(String, Rule, Target, usize)> = vec![];
    for (layer, rules) in (0..n).filter(|layer| changed[*layer]).map(|layer| {
        let rules: Vec<(String, &Rule)> = if layer == 0 {
            vec![(entry_node.to_owned(), &entry_rule)]
        } else {
            kept[layer - 1]
                .iter()
                .filter_map(|hop| rule(hop).map(|r| (hop.node_id.clone(), r)))
                .collect()
        };
        (layer, rules)
    }) {
        let next: BTreeSet<RuleRef> = old[layer].iter().map(hop_ref).collect();
        let gone: BTreeSet<RuleRef> = removed[layer].iter().map(|h| hop_ref(h)).collect();
        for (node, found) in rules {
            let server = label(conn, &node)?;
            let hops: Vec<&Target> = found
                .targets
                .iter()
                .filter(|t| t.via.as_ref().is_some_and(|via| next.contains(via)))
                .collect();
            for hop in &kept[layer] {
                if rule(hop).is_some()
                    && !hops.iter().any(|t| t.via.as_ref() == Some(&hop_ref(hop)))
                {
                    conflict(
                        &mut p,
                        &node,
                        Some(&found.id),
                        format!(
                            "rule {} on {server} no longer routes to {} although that server is still in layer {}; it was changed outside the chain",
                            found.name,
                            label(conn, &hop.node_id)?,
                            layer + 1
                        ),
                    );
                }
            }
            let template = hops
                .iter()
                .find(|t| t.via.as_ref().is_some_and(|via| !gone.contains(via)))
                .or(hops.first());
            let Some(template) = template else {
                conflict(
                    &mut p,
                    &node,
                    Some(&found.id),
                    format!(
                        "rule {} on {server} has no next hop in layer {} any more; it was changed outside the chain",
                        found.name,
                        layer + 1
                    ),
                );
                continue;
            };
            if let Some(feature) = unsupported_target(template) {
                conflict(
                    &mut p,
                    &node,
                    Some(&found.id),
                    format!(
                        "rule {} on {server} reaches layer {} with {feature}; a refresh adds only plain next hops",
                        found.name,
                        layer + 1
                    ),
                );
            }
            pending.push((node, found.clone(), (*template).clone(), layer));
        }
    }
    // New servers copy every setting of a remaining rule of their layer.
    let mut references: BTreeMap<usize, (String, Rule)> = BTreeMap::new();
    for layer in (0..n).filter(|layer| !fresh[*layer].is_empty()) {
        let Some((hop, found)) = kept[layer]
            .iter()
            .chain(&removed[layer])
            .find_map(|hop| rule(hop).map(|r| (*hop, r)))
        else {
            p.conflicts.push(problem(
                None,
                None,
                format!(
                    "layer {} has no rule left to copy the new servers' settings from; build a new forwarding",
                    layer + 1
                ),
            ));
            continue;
        };
        let server = label(conn, &hop.node_id)?;
        if let Some(feature) = unsupported(found) {
            conflict(
                &mut p,
                &hop.node_id,
                Some(&found.id),
                format!(
                    "rule {} on {server} in layer {} uses {feature}, which a refresh does not copy to new servers",
                    found.name,
                    layer + 1
                ),
            );
        }
        if let Some(feature) = found.targets.iter().find_map(unsupported_target) {
            conflict(
                &mut p,
                &hop.node_id,
                Some(&found.id),
                format!(
                    "rule {} on {server} in layer {} reaches its targets with {feature}; a refresh adds only plain next hops",
                    found.name,
                    layer + 1
                ),
            );
        }
        if layer + 1 < n {
            for hop in &kept[layer + 1] {
                if let Some(next) = rule(hop).filter(|r| r.advertise.is_none()) {
                    conflict(
                        &mut p,
                        &hop.node_id,
                        Some(&next.id),
                        format!(
                            "rule {} on {} in layer {} has no advertised endpoint, so the new servers of layer {} cannot route to it; give it one or build a new forwarding",
                            next.name,
                            label(conn, &hop.node_id)?,
                            layer + 2,
                            layer + 1
                        ),
                    );
                }
            }
            let next: BTreeSet<RuleRef> = old[layer + 1].iter().map(hop_ref).collect();
            if !found
                .targets
                .iter()
                .any(|t| t.via.as_ref().is_some_and(|via| next.contains(via)))
            {
                conflict(
                    &mut p,
                    &hop.node_id,
                    Some(&found.id),
                    format!(
                        "rule {} on {server} has no next hop in layer {} any more; it was changed outside the chain",
                        found.name,
                        layer + 2
                    ),
                );
            }
        }
        p.notes.push(format!(
            "new servers in layer {} ({}) copy the settings of rule {} on {server}: source and destination lists, firewall rule set, quota, expiry, limits, timeouts and balance; each gets its own meter",
            layer + 1,
            fresh[layer]
                .iter()
                .map(|node| label(conn, node))
                .collect::<Result<Vec<_>>>()?
                .join(", "),
            found.name
        ));
        references.insert(layer, (hop.node_id.clone(), found.clone()));
    }

    // P (`stopped`): the entry and every kept rule above the deepest changed
    // layer. Only those of R (`pending`) get new next hops, but an enabled
    // rule may not route to a disabled one, so all of P is paused, then
    // stopped together, and enabled again by the rewire: every server of P
    // (`quiet`) must have no sessions for that. Rules of removed servers
    // that route into P stop with it and are not enabled again; rules added
    // on new servers never stop.
    p.stopped.push(reference(entry_node, entry));
    for hops in &kept[..deepest - 1] {
        p.stopped.extend(
            hops.iter()
                .filter(|h| rule(h).is_some())
                .map(|h| hop_ref(h)),
        );
    }
    let quiet: BTreeSet<String> = p.stopped.iter().map(|r| r.node_id.clone()).collect();
    p.quiet = quiet.into_iter().collect();
    // The entry and P pause and stop, new servers get rules the refresh
    // waits for: their agents must be able to take paused targets. Removed
    // servers are not checked or waited for; an old one keeps its last
    // configuration.
    let mut gated: BTreeMap<String, &str> = p
        .quiet
        .iter()
        .map(|n| (n.clone(), "pauses targets on"))
        .collect();
    for node in fresh.iter().flatten() {
        gated.entry(node.clone()).or_insert("adds rules to");
    }
    for (node, role) in gated {
        match pause_unsupported(conn, &node, role)? {
            Some((true, reason)) => p.too_old.push(problem(Some(&node), None, reason)),
            Some((false, reason)) => p.unseen.push(problem(Some(&node), None, reason)),
            None => {}
        }
    }
    for hops in &removed[..deepest.saturating_sub(2)] {
        p.stopped.extend(
            hops.iter()
                .filter(|h| rule(h).is_some())
                .map(|h| hop_ref(h)),
        );
    }
    p.removed = removed
        .iter()
        .flatten()
        .filter(|h| rule(h).is_some())
        .map(|h| hop_ref(h))
        .collect();
    // Rules outside this forwarding must not route into what stops.
    let ours: BTreeSet<RuleRef> = std::iter::once(reference(entry_node, entry))
        .chain(old.iter().flatten().map(hop_ref))
        .collect();
    // M3: other forwardings' sessions on a server of R hold the refresh up
    // until its deadline, as the whole server must be idle.
    for node in &p.quiet {
        let others: Vec<&str> = configs
            .get(node)
            .map(|config| {
                config
                    .rules
                    .iter()
                    .filter(|r| r.enabled && !ours.contains(&reference(node, &r.id)))
                    .map(|r| r.name.as_str())
                    .collect()
            })
            .unwrap_or_default();
        if !others.is_empty() {
            p.shared.push(problem(
                Some(node),
                None,
                format!(
                    "{} also carries {} enabled rule(s) of other forwardings ({}); the refresh needs the whole server without sessions, so their sessions can hold it up until its deadline",
                    label(conn, node)?,
                    others.len(),
                    others.join(", ")
                ),
            ));
        }
    }
    let stopping: BTreeSet<RuleRef> = p.stopped.iter().chain(&p.removed).cloned().collect();
    for config in configs.values() {
        for other in config.rules.iter().filter(|r| r.enabled) {
            if ours.contains(&reference(&config.node_id, &other.id)) {
                continue;
            }
            if let Some(via) = other
                .targets
                .iter()
                .filter_map(|t| t.via.as_ref())
                .find(|via| stopping.contains(via))
            {
                let server = label(conn, &config.node_id)?;
                conflict(
                    &mut p,
                    &config.node_id,
                    Some(&other.id),
                    format!(
                        "rule {} on {server} is not part of this forwarding but routes to its rule on {}; a refresh would have to stop it",
                        other.name,
                        label(conn, &via.node_id)?
                    ),
                );
            }
        }
    }
    let servers: BTreeSet<&String> = p
        .quiet
        .iter()
        .chain(p.stopped.iter().map(|r| &r.node_id))
        .chain(fresh.iter().flatten())
        .chain(p.removed.iter().map(|r| &r.node_id))
        .collect();
    if servers.len() > MAX_SERVERS {
        p.conflicts.push(problem(
            None,
            None,
            format!(
                "this refresh would change {} servers; at most {MAX_SERVERS} can be published together",
                servers.len()
            ),
        ));
    }
    if !p.conflicts.is_empty() {
        return Ok(p);
    }

    // Endpoints for new servers, in layer order.
    let fresh_hops: Vec<(usize, &String)> = fresh
        .iter()
        .enumerate()
        .flat_map(|(layer, nodes)| nodes.iter().map(move |node| (layer, node)))
        .collect();
    let mut advertised: BTreeMap<RuleRef, String> = BTreeMap::new();
    for hop in old.iter().flatten() {
        if let Some(address) = rule(hop).and_then(|r| r.advertise.clone()) {
            advertised.insert(hop_ref(hop), address);
        }
    }
    let mut fresh_ids: BTreeMap<String, String> = BTreeMap::new();
    let mut allocation = None;
    if !fresh_hops.is_empty() {
        let request = EndpointRequest {
            hops: fresh_hops
                .iter()
                .map(|(_, node)| EndpointHop {
                    node_id: (*node).clone(),
                    listen: None,
                    advertise: None,
                })
                .collect(),
        };
        let result = match endpoint_allocation::allocate(conn, actor, &request, MAX_SERVERS) {
            Ok(result) => result,
            Err(error) if error.downcast_ref::<Rejection>().is_some() => {
                p.conflicts.push(problem(None, None, message(&error)));
                return Ok(p);
            }
            Err(error) => return Err(error),
        };
        for endpoint in &result.endpoints {
            if let Some(error) = &endpoint.error {
                let server = label(conn, &endpoint.node_id)?;
                p.conflicts.push(problem(
                    Some(&endpoint.node_id),
                    None,
                    format!("{server}: {}", endpoint_error(error, None).1),
                ));
            }
        }
        if !p.conflicts.is_empty() {
            return Ok(p);
        }
        for endpoint in &result.endpoints {
            let id = Uuid::new_v4().to_string();
            advertised.insert(
                reference(&endpoint.node_id, &id),
                endpoint.advertise.clone().unwrap_or_default(),
            );
            fresh_ids.insert(endpoint.node_id.clone(), id);
        }
        allocation = Some(result);
    }
    p.layers = current
        .iter()
        .zip(old)
        .map(|(members, hops)| {
            members
                .iter()
                .map(|node| Hop {
                    node_id: node.clone(),
                    rule_id: hops
                        .iter()
                        .find(|h| &h.node_id == node)
                        .map(|h| h.rule_id.clone())
                        .unwrap_or_else(|| fresh_ids[node].clone()),
                })
                .collect()
        })
        .collect();
    let added_hops = |layer: usize, template: &Target| -> Vec<Target> {
        p.layers[layer]
            .iter()
            .filter(|hop| fresh[layer].contains(&hop.node_id))
            .filter_map(|hop| {
                advertised
                    .get(&hop_ref(hop))
                    .map(|address| next_hop(template, address.clone(), hop_ref(hop)))
            })
            .collect()
    };
    // Rules that stay get the next hops of new servers after their own.
    let mut rewired = vec![];
    for (node, found, template, layer) in &pending {
        let gone: BTreeSet<RuleRef> = removed[*layer].iter().map(|h| hop_ref(h)).collect();
        let mut targets: Vec<Target> = found
            .targets
            .iter()
            .filter(|t| t.via.as_ref().is_none_or(|via| !gone.contains(via)))
            .cloned()
            .collect();
        targets.extend(added_hops(*layer, template));
        rewired.push(Rewire {
            node_id: node.clone(),
            rule_id: found.id.clone(),
            targets,
        });
    }
    p.rewired = rewired;
    let mut updates = vec![];
    if let Some(allocation) = &allocation {
        for (index, (layer, node)) in fresh_hops.iter().enumerate() {
            let (_, base) = &references[layer];
            let endpoint = &allocation.endpoints[index];
            let mut new = base.clone();
            new.id = fresh_ids[*node].clone();
            new.listen = endpoint
                .listen
                .context("allocated endpoint has no listener")?;
            new.advertise = endpoint.advertise.clone();
            new.meter_epoch = Uuid::new_v4().to_string();
            new.budget_ids.clear();
            new.enabled = true;
            if layer + 1 < n {
                let next: BTreeSet<RuleRef> = old[layer + 1].iter().map(hop_ref).collect();
                let template = base
                    .targets
                    .iter()
                    .find(|t| t.via.as_ref().is_some_and(|via| next.contains(via)))
                    .context("reference rule has no next hop")?
                    .clone();
                let mut targets: Vec<Target> = base
                    .targets
                    .iter()
                    .filter(|t| t.via.as_ref().is_none_or(|via| !next.contains(via)))
                    .cloned()
                    .collect();
                for hop in &p.layers[layer + 1] {
                    let Some(address) = advertised.get(&hop_ref(hop)) else {
                        p.conflicts.push(problem(
                            Some(&hop.node_id),
                            Some(&hop.rule_id),
                            format!(
                                "{} in layer {} has no advertised endpoint for the new servers to route to",
                                label(conn, &hop.node_id)?,
                                layer + 2
                            ),
                        ));
                        continue;
                    };
                    targets.push(next_hop(&template, address.clone(), hop_ref(hop)));
                }
                new.targets = targets;
            }
            let config = &allocation.configs[index];
            let mut rules = config.rules.clone();
            rules.push(new.clone());
            updates.push(ConfigUpdate {
                node_id: (*node).clone(),
                expected_revision: config.revision,
                rules,
                rate_bytes_per_sec: None,
                rate_limits: None,
            });
            p.hops.push(PlannedHop {
                layer: layer + 1,
                node_id: (*node).clone(),
                node_name: label(conn, node)?,
                rule_id: new.id.clone(),
                listen: new.listen,
                advertise: new.advertise.clone().unwrap_or_default(),
            });
            p.added.push(reference(node, &new.id));
        }
        p.add_batch = Some(ConfigBatch { updates });
    }
    if !p.conflicts.is_empty() {
        return Ok(p);
    }

    // Warnings: what the refresh leaves for the operator to check.
    for layer in (0..n).filter(|layer| changed[*layer]) {
        if layer + 1 < n
            && kept[layer + 1]
                .iter()
                .filter_map(|hop| rule(hop))
                .any(|r| !r.allow_sources.is_empty() || r.firewall_inbound_set.is_some())
        {
            p.warnings.push(problem(
                None,
                None,
                format!(
                    "rules in layer {} limit their sources with a source list or firewall rule set, and a refresh does not change them: check that new servers of layer {} are allowed and that removed ones no longer need to be",
                    layer + 2,
                    layer + 1
                ),
            ));
        }
    }
    p.warnings.extend(p.shared.iter().cloned());
    if !p.removed.is_empty() {
        p.notes.push(
            "rules of removed servers stop routing with the rewire, are disabled and are deleted once their server reports no sessions".into(),
        );
    }

    // The forwarding once refreshed and cleaned up, checked as a graph, and
    // the first publish checked like a configuration preview.
    let mut finals = configs.clone();
    let removed_keys: BTreeSet<String> = p
        .removed
        .iter()
        .map(|r| key(&r.node_id, &r.rule_id))
        .collect();
    if let Some(batch) = &p.add_batch {
        for update in &batch.updates {
            if let Some(config) = finals.get_mut(&update.node_id) {
                config.rules = update.rules.clone();
            }
        }
    }
    for config in finals.values_mut() {
        let node = config.node_id.clone();
        config
            .rules
            .retain(|r| !removed_keys.contains(&key(&node, &r.id)));
        for r in &mut config.rules {
            if let Some(rewire) = p
                .rewired
                .iter()
                .find(|w| w.node_id == node && w.rule_id == r.id)
            {
                r.targets = rewire.targets.clone();
            }
        }
    }
    if let Err(error) = crate::topology::validate(&finals.values().cloned().collect::<Vec<_>>()) {
        p.conflicts.push(problem(
            None,
            None,
            format!("the refreshed forwarding would not be valid: {error}"),
        ));
        return Ok(p);
    }
    for (node, after) in &finals {
        let before = &configs[node];
        if before.rules == after.rules {
            continue;
        }
        let mut change = ServerChange {
            node_id: node.clone(),
            node_name: node_name(conn, node)?,
            revision: before.revision,
            added: vec![],
            removed: vec![],
            modified: vec![],
            rule_changes: vec![],
        };
        for r in &after.rules {
            match before.rules.iter().find(|b| b.id == r.id) {
                None => change.added.push(r.id.clone()),
                Some(b) if b != r => change.modified.push(r.id.clone()),
                _ => {}
            }
        }
        for b in &before.rules {
            if !after.rules.iter().any(|r| r.id == b.id) {
                change.removed.push(b.id.clone());
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
                before: before.rules.iter().find(|r| &r.id == id).cloned(),
                after: after.rules.iter().find(|r| &r.id == id).cloned(),
            });
        }
        p.result.push(change);
    }
    let checked = |batch: ConfigBatch,
                   p: &mut Planned,
                   clocks: &mut leases::LeaseClocks|
     -> Result<Option<BatchResult>> {
        let batch_nodes: Vec<String> = batch.updates.iter().map(|u| u.node_id.clone()).collect();
        match topology::prepare(conn, clocks, actor, batch) {
            Ok(result) => Ok(Some(result)),
            Err(error) if error.downcast_ref::<Rejection>().is_some() => {
                let mut found = lines(&error);
                if found.is_empty() {
                    // A batch of one server names it.
                    let node = (batch_nodes.len() == 1).then(|| batch_nodes[0].as_str());
                    p.conflicts.push(problem(node, None, message(&error)));
                }
                for line in found.drain(..) {
                    p.conflicts
                        .push(problem(Some(&line.node_id), None, line.error));
                }
                Ok(None)
            }
            Err(error) => Err(error),
        }
    };
    if let Some(batch) = p.add_batch.clone() {
        p.preview = checked(batch, &mut p, clocks)?;
    }
    let (pause, _) = pause_updates(&configs, &kept_stopped(&p.stopped, &p.quiet), until);
    if !pause.is_empty() {
        let result = checked(ConfigBatch { updates: pause }, &mut p, clocks)?;
        if p.preview.is_none() {
            p.preview = result;
        }
    }
    Ok(p)
}

/// The record of the use `entry` of `chain`, or 404.
fn use_record(conn: &Connection, chain: &Chain, entry: &str) -> Result<ChainUse> {
    match get::<ChainUse>(conn, &format!("{USE}{entry}"))? {
        Some(record) if record.chain_id == chain.id => Ok(record),
        _ => reject(404, "forwarding of this chain not found"),
    }
}
/// `user` as an actor that may still change servers of `tenant`, or why not.
fn user_actor(
    conn: &Connection,
    user: &str,
    tenant: &str,
) -> Result<std::result::Result<Actor, String>> {
    let actor = conn
        .query_row(
            "SELECT id,tenant_id,username,role FROM users WHERE id=?1 AND disabled=0",
            [user],
            actor_row,
        )
        .optional()?;
    Ok(match actor {
        None => Err(format!("user {user} was deleted or disabled")),
        Some(actor) if !actor.may_write() => Err(format!(
            "user {} can no longer change servers",
            actor.username
        )),
        Some(actor) if !actor.permits_tenant(tenant) => Err(format!(
            "user {} can no longer change servers of this tenant",
            actor.username
        )),
        Some(actor) => Ok(actor),
    })
}
/// Restores and cleans up as the controller: putting back what a refresh
/// changed needs no permission beyond the one that started it.
fn system_actor(op: &Refresh) -> Actor {
    Actor {
        id: SYSTEM.into(),
        tenant_id: op.tenant_id.clone(),
        username: SYSTEM.into(),
        role: Role::SystemAdmin,
    }
}
/// The forwarding's rules a refresh watches: each rule of it when the
/// refresh was confirmed, and each rule it added, by key.
fn ours(op: &Refresh) -> BTreeSet<String> {
    op.before
        .keys()
        .cloned()
        .chain(op.added.iter().map(|r| key(&r.node_id, &r.rule_id)))
        .collect()
}
/// Every rule whose last published form `op` keeps: its own and those it
/// still retires.
fn tracked(op: &Refresh) -> BTreeSet<String> {
    ours(op)
        .into_iter()
        .chain(op.retire.iter().map(|r| key(&r.node_id, &r.rule_id)))
        .collect()
}
fn split(k: &str) -> (&str, &str) {
    k.split_once('/').unwrap_or((k, ""))
}
/// `rule` as compared for changes by others: any publish on its server may
/// assign budgets again.
fn comparable(rule: &Rule) -> Rule {
    let mut rule = rule.clone();
    rule.budget_ids.clear();
    rule
}
/// [`comparable`] without what a restore changes: `enabled` and pauses.
fn toggles(rule: &Rule) -> Rule {
    let mut rule = comparable(rule);
    rule.enabled = false;
    for target in &mut rule.targets {
        target.paused = false;
        target.paused_until_ms = None;
    }
    rule
}
/// The configuration revision of each server of `op`'s rules.
fn known_revisions(configs: &Configs, op: &Refresh) -> BTreeMap<String, u64> {
    tracked(op)
        .iter()
        .filter_map(|k| {
            let (node, _) = split(k);
            configs.get(node).map(|c| (node.to_owned(), c.revision))
        })
        .collect()
}
/// Whether a server of `op`'s rules has a revision `op` has not seen: only
/// then can someone else have changed one of its rules.
fn revisions_moved(conn: &Connection, op: &Refresh) -> Result<bool> {
    for (node, seen) in &op.known {
        let desired: Option<u64> = conn
            .query_row(
                "SELECT desired_revision FROM nodes WHERE id=?1",
                [node],
                |r| r.get(0),
            )
            .optional()?;
        if desired != Some(*seen) {
            return Ok(true);
        }
    }
    Ok(false)
}
/// Rules of `op` that someone else changed or deleted since it last
/// published them, by key.
fn mismatched(configs: &Configs, op: &Refresh) -> BTreeMap<String, &'static str> {
    ours(op)
        .into_iter()
        .filter_map(|k| {
            let last = op.last_rules.get(&k)?;
            let (node, rule) = split(&k);
            match rule_of(configs, node, rule) {
                None => Some((k, "was deleted")),
                Some(current) if comparable(current) != comparable(last) => {
                    Some((k, "was changed"))
                }
                _ => None,
            }
        })
        .collect()
}
/// The revisions of `op`'s own commits, by server.
fn own_revisions(op: &Refresh) -> BTreeSet<(String, u64)> {
    op.commits
        .iter()
        .flat_map(|c| c.revisions.iter().map(|(n, r)| (n.clone(), *r)))
        .collect()
}
/// Each configuration of `node` from `from` on, in order; `None` when the
/// history has a gap.
fn history(conn: &Connection, node: &str, from: u64) -> Result<Option<Vec<NodeConfig>>> {
    let mut q = conn.prepare(
        "SELECT revision,config_json FROM config_history WHERE node_id=?1 AND revision>=?2 ORDER BY revision",
    )?;
    let rows = q
        .query_map(params![node, from], |r| {
            Ok((r.get::<_, u64>(0)?, r.get::<_, String>(1)?))
        })?
        .collect::<rusqlite::Result<Vec<_>>>()?;
    let mut configs: Vec<NodeConfig> = vec![];
    for (revision, json) in rows {
        let expected = configs.last().map_or(from, |c| c.revision + 1);
        if revision != expected {
            return Ok(None);
        }
        configs.push(serde_json::from_str(&json)?);
    }
    Ok(Some(configs))
}
/// Rules of `op` that someone else changed or deleted since it last looked,
/// write by write: a change a later write set back still counts, as when
/// someone enables a stopped rule and disables it again. Writes are told
/// apart by revision, not by user.
fn foreign_changes(conn: &Connection, configs: &Configs, op: &Refresh) -> Result<Vec<NodeProblem>> {
    let keys = ours(op);
    let own = own_revisions(op);
    let mut changed: BTreeMap<String, &'static str> = BTreeMap::new();
    let mut gaps = vec![];
    for (node, seen) in &op.known {
        let prefix = format!("{node}/");
        let rules: Vec<&str> = keys
            .iter()
            .filter_map(|k| k.strip_prefix(&prefix))
            .collect();
        if rules.is_empty() {
            continue;
        }
        let Some(history) = history(conn, node, *seen)? else {
            gaps.push(node.clone());
            continue;
        };
        for pair in history.windows(2) {
            if own.contains(&(node.clone(), pair[1].revision)) {
                continue;
            }
            for rule in &rules {
                let find = |c: &NodeConfig| c.rules.iter().find(|r| r.id == *rule).map(comparable);
                if find(&pair[0]) != find(&pair[1]) {
                    changed.entry(key(node, rule)).or_insert("was changed");
                }
            }
        }
    }
    for (k, what) in mismatched(configs, op) {
        changed.insert(k, what);
    }
    let mut found = vec![];
    for (k, what) in changed {
        let (node, rule) = split(&k);
        let name = op
            .last_rules
            .get(&k)
            .map_or(rule, |r| r.name.as_str())
            .to_owned();
        found.push(node_problem(
            node,
            format!(
                "rule {name} on {} {what} by someone else during the refresh",
                label(conn, node)?
            ),
        ));
    }
    for node in gaps {
        found.push(node_problem(
            &node,
            format!(
                "the configuration history of {} has a gap, so changes by someone else cannot be ruled out",
                label(conn, &node)?
            ),
        ));
    }
    Ok(found)
}
fn step_name(step: RefreshStep) -> &'static str {
    match step {
        RefreshStep::Add => "add",
        RefreshStep::Pause => "pause",
        RefreshStep::Stop => "stop",
        RefreshStep::Rewire => "rewire",
        RefreshStep::Restore => "restore",
        RefreshStep::Cleanup => "cleanup",
    }
}
fn audit_refresh(tx: &Transaction<'_>, actor: &str, op: &Refresh, step: &str) -> Result<()> {
    audit(
        tx,
        actor,
        "forwarding_chain.refresh",
        &op.chain_id,
        &serde_json::json!({"refresh_id": op.id, "entry_rule_id": op.entry_rule_id, "step": step,
            "automatic": op.automatic, "phase": op.phase, "outcome": op.outcome, "error": op.error,
            "retry_error": op.retry_error, "unresolved": op.unresolved,
            "changes": op.changes, "revisions": op.commits.last().map(|c| &c.revisions)})
        .to_string(),
    )
}
/// Counts an automatic refresh's result on its use's settings.
fn settle_automatic(tx: &Transaction<'_>, op: &Refresh, now: i64) -> Result<()> {
    if !op.automatic {
        return Ok(());
    }
    let use_key = format!("{USE}{}", op.entry_rule_id);
    let Some(mut record) = get::<ChainUse>(tx, &use_key)? else {
        return Ok(());
    };
    if record.auto_sync.is_none() {
        return Ok(());
    }
    match op.outcome {
        Some(RefreshOutcome::Succeeded) => {
            let sync = record.auto_sync.as_mut().unwrap();
            sync.failures = 0;
            sync.next_attempt_ms = 0;
            sync.last_result = Some("refreshed".into());
        }
        _ => {
            let error = op.error.clone().unwrap_or_else(|| "refresh failed".into());
            failed_automatically(tx, &mut record, &error, now)?;
        }
    }
    put(tx, &use_key, &record)
}
/// Backs automatic refresh of `record` off after a failure, and turns it
/// off after too many in a row.
fn failed_automatically(
    tx: &Transaction<'_>,
    record: &mut ChainUse,
    error: &str,
    now: i64,
) -> Result<()> {
    let Some(sync) = record.auto_sync.as_mut() else {
        return Ok(());
    };
    sync.failures += 1;
    sync.last_result = Some(error.to_owned());
    sync.next_attempt_ms = now + (AUTO_BACKOFF_MS << (sync.failures - 1).min(8));
    let failures = sync.failures;
    let user = sync.enabled_by.clone();
    if failures >= AUTO_MAX_FAILURES {
        record.auto_sync = None;
        record.auto_sync_stopped = Some(format!(
            "turned off after {failures} automatic refreshes in a row failed; last: {error}"
        ));
    }
    audit(
        tx,
        SYSTEM,
        "forwarding_chain.auto_sync_failure",
        &record.chain_id,
        &serde_json::json!({"entry_node_id": record.entry_node_id, "enabled_by": user,
            "failures": failures, "error": error, "turned_off": record.auto_sync.is_none()})
        .to_string(),
    )
}
/// Stores `op` and audits `step` as `actor`; `settle` counts an automatic
/// refresh's result.
fn save(
    conn: &mut LoggedConnection,
    op: &Refresh,
    actor: &str,
    step: &str,
    now: i64,
    settle: bool,
) -> Result<()> {
    let tx = conn.transaction()?;
    put(&tx, &refresh_key(&op.entry_rule_id), op)?;
    audit_refresh(&tx, actor, op, step)?;
    if settle {
        settle_automatic(&tx, op, now)?;
    }
    tx.commit()?;
    Ok(())
}
/// Stores what `op` noticed, without an audit entry.
fn note(conn: &mut LoggedConnection, op: &Refresh) -> Result<()> {
    let tx = conn.transaction()?;
    put(&tx, &refresh_key(&op.entry_rule_id), op)?;
    tx.commit()?;
    Ok(())
}
/// Publishes `updates` as `step` of `op` and stores `op` as `edit` leaves
/// it, in one transaction. A rejected publish changes nothing and comes
/// back as the inner error. Only a restore passes `restorable`.
#[allow(clippy::too_many_arguments)]
fn publish_step(
    conn: &mut LoggedConnection,
    clocks: &mut leases::LeaseClocks,
    actor: &Actor,
    op: &mut Refresh,
    step: RefreshStep,
    audit_as: Option<&str>,
    updates: Vec<ConfigUpdate>,
    restorable: Option<&topology::Restorable>,
    now: i64,
    edit: impl FnOnce(&Transaction<'_>, &mut Refresh) -> Result<()>,
) -> Result<std::result::Result<(), anyhow::Error>> {
    let tx = conn.transaction()?;
    let mut next = op.clone();
    if !updates.is_empty() {
        let batch = ConfigBatch { updates };
        let published = match restorable {
            Some(restorable) => topology::publish_in_with(&tx, clocks, actor, batch, restorable),
            None => topology::publish_in(&tx, clocks, actor, batch),
        };
        let result = match published {
            Ok(result) => result,
            Err(error) if error.downcast_ref::<Rejection>().is_some() => return Ok(Err(error)),
            Err(error) => return Err(error),
        };
        // Rules the step adds count from here, so take them in first.
        edit(&tx, &mut next)?;
        record_commit(&mut next, step, &result, now);
    } else {
        edit(&tx, &mut next)?;
    }
    next.updated_at_ms = now;
    put(&tx, &refresh_key(&next.entry_rule_id), &next)?;
    audit_refresh(&tx, &actor.id, &next, audit_as.unwrap_or(step_name(step)))?;
    if next.outcome.is_some() && op.outcome != next.outcome {
        settle_automatic(&tx, &next, now)?;
    }
    tx.commit()?;
    *op = next;
    Ok(Ok(()))
}

/// Records `result` as `step` of `op`: its revisions, and each of its rules
/// as published, to notice changes by anyone else.
fn record_commit(op: &mut Refresh, step: RefreshStep, result: &BatchResult, now: i64) {
    op.commits.push(RefreshCommit {
        step,
        at_ms: now,
        revisions: result
            .configs
            .iter()
            .map(|c| (c.node_id.clone(), c.revision))
            .collect(),
    });
    let keys = tracked(op);
    for config in &result.configs {
        let prefix = format!("{}/", config.node_id);
        let mut ours = false;
        for k in keys.iter().filter(|k| k.starts_with(&prefix)) {
            ours = true;
            match config.rules.iter().find(|r| r.id == k[prefix.len()..]) {
                // A restore changes only `enabled` and pauses: a rule that
                // differs from how the refresh last left it in anything else
                // was changed by someone else and keeps counting as theirs,
                // so the cleanup does not delete it.
                Some(found)
                    if step == RefreshStep::Restore
                        && op
                            .last_rules
                            .get(k)
                            .is_some_and(|last| toggles(last) != toggles(found)) => {}
                Some(found) => {
                    op.last_rules.insert(k.clone(), found.clone());
                }
                None => {
                    op.last_rules.remove(k);
                }
            }
        }
        if ours {
            op.known.insert(config.node_id.clone(), config.revision);
        }
    }
}
/// What keeps `op` from its next step before the rewire: a failure that
/// ends it, and what it waits for.
struct Blockers {
    failure: Option<(String, Vec<NodeProblem>)>,
    waiting: Vec<NodeProblem>,
}
fn last_commit(op: &Refresh, step: RefreshStep) -> Option<&RefreshCommit> {
    op.commits.iter().rev().find(|c| c.step == step)
}
/// The servers the forwarding needs again once refreshed or put back: those
/// of the rules it pauses and stops, but rules of removed servers.
fn path_servers(op: &Refresh) -> BTreeSet<String> {
    op.quiet.iter().cloned().collect()
}
/// The rules of `stopped` whose targets are paused: those on `quiet`
/// servers, the ones the forwarding keeps.
fn kept_stopped(stopped: &[RuleRef], quiet: &[String]) -> Vec<RuleRef> {
    stopped
        .iter()
        .filter(|r| quiet.contains(&r.node_id))
        .cloned()
        .collect()
}
fn blockers(conn: &Connection, live: &mut Live<'_>, op: &Refresh) -> Result<Blockers> {
    let mut b = Blockers {
        failure: None,
        waiting: vec![],
    };
    let mut failed = vec![];
    // An agent that cannot apply a step of the refresh ends it.
    let step = match op.phase {
        RefreshPhase::Preparing => RefreshStep::Add,
        RefreshPhase::Draining => RefreshStep::Pause,
        RefreshPhase::Stopping => RefreshStep::Stop,
        _ => return Ok(b),
    };
    if let Some(commit) = last_commit(op, step) {
        // Removed servers stop with the forwarding but are not needed again:
        // the refresh does not wait for theirs.
        let needed = commit
            .revisions
            .iter()
            .filter(|(node, _)| step == RefreshStep::Add || op.quiet.contains(node));
        for (node, revision) in needed {
            match apply_state(conn, node, *revision)? {
                ("failed", error) => failed.push(node_problem(
                    node,
                    format!(
                        "{} could not apply revision {revision}: {}",
                        label(conn, node)?,
                        error.unwrap_or_default()
                    ),
                )),
                ("deleted", _) => failed.push(node_problem(
                    node,
                    format!("server {node} was deleted during the refresh"),
                )),
                ("applied", _) => {}
                ("not_enrolled", _) if op.phase != RefreshPhase::Preparing => {}
                (state, _) => b.waiting.push(node_problem(
                    node,
                    format!(
                        "{}: waiting for its agent to apply revision {revision}{}",
                        label(conn, node)?,
                        if state == "not_enrolled" {
                            " (no agent has enrolled yet)"
                        } else {
                            ""
                        }
                    ),
                )),
            }
        }
    }
    if !failed.is_empty() {
        let what = match op.phase {
            RefreshPhase::Preparing => "a new server could not apply its rule",
            RefreshPhase::Draining => {
                "a server could not apply the pause (agents older than 0.142.0 do not know paused targets)"
            }
            _ => "a server could not apply the stop",
        };
        b.failure = Some((what.into(), failed));
        return Ok(b);
    }
    if op.phase == RefreshPhase::Preparing {
        // Nothing pauses until every server it pauses or stops is
        // connected, in sync and without an apply error.
        for node in path_servers(op) {
            let state = server_state(conn, live, &node)?;
            if state.enrolled
                && (!state.online
                    || state.applied_revision != state.desired_revision
                    || state.apply_error.is_some())
            {
                b.waiting.push(node_problem(
                    &node,
                    format!(
                        "{} must be connected and in sync before the forwarding pauses: {}",
                        label(conn, &node)?,
                        busy(&state)
                    ),
                ));
            }
        }
    } else {
        for node in &op.quiet {
            let state = server_state(conn, live, node)?;
            if !state.idle {
                b.waiting.push(node_problem(
                    node,
                    format!("{} must be idle: {}", label(conn, node)?, busy(&state)),
                ));
            }
        }
    }
    Ok(b)
}
/// The servers whose agents carry the forwarding as `op` leaves it, so
/// their confirmation counts: `quiet` always, and unless the rewire was
/// committed, also removed servers whose stopped rules were enabled before
/// and are enabled again by a restore, while the entry still routes to
/// them. Such a server counts once its agent applied this refresh's pause or
/// stop; until then it runs the forwarding as it was, which the restore puts
/// back anyway. Once seen, it is kept in [`Refresh::carried`].
fn carrying(conn: &Connection, op: &Refresh) -> Result<BTreeSet<String>> {
    let mut nodes: BTreeSet<String> = op.quiet.iter().cloned().collect();
    if last_commit(op, RefreshStep::Rewire).is_some() {
        return Ok(nodes);
    }
    nodes.extend(op.carried.iter().cloned());
    nodes.extend(stop_applied(conn, op)?);
    Ok(nodes)
}
/// Removed servers of `stopped` whose stopped rules were enabled before and
/// whose agents applied this refresh's first pause or stop by now, apart
/// from those already in [`Refresh::carried`].
fn stop_applied(conn: &Connection, op: &Refresh) -> Result<BTreeSet<String>> {
    let mut nodes = BTreeSet::new();
    for r in &op.stopped {
        if op.quiet.contains(&r.node_id)
            || op.carried.contains(&r.node_id)
            || nodes.contains(&r.node_id)
            || !op
                .before
                .get(&key(&r.node_id, &r.rule_id))
                .is_some_and(|b| b.enabled)
        {
            continue;
        }
        let first = op
            .commits
            .iter()
            .filter(|c| matches!(c.step, RefreshStep::Pause | RefreshStep::Stop))
            .filter_map(|c| c.revisions.get(&r.node_id))
            .min();
        if let (Some(first), Some(row)) = (first, node_row(conn, &r.node_id)?)
            && row.enrolled
            && row.applied >= *first
        {
            nodes.insert(r.node_id.clone());
        }
    }
    Ok(nodes)
}
/// Agents that have not applied the last commit of `step` for their
/// server: failed ones and pending ones. Deleted and unenrolled servers
/// have nothing to confirm.
fn unconfirmed(
    conn: &Connection,
    live: &mut Live<'_>,
    op: &Refresh,
    step: RefreshStep,
    what: &str,
) -> Result<(Vec<NodeProblem>, Vec<NodeProblem>)> {
    // Only the servers the forwarding runs on (see [`carrying`]): a removed
    // server's rule the rewire disables, or a new server's rule a restore
    // disables, carries no traffic of it; their agents are listed but not
    // waited for.
    let carrying = carrying(conn, op)?;
    let mut last: BTreeMap<&str, u64> = BTreeMap::new();
    for commit in op.commits.iter().filter(|c| c.step == step) {
        for (node, revision) in &commit.revisions {
            if carrying.contains(node) {
                last.insert(node, *revision);
            }
        }
    }
    let (mut failed, mut pending) = (vec![], vec![]);
    for (node, revision) in last {
        match apply_state(conn, node, revision)? {
            ("failed", error) => failed.push(node_problem(
                node,
                format!(
                    "{} rejected {what} (revision {revision}): {}; it keeps running its last applied configuration and its agent retries",
                    label(conn, node)?,
                    error.unwrap_or_default()
                ),
            )),
            ("pending", _) => {
                let online = server_state(conn, live, node)?.online;
                pending.push(node_problem(
                    node,
                    format!(
                        "{}: waiting for its agent to apply {what} (revision {revision}){}",
                        label(conn, node)?,
                        if online {
                            ""
                        } else {
                            "; the server is offline and confirms once it reconnects"
                        }
                    ),
                ))
            }
            _ => {}
        }
    }
    Ok((failed, pending))
}

/// Configurations read at most once per pass of the refresh task, and
/// again after a publish.
#[derive(Default)]
pub(super) struct Snapshot {
    configs: Option<Configs>,
}
impl Snapshot {
    fn configs(&mut self, conn: &Connection) -> Result<&Configs> {
        if self.configs.is_none() {
            self.configs = Some(topology::all_configs(conn)?);
        }
        Ok(self.configs.as_ref().unwrap())
    }
    fn stale(&mut self) {
        self.configs = None;
    }
}

/// One move of `op`. Returns whether it published a configuration.
fn step(
    conn: &mut LoggedConnection,
    live: &mut Live<'_>,
    snap: &mut Snapshot,
    mut op: Refresh,
    now: i64,
) -> Result<bool> {
    // Kept once seen: a new lease resets what an agent applied to 0.
    if op.phase != RefreshPhase::Finished && last_commit(&op, RefreshStep::Rewire).is_none() {
        let seen = stop_applied(conn, &op)?;
        if !seen.is_empty() {
            op.carried.extend(seen);
            note(conn, &op)?;
        }
    }
    match op.phase {
        RefreshPhase::Finished => return Ok(false),
        RefreshPhase::Restoring => return restore(conn, live, op, now),
        RefreshPhase::Cleanup => return cleanup(conn, live, snap, op, now),
        RefreshPhase::Confirming | RefreshPhase::Blocked => {
            return confirm(conn, live, snap, op, now);
        }
        _ => {}
    }
    let actor = user_actor(conn, &op.actor_id, &op.tenant_id)?;
    let moved = revisions_moved(conn, &op)?;
    let foreign = if moved {
        let configs = snap.configs(conn)?;
        let foreign = foreign_changes(conn, configs, &op)?;
        if foreign.is_empty() {
            // Someone changed other rules of these servers: noted, so
            // the next pass reads no configuration for it.
            op.known = known_revisions(configs, &op);
            note(conn, &op)?;
        }
        foreign
    } else {
        vec![]
    };
    let b = blockers(conn, live, &op)?;
    let abort = if op.cancel_requested {
        Some((
            RefreshOutcome::Cancelled,
            "cancelled by an operator".to_owned(),
            vec![],
        ))
    } else if let Err(reason) = &actor {
        Some((
            RefreshOutcome::Failed,
            format!("stopped because the user who started it lost permission: {reason}"),
            vec![],
        ))
    } else if !foreign.is_empty() {
        Some((
            RefreshOutcome::Failed,
            "rules of this forwarding were changed by someone else during the refresh".to_owned(),
            foreign,
        ))
    } else if let Some((error, problems)) = b.failure {
        Some((RefreshOutcome::Failed, error, problems))
    } else if now >= op.deadline_ms {
        // Checked on every pass, so nothing is paused or stopped late.
        Some((
            RefreshOutcome::Failed,
            format!(
                "timed out after {} s{}",
                (op.deadline_ms - op.started_at_ms) / 1000,
                if b.waiting.is_empty() {
                    ""
                } else {
                    " while waiting"
                }
            ),
            b.waiting.clone(),
        ))
    } else {
        None
    };
    let actor_id = actor
        .as_ref()
        .map_or_else(|_| SYSTEM.to_owned(), |a| a.id.clone());
    if let Some(abort) = abort {
        return give_up(conn, live, op, abort, &actor_id, now);
    }
    if !b.waiting.is_empty() {
        return Ok(false);
    }
    let actor = actor.unwrap();
    let configs = snap.configs(conn)?;
    let mut paused = vec![];
    let (step, updates) = match op.phase {
        RefreshPhase::Preparing => {
            let (updates, targets) = pause_updates(
                configs,
                &kept_stopped(&op.stopped, &op.quiet),
                op.deadline_ms,
            );
            paused = targets;
            (RefreshStep::Pause, updates)
        }
        RefreshPhase::Draining => {
            let stopping: BTreeSet<RuleRef> = op.stopped.iter().cloned().collect();
            let updates = edit(configs, |node, rule| {
                let stop = rule.enabled && stopping.contains(&reference(node, &rule.id));
                if stop {
                    rule.enabled = false;
                }
                stop
            });
            (RefreshStep::Stop, updates)
        }
        _ => (RefreshStep::Rewire, rewire_updates(configs, &op)),
    };
    let next = match step {
        RefreshStep::Pause => RefreshPhase::Draining,
        RefreshStep::Stop => RefreshPhase::Stopping,
        _ => RefreshPhase::Confirming,
    };
    let published = !updates.is_empty();
    let result = publish_step(
        conn,
        live.clocks,
        &actor,
        &mut op,
        step,
        None,
        updates,
        None,
        now,
        |tx, op| {
            op.phase = next;
            // Recorded only once published.
            if step == RefreshStep::Pause {
                op.paused = paused;
            }
            if step == RefreshStep::Rewire {
                // Committed by the controller: the use is built from the
                // new layers, whatever its agents do next.
                op.retire.extend(op.removed.clone());
                let use_key = format!("{USE}{}", op.entry_rule_id);
                if let Some(mut record) = get::<ChainUse>(tx, &use_key)? {
                    record.layers = op.layers.clone();
                    put(tx, &use_key, &record)?;
                }
            }
            Ok(())
        },
    )?;
    match result {
        Ok(()) => Ok(published),
        Err(error) => {
            snap.stale();
            let abort = (
                RefreshOutcome::Failed,
                format!(
                    "the {} step was refused: {}",
                    step_name(step),
                    message(&error)
                ),
                lines(&error),
            );
            give_up(conn, live, op, abort, &actor_id, now)
        }
    }
}
/// Ends `op` before its rewire and starts putting the forwarding back.
fn give_up(
    conn: &mut LoggedConnection,
    live: &mut Live<'_>,
    mut op: Refresh,
    (outcome, error, problems): (RefreshOutcome, String, Vec<NodeProblem>),
    actor_id: &str,
    now: i64,
) -> Result<bool> {
    op.failed_in = Some(op.phase);
    op.outcome = Some(outcome);
    op.error = Some(error);
    op.problems = problems;
    op.phase = RefreshPhase::Restoring;
    op.updated_at_ms = now;
    save(conn, &op, actor_id, "abort", now, true)?;
    restore(conn, live, op, now)
}
/// The publish that rewires `op`'s forwarding: the rules of R get their new
/// next hops, every kept rule the stop disabled is enabled and resumed, and
/// rules of removed servers are disabled.
fn rewire_updates(configs: &Configs, op: &Refresh) -> Vec<ConfigUpdate> {
    let retire: BTreeSet<RuleRef> = op.removed.iter().cloned().collect();
    edit(configs, |node, rule| {
        let me = reference(node, &rule.id);
        let before = rule.clone();
        if retire.contains(&me) {
            rule.enabled = false;
        } else {
            if let Some(rewire) = op
                .rewired
                .iter()
                .find(|w| w.node_id == node && w.rule_id == rule.id)
            {
                rule.targets = rewire.targets.clone();
            }
            resume(op, node, rule);
            if op.stopped.contains(&me) {
                rule.enabled = true;
            }
        }
        *rule != before
    })
}
/// After the rewire a refresh only goes forward: it waits for every agent
/// to apply it (`confirming`), and is `blocked` when one rejects it or does
/// not confirm it in time. A blocked refresh still succeeds once every agent
/// applied the rewire, and ends as failed, as published, when someone
/// changes its rules or an operator dismisses it.
fn confirm(
    conn: &mut LoggedConnection,
    live: &mut Live<'_>,
    snap: &mut Snapshot,
    mut op: Refresh,
    now: i64,
) -> Result<bool> {
    let (failed, pending) = unconfirmed(conn, live, &op, RefreshStep::Rewire, "the rewire")?;
    let after = if op.retire.is_empty() {
        RefreshPhase::Finished
    } else {
        RefreshPhase::Cleanup
    };
    if failed.is_empty() && pending.is_empty() {
        if op.phase == RefreshPhase::Blocked {
            op.notes.push(format!(
                "the rewire was confirmed by every agent after it was blocked: {}",
                op.error.take().unwrap_or_default()
            ));
            op.failed_in = None;
            op.problems.clear();
        }
        op.outcome = Some(RefreshOutcome::Succeeded);
        op.phase = after;
        op.updated_at_ms = now;
        save(conn, &op, SYSTEM, "confirmed", now, true)?;
        return Ok(false);
    }
    if op.phase == RefreshPhase::Blocked {
        let foreign = if revisions_moved(conn, &op)? {
            foreign_changes(conn, snap.configs(conn)?, &op)?
        } else {
            vec![]
        };
        let ended = if op.cancel_requested {
            Some(
                "dismissed by an operator; the configuration stays as the rewire published it"
                    .to_owned(),
            )
        } else if !foreign.is_empty() {
            Some(format!(
                "left to an operator as it is: {}",
                foreign
                    .iter()
                    .map(|f| f.error.clone())
                    .collect::<Vec<_>>()
                    .join("; ")
            ))
        } else {
            None
        };
        if let Some(ended) = ended {
            op.notes.push(ended);
            op.cancel_requested = false;
            op.phase = after;
            op.updated_at_ms = now;
            save(conn, &op, SYSTEM, "handed_over", now, false)?;
        } else {
            let problems: Vec<NodeProblem> = failed.into_iter().chain(pending).collect();
            if problems != op.problems {
                op.problems = problems;
                note(conn, &op)?;
            }
        }
        return Ok(false);
    }
    let rewired_at = last_commit(&op, RefreshStep::Rewire).map_or(now, |c| c.at_ms);
    if !failed.is_empty() || now >= op.deadline_ms.max(rewired_at + CONFIRM_GRACE_MS) {
        op.outcome = Some(RefreshOutcome::Failed);
        op.failed_in = Some(RefreshPhase::Confirming);
        op.error = Some(if failed.is_empty() {
            "not every agent confirmed the rewire in time; the forwarding is not refreshed on their servers yet".to_owned()
        } else {
            "an agent rejected the rewire; the forwarding is not refreshed on its server".to_owned()
        });
        op.problems = failed.into_iter().chain(pending).collect();
        op.phase = RefreshPhase::Blocked;
        op.updated_at_ms = now;
        save(conn, &op, SYSTEM, "blocked", now, true)?;
    }
    Ok(false)
}

/// What putting `op`'s forwarding back publishes now, field by field.
struct RestorePlan {
    updates: Vec<ConfigUpdate>,
    restorable: topology::Restorable,
    notes: Vec<String>,
    unresolved: Vec<Unresolved>,
}
/// A field a refresh owns from one of its commits until it ends: `enabled`
/// of a rule it stopped or added, or the pause of a target it paused.
enum Owned<'a> {
    Enabled(&'a str),
    Pause(&'a PausedTarget),
}
impl Owned<'_> {
    fn id(&self, node: &str) -> String {
        match self {
            Owned::Enabled(rule) => format!("enabled:{node}/{rule}"),
            Owned::Pause(p) => format!(
                "pause:{node}/{}/{}/{}",
                p.rule_id,
                p.address,
                serde_json::to_string(&p.via).unwrap_or_default()
            ),
        }
    }
    fn value(&self, config: &NodeConfig) -> serde_json::Value {
        match self {
            Owned::Enabled(rule) => serde_json::json!(
                config
                    .rules
                    .iter()
                    .find(|r| r.id == *rule)
                    .map(|r| r.enabled)
            ),
            Owned::Pause(p) => serde_json::json!(
                config
                    .rules
                    .iter()
                    .find(|r| r.id == p.rule_id)
                    .and_then(|r| r
                        .targets
                        .iter()
                        .find(|t| t.address == p.address && t.via == p.via))
                    .map(|t| (t.paused, t.paused_until_ms))
            ),
        }
    }
}
/// Who owns `op`'s fields now. Each write to a server since the refresh
/// first owned a field there that is not one of its own commits (told by
/// revision, not by user: an automatic refresh publishes as the user who
/// turned it on) is compared with the revision before it; a write that
/// changed an owned field took it over, even when a later write set it back.
#[derive(Default)]
struct Ownership {
    /// Owned fields someone else took over, by [`Owned::id`].
    taken: BTreeSet<String>,
    /// Servers whose configuration history has a gap: every owned field
    /// there counts as taken over.
    incomplete: BTreeSet<String>,
    /// Servers someone else saved without taking a field over.
    saved: BTreeSet<String>,
}
fn ownership(conn: &Connection, op: &Refresh) -> Result<Ownership> {
    let mut fields: BTreeMap<&str, Vec<(u64, Owned<'_>)>> = BTreeMap::new();
    if let Some(stop) = last_commit(op, RefreshStep::Stop) {
        for r in &op.stopped {
            if let Some(revision) = stop.revisions.get(&r.node_id) {
                fields
                    .entry(&r.node_id)
                    .or_default()
                    .push((*revision, Owned::Enabled(&r.rule_id)));
            }
        }
    }
    if let Some(pause) = last_commit(op, RefreshStep::Pause) {
        for p in &op.paused {
            if let Some(revision) = pause.revisions.get(&p.node_id) {
                fields
                    .entry(&p.node_id)
                    .or_default()
                    .push((*revision, Owned::Pause(p)));
            }
        }
    }
    if let Some(add) = last_commit(op, RefreshStep::Add) {
        for r in &op.added {
            if let Some(revision) = add.revisions.get(&r.node_id) {
                fields
                    .entry(&r.node_id)
                    .or_default()
                    .push((*revision, Owned::Enabled(&r.rule_id)));
            }
        }
    }
    let mut result = Ownership::default();
    let own = own_revisions(op);
    for (node, owned) in fields {
        let Some(row) = node_row(conn, node)? else {
            continue;
        };
        let first = owned
            .iter()
            .map(|(from, _)| *from)
            .min()
            .unwrap_or_default();
        let configs = match history(conn, node, first)? {
            Some(configs) if configs.last().is_some_and(|c| c.revision == row.desired) => configs,
            _ => {
                result.incomplete.insert(node.to_owned());
                continue;
            }
        };
        for pair in configs.windows(2) {
            if own.contains(&(node.to_owned(), pair[1].revision)) {
                continue;
            }
            result.saved.insert(node.to_owned());
            for (from, field) in &owned {
                if *from <= pair[0].revision && field.value(&pair[0]) != field.value(&pair[1]) {
                    result.taken.insert(field.id(node));
                }
            }
        }
    }
    Ok(result)
}
/// Puts back only the fields `op` still owns (see [`ownership`]): `enabled`
/// of rules of R its stop disabled, the pause of targets it paused, and
/// `enabled` of rules it added (disabled; the cleanup deletes them). Every
/// other field, `draining` set by maintenance included, keeps its current
/// value. A rule of R is enabled again, with the route it had before, only
/// while no rule of the forwarding was rerouted, re-listened or deleted by
/// someone else and the operator did not ask to keep it stopped; otherwise
/// it stays stopped for an operator.
fn restore_plan(conn: &Connection, configs: &Configs, op: &Refresh) -> Result<RestorePlan> {
    use crate::topology::route_signature;
    let owner = ownership(conn, op)?;
    let stopped_by_us = last_commit(op, RefreshStep::Stop).is_some();
    let mut names: BTreeMap<String, String> = BTreeMap::new();
    for k in tracked(op) {
        let (node, _) = split(&k);
        if !names.contains_key(node) {
            names.insert(node.to_owned(), label(conn, node)?);
        }
    }
    let name = |node: &str| names.get(node).cloned().unwrap_or_else(|| node.to_owned());
    let mut unresolved = vec![];
    for (k, before) in &op.before {
        let (node, rule) = split(k);
        let what = match rule_of(configs, node, rule) {
            None => "was deleted",
            Some(current) if route_signature(current) != route_signature(before) => {
                "was rerouted or given another listener"
            }
            _ => continue,
        };
        unresolved.push(Unresolved {
            node_id: node.into(),
            rule_id: rule.into(),
            error: format!(
                "rule {} on {} {what} by someone else during the refresh; the refresh does not touch it. Check its routes and the rules that route to it",
                before.name,
                name(node)
            ),
        });
    }
    let path_intact = unresolved.is_empty();
    let changed_rules = unresolved
        .iter()
        .map(|u| format!("{} on {}", u.rule_id, name(&u.node_id)))
        .collect::<Vec<_>>()
        .join(", ");
    for node in &owner.incomplete {
        unresolved.push(Unresolved {
            node_id: node.clone(),
            rule_id: String::new(),
            error: format!(
                "the configuration history of {} has a gap since the refresh changed it, so the refresh cannot tell what someone else changed there and leaves its rules as they are. Check the rules of this forwarding on it, then resume paused targets and enable stopped rules yourself (enabling needs the server without sessions)",
                name(node)
            ),
        });
    }
    let stopped: BTreeSet<String> = op
        .stopped
        .iter()
        .map(|r| key(&r.node_id, &r.rule_id))
        .collect();
    let added: BTreeSet<String> = op
        .added
        .iter()
        .map(|r| key(&r.node_id, &r.rule_id))
        .collect();
    // The rules of R it would enable again, less each whose next hop stays
    // disabled (someone else disabled it, or it stays stopped itself): an
    // enabled rule may not route to a disabled one, so enabling it would be
    // refused on every try. Those stay stopped for an operator at once.
    let mut enable: BTreeSet<String> = BTreeSet::new();
    if path_intact && stopped_by_us && !op.keep_stopped {
        for k in &stopped {
            let (node, rule) = split(k);
            let (Some(current), Some(last)) = (rule_of(configs, node, rule), op.last_rules.get(k))
            else {
                continue;
            };
            if !current.enabled
                && op.before.get(k).is_some_and(|b| b.enabled)
                && route_signature(current) == route_signature(last)
                && !owner.incomplete.contains(node)
                && !owner.taken.contains(&Owned::Enabled(rule).id(node))
            {
                enable.insert(k.clone());
            }
        }
    }
    let mut held: BTreeMap<String, String> = BTreeMap::new();
    loop {
        let before = enable.len();
        for k in enable.clone() {
            let (node, rule) = split(&k);
            let current = rule_of(configs, node, rule).expect("checked above");
            let off = current
                .targets
                .iter()
                .filter_map(|t| t.via.as_ref())
                .find(|via| {
                    let next = key(&via.node_id, &via.rule_id);
                    !enable.contains(&next)
                        && (added.contains(&next)
                            || rule_of(configs, &via.node_id, &via.rule_id)
                                .is_none_or(|r| !r.enabled))
                });
            if let Some(via) = off {
                let next = rule_of(configs, &via.node_id, &via.rule_id)
                    .map_or(via.rule_id.as_str(), |r| r.name.as_str());
                held.insert(k.clone(), format!("{next} on {}", name(&via.node_id)));
                enable.remove(&k);
            }
        }
        if enable.len() == before {
            break;
        }
    }
    let mut restorable = topology::Restorable::new();
    let mut notes = vec![];
    let mut left = vec![];
    let updates = edit(configs, |node, rule| {
        let k = key(node, &rule.id);
        let Some(last) = op.last_rules.get(&k) else {
            return false;
        };
        if route_signature(rule) != route_signature(last) || owner.incomplete.contains(node) {
            return false;
        }
        let mut changed = false;
        for target in &mut rule.targets {
            let Some(paused) = op.paused.iter().find(|p| {
                p.node_id == node
                    && p.rule_id == rule.id
                    && p.address == target.address
                    && p.via == target.via
            }) else {
                continue;
            };
            if owner.taken.contains(&Owned::Pause(paused).id(node)) {
                notes.push(format!(
                    "kept the pause someone else set on target {} of rule {} on {}",
                    target.address,
                    rule.name,
                    name(node)
                ));
            } else if target.paused {
                target.paused = false;
                target.paused_until_ms = None;
                changed = true;
            }
        }
        let mine = stopped.contains(&k) || added.contains(&k);
        if mine && owner.taken.contains(&Owned::Enabled(&rule.id).id(node)) {
            notes.push(format!(
                "rule {} on {} was enabled or disabled by someone else during the refresh; left as they set it",
                rule.name,
                name(node)
            ));
        } else if added.contains(&k) {
            if rule.enabled {
                rule.enabled = false;
                changed = true;
            }
        } else if stopped.contains(&k)
            && stopped_by_us
            && !rule.enabled
            && op.before.get(&k).is_some_and(|b| b.enabled)
        {
            if op.keep_stopped {
                left.push(Unresolved {
                    node_id: node.into(),
                    rule_id: rule.id.clone(),
                    error: format!(
                        "rule {} on {} stays disabled because the operator cancelled the refresh asking to keep its rules stopped. Enable it in the server's rules when wanted; its server must have no sessions for that",
                        rule.name,
                        name(node)
                    ),
                });
            } else if let Some(next) = held.get(&k) {
                left.push(Unresolved {
                    node_id: node.into(),
                    rule_id: rule.id.clone(),
                    error: format!(
                        "rule {} on {} stays disabled: its next hop {next} is disabled, and an enabled rule may not route to a disabled one. Enable that next hop first (or check why it was disabled), then enable this rule in the server's rules; its server must have no sessions for that",
                        rule.name,
                        name(node)
                    ),
                });
            } else if path_intact {
                rule.enabled = true;
                // The route it had when the refresh began, which the path
                // check just found unchanged.
                restorable.insert(
                    (node.to_owned(), rule.id.clone()),
                    route_signature(&op.before[&k]),
                );
                changed = true;
                if owner.saved.contains(node) {
                    notes.push(format!(
                        "{} was saved by someone else while the refresh had rule {} stopped; a save cannot ask to keep it stopped, so the refresh enabled it again by ownership. Disable it again if that was meant",
                        name(node),
                        rule.name
                    ));
                }
            } else {
                left.push(Unresolved {
                    node_id: node.into(),
                    rule_id: rule.id.clone(),
                    error: format!(
                        "rule {} on {} stays disabled: the refresh enables the rules it stopped only while the forwarding's routes are as they were, and {changed_rules} changed. Check its routes and next hops, then enable it in the server's rules; its server must have no sessions for that",
                        rule.name,
                        name(node)
                    ),
                });
            }
        }
        changed
    });
    unresolved.extend(left);
    Ok(RestorePlan {
        updates,
        restorable,
        notes,
        unresolved,
    })
}
/// Puts back what `op` changed before its rewire, as the controller and
/// without waiting for idle servers. The plan, the path check and the
/// publish read one transaction, and the publish runs every check of
/// [`topology::prepare`] but the idle one for exactly the rules it enables
/// with their old route. A server whose part is refused is retried. Once
/// nothing is left to publish, every agent of the path must apply it; one
/// that rejects it or has not confirmed it in [`CONFIRM_GRACE_MS`] marks it
/// late. Then the rules it added are deleted by the cleanup. An operator can
/// end it at any point (see [`end_restore`]).
fn restore(
    conn: &mut LoggedConnection,
    live: &mut Live<'_>,
    mut op: Refresh,
    now: i64,
) -> Result<bool> {
    if op.end_requested {
        return end_restore(conn, live, op, now);
    }
    if let Some(restored_at) = op.restored_at_ms {
        let (failed, pending) = unconfirmed(conn, live, &op, RefreshStep::Restore, "the restore")?;
        if failed.is_empty() && pending.is_empty() {
            if op.restore_late {
                op.notes.push(
                    "every agent of the path confirmed the restore after it was rejected or overdue"
                        .to_owned(),
                );
            }
            op.phase = if op.retire.is_empty() {
                RefreshPhase::Finished
            } else {
                RefreshPhase::Cleanup
            };
            op.updated_at_ms = now;
            save(conn, &op, SYSTEM, "restored", now, false)?;
        } else if !op.restore_late && (!failed.is_empty() || now >= restored_at + CONFIRM_GRACE_MS)
        {
            // Audited once; the agents keep retrying and it goes on waiting.
            op.restore_late = true;
            op.updated_at_ms = now;
            let step = if failed.is_empty() {
                "restore_overdue"
            } else {
                "restore_rejected"
            };
            save(conn, &op, SYSTEM, step, now, false)?;
        }
        return Ok(false);
    }
    // Refused before: tried again once what its checks read changed, and
    // otherwise only every RESTORE_RETRY_MS.
    let retry_key = retry_key(conn)?;
    if op.retry_error.is_some()
        && op.retry_key.as_deref() == Some(retry_key.as_str())
        && op.retry_at_ms.is_some_and(|at| now < at)
    {
        return Ok(false);
    }
    let system = system_actor(&op);
    let tx = conn.transaction()?;
    let configs = topology::all_configs(&tx)?;
    let plan = restore_plan(&tx, &configs, &op)?;
    let mut next = op.clone();
    for n in &plan.notes {
        if !next.notes.contains(n) {
            next.notes.push(n.clone());
        }
    }
    next.updated_at_ms = now;
    if plan.updates.is_empty() {
        for added in &op.added {
            if !next.retire.contains(added) {
                next.retire.push(added.clone());
            }
        }
        next.unresolved = plan.unresolved;
        next.retry_error = None;
        next.refused.clear();
        next.retry_key = None;
        next.retry_at_ms = None;
        next.restored_at_ms = Some(now);
        put(&tx, &refresh_key(&next.entry_rule_id), &next)?;
        audit_refresh(&tx, SYSTEM, &next, "restore_committed")?;
        tx.commit()?;
        return restore(conn, live, next, now);
    }
    // All servers at once, as rules routing to each other must be enabled
    // together; when that is refused, as many servers as pass with each
    // other, and the rest is retried with its reason.
    let check = |tx: &Transaction<'_>,
                 clocks: &mut leases::LeaseClocks,
                 updates: &[ConfigUpdate]|
     -> Result<std::result::Result<(), String>> {
        match topology::prepare_with(
            tx,
            clocks,
            &system,
            ConfigBatch {
                updates: updates.to_vec(),
            },
            &plan.restorable,
        ) {
            Ok(_) => Ok(Ok(())),
            Err(error) if error.downcast_ref::<Rejection>().is_some() => Ok(Err(message(&error))),
            Err(error) => Err(error),
        }
    };
    let mut passing = vec![];
    let mut refused: Vec<(ConfigUpdate, String)> = vec![];
    if check(&tx, live.clocks, &plan.updates)?.is_ok() {
        passing = plan.updates;
    } else {
        let mut left: Vec<(ConfigUpdate, String)> = plan
            .updates
            .into_iter()
            .map(|u| (u, String::new()))
            .collect();
        loop {
            let mut progress = false;
            for (update, _) in std::mem::take(&mut left) {
                let mut trial = passing.clone();
                trial.push(update.clone());
                match check(&tx, live.clocks, &trial)? {
                    Ok(()) => {
                        passing = trial;
                        progress = true;
                    }
                    Err(error) => left.push((update, error)),
                }
            }
            if !progress || left.is_empty() {
                break;
            }
        }
        refused = left;
    }
    next.refused = refused
        .iter()
        .map(|(update, error)| {
            Ok(node_problem(
                &update.node_id,
                format!("{}: {error}", label(&tx, &update.node_id)?),
            ))
        })
        .collect::<Result<Vec<_>>>()?;
    next.retry_error = (!next.refused.is_empty()).then(|| {
        format!(
            "restoring is refused on some servers, retrying: {}",
            next.refused
                .iter()
                .map(|r| r.error.as_str())
                .collect::<Vec<_>>()
                .join("; ")
        )
    });
    (next.retry_key, next.retry_at_ms) = if next.refused.is_empty() {
        (None, None)
    } else {
        (Some(retry_key), Some(now + RESTORE_RETRY_MS))
    };
    let result = if passing.is_empty() {
        None
    } else {
        Some(topology::publish_in_with(
            &tx,
            live.clocks,
            &system,
            ConfigBatch { updates: passing },
            &plan.restorable,
        )?)
    };
    let Some(result) = result else {
        drop(tx);
        let changed = op.retry_error != next.retry_error;
        op.retry_error = next.retry_error;
        op.refused = next.refused;
        op.retry_key = next.retry_key;
        op.retry_at_ms = next.retry_at_ms;
        op.notes = next.notes;
        if changed {
            op.updated_at_ms = now;
            save(conn, &op, SYSTEM, "restore_retry", now, false)?;
        } else {
            note(conn, &op)?;
        }
        return Ok(false);
    };
    record_commit(&mut next, RefreshStep::Restore, &result, now);
    put(&tx, &refresh_key(&next.entry_rule_id), &next)?;
    audit_refresh(&tx, SYSTEM, &next, "restore")?;
    tx.commit()?;
    // Once published, what is left (nothing, or only refused servers) is
    // settled in the same pass.
    restore(conn, live, next, now)?;
    Ok(true)
}
/// What a refused restore's checks read besides its own rules: each
/// server's revisions and apply error, and the abilities agents reported
/// (`*_node:<id>` records, such as support for rate limits).
fn retry_key(conn: &Connection) -> Result<String> {
    Ok(conn.query_row(
        "SELECT (SELECT ifnull(group_concat(id||':'||desired_revision||':'||applied_revision||':'||ifnull(apply_error,''),','),'')
                 FROM (SELECT id,desired_revision,applied_revision,apply_error FROM nodes ORDER BY id))
             ||'|'||(SELECT count(*) FROM metadata WHERE key GLOB '*_node:*')",
        [],
        |r| r.get(0),
    )?)
}
/// Ends a restore an operator gave up on, where it is: what it published
/// stays, it no longer retries, and each rule it stopped that is still
/// disabled and each target it paused that is still paused goes to
/// `unresolved` with why. Agents that have not confirmed keep retrying by
/// themselves; the forwarding counts as interrupted until they apply it.
fn end_restore(
    conn: &mut LoggedConnection,
    live: &mut Live<'_>,
    mut op: Refresh,
    now: i64,
) -> Result<bool> {
    let configs = topology::all_configs(conn)?;
    let owner = ownership(conn, &op)?;
    let why = match (&op.retry_error, op.restored_at_ms) {
        (Some(error), _) => error.clone(),
        (None, Some(_)) => "it was published, but not every agent had applied it".to_owned(),
        (None, None) => "it was not published yet".to_owned(),
    };
    let mut left = op.unresolved.clone();
    let listed = |left: &[Unresolved], node: &str, rule: &str| {
        left.iter().any(|u| u.node_id == node && u.rule_id == rule)
    };
    for r in op.stopped.clone() {
        let k = key(&r.node_id, &r.rule_id);
        let Some(current) = rule_of(&configs, &r.node_id, &r.rule_id) else {
            continue;
        };
        if current.enabled
            || !op.before.get(&k).is_some_and(|b| b.enabled)
            || owner
                .taken
                .contains(&Owned::Enabled(&r.rule_id).id(&r.node_id))
            || listed(&left, &r.node_id, &r.rule_id)
        {
            continue;
        }
        let server = label(conn, &r.node_id)?;
        left.push(Unresolved {
            node_id: r.node_id.clone(),
            rule_id: r.rule_id.clone(),
            error: if op.keep_stopped {
                format!(
                    "rule {} on {server} stays disabled because the operator cancelled the refresh asking to keep its rules stopped. Enable it in the server's rules when wanted; its server must have no sessions for that",
                    current.name
                )
            } else {
                format!(
                    "rule {} on {server} is still disabled: an operator ended the restore before it was enabled again ({why}). Check its route and next hops, then enable it in the server's rules; its server must have no sessions for that",
                    current.name
                )
            },
        });
    }
    for p in op.paused.clone() {
        let Some(current) = rule_of(&configs, &p.node_id, &p.rule_id) else {
            continue;
        };
        let still = current
            .targets
            .iter()
            .any(|t| t.address == p.address && t.via == p.via && t.paused);
        if still && !owner.taken.contains(&Owned::Pause(&p).id(&p.node_id)) {
            left.push(Unresolved {
                node_id: p.node_id.clone(),
                rule_id: p.rule_id.clone(),
                error: format!(
                    "target {} of rule {} on {} is still paused: an operator ended the restore before it was resumed ({why}). Resume it in the server's rules",
                    p.address,
                    current.name,
                    label(conn, &p.node_id)?
                ),
            });
        }
    }
    if op.restored_at_ms.is_some() {
        let (failed, pending) = unconfirmed(conn, live, &op, RefreshStep::Restore, "the restore")?;
        let open: Vec<String> = failed.into_iter().chain(pending).map(|p| p.error).collect();
        if !open.is_empty() {
            op.notes.push(format!(
                "ended by an operator while agents had not confirmed the restore; they keep retrying, and the forwarding is back on each server once its agent applies it: {}",
                open.join("; ")
            ));
        }
    }
    for added in op.added.clone() {
        // Still enabled as the refresh left it: the restore had not disabled
        // it (its server's part was refused, as when another rule routes to
        // it). It is not someone else's, and the cleanup only deletes
        // disabled rules, so an operator takes it.
        let k = key(&added.node_id, &added.rule_id);
        if let Some(current) = rule_of(&configs, &added.node_id, &added.rule_id)
            && current.enabled
            && op
                .last_rules
                .get(&k)
                .is_some_and(|last| comparable(last) == comparable(current))
        {
            op.retire.retain(|r| r != &added);
            if !listed(&left, &added.node_id, &added.rule_id) {
                left.push(Unresolved {
                    node_id: added.node_id.clone(),
                    rule_id: added.rule_id.clone(),
                    error: format!(
                        "rule {} on {}, which this refresh added, is still enabled with its listener: an operator ended the restore before it was disabled ({why}). The forwarding does not use it; once no other rule routes to it, delete it in the server's rules",
                        current.name,
                        label(conn, &added.node_id)?
                    ),
                });
            }
            continue;
        }
        if !op.retire.contains(&added) {
            op.retire.push(added);
        }
    }
    op.unresolved = left;
    op.retry_error = None;
    op.refused.clear();
    op.retry_key = None;
    op.retry_at_ms = None;
    op.phase = if op.retire.is_empty() {
        RefreshPhase::Finished
    } else {
        RefreshPhase::Cleanup
    };
    op.updated_at_ms = now;
    save(conn, &op, SYSTEM, "restore_ended", now, false)?;
    Ok(false)
}
/// Deletes retired rules once disabled, routed to by nothing and their
/// server idle. A retired rule someone else changed or enabled again is no
/// longer the refresh's. Cleanup does not hold the forwarding up.
fn cleanup(
    conn: &mut LoggedConnection,
    live: &mut Live<'_>,
    snap: &mut Snapshot,
    mut op: Refresh,
    now: i64,
) -> Result<bool> {
    // Cheap first: only a rule on an idle or deleted server can go.
    let mut ready: BTreeSet<String> = BTreeSet::new();
    for node in op.retire.iter().map(|r| &r.node_id) {
        if ready.contains(node) {
            continue;
        }
        if node_row(conn, node)?.is_none() || topology::quiescent(conn, live.clocks, node)? {
            ready.insert(node.clone());
        }
    }
    if ready.is_empty() {
        return Ok(false);
    }
    let configs = snap.configs(conn)?;
    let mut remaining = vec![];
    let mut forgotten = vec![];
    let mut delete: BTreeSet<RuleRef> = BTreeSet::new();
    for retired in &op.retire {
        let Some(rule) = rule_of(configs, &retired.node_id, &retired.rule_id) else {
            continue;
        };
        let k = key(&retired.node_id, &retired.rule_id);
        if rule.enabled
            || op
                .last_rules
                .get(&k)
                .is_some_and(|last| comparable(last) != comparable(rule))
        {
            forgotten.push(format!(
                "left in place: rule {} on {} was changed by someone else",
                rule.name,
                label(conn, &retired.node_id)?
            ));
            continue;
        }
        let routed = configs.values().any(|c| {
            c.rules
                .iter()
                .any(|r| r.targets.iter().any(|t| t.via.as_ref() == Some(retired)))
        });
        if !routed && ready.contains(&retired.node_id) {
            delete.insert(retired.clone());
        } else {
            remaining.push(retired.clone());
        }
    }
    if delete.is_empty() && remaining.len() == op.retire.len() {
        return Ok(false);
    }
    let updates: Vec<ConfigUpdate> = configs
        .values()
        .filter(|c| delete.iter().any(|d| d.node_id == c.node_id))
        .map(|c| ConfigUpdate {
            node_id: c.node_id.clone(),
            expected_revision: c.revision,
            rules: c
                .rules
                .iter()
                .filter(|r| !delete.contains(&reference(&c.node_id, &r.id)))
                .cloned()
                .collect(),
            rate_bytes_per_sec: None,
            rate_limits: None,
        })
        .collect();
    let published = !updates.is_empty();
    let system = system_actor(&op);
    let result = publish_step(
        conn,
        live.clocks,
        &system,
        &mut op,
        RefreshStep::Cleanup,
        None,
        updates,
        None,
        now,
        |_, op| {
            op.retry_error = None;
            op.notes.extend(forgotten);
            op.retire = remaining;
            if op.retire.is_empty() {
                op.phase = RefreshPhase::Finished;
            }
            Ok(())
        },
    )?;
    if let Err(error) = result {
        let error = format!("cleanup failed, retrying: {}", message(&error));
        if op.retry_error.as_deref() != Some(&error) {
            op.retry_error = Some(error);
            op.updated_at_ms = now;
            save(conn, &op, SYSTEM, "cleanup_retry", now, false)?;
        }
        return Ok(false);
    }
    Ok(published)
}
/// What the cleanup waits for, with what to do about a server that does
/// not come back.
fn cleanup_waiting(
    conn: &Connection,
    live: &mut Live<'_>,
    op: &Refresh,
) -> Result<Vec<NodeProblem>> {
    let nodes: BTreeSet<&String> = op.retire.iter().map(|r| &r.node_id).collect();
    let mut waiting = vec![];
    for node in nodes {
        if node_row(conn, node)?.is_none() {
            continue;
        }
        let state = server_state(conn, live, node)?;
        if !state.idle {
            waiting.push(node_problem(
                node,
                format!(
                    "{} must be idle before its disabled rule is deleted: {}. This does not affect the forwarding; if the server is gone for good, revoke and delete it and the refresh forgets the rule",
                    label(conn, node)?,
                    busy(&state)
                ),
            ));
        }
    }
    Ok(waiting)
}

/// In-progress refreshes, by entry rule, as stored: finished ones are not
/// read. An unreadable record is passed on for the caller to report.
fn active_records(conn: &Connection) -> Result<Vec<(String, String)>> {
    let mut q = conn.prepare(
        "SELECT substr(key,15),value FROM metadata WHERE key GLOB 'chain_refresh:*'
         AND CASE WHEN json_valid(value) THEN json_extract(value,'$.phase')<>'finished' ELSE 1 END ORDER BY key",
    )?;
    let rows = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
    Ok(rows.collect::<rusqlite::Result<Vec<_>>>()?)
}
/// Another refresh still able to stop or wait on one of `nodes`: its entry
/// rule and the shared servers.
fn overlapping(
    conn: &Connection,
    entry: &str,
    nodes: &BTreeSet<String>,
) -> Result<Option<(String, Vec<String>)>> {
    for (other, value) in active_records(conn)? {
        if other == entry {
            continue;
        }
        let Ok(op) = serde_json::from_str::<Refresh>(&value) else {
            continue;
        };
        if matches!(op.phase, RefreshPhase::Cleanup | RefreshPhase::Finished) {
            continue;
        }
        let shared: Vec<String> = op
            .quiet
            .iter()
            .chain(op.stopped.iter().map(|r| &r.node_id))
            .filter(|n| nodes.contains(*n))
            .cloned()
            .collect::<BTreeSet<_>>()
            .into_iter()
            .collect();
        if !shared.is_empty() {
            return Ok(Some((other, shared)));
        }
    }
    Ok(None)
}

/// Starts a refresh of `record` as `actor` from `planned`, publishing the
/// rules of new servers in the same transaction.
#[allow(clippy::too_many_arguments)]
fn begin(
    conn: &mut LoggedConnection,
    clocks: &mut leases::LeaseClocks,
    actor: &Actor,
    chain: &Chain,
    entry: &str,
    record: &ChainUse,
    planned: Planned,
    timeout: u64,
    automatic: bool,
    now: i64,
) -> Result<Refresh> {
    let mine: BTreeSet<String> = planned
        .quiet
        .iter()
        .cloned()
        .chain(planned.stopped.iter().map(|r| r.node_id.clone()))
        .collect();
    if let Some((other, shared)) = overlapping(conn, entry, &mine)? {
        let names = shared
            .iter()
            .map(|n| label(conn, n))
            .collect::<Result<Vec<_>>>()?
            .join(", ");
        return reject(
            409,
            format!(
                "the refresh of another forwarding (entry rule {other}) is still pausing or stopping {names}; wait until it has finished"
            ),
        );
    }
    let configs = topology::all_configs(conn)?;
    // Rules a previous refresh still cleans up are carried on.
    let previous = get::<Refresh>(conn, &refresh_key(entry))?;
    let mut before: BTreeMap<String, Rule> = BTreeMap::new();
    let entry_ref = std::iter::once(reference(&record.entry_node_id, entry));
    for r in entry_ref.chain(record.layers.iter().flatten().map(hop_ref)) {
        if let Some(found) = rule_of(&configs, &r.node_id, &r.rule_id) {
            before.insert(key(&r.node_id, &r.rule_id), found.clone());
        }
    }
    let mut last_rules = before.clone();
    let mut retire = vec![];
    if let Some(previous) = previous {
        for r in previous.retire {
            let k = key(&r.node_id, &r.rule_id);
            if let Some(last) = previous.last_rules.get(&k) {
                last_rules.entry(k).or_insert_with(|| last.clone());
            }
            retire.push(r);
        }
    }
    let mut op = Refresh {
        id: Uuid::new_v4().to_string(),
        chain_id: chain.id.clone(),
        tenant_id: chain.tenant_id.clone(),
        entry_rule_id: entry.into(),
        entry_node_id: record.entry_node_id.clone(),
        actor_id: actor.id.clone(),
        automatic,
        token: planned.token,
        started_at_ms: now,
        deadline_ms: now + i64::try_from(timeout)? * 1000,
        updated_at_ms: now,
        phase: RefreshPhase::Preparing,
        outcome: None,
        cancel_requested: false,
        failed_in: None,
        error: None,
        retry_error: None,
        problems: vec![],
        notes: planned.notes,
        changes: planned.changes,
        layers: planned.layers,
        added: planned.added,
        rewired: planned.rewired,
        stopped: planned.stopped,
        quiet: planned.quiet,
        paused: vec![],
        removed: planned.removed,
        retire,
        before,
        last_rules,
        unresolved: vec![],
        restored_at_ms: None,
        keep_stopped: false,
        known: BTreeMap::new(),
        refused: vec![],
        retry_key: None,
        retry_at_ms: None,
        restore_late: false,
        end_requested: false,
        carried: vec![],
        commits: vec![],
    };
    op.known = known_revisions(&configs, &op);
    let updates = planned.add_batch.map(|b| b.updates).unwrap_or_default();
    match publish_step(
        conn,
        clocks,
        actor,
        &mut op,
        RefreshStep::Add,
        Some("start"),
        updates,
        None,
        now,
        |_, _| Ok(()),
    )? {
        Ok(()) => Ok(op),
        Err(error) => Err(error),
    }
}

/// Starts automatic refreshes that are due; one use's error does not keep
/// the others from theirs. Returns whether one published.
fn automatic(conn: &mut LoggedConnection, live: &mut Live<'_>, now: i64) -> Result<bool> {
    let records: Vec<(String, String)> = {
        let mut q = conn.prepare(
            "SELECT substr(key,11),value FROM metadata WHERE key GLOB 'chain_use:*'
             AND CASE WHEN json_valid(value) THEN json_extract(value,'$.auto_sync') IS NOT NULL ELSE 0 END ORDER BY key",
        )?;
        let rows = q.query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    if records.is_empty() {
        return Ok(false);
    }
    let groups = all_groups(conn)?;
    let mut published = false;
    for (entry, value) in records {
        let outcome = serde_json::from_str::<ChainUse>(&value)
            .map_err(anyhow::Error::from)
            .and_then(|record| automatic_one(conn, live, &groups, &entry, record, now));
        match outcome {
            Ok(changed) => published |= changed,
            Err(error) => {
                tracing::error!(%error, entry_rule_id = %entry, "automatic chain refresh failed")
            }
        }
    }
    Ok(published)
}
fn automatic_one(
    conn: &mut LoggedConnection,
    live: &mut Live<'_>,
    groups: &[EndpointGroup],
    entry: &str,
    mut record: ChainUse,
    now: i64,
) -> Result<bool> {
    let Some(sync) = record.auto_sync.clone() else {
        return Ok(false);
    };
    if now < sync.next_attempt_ms {
        return Ok(false);
    }
    if get::<Refresh>(conn, &refresh_key(entry))?
        .is_some_and(|op| !matches!(op.phase, RefreshPhase::Finished | RefreshPhase::Cleanup))
    {
        return Ok(false);
    }
    let Some(chain) = get::<Chain>(conn, &format!("{CHAIN}{}", record.chain_id))? else {
        return Ok(false);
    };
    // Paused while the chain is disabled; not a failure.
    if !chain.enabled {
        return Ok(false);
    }
    let use_key = format!("{USE}{entry}");
    let actor = match user_actor(conn, &sync.enabled_by, &chain.tenant_id)? {
        Ok(actor) => actor,
        Err(reason) => {
            record.auto_sync = None;
            record.auto_sync_stopped = Some(format!("turned off: {reason}"));
            let tx = conn.transaction()?;
            put(&tx, &use_key, &record)?;
            audit(
                &tx,
                SYSTEM,
                "forwarding_chain.auto_sync",
                &chain.id,
                &serde_json::json!({"entry_rule_id": entry, "enabled": false, "reason": reason})
                    .to_string(),
            )?;
            tx.commit()?;
            return Ok(false);
        }
    };
    if changes(&chain, groups, &record).is_empty() {
        return Ok(false);
    }
    // Waits, without counting a failure, while another refresh pauses or
    // stops a server this forwarding uses or would use.
    let involved: BTreeSet<String> = std::iter::once(record.entry_node_id.clone())
        .chain(record.layers.iter().flatten().map(|h| h.node_id.clone()))
        .chain(
            chain
                .layers
                .iter()
                .filter_map(|l| groups.iter().find(|g| g.id == l.group_id))
                .flat_map(|g| g.members.iter().cloned()),
        )
        .collect();
    if overlapping(conn, entry, &involved)?.is_some() {
        return Ok(false);
    }
    let fail = |conn: &mut LoggedConnection, record: &mut ChainUse, error: &str| -> Result<bool> {
        let tx = conn.transaction()?;
        failed_automatically(&tx, record, error, now)?;
        put(&tx, &use_key, record)?;
        tx.commit()?;
        Ok(false)
    };
    let until = now + i64::try_from(sync.timeout_secs)? * 1000;
    let planned = match plan(conn, live.clocks, &actor, &chain, entry, &record, until) {
        Ok(planned) => planned,
        Err(error) if error.downcast_ref::<Rejection>().is_some() => {
            return fail(conn, &mut record, &message(&error));
        }
        Err(error) => return Err(error),
    };
    if planned.up_to_date {
        return Ok(false);
    }
    // Automatic runs do not wait on other forwardings' sessions, and an agent
    // too old to pause targets is a conflict like any other.
    let conflicts: Vec<&RefreshProblem> = planned
        .conflicts
        .iter()
        .chain(&planned.shared)
        .chain(&planned.too_old)
        .collect();
    if !conflicts.is_empty() {
        let error = format!(
            "could not start: {}",
            conflicts
                .iter()
                .map(|c| c.message.clone())
                .collect::<Vec<_>>()
                .join("; ")
        );
        return fail(conn, &mut record, &error);
    }
    // A server that never connected, as one added to a group before its
    // agent is installed: looked at again later, not a failure.
    if !planned.unseen.is_empty() {
        if let Some(sync) = record.auto_sync.as_mut() {
            sync.last_result = Some(format!(
                "waiting: {}",
                planned
                    .unseen
                    .iter()
                    .map(|c| c.message.clone())
                    .collect::<Vec<_>>()
                    .join("; ")
            ));
            sync.next_attempt_ms = now + AUTO_BACKOFF_MS;
        }
        let tx = conn.transaction()?;
        put(&tx, &use_key, &record)?;
        tx.commit()?;
        return Ok(false);
    }
    let adds = planned.add_batch.is_some();
    match begin(
        conn,
        live.clocks,
        &actor,
        &chain,
        entry,
        &record,
        planned,
        sync.timeout_secs,
        true,
        now,
    ) {
        Ok(_) => Ok(adds),
        Err(error) if error.downcast_ref::<Rejection>().is_some() => fail(
            conn,
            &mut record,
            &format!("could not start: {}", message(&error)),
        ),
        Err(error) => Err(error),
    }
}
/// Forgets finished refreshes whose forwarding's record is gone, as when
/// the chain was deleted during a cleanup.
fn forget_orphans(conn: &mut LoggedConnection) -> Result<()> {
    let orphans: Vec<String> = {
        let mut q = conn.prepare(
            "SELECT r.key FROM metadata r WHERE r.key GLOB 'chain_refresh:*'
             AND CASE WHEN json_valid(r.value) THEN json_extract(r.value,'$.phase')='finished' ELSE 0 END
             AND NOT EXISTS(SELECT 1 FROM metadata u WHERE u.key='chain_use:'||substr(r.key,15))",
        )?;
        let rows = q.query_map([], |r| r.get(0))?;
        rows.collect::<rusqlite::Result<Vec<_>>>()?
    };
    if orphans.is_empty() {
        return Ok(());
    }
    let tx = conn.transaction()?;
    for k in orphans {
        tx.execute("DELETE FROM metadata WHERE key=?1", [k])?;
    }
    tx.commit()?;
    Ok(())
}

/// Where `op` is, for people (see [`RefreshView::stage`]).
/// `rejected`: an agent of the path rejects the committed restore.
fn stage(op: &Refresh, rejected: bool) -> &'static str {
    match op.phase {
        RefreshPhase::Preparing | RefreshPhase::Draining | RefreshPhase::Stopping => "updating",
        RefreshPhase::Confirming => "confirming",
        RefreshPhase::Blocked => "blocked",
        RefreshPhase::Restoring if op.restored_at_ms.is_some() && rejected => "restore_failed",
        RefreshPhase::Restoring if op.restored_at_ms.is_some() && op.restore_late => {
            "restore_overdue"
        }
        RefreshPhase::Restoring if op.restored_at_ms.is_some() => "restore_confirming",
        RefreshPhase::Restoring if op.retry_error.is_some() => "restore_blocked",
        RefreshPhase::Restoring => "restoring",
        RefreshPhase::Cleanup => "cleanup",
        RefreshPhase::Finished => "finished",
    }
}
/// `op` as the panel shows it, with the live state of its servers and the
/// current configurations `configs`.
pub(super) fn view(
    conn: &Connection,
    live: &mut Live<'_>,
    configs: &Configs,
    op: &Refresh,
) -> Result<RefreshView> {
    let mut rejected = false;
    let waiting = match op.phase {
        RefreshPhase::Preparing | RefreshPhase::Draining | RefreshPhase::Stopping => {
            let b = blockers(conn, live, op)?;
            b.failure
                .map(|(_, p)| p)
                .unwrap_or_default()
                .into_iter()
                .chain(b.waiting)
                .collect()
        }
        RefreshPhase::Confirming | RefreshPhase::Blocked => {
            let (failed, pending) = unconfirmed(conn, live, op, RefreshStep::Rewire, "the rewire")?;
            failed.into_iter().chain(pending).collect()
        }
        RefreshPhase::Restoring if op.restored_at_ms.is_some() => {
            let (failed, pending) =
                unconfirmed(conn, live, op, RefreshStep::Restore, "the restore")?;
            rejected = !failed.is_empty();
            failed.into_iter().chain(pending).collect()
        }
        RefreshPhase::Restoring => op.refused.clone(),
        RefreshPhase::Cleanup => cleanup_waiting(conn, live, op)?,
        _ => vec![],
    };
    let mut servers = vec![];
    for node in path_servers(op) {
        if node_row(conn, &node)?.is_some() {
            servers.push(server_state(conn, live, &node)?);
        }
    }
    // The last step that changed each server, and whether its agent has it.
    let mut last: BTreeMap<&str, (RefreshStep, u64)> = BTreeMap::new();
    for commit in &op.commits {
        for (node, revision) in &commit.revisions {
            last.insert(node, (commit.step, *revision));
        }
    }
    let mut agents = vec![];
    for (node, (step, revision)) in last {
        let (state, error) = apply_state(conn, node, revision)?;
        let online = node_row(conn, node)?.is_some() && server_state(conn, live, node)?.online;
        agents.push(AgentState {
            node_id: node.into(),
            node_name: node_name(conn, node)?,
            step,
            revision,
            state,
            online,
            error,
        });
    }
    // Interrupted as things are, on the servers that carry the forwarding
    // (see [`carrying`]): a rule the stop disabled is still disabled (once
    // ended, only one it left to an operator), a target it paused is still
    // paused, or an agent has not applied a step that pauses, stops, rewires
    // or restores.
    let carrying = carrying(conn, op)?;
    let disabled = |r: &RuleRef| {
        carrying.contains(&r.node_id)
            && op
                .before
                .get(&key(&r.node_id, &r.rule_id))
                .is_some_and(|b| b.enabled)
            && rule_of(configs, &r.node_id, &r.rule_id).is_some_and(|current| !current.enabled)
    };
    let stopped_now = if matches!(op.phase, RefreshPhase::Cleanup | RefreshPhase::Finished) {
        op.unresolved
            .iter()
            .any(|u| disabled(&reference(&u.node_id, &u.rule_id)))
    } else {
        op.stopped.iter().any(disabled)
    };
    let paused_now = op.paused.iter().any(|p| {
        rule_of(configs, &p.node_id, &p.rule_id).is_some_and(|current| {
            current
                .targets
                .iter()
                .any(|t| t.address == p.address && t.via == p.via && t.paused)
        })
    });
    // A cleanup commit on such a server never hides one of those steps: the
    // cleanup waits until its agent applied the latest revision.
    let unapplied = agents.iter().any(|a| {
        carrying.contains(&a.node_id)
            && matches!(
                a.step,
                RefreshStep::Pause | RefreshStep::Stop | RefreshStep::Rewire | RefreshStep::Restore
            )
            && matches!(a.state, "pending" | "failed")
    });
    Ok(RefreshView {
        id: op.id.clone(),
        automatic: op.automatic,
        actor_id: op.actor_id.clone(),
        started_at_ms: op.started_at_ms,
        deadline_ms: op.deadline_ms,
        updated_at_ms: op.updated_at_ms,
        phase: op.phase,
        outcome: op.outcome,
        cancel_requested: op.cancel_requested,
        failed_in: op.failed_in,
        error: op.error.clone(),
        retry_error: op.retry_error.clone(),
        problems: op.problems.clone(),
        notes: op.notes.clone(),
        changes: op.changes.clone(),
        stage: stage(op, rejected),
        interrupted: stopped_now || paused_now || unapplied,
        waiting,
        servers,
        agents,
        retire_pending: if op.phase == RefreshPhase::Cleanup {
            op.retire.clone()
        } else {
            vec![]
        },
        unresolved: op.unresolved.clone(),
        commits: op.commits.clone(),
    })
}
pub(super) fn current(conn: &Connection, entry: &str) -> Result<Option<Refresh>> {
    get(conn, &refresh_key(entry))
}
/// Forgets the finished refresh of a forgotten use; one still cleaning up
/// goes on.
pub(super) fn forget(tx: &Transaction<'_>, entry: &str) -> Result<()> {
    if current(tx, entry)?.is_some_and(|op| op.phase == RefreshPhase::Finished) {
        tx.execute("DELETE FROM metadata WHERE key=?1", [refresh_key(entry)])?;
    }
    Ok(())
}
/// Whether a refresh of `entry` still changes or can still put back its
/// forwarding (its cleanup does not count).
pub(super) fn active(conn: &Connection, entry: &str) -> Result<bool> {
    Ok(current(conn, entry)?.is_some_and(|op| {
        matches!(
            op.phase,
            RefreshPhase::Preparing
                | RefreshPhase::Draining
                | RefreshPhase::Stopping
                | RefreshPhase::Confirming
                | RefreshPhase::Blocked
                | RefreshPhase::Restoring
        )
    }))
}

impl Store {
    fn live_view(&self, conn: &Connection, entry: &str) -> Result<RefreshView> {
        let op = current(conn, entry)?.context("refresh not found")?;
        let configs = topology::all_configs(conn)?;
        let mut clocks = self.3.lock().unwrap();
        let mut live = Live {
            clocks: &mut clocks,
            telemetry: &self.4,
        };
        view(conn, &mut live, &configs, &op)
    }
    /// What refreshing the forwarding `entry` of chain `id` would do; nothing
    /// is written or reserved.
    pub fn plan_chain_refresh(
        &self,
        actor: &Actor,
        id: &str,
        entry: &str,
        input: RefreshPlanInput,
    ) -> Result<RefreshPlan> {
        writer(actor, "forwardings")?;
        let timeout = timeout_secs(input.timeout_secs)?;
        let conn = self.0.lock().unwrap();
        let chain = visible_chain(&conn, actor, id)?;
        let record = use_record(&conn, &chain, entry)?;
        let mut clocks = self.3.lock().unwrap();
        let until = now_ms() + i64::try_from(timeout)? * 1000;
        let planned = plan(&conn, &mut clocks, actor, &chain, entry, &record, until)?;
        refuse_too_old(&planned)?;
        let mut live = Live {
            clocks: &mut clocks,
            telemetry: &self.4,
        };
        let mut idle_servers = vec![];
        for node in &planned.quiet {
            idle_servers.push(server_state(&conn, &mut live, node)?);
        }
        Ok(RefreshPlan {
            entry_rule_id: entry.into(),
            token: planned.token,
            up_to_date: planned.up_to_date,
            changes: planned.changes,
            conflicts: planned.conflicts,
            warnings: planned.warnings,
            notes: planned.notes,
            interrupts: !planned.up_to_date,
            timeout_secs: timeout,
            idle_servers,
            hops: planned.hops,
            expected_revisions: planned.revisions,
            result: planned.result,
            preview: planned.preview,
        })
    }
    /// Starts the previewed refresh: 409 when anything the preview covered
    /// changed. Repeating a confirmation returns the refresh it started.
    pub fn refresh_chain_use(
        &self,
        actor: &Actor,
        id: &str,
        entry: &str,
        input: RefreshInput,
    ) -> Result<RefreshView> {
        writer(actor, "forwardings")?;
        let timeout = timeout_secs(input.timeout_secs)?;
        {
            let mut conn = self.0.lock().unwrap();
            let chain = visible_chain(&conn, actor, id)?;
            let record = use_record(&conn, &chain, entry)?;
            if let Some(op) = current(&conn, entry)? {
                if op.token == input.token {
                    return self.live_view(&conn, entry);
                }
                if active(&conn, entry)? {
                    return reject(
                        409,
                        "another refresh of this forwarding is in progress; wait for it or cancel it",
                    );
                }
            }
            let mut clocks = self.3.lock().unwrap();
            let now = now_ms();
            let planned = plan(
                &conn,
                &mut clocks,
                actor,
                &chain,
                entry,
                &record,
                now + i64::try_from(timeout)? * 1000,
            )?;
            refuse_too_old(&planned)?;
            let mut stale: Vec<LineError> = vec![];
            for (node, revision) in &planned.revisions {
                let error = match input.expected_revisions.get(node) {
                    None => "this server was not part of the preview",
                    Some(expected) if expected != revision => {
                        "configuration changed since the preview"
                    }
                    Some(_) => continue,
                };
                stale.push(LineError {
                    node_id: node.clone(),
                    error: error.into(),
                });
            }
            for node in input.expected_revisions.keys() {
                if !planned.revisions.contains_key(node) {
                    stale.push(LineError {
                        node_id: node.clone(),
                        error: "this server is no longer part of the refresh".into(),
                    });
                }
            }
            if !stale.is_empty() {
                return Err(anyhow::Error::from(Rejection {
                    status: 409,
                    message:
                        "the preview is out of date: server configurations changed; preview again"
                            .into(),
                })
                .context(LineErrors(stale)));
            }
            if planned.token != input.token {
                return reject(
                    409,
                    "the preview is out of date: the chain, its groups or the forwarding changed; preview again",
                );
            }
            if planned.up_to_date {
                return reject(
                    409,
                    "this forwarding already uses its groups' current servers",
                );
            }
            if !planned.conflicts.is_empty() {
                let lines: Vec<LineError> = planned
                    .conflicts
                    .iter()
                    .filter_map(|c| {
                        c.node_id.as_ref().map(|node| LineError {
                            node_id: node.clone(),
                            error: c.message.clone(),
                        })
                    })
                    .collect();
                return Err(anyhow::Error::from(Rejection {
                    status: 409,
                    message: format!(
                        "this forwarding cannot be refreshed: {}",
                        planned
                            .conflicts
                            .iter()
                            .map(|c| c.message.clone())
                            .collect::<Vec<_>>()
                            .join("; ")
                    ),
                })
                .context(LineErrors(lines)));
            }
            begin(
                &mut conn,
                &mut clocks,
                actor,
                &chain,
                entry,
                &record,
                planned,
                timeout,
                false,
                now,
            )?;
        }
        self.2.config.notify_waiters();
        self.advance(Some(entry), now_ms())?;
        let conn = self.0.lock().unwrap();
        self.live_view(&conn, entry)
    }
    /// Asks a refresh to stop and put the forwarding back, before its
    /// rewire; `keep_stopped` keeps the rules its stop disabled stopped,
    /// which needs write permission on each of their servers. A blocked
    /// refresh is dismissed instead: it ends as published. A restoring one
    /// is ended where it is, leaving what it did not put back to an operator.
    pub fn cancel_chain_refresh(
        &self,
        actor: &Actor,
        id: &str,
        entry: &str,
        input: CancelInput,
    ) -> Result<RefreshView> {
        writer(actor, "forwardings")?;
        {
            let mut conn = self.0.lock().unwrap();
            let chain = visible_chain(&conn, actor, id)?;
            use_record(&conn, &chain, entry)?;
            let Some(mut op) = current(&conn, entry)? else {
                return reject(404, "this forwarding has no refresh");
            };
            let revocable = matches!(
                op.phase,
                RefreshPhase::Preparing | RefreshPhase::Draining | RefreshPhase::Stopping
            );
            if input.keep_stopped && !revocable {
                return reject(
                    409,
                    "the refresh can no longer keep rules stopped: its rewire or restore is published. Disable the rule the ordinary way instead",
                );
            }
            let ending = op.phase == RefreshPhase::Restoring;
            if !revocable && !ending && op.phase != RefreshPhase::Blocked {
                return reject(409, "this refresh can no longer be cancelled");
            }
            if input.keep_stopped {
                // A server deleted since (as one that left and never came
                // back) has nothing left to keep stopped.
                let nodes: BTreeSet<&String> = op.stopped.iter().map(|r| &r.node_id).collect();
                for node in nodes {
                    if node_row(&conn, node)?.is_some() {
                        require_node(&conn, actor, node, true)?;
                    }
                }
            }
            if ending {
                // Ends the restore where it is (see `end_restore`).
                if !op.end_requested {
                    op.end_requested = true;
                    let tx = conn.transaction()?;
                    put(&tx, &refresh_key(entry), &op)?;
                    audit_refresh(&tx, &actor.id, &op, "end_restore")?;
                    tx.commit()?;
                }
            } else if !op.cancel_requested || (input.keep_stopped && !op.keep_stopped) {
                op.cancel_requested = true;
                op.keep_stopped |= input.keep_stopped;
                let tx = conn.transaction()?;
                put(&tx, &refresh_key(entry), &op)?;
                audit_refresh(
                    &tx,
                    &actor.id,
                    &op,
                    if input.keep_stopped {
                        "cancel_keep_stopped"
                    } else {
                        "cancel"
                    },
                )?;
                tx.commit()?;
            }
        }
        self.advance(Some(entry), now_ms())?;
        let conn = self.0.lock().unwrap();
        self.live_view(&conn, entry)
    }
    /// Turns automatic refresh of one forwarding on or off.
    pub fn set_chain_auto_sync(
        &self,
        actor: &Actor,
        id: &str,
        entry: &str,
        input: AutoSyncInput,
    ) -> Result<UseView> {
        writer(actor, "forwardings")?;
        let timeout = timeout_secs(input.timeout_secs)?;
        let mut conn = self.0.lock().unwrap();
        let chain = visible_chain(&conn, actor, id)?;
        let mut record = use_record(&conn, &chain, entry)?;
        record.auto_sync = input.auto_sync.then(|| AutoSync {
            enabled_by: actor.id.clone(),
            enabled_at_ms: now_ms(),
            timeout_secs: timeout,
            failures: 0,
            next_attempt_ms: 0,
            last_result: None,
        });
        record.auto_sync_stopped = None;
        let tx = conn.transaction()?;
        put(&tx, &format!("{USE}{entry}"), &record)?;
        audit(
            &tx,
            &actor.id,
            "forwarding_chain.auto_sync",
            &chain.id,
            &serde_json::json!({"entry_rule_id": entry, "enabled": input.auto_sync, "timeout_secs": timeout})
                .to_string(),
        )?;
        tx.commit()?;
        let configs = topology::all_configs(&conn)?;
        let groups = all_groups(&conn)?;
        let mut clocks = self.3.lock().unwrap();
        let mut live = Live {
            clocks: &mut clocks,
            telemetry: &self.4,
        };
        use_view(&conn, &mut live, &configs, &groups, &chain, entry, &record)
    }
    /// Moves every refresh on by one step and starts automatic ones that are
    /// due; `only` limits it to one forwarding's refresh. Each record is
    /// handled on its own: one that cannot be read or moved is logged and
    /// the others go on.
    fn advance(&self, only: Option<&str>, now: i64) -> Result<()> {
        let published = {
            let mut conn = self.0.lock().unwrap();
            let mut clocks = self.3.lock().unwrap();
            let mut live = Live {
                clocks: &mut clocks,
                telemetry: &self.4,
            };
            let mut snap = Snapshot::default();
            let mut published = false;
            for (entry, value) in active_records(&conn)? {
                if only.is_some_and(|only| only != entry) {
                    continue;
                }
                let moved = serde_json::from_str::<Refresh>(&value)
                    .map_err(anyhow::Error::from)
                    .and_then(|op| step(&mut conn, &mut live, &mut snap, op, now));
                match moved {
                    Ok(changed) => {
                        if changed {
                            snap.stale();
                        }
                        published |= changed;
                    }
                    Err(error) => {
                        snap.stale();
                        tracing::error!(%error, entry_rule_id = %entry, "chain refresh step failed; retrying")
                    }
                }
            }
            // Neither holds up the refreshes above, now or on the next pass.
            if only.is_none() {
                match automatic(&mut conn, &mut live, now) {
                    Ok(changed) => published |= changed,
                    Err(error) => {
                        tracing::error!(%error, "automatic chain refreshes failed; retrying")
                    }
                }
                if let Err(error) = forget_orphans(&mut conn) {
                    tracing::error!(%error, "finished chain refreshes could not be forgotten; retrying");
                }
            }
            published
        };
        if published {
            self.2.config.notify_waiters();
        }
        Ok(())
    }
    /// One pass of the controller's refresh task.
    pub fn advance_chain_refreshes(&self) -> Result<()> {
        self.advance(None, now_ms())
    }
    /// The same pass as of `now` (ms since the epoch), for deadlines and
    /// automatic-refresh backoff in tests.
    pub fn advance_chain_refreshes_at(&self, now: i64) -> Result<()> {
        self.advance(None, now)
    }
}
