//! Declared cross-node graph. Rules remain the authoritative configuration;
//! edges identify a downstream rule, rather than a second editable graph copy.
use crate::model::*;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};
use std::collections::{BTreeMap, BTreeSet, VecDeque};

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigUpdate {
    pub node_id: String,
    pub expected_revision: u64,
    pub rules: Vec<Rule>,
    /// Node-wide byte rate: omit to keep the current cap, `null` clears it.
    #[serde(
        default,
        deserialize_with = "explicit",
        skip_serializing_if = "Option::is_none"
    )]
    pub rate_bytes_per_sec: Option<Option<u64>>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ConfigBatch {
    pub updates: Vec<ConfigUpdate>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ConfigChange {
    pub node_id: String,
    pub from_revision: u64,
    pub to_revision: u64,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub modified: Vec<String>,
    pub rule_changes: Vec<RuleChange>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleChange {
    pub rule_id: String,
    pub before: Option<Rule>,
    pub after: Option<Rule>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BatchResult {
    pub configs: Vec<NodeConfig>,
    pub changes: Vec<ConfigChange>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Edge {
    pub from: RuleRef,
    pub to: RuleRef,
    pub address: String,
    pub weight: u16,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Graph {
    pub edges: Vec<Edge>,
    pub roots: Vec<RuleRef>,
}
pub fn endpoint(address: &str) -> Result<(String, u16)> {
    validate_target(address)?;
    if let Ok(address) = address.parse::<std::net::SocketAddr>() {
        Ok((canonical_ip(address.ip()).to_string(), address.port()))
    } else {
        let (host, port) = address.rsplit_once(':').unwrap();
        Ok((
            host.trim_end_matches('.').to_ascii_lowercase(),
            port.parse()?,
        ))
    }
}
fn width(rule: &Rule) -> u16 {
    rule.listen_end_port.unwrap_or(rule.listen.port()) - rule.listen.port()
}
fn compatible(source: &Rule, target: &Target, destination: &Rule) -> Result<()> {
    ensure!(
        source.outbound_multipath.is_some() == destination.inbound_multipath.is_some(),
        "next-hop multipath settings do not match"
    );
    if let (Some(client), Some(server)) =
        (&source.outbound_multipath, &destination.inbound_multipath)
    {
        ensure!(
            client.paths.len() <= usize::from(server.max_paths),
            "next-hop multipath path limit is too small"
        );
        ensure!(
            client.mode != crate::multipath::Mode::Replicate || server.allow_replication,
            "next hop rejects multipath replication"
        );
    }
    ensure!(
        (!source.protocol.tcp() || destination.protocol.tcp())
            && (!source.protocol.udp() || destination.protocol.udp()),
        "next hop does not accept the source protocol"
    );
    ensure!(
        !source.enabled || destination.enabled,
        "enabled rule points to a disabled next hop; stop its predecessors in the same batch"
    );
    ensure!(
        source.port_mapping != PortMapping::Offset || width(source) <= width(destination),
        "next-hop listener range is too short for offset mapping"
    );
    ensure!(
        target.tls.is_some() == destination.inbound_tls.is_some(),
        "next-hop TLS settings do not match"
    );
    if destination
        .inbound_tls
        .as_ref()
        .is_some_and(|tls| tls.client_ca.is_some())
    {
        ensure!(
            target
                .tls
                .as_ref()
                .is_some_and(|tls| tls.identity.is_some()),
            "next hop requires a TLS client identity"
        );
    }
    match (&target.websocket, &destination.inbound_websocket) {
        (None, None) => {}
        (Some(client), Some(server)) => {
            ensure!(
                client.path == server.path,
                "next-hop WebSocket path mismatch"
            );
            ensure!(
                server
                    .host
                    .as_ref()
                    .is_none_or(|host| host.eq_ignore_ascii_case(&client.host)),
                "next-hop WebSocket Host mismatch"
            );
            ensure!(
                client
                    .origin
                    .as_ref()
                    .is_none_or(|origin| server.allowed_origins.contains(origin)),
                "next-hop WebSocket Origin rejected"
            );
        }
        _ => anyhow::bail!("next-hop WebSocket settings do not match"),
    }
    match (&target.proxy_protocol, &destination.inbound_proxy) {
        (None, None) => {}
        (Some(client), Some(server)) => {
            ensure!(
                client.placement == server.placement,
                "next-hop PROXY placement mismatch"
            );
            ensure!(
                matches!(
                    (client.version, server.version),
                    (_, ProxyAccept::Any)
                        | (ProxyVersion::V1, ProxyAccept::V1)
                        | (ProxyVersion::V2, ProxyAccept::V2)
                ),
                "next-hop PROXY version mismatch"
            );
            ensure!(
                target.prewarm.is_none() || server.accept_prewarmed,
                "next hop does not accept pre-warmed connections"
            );
        }
        _ => anyhow::bail!("next-hop PROXY settings do not match"),
    }
    Ok(())
}

pub fn validate(configs: &[NodeConfig]) -> Result<Graph> {
    let mut rules = BTreeMap::new();
    let mut addresses = BTreeMap::new();
    let mut identities = BTreeSet::new();
    for config in configs {
        config.validate()?;
        for rule in &config.rules {
            let reference = RuleRef {
                node_id: config.node_id.clone(),
                rule_id: rule.id.clone(),
            };
            ensure!(
                identities.insert(&rule.id),
                "rule identity occurs on more than one node"
            );
            if let Some(address) = &rule.advertise {
                let (host, port) = endpoint(address)?;
                ensure!(
                    port.checked_add(width(rule)).is_some(),
                    "advertised port range overflows"
                );
                for port in port..=port + width(rule) {
                    for tcp in [true, false] {
                        if (tcp && rule.protocol.tcp()) || (!tcp && rule.protocol.udp()) {
                            ensure!(
                                addresses
                                    .insert(
                                        (rule.tenant_id.clone(), host.clone(), port, tcp),
                                        reference.clone()
                                    )
                                    .is_none(),
                                "advertised listener/range overlaps another endpoint in this tenant"
                            );
                        }
                    }
                }
            }
            rules.insert(reference, rule);
        }
    }
    let mut outgoing: BTreeMap<RuleRef, BTreeSet<RuleRef>> = BTreeMap::new();
    let mut incoming: BTreeMap<RuleRef, usize> = rules.keys().cloned().map(|r| (r, 0)).collect();
    let mut edges = Vec::new();
    for (reference, rule) in &rules {
        for target in &rule.targets {
            let (host, port) = endpoint(&target.address)?;
            if let Some(next) = &target.via {
                let destination = rules
                    .get(next)
                    .ok_or_else(|| anyhow::anyhow!("next-hop node or rule does not exist"))?;
                ensure!(
                    rule.tenant_id == destination.tenant_id,
                    "cross-tenant next hops require a separate sharing authorization"
                );
                let advertised = destination
                    .advertise
                    .as_deref()
                    .ok_or_else(|| anyhow::anyhow!("next hop has no advertised endpoint"))?;
                let (advertised_host, advertised_port) = endpoint(advertised)?;
                let matches = if rule.outbound_multipath.is_some() {
                    host == advertised_host
                        && (advertised_port..=advertised_port + width(destination)).contains(&port)
                } else {
                    (advertised_host, advertised_port) == (host, port)
                };
                ensure!(
                    matches,
                    "target address differs from the referenced endpoint; update all affected rules together"
                );
                compatible(rule, target, destination)?;
                if outgoing
                    .entry(reference.clone())
                    .or_default()
                    .insert(next.clone())
                {
                    *incoming.get_mut(next).unwrap() += 1;
                }
                edges.push(Edge {
                    from: reference.clone(),
                    to: next.clone(),
                    address: target.address.clone(),
                    weight: target.weight,
                });
            } else {
                // A known advertised endpoint must remain a typed reference;
                // deleting only `via` must not bypass graph validation.
                let end = if rule.port_mapping == PortMapping::Offset {
                    port + width(rule)
                } else {
                    port
                };
                for port in port..=end {
                    for tcp in [true, false] {
                        if (tcp && rule.protocol.tcp()) || (!tcp && rule.protocol.udp()) {
                            ensure!(
                                !addresses.contains_key(&(
                                    rule.tenant_id.clone(),
                                    host.clone(),
                                    port,
                                    tcp
                                )),
                                "target is an advertised endpoint; use an explicit next-hop reference"
                            );
                        }
                    }
                }
            }
        }
    }
    let roots: Vec<_> = incoming
        .iter()
        .filter(|(_, n)| **n == 0)
        .map(|(r, _)| r.clone())
        .collect();
    let mut ready: VecDeque<_> = roots.clone().into();
    let mut visited = 0;
    while let Some(current) = ready.pop_front() {
        visited += 1;
        if let Some(next) = outgoing.get(&current) {
            for next in next {
                let count = incoming.get_mut(next).unwrap();
                *count -= 1;
                if *count == 0 {
                    ready.push_back(next.clone());
                }
            }
        }
    }
    ensure!(
        visited == rules.len(),
        "cross-node topology contains a cycle"
    );
    Ok(Graph { edges, roots })
}

pub fn participates(rule: &Rule) -> bool {
    rule.advertise.is_some() || rule.targets.iter().any(|target| target.via.is_some())
}
/// Weights and balancing can change without changing the directed graph.
pub fn route_signature(rule: &Rule) -> serde_json::Value {
    serde_json::json!({"listen":rule.listen,"listen_end_port":rule.listen_end_port,"port_mapping":rule.port_mapping,"advertise":rule.advertise,"protocol":rule.protocol,"inbound_tls":rule.inbound_tls,"inbound_proxy":rule.inbound_proxy,"inbound_websocket":rule.inbound_websocket,"inbound_multipath":rule.inbound_multipath,"outbound_multipath":rule.outbound_multipath,"outbound_bind":rule.outbound_bind,"dns_cache":rule.dns_cache,"targets":rule.targets.iter().map(|t|serde_json::json!({"address":t.address,"via":t.via,"tls":t.tls,"proxy":t.proxy_protocol,"websocket":t.websocket})).collect::<Vec<_>>()})
}
