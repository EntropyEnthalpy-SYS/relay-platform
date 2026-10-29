//! Read-only endpoint proposals. Config revisions and final graph validation
//! arbitrate competing drafts; only publication assigns a managed listener.
use super::*;
use crate::node::{AllocatedEndpoint, EndpointAllocation, EndpointRequest, ForwardingDefaults};
use std::collections::{BTreeMap, HashSet};
use std::net::SocketAddr;

fn infer(config: &NodeConfig) -> Option<ForwardingDefaults> {
    let mut candidates = Vec::new();
    for rule in &config.rules {
        // A gateway's private bridge says nothing about its public endpoint.
        if rule.protocol_gateway.is_some() {
            continue;
        }
        let (host, public_port) = if let Some(address) = &rule.advertise {
            crate::topology::endpoint(address).ok()?
        } else if !rule.listen.ip().is_unspecified() {
            (
                canonical_ip(rule.listen.ip()).to_string(),
                rule.listen.port(),
            )
        } else {
            continue;
        };
        let candidate = (
            host,
            rule.listen.ip(),
            i32::from(public_port) - i32::from(rule.listen.port()),
        );
        if !candidates.contains(&candidate) {
            candidates.push(candidate);
        }
    }
    if candidates.len() != 1 {
        return None;
    }
    let (host, ip, delta) = candidates.remove(0);
    // Arbitrary existing NAT mappings do not establish a whole usable range.
    // Ask for confirmed range settings instead of extrapolating one mapped port.
    if delta != 0 {
        return None;
    }
    let defaults = ForwardingDefaults {
        host,
        listen_ip: Some(ip),
        ..Default::default()
    };
    defaults.validate().ok()?;
    Some(defaults)
}

fn ports(config: &NodeConfig) -> HashSet<u16> {
    config
        .rules
        .iter()
        .flat_map(|rule| {
            (rule.listen.port()..=rule.listen_end_port.unwrap_or(rule.listen.port())).chain(
                rule.protocol_gateway
                    .as_ref()
                    .map(|gateway| gateway.listen.port()),
            )
        })
        .collect()
}

impl Store {
    pub fn allocate_endpoints(
        &self,
        actor: &Actor,
        request: EndpointRequest,
    ) -> Result<EndpointAllocation> {
        if !actor.may_write() {
            return reject(403, "read-only role cannot allocate rule endpoints");
        }
        if request.hops.is_empty() || request.hops.len() > 16 {
            return reject(400, "endpoint allocation requires 1..16 different nodes");
        }
        let conn = self.0.lock().unwrap();
        let mut selected = HashSet::new();
        let mut tenant = None;
        for hop in &request.hops {
            if !selected.insert(hop.node_id.clone()) {
                return reject(400, "each path hop requires a different node");
            }
            let next_tenant = require_node(&conn, actor, &hop.node_id, true)?;
            if tenant
                .as_ref()
                .is_some_and(|current| current != &next_tenant)
            {
                return reject(400, "all path nodes must belong to the same tenant");
            }
            tenant = Some(next_tenant);
            match (&hop.listen, &hop.advertise) {
                (Some(listen), Some(address)) => {
                    if listen.port() == 0 || listen.ip().is_multicast() {
                        return reject(400, "invalid manual listener");
                    }
                    validate_target(address).map_err(|error| Rejection {
                        status: 400,
                        message: error.to_string(),
                    })?;
                }
                (None, None) => {}
                _ => {
                    return reject(
                        400,
                        "manual endpoints require both listen and reachable addresses",
                    );
                }
            }
        }
        let configs = super::topology::all_configs(&conn)?;
        let mut defaults = BTreeMap::new();
        let mut used_public = HashSet::new();
        let mut used_local: BTreeMap<_, _> = configs
            .iter()
            .map(|(id, config)| (id.clone(), ports(config)))
            .collect();
        for (id, config) in &configs {
            let saved = node_profiles::read(&conn, id)?.settings.forwarding;
            let source = if saved.is_some() {
                "profile"
            } else {
                "existing_rule"
            };
            let value = saved.or_else(|| infer(config));
            for rule in &config.rules {
                if let Some(address) = &rule.advertise {
                    let (host, start) = crate::topology::endpoint(address)?;
                    for port in start
                        ..=start
                            + (rule.listen_end_port.unwrap_or(rule.listen.port())
                                - rule.listen.port())
                    {
                        used_public.insert((host.clone(), port));
                    }
                }
                if let Some(gateway) = &rule.protocol_gateway
                    && !gateway.listen.ip().is_unspecified()
                {
                    used_public.insert((
                        canonical_ip(gateway.listen.ip()).to_string(),
                        gateway.listen.port(),
                    ));
                }
                // Explicit local IPs also protect same-host Agents whose older
                // rules had no advertised address or forwarding defaults.
                if !rule.listen.ip().is_unspecified() {
                    for port in
                        rule.listen.port()..=rule.listen_end_port.unwrap_or(rule.listen.port())
                    {
                        used_public.insert((canonical_ip(rule.listen.ip()).to_string(), port));
                    }
                }
            }
            if let Some(value) = &value {
                for port in &used_local[id] {
                    if value.public_port_start.is_none() {
                        used_public.insert((value.canonical_host(), *port));
                    } else if (value.port_start..=value.port_end).contains(port) {
                        used_public.insert((value.canonical_host(), value.public_port(*port)));
                    }
                }
            }
            defaults.insert(id.clone(), (value, source));
        }

        // Reserve every explicit draft endpoint first, regardless of path order.
        let mut manual = BTreeMap::new();
        for hop in &request.hops {
            if let (Some(listen), Some(address)) = (hop.listen, &hop.advertise) {
                let endpoint = crate::topology::endpoint(address)?;
                if used_local[&hop.node_id].contains(&listen.port())
                    || used_public.contains(&endpoint)
                {
                    manual.insert(hop.node_id.clone(), false);
                } else {
                    used_local
                        .get_mut(&hop.node_id)
                        .unwrap()
                        .insert(listen.port());
                    used_public.insert(endpoint);
                    manual.insert(hop.node_id.clone(), true);
                }
            }
        }
        let mut endpoints = Vec::new();
        for hop in &request.hops {
            let (value, source) = &defaults[&hop.node_id];
            let mut result = AllocatedEndpoint {
                node_id: hop.node_id.clone(),
                listen: None,
                advertise: None,
                source: (*source).into(),
                defaults: value.clone(),
                error: None,
            };
            if let Some(available) = manual.get(&hop.node_id) {
                result.source = "manual".into();
                if *available {
                    result.listen = hop.listen;
                    result.advertise = hop.advertise.clone();
                } else {
                    result.error = Some("port_in_use".into());
                }
            } else if let Some(value) = value {
                let host = value.canonical_host();
                let port = (value.port_start..=value.port_end).find(|port| {
                    !used_local[&hop.node_id].contains(port)
                        && !used_public.contains(&(host.clone(), value.public_port(*port)))
                });
                if let Some(port) = port {
                    let public = value.public_port(port);
                    result.listen = Some(SocketAddr::new(value.bind_ip(), port));
                    result.advertise = Some(value.endpoint(public));
                    used_local.get_mut(&hop.node_id).unwrap().insert(port);
                    used_public.insert((host, public));
                } else {
                    result.error = Some("ports_exhausted".into());
                }
            } else {
                result.error = Some("address_required".into());
            }
            endpoints.push(result);
        }
        Ok(EndpointAllocation {
            endpoints,
            configs: request
                .hops
                .iter()
                .map(|hop| configs[&hop.node_id].clone())
                .collect(),
        })
    }
}

#[cfg(test)]
#[path = "endpoint_allocation_tests.rs"]
mod tests;
