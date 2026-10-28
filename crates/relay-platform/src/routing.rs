//! Reject loops among listeners owned by this Engine, including DNS resolved edges.
use crate::model::{NodeConfig, canonical_address, canonical_ip};
use anyhow::{Context, Result, ensure};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::{IpAddr, SocketAddr},
    sync::{Arc, Mutex},
};

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
pub(crate) struct Endpoint {
    pub address: SocketAddr,
    pub tcp: bool,
}
type Graph = HashMap<Endpoint, HashSet<Endpoint>>;

#[derive(Default)]
pub(crate) struct Topology {
    listeners: HashMap<(u16, bool), Vec<Endpoint>>,
    gateway_endpoints: HashSet<Endpoint>,
    local_ips: HashSet<IpAddr>,
    edges: Graph,
}
impl Topology {
    pub fn build(config: &NodeConfig, local_ips: HashSet<IpAddr>) -> Result<Self> {
        let mut topology = Self {
            local_ips,
            ..Self::default()
        };
        for rule in config.rules.iter().filter(|r| r.enabled) {
            let mut endpoints = vec![];
            for address in rule.listen_addresses() {
                for tcp in [true, false] {
                    if (tcp && rule.protocol.tcp()) || (!tcp && rule.protocol.udp()) {
                        endpoints.push(Endpoint { address, tcp });
                    }
                }
            }
            if let Some(gateway) = &rule.protocol_gateway {
                let endpoint = Endpoint {
                    address: gateway.listen,
                    tcp: !gateway.protocol.uses_udp_socket(),
                };
                topology.gateway_endpoints.insert(endpoint);
                endpoints.push(endpoint);
            }
            for endpoint in endpoints {
                let Endpoint { address, tcp } = endpoint;
                if !address.ip().is_unspecified() {
                    topology.local_ips.insert(address.ip());
                }
                let bucket = topology.listeners.entry((address.port(), tcp)).or_default();
                ensure!(
                    !bucket
                        .iter()
                        .any(|e| e.address.is_ipv4() == address.is_ipv4()
                            && (e.address.ip().is_unspecified()
                                || address.ip().is_unspecified()
                                || e.address.ip() == address.ip())),
                    "overlapping listeners at {address}"
                );
                bucket.push(endpoint);
            }
        }
        for rule in config.rules.iter().filter(|r| r.enabled) {
            for address in rule.listen_addresses() {
                for index in 0..rule.targets.len() {
                    let Ok(target) = rule
                        .target_address(index, address.port())?
                        .parse::<SocketAddr>()
                    else {
                        continue;
                    };
                    for tcp in [true, false] {
                        if (tcp && !rule.protocol.tcp()) || (!tcp && !rule.protocol.udp()) {
                            continue;
                        }
                        if let Some(destination) =
                            topology.destination(canonical_address(target), tcp)
                        {
                            topology
                                .edges
                                .entry(Endpoint { address, tcp })
                                .or_default()
                                .insert(destination);
                        }
                    }
                }
            }
        }
        topology.check_acyclic()?;
        Ok(topology)
    }

    fn destination(&self, address: SocketAddr, tcp: bool) -> Option<Endpoint> {
        let local = address.ip().is_loopback() || self.local_ips.contains(&address.ip());
        self.listeners
            .get(&(address.port(), tcp))?
            .iter()
            .copied()
            .find(|e| {
                e.address.is_ipv4() == address.is_ipv4()
                    && (e.address.ip() == address.ip()
                        || (e.address.ip().is_unspecified() && local))
            })
    }

    fn check_acyclic(&self) -> Result<()> {
        let mut incoming = HashMap::<Endpoint, usize>::new();
        for (&source, destinations) in &self.edges {
            incoming.entry(source).or_default();
            for &destination in destinations {
                *incoming.entry(destination).or_default() += 1;
            }
        }
        let mut queue: VecDeque<_> = incoming
            .iter()
            .filter_map(|(&e, &n)| (n == 0).then_some(e))
            .collect();
        let mut count = 0;
        while let Some(source) = queue.pop_front() {
            count += 1;
            if let Some(edges) = self.edges.get(&source) {
                for destination in edges {
                    let n = incoming.get_mut(destination).unwrap();
                    *n -= 1;
                    if *n == 0 {
                        queue.push_back(*destination);
                    }
                }
            }
        }
        ensure!(count == incoming.len(), "node-local forwarding cycle");
        Ok(())
    }
}

pub(crate) fn local_ips() -> Result<HashSet<IpAddr>> {
    Ok(if_addrs::get_if_addrs()
        .context("cannot enumerate local IPs for loop protection")?
        .iter()
        .map(|i| canonical_ip(i.ip()))
        .collect())
}
pub(crate) fn validate_static(config: &NodeConfig) -> Result<()> {
    Topology::build(config, HashSet::new()).map(|_| ())
}

#[derive(Default)]
struct State {
    topology: Topology,
    active: HashMap<Endpoint, HashMap<Endpoint, usize>>,
}
#[derive(Default)]
pub(crate) struct Routes(Mutex<State>);
impl Routes {
    pub fn install(&self, topology: Topology) {
        self.0.lock().unwrap().topology = topology;
    }
    pub fn reserve(self: &Arc<Self>, source: Endpoint, target: SocketAddr) -> Result<LoopGuard> {
        let target = canonical_address(target);
        let mut state = self.0.lock().unwrap();
        // A newly attached local address must not turn a formerly remote target into a loop.
        if !target.ip().is_loopback()
            && !state.topology.local_ips.contains(&target.ip())
            && state
                .topology
                .listeners
                .get(&(target.port(), source.tcp))
                .is_some_and(|endpoints| {
                    endpoints.iter().any(|e| {
                        e.address.is_ipv4() == target.is_ipv4() && e.address.ip().is_unspecified()
                    })
                })
        {
            state.topology.local_ips.extend(local_ips()?);
        }
        let Some(destination) = state.topology.destination(target, source.tcp) else {
            return Ok(LoopGuard(None));
        };
        ensure!(
            !state.topology.gateway_endpoints.contains(&destination),
            "native egress cannot target a gateway owned by this node"
        );
        let already_active = state
            .active
            .get(&source)
            .is_some_and(|e| e.contains_key(&destination));
        if !already_active {
            let mut visited = HashSet::new();
            let mut pending = vec![destination];
            while let Some(endpoint) = pending.pop() {
                ensure!(
                    endpoint != source,
                    "resolved target would create a node-local forwarding cycle"
                );
                if !visited.insert(endpoint) {
                    continue;
                }
                if let Some(edges) = state.topology.edges.get(&endpoint) {
                    pending.extend(edges.iter().copied());
                }
                if let Some(edges) = state.active.get(&endpoint) {
                    pending.extend(edges.keys().copied());
                }
            }
        }
        *state
            .active
            .entry(source)
            .or_default()
            .entry(destination)
            .or_default() += 1;
        Ok(LoopGuard(Some((self.clone(), source, destination))))
    }
}
pub(crate) struct LoopGuard(Option<(Arc<Routes>, Endpoint, Endpoint)>);
impl Drop for LoopGuard {
    fn drop(&mut self) {
        if let Some((routes, source, destination)) = &self.0 {
            let mut state = routes.0.lock().unwrap();
            let edges = state.active.get_mut(source).unwrap();
            let count = edges.get_mut(destination).unwrap();
            *count -= 1;
            if *count == 0 {
                edges.remove(destination);
            }
            if edges.is_empty() {
                state.active.remove(source);
            }
        }
    }
}
