//! WireGuard network persistence. Networks, members and the public keys that
//! node agents report live in metadata, so the schema and recovery log stay
//! unchanged. Only system administrators manage networks.
use super::*;
use crate::wireguard::{
    self as wg, Desired, Issued, Kind, MAX_MEMBERS, MAX_NETWORKS, MAX_NODE_NETWORKS, Member,
    MemberInput, MemberView, Network, NetworkInput, NetworkView, NodeReadiness, PairView, Path,
    PeerReport, Report, View,
};
use std::{collections::HashMap, net::Ipv4Addr};

const FEATURE: &str = "wireguard";
/// A device counts as connected while its newest handshake is this recent.
const CONNECTED_S: u64 = 180;

fn read<T: serde::de::DeserializeOwned>(
    conn: &Connection,
    kind: &str,
    id: &str,
) -> Result<Option<T>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            [format!("wg_{kind}:{id}")],
            |r| r.get(0),
        )
        .optional()?;
    Ok(raw.map(|value| serde_json::from_str(&value)).transpose()?)
}
fn write<T: Serialize>(tx: &Transaction<'_>, kind: &str, id: &str, value: &T) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![format!("wg_{kind}:{id}"), serde_json::to_string(value)?],
    )?;
    Ok(())
}
fn remove(tx: &Transaction<'_>, kind: &str, id: &str) -> Result<()> {
    tx.execute(
        "DELETE FROM metadata WHERE key=?1",
        [format!("wg_{kind}:{id}")],
    )?;
    Ok(())
}
fn all<T: serde::de::DeserializeOwned>(conn: &Connection, kind: &str) -> Result<Vec<T>> {
    let mut q = conn.prepare("SELECT value FROM metadata WHERE key GLOB ?1 ORDER BY key")?;
    let rows: Vec<String> = q
        .query_map([format!("wg_{kind}:*")], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    rows.into_iter()
        .map(|value| serde_json::from_str(&value).context("invalid stored WireGuard data"))
        .collect()
}
/// Node id to the public key its agent reported.
fn node_keys(conn: &Connection) -> Result<HashMap<String, String>> {
    let mut q =
        conn.prepare("SELECT substr(key,13),value FROM metadata WHERE key GLOB 'wg_node_key:*'")?;
    let rows = q
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(rows)
}
fn members_of(conn: &Connection, network: &str) -> Result<Vec<Member>> {
    let mut members: Vec<Member> = all::<Member>(conn, "member")?
        .into_iter()
        .filter(|m| m.network_id == network)
        .collect();
    members.sort_by_key(|m| m.address);
    Ok(members)
}
/// Networks; the feature cannot be switched off while any exist.
pub(super) fn network_count(conn: &Connection) -> Result<usize> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM metadata WHERE key GLOB 'wg_network:*'",
        [],
        |r| r.get(0),
    )?)
}

/// Keeps the public key a node's agent reports, written only when it changes.
pub(super) fn observe(tx: &Transaction<'_>, node: &str, report: Option<&Report>) -> Result<()> {
    let Some(key) = report
        .and_then(|r| r.public_key.as_deref())
        .filter(|k| wg::valid_key(k))
    else {
        return Ok(());
    };
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES('wg_node_key:'||?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value WHERE value<>excluded.value",
        params![node, key],
    )?;
    Ok(())
}

/// What `node` should have: one interface per network it is a member of.
/// Empty while the feature is off.
pub(super) fn desired(conn: &Connection, node: &str) -> Result<Desired> {
    if !features::enabled(conn, FEATURE)? {
        return Ok(Desired::new(false, vec![]));
    }
    let members = all::<Member>(conn, "member")?;
    let mine: Vec<&str> = members
        .iter()
        .filter(|m| m.node_id.as_deref() == Some(node))
        .map(|m| m.network_id.as_str())
        .collect();
    if mine.is_empty() {
        return Ok(Desired::new(true, vec![]));
    }
    let keys = node_keys(conn)?;
    let mut interfaces = vec![];
    for network in all::<Network>(conn, "network")?
        .iter()
        .filter(|n| mine.contains(&n.id.as_str()))
    {
        let mut peers: Vec<Member> = members
            .iter()
            .filter(|m| m.network_id == network.id)
            .cloned()
            .collect();
        peers.sort_by_key(|m| m.address);
        // One broken network must not stop the node's sync.
        match wg::render(network, &peers, &keys, node) {
            Ok(interface) => interfaces.extend(interface),
            Err(error) => {
                tracing::warn!(%error, network = %network.id, "WireGuard network skipped")
            }
        }
    }
    Ok(Desired::new(true, interfaces))
}

fn require_admin(actor: &Actor) -> Result<()> {
    if actor.role != Role::SystemAdmin {
        return reject(403, "WireGuard networks require a system administrator");
    }
    Ok(())
}
fn invalid<T>(error: anyhow::Error) -> Result<T> {
    reject(400, format!("{error:#}"))
}
fn network(conn: &Connection, id: &str) -> Result<Network> {
    match read(conn, "network", id)? {
        Some(network) => Ok(network),
        None => reject(404, "WireGuard network not found"),
    }
}
fn member(conn: &Connection, id: &str) -> Result<Member> {
    match read(conn, "member", id)? {
        Some(member) => Ok(member),
        None => reject(404, "WireGuard member not found"),
    }
}
fn port_of(network: &Network, member: &Member) -> u16 {
    member.listen_port.unwrap_or(network.listen_port)
}
/// Each interface on a node needs its own UDP port.
fn port_clash(conn: &Connection, node: &str, port: u16, except: &str) -> Result<()> {
    for other in all::<Member>(conn, "member")?
        .iter()
        .filter(|m| m.node_id.as_deref() == Some(node) && m.network_id != except)
    {
        if let Some(network) = read::<Network>(conn, "network", &other.network_id)?
            && port_of(&network, other) == port
        {
            return reject(
                409,
                format!(
                    "the node already uses UDP port {port} for the network {}; give this member its own port",
                    network.name
                ),
            );
        }
    }
    Ok(())
}

fn network_fields(
    conn: &Connection,
    input: NetworkInput,
    current: Option<&Network>,
) -> Result<Network> {
    let name = input.name.trim().to_string();
    if name.is_empty() || name.chars().count() > 64 {
        return reject(400, "the name needs 1..64 characters");
    }
    let cidr = match (input.cidr.as_deref(), current) {
        (Some(text), _) => wg::network_cidr(text).or_else(invalid)?,
        (None, Some(current)) => current.cidr,
        (None, None) => return reject(400, "choose an address range such as 10.88.0.0/24"),
    };
    let mtu = input
        .mtu
        .unwrap_or(current.map_or(wg::DEFAULT_MTU, |c| c.mtu));
    if !(1280..=1420).contains(&mtu) {
        return reject(400, "the MTU must be 1280..1420");
    }
    let listen_port = input
        .listen_port
        .unwrap_or(current.map_or(wg::DEFAULT_PORT, |c| c.listen_port));
    if listen_port == 0 {
        return reject(400, "the port must be 1..65535");
    }
    let networks = all::<Network>(conn, "network")?;
    if current.is_none() && networks.len() >= MAX_NETWORKS {
        return reject(409, format!("at most {MAX_NETWORKS} WireGuard networks"));
    }
    for other in networks
        .iter()
        .filter(|n| Some(&n.id) != current.map(|c| &c.id))
    {
        if other.cidr.contains(&cidr) || cidr.contains(&other.cidr) {
            return reject(
                409,
                format!(
                    "{cidr} overlaps the network {} ({})",
                    other.name, other.cidr
                ),
            );
        }
    }
    let members = match current {
        Some(current) => members_of(conn, &current.id)?,
        None => vec![],
    };
    if current.is_some_and(|c| c.cidr != cidr) && !members.is_empty() {
        return reject(409, "the range cannot change while the network has members");
    }
    let relay = input.relay.filter(|r| !r.is_empty());
    if let Some(relay) = &relay
        && !members.iter().any(|m| &m.id == relay && wg::public(m))
    {
        return reject(
            400,
            "the relay must be a node of this network with a public endpoint",
        );
    }
    if let Some(current) = current.filter(|c| c.listen_port != listen_port) {
        for member in members.iter().filter(|m| m.listen_port.is_none()) {
            if let Some(node) = &member.node_id {
                port_clash(conn, node, listen_port, &current.id)?;
            }
        }
    }
    Ok(Network {
        id: current.map_or_else(|| Uuid::new_v4().to_string(), |c| c.id.clone()),
        name,
        cidr,
        mtu,
        listen_port,
        relay,
        updated_at_ms: now_ms(),
    })
}

fn member_fields(
    conn: &Connection,
    network: &Network,
    input: MemberInput,
    current: Option<&Member>,
) -> Result<Member> {
    let members = members_of(conn, &network.id)?;
    let others: Vec<&Member> = members
        .iter()
        .filter(|m| Some(&m.id) != current.map(|c| &c.id))
        .collect();
    if current.is_none() && members.len() >= MAX_MEMBERS {
        return reject(409, format!("a network has at most {MAX_MEMBERS} members"));
    }
    if let Some(current) = current
        && (current.kind != input.kind
            || input
                .node_id
                .as_ref()
                .is_some_and(|n| Some(n) != current.node_id.as_ref())
            || input
                .public_key
                .as_ref()
                .is_some_and(|k| Some(k) != current.public_key.as_ref()))
    {
        return reject(
            400,
            "the kind, node and key of a member cannot change; rekey a device for a new key",
        );
    }
    let address = match (
        input
            .address
            .as_deref()
            .map(str::trim)
            .filter(|a| !a.is_empty()),
        current,
    ) {
        (_, Some(current)) => current.address,
        (Some(text), None) => {
            let address: Ipv4Addr = text
                .parse()
                .or_else(|_| reject(400, "the address must be an IPv4 address"))?;
            if !network.cidr.hosts().any(|host| host == address) {
                return reject(
                    400,
                    format!("the address must be a host address inside {}", network.cidr),
                );
            }
            if others.iter().any(|m| m.address == address) {
                return reject(409, format!("{address} is already taken"));
            }
            address
        }
        (None, None) => match wg::free_address(network.cidr, &members) {
            Some(address) => address,
            None => return reject(409, format!("{} has no free address left", network.cidr)),
        },
    };
    let mut member = Member {
        id: current.map_or_else(|| Uuid::new_v4().to_string(), |c| c.id.clone()),
        network_id: network.id.clone(),
        kind: input.kind,
        node_id: None,
        name: String::new(),
        address,
        endpoint: None,
        listen_port: None,
        via: None,
        public_key: None,
        updated_at_ms: now_ms(),
    };
    let keys = node_keys(conn)?;
    let key_taken = |key: &str| {
        others.iter().any(|m| {
            m.public_key.as_deref() == Some(key)
                || m.node_id
                    .as_ref()
                    .and_then(|n| keys.get(n))
                    .map(String::as_str)
                    == Some(key)
        })
    };
    match input.kind {
        Kind::Node => {
            let node = input
                .node_id
                .filter(|n| !n.is_empty())
                .or_else(|| current.and_then(|c| c.node_id.clone()));
            let Some(node) = node else {
                return reject(400, "choose a node");
            };
            let exists: bool = conn.query_row(
                "SELECT EXISTS(SELECT 1 FROM nodes WHERE id=?1)",
                [&node],
                |r| r.get(0),
            )?;
            if !exists {
                return reject(404, "node not found");
            }
            if others.iter().any(|m| m.node_id.as_ref() == Some(&node)) {
                return reject(409, "this node is already in the network");
            }
            let joined = all::<Member>(conn, "member")?
                .iter()
                .filter(|m| m.node_id.as_ref() == Some(&node) && m.network_id != network.id)
                .count();
            if current.is_none() && joined >= MAX_NODE_NETWORKS {
                return reject(
                    409,
                    format!("a node can join at most {MAX_NODE_NETWORKS} networks"),
                );
            }
            match keys.get(&node) {
                None => {
                    return reject(
                        409,
                        "this node's agent has not reported a WireGuard key yet: allow WireGuard on the server (deploy/relay-agent-wireguard.conf) and wait for its next report",
                    );
                }
                Some(key) if key_taken(key) => {
                    return reject(409, "another member already uses this node's key");
                }
                Some(_) => {}
            }
            if input.listen_port == Some(0) {
                return reject(400, "the port must be 1..65535");
            }
            member.listen_port = input.listen_port;
            let port = port_of(network, &member);
            port_clash(conn, &node, port, &network.id)?;
            member.endpoint = match input
                .endpoint
                .as_deref()
                .map(str::trim)
                .filter(|e| !e.is_empty())
            {
                Some(text) => Some(wg::endpoint(text, port).or_else(invalid)?),
                None => None,
            };
            if let Some(ip) = member
                .endpoint
                .as_deref()
                .and_then(|e| e.parse::<std::net::SocketAddrV4>().ok())
                && network.cidr.contains(ip.ip())
            {
                return reject(400, "the endpoint cannot be inside the network's own range");
            }
            if let Some(current) = current
                && member.endpoint.is_none()
            {
                let devices = others
                    .iter()
                    .filter(|m| m.via.as_deref() == Some(current.id.as_str()))
                    .count();
                if devices > 0 {
                    return reject(
                        409,
                        format!(
                            "{devices} device(s) connect through this node; it needs its endpoint"
                        ),
                    );
                }
                if network.relay.as_deref() == Some(current.id.as_str()) {
                    return reject(
                        409,
                        "this node is the network's relay; it needs its endpoint",
                    );
                }
            }
            member.node_id = Some(node);
        }
        Kind::Device => {
            let name = input.name.as_deref().unwrap_or_default().trim().to_string();
            if name.is_empty() || name.chars().count() > 64 {
                return reject(400, "the device name needs 1..64 characters");
            }
            if input.node_id.is_some()
                || input
                    .endpoint
                    .as_deref()
                    .is_some_and(|e| !e.trim().is_empty())
            {
                return reject(
                    400,
                    "a device has no node and no endpoint; it connects to its hub",
                );
            }
            member.name = name;
            let hub = match input.via.as_deref().filter(|v| !v.is_empty()) {
                Some(via) => members.iter().find(|m| m.id == via && wg::public(m)),
                None => wg::relay(network, &members),
            };
            let Some(hub) = hub else {
                return reject(
                    409,
                    "a device connects through a node with a public endpoint; add one to the network first",
                );
            };
            member.via = Some(hub.id.clone());
            member.public_key = match (input.public_key.as_deref().map(str::trim), current) {
                (_, Some(current)) => current.public_key.clone(),
                (Some(key), None) if !key.is_empty() => {
                    if !wg::valid_key(key) {
                        return reject(
                            400,
                            "the public key must be 44 characters of base64, as wg pubkey prints it",
                        );
                    }
                    if key_taken(key) {
                        return reject(409, "another member already uses this key");
                    }
                    Some(key.to_string())
                }
                _ => None,
            };
        }
    }
    Ok(member)
}

/// The device's configuration, with the private key when the panel made it.
fn issue(
    conn: &Connection,
    network: &Network,
    device: Member,
    private_key: Option<&str>,
) -> Result<Issued> {
    let members = members_of(conn, &network.id)?;
    let hub = wg::hub(&device, &members);
    let hub_key = hub
        .and_then(|h| h.node_id.as_ref())
        .and_then(|node| node_keys(conn).ok()?.remove(node));
    let (Some(hub), Some(hub_key)) = (hub, hub_key) else {
        return reject(409, "the device's hub has no reported key yet");
    };
    let config = wg::device_config(network, &device, private_key, hub, &hub_key);
    let qr_svg = match private_key {
        Some(_) => Some(
            qrcode::QrCode::new(config.as_bytes())
                .context("QR encoding failed")?
                .render::<qrcode::render::svg::Color>()
                .min_dimensions(240, 240)
                .build(),
        ),
        None => None,
    };
    Ok(Issued {
        member: device,
        config: Some(config),
        qr_svg,
    })
}

fn age(handshake: u64, now_s: u64) -> Option<u64> {
    (handshake > 0).then(|| now_s.saturating_sub(handshake))
}

impl Store {
    /// Every network with its members' state and how each pair connects.
    pub fn wireguard(&self, actor: &Actor) -> Result<View> {
        require_admin(actor)?;
        let conn = self.0.lock().unwrap();
        let telemetry = &self.4;
        let keys = node_keys(&conn)?;
        let now_s = (now_ms() / 1000) as u64;
        // Node id to its name, freshness and newest WireGuard report.
        let mut nodes: HashMap<String, (String, bool, Option<Report>)> = HashMap::new();
        let mut readiness = vec![];
        let mut q = conn.prepare(
            "SELECT id,name,last_seen_ms,COALESCE(stats_json,'{}') FROM nodes ORDER BY name",
        )?;
        let rows: Vec<(String, String, Option<i64>, String)> = q
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))?
            .collect::<rusqlite::Result<_>>()?;
        for (id, name, last_seen, stats) in rows {
            let (last_seen, stats) = telemetry.current(&id, last_seen, stats);
            let online = last_seen.is_some_and(|seen| now_ms().saturating_sub(seen) <= 90_000);
            let report = serde_json::from_str::<EngineStats>(&stats)
                .ok()
                .and_then(|stats| stats.wireguard);
            readiness.push(NodeReadiness {
                id: id.clone(),
                name: name.clone(),
                key_reported: keys.contains_key(&id),
                problem: report.as_ref().and_then(|r| r.problem.clone()),
            });
            nodes.insert(id, (name, online, report));
        }
        let mut expected: HashMap<String, String> = HashMap::new();
        let mut networks = vec![];
        let mut all_networks = all::<Network>(&conn, "network")?;
        all_networks.sort_by(|a, b| a.name.cmp(&b.name));
        for network in all_networks {
            let members = members_of(&conn, &network.id)?;
            let relay = wg::relay(&network, &members);
            let key = |m: &Member| match m.kind {
                Kind::Node => m.node_id.as_ref().and_then(|n| keys.get(n)).cloned(),
                Kind::Device => m.public_key.clone(),
            };
            let label = |m: &Member| match &m.node_id {
                Some(node) => nodes
                    .get(node)
                    .map_or_else(|| node.clone(), |n| n.0.clone()),
                None => m.name.clone(),
            };
            // What `from` sees of `to` on this network's link.
            let leg = |from: &Member, to: &Member| -> Option<PeerReport> {
                let report = nodes.get(from.node_id.as_ref()?)?.2.as_ref()?;
                let interface = report
                    .interfaces
                    .iter()
                    .find(|i| i.network_id == network.id)?;
                let key = key(to)?;
                interface
                    .peers
                    .iter()
                    .find(|p| p.public_key == key)
                    .cloned()
            };
            let either = |a: &Member, b: &Member| leg(a, b).or_else(|| leg(b, a));
            let mut views = vec![];
            for member in &members {
                let (state, error) = match &member.node_id {
                    Some(node) => {
                        let (_, online, report) = nodes.get(node).cloned().unwrap_or_default();
                        let digest = match expected.get(node) {
                            Some(digest) => digest.clone(),
                            None => {
                                let digest = desired(&conn, node)?.digest;
                                expected.insert(node.clone(), digest.clone());
                                digest
                            }
                        };
                        let interface_error = report.as_ref().and_then(|r| {
                            r.interfaces
                                .iter()
                                .find(|i| i.network_id == network.id)
                                .and_then(|i| i.error.clone())
                        });
                        match report {
                            _ if !online => ("offline", None),
                            None => ("waiting", None),
                            Some(report) if report.problem.is_some() => ("error", report.problem),
                            Some(_) if interface_error.is_some() => ("error", interface_error),
                            Some(report) if report.applied != digest => ("updating", None),
                            Some(_) => ("up", None),
                        }
                    }
                    None => {
                        let fresh = wg::hub(member, &members)
                            .and_then(|hub| leg(hub, member))
                            .and_then(|p| age(p.handshake, now_s))
                            .is_some_and(|age| age <= CONNECTED_S);
                        (if fresh { "connected" } else { "idle" }, None)
                    }
                };
                views.push(MemberView {
                    member: member.clone(),
                    label: label(member),
                    state,
                    error,
                });
            }
            let mut pairs = vec![];
            for (index, a) in members.iter().enumerate() {
                for b in &members[index + 1..] {
                    let route = match (a.kind, b.kind) {
                        (Kind::Node, Kind::Node) => wg::path(a, b, relay),
                        (Kind::Node, Kind::Device) if b.via.as_deref() == Some(a.id.as_str()) => {
                            Path::Direct
                        }
                        (Kind::Device, Kind::Node) if a.via.as_deref() == Some(b.id.as_str()) => {
                            Path::Direct
                        }
                        _ => continue,
                    };
                    let mut pair = PairView {
                        a: label(a),
                        b: label(b),
                        path: "unreachable",
                        via: None,
                        handshake_age_s: None,
                        rx_bytes: None,
                        tx_bytes: None,
                    };
                    match route {
                        Path::Direct => {
                            pair.path = "direct";
                            if let Some(peer) = either(a, b) {
                                pair.handshake_age_s = age(peer.handshake, now_s);
                                pair.rx_bytes = Some(peer.rx_bytes);
                                pair.tx_bytes = Some(peer.tx_bytes);
                            }
                        }
                        Path::Relayed(relay) => {
                            pair.path = "relayed";
                            pair.via = Some(label(relay));
                            let legs = [either(a, relay), either(b, relay)];
                            pair.handshake_age_s = legs
                                .iter()
                                .map(|leg| leg.as_ref().and_then(|p| age(p.handshake, now_s)))
                                .collect::<Option<Vec<u64>>>()
                                .and_then(|ages| ages.into_iter().max());
                        }
                        Path::Unreachable => {}
                    }
                    pairs.push(pair);
                }
            }
            networks.push(NetworkView {
                interface: wg::interface_name(&network.id),
                relay_in_use: relay.map(|r| r.id.clone()),
                network,
                members: views,
                pairs,
            });
        }
        Ok(View {
            enabled: features::enabled(&conn, FEATURE)?,
            networks,
            nodes: readiness,
        })
    }

    pub fn create_wireguard_network(&self, actor: &Actor, input: NetworkInput) -> Result<Network> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        features::require(&tx, FEATURE, "WireGuard networking")?;
        let network = network_fields(&tx, input, None)?;
        write(&tx, "network", &network.id, &network)?;
        audit(
            &tx,
            &actor.id,
            "wireguard.network.create",
            &network.id,
            &serde_json::json!({"name": network.name, "cidr": network.cidr}).to_string(),
        )?;
        tx.commit()?;
        Ok(network)
    }
    pub fn update_wireguard_network(
        &self,
        actor: &Actor,
        id: &str,
        input: NetworkInput,
    ) -> Result<Network> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        features::require(&tx, FEATURE, "WireGuard networking")?;
        let current = network(&tx, id)?;
        let network = network_fields(&tx, input, Some(&current))?;
        write(&tx, "network", id, &network)?;
        audit(
            &tx,
            &actor.id,
            "wireguard.network.update",
            id,
            &serde_json::json!({"name": network.name}).to_string(),
        )?;
        tx.commit()?;
        Ok(network)
    }
    /// Removes the network with its members; their agents remove the links.
    pub fn delete_wireguard_network(&self, actor: &Actor, id: &str) -> Result<()> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let network = network(&tx, id)?;
        for member in members_of(&tx, id)? {
            remove(&tx, "member", &member.id)?;
        }
        remove(&tx, "network", id)?;
        audit(
            &tx,
            &actor.id,
            "wireguard.network.delete",
            id,
            &serde_json::json!({"name": network.name}).to_string(),
        )?;
        tx.commit()?;
        Ok(())
    }

    pub fn create_wireguard_member(
        &self,
        actor: &Actor,
        network_id: &str,
        input: MemberInput,
    ) -> Result<Issued> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        features::require(&tx, FEATURE, "WireGuard networking")?;
        let network = network(&tx, network_id)?;
        let mut member = member_fields(&tx, &network, input, None)?;
        let private_key =
            (member.kind == Kind::Device && member.public_key.is_none()).then(wg::private_key);
        if let Some(private_key) = &private_key {
            member.public_key = Some(wg::public_key(private_key)?);
        }
        write(&tx, "member", &member.id, &member)?;
        let issued = match member.kind {
            Kind::Device => issue(&tx, &network, member, private_key.as_deref())?,
            Kind::Node => Issued {
                member,
                config: None,
                qr_svg: None,
            },
        };
        let m = &issued.member;
        audit(&tx, &actor.id, "wireguard.member.create", &m.id, &serde_json::json!({"network_id": network.id, "kind": m.kind, "node_id": m.node_id, "name": m.name, "address": m.address}).to_string())?;
        tx.commit()?;
        Ok(issued)
    }
    pub fn update_wireguard_member(
        &self,
        actor: &Actor,
        id: &str,
        input: MemberInput,
    ) -> Result<Member> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        features::require(&tx, FEATURE, "WireGuard networking")?;
        let current = member(&tx, id)?;
        let network = network(&tx, &current.network_id)?;
        let member = member_fields(&tx, &network, input, Some(&current))?;
        write(&tx, "member", id, &member)?;
        audit(&tx, &actor.id, "wireguard.member.update", id, "{}")?;
        tx.commit()?;
        Ok(member)
    }
    pub fn delete_wireguard_member(&self, actor: &Actor, id: &str) -> Result<()> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let member = member(&tx, id)?;
        let mut network = network(&tx, &member.network_id)?;
        let devices = members_of(&tx, &network.id)?
            .iter()
            .filter(|m| m.via.as_deref() == Some(id))
            .count();
        if devices > 0 {
            return reject(
                409,
                format!(
                    "{devices} device(s) connect through this node; remove them or move them first"
                ),
            );
        }
        if network.relay.as_deref() == Some(id) {
            network.relay = None;
            write(&tx, "network", &network.id.clone(), &network)?;
        }
        remove(&tx, "member", id)?;
        audit(&tx, &actor.id, "wireguard.member.delete", id, "{}")?;
        tx.commit()?;
        Ok(())
    }
    /// A new key pair for a device; the old configuration stops working.
    pub fn rekey_wireguard_device(&self, actor: &Actor, id: &str) -> Result<Issued> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        features::require(&tx, FEATURE, "WireGuard networking")?;
        let mut member = member(&tx, id)?;
        if member.kind != Kind::Device {
            return reject(
                400,
                "only devices get keys from the panel; a node makes its own",
            );
        }
        let network = network(&tx, &member.network_id)?;
        let private_key = wg::private_key();
        member.public_key = Some(wg::public_key(&private_key)?);
        member.updated_at_ms = now_ms();
        write(&tx, "member", id, &member)?;
        let issued = issue(&tx, &network, member, Some(&private_key))?;
        audit(&tx, &actor.id, "wireguard.member.rekey", id, "{}")?;
        tx.commit()?;
        Ok(issued)
    }
}
