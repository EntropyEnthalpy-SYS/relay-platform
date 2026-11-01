//! WireGuard networking between nodes and user devices. The panel keeps
//! networks and their members; for every sync it renders the interface a
//! member node should have, and the node's agent applies it on links named
//! `rwg-*` only. A pair where neither side has a public endpoint goes through
//! the network's relay node, and a device connects to one public node (its
//! hub). With NAT traversal on, two such nodes try to reach each other
//! directly first ([`punch`]). Node private keys are made on the node and
//! never leave it; device keys are made by the panel and shown once.
use anyhow::{Context, Result, anyhow, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use ipnet::Ipv4Net;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::{IpAddr, Ipv4Addr, SocketAddr},
};

pub mod punch;

pub const MAX_NETWORKS: usize = 16;
pub const MAX_MEMBERS: usize = 64;
/// Networks one node can join; each needs its own interface and port.
pub const MAX_NODE_NETWORKS: usize = 4;
/// The agent owns only WireGuard links whose name starts with this.
pub const PREFIX: &str = "rwg-";
/// Keeps a NAT mapping open towards public peers.
pub const KEEPALIVE: u16 = 25;
pub const DEFAULT_PORT: u16 = 51820;
pub const DEFAULT_MTU: u16 = 1420;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Kind {
    Node,
    Device,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Network {
    pub id: String,
    pub name: String,
    pub cidr: Ipv4Net,
    pub mtu: u16,
    pub listen_port: u16,
    /// The node member that relays between members without a public
    /// endpoint; `None` picks the public node with the lowest address.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub relay: Option<String>,
    pub updated_at_ms: i64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Member {
    pub id: String,
    pub network_id: String,
    pub kind: Kind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    /// Devices only; node members show the node's name.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub name: String,
    pub address: Ipv4Addr,
    /// `host:port` where other members reach this node; a node with one is public.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Replaces the network's port on this node.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub listen_port: Option<u16>,
    /// Devices only: the public node member the device connects to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    /// Devices only.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    pub updated_at_ms: i64,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NetworkInput {
    pub name: String,
    /// Required for a new network; cannot change while it has members.
    #[serde(default)]
    pub cidr: Option<String>,
    #[serde(default)]
    pub mtu: Option<u16>,
    #[serde(default)]
    pub listen_port: Option<u16>,
    #[serde(default)]
    pub relay: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberInput {
    pub kind: Kind,
    #[serde(default)]
    pub node_id: Option<String>,
    #[serde(default)]
    pub name: Option<String>,
    /// Fixed once the member exists; empty picks the lowest free address.
    #[serde(default)]
    pub address: Option<String>,
    #[serde(default)]
    pub endpoint: Option<String>,
    #[serde(default)]
    pub listen_port: Option<u16>,
    #[serde(default)]
    pub via: Option<String>,
    /// A device's own public key; without one the panel makes the key pair.
    #[serde(default)]
    pub public_key: Option<String>,
}

/// A new device or new device key: the configuration holds the private key
/// when the panel made it, and is shown only in this reply.
#[derive(Debug, Serialize)]
pub struct Issued {
    #[serde(flatten)]
    pub member: Member,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub config: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub qr_svg: Option<String>,
}

/// What one node should have, sent with every sync. Unknown fields are
/// ignored so later controllers can add some without breaking older agents.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Desired {
    /// The feature is on: an agent allowed to manage WireGuard makes its key.
    pub enabled: bool,
    pub digest: String,
    pub interfaces: Vec<Interface>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Interface {
    pub network_id: String,
    pub name: String,
    pub address: Ipv4Addr,
    pub prefix: u8,
    pub mtu: u16,
    pub listen_port: u16,
    /// Relays and hubs pass traffic between their peers.
    pub forwarding: bool,
    pub peers: Vec<Peer>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Peer {
    pub public_key: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    pub allowed_ips: Vec<Ipv4Net>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub keepalive: Option<u16>,
}

/// What the agent reports back. Sent only to a controller that sent a
/// [`Desired`], as older controllers reject unknown statistics.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Report {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub public_key: Option<String>,
    /// The server lets the agent manage WireGuard.
    pub ready: bool,
    /// The agent writes peer entries without allowed IPs, which NAT
    /// traversal probes use; agents before 0.139.0 cannot.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub probes: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
    /// The digest of the desired state last applied; what failed is in
    /// `problem` or the interface's `error`.
    pub applied: String,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub interfaces: Vec<InterfaceReport>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct InterfaceReport {
    pub network_id: String,
    pub name: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
    pub peers: Vec<PeerReport>,
}
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct PeerReport {
    pub public_key: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub endpoint: Option<String>,
    /// Unix seconds of the newest handshake; 0 if none yet.
    pub handshake: u64,
    pub rx_bytes: u64,
    pub tx_bytes: u64,
}

/// The panel's view of every network.
#[derive(Clone, Debug, Serialize)]
pub struct View {
    pub enabled: bool,
    pub networks: Vec<NetworkView>,
    /// Every node and whether its agent can join a network now.
    pub nodes: Vec<NodeReadiness>,
}
#[derive(Clone, Debug, Serialize)]
pub struct NetworkView {
    #[serde(flatten)]
    pub network: Network,
    pub interface: String,
    /// The relay in use, explicit or picked.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub relay_in_use: Option<String>,
    pub members: Vec<MemberView>,
    pub pairs: Vec<PairView>,
}
#[derive(Clone, Debug, Serialize)]
pub struct MemberView {
    #[serde(flatten)]
    pub member: Member,
    /// The node's or device's name.
    pub label: String,
    /// Nodes: offline, waiting (no report yet), error, updating or up.
    /// Devices: connected or idle.
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct PairView {
    pub a: String,
    pub b: String,
    /// direct, probing (relayed while trying to connect directly), relayed
    /// or unreachable.
    pub path: &'static str,
    /// Direct through both members' NATs.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub punched: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<String>,
    /// Why a pair behind NATs is relayed after trying to connect directly.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    /// Seconds until the next direct attempt.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retry_in_s: Option<u64>,
    /// Seconds since the newest handshake on the path; for a relayed pair,
    /// the older of its two legs.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub handshake_age_s: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rx_bytes: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub tx_bytes: Option<u64>,
}
#[derive(Clone, Debug, Serialize)]
pub struct NodeReadiness {
    pub id: String,
    pub name: String,
    /// The agent reported a public key, so the node can join a network.
    pub key_reported: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub problem: Option<String>,
}

impl Desired {
    pub fn new(enabled: bool, mut interfaces: Vec<Interface>) -> Self {
        interfaces.sort_by(|a, b| a.name.cmp(&b.name));
        let encoded =
            serde_json::to_vec(&(enabled, &interfaces)).expect("desired state serializes");
        Self {
            enabled,
            digest: blake3::hash(&encoded).to_hex()[..16].to_string(),
            interfaces,
        }
    }
}

impl Report {
    /// Bounds what a controller stores from one report.
    pub fn within_limits(&self) -> bool {
        let short = |text: &Option<String>| text.as_ref().is_none_or(|t| t.len() <= 2048);
        short(&self.problem)
            && self.applied.len() <= 64
            && self.interfaces.len() <= MAX_NODE_NETWORKS
            && self.interfaces.iter().all(|i| {
                short(&i.error)
                    && i.name.len() <= 15
                    && i.network_id.len() <= 64
                    && i.peers.len() <= MAX_MEMBERS
                    && i.peers.iter().all(|p| {
                        p.public_key.len() <= 64
                            && p.endpoint.as_ref().is_none_or(|e| e.len() <= 300)
                    })
            })
    }
}

/// A new private key, clamped like `wg genkey`.
pub fn private_key() -> String {
    let mut key = [0u8; 32];
    rand::RngCore::fill_bytes(&mut rand::rngs::OsRng, &mut key);
    key[0] &= 248;
    key[31] = (key[31] & 127) | 64;
    STANDARD.encode(key)
}
fn decode_key(text: &str) -> Result<[u8; 32]> {
    STANDARD
        .decode(text)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or_else(|| anyhow!("a WireGuard key is 32 bytes in base64 (44 characters)"))
}
pub fn public_key(private_key: &str) -> Result<String> {
    Ok(STANDARD.encode(x25519_dalek::x25519(
        decode_key(private_key)?,
        x25519_dalek::X25519_BASEPOINT_BYTES,
    )))
}
pub fn valid_key(text: &str) -> bool {
    text.len() == 44 && decode_key(text).is_ok()
}

/// The link a node uses for `network`.
pub fn interface_name(network_id: &str) -> String {
    let hex: String = network_id
        .chars()
        .filter(char::is_ascii_hexdigit)
        .take(8)
        .collect();
    format!("{PREFIX}{hex}")
}

const PRIVATE: [&str; 4] = [
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
    "100.64.0.0/10",
];
pub fn network_cidr(text: &str) -> Result<Ipv4Net> {
    let net: Ipv4Net = text
        .trim()
        .parse()
        .context("use an IPv4 range such as 10.88.0.0/24")?;
    ensure!(
        (16..=29).contains(&net.prefix_len()),
        "the range must be /16 to /29"
    );
    ensure!(
        net == net.trunc(),
        "start the range at its first address: {}",
        net.trunc()
    );
    ensure!(
        PRIVATE
            .iter()
            .any(|p| p.parse::<Ipv4Net>().unwrap().contains(&net)),
        "the range must be private: inside 10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16 or 100.64.0.0/10"
    );
    Ok(net)
}

/// `host[:port]` where other members reach a node, as `host:port`.
pub fn endpoint(text: &str, default_port: u16) -> Result<String> {
    let text = text.trim();
    let usable = |ip: IpAddr| {
        let ip = crate::model::canonical_ip(ip);
        !ip.is_unspecified()
            && !ip.is_loopback()
            && !ip.is_multicast()
            && ip != IpAddr::V4(Ipv4Addr::BROADCAST)
    };
    let wrong =
        || anyhow!("the endpoint must be a public address or host name, with an optional port");
    if let Ok(address) = text.parse::<SocketAddr>() {
        ensure!(usable(address.ip()) && address.port() != 0, wrong());
        return Ok(
            SocketAddr::new(crate::model::canonical_ip(address.ip()), address.port()).to_string(),
        );
    }
    if let Ok(ip) = text.parse::<IpAddr>() {
        ensure!(usable(ip), wrong());
        return Ok(SocketAddr::new(crate::model::canonical_ip(ip), default_port).to_string());
    }
    let (host, port) = match text.rsplit_once(':') {
        Some((host, port)) => (
            host,
            port.parse::<u16>()
                .ok()
                .filter(|p| *p != 0)
                .ok_or_else(wrong)?,
        ),
        None => (text, default_port),
    };
    let host = host.trim_end_matches('.').to_ascii_lowercase();
    let labels: Vec<&str> = host.split('.').collect();
    ensure!(
        host.len() <= 253
            && labels.len() >= 2
            && labels.iter().all(|l| {
                (1..=63).contains(&l.len())
                    && !l.starts_with('-')
                    && !l.ends_with('-')
                    && l.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
            })
            && !labels.last().unwrap().bytes().all(|b| b.is_ascii_digit()),
        wrong()
    );
    Ok(format!("{host}:{port}"))
}

/// How traffic between two members travels.
#[derive(Clone, Copy, Debug)]
pub enum Path<'a> {
    Direct,
    Relayed(&'a Member),
    Unreachable,
}
pub fn public(member: &Member) -> bool {
    member.kind == Kind::Node && member.endpoint.is_some()
}
/// The member that relays between members without a public endpoint.
pub fn relay<'a>(network: &Network, members: &'a [Member]) -> Option<&'a Member> {
    let mut candidates = members.iter().filter(|m| public(m));
    match &network.relay {
        Some(id) => candidates.find(|m| &m.id == id),
        None => candidates.min_by_key(|m| m.address),
    }
}
/// Either side being public is enough: the other side keeps the path open.
pub fn path<'a>(a: &Member, b: &Member, relay: Option<&'a Member>) -> Path<'a> {
    if a.endpoint.is_some() || b.endpoint.is_some() {
        Path::Direct
    } else {
        relay.map_or(Path::Unreachable, Path::Relayed)
    }
}
/// A direct entry for a peer that also lacks a public endpoint.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Punch {
    /// The peer's address and port as its NAT presents them to the relay.
    pub endpoint: Option<String>,
    /// The hole is open: traffic to the peer goes here, not through the relay.
    pub open: bool,
}
pub fn hub<'a>(device: &Member, members: &'a [Member]) -> Option<&'a Member> {
    members
        .iter()
        .find(|m| public(m) && device.via.as_deref() == Some(m.id.as_str()))
}

/// The interface `node` should have in `network`, or `None` when it is no
/// member. `keys` maps node ids to the public keys their agents reported;
/// a node whose key is unknown is left out until it reports one. `punches`
/// holds the node's direct entries for peers behind NATs, by member id.
pub fn render(
    network: &Network,
    members: &[Member],
    keys: &HashMap<String, String>,
    node: &str,
    punches: &HashMap<String, Punch>,
) -> Result<Option<Interface>> {
    let Some(me) = members
        .iter()
        .find(|m| m.kind == Kind::Node && m.node_id.as_deref() == Some(node))
    else {
        return Ok(None);
    };
    let key = |m: &Member| match m.kind {
        Kind::Node => m.node_id.as_ref().and_then(|n| keys.get(n)).cloned(),
        Kind::Device => m.public_key.clone(),
    };
    let relay = relay(network, members);
    let mut peers: BTreeMap<String, Peer> = BTreeMap::new();
    // Puts `address` on the entry for `carrier`, the peer that receives it.
    let mut route = |carrier: &Member, address: Ipv4Addr| {
        let Some(public_key) = key(carrier) else {
            return;
        };
        peers
            .entry(public_key.clone())
            .or_insert_with(|| Peer {
                public_key,
                endpoint: carrier.endpoint.clone(),
                allowed_ips: vec![],
                keepalive: (me.endpoint.is_none() && carrier.endpoint.is_some())
                    .then_some(KEEPALIVE),
            })
            .allowed_ips
            .push(Ipv4Net::new(address, 32).unwrap());
    };
    // `target` lives behind `next`: a node, or the hub of a device.
    let mut reach = |next: &Member, address: Ipv4Addr| match path(me, next, relay) {
        Path::Direct => route(next, address),
        Path::Relayed(_) if punches.get(&next.id).is_some_and(|p| p.open) => route(next, address),
        Path::Relayed(relay) => route(relay, address),
        Path::Unreachable => {}
    };
    for other in members.iter().filter(|m| m.id != me.id && key(m).is_some()) {
        match other.kind {
            Kind::Node => reach(other, other.address),
            Kind::Device => match hub(other, members) {
                Some(hub) if hub.id == me.id => reach(other, other.address),
                Some(hub) if key(hub).is_some() => reach(hub, other.address),
                _ => {}
            },
        }
    }
    // A probe's entry carries no traffic until the hole is open.
    for (id, punch) in punches {
        let Some(other) = members.iter().find(|m| &m.id == id && m.kind == Kind::Node) else {
            continue;
        };
        let Some(public_key) =
            key(other).filter(|_| matches!(path(me, other, relay), Path::Relayed(_)))
        else {
            continue;
        };
        let peer = peers.entry(public_key.clone()).or_insert_with(|| Peer {
            public_key,
            endpoint: None,
            allowed_ips: vec![],
            keepalive: None,
        });
        peer.endpoint = punch.endpoint.clone();
        peer.keepalive = Some(KEEPALIVE);
    }
    let mut seen = HashSet::new();
    let mut peers: Vec<Peer> = peers.into_values().collect();
    for peer in &mut peers {
        peer.allowed_ips.sort();
        for net in &peer.allowed_ips {
            ensure!(
                network.cidr.contains(net) && net.addr() != me.address && seen.insert(*net),
                "the routes for WireGuard network {} overlap",
                network.name
            );
        }
    }
    Ok(Some(Interface {
        network_id: network.id.clone(),
        name: interface_name(&network.id),
        address: me.address,
        prefix: network.cidr.prefix_len(),
        mtu: network.mtu,
        listen_port: me.listen_port.unwrap_or(network.listen_port),
        forwarding: relay.is_some_and(|r| r.id == me.id)
            || members
                .iter()
                .any(|m| m.kind == Kind::Device && m.via.as_deref() == Some(me.id.as_str())),
        peers,
    }))
}

/// The file `wg syncconf` reads; it holds the private key, so it goes to
/// `wg` on standard input only.
pub fn wg_config(interface: &Interface, private_key: &str) -> String {
    let mut text = format!(
        "[Interface]\nPrivateKey = {private_key}\nListenPort = {}\n",
        interface.listen_port
    );
    for peer in &interface.peers {
        text.push_str(&format!("\n[Peer]\nPublicKey = {}\n", peer.public_key));
        // wg refuses an empty list; leaving the line out clears the list.
        if !peer.allowed_ips.is_empty() {
            let allowed: Vec<String> = peer.allowed_ips.iter().map(ToString::to_string).collect();
            text.push_str(&format!("AllowedIPs = {}\n", allowed.join(", ")));
        }
        if let Some(endpoint) = &peer.endpoint {
            text.push_str(&format!("Endpoint = {endpoint}\n"));
        }
        if let Some(seconds) = peer.keepalive {
            text.push_str(&format!("PersistentKeepalive = {seconds}\n"));
        }
    }
    text
}

/// A wg-quick file for a device: everything in the network goes to its hub.
pub fn device_config(
    network: &Network,
    device: &Member,
    private_key: Option<&str>,
    hub: &Member,
    hub_key: &str,
) -> String {
    format!(
        "[Interface]\nPrivateKey = {}\nAddress = {}/{}\nMTU = {}\n\n[Peer]\nPublicKey = {hub_key}\nEndpoint = {}\nAllowedIPs = {}\nPersistentKeepalive = {KEEPALIVE}\n",
        private_key.unwrap_or("<the device's own private key>"),
        device.address,
        network.cidr.prefix_len(),
        network.mtu,
        hub.endpoint.as_deref().unwrap_or_default(),
        network.cidr,
    )
}

/// The lowest host address of `cidr` that no member holds.
pub fn free_address(cidr: Ipv4Net, members: &[Member]) -> Option<Ipv4Addr> {
    cidr.hosts()
        .find(|address| !members.iter().any(|m| m.address == *address))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn hex(text: &str) -> String {
        let bytes: Vec<u8> = (0..text.len())
            .step_by(2)
            .map(|i| u8::from_str_radix(&text[i..i + 2], 16).unwrap())
            .collect();
        STANDARD.encode(bytes)
    }

    #[test]
    fn public_keys_match_rfc_7748() {
        // RFC 7748 section 6.1, Alice and Bob.
        for (private, public) in [
            (
                "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
                "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
            ),
            (
                "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb",
                "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f",
            ),
        ] {
            assert_eq!(public_key(&hex(private)).unwrap(), hex(public));
        }
        let key = private_key();
        assert!(valid_key(&key) && valid_key(&public_key(&key).unwrap()));
        assert_ne!(key, private_key());
        assert!(!valid_key("short") && public_key("AAAA").is_err());
    }

    #[test]
    fn ranges_and_endpoints_are_checked() {
        assert_eq!(
            network_cidr(" 10.88.0.0/24 ").unwrap().to_string(),
            "10.88.0.0/24"
        );
        for bad in [
            "10.88.0.1/24",
            "10.0.0.0/8",
            "10.88.0.0/30",
            "8.8.8.0/24",
            "fd00::/64",
            "x",
        ] {
            assert!(network_cidr(bad).is_err(), "{bad}");
        }
        assert_eq!(endpoint("203.0.113.7", 51820).unwrap(), "203.0.113.7:51820");
        assert_eq!(
            endpoint("203.0.113.7:51999", 51820).unwrap(),
            "203.0.113.7:51999"
        );
        assert_eq!(
            endpoint("2001:db8::1", 51820).unwrap(),
            "[2001:db8::1]:51820"
        );
        assert_eq!(
            endpoint("[2001:db8::1]:1", 51820).unwrap(),
            "[2001:db8::1]:1"
        );
        assert_eq!(
            endpoint("VPN.Example.com.", 51820).unwrap(),
            "vpn.example.com:51820"
        );
        assert_eq!(
            endpoint("vpn.example.com:443", 51820).unwrap(),
            "vpn.example.com:443"
        );
        for bad in [
            "0.0.0.0",
            "127.0.0.1:5",
            "203.0.113.7:0",
            "localhost",
            "a..b",
            "1.2.3.4.5",
            "x.com:99999",
            "a b.com",
        ] {
            assert!(endpoint(bad, 51820).is_err(), "{bad}");
        }
    }

    fn member(id: &str, kind: Kind, last: u8, endpoint: Option<&str>) -> Member {
        Member {
            id: id.into(),
            network_id: "net".into(),
            kind,
            node_id: (kind == Kind::Node).then(|| format!("node-{id}")),
            name: String::new(),
            address: Ipv4Addr::new(10, 88, 0, last),
            endpoint: endpoint.map(str::to_string),
            listen_port: None,
            via: None,
            public_key: (kind == Kind::Device).then(|| format!("key-{id}")),
            updated_at_ms: 0,
        }
    }
    fn network(relay: Option<&str>) -> Network {
        Network {
            id: "0f1e2d3c-0000-4000-8000-000000000000".into(),
            name: "lab".into(),
            cidr: "10.88.0.0/24".parse().unwrap(),
            mtu: 1420,
            listen_port: 51820,
            relay: relay.map(str::to_string),
            updated_at_ms: 0,
        }
    }
    fn keys(members: &[Member]) -> HashMap<String, String> {
        members
            .iter()
            .filter_map(|m| m.node_id.clone().map(|n| (n, format!("key-{}", m.id))))
            .collect()
    }
    fn none() -> HashMap<String, Punch> {
        HashMap::new()
    }
    /// Each peer as `key endpoint keepalive allowed,allowed`.
    fn peers(interface: &Interface) -> Vec<String> {
        interface
            .peers
            .iter()
            .map(|p| {
                let allowed: Vec<String> =
                    p.allowed_ips.iter().map(|n| n.addr().to_string()).collect();
                format!(
                    "{} {} {} {}",
                    p.public_key,
                    p.endpoint.as_deref().unwrap_or("-"),
                    p.keepalive.unwrap_or(0),
                    allowed.join(",")
                )
            })
            .collect()
    }

    #[test]
    fn members_behind_nat_reach_each_other_and_devices_through_public_nodes() {
        // Two public nodes; the explicit relay is the one with the higher
        // address, so a relay picked by address would show up wrongly.
        let mut device = member("d", Kind::Device, 9, None);
        device.via = Some("p1".into());
        let members = vec![
            member("p1", Kind::Node, 1, Some("203.0.113.1:51820")),
            member("a", Kind::Node, 2, None),
            member("b", Kind::Node, 3, None),
            member("p2", Kind::Node, 5, Some("203.0.113.5:51820")),
            device,
        ];
        let net = network(Some("p2"));
        let keys = keys(&members);
        let a = render(&net, &members, &keys, "node-a", &none())
            .unwrap()
            .unwrap();
        assert_eq!(a.name, "rwg-0f1e2d3c");
        assert_eq!(
            (a.address, a.prefix, a.forwarding),
            (Ipv4Addr::new(10, 88, 0, 2), 24, false)
        );
        assert_eq!(
            peers(&a),
            [
                "key-p1 203.0.113.1:51820 25 10.88.0.1,10.88.0.9",
                "key-p2 203.0.113.5:51820 25 10.88.0.3,10.88.0.5",
            ]
        );
        let p2 = render(&net, &members, &keys, "node-p2", &none())
            .unwrap()
            .unwrap();
        assert!(p2.forwarding);
        assert_eq!(
            peers(&p2),
            [
                "key-a - 0 10.88.0.2",
                "key-b - 0 10.88.0.3",
                "key-p1 203.0.113.1:51820 0 10.88.0.1,10.88.0.9",
            ]
        );
        let p1 = render(&net, &members, &keys, "node-p1", &none())
            .unwrap()
            .unwrap();
        assert!(p1.forwarding, "the device hub forwards");
        assert!(peers(&p1).contains(&"key-d - 0 10.88.0.9".to_string()));
        assert!(
            render(&net, &members, &keys, "node-x", &none())
                .unwrap()
                .is_none()
        );

        // Without an explicit relay the lowest public address relays.
        let b = render(&network(None), &members, &keys, "node-b", &none())
            .unwrap()
            .unwrap();
        assert_eq!(
            peers(&b),
            [
                "key-p1 203.0.113.1:51820 25 10.88.0.1,10.88.0.2,10.88.0.9",
                "key-p2 203.0.113.5:51820 25 10.88.0.5",
            ]
        );
    }

    #[test]
    fn probes_add_entries_without_traffic_and_open_holes_leave_the_relay() {
        let members = vec![
            member("p", Kind::Node, 1, Some("203.0.113.1:51820")),
            member("a", Kind::Node, 2, None),
            member("b", Kind::Node, 3, None),
            member("c", Kind::Node, 4, None),
        ];
        let keys = keys(&members);
        let punch = |endpoint: &str, open| Punch {
            endpoint: Some(endpoint.into()),
            open,
        };
        // Probing `b`, direct to `c`; a punch towards the public relay is ignored.
        let punches = HashMap::from([
            ("b".to_string(), punch("198.51.100.3:40002", false)),
            ("c".to_string(), punch("198.51.100.4:40003", true)),
            ("p".to_string(), punch("198.51.100.9:1", true)),
        ]);
        let a = render(&network(None), &members, &keys, "node-a", &punches)
            .unwrap()
            .unwrap();
        assert_eq!(
            peers(&a),
            [
                "key-b 198.51.100.3:40002 25 ",
                "key-c 198.51.100.4:40003 25 10.88.0.4",
                "key-p 203.0.113.1:51820 25 10.88.0.1,10.88.0.3",
            ]
        );
        assert!(!a.forwarding);
        assert!(wg_config(&a, "K").contains(
            "PublicKey = key-b\nEndpoint = 198.51.100.3:40002\nPersistentKeepalive = 25\n"
        ));
    }

    #[test]
    fn unknown_keys_and_missing_relays_leave_peers_out() {
        let members = vec![
            member("a", Kind::Node, 2, None),
            member("b", Kind::Node, 3, None),
        ];
        let keys = keys(&members);
        let a = render(&network(None), &members, &keys, "node-a", &none())
            .unwrap()
            .unwrap();
        assert!(a.peers.is_empty(), "no relay: unreachable");

        let members = vec![
            member("a", Kind::Node, 2, Some("198.51.100.2:51820")),
            member("b", Kind::Node, 3, None),
            member("c", Kind::Node, 4, None),
        ];
        let mut keys = self::keys(&members);
        keys.remove("node-c");
        let b = render(&network(None), &members, &keys, "node-b", &none())
            .unwrap()
            .unwrap();
        assert_eq!(peers(&b), ["key-a 198.51.100.2:51820 25 10.88.0.2"]);
        let a = render(&network(None), &members, &keys, "node-a", &none())
            .unwrap()
            .unwrap();
        assert_eq!(peers(&a), ["key-b - 0 10.88.0.3"]);
        assert!(a.forwarding, "the only public node relays");
    }

    #[test]
    fn digest_and_config_text_follow_the_desired_state() {
        let members = vec![
            member("p", Kind::Node, 1, Some("203.0.113.1:51820")),
            member("a", Kind::Node, 2, None),
        ];
        let keys = keys(&members);
        let a = render(&network(None), &members, &keys, "node-a", &none())
            .unwrap()
            .unwrap();
        let text = wg_config(&a, "PRIVATE");
        assert_eq!(
            text,
            "[Interface]\nPrivateKey = PRIVATE\nListenPort = 51820\n\n[Peer]\nPublicKey = key-p\nAllowedIPs = 10.88.0.1/32\nEndpoint = 203.0.113.1:51820\nPersistentKeepalive = 25\n"
        );
        let first = Desired::new(true, vec![a.clone()]);
        let mut moved = a;
        moved.peers[0].endpoint = Some("203.0.113.9:51820".into());
        assert_ne!(first.digest, Desired::new(true, vec![moved]).digest);
        assert_ne!(
            Desired::new(true, vec![]).digest,
            Desired::new(false, vec![]).digest
        );
        assert_eq!(
            free_address(network(None).cidr, &members),
            Some(Ipv4Addr::new(10, 88, 0, 3))
        );
    }
}
