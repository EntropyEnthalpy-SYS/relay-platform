//! Independent authoritative DNS pool. The panel keeps zones, member nodes and
//! records; for every sync it renders the answers a member serves, health
//! gating included, and the member's agent answers queries for them on its
//! own addresses over UDP and TCP. The agent keeps the last copy so a restart
//! keeps answering while the controller is unreachable.
use anyhow::{Context, Result, bail};
use hickory_proto::{
    op::{Edns, Message, MessageType, OpCode, Query, ResponseCode},
    rr::{
        DNSClass, Name, RData, Record as WireRecord, RecordType,
        rdata::{A, AAAA, CNAME, NS, SOA, TXT},
    },
};
use serde::{Deserialize, Serialize};
use socket2::{Domain, Socket, Type};
use std::{
    collections::{BTreeMap, HashMap, HashSet},
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex, RwLock,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

pub const MAX_ZONES: usize = 16;
pub const MAX_MEMBERS: usize = 8;
pub const MAX_LISTEN: usize = 4;
pub const MAX_RECORDS: usize = 256;
pub const MAX_VALUES: usize = 16;
/// Largest UDP answer: the EDNS size DNS Flag Day 2020 settled on.
const UDP_LIMIT: u16 = 1232;
/// Per source /24 (IPv4) or /56 (IPv6), so the servers are poor amplifiers.
const RATE_PER_SECOND: f64 = 200.0;
const RATE_BURST: f64 = 400.0;
const TCP_CONNECTIONS: usize = 64;
const TCP_IDLE: Duration = Duration::from_secs(10);
const BIND_RETRY: Duration = Duration::from_secs(30);

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "UPPERCASE")]
pub enum Kind {
    A,
    Aaaa,
    Cname,
    Txt,
}

/// A zone as the panel stores it. Names are lowercase without a final dot.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Zone {
    pub id: String,
    pub name: String,
    /// Contact address published in the SOA record.
    pub hostmaster: String,
    pub ttl: u32,
    pub negative_ttl: u32,
    /// Health gating never leaves a record with fewer values than this.
    pub min_keep: u32,
    /// SOA serial; raised on every change to the zone, its members or records.
    pub serial: u32,
    pub updated_at_ms: i64,
}
/// A node that answers for a zone as `label.zone`.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Member {
    pub id: String,
    pub zone_id: String,
    pub node_id: String,
    pub label: String,
    /// Addresses the agent listens on; explicit, never a wildcard.
    pub listen: Vec<IpAddr>,
    /// The public address published as glue, for a node behind cloud NAT.
    pub advertise: IpAddr,
    pub port: u16,
    pub updated_at_ms: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Record {
    pub id: String,
    pub zone_id: String,
    /// Relative to the zone; `@` is the zone itself.
    pub name: String,
    #[serde(rename = "type")]
    pub kind: Kind,
    /// `None` uses the zone's TTL.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl: Option<u32>,
    pub values: Vec<Value>,
    pub updated_at_ms: i64,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Value {
    pub content: String,
    /// Served only while the node rule has a fresh, eligible healthy target.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub health: Option<crate::dns::HealthGate>,
}

#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ZoneInput {
    pub name: String,
    #[serde(default)]
    pub hostmaster: Option<String>,
    #[serde(default)]
    pub ttl: Option<u32>,
    #[serde(default)]
    pub negative_ttl: Option<u32>,
    #[serde(default)]
    pub min_keep: Option<u32>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MemberInput {
    pub node_id: String,
    #[serde(default)]
    pub label: Option<String>,
    pub listen: Vec<IpAddr>,
    #[serde(default)]
    pub advertise: Option<IpAddr>,
    #[serde(default)]
    pub port: Option<u16>,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecordInput {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: Kind,
    #[serde(default)]
    pub ttl: Option<u32>,
    pub values: Vec<Value>,
}

/// What one member serves, sent with every sync. Fields are never denied so
/// later controllers can add some without breaking older agents.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct Snapshot {
    pub digest: String,
    pub listen: Vec<SocketAddr>,
    pub zones: Vec<ServeZone>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServeZone {
    pub name: String,
    pub serial: u32,
    /// The SOA RNAME, already in DNS-name form.
    pub hostmaster: String,
    pub ttl: u32,
    pub negative_ttl: u32,
    pub nameservers: Vec<NameServer>,
    pub sets: Vec<ServeSet>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NameServer {
    pub name: String,
    pub address: IpAddr,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct ServeSet {
    pub name: String,
    #[serde(rename = "type")]
    pub kind: Kind,
    pub ttl: u32,
    pub values: Vec<String>,
}
/// What the agent reports back. Sent only to a controller that sent a
/// [`Snapshot`], as older controllers reject unknown statistics.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(default)]
pub struct ServeStats {
    /// The snapshot being served.
    pub digest: String,
    pub listening: Vec<SocketAddr>,
    #[serde(skip_serializing_if = "Vec::is_empty")]
    pub errors: Vec<String>,
    pub queries: u64,
    pub nxdomain: u64,
    pub refused: u64,
    pub truncated: u64,
    pub limited: u64,
}

/// The panel's view: every zone with what its members serve right now.
#[derive(Clone, Debug, Serialize)]
pub struct PoolView {
    pub enabled: bool,
    pub zones: Vec<ZoneView>,
}
#[derive(Clone, Debug, Serialize)]
pub struct ZoneView {
    #[serde(flatten)]
    pub zone: Zone,
    pub members: Vec<MemberView>,
    pub records: Vec<RecordView>,
}
#[derive(Clone, Debug, Serialize)]
pub struct MemberView {
    #[serde(flatten)]
    pub member: Member,
    pub node_name: String,
    /// The member's name server host name, `label.zone`.
    pub nameserver: String,
    /// offline, waiting (no report yet: possibly an agent older than this
    /// feature), error (a listener failed), updating or serving.
    pub state: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub report: Option<ServeStats>,
}
#[derive(Clone, Debug, Serialize)]
pub struct RecordView {
    #[serde(flatten)]
    pub record: Record,
    /// The values answered now, after health gating and `min_keep`.
    pub served: Vec<String>,
    /// Per value: `None` without a health gate, otherwise whether it passes.
    pub healthy: Vec<Option<bool>>,
}

impl Snapshot {
    pub fn new(mut listen: Vec<SocketAddr>, zones: Vec<ServeZone>) -> Self {
        listen.sort();
        listen.dedup();
        let encoded = serde_json::to_vec(&(&listen, &zones)).expect("snapshot serializes");
        let digest = blake3::hash(&encoded).to_hex()[..16].to_string();
        Self {
            digest,
            listen,
            zones,
        }
    }
}

fn label_ok(label: &str, underscore: bool) -> bool {
    (1..=63).contains(&label.len())
        && !label.starts_with('-')
        && !label.ends_with('-')
        && label.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-' || (underscore && b == b'_')
        })
}
/// A zone name: two or more lowercase labels, at most 253 bytes.
pub fn zone_name(input: &str) -> Result<String> {
    let name = input.trim().trim_end_matches('.').to_ascii_lowercase();
    if name.len() > 253
        || name.split('.').count() < 2
        || !name.split('.').all(|l| label_ok(l, false))
    {
        bail!("zone name must be a domain such as edge.example.com");
    }
    Ok(name)
}
/// A record name relative to `zone`: `@` or labels such as `www` or `_acme-challenge.api`.
pub fn record_name(input: &str, zone: &str) -> Result<String> {
    let name = input.trim().trim_end_matches('.').to_ascii_lowercase();
    if name == "@" || name.is_empty() {
        return Ok("@".into());
    }
    if !name.split('.').all(|l| label_ok(l, true)) || name.len() + zone.len() + 1 > 253 {
        bail!(
            "record name must be @ or labels of letters, digits, '-' or '_' (wildcards are not supported)"
        );
    }
    Ok(name)
}
pub fn nameserver_label(input: &str) -> Result<String> {
    let label = input.trim().to_ascii_lowercase();
    if !label_ok(&label, false) {
        bail!("name server label must be one DNS label such as ns1");
    }
    Ok(label)
}
/// Fully qualified record name without the final dot.
pub fn absolute(name: &str, zone: &str) -> String {
    if name == "@" {
        zone.into()
    } else {
        format!("{name}.{zone}")
    }
}
/// `hostmaster@example.com` as the SOA RNAME `hostmaster.example.com`.
pub fn hostmaster_name(email: &str) -> Result<String> {
    let email = email.trim().to_ascii_lowercase();
    let Some((local, domain)) = email.split_once('@') else {
        bail!("hostmaster must be an email address");
    };
    if !label_ok(local, true) || zone_name(domain).is_err() {
        bail!("hostmaster must be an email address whose name part has no dots");
    }
    Ok(format!("{local}.{}", domain.trim_end_matches('.')))
}
pub fn validate_value(kind: Kind, content: &str) -> Result<()> {
    match kind {
        Kind::A => {
            content
                .parse::<std::net::Ipv4Addr>()
                .context("A values must be IPv4 addresses")?;
        }
        Kind::Aaaa => {
            content
                .parse::<std::net::Ipv6Addr>()
                .context("AAAA values must be IPv6 addresses")?;
        }
        Kind::Cname => {
            let target = content.trim_end_matches('.');
            if target != target.to_ascii_lowercase() || zone_name(target).is_err() {
                bail!("a CNAME value must be a lowercase host name such as edge.example.net");
            }
        }
        Kind::Txt => {
            if content.is_empty() || content.len() > 255 || content.chars().any(char::is_control) {
                bail!("a TXT value must be 1..255 bytes without control characters");
            }
        }
    }
    Ok(())
}

/// The values a record serves now: healthy ones, topped up in configured
/// order to `min_keep` so gating never empties a record below that.
pub fn served(
    values: &[Value],
    min_keep: usize,
    healthy: &mut impl FnMut(&crate::dns::HealthGate) -> bool,
) -> (Vec<String>, Vec<Option<bool>>) {
    let states: Vec<Option<bool>> = values
        .iter()
        .map(|value| value.health.as_ref().map(&mut *healthy))
        .collect();
    let mut keep: Vec<bool> = states.iter().map(|state| state.unwrap_or(true)).collect();
    let mut count = keep.iter().filter(|k| **k).count();
    for kept in &mut keep {
        if count >= min_keep {
            break;
        }
        if !*kept {
            *kept = true;
            count += 1;
        }
    }
    let answers = values
        .iter()
        .zip(keep)
        .filter(|(_, kept)| *kept)
        .map(|(value, _)| value.content.trim_end_matches('.').to_string())
        .collect();
    (answers, states)
}
/// Renders a zone for its members. `healthy` decides each gated value.
pub fn render(
    zone: &Zone,
    members: &[Member],
    records: &[Record],
    healthy: &mut impl FnMut(&crate::dns::HealthGate) -> bool,
) -> Result<ServeZone> {
    let mut sets = Vec::with_capacity(records.len());
    for record in records {
        let (values, _) = served(&record.values, zone.min_keep as usize, healthy);
        if values.is_empty() {
            continue;
        }
        sets.push(ServeSet {
            name: absolute(&record.name, &zone.name),
            kind: record.kind,
            ttl: record.ttl.unwrap_or(zone.ttl),
            values,
        });
    }
    sets.sort_by(|a, b| (&a.name, a.kind).cmp(&(&b.name, b.kind)));
    let mut nameservers: Vec<NameServer> = members
        .iter()
        .map(|member| NameServer {
            name: absolute(&member.label, &zone.name),
            address: member.advertise,
        })
        .collect();
    nameservers.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(ServeZone {
        name: zone.name.clone(),
        serial: zone.serial,
        hostmaster: hostmaster_name(&zone.hostmaster)?,
        ttl: zone.ttl,
        negative_ttl: zone.negative_ttl,
        nameservers,
        sets,
    })
}

fn fqdn(name: &str) -> Result<Name> {
    Ok(Name::from_ascii(format!("{}.", name.trim_end_matches('.')))?.to_lowercase())
}
fn kind_type(kind: Kind) -> RecordType {
    match kind {
        Kind::A => RecordType::A,
        Kind::Aaaa => RecordType::AAAA,
        Kind::Cname => RecordType::CNAME,
        Kind::Txt => RecordType::TXT,
    }
}

/// One zone indexed for answering.
struct Indexed {
    origin: Name,
    negative: WireRecord,
    sets: HashMap<(Name, RecordType), Vec<WireRecord>>,
    /// Every name that exists, including empty parents such as `b.zone` for `a.b.zone`.
    names: HashSet<Name>,
    glue: Vec<WireRecord>,
}
#[derive(Default)]
pub struct Catalog(Vec<Indexed>);

impl Catalog {
    /// Indexes the zones, skipping (and returning) any that cannot be served.
    pub fn build(zones: &[ServeZone]) -> (Self, Vec<String>) {
        let mut catalog = Self::default();
        let mut problems = vec![];
        for zone in zones {
            match Self::index(zone) {
                Ok(indexed) => catalog.0.push(indexed),
                Err(error) => problems.push(format!("{}: {error:#}", zone.name)),
            }
        }
        (catalog, problems)
    }
    fn index(zone: &ServeZone) -> Result<Indexed> {
        let origin = fqdn(&zone.name)?;
        let mut sets: HashMap<(Name, RecordType), Vec<WireRecord>> = HashMap::new();
        let primary = zone
            .nameservers
            .first()
            .map_or(zone.name.as_str(), |ns| ns.name.as_str());
        let soa = SOA::new(
            fqdn(primary)?,
            fqdn(&zone.hostmaster)?,
            zone.serial,
            3600,
            600,
            1_209_600,
            zone.negative_ttl,
        );
        sets.insert(
            (origin.clone(), RecordType::SOA),
            vec![WireRecord::from_rdata(
                origin.clone(),
                zone.ttl,
                RData::SOA(soa.clone()),
            )],
        );
        let negative = WireRecord::from_rdata(
            origin.clone(),
            zone.ttl.min(zone.negative_ttl),
            RData::SOA(soa),
        );
        let mut glue = vec![];
        for ns in &zone.nameservers {
            let name = fqdn(&ns.name)?;
            let ns_set = sets.entry((origin.clone(), RecordType::NS)).or_default();
            if !ns_set.iter().any(|r| r.data == RData::NS(NS(name.clone()))) {
                ns_set.push(WireRecord::from_rdata(
                    origin.clone(),
                    zone.ttl,
                    RData::NS(NS(name.clone())),
                ));
            }
            let (kind, data) = match ns.address {
                IpAddr::V4(ip) => (RecordType::A, RData::A(A(ip))),
                IpAddr::V6(ip) => (RecordType::AAAA, RData::AAAA(AAAA(ip))),
            };
            let record = WireRecord::from_rdata(name.clone(), zone.ttl, data);
            if origin.zone_of(&name) {
                glue.push(record.clone());
                sets.entry((name, kind)).or_default().push(record);
            }
        }
        for set in &zone.sets {
            let name = fqdn(&set.name)?;
            if !origin.zone_of(&name) {
                bail!("{} is outside the zone", set.name);
            }
            let records = set
                .values
                .iter()
                .map(|value| {
                    let data = match set.kind {
                        Kind::A => RData::A(A(value.parse()?)),
                        Kind::Aaaa => RData::AAAA(AAAA(value.parse()?)),
                        Kind::Cname => RData::CNAME(CNAME(fqdn(value)?)),
                        Kind::Txt => RData::TXT(TXT::new(vec![value.clone()])),
                    };
                    Ok(WireRecord::from_rdata(name.clone(), set.ttl, data))
                })
                .collect::<Result<Vec<_>>>()?;
            sets.entry((name, kind_type(set.kind)))
                .or_default()
                .extend(records);
        }
        let mut names = HashSet::new();
        for (name, _) in sets.keys() {
            let mut name = name.clone();
            while origin.zone_of(&name) && names.insert(name.clone()) && name != origin {
                name = name.base_name();
            }
        }
        Ok(Indexed {
            origin,
            negative,
            sets,
            names,
            glue,
        })
    }

    /// Fills the answer for one question and returns its response code.
    fn lookup(&self, query: &Query, response: &mut Message) -> ResponseCode {
        if query.query_class() != DNSClass::IN {
            return ResponseCode::Refused;
        }
        let mut name = query.name().to_lowercase();
        let Some(zone) = self
            .0
            .iter()
            .filter(|zone| zone.origin.zone_of(&name))
            .max_by_key(|zone| zone.origin.num_labels())
        else {
            return ResponseCode::Refused;
        };
        let qtype = query.query_type();
        if matches!(qtype, RecordType::AXFR | RecordType::IXFR) {
            return ResponseCode::Refused;
        }
        response.metadata.authoritative = true;
        // ANY gets the address records only (RFC 8482).
        let wanted: &[RecordType] = if qtype == RecordType::ANY {
            &[RecordType::A, RecordType::AAAA]
        } else {
            std::slice::from_ref(&qtype)
        };
        for _ in 0..8 {
            let mut found = false;
            for kind in wanted {
                if let Some(set) = zone.sets.get(&(name.clone(), *kind)) {
                    response.add_answers(set.iter().cloned());
                    found = true;
                }
            }
            if found {
                if qtype == RecordType::NS && name == zone.origin {
                    response.add_additionals(zone.glue.iter().cloned());
                }
                return ResponseCode::NoError;
            }
            let Some(chain) = zone.sets.get(&(name.clone(), RecordType::CNAME)) else {
                break;
            };
            if qtype == RecordType::CNAME {
                break;
            }
            response.add_answers(chain.iter().cloned());
            let RData::CNAME(CNAME(target)) = &chain[0].data else {
                break;
            };
            if !zone.origin.zone_of(target) {
                // The resolver follows a target outside the zone itself.
                return ResponseCode::NoError;
            }
            name = target.to_lowercase();
        }
        response.add_authority(zone.negative.clone());
        if zone.names.contains(&name) {
            ResponseCode::NoError
        } else {
            ResponseCode::NXDomain
        }
    }
}

#[derive(Default)]
struct Counters {
    queries: AtomicU64,
    nxdomain: AtomicU64,
    refused: AtomicU64,
    truncated: AtomicU64,
    limited: AtomicU64,
}

/// Answers one DNS message, or `None` when it must be dropped (not a query,
/// or unreadable). Over UDP the answer is cut to the client's EDNS size.
fn respond(catalog: &Catalog, request: &[u8], udp: bool, counters: &Counters) -> Option<Vec<u8>> {
    let query = Message::from_vec(request).ok()?;
    if query.metadata.message_type != MessageType::Query {
        return None;
    }
    counters.queries.fetch_add(1, Ordering::Relaxed);
    let mut response = Message::response(query.metadata.id, query.metadata.op_code);
    response.metadata.recursion_desired = query.metadata.recursion_desired;
    response.add_queries(query.queries.iter().cloned());
    if query.edns.is_some() {
        let mut edns = Edns::new();
        edns.set_max_payload(UDP_LIMIT);
        response.set_edns(edns);
    }
    let code = if query.metadata.op_code != OpCode::Query {
        ResponseCode::NotImp
    } else if query.queries.len() != 1 {
        ResponseCode::FormErr
    } else {
        catalog.lookup(&query.queries[0], &mut response)
    };
    response.metadata.response_code = code;
    match code {
        ResponseCode::NXDomain => counters.nxdomain.fetch_add(1, Ordering::Relaxed),
        ResponseCode::Refused => counters.refused.fetch_add(1, Ordering::Relaxed),
        _ => 0,
    };
    let bytes = response.to_vec().ok()?;
    let limit = if udp {
        query
            .edns
            .as_ref()
            .map_or(512, |edns| edns.max_payload().clamp(512, UDP_LIMIT)) as usize
    } else {
        u16::MAX as usize
    };
    if bytes.len() > limit {
        counters.truncated.fetch_add(1, Ordering::Relaxed);
        return response.truncate().to_vec().ok();
    }
    Some(bytes)
}

#[derive(Default)]
struct Limiter(Mutex<HashMap<IpAddr, (f64, Instant)>>);
impl Limiter {
    fn allow(&self, ip: IpAddr) -> bool {
        let key = match crate::model::canonical_ip(ip) {
            IpAddr::V4(ip) => IpAddr::V4((u32::from(ip) & 0xffff_ff00).into()),
            IpAddr::V6(ip) => IpAddr::V6((u128::from(ip) & !((1u128 << 72) - 1)).into()),
        };
        let now = Instant::now();
        let mut buckets = self.0.lock().unwrap();
        if buckets.len() >= 65_536 {
            buckets.retain(|_, (_, seen)| now.duration_since(*seen) < Duration::from_secs(2));
        }
        let (tokens, seen) = buckets.entry(key).or_insert((RATE_BURST, now));
        *tokens =
            (*tokens + now.duration_since(*seen).as_secs_f64() * RATE_PER_SECOND).min(RATE_BURST);
        *seen = now;
        if *tokens >= 1.0 {
            *tokens -= 1.0;
            true
        } else {
            false
        }
    }
}

#[derive(Default)]
struct Shared {
    catalog: RwLock<Arc<Catalog>>,
    counters: Counters,
    limiter: Limiter,
}
impl Shared {
    fn answer(&self, request: &[u8], udp: bool) -> Option<Vec<u8>> {
        let catalog = self.catalog.read().unwrap().clone();
        respond(&catalog, request, udp, &self.counters)
    }
}

/// The agent's DNS server: listeners follow the latest snapshot.
#[derive(Default)]
pub struct Responder {
    shared: Arc<Shared>,
    digest: String,
    wanted: Vec<SocketAddr>,
    listeners: BTreeMap<SocketAddr, CancellationToken>,
    failed: BTreeMap<SocketAddr, String>,
    retry_at: Option<Instant>,
    problems: Vec<String>,
}
impl Drop for Responder {
    fn drop(&mut self) {
        for stop in self.listeners.values() {
            stop.cancel();
        }
    }
}
impl Responder {
    /// Serves `snapshot` from now on. Must run inside a Tokio runtime.
    pub fn apply(&mut self, snapshot: &Snapshot) {
        if snapshot.digest != self.digest {
            let (catalog, problems) = Catalog::build(&snapshot.zones);
            *self.shared.catalog.write().unwrap() = Arc::new(catalog);
            self.problems = problems;
            self.digest = snapshot.digest.clone();
            self.wanted = snapshot.listen.clone();
            let wanted = &self.wanted;
            self.listeners.retain(|address, stop| {
                let keep = wanted.contains(address);
                if !keep {
                    stop.cancel();
                }
                keep
            });
            self.failed.retain(|address, _| wanted.contains(address));
            self.retry_at = None;
        }
        if self.retry_at.is_some_and(|at| Instant::now() < at) {
            return;
        }
        for address in self.wanted.clone() {
            if self.listeners.contains_key(&address) {
                continue;
            }
            match self.bind(address) {
                Ok(stop) => {
                    self.listeners.insert(address, stop);
                    self.failed.remove(&address);
                }
                Err(error) => {
                    let reason = match error.kind() {
                        std::io::ErrorKind::PermissionDenied => "permission denied: ports below 1024 need CAP_NET_BIND_SERVICE (deploy/relay-agent-dns.conf)".to_string(),
                        std::io::ErrorKind::AddrInUse => "address in use: another program (often a local DNS server) already listens there".to_string(),
                        std::io::ErrorKind::AddrNotAvailable => "address not available: it is not assigned to this server".to_string(),
                        _ => error.to_string(),
                    };
                    tracing::warn!(%address, %reason, "authoritative DNS listener unavailable");
                    self.failed.insert(address, reason);
                }
            }
        }
        self.retry_at = (!self.failed.is_empty()).then(|| Instant::now() + BIND_RETRY);
    }
    pub fn report(&self) -> ServeStats {
        let counters = &self.shared.counters;
        ServeStats {
            digest: self.digest.clone(),
            listening: self.listeners.keys().copied().collect(),
            errors: self
                .failed
                .iter()
                .map(|(address, reason)| format!("{address}: {reason}"))
                .chain(self.problems.iter().cloned())
                .collect(),
            queries: counters.queries.load(Ordering::Relaxed),
            nxdomain: counters.nxdomain.load(Ordering::Relaxed),
            refused: counters.refused.load(Ordering::Relaxed),
            truncated: counters.truncated.load(Ordering::Relaxed),
            limited: counters.limited.load(Ordering::Relaxed),
        }
    }
    fn bind(&self, address: SocketAddr) -> std::io::Result<CancellationToken> {
        let socket = |kind: Type| -> std::io::Result<Socket> {
            let socket = Socket::new(Domain::for_address(address), kind, None)?;
            if address.is_ipv6() {
                socket.set_only_v6(true)?;
            }
            socket.set_nonblocking(true)?;
            Ok(socket)
        };
        let udp = socket(Type::DGRAM)?;
        udp.bind(&address.into())?;
        let udp = tokio::net::UdpSocket::from_std(udp.into())?;
        let tcp = socket(Type::STREAM)?;
        tcp.set_reuse_address(true)?;
        tcp.bind(&address.into())?;
        tcp.listen(128)?;
        let tcp = tokio::net::TcpListener::from_std(tcp.into())?;
        let stop = CancellationToken::new();
        tokio::spawn(serve_udp(udp, self.shared.clone(), stop.clone()));
        tokio::spawn(serve_tcp(tcp, self.shared.clone(), stop.clone()));
        Ok(stop)
    }
}

async fn serve_udp(socket: tokio::net::UdpSocket, shared: Arc<Shared>, stop: CancellationToken) {
    let mut buffer = vec![0u8; 4096];
    loop {
        let received = tokio::select! {
            _ = stop.cancelled() => return,
            received = socket.recv_from(&mut buffer) => received,
        };
        let Ok((length, peer)) = received else {
            // ICMP errors from earlier replies surface here on some systems.
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        };
        if !shared.limiter.allow(peer.ip()) {
            shared.counters.limited.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        if let Some(reply) = shared.answer(&buffer[..length], true) {
            let _ = socket.send_to(&reply, peer).await;
        }
    }
}

async fn serve_tcp(
    listener: tokio::net::TcpListener,
    shared: Arc<Shared>,
    stop: CancellationToken,
) {
    let slots = Arc::new(tokio::sync::Semaphore::new(TCP_CONNECTIONS));
    loop {
        let accepted = tokio::select! {
            _ = stop.cancelled() => return,
            accepted = listener.accept() => accepted,
        };
        let Ok((stream, _)) = accepted else {
            tokio::time::sleep(Duration::from_millis(10)).await;
            continue;
        };
        // Over the limit the connection is closed at once.
        let Ok(slot) = slots.clone().try_acquire_owned() else {
            continue;
        };
        let (shared, stop) = (shared.clone(), stop.clone());
        tokio::spawn(async move {
            let _slot = slot;
            tokio::select! {
                _ = stop.cancelled() => {}
                _ = serve_stream(stream, &shared) => {}
            }
        });
    }
}

async fn serve_stream(mut stream: tokio::net::TcpStream, shared: &Shared) -> std::io::Result<()> {
    let idle = |_| std::io::Error::from(std::io::ErrorKind::TimedOut);
    for _ in 0..100 {
        let mut length = [0u8; 2];
        tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut length))
            .await
            .map_err(idle)??;
        let mut request = vec![0; u16::from_be_bytes(length) as usize];
        tokio::time::timeout(TCP_IDLE, stream.read_exact(&mut request))
            .await
            .map_err(idle)??;
        let Some(reply) = shared.answer(&request, false) else {
            return Ok(());
        };
        let mut framed = Vec::with_capacity(reply.len() + 2);
        framed.extend_from_slice(&(reply.len() as u16).to_be_bytes());
        framed.extend_from_slice(&reply);
        stream.write_all(&framed).await?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::dns::HealthGate;

    fn zone() -> ServeZone {
        let set = |name: &str, kind, values: &[&str]| ServeSet {
            name: name.into(),
            kind,
            ttl: 30,
            values: values.iter().map(|v| v.to_string()).collect(),
        };
        ServeZone {
            name: "edge.example.com".into(),
            serial: 7,
            hostmaster: "hostmaster.example.com".into(),
            ttl: 60,
            negative_ttl: 45,
            nameservers: vec![
                NameServer {
                    name: "ns1.edge.example.com".into(),
                    address: "192.0.2.1".parse().unwrap(),
                },
                NameServer {
                    name: "ns2.edge.example.com".into(),
                    address: "2001:db8::2".parse().unwrap(),
                },
            ],
            sets: vec![
                set("edge.example.com", Kind::A, &["198.51.100.1"]),
                set(
                    "www.edge.example.com",
                    Kind::Cname,
                    &["app.deep.edge.example.com"],
                ),
                set(
                    "app.deep.edge.example.com",
                    Kind::A,
                    &["198.51.100.7", "198.51.100.8"],
                ),
                set("out.edge.example.com", Kind::Cname, &["cdn.example.net"]),
                set("txt.edge.example.com", Kind::Txt, &["v=spf1 -all"]),
                set(
                    "big.edge.example.com",
                    Kind::A,
                    &(1..=60)
                        .map(|i| format!("203.0.113.{i}"))
                        .collect::<Vec<_>>()
                        .iter()
                        .map(String::as_str)
                        .collect::<Vec<_>>(),
                ),
            ],
        }
    }
    fn ask(name: &str, kind: RecordType, edns: Option<u16>, udp: bool) -> Message {
        let (catalog, problems) = Catalog::build(&[zone()]);
        assert!(problems.is_empty(), "{problems:?}");
        let mut query = Message::query();
        query.metadata.recursion_desired = true;
        query.add_query(Query::query(Name::from_ascii(name).unwrap(), kind));
        if let Some(size) = edns {
            let mut e = Edns::new();
            e.set_max_payload(size);
            query.set_edns(e);
        }
        let reply = respond(
            &catalog,
            &query.to_vec().unwrap(),
            udp,
            &Counters::default(),
        )
        .unwrap();
        let reply = Message::from_vec(&reply).unwrap();
        assert_eq!(reply.metadata.id, query.metadata.id);
        assert!(reply.metadata.recursion_desired && !reply.metadata.recursion_available);
        reply
    }
    fn values(reply: &Message) -> Vec<String> {
        reply.answers.iter().map(|r| r.data.to_string()).collect()
    }

    #[test]
    fn answers_follow_the_zone_and_negative_answers_carry_the_soa() {
        // Case does not matter, and CNAMEs inside the zone are followed.
        let reply = ask("WWW.Edge.Example.com.", RecordType::A, None, true);
        assert_eq!(reply.metadata.response_code, ResponseCode::NoError);
        assert!(reply.metadata.authoritative);
        assert_eq!(
            values(&reply),
            ["app.deep.edge.example.com.", "198.51.100.7", "198.51.100.8"]
        );
        // A CNAME leaving the zone is returned alone for the resolver to follow.
        assert_eq!(
            values(&ask("out.edge.example.com.", RecordType::A, None, true)),
            ["cdn.example.net."]
        );
        // An existing name without the asked type: NOERROR with the SOA.
        let nodata = ask("txt.edge.example.com.", RecordType::AAAA, None, true);
        assert_eq!(nodata.metadata.response_code, ResponseCode::NoError);
        assert!(nodata.answers.is_empty());
        assert_eq!(nodata.authorities[0].record_type(), RecordType::SOA);
        assert_eq!(nodata.authorities[0].ttl, 45);
        // An empty parent of an existing name also exists.
        assert_eq!(
            ask("deep.edge.example.com.", RecordType::A, None, true)
                .metadata
                .response_code,
            ResponseCode::NoError
        );
        let missing = ask("nope.edge.example.com.", RecordType::A, None, true);
        assert_eq!(missing.metadata.response_code, ResponseCode::NXDomain);
        assert_eq!(missing.authorities.len(), 1);
        // Names outside every zone are refused, not answered.
        let other = ask("example.com.", RecordType::A, None, true);
        assert_eq!(other.metadata.response_code, ResponseCode::Refused);
        assert!(!other.metadata.authoritative);
        assert_eq!(
            ask("edge.example.com.", RecordType::AXFR, None, false)
                .metadata
                .response_code,
            ResponseCode::Refused
        );
        assert_eq!(
            values(&ask("txt.edge.example.com.", RecordType::TXT, None, true)),
            ["v=spf1 -all"]
        );
    }

    #[test]
    fn apex_serves_soa_ns_with_glue_and_any_gets_addresses_only() {
        let soa = ask("edge.example.com.", RecordType::SOA, None, true);
        assert_eq!(
            values(&soa),
            ["ns1.edge.example.com. hostmaster.example.com. 7 3600 600 1209600 45"]
        );
        let ns = ask("edge.example.com.", RecordType::NS, None, true);
        assert_eq!(
            values(&ns),
            ["ns1.edge.example.com.", "ns2.edge.example.com."]
        );
        let glue: Vec<String> = ns
            .additionals
            .iter()
            .map(|r| format!("{} {}", r.name, r.data))
            .collect();
        assert_eq!(
            glue,
            [
                "ns1.edge.example.com. 192.0.2.1",
                "ns2.edge.example.com. 2001:db8::2"
            ]
        );
        assert_eq!(
            values(&ask("ns2.edge.example.com.", RecordType::AAAA, None, true)),
            ["2001:db8::2"]
        );
        assert_eq!(
            values(&ask("edge.example.com.", RecordType::ANY, None, true)),
            ["198.51.100.1"]
        );
    }

    #[test]
    fn udp_answers_respect_the_edns_size_and_tcp_carries_them_whole() {
        let plain = ask("big.edge.example.com.", RecordType::A, None, true);
        assert!(plain.metadata.truncation && plain.answers.is_empty());
        let edns = ask("big.edge.example.com.", RecordType::A, Some(4096), true);
        assert!(!edns.metadata.truncation, "60 addresses fit in 1232 bytes");
        assert_eq!(edns.answers.len(), 60);
        assert_eq!(edns.edns.as_ref().unwrap().max_payload(), 1232);
        let tcp = ask("big.edge.example.com.", RecordType::A, None, false);
        assert!(!tcp.metadata.truncation);
        assert_eq!(tcp.answers.len(), 60);
    }

    #[test]
    fn health_gating_keeps_min_keep_values_in_configured_order() {
        let gate = |rule: &str| {
            Some(HealthGate {
                node_id: "n".into(),
                rule_id: rule.into(),
            })
        };
        let values = vec![
            Value {
                content: "192.0.2.1".into(),
                health: gate("down-1"),
            },
            Value {
                content: "192.0.2.2".into(),
                health: gate("up"),
            },
            Value {
                content: "192.0.2.3".into(),
                health: gate("down-2"),
            },
        ];
        let mut healthy = |g: &HealthGate| g.rule_id == "up";
        assert_eq!(served(&values, 0, &mut healthy).0, ["192.0.2.2"]);
        assert_eq!(served(&values, 1, &mut healthy).0, ["192.0.2.2"]);
        // Topped up from the first unhealthy value, keeping configured order.
        assert_eq!(
            served(&values, 2, &mut healthy),
            (
                vec!["192.0.2.1".to_string(), "192.0.2.2".into()],
                vec![Some(false), Some(true), Some(false)]
            )
        );
        let mut none = |_: &HealthGate| false;
        assert!(served(&values, 0, &mut none).0.is_empty());
    }

    #[test]
    fn names_and_contacts_are_validated() {
        assert_eq!(zone_name("Edge.Example.com.").unwrap(), "edge.example.com");
        assert!(zone_name("com").is_err() && zone_name("-a.example.com").is_err());
        assert_eq!(
            record_name("_acme-challenge.API", "edge.example.com").unwrap(),
            "_acme-challenge.api"
        );
        assert!(record_name("*", "edge.example.com").is_err());
        assert_eq!(
            hostmaster_name("hostmaster@example.com").unwrap(),
            "hostmaster.example.com"
        );
        assert!(hostmaster_name("first.last@example.com").is_err());
        assert!(validate_value(Kind::Cname, "edge.example.net").is_ok());
        assert!(validate_value(Kind::A, "2001:db8::1").is_err());
        assert!(validate_value(Kind::Txt, "line\nbreak").is_err());
    }

    #[test]
    fn requests_that_are_not_queries_are_dropped_or_refused() {
        let (catalog, _) = Catalog::build(&[zone()]);
        let counters = Counters::default();
        assert!(respond(&catalog, b"garbage", true, &counters).is_none());
        let mut response = Message::response(9, OpCode::Query);
        response.add_query(Query::query(
            Name::from_ascii("edge.example.com.").unwrap(),
            RecordType::A,
        ));
        assert!(
            respond(&catalog, &response.to_vec().unwrap(), true, &counters).is_none(),
            "never answer a response"
        );
        let mut notify = Message::new(10, MessageType::Query, OpCode::Notify);
        notify.add_query(Query::query(
            Name::from_ascii("edge.example.com.").unwrap(),
            RecordType::SOA,
        ));
        let reply = Message::from_vec(
            &respond(&catalog, &notify.to_vec().unwrap(), true, &counters).unwrap(),
        )
        .unwrap();
        assert_eq!(reply.metadata.response_code, ResponseCode::NotImp);
    }
}
