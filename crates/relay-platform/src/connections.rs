//! Live connections and block records of each rule (连接统计 and 拦截记录).
//!
//! On an agent, [`Registry`] holds every open session of every rule: TCP
//! connections of each inbound kind and UDP sessions and associations, with
//! the client as the rule sees it, the target or requested destination and
//! byte counts. Registering takes a short lock on one of [`SHARDS`] maps and
//! never awaits; the [`Tracked`] guard removes the entry on every exit path.
//! Byte counters are atomics, added where the forwarding counters are.
//!
//! [`Blocks`] records every refused connection, UDP session or datagram with
//! a reason. Repeats of the same rule, source IP and reason within
//! [`WINDOW_MS`] of the first are one entry with a count. At most [`KEEP`]
//! entries are kept and the one changed longest ago goes first, so a flood
//! costs one short lock per refusal and no memory beyond that bound.
//!
//! Nothing is sent unless the controller asked: it says it takes reports in
//! every sync reply, asks for one rule's sessions with
//! `SyncResponse::live_connection_requests` and for block records after a
//! [`Cursor`], as for log lines ([`crate::logs`]). An entry that changes gets
//! a new sequence number and is sent again; the controller ([`Kept`])
//! replaces its copy, so nothing is counted twice.
use crate::model::{ConnectionCounts, RuleRef, Target, canonical_ip, identifier, now_ms};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap},
    net::{IpAddr, SocketAddr},
    ops::Bound,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
};

/// Sessions in one snapshot, newest first; the totals count all of them.
pub const MAX_SESSIONS: usize = 200;
/// Snapshots in one report; further requests wait for the next one.
pub const MAX_SNAPSHOTS: usize = 4;
/// Block records an agent keeps, and the controller keeps per node.
pub const KEEP: usize = 1000;
/// Block records in one report.
pub const BATCH: usize = 200;
/// Identical refusals within this time of the first are one record.
pub const WINDOW_MS: i64 = 60_000;
pub const DETAIL_CHARS: usize = 120;
/// Targets are at most 300 bytes; destinations are clipped to the same.
const ADDRESS_BYTES: usize = 300;
const NAME_BYTES: usize = 32;
const SHARDS: usize = 16;
/// Rules whose refusals are counted by reason. A stream of new rule ids
/// stops being counted there; their records are still kept.
const COUNTED_RULES: usize = 4096;

/// Why a connection, UDP session or datagram was refused.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Reason {
    /// The rule has an allow list and the source is not in it.
    SourceNotAllowed,
    /// The source is in the rule's deny list.
    SourceDenied,
    /// The rule takes PROXY headers and the sender is not trusted.
    ProxyUntrusted,
    Expired,
    ConnectionLimit,
    UdpSessionLimit,
    Http2StreamLimit,
    /// The rule's quota is used up.
    Quota,
    /// A shared budget refused, or granted nothing in time.
    Budget,
    /// The meter admits nothing for another reason: the rule is not active
    /// on this agent.
    Inactive,
    /// No target takes new sessions: all paused, unhealthy or full.
    NoTarget,
    /// A proxy client's destination is outside the destination rules or not
    /// a public address.
    DestinationDenied,
    AuthFailed,
    HandshakeFailed,
    /// A firewall rule set refused the client or the destination; the
    /// detail names the layer, the set and its rule or default action.
    Firewall,
}
impl Reason {
    const ALL: [Self; 15] = [
        Self::SourceNotAllowed,
        Self::SourceDenied,
        Self::ProxyUntrusted,
        Self::Expired,
        Self::ConnectionLimit,
        Self::UdpSessionLimit,
        Self::Http2StreamLimit,
        Self::Quota,
        Self::Budget,
        Self::Inactive,
        Self::NoTarget,
        Self::DestinationDenied,
        Self::AuthFailed,
        Self::HandshakeFailed,
        Self::Firewall,
    ];
    pub fn as_str(self) -> &'static str {
        match self {
            Self::SourceNotAllowed => "source_not_allowed",
            Self::SourceDenied => "source_denied",
            Self::ProxyUntrusted => "proxy_untrusted",
            Self::Expired => "expired",
            Self::ConnectionLimit => "connection_limit",
            Self::UdpSessionLimit => "udp_session_limit",
            Self::Http2StreamLimit => "http2_stream_limit",
            Self::Quota => "quota",
            Self::Budget => "budget",
            Self::Inactive => "inactive",
            Self::NoTarget => "no_target",
            Self::DestinationDenied => "destination_denied",
            Self::AuthFailed => "auth_failed",
            Self::HandshakeFailed => "handshake_failed",
            Self::Firewall => "firewall",
        }
    }
    fn index(self) -> usize {
        Self::ALL.iter().position(|r| *r == self).unwrap_or(0)
    }
}

/// An agent's answer to a controller that takes reports. Its presence
/// tells the controller the agent keeps sessions and block records.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    /// The rules the controller asked for in its last reply.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub snapshots: Vec<Snapshot>,
    /// Records changed after the controller's cursor.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub blocks: Option<BlockBatch>,
}
impl Report {
    pub fn within_limits(&self) -> bool {
        self.snapshots.len() <= MAX_SNAPSHOTS
            && self.snapshots.iter().all(Snapshot::within_limits)
            && self.blocks.as_ref().is_none_or(BlockBatch::within_limits)
    }
}

/// One rule's open sessions when the agent answered.
#[derive(Clone, Debug, Default, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub rule_id: String,
    pub taken_at_ms: i64,
    /// All open TCP sessions and UDP sessions of the rule, also those left out.
    pub tcp: u64,
    pub udp: u64,
    /// The newest [`MAX_SESSIONS`].
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub sessions: Vec<Session>,
    /// Refusals of the rule by reason since the agent started.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub refused: Vec<ReasonCount>,
}
impl Snapshot {
    fn within_limits(&self) -> bool {
        self.rule_id.len() <= 80
            && self.sessions.len() <= MAX_SESSIONS
            && self.refused.len() <= Reason::ALL.len()
            && self.refused.iter().all(|r| r.reason.len() <= NAME_BYTES)
            && self.sessions.iter().all(Session::within_limits)
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReasonCount {
    pub reason: String,
    pub count: u64,
}

/// One open session.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Session {
    pub id: u64,
    /// How the client reached the rule: `tcp`, `tls`, `websocket`, `wss`,
    /// `socks5`, `socks5_udp`, `http_connect`, `http2_connect`,
    /// `shadowsocks`, `shadowsocks_uot`, `multipath`, `gateway`, `udp` or
    /// `shadowsocks_udp`.
    pub protocol: String,
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub udp: bool,
    /// After a PROXY header, the address it carried.
    pub client: SocketAddr,
    pub started_ms: i64,
    /// The configured target the session uses.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target_index: Option<usize>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub target: String,
    /// The address the agent connected to.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub remote: Option<SocketAddr>,
    /// The next hop's rule when the target is another server's rule.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub via: Option<RuleRef>,
    /// What a proxy client (SOCKS5, HTTP CONNECT, HTTP/2 CONNECT,
    /// Shadowsocks, protocol gateway) asked for; for HTTP/2 CONNECT the
    /// latest stream's.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub destination: String,
    pub upload_bytes: u64,
    pub download_bytes: u64,
}
impl Session {
    fn within_limits(&self) -> bool {
        self.protocol.len() <= NAME_BYTES
            && self.target.len() <= ADDRESS_BYTES
            && self.destination.len() <= ADDRESS_BYTES
            && self
                .via
                .as_ref()
                .is_none_or(|v| v.node_id.len() <= 80 && v.rule_id.len() <= 80)
    }
}

/// Block records of one agent run, oldest change first; `stream` is new on
/// every start.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BlockBatch {
    pub stream: String,
    pub entries: Vec<Block>,
}
impl BlockBatch {
    fn within_limits(&self) -> bool {
        self.stream.len() <= 64
            && self.entries.len() <= BATCH
            && self.entries.iter().all(|b| {
                b.rule_id.len() <= 80
                    && b.protocol.len() <= NAME_BYTES
                    && b.reason.len() <= NAME_BYTES
                    && b.detail.chars().count() <= DETAIL_CHARS
                    && b.detail.len() <= DETAIL_CHARS * 4
            })
    }
}

/// Refusals of one rule, source IP and reason from `first_ms` on.
#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Block {
    /// Stays the same within a stream while the record grows.
    pub id: u64,
    /// The record's latest change.
    pub seq: u64,
    pub rule_id: String,
    pub protocol: String,
    pub source: IpAddr,
    pub reason: String,
    /// At most [`DETAIL_CHARS`]; never credentials or payload.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
    pub first_ms: i64,
    pub last_ms: i64,
    pub count: u64,
}

/// The last record the controller holds from a node. An unknown stream
/// asks for every record the agent still keeps.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct Cursor {
    pub stream: String,
    pub seq: u64,
}

fn lock<T>(mutex: &Mutex<T>) -> MutexGuard<'_, T> {
    mutex
        .lock()
        .unwrap_or_else(|poisoned| poisoned.into_inner())
}
fn clip_bytes(text: &str, limit: usize) -> String {
    let mut end = text.len().min(limit);
    while !text.is_char_boundary(end) {
        end -= 1;
    }
    text[..end].to_owned()
}
/// At most [`DETAIL_CHARS`] characters, without control characters.
pub fn clip_detail(text: &str) -> String {
    text.chars()
        .filter(|c| !c.is_control())
        .take(DETAIL_CHARS)
        .collect()
}

/// How a client reaches a rule, as [`Session::protocol`] names it.
pub fn protocol(rule: &crate::model::Rule, udp: bool) -> &'static str {
    if udp {
        return if rule.inbound_shadowsocks.is_some() {
            "shadowsocks_udp"
        } else {
            "udp"
        };
    }
    if rule.protocol_gateway.is_some() {
        "gateway"
    } else if rule.inbound_http2_connect.is_some() {
        "http2_connect"
    } else if rule.inbound_http_connect.is_some() {
        "http_connect"
    } else if rule.inbound_socks5.is_some() {
        "socks5"
    } else if rule.inbound_shadowsocks.is_some() {
        "shadowsocks"
    } else if rule.inbound_multipath.is_some() {
        "multipath"
    } else if rule.inbound_websocket.is_some() {
        if rule.inbound_tls.is_some() {
            "wss"
        } else {
            "websocket"
        }
    } else if rule.inbound_tls.is_some() {
        "tls"
    } else {
        "tcp"
    }
}

/// Every open session of an agent.
pub struct Registry {
    next: AtomicU64,
    shards: [Mutex<HashMap<u64, Arc<Live>>>; SHARDS],
}
impl Default for Registry {
    fn default() -> Self {
        Self {
            next: AtomicU64::new(1),
            shards: std::array::from_fn(|_| Mutex::default()),
        }
    }
}

/// One open session. Its details are set as setup goes on; its byte
/// counters grow as data is forwarded.
pub struct Live {
    id: u64,
    rule: Arc<str>,
    udp: bool,
    started_ms: i64,
    upload: AtomicU64,
    download: AtomicU64,
    detail: Mutex<Detail>,
}
struct Detail {
    protocol: &'static str,
    client: SocketAddr,
    target: Option<(usize, String)>,
    remote: Option<SocketAddr>,
    via: Option<RuleRef>,
    destination: String,
}

/// Keeps a session listed until dropped.
pub struct Tracked {
    registry: Arc<Registry>,
    live: Arc<Live>,
}
impl Drop for Tracked {
    fn drop(&mut self) {
        lock(&self.registry.shards[self.live.id as usize % SHARDS]).remove(&self.live.id);
    }
}
impl std::ops::Deref for Tracked {
    type Target = Arc<Live>;
    fn deref(&self) -> &Arc<Live> {
        &self.live
    }
}

impl Registry {
    /// Lists a new session of `rule` until the returned guard is dropped.
    pub fn track(
        self: &Arc<Self>,
        rule: &Arc<str>,
        protocol: &'static str,
        udp: bool,
        client: SocketAddr,
    ) -> Tracked {
        let id = self.next.fetch_add(1, Ordering::Relaxed);
        let live = Arc::new(Live {
            id,
            rule: rule.clone(),
            udp,
            started_ms: now_ms(),
            upload: AtomicU64::new(0),
            download: AtomicU64::new(0),
            detail: Mutex::new(Detail {
                protocol,
                client,
                target: None,
                remote: None,
                via: None,
                destination: String::new(),
            }),
        });
        lock(&self.shards[id as usize % SHARDS]).insert(id, live.clone());
        Tracked {
            registry: self.clone(),
            live,
        }
    }
    /// Open sessions of every rule.
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| lock(s).len()).sum()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// `rule`'s open TCP and UDP sessions and the newest [`MAX_SESSIONS`].
    pub fn snapshot(&self, rule: &str) -> (u64, u64, Vec<Session>) {
        let mut found: Vec<Arc<Live>> = vec![];
        for shard in &self.shards {
            found.extend(
                lock(shard)
                    .values()
                    .filter(|live| &*live.rule == rule)
                    .cloned(),
            );
        }
        let udp = found.iter().filter(|live| live.udp).count() as u64;
        let tcp = found.len() as u64 - udp;
        found.sort_unstable_by_key(|live| std::cmp::Reverse((live.started_ms, live.id)));
        found.truncate(MAX_SESSIONS);
        (tcp, udp, found.iter().map(|live| live.view()).collect())
    }
}

impl Live {
    pub fn rule(&self) -> &Arc<str> {
        &self.rule
    }
    pub fn add_upload(&self, bytes: u64) {
        self.upload.fetch_add(bytes, Ordering::Relaxed);
    }
    pub fn add_download(&self, bytes: u64) {
        self.download.fetch_add(bytes, Ordering::Relaxed);
    }
    pub fn client(&self) -> SocketAddr {
        lock(&self.detail).client
    }
    pub fn protocol(&self) -> &'static str {
        lock(&self.detail).protocol
    }
    /// The client a PROXY header named.
    pub fn set_client(&self, client: SocketAddr) {
        lock(&self.detail).client = client;
    }
    pub fn set_protocol(&self, protocol: &'static str) {
        lock(&self.detail).protocol = protocol;
    }
    pub fn set_destination(&self, destination: &str) {
        lock(&self.detail).destination = clip_bytes(destination, ADDRESS_BYTES);
    }
    pub fn set_remote(&self, remote: SocketAddr) {
        lock(&self.detail).remote = Some(remote);
    }
    /// The configured target the session uses, and where it connected.
    pub fn set_target(&self, index: usize, target: &Target, remote: Option<SocketAddr>) {
        let address = clip_bytes(&target.address, ADDRESS_BYTES);
        let mut detail = lock(&self.detail);
        detail.target = Some((index, address));
        detail.via = target.via.clone();
        detail.remote = remote;
    }
    fn view(&self) -> Session {
        let detail = lock(&self.detail);
        Session {
            id: self.id,
            protocol: detail.protocol.to_owned(),
            udp: self.udp,
            client: detail.client,
            started_ms: self.started_ms,
            target_index: detail.target.as_ref().map(|(index, _)| *index),
            target: detail
                .target
                .as_ref()
                .map(|(_, address)| address.clone())
                .unwrap_or_default(),
            remote: detail.remote,
            via: detail.via.clone(),
            destination: detail.destination.clone(),
            upload_bytes: self.upload.load(Ordering::Relaxed),
            download_bytes: self.download.load(Ordering::Relaxed),
        }
    }
}

/// An agent's latest block records.
pub struct Blocks(Mutex<Ring>);
struct Ring {
    stream: String,
    next: u64,
    entries: HashMap<u64, Entry>,
    /// Entries by their latest change.
    order: BTreeMap<u64, u64>,
    /// Entries that repeats may still join, by rule, source and reason.
    open: HashMap<(Arc<str>, IpAddr, Reason), u64>,
    refused: HashMap<Arc<str>, [u64; Reason::ALL.len()]>,
}
struct Entry {
    id: u64,
    seq: u64,
    rule: Arc<str>,
    protocol: &'static str,
    source: IpAddr,
    reason: Reason,
    detail: String,
    first_ms: i64,
    last_ms: i64,
    count: u64,
}
impl Default for Blocks {
    fn default() -> Self {
        Self(Mutex::new(Ring {
            stream: uuid::Uuid::new_v4().simple().to_string(),
            next: 1,
            entries: HashMap::new(),
            order: BTreeMap::new(),
            open: HashMap::new(),
            refused: HashMap::new(),
        }))
    }
}
impl Blocks {
    /// Records a refusal. `detail` is only built for a new record.
    pub fn record(
        &self,
        rule: &Arc<str>,
        protocol: &'static str,
        source: IpAddr,
        reason: Reason,
        detail: impl FnOnce() -> String,
    ) {
        self.record_at(now_ms(), rule, protocol, source, reason, detail);
    }
    fn record_at(
        &self,
        now: i64,
        rule: &Arc<str>,
        protocol: &'static str,
        source: IpAddr,
        reason: Reason,
        detail: impl FnOnce() -> String,
    ) {
        let source = canonical_ip(source);
        let mut ring = lock(&self.0);
        let Ring {
            next,
            entries,
            order,
            open,
            refused,
            ..
        } = &mut *ring;
        if let Some(counts) = refused.get_mut(&**rule) {
            counts[reason.index()] += 1;
        } else if refused.len() < COUNTED_RULES {
            let mut counts = [0; Reason::ALL.len()];
            counts[reason.index()] = 1;
            refused.insert(rule.clone(), counts);
        }
        let key = (rule.clone(), source, reason);
        if let Some(&id) = open.get(&key) {
            if let Some(entry) = entries.get_mut(&id)
                && now.saturating_sub(entry.first_ms) < WINDOW_MS
            {
                order.remove(&entry.seq);
                entry.seq = *next;
                *next += 1;
                order.insert(entry.seq, id);
                entry.count += 1;
                entry.last_ms = entry.last_ms.max(now);
                return;
            }
            open.remove(&key);
        }
        let id = *next;
        *next += 1;
        entries.insert(
            id,
            Entry {
                id,
                seq: id,
                rule: rule.clone(),
                protocol,
                source,
                reason,
                detail: clip_detail(&detail()),
                first_ms: now,
                last_ms: now,
                count: 1,
            },
        );
        order.insert(id, id);
        open.insert(key, id);
        while entries.len() > KEEP {
            let Some((_, oldest)) = order.pop_first() else {
                break;
            };
            if let Some(entry) = entries.remove(&oldest) {
                let key = (entry.rule, entry.source, entry.reason);
                if open.get(&key) == Some(&oldest) {
                    open.remove(&key);
                }
            }
        }
    }
    /// Records changed after `cursor`, oldest change first, or `None` when
    /// there are none.
    pub fn after(&self, cursor: &Cursor) -> Option<BlockBatch> {
        let ring = lock(&self.0);
        let from = if cursor.stream == ring.stream {
            cursor.seq
        } else {
            0
        };
        let entries: Vec<Block> = ring
            .order
            .range((Bound::Excluded(from), Bound::Unbounded))
            .take(BATCH)
            .filter_map(|(_, id)| ring.entries.get(id))
            .map(|entry| Block {
                id: entry.id,
                seq: entry.seq,
                rule_id: entry.rule.to_string(),
                protocol: entry.protocol.to_owned(),
                source: entry.source,
                reason: entry.reason.as_str().to_owned(),
                detail: entry.detail.clone(),
                first_ms: entry.first_ms,
                last_ms: entry.last_ms,
                count: entry.count,
            })
            .collect();
        (!entries.is_empty()).then(|| BlockBatch {
            stream: ring.stream.clone(),
            entries,
        })
    }
    /// `rule`'s refusals by reason since this agent started.
    pub fn refused(&self, rule: &str) -> Vec<ReasonCount> {
        let ring = lock(&self.0);
        let Some(counts) = ring.refused.get(rule) else {
            return vec![];
        };
        Reason::ALL
            .iter()
            .zip(counts)
            .filter(|(_, count)| **count > 0)
            .map(|(reason, count)| ReasonCount {
                reason: reason.as_str().to_owned(),
                count: *count,
            })
            .collect()
    }
}

/// The controller's copy of one node's latest block records.
#[derive(Default)]
pub struct Kept {
    cursor: Cursor,
    arrivals: u64,
    entries: HashMap<(String, u64), (u64, Block)>,
    /// Records by arrival of their latest change.
    order: BTreeMap<u64, (String, u64)>,
}
impl Kept {
    /// Keeps the records of `batch` newer than the copy and returns where
    /// the copy now ends. A record sent again replaces the kept one.
    pub fn add(&mut self, batch: Option<BlockBatch>) -> Cursor {
        if let Some(batch) = batch.filter(|b| identifier(&b.stream)) {
            let mut last = if batch.stream == self.cursor.stream {
                self.cursor.seq
            } else {
                0
            };
            for block in batch.entries.into_iter().take(BATCH) {
                if block.seq <= last {
                    continue;
                }
                last = block.seq;
                let key = (batch.stream.clone(), block.id);
                if let Some((arrival, _)) = self.entries.remove(&key) {
                    self.order.remove(&arrival);
                }
                self.arrivals += 1;
                self.order.insert(self.arrivals, key.clone());
                self.entries.insert(key, (self.arrivals, block));
                while self.entries.len() > KEEP {
                    let Some((_, oldest)) = self.order.pop_first() else {
                        break;
                    };
                    self.entries.remove(&oldest);
                }
            }
            self.cursor = Cursor {
                stream: batch.stream,
                seq: last,
            };
        }
        self.cursor.clone()
    }
    pub fn cursor(&self) -> Cursor {
        self.cursor.clone()
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    /// Up to `limit` records that `keep` accepts, latest change first.
    pub fn read(&self, keep: impl Fn(&Block) -> bool, limit: usize) -> Vec<Block> {
        self.order
            .values()
            .rev()
            .filter_map(|key| self.entries.get(key).map(|(_, block)| block))
            .filter(|block| keep(block))
            .take(limit)
            .cloned()
            .collect()
    }
}

/// `GET /api/v1/nodes/{node}/rules/{rule}/connections`.
#[derive(Clone, Debug, Serialize)]
pub struct RuleView {
    /// `ready`, `pending` (asked, no answer yet), `no_answer` (none within
    /// 30 s), `unsupported` (agent too old) or `offline`.
    pub state: &'static str,
    /// When the agent took the sessions shown; absent before the first.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taken_at_ms: Option<i64>,
    pub totals: Totals,
    pub sessions: Vec<Session>,
    pub truncated: bool,
    pub counters: RuleCounters,
}
#[derive(Clone, Copy, Debug, Default, Serialize)]
pub struct Totals {
    pub tcp: u64,
    pub udp: u64,
}
/// What the node reported for the rule since its agent started.
#[derive(Clone, Debug, Default, Serialize)]
pub struct RuleCounters {
    /// TLS, PROXY and WebSocket setup of accepted connections.
    pub inbound: Option<ConnectionCounts>,
    /// Dials per configured target: the next-hop distribution.
    pub targets: Vec<TargetCounts>,
    /// Refusals by reason, from the latest snapshot.
    pub refused: Vec<ReasonCount>,
}
#[derive(Clone, Debug, Serialize)]
pub struct TargetCounts {
    pub target_index: usize,
    pub target_address: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub via: Option<RuleRef>,
    pub counts: ConnectionCounts,
}
/// `GET /api/v1/nodes/{node}/blocks`.
#[derive(Clone, Debug, Serialize)]
pub struct BlocksView {
    /// False while the node's agent has not reported that it keeps records.
    pub supported: bool,
    pub blocks: Vec<BlockView>,
}
#[derive(Clone, Debug, Serialize)]
pub struct BlockView {
    pub rule_id: String,
    pub protocol: String,
    pub source: IpAddr,
    pub reason: String,
    pub detail: String,
    pub first_ms: i64,
    pub last_ms: i64,
    pub count: u64,
}
impl From<Block> for BlockView {
    fn from(block: Block) -> Self {
        Self {
            rule_id: block.rule_id,
            protocol: block.protocol,
            source: block.source,
            reason: block.reason,
            detail: block.detail,
            first_ms: block.first_ms,
            last_ms: block.last_ms,
            count: block.count,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn client(port: u16) -> SocketAddr {
        SocketAddr::from(([198, 51, 100, 7], port))
    }

    #[test]
    fn a_session_is_listed_until_its_guard_drops_on_every_exit_path() {
        let registry = Arc::new(Registry::default());
        let (a, b): (Arc<str>, Arc<str>) = ("a".into(), "b".into());
        // Returned normally.
        {
            let tracked = registry.track(&a, "tcp", false, client(1));
            tracked.add_upload(5);
            assert_eq!(registry.snapshot("a").0, 1);
        }
        assert!(registry.is_empty());
        // An error returned early with `?`.
        let failing = || -> Result<(), ()> {
            let _tracked = registry.track(&a, "tcp", false, client(2));
            Err(())?;
            Ok(())
        };
        assert!(failing().is_err());
        assert!(registry.is_empty());
        // A panic while the session ran.
        let shared = registry.clone();
        let rule = a.clone();
        let panicked = std::thread::spawn(move || {
            let _tracked = shared.track(&rule, "tcp", false, client(3));
            panic!("session task failed");
        })
        .join();
        assert!(panicked.is_err());
        assert!(registry.is_empty());
        // A task cancelled while it waits, and one aborted.
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let (shared, rule) = (registry.clone(), a.clone());
            let waiting = async move {
                let _tracked = shared.track(&rule, "udp", true, client(4));
                std::future::pending::<()>().await;
            };
            let cancel = tokio_util::sync::CancellationToken::new();
            cancel.cancel();
            tokio::select! { biased; _ = cancel.cancelled() => {}, _ = waiting => {} }
            let (shared, rule) = (registry.clone(), a.clone());
            let (started, ready) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(async move {
                let _tracked = shared.track(&rule, "tcp", false, client(5));
                let _ = started.send(());
                std::future::pending::<()>().await;
            });
            ready.await.unwrap();
            assert_eq!(registry.len(), 1);
            task.abort();
            let _ = task.await;
        });
        assert!(registry.is_empty());
        // Each guard removes its own session only.
        let first = registry.track(&a, "tcp", false, client(6));
        let second = registry.track(&b, "udp", true, client(7));
        let third = registry.track(&a, "udp", true, client(8));
        drop(first);
        let (tcp, udp, sessions) = registry.snapshot("a");
        assert_eq!((tcp, udp, sessions.len()), (0, 1, 1));
        assert_eq!(sessions[0].client, client(8));
        assert_eq!(registry.snapshot("b").1, 1);
        drop((second, third));
        assert!(registry.is_empty());
    }

    #[test]
    fn a_snapshot_lists_the_newest_sessions_with_their_details_and_counts_all() {
        let registry = Arc::new(Registry::default());
        let rule: Arc<str> = "web".into();
        let other: Arc<str> = "other".into();
        let held: Vec<Tracked> = (0..MAX_SESSIONS as u16 + 25)
            .map(|i| registry.track(&rule, "tcp", i % 5 == 0, client(i)))
            .collect();
        let _elsewhere = registry.track(&other, "tcp", false, client(9));
        let newest = held.last().unwrap();
        newest.set_client(client(40_000));
        newest.set_protocol("socks5");
        newest.set_destination(&"x".repeat(400));
        let target = Target {
            address: "relay-b.example.net:30001".into(),
            via: Some(RuleRef {
                node_id: "n2".into(),
                rule_id: "r2".into(),
            }),
            ..serde_json::from_value(serde_json::json!({"address": "x:1"})).unwrap()
        };
        newest.set_target(1, &target, Some("203.0.113.9:30001".parse().unwrap()));
        newest.add_upload(10);
        newest.add_upload(5);
        newest.add_download(7);
        let (tcp, udp, sessions) = registry.snapshot("web");
        assert_eq!((tcp + udp, udp), (MAX_SESSIONS as u64 + 25, 45));
        assert_eq!(sessions.len(), MAX_SESSIONS);
        // Newest first: the last registered, then the one before.
        assert_eq!(sessions[0].client, client(40_000));
        assert_eq!(sessions[1].client, client(MAX_SESSIONS as u16 + 23));
        let first = &sessions[0];
        assert_eq!(
            (
                first.protocol.as_str(),
                first.target_index,
                first.target.as_str()
            ),
            ("socks5", Some(1), "relay-b.example.net:30001")
        );
        assert_eq!(first.via.as_ref().unwrap().node_id, "n2");
        assert_eq!(first.remote, Some("203.0.113.9:30001".parse().unwrap()));
        assert_eq!((first.upload_bytes, first.download_bytes), (15, 7));
        assert_eq!(first.destination.len(), ADDRESS_BYTES);
        let report = Report {
            snapshots: (0..MAX_SNAPSHOTS)
                .map(|_| Snapshot {
                    rule_id: "web".into(),
                    taken_at_ms: 1,
                    tcp,
                    udp,
                    sessions: sessions.clone(),
                    refused: vec![],
                })
                .collect(),
            blocks: None,
        };
        assert!(report.within_limits(), "built reports stay within bounds");
        let mut over = report.clone();
        over.snapshots.push(over.snapshots[0].clone());
        assert!(!over.within_limits());
        let mut over = report.clone();
        over.snapshots[0].sessions.push(sessions[0].clone());
        assert!(!over.within_limits());
        let mut over = report;
        over.snapshots[0].sessions[0].destination = "y".repeat(ADDRESS_BYTES + 1);
        assert!(!over.within_limits());
        drop(held);
        assert_eq!(registry.snapshot("web"), (0, 0, vec![]));
    }

    fn ip(last: u8) -> IpAddr {
        IpAddr::from([203, 0, 113, last])
    }

    #[test]
    fn repeats_within_the_window_are_one_record_and_later_ones_start_another() {
        let blocks = Blocks::default();
        let rule: Arc<str> = "web".into();
        let built = std::cell::Cell::new(0);
        let detail = |text: &str| {
            built.set(built.get() + 1);
            text.to_owned()
        };
        let t = 1_000_000;
        blocks.record_at(t, &rule, "tcp", ip(1), Reason::SourceDenied, || {
            detail("matches deny-list network 203.0.113.0/24")
        });
        for offset in [1, 30_000, WINDOW_MS - 1] {
            blocks.record_at(
                t + offset,
                &rule,
                "tcp",
                ip(1),
                Reason::SourceDenied,
                || detail("rebuilt"),
            );
        }
        // Another reason, source or rule is another record; an IPv4-mapped
        // IPv6 source is the same as its IPv4 address.
        blocks.record_at(t + 2, &rule, "tcp", ip(1), Reason::ConnectionLimit, || {
            detail("limit 2 connections")
        });
        blocks.record_at(t + 3, &rule, "tcp", ip(2), Reason::SourceDenied, || {
            detail("x")
        });
        let mapped: IpAddr = "::ffff:203.0.113.2".parse().unwrap();
        blocks.record_at(t + 4, &rule, "tcp", mapped, Reason::SourceDenied, || {
            detail("x")
        });
        // A repeat after the window starts a new record.
        blocks.record_at(
            t + WINDOW_MS,
            &rule,
            "tcp",
            ip(1),
            Reason::SourceDenied,
            || detail("later"),
        );
        assert_eq!(built.get(), 4, "details are built for new records only");
        let batch = blocks.after(&Cursor::default()).unwrap();
        let seen: Vec<_> = batch
            .entries
            .iter()
            .map(|b| (b.source, b.reason.as_str(), b.count, b.detail.as_str()))
            .collect();
        // Oldest change first: the denied source's record last grew before
        // the other records were made.
        assert_eq!(
            seen,
            [
                (
                    ip(1),
                    "source_denied",
                    4,
                    "matches deny-list network 203.0.113.0/24"
                ),
                (ip(1), "connection_limit", 1, "limit 2 connections"),
                (ip(2), "source_denied", 2, "x"),
                (ip(1), "source_denied", 1, "later"),
            ]
        );
        let grown = &batch.entries[0];
        assert_eq!((grown.first_ms, grown.last_ms), (t, t + WINDOW_MS - 1));
        assert_eq!(
            blocks.refused("web"),
            [
                ReasonCount {
                    reason: "source_denied".into(),
                    count: 7
                },
                ReasonCount {
                    reason: "connection_limit".into(),
                    count: 1
                },
            ]
        );
        assert!(blocks.refused("other").is_empty());
    }

    #[test]
    fn a_flood_keeps_the_ring_and_the_aggregation_map_bounded() {
        let blocks = Blocks::default();
        let rules: Vec<Arc<str>> = (0..3).map(|i| format!("r{i}").into()).collect();
        // Many sources, each refused twice; then one source thousands of times.
        for round in 0..2 {
            for i in 0..5000u32 {
                let source = IpAddr::from((0x0a00_0000 + i).to_be_bytes());
                blocks.record_at(
                    round,
                    &rules[(i % 3) as usize],
                    "udp",
                    source,
                    Reason::SourceNotAllowed,
                    || "y".repeat(500),
                );
            }
        }
        for i in 0..20_000 {
            blocks.record_at(i, &rules[0], "tcp", ip(9), Reason::ConnectionLimit, || {
                "limit 1 connections".into()
            });
        }
        {
            let ring = lock(&blocks.0);
            assert_eq!(ring.entries.len(), KEEP);
            assert_eq!(ring.order.len(), KEEP);
            assert!(ring.open.len() <= KEEP, "{}", ring.open.len());
            assert!(ring.open.values().all(|id| ring.entries.contains_key(id)));
            assert!(
                ring.entries
                    .values()
                    .all(|e| e.detail.chars().count() <= DETAIL_CHARS)
            );
        }
        // The flooding source is one record, the newest change.
        let mut cursor = Cursor::default();
        let mut all = vec![];
        while let Some(batch) = blocks.after(&cursor) {
            assert!(batch.entries.len() <= BATCH && batch.within_limits());
            cursor = Cursor {
                stream: batch.stream.clone(),
                seq: batch.entries.last().unwrap().seq,
            };
            all.extend(batch.entries);
        }
        assert_eq!(all.len(), KEEP);
        let last = all.last().unwrap();
        assert_eq!((last.source, last.count), (ip(9), 20_000));
        // Too many rules: counting stops for new ones, records go on.
        for i in 0..COUNTED_RULES + 10 {
            let rule: Arc<str> = format!("many{i}").into();
            blocks.record_at(0, &rule, "tcp", ip(1), Reason::Expired, String::new);
        }
        assert!(lock(&blocks.0).refused.len() <= COUNTED_RULES);
        assert_eq!(lock(&blocks.0).entries.len(), KEEP);
    }

    fn batch(stream: &str, entries: &[(u64, u64, u64)]) -> Option<BlockBatch> {
        Some(BlockBatch {
            stream: stream.into(),
            entries: entries
                .iter()
                .map(|&(id, seq, count)| Block {
                    id,
                    seq,
                    rule_id: "web".into(),
                    protocol: "tcp".into(),
                    source: ip(id as u8),
                    reason: "source_denied".into(),
                    detail: String::new(),
                    first_ms: 0,
                    last_ms: seq as i64,
                    count,
                })
                .collect(),
        })
    }

    #[test]
    fn the_controller_keeps_each_record_once_through_resends_updates_and_restarts() {
        let mut kept = Kept::default();
        assert_eq!(kept.add(None), Cursor::default());
        assert_eq!(kept.add(batch("a", &[(1, 1, 1), (2, 2, 1)])).seq, 2);
        // A lost reply: the agent sends the same records again, plus a newer one.
        let cursor = kept.add(batch("a", &[(1, 1, 1), (2, 2, 1), (3, 3, 1)]));
        assert_eq!((cursor.stream.as_str(), cursor.seq), ("a", 3));
        assert_eq!(kept.len(), 3);
        // Record 1 grew: it comes again with a new sequence number and
        // replaces the kept copy instead of adding to it.
        kept.add(batch("a", &[(1, 4, 5)]));
        kept.add(batch("a", &[(1, 4, 5)]));
        assert_eq!(kept.len(), 3);
        let read = kept.read(|_| true, 10);
        let seen: Vec<_> = read.iter().map(|b| (b.id, b.count)).collect();
        assert_eq!(seen, [(1, 5), (3, 1), (2, 1)], "latest change first");
        // The agent restarted: a new stream starts again at 1 and is kept
        // next to the old records.
        assert_eq!(kept.add(batch("b", &[(1, 1, 2)])).seq, 1);
        assert_eq!(kept.len(), 4);
        assert_eq!(kept.read(|b| b.count == 2, 10).len(), 1);
        assert_eq!(kept.read(|_| true, 2).len(), 2);
        // An invalid stream name is ignored.
        assert_eq!(kept.add(batch("../x", &[(9, 9, 9)])).stream, "b");
        // At most KEEP records, the oldest change dropped first.
        let many: Vec<(u64, u64, u64)> = (2..=KEEP as u64 + 1).map(|i| (i, i, 1)).collect();
        for chunk in many.chunks(BATCH) {
            kept.add(batch("b", chunk));
        }
        assert_eq!(kept.len(), KEEP);
        assert!(
            kept.read(|b| b.count == 5, KEEP).is_empty(),
            "stream a's records were the oldest"
        );
    }

    #[test]
    fn a_rule_names_how_its_clients_connect() {
        let mut rule: crate::model::Rule = serde_json::from_value(serde_json::json!({
            "id": "r", "tenant_id": "t", "owner_id": "o", "name": "n",
            "listen": "127.0.0.1:1", "protocol": "both", "targets": [{"address": "x:1"}],
            "quota_bytes": null, "expires_at_ms": null, "rate_bytes_per_sec": null, "meter_epoch": "e",
        }))
        .unwrap();
        assert_eq!(
            (protocol(&rule, false), protocol(&rule, true)),
            ("tcp", "udp")
        );
        rule.inbound_tls = Some(crate::model::TlsServer {
            identity: "c".into(),
            client_ca: None,
        });
        assert_eq!(protocol(&rule, false), "tls");
        rule.inbound_socks5 = Some(serde_json::from_value(serde_json::json!({})).unwrap());
        assert_eq!(
            (protocol(&rule, false), protocol(&rule, true)),
            ("socks5", "udp")
        );
    }
}
