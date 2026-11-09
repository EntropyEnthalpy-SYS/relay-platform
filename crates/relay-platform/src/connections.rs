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
//! a new sequence number and is sent again; the controller keeps one copy
//! per record in its block-record database, so nothing is counted twice.
//!
//! A controller that also sends `SyncResponse::connection_termination` may
//! ask to end single sessions ([`Termination`]). Session ids count from 1 in
//! every agent process, so a request names the [`Registry::instance`] too: a
//! request for another instance is `stale_instance` and never ends a
//! session of this run that happens to have the same id. Ending a session
//! cancels its task, which closes its sockets on every protocol; the answer
//! ([`TerminationResult`]) says `closed` only once the session left the
//! registry.
use crate::model::{ConnectionCounts, RuleRef, Target, canonical_ip, identifier, now_ms};
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, HashMap, VecDeque},
    net::{IpAddr, SocketAddr},
    ops::Bound,
    sync::{
        Arc, Mutex, MutexGuard,
        atomic::{AtomicU64, Ordering},
    },
    time::Duration,
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

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
/// Termination requests in one sync reply, and answers in one report.
pub const MAX_TERMINATIONS: usize = 16;
/// How long an agent waits for a cancelled session to end before it answers
/// `timed_out`.
pub const CLOSE_WAIT: Duration = Duration::from_secs(3);
/// Answers an agent repeats when the controller asks again.
const ANSWERED: usize = 64;
const ID_BYTES: usize = 64;

/// Whether a `udp` (else TCP) session of `rule` can be ended alone, fixed
/// from the rule when the session is listed and never from its shown
/// protocol, which changes as setup goes on. True only where ending a
/// session was tested to stop its traffic on both sides (see
/// docs/CONNECTIONS.md): plain TCP and UDP, TLS, a WebSocket or a multipath
/// inbound, HTTP CONNECT, SOCKS5 and HTTP/2 CONNECT directly or inside TLS,
/// TCP sessions with a PROXY header (plain, before the TLS handshake or
/// inside TLS), MPTCP, with TLS, WebSocket or multipath towards the target.
/// Not a protocol gateway's bridge sessions, whose client connection
/// belongs to the gateway's engine; not a multipath inbound over WebSocket,
/// whose joining paths' WebSocket connections end with the session that
/// created it and not with its own; and not (untested) Shadowsocks, egress
/// proxies, reverse tunnels, a proxy inbound inside WebSocket or multipath,
/// or UDP sessions with PROXY headers.
pub fn terminable(rule: &crate::model::Rule, udp: bool) -> bool {
    let proxy_inbound = rule.inbound_socks5.is_some()
        || rule.inbound_http_connect.is_some()
        || rule.inbound_http2_connect.is_some();
    let (websocket, multipath) = (
        rule.inbound_websocket.is_some(),
        rule.inbound_multipath.is_some(),
    );
    rule.protocol_gateway.is_none()
        && rule.inbound_shadowsocks.is_none()
        && rule.egress_proxy.is_none()
        && rule.reverse_tunnel.is_none()
        && !(websocket && multipath)
        && !(proxy_inbound && (websocket || multipath))
        && !(udp && rule.inbound_proxy.is_some())
}

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
    /// The agent run whose session ids the snapshots carry. Sent, with
    /// `terminations`, only to a controller that sent
    /// `SyncResponse::connection_termination`, since older ones reject
    /// unknown fields here; its presence tells the controller this agent
    /// ends single sessions.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub instance: String,
    /// Answers to termination requests.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub terminations: Vec<TerminationResult>,
}
impl Report {
    pub fn within_limits(&self) -> bool {
        self.snapshots.len() <= MAX_SNAPSHOTS
            && self.snapshots.iter().all(Snapshot::within_limits)
            && self.blocks.as_ref().is_none_or(BlockBatch::within_limits)
            && (self.instance.is_empty()
                || (self.instance.len() <= ID_BYTES && identifier(&self.instance)))
            && self.terminations.len() <= MAX_TERMINATIONS
            && self.terminations.iter().all(|t| {
                t.id.len() <= ID_BYTES
                    && t.outcome.len() <= NAME_BYTES
                    && t.detail.chars().count() <= DETAIL_CHARS
                    && t.detail.len() <= DETAIL_CHARS * 4
            })
    }
}

/// `SyncResponse::connection_terminations`: end session `session_id` of
/// `rule_id` if it belongs to agent run `instance`. Sent by the controller,
/// so unknown fields are ignored: a newer controller may add some.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Termination {
    pub id: String,
    pub rule_id: String,
    pub instance: String,
    pub session_id: u64,
}

/// What became of a [`Termination`]. `outcome` is one of
/// [`Outcome::as_str`]; it is a string so that a newer agent's outcome does
/// not fail an older controller's sync.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TerminationResult {
    pub id: String,
    pub outcome: String,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub detail: String,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Outcome {
    /// The session's task ended and it left the registry.
    Closed,
    /// No session of the rule has this id in this run: it already ended.
    NotFound,
    /// The request names another agent run; its sessions ended with it.
    StaleInstance,
    /// Sessions of this protocol cannot be ended one by one.
    Unsupported,
    /// Cancelled, but still open after [`CLOSE_WAIT`].
    TimedOut,
}
impl Outcome {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Closed => "closed",
            Self::NotFound => "not_found",
            Self::StaleInstance => "stale_instance",
            Self::Unsupported => "unsupported",
            Self::TimedOut => "timed_out",
        }
    }
    pub fn parse(text: &str) -> Option<Self> {
        [
            Self::Closed,
            Self::NotFound,
            Self::StaleInstance,
            Self::Unsupported,
            Self::TimedOut,
        ]
        .into_iter()
        .find(|o| o.as_str() == text)
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
    /// Whether the agent can end this session alone ([`terminable`]). Sent,
    /// like [`Report::instance`], only to a controller that said
    /// `connection_termination`; absent means it cannot.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub terminable: bool,
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
    /// New in every agent process; session ids are unique within it.
    instance: String,
    next: AtomicU64,
    shards: [Mutex<HashMap<u64, Arc<Live>>>; SHARDS],
    /// The latest answers, repeated when a request comes again.
    answered: Mutex<VecDeque<TerminationResult>>,
}
impl Default for Registry {
    fn default() -> Self {
        Self {
            instance: uuid::Uuid::new_v4().simple().to_string(),
            next: AtomicU64::new(1),
            shards: std::array::from_fn(|_| Mutex::default()),
            answered: Mutex::default(),
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
    /// Cancelled to end the session from the panel.
    cancel: CancellationToken,
    /// Fixed when listed: see [`terminable`].
    terminable: bool,
    /// Tasks the session spawned; it stays listed until they ended.
    work: TaskTracker,
}
struct Detail {
    protocol: &'static str,
    client: SocketAddr,
    target: Option<(usize, String)>,
    remote: Option<SocketAddr>,
    via: Option<RuleRef>,
    destination: String,
}

/// Keeps a session listed until dropped and the tasks it spawned ended.
pub struct Tracked {
    registry: Arc<Registry>,
    live: Arc<Live>,
}
impl Drop for Tracked {
    /// However the session's task ended, also by a panic or an abort without
    /// [`Live::finish`]: what it spawned is cancelled, and the session stays
    /// listed, so not `closed`, until that ended.
    fn drop(&mut self) {
        self.live.cancel.cancel();
        self.live.work.close();
        let (registry, id) = (self.registry.clone(), self.live.id);
        let unlist = move || {
            lock(&registry.shards[id as usize % SHARDS]).remove(&id);
        };
        let work = self.live.work.clone();
        match tokio::runtime::Handle::try_current() {
            Ok(runtime) if !work.is_empty() => {
                runtime.spawn(async move {
                    work.wait().await;
                    unlist();
                });
            }
            // Ended, or no runtime is left to run what it spawned.
            _ => unlist(),
        }
    }
}
impl std::ops::Deref for Tracked {
    type Target = Arc<Live>;
    fn deref(&self) -> &Arc<Live> {
        &self.live
    }
}

impl Registry {
    /// Lists a new session of `rule` until the returned guard is dropped;
    /// `terminable` says whether it can be ended alone ([`terminable`]).
    pub fn track(
        self: &Arc<Self>,
        rule: &Arc<str>,
        protocol: &'static str,
        udp: bool,
        client: SocketAddr,
        terminable: bool,
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
            cancel: CancellationToken::new(),
            terminable,
            work: TaskTracker::new(),
        });
        lock(&self.shards[id as usize % SHARDS]).insert(id, live.clone());
        Tracked {
            registry: self.clone(),
            live,
        }
    }
    /// This agent run; see [`Termination`].
    pub fn instance(&self) -> &str {
        &self.instance
    }
    fn get(&self, id: u64) -> Option<Arc<Live>> {
        lock(&self.shards[id as usize % SHARDS]).get(&id).cloned()
    }
    /// Ends the sessions the controller asked for and answers each request:
    /// `closed` once, within [`CLOSE_WAIT`], the session's task ended (it
    /// left the registry) and so did every task it spawned (its task group
    /// is empty), whether or not the task called [`Live::finish`].
    /// A request answered before gets the same answer again.
    pub async fn terminate(&self, requests: &[Termination]) -> Vec<TerminationResult> {
        let mut results: Vec<(String, Outcome, String)> = vec![];
        let mut waiting: Vec<(usize, Arc<Live>)> = vec![];
        let mut repeated: Vec<TerminationResult> = vec![];
        for request in requests.iter().take(MAX_TERMINATIONS) {
            if let Some(answer) = lock(&self.answered)
                .iter()
                .find(|a| a.id == request.id)
                .cloned()
            {
                repeated.push(answer);
                continue;
            }
            let outcome = if request.instance != self.instance {
                Outcome::StaleInstance
            } else {
                match self
                    .get(request.session_id)
                    .filter(|live| *live.rule == *request.rule_id)
                {
                    None => Outcome::NotFound,
                    Some(live) if !live.terminable => Outcome::Unsupported,
                    Some(live) => {
                        live.cancel.cancel();
                        waiting.push((results.len(), live));
                        Outcome::TimedOut
                    }
                }
            };
            results.push((request.id.clone(), outcome, String::new()));
        }
        let deadline = tokio::time::Instant::now() + CLOSE_WAIT;
        loop {
            waiting.retain(|(index, live)| {
                let ended = self.get(live.id).is_none() && live.work.is_empty();
                if ended {
                    results[*index].1 = Outcome::Closed;
                }
                !ended
            });
            if waiting.is_empty() || tokio::time::Instant::now() >= deadline {
                break;
            }
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
        for (index, _) in waiting {
            results[index].2 = format!(
                "the session was cancelled but had not ended after {} s",
                CLOSE_WAIT.as_secs()
            );
        }
        let answers: Vec<TerminationResult> = results
            .into_iter()
            .map(|(id, outcome, detail)| TerminationResult {
                id,
                outcome: outcome.as_str().to_owned(),
                detail,
            })
            .collect();
        let mut answered = lock(&self.answered);
        for answer in &answers {
            answered.push_back(answer.clone());
            if answered.len() > ANSWERED {
                answered.pop_front();
            }
        }
        repeated.extend(answers);
        repeated
    }
    /// Open sessions of every rule.
    pub fn len(&self) -> usize {
        self.shards.iter().map(|s| lock(s).len()).sum()
    }
    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
    /// `rule`'s open TCP and UDP sessions and the newest [`MAX_SESSIONS`];
    /// with `terminable` whether each can be ended alone.
    pub fn snapshot(&self, rule: &str, terminable: bool) -> (u64, u64, Vec<Session>) {
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
        (
            tcp,
            udp,
            found.iter().map(|live| live.view(terminable)).collect(),
        )
    }
}

impl Live {
    /// This session's number, unique within its engine.
    pub fn id(&self) -> u64 {
        self.id
    }
    pub fn rule(&self) -> &Arc<str> {
        &self.rule
    }
    /// Completes when the panel ended the session; a session's task selects
    /// on it next to its rule's cancellation.
    pub fn cancelled(&self) -> tokio_util::sync::WaitForCancellationFuture<'_> {
        self.cancel.cancelled()
    }
    /// A token for a task the session spawned, cancelled with the session.
    pub fn child_token(&self) -> CancellationToken {
        self.cancel.child_token()
    }
    /// Where the session spawns its tasks, so that it stays listed, and is
    /// not reported `closed`, until they ended. Closing the group does not
    /// refuse later spawns, so only these spawn into it, each while the
    /// group cannot have emptied: the engine's TCP session task before it
    /// ends (a SOCKS5 UDP association, multipath drivers, the WebSocket
    /// drivers of its client and target sides, HTTP/2 CONNECT stream
    /// handlers through its executor), and tasks already in the group
    /// (HTTP/2 tunnels, multipath path workers, SOCKS5 UDP reply readers).
    pub(crate) fn tasks(&self) -> TaskTracker {
        self.work.clone()
    }
    /// Called by the session's task as it ends: cancels what the session
    /// spawned and waits for it, so that the engine's shutdown, which waits
    /// for session tasks, also waits for what they spawned. Dropping the
    /// [`Tracked`] guard does the rest without it.
    pub async fn finish(&self) {
        self.cancel.cancel();
        self.work.close();
        self.work.wait().await;
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
    fn view(&self, terminable: bool) -> Session {
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
            terminable: terminable && self.terminable,
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

/// `GET /api/v1/nodes/{node}/rules/{rule}/connections`.
#[derive(Clone, Debug, Serialize)]
pub struct RuleView {
    /// `ready`, `pending` (asked, no answer yet), `no_answer` (none within
    /// 30 s), `unsupported` (agent too old) or `offline`.
    pub state: &'static str,
    /// When the agent took the sessions shown; absent before the first.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub taken_at_ms: Option<i64>,
    /// The agent run the session ids belong to; absent from agents that
    /// cannot end single sessions.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub instance: Option<String>,
    /// The user may end sessions of this rule here now: they may write, the
    /// server is online and its agent ends single sessions.
    pub can_terminate: bool,
    pub totals: Totals,
    pub sessions: Vec<SessionView>,
    pub truncated: bool,
    pub counters: RuleCounters,
}
/// A listed session and whether the panel may offer to end it.
#[derive(Clone, Debug, Serialize)]
pub struct SessionView {
    #[serde(flatten)]
    pub session: Session,
    pub terminable: bool,
}
/// `POST /api/v1/nodes/{node}/rules/{rule}/connections/terminate` and
/// `GET .../connections/terminations/{id}`: one request to end a session.
#[derive(Clone, Debug, Serialize)]
pub struct TerminationView {
    pub id: String,
    pub node_id: String,
    pub rule_id: String,
    pub instance: String,
    pub session_id: u64,
    /// As the latest snapshot listed the session; empty when it did not.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub protocol: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub client: Option<SocketAddr>,
    /// `pending` (waiting for the agent), an [`Outcome`] the agent or the
    /// controller determined, or `expired`: no answer within 30 s, so the
    /// controller does not know whether the session ended.
    pub state: String,
    #[serde(skip_serializing_if = "String::is_empty")]
    pub detail: String,
    pub requested_by: String,
    pub requested_ms: i64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub finished_ms: Option<i64>,
    /// The same unfinished or answered request existed: nothing new was sent.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub duplicate: bool,
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
    /// Pass as `before` for the next, older page; absent on the last page.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub next_before: Option<i64>,
    /// How long and how many records the controller keeps.
    pub retention: Retention,
    /// The controller could not open its block-record file (see its log):
    /// it runs without records until it restarts, and `blocks` is empty.
    #[serde(skip_serializing_if = "std::ops::Not::not")]
    pub unavailable: bool,
}
/// The controller keeps each server's block records for `days` after their
/// latest change, and at most `per_node` of them, the oldest change first
/// to go.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
pub struct Retention {
    pub days: u32,
    pub per_node: u32,
}
impl Retention {
    pub const DAYS: std::ops::RangeInclusive<u32> = 1..=365;
    pub const PER_NODE: std::ops::RangeInclusive<u32> = 100..=100_000;
}
impl Default for Retention {
    fn default() -> Self {
        Self {
            days: 30,
            per_node: 10_000,
        }
    }
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
            let tracked = registry.track(&a, "tcp", false, client(1), true);
            tracked.add_upload(5);
            assert_eq!(registry.snapshot("a", true).0, 1);
        }
        assert!(registry.is_empty());
        // An error returned early with `?`.
        let failing = || -> Result<(), ()> {
            let _tracked = registry.track(&a, "tcp", false, client(2), true);
            Err(())?;
            Ok(())
        };
        assert!(failing().is_err());
        assert!(registry.is_empty());
        // A panic while the session ran.
        let shared = registry.clone();
        let rule = a.clone();
        let panicked = std::thread::spawn(move || {
            let _tracked = shared.track(&rule, "tcp", false, client(3), true);
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
                let _tracked = shared.track(&rule, "udp", true, client(4), true);
                std::future::pending::<()>().await;
            };
            let cancel = tokio_util::sync::CancellationToken::new();
            cancel.cancel();
            tokio::select! { biased; _ = cancel.cancelled() => {}, _ = waiting => {} }
            let (shared, rule) = (registry.clone(), a.clone());
            let (started, ready) = tokio::sync::oneshot::channel();
            let task = tokio::spawn(async move {
                let _tracked = shared.track(&rule, "tcp", false, client(5), true);
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
        let first = registry.track(&a, "tcp", false, client(6), true);
        let second = registry.track(&b, "udp", true, client(7), true);
        let third = registry.track(&a, "udp", true, client(8), true);
        drop(first);
        let (tcp, udp, sessions) = registry.snapshot("a", true);
        assert_eq!((tcp, udp, sessions.len()), (0, 1, 1));
        assert_eq!(sessions[0].client, client(8));
        assert_eq!(registry.snapshot("b", true).1, 1);
        drop((second, third));
        assert!(registry.is_empty());
    }

    #[test]
    fn a_snapshot_lists_the_newest_sessions_with_their_details_and_counts_all() {
        let registry = Arc::new(Registry::default());
        let rule: Arc<str> = "web".into();
        let other: Arc<str> = "other".into();
        let held: Vec<Tracked> = (0..MAX_SESSIONS as u16 + 25)
            .map(|i| registry.track(&rule, "tcp", i % 5 == 0, client(i), true))
            .collect();
        let _elsewhere = registry.track(&other, "tcp", false, client(9), true);
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
        let (tcp, udp, sessions) = registry.snapshot("web", true);
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
            instance: registry.instance().to_owned(),
            terminations: vec![],
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
        assert_eq!(registry.snapshot("web", true), (0, 0, vec![]));
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

    #[test]
    fn a_session_ends_only_for_its_own_run_and_rule_and_answers_repeat() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let registry = Arc::new(Registry::default());
            let (web, other): (Arc<str>, Arc<str>) = ("web".into(), "other".into());
            // A session task as the engine runs it: it ends when cancelled.
            let run = |rule: &Arc<str>, protocol: &'static str, terminable: bool, port: u16| {
                let tracked = registry.track(rule, protocol, false, client(port), terminable);
                let id = tracked.id;
                tokio::spawn(async move {
                    tracked.cancelled().await;
                    tracked.finish().await;
                });
                id
            };
            let first = run(&web, "tcp", true, 1);
            let second = run(&web, "tcp", true, 2);
            let bridged = run(&web, "gateway", false, 3);
            let elsewhere = run(&other, "tcp", true, 4);
            let instance = registry.instance().to_owned();
            assert_eq!(instance.len(), 32);
            assert_ne!(
                instance,
                Registry::default().instance(),
                "every run is another instance"
            );
            let ask = |id: &str, rule: &str, instance: &str, session_id: u64| Termination {
                id: id.into(),
                rule_id: rule.into(),
                instance: instance.into(),
                session_id,
            };
            let outcomes = |answers: Vec<TerminationResult>| -> Vec<(String, String)> {
                answers.into_iter().map(|a| (a.id, a.outcome)).collect()
            };
            let pair = |id: &str, outcome: &str| (id.to_owned(), outcome.to_owned());
            // The same session id of an earlier run, another rule's session
            // with that id, and a gateway bridge: nothing ends.
            let answers = registry
                .terminate(&[
                    ask("r1", "web", "0123456789abcdef0123456789abcdef", first),
                    ask("r2", "web", &instance, elsewhere),
                    ask("r3", "web", &instance, bridged),
                    ask("r4", "web", &instance, 999),
                ])
                .await;
            assert_eq!(
                outcomes(answers),
                [
                    pair("r1", "stale_instance"),
                    pair("r2", "not_found"),
                    pair("r3", "unsupported"),
                    pair("r4", "not_found"),
                ]
            );
            assert_eq!(registry.snapshot("web", true).0, 3);
            assert_eq!(registry.snapshot("other", true).0, 1);
            // What a session shows as its protocol changes as setup goes on
            // (a gateway's bridge is a SOCKS5 server, and a UDP association
            // shows as `socks5_udp`); whether it can end does not.
            let shown = |terminable: bool| -> Vec<(u64, bool)> {
                let (_, _, sessions) = registry.snapshot("web", terminable);
                sessions.iter().map(|s| (s.id, s.terminable)).collect()
            };
            assert_eq!(
                shown(true),
                [(bridged, false), (second, true), (first, true)]
            );
            assert!(shown(false).iter().all(|(_, can)| !can), "only when asked");
            registry.get(bridged).unwrap().set_protocol("socks5_udp");
            registry.get(second).unwrap().set_protocol("gateway");
            let answers = registry
                .terminate(&[ask("r3b", "web", &instance, bridged)])
                .await;
            assert_eq!(outcomes(answers), [pair("r3b", "unsupported")]);
            assert_eq!(shown(true)[0], (bridged, false));
            // The right one ends; the others stay.
            let answers = registry
                .terminate(&[ask("r5", "web", &instance, first)])
                .await;
            assert_eq!(outcomes(answers), [pair("r5", "closed")]);
            let left: Vec<u64> = registry
                .snapshot("web", true)
                .2
                .iter()
                .map(|s| s.id)
                .collect();
            assert_eq!(left, [bridged, second]);
            // Asked again (a lost reply), the request gets the same answer;
            // a new request for the ended session finds nothing.
            let answers = registry
                .terminate(&[
                    ask("r5", "web", &instance, first),
                    ask("r6", "web", &instance, first),
                ])
                .await;
            assert_eq!(
                outcomes(answers),
                [pair("r5", "closed"), pair("r6", "not_found")]
            );
            // A session that does not end in time is reported as such.
            let stuck = registry.track(&web, "tcp", false, client(5), true);
            let started = tokio::time::Instant::now();
            let answers = registry
                .terminate(&[ask("r7", "web", &instance, stuck.id)])
                .await;
            assert!(started.elapsed() >= CLOSE_WAIT);
            assert_eq!(answers[0].outcome, "timed_out");
            assert!(answers[0].detail.contains("had not ended"));
            drop(stuck);
            let report = Report {
                instance,
                terminations: (0..=MAX_TERMINATIONS)
                    .map(|i| TerminationResult {
                        id: format!("r{i}"),
                        outcome: "closed".into(),
                        detail: String::new(),
                    })
                    .collect(),
                ..Report::default()
            };
            assert!(!report.within_limits(), "at most 16 answers");
            let bad = Report {
                instance: "../x".into(),
                ..Report::default()
            };
            assert!(!bad.within_limits());
        });
    }

    #[test]
    fn a_session_is_closed_only_after_what_it_spawned_ended_however_its_task_ended() {
        let runtime = tokio::runtime::Builder::new_current_thread()
            .enable_all()
            .build()
            .unwrap();
        runtime.block_on(async {
            let registry = Arc::new(Registry::default());
            let web: Arc<str> = "web".into();
            let instance = registry.instance().to_owned();
            let ask = |id: &str, session_id: u64| Termination {
                id: id.into(),
                rule_id: "web".into(),
                instance: instance.clone(),
                session_id,
            };
            let listed = |id: u64| {
                let (_, _, sessions) = registry.snapshot("web", true);
                sessions.iter().any(|s| s.id == id)
            };
            // The session's task ends without `finish`: dropped, by a panic,
            // or aborted. One task it spawned only ends when released, one
            // when the session is cancelled.
            for (round, way) in ["drop", "panic", "abort"].into_iter().enumerate() {
                let tracked = registry.track(&web, "tcp", false, client(20 + round as u16), true);
                let id = tracked.id;
                let (release, released) = tokio::sync::oneshot::channel::<()>();
                tracked.tasks().spawn(async move {
                    let _ = released.await;
                });
                let token = tracked.child_token();
                let cancelled = tracked
                    .tasks()
                    .spawn(async move { token.cancelled().await });
                match way {
                    "drop" => drop(tracked),
                    "panic" => {
                        let task = tokio::spawn(async move {
                            let _tracked = tracked;
                            panic!("a session task failed");
                        });
                        assert!(task.await.unwrap_err().is_panic());
                    }
                    _ => {
                        let task = tokio::spawn(async move {
                            let _tracked = tracked;
                            std::future::pending::<()>().await;
                        });
                        tokio::task::yield_now().await;
                        task.abort();
                        assert!(task.await.unwrap_err().is_cancelled());
                    }
                }
                tokio::time::timeout(Duration::from_secs(5), cancelled)
                    .await
                    .expect("what the session spawned is cancelled")
                    .unwrap();
                assert!(listed(id), "{way}: listed while a task it spawned runs");
                let answers = registry.terminate(&[ask(&format!("{way}-1"), id)]).await;
                assert_eq!(answers[0].outcome, "timed_out", "{way}");
                assert!(listed(id), "{way}");
                // Released while a request waits: that request gets `closed`.
                let again = [ask(&format!("{way}-2"), id)];
                let (answers, ()) = tokio::join!(registry.terminate(&again), async {
                    release.send(()).unwrap()
                });
                assert_eq!(answers[0].outcome, "closed", "{way}");
                assert!(!listed(id), "{way}");
            }
            assert!(registry.is_empty());
        });
    }

    #[test]
    fn only_rules_whose_sessions_were_tested_to_end_alone_say_so() {
        let base: crate::model::Rule = serde_json::from_value(serde_json::json!({
            "id": "r", "tenant_id": "t", "owner_id": "o", "name": "n",
            "listen": "127.0.0.1:1", "protocol": "both", "targets": [{"address": "x:1"}],
            "quota_bytes": null, "expires_at_ms": null, "rate_bytes_per_sec": null, "meter_epoch": "e",
        }))
        .unwrap();
        let with = |change: &dyn Fn(&mut crate::model::Rule)| {
            let mut rule = base.clone();
            change(&mut rule);
            rule
        };
        let shadowsocks = |udp_over_tcp: bool, protocol: crate::model::Protocol| {
            with(&move |rule| {
                rule.protocol = protocol;
                rule.inbound_shadowsocks = Some(crate::shadowsocks::ServerConfig {
                    method: crate::shadowsocks::Method::Blake3Aes128Gcm,
                    password: "AAAAAAAAAAAAAAAAAAAAAA==".into(),
                    allow_private_destinations: false,
                    udp_over_tcp,
                })
            })
        };
        let not = [
            (
                "protocol gateway",
                with(&|rule| {
                    rule.protocol_gateway = Some(crate::gateway::Config {
                        listen: "127.0.0.1:2".parse().unwrap(),
                        protocol: crate::gateway::WireProtocol::Vless {
                            uuid: "bf000d23-0752-40b4-affe-68f7707a9661".into(),
                            vision: false,
                        },
                        security: crate::gateway::Security::Certificate {
                            identity: "server".into(),
                            server_name: None,
                        },
                        allow_private_destinations: false,
                    })
                }),
            ),
            (
                "Shadowsocks TCP",
                shadowsocks(false, crate::model::Protocol::Tcp),
            ),
            (
                "Shadowsocks UDP over TCP",
                shadowsocks(true, crate::model::Protocol::Tcp),
            ),
            (
                "Shadowsocks UDP",
                shadowsocks(false, crate::model::Protocol::Udp),
            ),
            (
                "egress proxy",
                with(&|rule| {
                    rule.egress_proxy = Some(
                        serde_json::from_value(
                            serde_json::json!({"kind": "socks5", "servers": ["127.0.0.1:1080"]}),
                        )
                        .unwrap(),
                    )
                }),
            ),
            (
                "reverse tunnel public side",
                with(&|rule| rule.reverse_tunnel = Some("tunnel".into())),
            ),
            (
                "SOCKS5 inside WebSocket",
                with(&|rule| {
                    rule.protocol = crate::model::Protocol::Tcp;
                    rule.inbound_socks5 =
                        Some(serde_json::from_value(serde_json::json!({})).unwrap());
                    rule.inbound_websocket = Some(crate::model::WebSocketServer {
                        path: "/w".into(),
                        host: None,
                        allowed_origins: vec![],
                    });
                }),
            ),
            (
                "HTTP CONNECT inside multipath",
                with(&|rule| {
                    rule.protocol = crate::model::Protocol::Tcp;
                    rule.inbound_http_connect =
                        Some(serde_json::from_value(serde_json::json!({})).unwrap());
                    rule.inbound_multipath = Some(crate::multipath::ServerConfig {
                        limits: Default::default(),
                        max_paths: 2,
                        allow_replication: false,
                    });
                }),
            ),
            (
                "multipath inbound over WebSocket",
                with(&|rule| {
                    rule.protocol = crate::model::Protocol::Tcp;
                    rule.inbound_tls = Some(crate::model::TlsServer {
                        identity: "c".into(),
                        client_ca: Some("root".into()),
                    });
                    rule.inbound_websocket = Some(crate::model::WebSocketServer {
                        path: "/w".into(),
                        host: None,
                        allowed_origins: vec![],
                    });
                    rule.inbound_multipath = Some(crate::multipath::ServerConfig {
                        limits: Default::default(),
                        max_paths: 2,
                        allow_replication: false,
                    });
                }),
            ),
        ];
        for (name, rule) in &not {
            assert!(
                !terminable(rule, false) && !terminable(rule, true),
                "{name}"
            );
        }
        // PROXY headers: TCP sessions of a TCP and UDP rule can end alone,
        // its UDP sessions cannot.
        let proxied = with(&|rule| {
            rule.inbound_proxy = Some(
                serde_json::from_value(serde_json::json!({
                    "version": "v2", "trusted_sources": ["127.0.0.1/32"],
                }))
                .unwrap(),
            )
        });
        assert!(terminable(&proxied, false) && !terminable(&proxied, true));
        assert!(terminable(&base, true));
        let yes = [
            ("plain TCP", base.clone()),
            (
                "TLS with a PROXY header inside",
                with(&|rule| {
                    rule.protocol = crate::model::Protocol::Tcp;
                    rule.inbound_tls = Some(crate::model::TlsServer {
                        identity: "c".into(),
                        client_ca: None,
                    });
                    rule.inbound_proxy = Some(
                        serde_json::from_value(serde_json::json!({
                            "version": "v2", "trusted_sources": ["127.0.0.1/32"],
                            "placement": "inside_tls",
                        }))
                        .unwrap(),
                    );
                }),
            ),
            (
                "SOCKS5",
                with(&|rule| {
                    rule.inbound_socks5 =
                        Some(serde_json::from_value(serde_json::json!({})).unwrap())
                }),
            ),
            (
                "WebSocket inbound",
                with(&|rule| {
                    rule.protocol = crate::model::Protocol::Tcp;
                    rule.inbound_websocket = Some(crate::model::WebSocketServer {
                        path: "/w".into(),
                        host: None,
                        allowed_origins: vec![],
                    });
                }),
            ),
            (
                "multipath inbound",
                with(&|rule| {
                    rule.protocol = crate::model::Protocol::Tcp;
                    rule.inbound_multipath = Some(crate::multipath::ServerConfig {
                        limits: Default::default(),
                        max_paths: 2,
                        allow_replication: false,
                    });
                }),
            ),
        ];
        for (name, rule) in &yes {
            assert!(terminable(rule, false), "{name}");
        }
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
