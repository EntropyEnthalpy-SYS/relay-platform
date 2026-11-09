//! Live connections, single-session ends and block records on the
//! controller. Snapshots, snapshot requests and termination requests live in
//! memory and are lost when the controller restarts, like live logs; block
//! records go to their own database ([`records`]) and survive it. Agents
//! that never reported support (`connections_node:<node id>`, written once,
//! as for speed tests) get no requests and no cursor, and the panel shows
//! that their agent needs an upgrade.
//!
//! A panel request for a rule's sessions asks the node's agent through its
//! configuration watch, as speed tests do; the agent answers with its next
//! report. A snapshot younger than [`FRESH_MS`] is reused, so one user
//! polling cannot make the agent take snapshots faster than that, and at
//! most [`MAX_PENDING`] rules of a node wait for an answer at a time.
//!
//! Ending a session: an agent that reports its run (`instance`) ends single
//! sessions (`connection_termination_node:<node id>`, written while it
//! does, removed when a report comes without). A request names the run and
//! the session id from the snapshot the user saw; the same unfinished or
//! answered request for that run and session is the same request
//! (`duplicate`), not a second one. It goes to the agent with every sync
//! reply until the agent answers, until a report shows another run
//! (`stale_instance`: the sessions of the earlier run ended with it), or
//! for [`TERMINATE_ANSWER_MS`], after which it is `expired` and may be asked
//! again; an answer that comes later still settles it. Requests, answers and
//! expiries are audited. Whether a session can be ended is what its agent
//! reported for it (`Session::terminable`), and never for a protocol
//! gateway's rule.
//!
//! The block-record file is opened once per controller run. If that fails,
//! the controller logs why and runs without records; `/blocks` then says
//! `unavailable`, and agents are told to go on from what they sent, so that
//! they do not send the same records again on every sync.
use super::*;
use crate::connections::{
    BlockBatch, BlocksView, MAX_SNAPSHOTS, MAX_TERMINATIONS, Outcome, Report, Retention,
    RuleCounters, RuleView, SessionView, Snapshot, TargetCounts, Termination, TerminationView,
    Totals,
};
use std::collections::{HashMap, HashSet};

mod records;
use records::{Query, Records};

/// A snapshot this young is shown instead of asking again.
const FRESH_MS: i64 = 2_000;
/// A request the agent has not answered by then is reported as unanswered.
const ANSWER_MS: i64 = 30_000;
/// A server whose agent has not synced for this long is offline.
const ONLINE_MS: i64 = 90_000;
/// Rules of one node waiting for a snapshot.
const MAX_PENDING: usize = 8;
/// Snapshots not looked at for this long are dropped.
const SNAPSHOT_MEMORY_MS: i64 = 60_000;
/// A termination request the agent has not answered by then is `expired`.
pub const TERMINATE_ANSWER_MS: i64 = 30_000;
/// Termination requests of one node waiting for an answer.
const MAX_PENDING_TERMINATIONS: usize = MAX_TERMINATIONS;
/// Finished termination requests are kept this long for the panel.
const TERMINATION_MEMORY_MS: i64 = 10 * 60_000;
/// Termination requests kept per node, the oldest finished first to go.
const MAX_TERMINATIONS_KEPT: usize = 128;
const PENDING: &str = "pending";
const EXPIRED: &str = "expired";

/// Watch wakes, snapshot and termination requests and answers, and the
/// block-record database once opened.
#[derive(Default)]
pub(super) struct Live {
    wake: HashSet<String>,
    /// Per node: rules asked for and when.
    pending: HashMap<String, Vec<(String, i64)>>,
    /// Per node and rule: the latest answer, when it arrived and the agent
    /// run it came from.
    snapshots: HashMap<(String, String), (i64, String, Snapshot)>,
    /// Per node: the agent run of its latest report, if it ends sessions.
    instances: HashMap<String, String>,
    /// Per node: termination requests, oldest first.
    terminations: HashMap<String, Vec<TerminationView>>,
    records: BlockRecords,
    /// Per node, while the records are unavailable: where its agent's
    /// records got to.
    unkept: HashMap<String, crate::connections::Cursor>,
}

/// The block-record database, opened at most once per controller run.
#[derive(Default)]
enum BlockRecords {
    #[default]
    Unopened,
    Ready(Arc<Records>),
    /// Opening failed, as logged then; the retention it was asked for.
    Unavailable(Retention),
}

fn node_key(node: &str) -> String {
    format!("connections_node:{node}")
}
fn termination_key(node: &str) -> String {
    format!("connection_termination_node:{node}")
}
fn exists(conn: &Connection, key: &str) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM metadata WHERE key=?1)",
        [key],
        |r| r.get(0),
    )?)
}

/// Whether `node`'s agent reported that it keeps sessions and records.
pub(super) fn supported(conn: &Connection, node: &str) -> Result<bool> {
    exists(conn, &node_key(node))
}
/// Whether `node`'s agent last reported that it ends single sessions.
fn terminating(conn: &Connection, node: &str) -> Result<bool> {
    exists(conn, &termination_key(node))
}

/// Marks unanswered requests older than [`TERMINATE_ANSWER_MS`] `expired`
/// and forgets old finished ones. Returns the ones it marked, to audit.
#[must_use]
fn settle(requests: &mut Vec<TerminationView>, now: i64) -> Vec<TerminationView> {
    let mut expired = vec![];
    for request in requests.iter_mut() {
        if request.state == PENDING
            && now.saturating_sub(request.requested_ms) > TERMINATE_ANSWER_MS
        {
            request.state = EXPIRED.into();
            request.detail =
                "the agent did not answer within 30 s; the session may still be open".into();
            request.finished_ms = Some(now);
            expired.push(request.clone());
        }
    }
    requests.retain(|r| {
        r.finished_ms
            .is_none_or(|at| now.saturating_sub(at) <= TERMINATION_MEMORY_MS)
    });
    while requests.len() > MAX_TERMINATIONS_KEPT {
        let Some(oldest) = requests.iter().position(|r| r.state != PENDING) else {
            break;
        };
        requests.remove(oldest);
    }
    expired
}

/// Audits what became of a termination request: `actor` is the answering
/// node, or the controller for an expiry.
fn audit_result(
    tx: &Transaction<'_>,
    actor: &str,
    request: &TerminationView,
    state: &str,
    detail: &str,
) -> Result<()> {
    audit(
        tx,
        actor,
        "connection.terminate.result",
        &request.id,
        &serde_json::json!({
            "node_id": request.node_id, "rule_id": request.rule_id, "instance": request.instance,
            "session_id": request.session_id, "outcome": state, "detail": detail,
        })
        .to_string(),
    )
}
/// Audits requests [`settle`] marked `expired`, in their own transaction.
fn audit_expired(
    conn: &mut crate::journal::LoggedConnection,
    expired: &[TerminationView],
) -> Result<()> {
    if expired.is_empty() {
        return Ok(());
    }
    let tx = conn.transaction()?;
    for request in expired {
        audit_result(&tx, "controller", request, EXPIRED, &request.detail)?;
    }
    tx.commit()?;
    Ok(())
}
/// Unanswered: waiting, or expired with no answer yet.
fn unanswered(request: &TerminationView) -> bool {
    request.state == PENDING || request.state == EXPIRED
}

/// What a sync's report changed, for after its commit.
#[derive(Default)]
pub(super) struct Observed {
    supported: bool,
    terminating: bool,
    /// The tenant of each rule whose block records came.
    tenants: HashMap<String, String>,
    /// Termination requests now answered: id, state and detail.
    resolved: Vec<(String, String, String)>,
}

/// Checks the size of `node`'s report, keeps that it reported support and
/// whether it ends sessions, and audits answered termination requests.
/// Agents report only to a controller that said it takes reports.
pub(super) fn observe(
    tx: &Transaction<'_>,
    live: &Mutex<Live>,
    node: &str,
    report: Option<&Report>,
) -> Result<Observed> {
    let mut observed = Observed::default();
    if let Some(report) = report {
        if !report.within_limits() {
            return reject(400, "sync payload exceeds limits");
        }
        if !supported(tx, node)? {
            tx.execute(
                "INSERT INTO metadata(key,value) VALUES(?1,'1')",
                [node_key(node)],
            )?;
        }
        match (report.instance.is_empty(), terminating(tx, node)?) {
            (false, false) => {
                tx.execute(
                    "INSERT INTO metadata(key,value) VALUES(?1,'1')",
                    [termination_key(node)],
                )?;
            }
            // Downgraded: an agent that does not name its run.
            (true, true) => {
                tx.execute("DELETE FROM metadata WHERE key=?1", [termination_key(node)])?;
            }
            _ => {}
        }
        for block in report.blocks.iter().flat_map(|b| &b.entries) {
            if !observed.tenants.contains_key(&block.rule_id)
                && let Some(tenant) = tx
                    .query_row(
                        "SELECT tenant_id FROM rule_bindings WHERE rule_id=?1 AND node_id=?2",
                        params![block.rule_id, node],
                        |r| r.get::<_, String>(0),
                    )
                    .optional()?
            {
                observed.tenants.insert(block.rule_id.clone(), tenant);
            }
        }
        let live = live.lock().unwrap();
        // Expiry waits for the commit (see `answer_connections`): a sync
        // refused or rolled back would lose its audit.
        if let Some(requests) = live.terminations.get(node) {
            // An answer that comes after the request expired still settles it.
            for request in requests.iter().filter(|r| unanswered(r)) {
                let resolved = match report.terminations.iter().find(|a| a.id == request.id) {
                    Some(answer) => Some((
                        Outcome::parse(&answer.outcome).map_or("unknown", Outcome::as_str),
                        crate::connections::clip_detail(&answer.detail),
                    )),
                    None if !report.instance.is_empty() && report.instance != request.instance => {
                        Some((
                            Outcome::StaleInstance.as_str(),
                            "the server's agent restarted; the sessions of its earlier run ended with it"
                                .into(),
                        ))
                    }
                    None => None,
                };
                let Some((state, detail)) = resolved else {
                    continue;
                };
                audit_result(tx, &format!("node:{node}"), request, state, &detail)?;
                observed
                    .resolved
                    .push((request.id.clone(), state.to_owned(), detail));
            }
        }
    }
    observed.supported = supported(tx, node)?;
    observed.terminating = terminating(tx, node)?;
    Ok(observed)
}

/// Whether `node`'s watch should answer at once; answers yes once.
pub(super) fn take_wake(live: &Mutex<Live>, node: &str) -> bool {
    live.lock().unwrap().wake.remove(node)
}

/// The node's tenant-visible rule, or 404.
fn visible_rule(conn: &Connection, actor: &Actor, node: &str, rule: &str) -> Result<Rule> {
    require_node(conn, actor, node, false)?;
    reverse_tunnels::current_config(conn, node)?
        .and_then(|config| config.rules.into_iter().find(|r| r.id == rule))
        .filter(|r| actor.permits_tenant(&r.tenant_id))
        .map_or_else(|| reject(404, "rule not found"), Ok)
}

/// Opens the block-record file; a file that cannot be used (a symbolic
/// link, other permissions than 0600, damaged, from a newer release, or a
/// read-only or full disk) leaves the controller running without records.
fn open_records(path: &std::path::Path, retention: Retention) -> BlockRecords {
    match Records::open(path, retention, now_ms()) {
        Ok(records) => BlockRecords::Ready(Arc::new(records)),
        Err(error) => {
            tracing::error!(
                path = %path.display(), error = %format!("{error:#}"),
                "block records unavailable: the controller runs without them until it restarts"
            );
            BlockRecords::Unavailable(retention)
        }
    }
}

impl Store {
    /// Keeps block records in `path` instead of `blocks.sqlite` beside the
    /// controller database, for `retention`, applied at once. If the file
    /// cannot be used, says why in the log and runs without records.
    pub fn enable_block_records(&self, path: &std::path::Path, retention: Retention) {
        let records = open_records(path, retention);
        self.12.lock().unwrap().records = records;
    }
    /// The block-record database, or the retention asked for when it is
    /// unavailable. Opened once, with the default retention beside the
    /// controller database when the controller did not choose, and not
    /// while holding the lock.
    fn block_records(&self) -> std::result::Result<Arc<Records>, Retention> {
        let found = |records: &BlockRecords| match records {
            BlockRecords::Ready(records) => Some(Ok(records.clone())),
            BlockRecords::Unavailable(retention) => Some(Err(*retention)),
            BlockRecords::Unopened => None,
        };
        if let Some(found) = found(&self.12.lock().unwrap().records) {
            return found;
        }
        let path = self.1.parent().map_or_else(
            || PathBuf::from("blocks.sqlite"),
            |p| p.join("blocks.sqlite"),
        );
        let opened = open_records(&path, Retention::default());
        let mut live = self.12.lock().unwrap();
        if matches!(live.records, BlockRecords::Unopened) {
            live.records = opened;
        }
        found(&live.records).expect("opened above")
    }

    /// After the sync committed: settles termination requests the report
    /// answered, keeps its snapshots and block records, then tells a
    /// supporting agent which rules to report, which sessions to end and
    /// where the controller's records of it end.
    pub(super) fn answer_connections(
        &self,
        node: &str,
        report: Option<Report>,
        observed: Observed,
        response: &mut SyncResponse,
    ) {
        let now = now_ms();
        let mut guard = self.12.lock().unwrap();
        let live = &mut *guard;
        let mut expired = vec![];
        if let Some(requests) = live.terminations.get_mut(node) {
            for (id, state, detail) in observed.resolved {
                if let Some(request) = requests.iter_mut().find(|r| r.id == id && unanswered(r)) {
                    request.state = state;
                    request.detail = detail;
                    request.finished_ms = Some(now);
                }
            }
            expired = settle(requests, now);
        }
        let mut blocks: Option<BlockBatch> = None;
        if let Some(report) = report {
            if report.instance.is_empty() {
                live.instances.remove(node);
            } else {
                live.instances
                    .insert(node.to_owned(), report.instance.clone());
            }
            let pending = live.pending.entry(node.to_owned()).or_default();
            for snapshot in report.snapshots {
                // Only answers to a request are kept.
                let Some(position) = pending
                    .iter()
                    .position(|(rule, _)| *rule == snapshot.rule_id)
                else {
                    continue;
                };
                pending.remove(position);
                live.snapshots.insert(
                    (node.to_owned(), snapshot.rule_id.clone()),
                    (now, report.instance.clone(), snapshot),
                );
            }
            blocks = report.blocks;
        }
        if observed.supported {
            response.live_connection_requests = live
                .pending
                .get(node)
                .into_iter()
                .flatten()
                .filter(|(_, asked)| now.saturating_sub(*asked) <= ANSWER_MS)
                .take(MAX_SNAPSHOTS)
                .map(|(rule, _)| rule.clone())
                .collect();
        }
        if observed.supported
            && observed.terminating
            && let Some(current) = live.instances.get(node)
        {
            response.connection_terminations = live
                .terminations
                .get(node)
                .into_iter()
                .flatten()
                .filter(|r| {
                    r.state == PENDING
                        && r.instance == *current
                        && now.saturating_sub(r.requested_ms) <= TERMINATE_ANSWER_MS
                })
                .take(MAX_TERMINATIONS)
                .map(|r| Termination {
                    id: r.id.clone(),
                    rule_id: r.rule_id.clone(),
                    instance: r.instance.clone(),
                    session_id: r.session_id,
                })
                .collect();
        }
        drop(guard);
        if !expired.is_empty()
            && let Err(error) = audit_expired(&mut self.0.lock().unwrap(), &expired)
        {
            tracing::warn!(error = %format!("{error:#}"), "expired termination requests not audited");
        }
        if !observed.supported {
            return;
        }
        match self.block_records() {
            Ok(records) => {
                // Without a cursor the agent sends what it keeps from the
                // start again, at most a batch per sync, until a write works.
                let kept = records
                    .add(node, blocks, &observed.tenants, now)
                    .and_then(|()| records.cursor(node));
                match &kept {
                    Ok(cursor) => response.block_cursor = Some(cursor.clone()),
                    Err(error) if records.failing(true) => {
                        tracing::warn!(error = %format!("{error:#}"), "block records not kept");
                    }
                    Err(_) => {}
                }
                if kept.is_ok() && records.failing(false) {
                    tracing::info!("block records kept again");
                }
            }
            // Nothing can be kept this run: the agent goes on from what it
            // sent instead of sending it again.
            Err(_) => {
                let mut live = self.12.lock().unwrap();
                let cursor = live.unkept.entry(node.to_owned()).or_default();
                if let Some(batch) = blocks.filter(|b| identifier(&b.stream)) {
                    let seq = batch.entries.iter().map(|b| b.seq).max().unwrap_or(0);
                    if cursor.stream != batch.stream || seq > cursor.seq {
                        *cursor = crate::connections::Cursor {
                            stream: batch.stream,
                            seq,
                        };
                    }
                }
                response.block_cursor = Some(cursor.clone());
            }
        }
    }

    /// A rule's open sessions as its agent last reported them, its counters
    /// and whether newer sessions are on the way. Asks the agent when the
    /// snapshot is older than [`FRESH_MS`] and no request is waiting.
    /// `may_end` is whether the caller's credential may end sessions (an
    /// API token's scope).
    pub fn rule_connections(
        &self,
        actor: &Actor,
        node: &str,
        rule: &str,
        may_end: bool,
    ) -> Result<RuleView> {
        let conn = self.0.lock().unwrap();
        let spec = visible_rule(&conn, actor, node, rule)?;
        let (seen, stats): (Option<i64>, String) = conn.query_row(
            "SELECT last_seen_ms,stats_json FROM nodes WHERE id=?1",
            [node],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let (seen, stats) = self.4.current(node, seen, stats);
        let stats: EngineStats = serde_json::from_str(&stats).unwrap_or_default();
        let mut counters = RuleCounters::default();
        for report in stats.connections.iter().filter(|r| r.rule_id == rule) {
            match report.target_index {
                None => counters.inbound = Some(report.counts),
                Some(index) => counters.targets.push(TargetCounts {
                    target_index: index,
                    target_address: report.target_address.clone(),
                    via: spec
                        .targets
                        .get(index)
                        .filter(|t| t.address == report.target_address)
                        .and_then(|t| t.via.clone()),
                    counts: report.counts,
                }),
            }
        }
        counters.targets.sort_by(|a, b| {
            (a.target_index, &a.target_address).cmp(&(b.target_index, &b.target_address))
        });
        let supported = supported(&conn, node)?;
        let terminating = terminating(&conn, node)?;
        drop(conn);
        let now = now_ms();
        let online = seen.is_some_and(|seen| now.saturating_sub(seen) <= ONLINE_MS);
        let mut guard = self.12.lock().unwrap();
        let live = &mut *guard;
        live.snapshots
            .retain(|_, (at, _, _)| now.saturating_sub(*at) <= SNAPSHOT_MEMORY_MS);
        let key = (node.to_owned(), rule.to_owned());
        let state = if seen.is_none() {
            "offline"
        } else if !supported {
            "unsupported"
        } else if !online {
            "offline"
        } else if live
            .snapshots
            .get(&key)
            .is_some_and(|(at, _, _)| now.saturating_sub(*at) < FRESH_MS)
        {
            "ready"
        } else {
            let pending = live.pending.entry(node.to_owned()).or_default();
            match pending.iter().position(|(r, _)| r == rule) {
                Some(index) if now.saturating_sub(pending[index].1) > ANSWER_MS => {
                    // Reported once; the next look asks again.
                    pending.remove(index);
                    "no_answer"
                }
                Some(_) => "pending",
                None => {
                    pending.retain(|(_, asked)| now.saturating_sub(*asked) <= ANSWER_MS);
                    if pending.len() >= MAX_PENDING {
                        return reject(
                            429,
                            "too many connection snapshots are waiting for this server; try again in a few seconds",
                        );
                    }
                    pending.push((rule.to_owned(), now));
                    live.wake.insert(node.to_owned());
                    self.2.config.notify_waiters();
                    "pending"
                }
            }
        };
        let snapshot = live.snapshots.get(&key);
        if let Some((_, _, snapshot)) = snapshot {
            counters.refused = snapshot.refused.clone();
        }
        let instance = snapshot
            .map(|(_, instance, _)| instance.clone())
            .filter(|i| !i.is_empty());
        // Only the agent's current run: the sessions of a run before its
        // restart ended with it, though its list is still shown.
        let current = instance.is_some() && live.instances.get(node) == instance.as_ref();
        let can_terminate = may_end && actor.may_write() && online && terminating && current;
        // A gateway's bridge sessions never end alone, whatever is reported.
        let gateway = spec.protocol_gateway.is_some();
        let snapshot = snapshot.map(|(_, _, s)| s);
        let totals = snapshot.map_or_else(Totals::default, |s| Totals {
            tcp: s.tcp,
            udp: s.udp,
        });
        let sessions: Vec<SessionView> = snapshot
            .map(|s| s.sessions.clone())
            .unwrap_or_default()
            .into_iter()
            .map(|mut session| {
                let terminable = can_terminate && !gateway && session.terminable;
                // Shown once, as decided here: the agent's own says no more.
                session.terminable = false;
                SessionView {
                    session,
                    terminable,
                }
            })
            .collect();
        Ok(RuleView {
            state,
            taken_at_ms: snapshot.map(|s| s.taken_at_ms),
            instance,
            can_terminate,
            truncated: (sessions.len() as u64) < totals.tcp + totals.udp,
            totals,
            sessions,
            counters,
        })
    }

    /// Asks `node`'s agent to end session `session_id` of `rule` in agent
    /// run `instance`, for a user who may change the rule and confirmed it.
    /// Returns whether this made a new request, and the request.
    pub fn terminate_session(
        &self,
        actor: &Actor,
        node: &str,
        rule: &str,
        instance: &str,
        session_id: u64,
        confirm: bool,
    ) -> Result<(bool, TerminationView)> {
        let mut conn = self.0.lock().unwrap();
        let spec = visible_rule(&conn, actor, node, rule)?;
        if !actor.may_write() {
            return reject(403, "read-only role cannot end sessions");
        }
        if !confirm {
            return reject(400, "ending a session needs \"confirm\": true");
        }
        if !identifier(instance) || instance.len() > 64 {
            return reject(400, "invalid agent instance");
        }
        if spec.protocol_gateway.is_some() {
            return reject(
                409,
                "a protocol gateway's client connections belong to its engine; its sessions cannot be ended one by one",
            );
        }
        // As the connection list judges it: the stored time is written only
        // every minute.
        let (seen, stats): (Option<i64>, String) = conn.query_row(
            "SELECT last_seen_ms,stats_json FROM nodes WHERE id=?1",
            [node],
            |r| Ok((r.get(0)?, r.get(1)?)),
        )?;
        let (seen, _) = self.4.current(node, seen, stats);
        let now = now_ms();
        if !seen.is_some_and(|seen| now.saturating_sub(seen) <= ONLINE_MS) {
            return reject(
                409,
                "the server is offline (no sync for 90 s); its sessions cannot be ended now",
            );
        }
        if !supported(&conn, node)? || !terminating(&conn, node)? {
            return reject(
                409,
                "this server's agent cannot end single sessions; upgrade it first",
            );
        }
        let mut live = self.12.lock().unwrap();
        if live
            .instances
            .get(node)
            .is_some_and(|current| current != instance)
        {
            return reject(
                409,
                "the server's agent restarted after this list was taken: the session ended with it; refresh the list",
            );
        }
        let listed = live
            .snapshots
            .get(&(node.to_owned(), rule.to_owned()))
            .filter(|(_, run, _)| run == instance)
            .and_then(|(_, _, snapshot)| snapshot.sessions.iter().find(|s| s.id == session_id))
            .cloned();
        if listed.as_ref().is_some_and(|session| !session.terminable) {
            return reject(
                409,
                "the server's agent cannot end this kind of session alone (see the connection documentation)",
            );
        }
        let requests = live.terminations.entry(node.to_owned()).or_default();
        let expired = settle(requests, now);
        audit_expired(&mut conn, &expired)?;
        if let Some(existing) = requests.iter().find(|r| {
            r.rule_id == rule
                && r.instance == instance
                && r.session_id == session_id
                && r.state != EXPIRED
        }) {
            return Ok((
                false,
                TerminationView {
                    duplicate: true,
                    ..existing.clone()
                },
            ));
        }
        if requests.iter().filter(|r| r.state == PENDING).count() >= MAX_PENDING_TERMINATIONS {
            return reject(
                429,
                "too many sessions of this server are waiting to be ended; try again in a few seconds",
            );
        }
        let request = TerminationView {
            id: Uuid::new_v4().simple().to_string(),
            node_id: node.to_owned(),
            rule_id: rule.to_owned(),
            instance: instance.to_owned(),
            session_id,
            protocol: listed
                .as_ref()
                .map(|s| s.protocol.clone())
                .unwrap_or_default(),
            client: listed.as_ref().map(|s| s.client),
            state: PENDING.into(),
            detail: String::new(),
            requested_by: actor.id.clone(),
            requested_ms: now,
            finished_ms: None,
            duplicate: false,
        };
        let tx = conn.transaction()?;
        audit(
            &tx,
            &actor.id,
            "connection.terminate",
            &request.id,
            &serde_json::json!({
                "node_id": node, "rule_id": rule, "instance": instance, "session_id": session_id,
                "protocol": request.protocol, "client": request.client,
            })
            .to_string(),
        )?;
        tx.commit()?;
        requests.push(request.clone());
        live.wake.insert(node.to_owned());
        self.2.config.notify_waiters();
        Ok((true, request))
    }

    /// One termination request of `rule` on `node`, as the panel follows it.
    pub fn session_termination(
        &self,
        actor: &Actor,
        node: &str,
        rule: &str,
        id: &str,
    ) -> Result<TerminationView> {
        let mut conn = self.0.lock().unwrap();
        visible_rule(&conn, actor, node, rule)?;
        let mut live = self.12.lock().unwrap();
        let requests = live.terminations.entry(node.to_owned()).or_default();
        let expired = settle(requests, now_ms());
        audit_expired(&mut conn, &expired)?;
        requests
            .iter()
            .find(|r| r.id == id && r.rule_id == rule)
            .cloned()
            .map_or_else(
                || {
                    reject(
                        404,
                        "termination request not found: results are kept for 10 minutes and not across a controller restart",
                    )
                },
                Ok,
            )
    }

    /// One page of the node's kept block records, latest change first; for
    /// other than system administrators only those of their tenant's rules.
    pub fn node_blocks(
        &self,
        actor: &Actor,
        node: &str,
        rule: Option<&str>,
        before: Option<i64>,
        limit: usize,
    ) -> Result<BlocksView> {
        let conn = self.0.lock().unwrap();
        if let Some(rule) = rule {
            visible_rule(&conn, actor, node, rule)?;
        } else {
            require_node(&conn, actor, node, false)?;
        }
        let supported = supported(&conn, node)?;
        drop(conn);
        let records = match self.block_records() {
            Ok(records) => records,
            Err(retention) => {
                return Ok(BlocksView {
                    supported,
                    blocks: vec![],
                    next_before: None,
                    retention,
                    unavailable: true,
                });
            }
        };
        let (blocks, next_before) = records.read(&Query {
            node,
            rule,
            tenant: (actor.role != Role::SystemAdmin).then_some(actor.tenant_id.as_str()),
            before,
            limit,
        })?;
        Ok(BlocksView {
            supported,
            blocks,
            next_before,
            retention: records.retention(),
            unavailable: false,
        })
    }

    /// Drops a deleted node's snapshots, requests and block records.
    pub(super) fn forget_connections(&self, node: &str) {
        {
            let mut live = self.12.lock().unwrap();
            live.wake.remove(node);
            live.pending.remove(node);
            live.instances.remove(node);
            live.terminations.remove(node);
            live.unkept.remove(node);
            live.snapshots.retain(|(id, _), _| id != node);
        }
        if let Ok(records) = self.block_records()
            && let Err(error) = records.forget(node)
        {
            tracing::warn!(node_id = %node, %error, "block records of a deleted server not removed");
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connections::{Cursor, TerminationResult};

    fn reply() -> SyncResponse {
        SyncResponse {
            credential_rotation: None,
            budget: None,
            controller_instance: String::new(),
            config: None,
            acknowledgements: vec![],
            server_time_ms: 0,
            user_rates: None,
            log_cursor: None,
            mptcp_paths: None,
            authoritative_dns: None,
            wireguard: None,
            reverse_tunnels: None,
            rate_limits: false,
            speed_test: false,
            speed_test_tasks: vec![],
            live_connections: true,
            live_connection_requests: vec![],
            block_cursor: None,
            egress_proxy: false,
            firewall: None,
            connection_termination: true,
            connection_terminations: vec![],
        }
    }

    /// A controller with node `n`'s rule `r` and a viewer.
    struct Fixture {
        _tmp: tempfile::TempDir,
        store: Store,
        admin: Actor,
        node: String,
    }
    fn fixture() -> Fixture {
        let tmp = tempfile::tempdir().unwrap();
        let store = Store::open(&tmp.path().join("controller.sqlite")).unwrap();
        store.set_kind("controller").unwrap();
        let admin = store.bootstrap("connections-test-password").unwrap();
        let (node, _) = store.create_node(&admin, "default", "n").unwrap();
        let rule: Rule = serde_json::from_value(serde_json::json!({
            "id": "r", "tenant_id": "default", "owner_id": admin.id, "name": "r",
            "listen": "127.0.0.1:20001", "protocol": "tcp", "targets": [{"address": "127.0.0.1:9"}],
            "quota_bytes": null, "expires_at_ms": null, "rate_bytes_per_sec": null, "meter_epoch": "e",
        }))
        .unwrap();
        store.set_config(&admin, &node.id, 0, vec![rule]).unwrap();
        Fixture {
            _tmp: tmp,
            store,
            admin,
            node: node.id,
        }
    }
    impl Fixture {
        fn sync(&self, report: Option<Report>) -> SyncResponse {
            self.try_sync(report, None).unwrap()
        }
        /// A sync, with another ledger to have it refused after its report
        /// was read.
        fn try_sync(&self, report: Option<Report>, ledger: Option<&str>) -> Result<SyncResponse> {
            let reconciled = self
                .store
                .reconcile(
                    &self.node,
                    ReconcileRequest {
                        lease: None,
                        ledger_id: None,
                        after: None,
                        expected_revision: None,
                    },
                )
                .unwrap()
                .ledger_id;
            self.store.sync(
                &self.node,
                SyncRequest {
                    logs: None,
                    lease: None,
                    budget: None,
                    ledger_id: ledger.map_or(reconciled, str::to_owned),
                    need_config: false,
                    applied_revision: 0,
                    apply_error: None,
                    usage: vec![],
                    stats: EngineStats {
                        live_connections: report,
                        ..EngineStats::default()
                    },
                },
            )
        }
    }
    fn run(instance: &str, answers: Vec<TerminationResult>) -> Report {
        Report {
            instance: instance.into(),
            terminations: answers,
            ..Report::default()
        }
    }
    fn status<T: std::fmt::Debug>(result: Result<T>) -> u16 {
        result
            .unwrap_err()
            .downcast_ref::<Rejection>()
            .map_or(500, |r| r.status)
    }

    #[test]
    fn requests_go_to_supporting_agents_only_and_answers_need_a_request() {
        let f = fixture();
        f.store
            .12
            .lock()
            .unwrap()
            .pending
            .insert("n".into(), vec![("a".into(), now_ms()), ("old".into(), 0)]);
        let observed = |supported| Observed {
            supported,
            ..Observed::default()
        };
        let mut old = reply();
        f.store
            .answer_connections("n", None, observed(false), &mut old);
        assert!(old.live_connection_requests.is_empty() && old.block_cursor.is_none());
        let mut new = reply();
        f.store
            .answer_connections("n", None, observed(true), &mut new);
        // Expired requests are not sent again.
        assert_eq!(new.live_connection_requests, ["a"]);
        assert_eq!(new.block_cursor, Some(Cursor::default()));
        // An answer nobody asked for is not kept.
        let snapshot = |rule: &str| Snapshot {
            rule_id: rule.into(),
            ..Snapshot::default()
        };
        let report = Report {
            snapshots: vec![snapshot("other"), snapshot("a")],
            ..Report::default()
        };
        let mut next = reply();
        f.store
            .answer_connections("n", Some(report), observed(true), &mut next);
        let live = f.store.12.lock().unwrap();
        assert!(live.snapshots.contains_key(&("n".into(), "a".into())));
        assert!(!live.snapshots.contains_key(&("n".into(), "other".into())));
        assert!(next.live_connection_requests.is_empty());
    }

    #[test]
    fn an_unanswered_request_is_reported_once_and_then_asked_again() {
        let f = fixture();
        f.sync(None);
        f.sync(Some(Report::default()));
        let state = || {
            f.store
                .rule_connections(&f.admin, &f.node, "r", true)
                .unwrap()
                .state
        };
        assert_eq!(state(), "pending");
        assert_eq!(
            f.sync(Some(Report::default())).live_connection_requests,
            ["r"]
        );
        // The agent never answers.
        f.store.12.lock().unwrap().pending.get_mut(&f.node).unwrap()[0].1 -= ANSWER_MS + 1;
        assert!(
            f.sync(Some(Report::default()))
                .live_connection_requests
                .is_empty(),
            "not sent again"
        );
        assert_eq!(state(), "no_answer");
        assert_eq!(state(), "pending", "the next look asks again");
        assert_eq!(
            f.sync(Some(Report::default())).live_connection_requests,
            ["r"]
        );
    }

    #[test]
    fn a_termination_goes_to_its_run_once_and_every_request_ends_explicitly() {
        let f = fixture();
        let (db, admin, node) = (&f.store, &f.admin, f.node.as_str());
        let ask = |instance: &str, session: u64| {
            db.terminate_session(admin, node, "r", instance, session, true)
        };
        // An agent that does not name its run cannot end sessions.
        f.sync(Some(Report::default()));
        assert_eq!(status(ask("run1", 1)), 409);
        // Once it does, a request needs a writer's confirmation.
        let reply = f.sync(Some(run("run1", vec![])));
        assert!(reply.connection_termination && reply.connection_terminations.is_empty());
        assert_eq!(
            status(db.terminate_session(admin, node, "r", "run1", 1, false)),
            400
        );
        db.create_user(
            admin,
            "default",
            "watcher",
            "connections-test-password",
            Role::Viewer,
        )
        .unwrap();
        let viewer = Actor {
            role: Role::Viewer,
            id: "viewer".into(),
            username: "watcher".into(),
            tenant_id: "default".into(),
        };
        assert_eq!(
            status(db.terminate_session(&viewer, node, "r", "run1", 1, true)),
            403
        );
        let other = Actor {
            role: Role::TenantAdmin,
            tenant_id: "other".into(),
            ..viewer.clone()
        };
        assert_eq!(
            status(db.terminate_session(&other, node, "r", "run1", 1, true)),
            404
        );
        assert_eq!(status(ask("../x", 1)), 400);
        let (created, first) = ask("run1", 1).unwrap();
        assert!(created && first.state == "pending" && !first.duplicate);
        // The same session again is the same request, not a second one.
        let (created, again) = ask("run1", 1).unwrap();
        assert!(!created && again.duplicate && again.id == first.id);
        // It goes to the agent with every reply until answered.
        let terminations = f.sync(Some(run("run1", vec![]))).connection_terminations;
        assert_eq!(
            terminations,
            [Termination {
                id: first.id.clone(),
                rule_id: "r".into(),
                instance: "run1".into(),
                session_id: 1
            }]
        );
        assert_eq!(
            f.sync(Some(run("run1", vec![])))
                .connection_terminations
                .len(),
            1
        );
        let closed = TerminationResult {
            id: first.id.clone(),
            outcome: "closed".into(),
            detail: String::new(),
        };
        assert!(
            f.sync(Some(run("run1", vec![closed.clone()])))
                .connection_terminations
                .is_empty()
        );
        let view = db.session_termination(admin, node, "r", &first.id).unwrap();
        assert_eq!(view.state, "closed");
        assert!(view.finished_ms.is_some());
        // The answer coming again changes and audits nothing.
        f.sync(Some(run("run1", vec![closed])));
        let (created, done) = ask("run1", 1).unwrap();
        assert!(!created && done.state == "closed" && done.duplicate);
        let audited = db.audit_log(admin).unwrap();
        let actions: Vec<&str> = audited
            .iter()
            .filter(|a| a["resource"] == first.id.as_str())
            .map(|a| a["action"].as_str().unwrap())
            .collect();
        assert_eq!(
            actions,
            ["connection.terminate.result", "connection.terminate"],
            "newest first"
        );
        // The agent restarted before answering: the request ends as stale
        // without reaching the new run, and the old run is refused.
        let (_, second) = ask("run1", 2).unwrap();
        assert!(
            f.sync(Some(run("run2", vec![])))
                .connection_terminations
                .is_empty()
        );
        assert_eq!(
            db.session_termination(admin, node, "r", &second.id)
                .unwrap()
                .state,
            "stale_instance"
        );
        assert_eq!(status(ask("run1", 3)), 409);
        // No answer within 30 s: expired, and asking again makes a new one.
        let (_, third) = ask("run2", 3).unwrap();
        f.store
            .12
            .lock()
            .unwrap()
            .terminations
            .get_mut(node)
            .unwrap()
            .iter_mut()
            .find(|r| r.id == third.id)
            .unwrap()
            .requested_ms -= TERMINATE_ANSWER_MS + 1;
        // A sync refused after its report was read expires nothing: the
        // expiry, and its audit, come with the next sync that commits.
        assert_eq!(
            status(f.try_sync(Some(run("run2", vec![])), Some("another-ledger"))),
            409
        );
        assert!(
            f.sync(Some(run("run2", vec![])))
                .connection_terminations
                .is_empty()
        );
        let expired = db.session_termination(admin, node, "r", &third.id).unwrap();
        assert_eq!(expired.state, "expired");
        let (created, retry) = ask("run2", 3).unwrap();
        assert!(created && retry.id != third.id);
        // The controller audited the expiry; an answer that comes later
        // still settles the expired request, and is audited too.
        let late = TerminationResult {
            id: third.id.clone(),
            outcome: "closed".into(),
            detail: String::new(),
        };
        f.sync(Some(run("run2", vec![late])));
        assert_eq!(
            db.session_termination(admin, node, "r", &third.id)
                .unwrap()
                .state,
            "closed"
        );
        let trail: Vec<(String, String)> = db
            .audit_log(admin)
            .unwrap()
            .iter()
            .filter(|a| a["resource"] == third.id.as_str())
            .map(|a| {
                let detail: serde_json::Value =
                    serde_json::from_str(a["detail"].as_str().unwrap()).unwrap();
                (
                    a["actor_id"].as_str().unwrap().to_owned(),
                    detail["outcome"].as_str().unwrap_or_default().to_owned(),
                )
            })
            .collect();
        assert_eq!(
            trail,
            [
                (format!("node:{node}"), "closed".to_owned()),
                ("controller".to_owned(), "expired".to_owned()),
                (admin.id.clone(), String::new()),
            ]
        );
        // At most 16 wait at a time.
        for session in 10..25 {
            ask("run2", session).unwrap();
        }
        assert_eq!(status(ask("run2", 99)), 429);
        // Downgraded: no run in the report, no requests, 409 again.
        assert!(
            f.sync(Some(Report::default()))
                .connection_terminations
                .is_empty()
        );
        assert_eq!(status(ask("run2", 100)), 409);
        // Unknown request ids, also after a controller restart, are 404.
        assert_eq!(
            status(db.session_termination(admin, node, "r", "nope")),
            404
        );
        let path = db.1.as_ref().clone();
        let restarted = Store::open(&path).unwrap();
        assert_eq!(
            status(restarted.session_termination(admin, node, "r", &first.id)),
            404
        );
    }

    fn rule(id: &str, tenant: &str, owner: &str, listen: &str) -> Rule {
        serde_json::from_value(serde_json::json!({
            "id": id, "tenant_id": tenant, "owner_id": owner, "name": id,
            "listen": listen, "protocol": "tcp", "targets": [{"address": "127.0.0.1:9"}],
            "quota_bytes": null, "expires_at_ms": null, "rate_bytes_per_sec": null, "meter_epoch": "e",
        }))
        .unwrap()
    }
    fn block(rule_id: &str, seq: u64) -> crate::connections::Block {
        crate::connections::Block {
            id: seq,
            seq,
            rule_id: rule_id.into(),
            protocol: "tcp".into(),
            source: "203.0.113.9".parse().unwrap(),
            reason: "source_denied".into(),
            detail: String::new(),
            first_ms: 1,
            last_ms: 1,
            count: 3,
        }
    }
    fn blocks(entries: Vec<crate::connections::Block>) -> Report {
        Report {
            instance: "run1".into(),
            blocks: Some(BlockBatch {
                stream: "s".into(),
                entries,
            }),
            ..Report::default()
        }
    }
    fn session(id: u64, protocol: &str, terminable: bool) -> crate::connections::Session {
        crate::connections::Session {
            id,
            protocol: protocol.into(),
            udp: false,
            client: "127.0.0.1:40000".parse().unwrap(),
            started_ms: 1,
            target_index: None,
            target: String::new(),
            remote: None,
            via: None,
            destination: String::new(),
            upload_bytes: 0,
            download_bytes: 0,
            terminable,
        }
    }

    #[test]
    fn ending_follows_the_agent_liveness_token_scope_and_gateways() {
        let f = fixture();
        let (db, admin, node) = (&f.store, &f.admin, f.node.as_str());
        let mut gateway = rule("gw", "default", &admin.id, "127.0.0.1:20002");
        gateway.targets.clear();
        gateway.protocol_gateway = Some(crate::gateway::Config {
            listen: "127.0.0.1:20443".parse().unwrap(),
            protocol: crate::gateway::WireProtocol::Vless {
                uuid: "bf000d23-0752-40b4-affe-68f7707a9661".into(),
                vision: false,
            },
            security: crate::gateway::Security::Certificate {
                identity: "server".into(),
                server_name: Some("relay.test".into()),
            },
            allow_private_destinations: true,
        });
        let plain = rule("r", "default", &admin.id, "127.0.0.1:20001");
        db.set_config(admin, node, 1, vec![plain, gateway]).unwrap();
        f.sync(Some(run("run1", vec![])));
        // The agent says which sessions can end: the plain rule's first, not
        // its second, and (wrongly) the gateway's bridge, shown as SOCKS5 UDP.
        for rule in ["r", "gw"] {
            db.rule_connections(admin, node, rule, true).unwrap();
        }
        let snapshot = |rule: &str, sessions| Snapshot {
            rule_id: rule.into(),
            taken_at_ms: 1,
            tcp: 2,
            sessions,
            ..Snapshot::default()
        };
        f.sync(Some(Report {
            instance: "run1".into(),
            snapshots: vec![
                snapshot("r", vec![session(1, "tcp", true), session(2, "tcp", false)]),
                snapshot("gw", vec![session(3, "socks5_udp", true)]),
            ],
            ..Report::default()
        }));
        let shown = |rule: &str, may_end: bool| -> (bool, Vec<bool>) {
            let view = db.rule_connections(admin, node, rule, may_end).unwrap();
            (
                view.can_terminate,
                view.sessions.iter().map(|s| s.terminable).collect(),
            )
        };
        assert_eq!(shown("r", true), (true, vec![true, false]));
        assert_eq!(shown("gw", true), (true, vec![false]), "never a gateway's");
        // A token without the scope that writes nodes is offered nothing.
        assert_eq!(shown("r", false), (false, vec![false, false]));
        let ask = |rule: &str, session: u64| {
            db.terminate_session(admin, node, rule, "run1", session, true)
        };
        assert_eq!(status(ask("gw", 3)), 409);
        assert_eq!(status(ask("gw", 99)), 409, "also a session not listed");
        assert_eq!(status(ask("r", 2)), 409);
        assert!(ask("r", 1).unwrap().0);
        // The stored report time is written once a minute: a server that
        // reports every 50 s is online although that time is 100 s old.
        let stale = now_ms() - 100_000;
        let set_seen = |seen: i64| {
            db.0.lock()
                .unwrap()
                .execute(
                    "UPDATE nodes SET last_seen_ms=?1 WHERE id=?2",
                    params![seen, node],
                )
                .unwrap();
        };
        set_seen(stale);
        db.4.keep_status(node, Some(stale), &EngineStats::default());
        assert!(shown("r", true).0);
        assert!(ask("r", 5).unwrap().0, "not offline");
        // No report for longer than 90 s: offline.
        set_seen(stale - 1);
        assert!(!shown("r", true).0);
        let refused = ask("r", 6).unwrap_err();
        let refused = refused.downcast_ref::<Rejection>().unwrap();
        assert_eq!(refused.status, 409);
        assert!(refused.message.contains("offline"), "{}", refused.message);
        // The agent restarted and has not listed its sessions again: the
        // old run's are still shown, and none can be ended.
        f.sync(Some(run("run2", vec![])));
        let view = db.rule_connections(admin, node, "r", true).unwrap();
        assert_eq!(view.instance.as_deref(), Some("run1"));
        assert_eq!(shown("r", true), (false, vec![false, false]));
    }

    /// The block-record file copied back with the usual permissions,
    /// damaged, a symbolic link, or in a directory the controller cannot
    /// write: the controller runs on without records.
    #[cfg(unix)]
    #[test]
    fn unusable_block_record_files_leave_the_controller_running() {
        use std::os::unix::fs::PermissionsExt;
        let f = fixture();
        let (db, admin, node) = (&f.store, &f.admin, f.node.as_str());
        let dir = f._tmp.path();
        let copied = dir.join("copied.sqlite");
        drop(Records::open(&copied, Retention::default(), now_ms()).unwrap());
        std::fs::set_permissions(&copied, std::fs::Permissions::from_mode(0o644)).unwrap();
        let damaged = dir.join("damaged.sqlite");
        crate::store::write_secret(&damaged, &[7u8; 4096]).unwrap();
        let link = dir.join("link.sqlite");
        std::os::unix::fs::symlink(dir.join("controller.sqlite"), &link).unwrap();
        let locked = dir.join("locked");
        std::fs::create_dir(&locked).unwrap();
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o500)).unwrap();
        let paths = [copied, damaged, link, locked.join("blocks.sqlite")];
        for (seq, path) in (1..).zip(&paths) {
            let retention = Retention {
                days: 3,
                per_node: 200,
            };
            db.enable_block_records(path, retention);
            let reply = f.sync(Some(blocks(vec![block("r", seq)])));
            // The agent goes on from what it sent instead of sending it again.
            assert_eq!(
                reply.block_cursor,
                Some(Cursor {
                    stream: "s".into(),
                    seq
                }),
                "{path:?}"
            );
            let view = db.node_blocks(admin, node, None, None, 10).unwrap();
            assert!(view.unavailable && view.blocks.is_empty(), "{path:?}");
            assert_eq!(view.retention, retention);
            assert_eq!(
                db.rule_connections(admin, node, "r", true).unwrap().state,
                "pending"
            );
        }
        std::fs::set_permissions(&locked, std::fs::Permissions::from_mode(0o700)).unwrap();
        assert!(!locked.join("blocks.sqlite").exists());
    }

    #[test]
    fn deleting_a_server_drops_its_records_and_support() {
        let f = fixture();
        let (db, admin, node) = (&f.store, &f.admin, f.node.as_str());
        // A server's rules all belong to its tenant (topology refuses
        // others), and a server keeps its tenant. A record of a rule the
        // controller does not know (removed before the record arrived) has
        // no tenant and is for system administrators only.
        let tenant = db.create_tenant(admin, "other").unwrap();
        f.sync(Some(blocks(vec![block("r", 1), block("gone", 2)])));
        let rules = |actor: &Actor| -> Vec<String> {
            db.node_blocks(actor, node, None, None, 10)
                .unwrap()
                .blocks
                .into_iter()
                .map(|b| b.rule_id)
                .collect()
        };
        assert_eq!(rules(admin), ["gone", "r"]);
        let view = db.node_blocks(admin, node, None, None, 10).unwrap();
        assert_eq!(view.retention, Retention::default());
        assert!(f._tmp.path().join("blocks.sqlite").exists());
        // Records keep the tenant of their rule: the server's tenant reads
        // its rule's records, other tenants do not see the server.
        let own = Actor {
            role: Role::TenantAdmin,
            tenant_id: "default".into(),
            id: "d".into(),
            username: "d".into(),
        };
        assert_eq!(rules(&own), ["r"]);
        let other = Actor {
            tenant_id: tenant.clone(),
            ..own.clone()
        };
        assert_eq!(status(db.node_blocks(&other, node, None, None, 10)), 404);
        db.delete_node(admin, node).unwrap();
        let conn = db.0.lock().unwrap();
        for key in [node_key(node), termination_key(node)] {
            assert!(!exists(&conn, &key).unwrap(), "{key}");
        }
        drop(conn);
        let records = db.block_records().unwrap();
        assert!(
            records
                .read(&Query {
                    node,
                    rule: None,
                    tenant: None,
                    before: None,
                    limit: 10
                })
                .unwrap()
                .0
                .is_empty()
        );
        assert_eq!(records.cursor(node).unwrap(), Cursor::default());
    }
}
