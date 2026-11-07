//! Live connections and block records on the controller. Nothing here is
//! stored: snapshots, requests and the latest [`KEEP`] block records of each
//! node live in memory and are lost when the controller restarts, like live
//! logs. Agents that never reported support (`connections_node:<node id>`,
//! written once, as for speed tests) get no requests and no cursor, and the
//! panel shows that their agent needs an upgrade.
//!
//! A panel request for a rule's sessions asks the node's agent through its
//! configuration watch, as speed tests do; the agent answers with its next
//! report. A snapshot younger than [`FRESH_MS`] is reused, so one user
//! polling cannot make the agent take snapshots faster than that, and at
//! most [`MAX_PENDING`] rules of a node wait for an answer at a time.
use super::*;
use crate::connections::{
    BlockView, BlocksView, KEEP, Kept, MAX_SNAPSHOTS, Report, RuleCounters, RuleView, Snapshot,
    TargetCounts, Totals,
};
use std::collections::{HashMap, HashSet};

/// A snapshot this young is shown instead of asking again.
const FRESH_MS: i64 = 2_000;
/// A request the agent has not answered by then is reported as unanswered.
const ANSWER_MS: i64 = 30_000;
const ONLINE_MS: i64 = 90_000;
/// Rules of one node waiting for a snapshot.
const MAX_PENDING: usize = 8;
/// Snapshots not looked at for this long are dropped.
const SNAPSHOT_MEMORY_MS: i64 = 60_000;

/// Watch wakes, snapshot requests and answers, and block records.
#[derive(Default)]
pub(super) struct Live {
    wake: HashSet<String>,
    /// Per node: rules asked for and when.
    pending: HashMap<String, Vec<(String, i64)>>,
    /// Per node and rule: the latest answer and when it arrived.
    snapshots: HashMap<(String, String), (i64, Snapshot)>,
    blocks: HashMap<String, Kept>,
}

fn node_key(node: &str) -> String {
    format!("connections_node:{node}")
}

/// Whether `node`'s agent reported that it keeps sessions and records.
pub(super) fn supported(conn: &Connection, node: &str) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM metadata WHERE key=?1)",
        [node_key(node)],
        |r| r.get(0),
    )?)
}

/// Checks the size of `node`'s report and keeps that it reported support.
/// Agents report only to a controller that said it takes reports.
pub(super) fn observe(tx: &Transaction<'_>, node: &str, report: Option<&Report>) -> Result<()> {
    let Some(report) = report else {
        return Ok(());
    };
    if !report.within_limits() {
        return reject(400, "sync payload exceeds limits");
    }
    if !supported(tx, node)? {
        tx.execute(
            "INSERT INTO metadata(key,value) VALUES(?1,'1')",
            [node_key(node)],
        )?;
    }
    Ok(())
}

/// Whether `node`'s watch should answer at once; answers yes once.
pub(super) fn take_wake(live: &Mutex<Live>, node: &str) -> bool {
    live.lock().unwrap().wake.remove(node)
}

/// After the sync committed: keeps the answers and records of `report`,
/// then tells a supporting agent which rules to report and where the
/// controller's copy of its records ends.
pub(super) fn answer(
    live: &Mutex<Live>,
    node: &str,
    supported: bool,
    report: Option<Report>,
    response: &mut SyncResponse,
) {
    let now = now_ms();
    let mut live = live.lock().unwrap();
    let live = &mut *live;
    if let Some(report) = report {
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
            live.snapshots
                .insert((node.to_owned(), snapshot.rule_id.clone()), (now, snapshot));
        }
        live.blocks
            .entry(node.to_owned())
            .or_default()
            .add(report.blocks);
    }
    if supported {
        response.block_cursor = Some(live.blocks.get(node).map(Kept::cursor).unwrap_or_default());
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
}

/// The node's tenant-visible rule, or 404.
fn visible_rule(conn: &Connection, actor: &Actor, node: &str, rule: &str) -> Result<Rule> {
    require_node(conn, actor, node, false)?;
    reverse_tunnels::current_config(conn, node)?
        .and_then(|config| config.rules.into_iter().find(|r| r.id == rule))
        .filter(|r| actor.permits_tenant(&r.tenant_id))
        .map_or_else(|| reject(404, "rule not found"), Ok)
}

impl Store {
    /// A rule's open sessions as its agent last reported them, its counters
    /// and whether newer sessions are on the way. Asks the agent when the
    /// snapshot is older than [`FRESH_MS`] and no request is waiting.
    pub fn rule_connections(&self, actor: &Actor, node: &str, rule: &str) -> Result<RuleView> {
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
        drop(conn);
        let now = now_ms();
        let online = seen.is_some_and(|seen| now.saturating_sub(seen) <= ONLINE_MS);
        let mut guard = self.12.lock().unwrap();
        let live = &mut *guard;
        live.snapshots
            .retain(|_, (at, _)| now.saturating_sub(*at) <= SNAPSHOT_MEMORY_MS);
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
            .is_some_and(|(at, _)| now.saturating_sub(*at) < FRESH_MS)
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
        if let Some((_, snapshot)) = live.snapshots.get(&key) {
            counters.refused = snapshot.refused.clone();
        }
        let snapshot = live.snapshots.get(&key).map(|(_, s)| s);
        let totals = snapshot.map_or_else(Totals::default, |s| Totals {
            tcp: s.tcp,
            udp: s.udp,
        });
        let sessions = snapshot.map(|s| s.sessions.clone()).unwrap_or_default();
        Ok(RuleView {
            state,
            taken_at_ms: snapshot.map(|s| s.taken_at_ms),
            truncated: (sessions.len() as u64) < totals.tcp + totals.udp,
            totals,
            sessions,
            counters,
        })
    }

    /// The node's kept block records, latest change first; for other than
    /// system administrators only those of rules they can see.
    pub fn node_blocks(
        &self,
        actor: &Actor,
        node: &str,
        rule: Option<&str>,
        limit: usize,
    ) -> Result<BlocksView> {
        let conn = self.0.lock().unwrap();
        if let Some(rule) = rule {
            visible_rule(&conn, actor, node, rule)?;
        } else {
            require_node(&conn, actor, node, false)?;
        }
        let visible: Option<HashSet<String>> = (actor.role != Role::SystemAdmin).then(|| {
            reverse_tunnels::current_config(&conn, node)
                .ok()
                .flatten()
                .map(|config| {
                    config
                        .rules
                        .into_iter()
                        .filter(|r| actor.permits_tenant(&r.tenant_id))
                        .map(|r| r.id)
                        .collect()
                })
                .unwrap_or_default()
        });
        let supported = supported(&conn, node)?;
        drop(conn);
        let live = self.12.lock().unwrap();
        let blocks = live
            .blocks
            .get(node)
            .map(|kept| {
                kept.read(
                    |block| {
                        rule.is_none_or(|rule| block.rule_id == rule)
                            && visible
                                .as_ref()
                                .is_none_or(|ids| ids.contains(&block.rule_id))
                    },
                    limit.clamp(1, KEEP),
                )
            })
            .unwrap_or_default();
        Ok(BlocksView {
            supported,
            blocks: blocks.into_iter().map(BlockView::from).collect(),
        })
    }

    /// Drops a deleted node's snapshots, requests and records.
    pub(super) fn forget_connections(&self, node: &str) {
        let mut live = self.12.lock().unwrap();
        live.wake.remove(node);
        live.pending.remove(node);
        live.blocks.remove(node);
        live.snapshots.retain(|(id, _), _| id != node);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::connections::Cursor;

    #[test]
    fn requests_go_to_supporting_agents_only_and_answers_need_a_request() {
        let live = Mutex::new(Live::default());
        live.lock()
            .unwrap()
            .pending
            .insert("n".into(), vec![("a".into(), now_ms()), ("old".into(), 0)]);
        let reply = || SyncResponse {
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
        };
        let mut old = reply();
        answer(&live, "n", false, None, &mut old);
        assert!(old.live_connection_requests.is_empty() && old.block_cursor.is_none());
        let mut new = reply();
        answer(&live, "n", true, None, &mut new);
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
            blocks: None,
        };
        let mut next = reply();
        answer(&live, "n", true, Some(report), &mut next);
        let live = live.lock().unwrap();
        assert!(live.snapshots.contains_key(&("n".into(), "a".into())));
        assert!(!live.snapshots.contains_key(&("n".into(), "other".into())));
        assert!(next.live_connection_requests.is_empty());
    }

    #[test]
    fn an_unanswered_request_is_reported_once_and_then_asked_again() {
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
        let sync = || {
            let ledger = store
                .reconcile(
                    &node.id,
                    ReconcileRequest {
                        lease: None,
                        ledger_id: None,
                        after: None,
                        expected_revision: None,
                    },
                )
                .unwrap()
                .ledger_id;
            store
                .sync(
                    &node.id,
                    SyncRequest {
                        logs: None,
                        lease: None,
                        budget: None,
                        ledger_id: ledger,
                        need_config: false,
                        applied_revision: 0,
                        apply_error: None,
                        usage: vec![],
                        stats: EngineStats {
                            live_connections: Some(Report::default()),
                            ..EngineStats::default()
                        },
                    },
                )
                .unwrap()
        };
        sync();
        let state = || store.rule_connections(&admin, &node.id, "r").unwrap().state;
        assert_eq!(state(), "pending");
        assert_eq!(sync().live_connection_requests, ["r"]);
        // The agent never answers.
        store.12.lock().unwrap().pending.get_mut(&node.id).unwrap()[0].1 -= ANSWER_MS + 1;
        assert!(sync().live_connection_requests.is_empty(), "not sent again");
        assert_eq!(state(), "no_answer");
        assert_eq!(state(), "pending", "the next look asks again");
        assert_eq!(sync().live_connection_requests, ["r"]);
    }
}
