//! Splits a user's total speed limit between the nodes that carry the user's
//! rules. Each node gets a share on every sync and enforces it for [`LEASE`];
//! a node that cannot reach the controller drops to its fallback, an equal
//! split. A share only grows into room the other nodes do not hold, so the
//! shares in force never add up to more than the total once every node has
//! synced, even while they move toward the busy nodes.
use crate::model::UserRateReport;
use std::collections::HashMap;
use std::time::{Duration, Instant};

/// How long an agent keeps a share without hearing from the controller.
pub const LEASE: Duration = Duration::from_secs(15);
/// After this long without a sync, a node holds at most its fallback.
pub const GRACE: Duration = Duration::from_secs(20);
/// A node whose sends waited this fraction of the time wants more.
const SATURATED: f64 = 0.02;

/// One node's part of one user's limit, as the controller last saw it.
struct Seat {
    seen: Instant,
    granted: u64,
    enforced: Option<u64>,
    fallback: u64,
    bytes: u64,
    waited_ms: u64,
    measured: Instant,
    rate: Option<f64>,
    saturated: bool,
}
impl Seat {
    /// The most this node may be enforcing now.
    fn held(&self, now: Instant) -> u64 {
        let held = self.granted.max(self.enforced.unwrap_or(0));
        if now.duration_since(self.seen) > GRACE {
            held.min(self.fallback)
        } else {
            held
        }
    }
}

#[derive(Clone, Debug, serde::Serialize)]
pub struct SeatView {
    pub node_id: String,
    pub share_bytes_per_sec: u64,
    pub enforced_bytes_per_sec: Option<u64>,
    pub measured_bytes_per_sec: Option<u64>,
    pub saturated: bool,
    /// `None`: not synced since the controller started; its share is reserved.
    pub seen_ms_ago: Option<u64>,
}

pub struct Allocator {
    started: Instant,
    /// Owner id, then node id.
    users: HashMap<String, HashMap<String, Seat>>,
}
impl Default for Allocator {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            users: HashMap::new(),
        }
    }
}
impl Allocator {
    /// Returns `(share, fallback)` for `node`, one of `nodes`, which carry
    /// the rules of `owner`, whose combined limit is `total` bytes/second.
    pub fn share(
        &mut self,
        owner: &str,
        total: u64,
        nodes: &[String],
        node: &str,
        report: Option<&UserRateReport>,
        now: Instant,
    ) -> (u64, u64) {
        let count = nodes.len().max(1) as u64;
        let fallback = (total / count).max(1);
        let seats = self.users.entry(owner.to_owned()).or_default();
        seats.retain(|id, _| nodes.contains(id));
        let own = report.and_then(|r| r.enforced_bytes_per_sec).unwrap_or(0);
        match (seats.get_mut(node), report) {
            (Some(seat), Some(report)) => {
                seat.enforced = report.enforced_bytes_per_sec;
                let elapsed = now.duration_since(seat.measured).as_secs_f64();
                if report.bytes < seat.bytes || report.waited_ms < seat.waited_ms {
                    // The agent restarted; start measuring again.
                    seat.rate = None;
                    seat.saturated = false;
                    (seat.bytes, seat.waited_ms, seat.measured) =
                        (report.bytes, report.waited_ms, now);
                } else if elapsed >= 0.2 {
                    let rate = (report.bytes - seat.bytes) as f64 / elapsed;
                    let waited = (report.waited_ms - seat.waited_ms) as f64 / 1000.0;
                    // Rises are smoothed; a drop counts at once, so a node
                    // that goes quiet hands its room on within a sync.
                    seat.rate = Some(seat.rate.map_or(rate, |old| rate.min((old + rate) / 2.0)));
                    // Waits before its traffic stopped mid-interval do not
                    // make a node that used little of its share busy.
                    seat.saturated = waited / elapsed > SATURATED
                        && rate * 2.0 >= seat.enforced.unwrap_or(0) as f64;
                    (seat.bytes, seat.waited_ms, seat.measured) =
                        (report.bytes, report.waited_ms, now);
                }
            }
            (Some(seat), None) => {
                seat.enforced = None;
                seat.rate = None;
                seat.saturated = false;
            }
            (None, _) => {
                seats.insert(
                    node.to_owned(),
                    Seat {
                        seen: now,
                        granted: 0,
                        enforced: report.and_then(|r| r.enforced_bytes_per_sec),
                        fallback,
                        bytes: report.map_or(0, |r| r.bytes),
                        waited_ms: report.map_or(0, |r| r.waited_ms),
                        measured: now,
                        rate: None,
                        saturated: false,
                    },
                );
            }
        }
        let young = now.duration_since(self.started) < GRACE;
        let mut others = 0u64;
        let demands: Vec<f64> = nodes
            .iter()
            .map(|id| {
                let seat = seats.get(id);
                if id != node {
                    // A node not seen since the controller started may still
                    // enforce a share from before; after the grace period it
                    // holds at most an equal split.
                    others = others.saturating_add(match seat {
                        Some(seat) => seat.held(now),
                        None if young => total,
                        None => fallback,
                    });
                }
                match seat {
                    Some(seat) if seat.saturated => f64::INFINITY,
                    Some(Seat {
                        rate: Some(rate), ..
                    }) => (rate * 1.5).max(total as f64 / (8 * count) as f64),
                    _ => total as f64 / count as f64,
                }
            })
            .collect();
        let at = nodes.iter().position(|id| id == node).unwrap_or(0);
        let target = water_fill(total as f64, &demands)
            .get(at)
            .copied()
            .unwrap_or(total as f64) as u64;
        let free = total.saturating_sub(others);
        let share = target.min(free.max(own)).max(1);
        let seat = seats.get_mut(node).expect("inserted above");
        (seat.seen, seat.granted, seat.fallback) = (now, share, fallback);
        (share, fallback)
    }
    /// Forgets `node` for every user it no longer serves under a limit.
    pub fn retain_node(&mut self, node: &str, limited: &[&str]) {
        for (owner, seats) in &mut self.users {
            if !limited.contains(&owner.as_str()) {
                seats.remove(node);
            }
        }
        self.users.retain(|_, seats| !seats.is_empty());
    }
    /// What each of `nodes` holds of `owner`'s limit `total`, as [`Self::share`] counts it.
    pub fn view(&self, owner: &str, total: u64, nodes: &[String], now: Instant) -> Vec<SeatView> {
        let seats = self.users.get(owner);
        let fallback = (total / nodes.len().max(1) as u64).max(1);
        let young = now.duration_since(self.started) < GRACE;
        let mut views: Vec<SeatView> = nodes
            .iter()
            .map(|node| match seats.and_then(|s| s.get(node)) {
                Some(seat) => SeatView {
                    node_id: node.clone(),
                    share_bytes_per_sec: seat.held(now),
                    enforced_bytes_per_sec: seat.enforced,
                    measured_bytes_per_sec: seat.rate.map(|r| r as u64),
                    saturated: seat.saturated,
                    seen_ms_ago: Some(now.duration_since(seat.seen).as_millis() as u64),
                },
                None => SeatView {
                    node_id: node.clone(),
                    share_bytes_per_sec: if young { total } else { fallback },
                    enforced_bytes_per_sec: None,
                    measured_bytes_per_sec: None,
                    saturated: false,
                    seen_ms_ago: None,
                },
            })
            .collect();
        views.sort_by(|a, b| a.node_id.cmp(&b.node_id));
        views
    }
}

/// Gives each node what it asks for, smallest demand first, up to an equal
/// split of what is left; anything left over is split equally.
fn water_fill(total: f64, demands: &[f64]) -> Vec<f64> {
    let mut order: Vec<usize> = (0..demands.len()).collect();
    order.sort_by(|&a, &b| demands[a].total_cmp(&demands[b]));
    let mut left = total;
    let mut out = vec![0.0; demands.len()];
    for (done, &index) in order.iter().enumerate() {
        out[index] = demands[index].min(left / (demands.len() - done) as f64);
        left -= out[index];
    }
    for value in &mut out {
        *value += left / demands.len() as f64;
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;

    const TOTAL: u64 = 1_000_000;
    fn nodes() -> Vec<String> {
        vec!["a".into(), "b".into()]
    }
    fn report(bytes: u64, waited_ms: u64, enforced: u64) -> UserRateReport {
        UserRateReport {
            tenant_id: "t".into(),
            owner_id: "u".into(),
            bytes,
            waited_ms,
            enforced_bytes_per_sec: Some(enforced),
        }
    }
    /// Two agents that send as fast as their shares allow (or `idle` bytes/s
    /// when not busy) and apply each share from their next sync on.
    struct Run {
        allocator: Allocator,
        now: Instant,
        enforced: [u64; 2],
        bytes: [u64; 2],
        waited: [u64; 2],
    }
    impl Run {
        fn new(start: Instant) -> Self {
            Self {
                allocator: Allocator {
                    started: start,
                    users: HashMap::new(),
                },
                now: start,
                enforced: [0; 2],
                bytes: [0; 2],
                waited: [0; 2],
            }
        }
        /// One second passes, then both nodes sync. Returns the shares in force.
        fn second(&mut self, busy: [bool; 2]) -> [u64; 2] {
            self.now += Duration::from_secs(1);
            for i in 0..2 {
                if busy[i] {
                    self.bytes[i] += self.enforced[i];
                    self.waited[i] += 500;
                } else {
                    self.bytes[i] += TOTAL / 100;
                }
                let sent = report(self.bytes[i], self.waited[i], self.enforced[i]);
                let (share, _) = self.allocator.share(
                    "u",
                    TOTAL,
                    &nodes(),
                    ["a", "b"][i],
                    (self.enforced[i] > 0).then_some(&sent),
                    self.now,
                );
                self.enforced[i] = share;
            }
            self.enforced
        }
    }

    #[test]
    fn shares_follow_demand_without_exceeding_the_total() {
        let mut run = Run::new(Instant::now() - GRACE * 2);
        for _ in 0..5 {
            let shares = run.second([true, false]);
            assert!(shares.iter().sum::<u64>() <= TOTAL, "{shares:?}");
        }
        // The idle node keeps a small reserve; the busy one gets the rest.
        assert!(run.enforced[0] >= TOTAL * 9 / 10, "{:?}", run.enforced);
        for _ in 0..6 {
            let shares = run.second([true, true]);
            assert!(shares.iter().sum::<u64>() <= TOTAL, "{shares:?}");
        }
        for share in run.enforced {
            assert!(
                share.abs_diff(TOTAL / 2) <= TOTAL / 50,
                "{:?}",
                run.enforced
            );
        }
        // A node that goes quiet gives its room back within a few syncs.
        for _ in 0..3 {
            let shares = run.second([false, true]);
            assert!(shares.iter().sum::<u64>() <= TOTAL, "{shares:?}");
        }
        assert!(run.enforced[1] >= TOTAL * 9 / 10, "{:?}", run.enforced);
    }

    #[test]
    fn a_node_whose_traffic_stopped_mid_interval_is_not_busy() {
        let mut run = Run::new(Instant::now() - GRACE * 2);
        for _ in 0..6 {
            run.second([true, true]);
        }
        let busy = |run: &Run| run.allocator.view("u", TOTAL, &nodes(), run.now)[0].saturated;
        assert!(busy(&run));
        // "a" sent a quarter of its share, waiting until it stopped.
        run.now += Duration::from_secs(1);
        run.bytes[0] += run.enforced[0] / 4;
        run.waited[0] += 100;
        let sent = report(run.bytes[0], run.waited[0], run.enforced[0]);
        run.allocator
            .share("u", TOTAL, &nodes(), "a", Some(&sent), run.now);
        assert!(!busy(&run));
    }

    #[test]
    fn a_restarted_controller_waits_for_unseen_nodes_before_granting_their_room() {
        let start = Instant::now();
        let mut allocator = Allocator {
            started: start,
            users: HashMap::new(),
        };
        // "b" may still enforce a share given before the restart.
        let (share, fallback) = allocator.share("u", TOTAL, &nodes(), "a", None, start);
        assert_eq!((share, fallback), (1, TOTAL / 2));
        // Once every lease from before has expired, "b" holds at most its fallback.
        let later = start + GRACE + Duration::from_secs(1);
        let (share, _) = allocator.share("u", TOTAL, &nodes(), "a", None, later);
        assert_eq!(share, TOTAL / 2);
    }

    #[test]
    fn a_silent_node_counts_only_its_fallback_after_the_grace_period() {
        let mut run = Run::new(Instant::now() - GRACE * 2);
        for _ in 0..5 {
            run.second([false, true]);
        }
        assert!(run.enforced[1] >= TOTAL * 9 / 10, "{:?}", run.enforced);
        // "b" stops syncing; "a" becomes busy and must not take b's room
        // until b's lease is over.
        let mut busy = 0;
        for second in 1..=30 {
            run.now += Duration::from_secs(1);
            run.bytes[0] += run.enforced[0];
            run.waited[0] += 500;
            let sent = report(run.bytes[0], run.waited[0], run.enforced[0]);
            let (share, _) = run
                .allocator
                .share("u", TOTAL, &nodes(), "a", Some(&sent), run.now);
            run.enforced[0] = share;
            let b_holds = if Duration::from_secs(second) > GRACE {
                TOTAL / 2
            } else {
                run.enforced[1]
            };
            assert!(share + b_holds <= TOTAL, "second {second}: {share}");
            busy = share;
        }
        assert_eq!(busy, TOTAL / 2);
    }

    #[test]
    fn water_fill_gives_small_demands_in_full() {
        let out = water_fill(100.0, &[10.0, f64::INFINITY, 30.0]);
        assert_eq!(out, vec![10.0, 60.0, 30.0]);
        let out = water_fill(100.0, &[10.0, 20.0]);
        assert_eq!(out, vec![45.0, 55.0]);
    }
}
