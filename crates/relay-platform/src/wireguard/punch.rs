//! NAT traversal ("hole punching") between node members that both lack a
//! public endpoint. The relay sees the address and port each one's NAT
//! presents; both get a peer entry for the other at that address with a
//! keepalive, so once each side has sent, each NAT lets the other's packets
//! in. The entry carries no traffic until a handshake on both sides shows
//! the hole is open, so a failed attempt costs nothing. Traffic moves off the
//! relay only then, and moves back when the direct path stops receiving.
//! Nothing is stored: a restarted controller rebuilds the state from the
//! agents' reports. Times are controller seconds; handshake times from
//! agents are compared only with earlier ones from the same agent, so clock
//! differences between servers do not matter.
use super::{InterfaceReport, Kind, Member, Network, Path, PeerReport, Punch, Report, path, relay};
use std::collections::{HashMap, HashSet};

/// A probe without a handshake on both sides by then has failed.
pub const PROBE_S: u64 = 45;
/// A direct path where either side received nothing for this long is dead;
/// keepalives arrive every 25 s.
pub const SILENT_S: u64 = 75;
/// The wait after the first failure; it doubles with each further one.
pub const RETRY_S: u64 = 300;
pub const MAX_RETRY_S: u64 = 3600;
/// An older report no longer describes the node.
const REPORT_S: u64 = 90;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Stage {
    /// Through the relay; the next probe waits for `retry_at`.
    Relayed,
    /// Through the relay while both sides try to reach each other.
    Probing,
    /// Directly through both NATs.
    Direct,
}

#[derive(Clone, Debug)]
pub struct Attempt {
    pub stage: Stage,
    pub since: u64,
    /// Each side's address and port as its NAT presents them.
    pub endpoints: [Option<String>; 2],
    pub retry_at: u64,
    pub failures: u32,
    /// Why the pair went back to the relay.
    pub reason: Option<String>,
    /// Probing: each side's handshake time with the other when the probe
    /// began. Direct: each side's received bytes and when they last grew.
    marks: [(u64, u64); 2],
}

/// Each side's entry for the other; `None` when that side has no current
/// report, `Some(None)` when its report has no such entry.
type Legs<'a> = [Option<Option<&'a PeerReport>>; 2];

fn received(legs: &Legs, now: u64) -> [(u64, u64); 2] {
    legs.map(|leg| (leg.flatten().map_or(0, |p| p.rx_bytes), now))
}

impl Attempt {
    /// A pair the controller has not followed yet. One that already has a
    /// working direct entry stays direct, so a controller restart does not
    /// move traffic (a dead one falls back after `SILENT_S`). Otherwise both
    /// sides must have reported, or the first node to sync after a restart
    /// could send its peer back to the relay.
    fn new(legs: &Legs, endpoints: [Option<&str>; 2], now: u64) -> Option<Self> {
        let open = legs
            .iter()
            .any(|leg| leg.flatten().is_some_and(|p| p.handshake > 0));
        if !open && !legs.iter().all(Option::is_some) {
            return None;
        }
        Some(Self {
            stage: if open { Stage::Direct } else { Stage::Relayed },
            since: now,
            endpoints: endpoints.map(|e| e.map(str::to_string)),
            retry_at: now,
            failures: 0,
            reason: None,
            marks: received(legs, now),
        })
    }

    /// Returns whether the stage changed. Only agents that can write a
    /// probe's entry (`able`) start one.
    fn step(&mut self, legs: &Legs, endpoints: [Option<&str>; 2], able: bool, now: u64) -> bool {
        let before = self.stage;
        match self.stage {
            Stage::Relayed => {
                if now >= self.retry_at
                    && able
                    && legs.iter().all(Option::is_some)
                    && endpoints.iter().all(Option::is_some)
                {
                    self.stage = Stage::Probing;
                    self.since = now;
                    self.endpoints = endpoints.map(|e| e.map(str::to_string));
                    self.marks = legs.map(|leg| (leg.flatten().map_or(0, |p| p.handshake), now));
                }
            }
            Stage::Probing => {
                let open = legs
                    .iter()
                    .zip(&self.marks)
                    .all(|(leg, (before, _))| leg.flatten().is_some_and(|p| p.handshake > *before));
                if open {
                    self.stage = Stage::Direct;
                    self.since = now;
                    self.failures = 0;
                    self.reason = None;
                    self.marks = received(legs, now);
                } else if now.saturating_sub(self.since) >= PROBE_S {
                    self.fail(
                        now,
                        format!("hole punching failed: no handshake within {PROBE_S} s"),
                    );
                }
            }
            Stage::Direct => {
                for (mark, leg) in self.marks.iter_mut().zip(legs) {
                    if let Some(peer) = leg.flatten()
                        && peer.rx_bytes != mark.0
                    {
                        *mark = (peer.rx_bytes, now);
                    }
                }
                if self
                    .marks
                    .iter()
                    .any(|(_, at)| now.saturating_sub(*at) >= SILENT_S)
                {
                    self.fail(
                        now,
                        format!("the direct path received nothing for {SILENT_S} s"),
                    );
                } else {
                    // A NAT that moved a node to another port: the relay sees
                    // the new one first.
                    for (mine, seen) in self.endpoints.iter_mut().zip(endpoints) {
                        if let Some(seen) = seen {
                            *mine = Some(seen.to_string());
                        }
                    }
                }
            }
        }
        self.stage != before
    }

    fn fail(&mut self, now: u64, reason: String) {
        self.failures += 1;
        let wait = RETRY_S
            .saturating_mul(1 << (self.failures - 1).min(8))
            .min(MAX_RETRY_S);
        self.stage = Stage::Relayed;
        self.since = now;
        self.retry_at = now + wait;
        self.reason = Some(reason);
    }
}

/// The controller's in-memory traversal state.
#[derive(Default)]
pub struct Traversal {
    /// Each member node's newest report and when it arrived.
    reports: HashMap<String, (Report, u64)>,
    /// By network and the two member ids in order.
    attempts: HashMap<(String, String, String), Attempt>,
    /// Nodes whose interfaces changed since their last sync or watch.
    woken: HashSet<String>,
    /// A stage changed since the last [`Self::take_changed`].
    changed: bool,
}

impl Traversal {
    pub fn observe(&mut self, node: &str, report: Option<&Report>, now: u64) {
        self.reports
            .retain(|_, (_, at)| now.saturating_sub(*at) <= REPORT_S);
        match report.filter(|r| !r.interfaces.is_empty()) {
            Some(report) => {
                self.reports.insert(node.to_string(), (report.clone(), now));
            }
            None => {
                self.reports.remove(node);
            }
        }
    }

    /// Advances every pair in `network` whose two nodes lack an endpoint and
    /// forgets the network's other pairs.
    pub fn step(
        &mut self,
        network: &Network,
        members: &[Member],
        keys: &HashMap<String, String>,
        now: u64,
    ) {
        let relay = relay(network, members);
        let reports = &self.reports;
        let report = |m: &Member| -> Option<&Report> {
            let (report, at) = reports.get(m.node_id.as_ref()?)?;
            (now.saturating_sub(*at) <= REPORT_S).then_some(report)
        };
        let interface = |m: &Member| -> Option<&InterfaceReport> {
            report(m)?
                .interfaces
                .iter()
                .find(|i| i.network_id == network.id && i.error.is_none())
        };
        let leg = |from: &Member, to: &Member| -> Option<Option<&PeerReport>> {
            let interface = interface(from)?;
            let key = to.node_id.as_ref().and_then(|n| keys.get(n));
            Some(key.and_then(|key| interface.peers.iter().find(|p| &p.public_key == key)))
        };
        // Where the relay last heard from `member`.
        let seen = |member: &Member| -> Option<&str> {
            leg(relay?, member)?
                .filter(|p| p.handshake > 0)?
                .endpoint
                .as_deref()
        };
        let mut live = HashSet::new();
        for (index, a) in members.iter().enumerate() {
            for b in &members[index + 1..] {
                if a.kind != Kind::Node
                    || b.kind != Kind::Node
                    || !matches!(path(a, b, relay), Path::Relayed(_))
                {
                    continue;
                }
                let (a, b) = if a.id < b.id { (a, b) } else { (b, a) };
                let id = (network.id.clone(), a.id.clone(), b.id.clone());
                let legs = [leg(a, b), leg(b, a)];
                let endpoints = [seen(a), seen(b)];
                let able = [a, b].iter().all(|m| report(m).is_some_and(|r| r.probes));
                let moved = match self.attempts.get_mut(&id) {
                    Some(attempt) => attempt.step(&legs, endpoints, able, now),
                    None => {
                        if let Some(attempt) = Attempt::new(&legs, endpoints, now) {
                            self.attempts.insert(id.clone(), attempt);
                        }
                        false
                    }
                };
                if moved {
                    self.changed = true;
                    self.woken.extend(a.node_id.clone());
                    self.woken.extend(b.node_id.clone());
                }
                live.insert(id);
            }
        }
        self.attempts
            .retain(|id, _| id.0 != network.id || live.contains(id));
    }

    /// Keeps only the attempts of networks `keep` accepts.
    pub fn retain(&mut self, keep: impl Fn(&str) -> bool) {
        self.attempts.retain(|id, _| keep(&id.0));
    }
    pub fn clear(&mut self) {
        self.attempts.clear();
        self.woken.clear();
    }

    /// The direct entries `member` should have in `network`, by the other
    /// member's id.
    pub fn punches(&self, network: &str, member: &str) -> HashMap<String, Punch> {
        self.attempts
            .iter()
            .filter(|((net, a, b), attempt)| {
                net == network && (a == member || b == member) && attempt.stage != Stage::Relayed
            })
            .map(|((_, a, b), attempt)| {
                let (other, side) = if a == member { (b, 1) } else { (a, 0) };
                (
                    other.clone(),
                    Punch {
                        endpoint: attempt.endpoints[side].clone(),
                        open: attempt.stage == Stage::Direct,
                    },
                )
            })
            .collect()
    }
    pub fn attempt(&self, network: &str, a: &str, b: &str) -> Option<&Attempt> {
        let (a, b) = if a < b { (a, b) } else { (b, a) };
        self.attempts
            .get(&(network.to_string(), a.to_string(), b.to_string()))
    }

    /// Whether `node` should sync at once because its interfaces changed;
    /// answers yes once.
    pub fn take_wake(&mut self, node: &str) -> bool {
        self.woken.remove(node)
    }
    pub fn take_changed(&mut self) -> bool {
        std::mem::take(&mut self.changed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::net::Ipv4Addr;

    fn member(id: &str, last: u8, endpoint: Option<&str>) -> Member {
        Member {
            id: id.into(),
            network_id: "net".into(),
            kind: Kind::Node,
            node_id: Some(format!("node-{id}")),
            name: String::new(),
            address: Ipv4Addr::new(10, 88, 0, last),
            endpoint: endpoint.map(str::to_string),
            listen_port: None,
            via: None,
            public_key: None,
            updated_at_ms: 0,
        }
    }
    fn network() -> Network {
        Network {
            id: "net".into(),
            name: "lab".into(),
            cidr: "10.88.0.0/24".parse().unwrap(),
            mtu: 1420,
            listen_port: 51820,
            relay: None,
            updated_at_ms: 0,
        }
    }
    /// The relay `p`, and `a` and `b` behind NATs.
    fn lab() -> (Network, Vec<Member>, HashMap<String, String>) {
        let members = vec![
            member("p", 1, Some("203.0.113.1:51820")),
            member("a", 2, None),
            member("b", 3, None),
        ];
        let keys = members
            .iter()
            .map(|m| (m.node_id.clone().unwrap(), format!("key-{}", m.id)))
            .collect();
        (network(), members, keys)
    }
    /// A report listing `peers` as `(member, endpoint, handshake, rx)`.
    fn report(peers: &[(&str, Option<&str>, u64, u64)]) -> Report {
        Report {
            ready: true,
            probes: true,
            interfaces: vec![InterfaceReport {
                network_id: "net".into(),
                name: "rwg-net".into(),
                error: None,
                peers: peers
                    .iter()
                    .map(|(id, endpoint, handshake, rx_bytes)| PeerReport {
                        public_key: format!("key-{id}"),
                        endpoint: endpoint.map(str::to_string),
                        handshake: *handshake,
                        rx_bytes: *rx_bytes,
                        tx_bytes: 0,
                    })
                    .collect(),
            }],
            ..Report::default()
        }
    }
    struct Lab {
        traversal: Traversal,
        network: Network,
        members: Vec<Member>,
        keys: HashMap<String, String>,
    }
    impl Lab {
        fn new() -> Self {
            let (network, members, keys) = lab();
            Self {
                traversal: Traversal::default(),
                network,
                members,
                keys,
            }
        }
        /// The relay hears `a` and `b` at their NAT addresses; `a` and `b`
        /// report their entries for each other (`None`: no entry).
        fn tick(&mut self, now: u64, a: Option<(u64, u64)>, b: Option<(u64, u64)>) -> Stage {
            let t = &mut self.traversal;
            t.observe(
                "node-p",
                Some(&report(&[
                    ("a", Some("198.51.100.2:40001"), 10, 1),
                    ("b", Some("198.51.100.3:40002"), 10, 1),
                ])),
                now,
            );
            let entry = |other: &'static str, seen: Option<(u64, u64)>| {
                let mut peers = vec![("p", Some("203.0.113.1:51820"), 10, 1)];
                peers.extend(seen.map(|(handshake, rx)| (other, None, handshake, rx)));
                report(&peers)
            };
            t.observe("node-a", Some(&entry("b", a)), now);
            t.observe("node-b", Some(&entry("a", b)), now);
            t.step(&self.network, &self.members, &self.keys, now);
            self.stage()
        }
        fn stage(&self) -> Stage {
            self.traversal.attempt("net", "a", "b").unwrap().stage
        }
    }

    #[test]
    fn a_probe_opens_the_hole_once_both_sides_handshake() {
        let mut lab = Lab::new();
        assert_eq!(lab.tick(1000, None, None), Stage::Relayed);
        assert!(lab.traversal.punches("net", "a").is_empty());
        assert_eq!(lab.tick(1005, None, None), Stage::Probing);
        assert!(lab.traversal.take_changed() && !lab.traversal.take_changed());
        assert!(lab.traversal.take_wake("node-b") && !lab.traversal.take_wake("node-b"));
        assert!(
            !lab.traversal.take_wake("node-p"),
            "the relay's entries stay"
        );
        // Each side gets an entry at the other's NAT address, without traffic.
        let a = lab.traversal.punches("net", "a");
        assert_eq!(
            a["b"],
            Punch {
                endpoint: Some("198.51.100.3:40002".into()),
                open: false
            }
        );
        assert_eq!(
            lab.traversal.punches("net", "b")["a"].endpoint.as_deref(),
            Some("198.51.100.2:40001")
        );
        assert!(lab.traversal.punches("net", "p").is_empty());
        // One side's handshake is not enough.
        assert_eq!(
            lab.tick(1010, Some((2000, 0)), Some((0, 0))),
            Stage::Probing
        );
        assert_eq!(
            lab.tick(1015, Some((2000, 92)), Some((2001, 92))),
            Stage::Direct
        );
        assert!(lab.traversal.punches("net", "a")["b"].open);
        // Keepalives keep it direct.
        for (now, rx) in [(1060, 184), (1105, 276), (1150, 368)] {
            assert_eq!(
                lab.tick(now, Some((2000, rx)), Some((2001, rx))),
                Stage::Direct
            );
        }
    }

    #[test]
    fn failed_probes_fall_back_with_a_reason_and_wait_longer_each_time() {
        let mut lab = Lab::new();
        lab.tick(1000, None, None);
        assert_eq!(lab.tick(1001, None, None), Stage::Probing);
        // Entries but no handshake: a NAT that changes the port per destination.
        assert_eq!(lab.tick(1045, Some((0, 0)), Some((0, 0))), Stage::Probing);
        assert_eq!(lab.tick(1046, Some((0, 0)), Some((0, 0))), Stage::Relayed);
        let attempt = lab.traversal.attempt("net", "b", "a").unwrap();
        assert_eq!((attempt.failures, attempt.retry_at), (1, 1046 + 300));
        assert!(
            attempt
                .reason
                .as_deref()
                .unwrap()
                .contains("hole punching failed")
        );
        assert!(lab.traversal.punches("net", "a").is_empty());
        assert_eq!(lab.tick(1345, None, None), Stage::Relayed);
        assert_eq!(lab.tick(1346, None, None), Stage::Probing);
        assert_eq!(lab.tick(1391, None, None), Stage::Relayed);
        assert_eq!(
            lab.traversal.attempt("net", "a", "b").unwrap().retry_at,
            1391 + 600
        );
        // The wait stops growing at an hour.
        let mut now = 1391;
        for _ in 0..6 {
            now = lab.traversal.attempt("net", "a", "b").unwrap().retry_at;
            assert_eq!(lab.tick(now, None, None), Stage::Probing);
            now += PROBE_S;
            assert_eq!(lab.tick(now, None, None), Stage::Relayed);
        }
        assert_eq!(
            lab.traversal.attempt("net", "a", "b").unwrap().retry_at,
            now + 3600
        );
    }

    #[test]
    fn a_direct_path_that_goes_silent_falls_back() {
        let mut lab = Lab::new();
        lab.tick(1000, None, None);
        lab.tick(1001, None, None);
        assert_eq!(
            lab.tick(1010, Some((2000, 92)), Some((2000, 92))),
            Stage::Direct
        );
        // `b` still hears `a`, but `a` stopped hearing `b`.
        assert_eq!(
            lab.tick(1050, Some((2000, 92)), Some((2000, 184))),
            Stage::Direct
        );
        assert_eq!(
            lab.tick(1084, Some((2000, 92)), Some((2000, 276))),
            Stage::Direct
        );
        assert_eq!(
            lab.tick(1085, Some((2000, 92)), Some((2000, 368))),
            Stage::Relayed
        );
        let attempt = lab.traversal.attempt("net", "a", "b").unwrap();
        assert_eq!((attempt.failures, attempt.retry_at), (1, 1085 + 300));
        assert!(
            attempt
                .reason
                .as_deref()
                .unwrap()
                .contains("received nothing")
        );
    }

    #[test]
    fn a_restarted_controller_keeps_working_direct_paths_and_waits_for_reports() {
        // `a` already has a direct entry with a handshake: no switch back.
        let mut lab = Lab::new();
        assert_eq!(
            lab.tick(1000, Some((900, 5000)), Some((900, 5000))),
            Stage::Direct
        );
        assert!(lab.traversal.punches("net", "b")["a"].open);
        assert!(!lab.traversal.take_changed());

        // After a restart the relay may report first: nothing is decided
        // yet, so the pair is not sent back to the relay.
        let mut lab = Lab::new();
        let relay_sees = |b_handshake| {
            report(&[
                ("a", Some("198.51.100.2:40001"), 10, 1),
                ("b", Some("198.51.100.3:40002"), b_handshake, 1),
            ])
        };
        let t = &mut lab.traversal;
        t.observe("node-p", Some(&relay_sees(10)), 1000);
        t.step(&lab.network, &lab.members, &lab.keys, 1000);
        assert!(t.attempt("net", "a", "b").is_none());
        // Nor with one side's report that shows no direct entry.
        t.observe("node-a", Some(&report(&[("p", None, 10, 1)])), 1001);
        t.step(&lab.network, &lab.members, &lab.keys, 1001);
        assert!(t.attempt("net", "a", "b").is_none());
        // No probe before the relay has heard both sides.
        t.observe("node-p", Some(&relay_sees(0)), 1010);
        t.observe("node-b", Some(&report(&[("p", None, 10, 1)])), 1010);
        t.step(&lab.network, &lab.members, &lab.keys, 1010);
        assert_eq!(lab.stage(), Stage::Relayed);
        lab.traversal.observe("node-p", Some(&relay_sees(0)), 1011);
        lab.traversal
            .step(&lab.network, &lab.members, &lab.keys, 1011);
        assert_eq!(lab.stage(), Stage::Relayed);
        assert_eq!(lab.tick(1011, None, None), Stage::Probing);
        lab.traversal
            .step(&lab.network, &lab.members, &lab.keys, 1056);
        assert_eq!(lab.stage(), Stage::Relayed);
        // The retry is due, but the reports are older than 90 s by then.
        lab.traversal
            .step(&lab.network, &lab.members, &lab.keys, 1356);
        assert_eq!(lab.stage(), Stage::Relayed);
        assert_eq!(lab.tick(1357, None, None), Stage::Probing);
    }

    #[test]
    fn agents_that_cannot_write_a_probe_entry_get_none() {
        let mut lab = Lab::new();
        lab.tick(1000, None, None);
        // `b` runs an agent before 0.139.0.
        let t = &mut lab.traversal;
        let old = Report {
            probes: false,
            ..report(&[("p", None, 10, 1)])
        };
        t.observe("node-b", Some(&old), 1005);
        t.step(&lab.network, &lab.members, &lab.keys, 1005);
        assert_eq!(lab.stage(), Stage::Relayed);
        assert!(!lab.traversal.take_changed());
    }

    #[test]
    fn only_pairs_without_endpoints_are_followed() {
        let mut lab = Lab::new();
        lab.tick(1000, None, None);
        assert!(lab.traversal.attempt("net", "a", "p").is_none());
        // `b` gets an endpoint: the pair is direct anyway and is forgotten.
        lab.members[2].endpoint = Some("203.0.113.3:51820".into());
        lab.traversal
            .step(&lab.network, &lab.members, &lab.keys, 1001);
        assert!(lab.traversal.attempt("net", "a", "b").is_none());
        lab.members[2].endpoint = None;
        lab.tick(1002, None, None);
        lab.traversal.retain(|id| id != "net");
        assert!(lab.traversal.attempt("net", "a", "b").is_none());
    }
}
