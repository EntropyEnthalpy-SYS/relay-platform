mod common;
use common::*;
use relay_platform::{
    api::{self, AppState},
    chain::{
        AutoSyncInput, BuildInput, CancelInput, ChainInput, ChainPlan, ChainView, GroupInput,
        GroupView, Layer, RefreshInput, RefreshOutcome, RefreshPhase, RefreshPlan,
        RefreshPlanInput, RefreshStep, RefreshView, UseView,
    },
    lease::{LeasePolicy, LeaseProof, LeaseRelease, LeaseRequest},
    model::{
        Balance, EngineStats, NodeConfig, Protocol, RateLimitReport, RateLimits, ReconcileRequest,
        Rule, SyncRequest,
    },
    node::{ForwardingDefaults, NodeSettings, NodeUpdate},
    shared_rule::LineErrors,
    store::{Actor, Node, Rejection, Role, Scope, Store, UserRateChange},
};
use serde_json::{Value, json};
use std::{
    collections::{BTreeMap, BTreeSet},
    net::SocketAddr,
};
use tokio_util::sync::CancellationToken;

const TARGET: &str = "192.0.2.80:443";

struct Fixture {
    _temp: tempfile::TempDir,
    store: Store,
    admin: Actor,
    nodes: Vec<Node>,
    tokens: Vec<String>,
    /// Servers whose agents report as an older version; the others report
    /// as 0.150.0 agents.
    shapes: std::cell::RefCell<BTreeMap<usize, Shape>>,
    /// Servers created with an execution lease, and each one's agent
    /// credential and current lease once enrolled.
    leased: Vec<usize>,
    leases: std::cell::RefCell<BTreeMap<usize, (String, LeaseProof)>>,
}
/// Agent versions by what their sync requests carry.
#[derive(Clone, Copy, Debug)]
enum Shape {
    V0_141_9,
    V0_144_0,
    V0_150_0,
}
/// A sync request as an idle agent of `shape` sends it to this controller,
/// as JSON: the fields and skip rules of that version's `SyncRequest` and
/// `EngineStats` (`git show v0.141.9:crates/relay-platform/src/model.rs`),
/// with host statistics and WireGuard reported as that version does. 0.142.0
/// added paused targets and WireGuard's `preshared_keys`; 0.145.0 the reverse
/// tunnel report every later agent sends on each sync after its first; 0.147.0
/// to 0.150.0 the rate limit, speed test, live connection, egress proxy and
/// firewall reports.
fn sync_json(
    shape: Shape,
    ledger_id: &str,
    applied: u64,
    error: Option<&str>,
    active: u64,
) -> Value {
    let mut stats = json!({
        "system": {"cpu_percent": 3.5, "process_cpu_percent": 0.4, "rss_bytes": 18_874_368,
            "memory_total_bytes": 2_147_483_648u64, "memory_available_bytes": 1_610_612_736u64,
            "load_1m": 0.08, "cpus": 2},
        "wireguard": {"ready": true, "probes": true, "applied": "0"},
        "active_tcp": active, "active_udp": 0, "accepted_tcp": 12, "rejected_connections": 0,
        "failed_connections": 0, "dropped_datagrams": 0, "forwarded_upload_bytes": 4096,
        "forwarded_download_bytes": 8192,
    });
    match shape {
        Shape::V0_141_9 => {}
        Shape::V0_144_0 => stats["wireguard"]["preshared_keys"] = json!(true),
        Shape::V0_150_0 => {
            stats["wireguard"]["preshared_keys"] = json!(true);
            for (field, report) in [
                ("reverse_tunnel", json!({"managed": true})),
                ("rate_limits", json!({})),
                ("speed_test", json!({})),
                ("live_connections", json!({})),
                ("egress_proxy", json!({})),
                ("firewall", json!({})),
            ] {
                stats[field] = report;
            }
        }
    }
    json!({"budget": null, "ledger_id": ledger_id, "need_config": false,
        "applied_revision": applied, "apply_error": error, "usage": [], "stats": stats})
}
/// Server `index` forwards on 30000 + 100 × index and the next 49 ports at
/// srv<index>.example.net.
fn forwarding(index: usize, start: u16, end: u16) -> NodeSettings {
    NodeSettings {
        forwarding: Some(ForwardingDefaults {
            host: format!("srv{index}.example.net"),
            listen_ip: None,
            port_start: start,
            port_end: end,
            public_port_start: None,
        }),
        ..Default::default()
    }
}
fn base_port(index: usize) -> u16 {
    30000 + 100 * index as u16
}
impl Fixture {
    fn new(count: usize) -> Self {
        Self::with_leases(count, &[])
    }
    /// Servers `leased` need an execution lease, as `--lease` agents do.
    fn with_leases(count: usize, leased: &[usize]) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("controller.db")).unwrap();
        store.set_kind("controller").unwrap();
        let admin = store.bootstrap(PASSWORD).unwrap();
        let (nodes, tokens) = (0..count)
            .map(|index| {
                let port = base_port(index);
                store
                    .create_node_with_settings(
                        &admin,
                        "default",
                        &format!("srv-{index}"),
                        leased.contains(&index).then(LeasePolicy::default),
                        forwarding(index, port, port + 49),
                    )
                    .unwrap()
            })
            .unzip();
        Self {
            _temp: temp,
            store,
            admin,
            nodes,
            tokens,
            shapes: Default::default(),
            leased: leased.to_vec(),
            leases: Default::default(),
        }
    }
    /// Records for servers without agents what the controller keeps once an
    /// agent of 0.145.0 or later reported (`reverse_tunnel_node:<id>`), as
    /// for a server whose agent reported and was revoked: for tests that edit
    /// routes freely without agents.
    fn able_to_pause(&self, indexes: &[usize]) {
        for index in indexes {
            self.store
                .set_metadata(
                    &format!("reverse_tunnel_node:{}", self.id(*index)),
                    r#"{"fingerprint":null}"#,
                )
                .unwrap();
        }
    }
    /// From now on server `index`'s agent reports as `shape`.
    fn agent(&self, index: usize, shape: Shape) {
        self.shapes.borrow_mut().insert(index, shape);
    }
    /// Gives servers agents that have not reported yet; leased ones hold a
    /// lease.
    fn enroll(&self, indexes: &[usize]) {
        for index in indexes {
            let credential = relay_platform::store::secret();
            self.store
                .enroll(&self.id(*index), &self.tokens[*index], &credential)
                .unwrap();
            if self.leased.contains(index) {
                self.acquire(*index, credential);
            }
        }
    }
    fn acquire(&self, index: usize, credential: String) {
        let (run_id, token) = (
            relay_platform::store::secret(),
            relay_platform::store::secret(),
        );
        let generation = self
            .store
            .exchange_lease(
                &credential,
                LeaseRequest {
                    run_id: run_id.clone(),
                    token: token.clone(),
                    generation: None,
                    resume_generation: None,
                },
            )
            .unwrap()
            .generation
            .unwrap();
        let proof = LeaseProof {
            run_id,
            generation,
            token,
        };
        self.leases.borrow_mut().insert(index, (credential, proof));
    }
    /// Leased server `index`'s agent restarts under a new lease: it releases
    /// the old one and acquires another, which makes the controller reset
    /// what the server applied to 0 until the new process reports.
    fn new_lease(&self, index: usize) {
        let (credential, proof) = self.leases.borrow_mut().remove(&index).unwrap();
        self.store
            .release_lease(
                &credential,
                LeaseRelease {
                    proof,
                    stats: EngineStats::default(),
                },
            )
            .unwrap();
        self.acquire(index, credential);
    }
    /// One report of server `index`'s agent: it applied `applied` (its
    /// desired revision by default) or failed with `error`, and has `active`
    /// TCP sessions.
    fn report_as(
        &self,
        index: usize,
        applied: Option<u64>,
        error: Option<&str>,
        active: u64,
        rate_limits: bool,
    ) {
        let node = self.id(index);
        let lease = self.leases.borrow().get(&index).map(|(_, p)| p.clone());
        let ledger_id = self
            .store
            .reconcile(
                &node,
                ReconcileRequest {
                    lease: lease.clone(),
                    ledger_id: None,
                    after: None,
                    expected_revision: None,
                },
            )
            .unwrap()
            .ledger_id;
        let applied = applied.unwrap_or_else(|| self.config(index).revision);
        // As a 0.150.0 agent after its first sync: with the reverse tunnel
        // report, and rate limits only where a test asks for them.
        let mut request: SyncRequest = match self.shapes.borrow().get(&index) {
            Some(shape) => {
                serde_json::from_value(sync_json(*shape, &ledger_id, applied, error, active))
                    .unwrap()
            }
            None => SyncRequest {
                logs: None,
                lease: None,
                budget: None,
                ledger_id,
                need_config: false,
                applied_revision: applied,
                apply_error: error.map(str::to_owned),
                usage: vec![],
                stats: EngineStats {
                    active_tcp: active,
                    rate_limits: rate_limits.then(RateLimitReport::default),
                    reverse_tunnel: Some(relay_platform::reverse_tunnel::Report {
                        managed: true,
                        ..Default::default()
                    }),
                    ..Default::default()
                },
            },
        };
        request.lease = lease;
        self.store.sync(&node, request).unwrap();
    }
    fn report(&self, index: usize, active: u64) {
        self.report_as(index, None, None, active, false);
    }
    fn report_all(&self) {
        for index in 0..self.nodes.len() {
            self.report(index, 0);
        }
    }
    fn advance(&self) {
        self.store.advance_chain_refreshes().unwrap();
    }
    fn use_of(&self, chain: &str) -> UseView {
        self.view(chain).uses.remove(0)
    }
    fn refresh(&self, chain: &str) -> RefreshView {
        self.use_of(chain).refresh.unwrap()
    }
    fn plan_refresh(&self, chain: &str, entry: &str) -> RefreshPlan {
        self.store
            .plan_chain_refresh(&self.admin, chain, entry, RefreshPlanInput::default())
            .unwrap()
    }
    fn confirm(&self, chain: &str, entry: &str, plan: &RefreshPlan) -> anyhow::Result<RefreshView> {
        self.store.refresh_chain_use(
            &self.admin,
            chain,
            entry,
            RefreshInput {
                token: plan.token.clone(),
                expected_revisions: plan.expected_revisions.clone(),
                timeout_secs: Some(plan.timeout_secs),
            },
        )
    }
    fn set_members(&self, group: &GroupView, members: &[usize]) {
        self.store
            .update_endpoint_group(
                &self.admin,
                &group.id,
                group_input(&group.name, self.ids(members)),
            )
            .unwrap();
    }
    /// Changes rule `id` on server `index` in place.
    fn edit_rule(&self, index: usize, id: &str, change: impl FnOnce(&mut Rule)) {
        let config = self.config(index);
        let mut rules = config.rules;
        change(rules.iter_mut().find(|rule| rule.id == id).unwrap());
        self.store
            .set_config(&self.admin, &self.id(index), config.revision, rules)
            .unwrap();
    }
    fn id(&self, index: usize) -> String {
        self.nodes[index].id.clone()
    }
    fn ids(&self, indexes: &[usize]) -> Vec<String> {
        indexes.iter().map(|index| self.id(*index)).collect()
    }
    fn index(&self, node: &str) -> usize {
        self.nodes.iter().position(|n| n.id == node).unwrap()
    }
    fn config(&self, index: usize) -> NodeConfig {
        self.store
            .config(&self.admin, &self.id(index), None)
            .unwrap()
    }
    fn revisions(&self) -> Vec<u64> {
        (0..self.nodes.len())
            .map(|index| self.config(index).revision)
            .collect()
    }
    fn rule(&self, index: usize, id: &str) -> Rule {
        self.config(index)
            .rules
            .into_iter()
            .find(|rule| rule.id == id)
            .unwrap()
    }
    /// Changes a server's forwarding port range.
    fn ports(&self, index: usize, start: u16, end: u16) {
        let node = self
            .store
            .nodes(&self.admin)
            .unwrap()
            .into_iter()
            .find(|node| node.id == self.id(index))
            .unwrap();
        self.store
            .update_node(
                &self.admin,
                &node.id,
                NodeUpdate {
                    expected_revision: node.profile.revision,
                    name: node.name,
                    settings: forwarding(index, start, end),
                },
            )
            .unwrap();
    }
    /// Adds an ordinary rule listening on `port`.
    fn occupy(&self, index: usize, id: &str, port: u16) {
        let config = self.config(index);
        let mut rule = rule("192.0.2.50:80".parse().unwrap(), Protocol::Tcp);
        rule.id = id.into();
        rule.meter_epoch = format!("{id}-epoch");
        rule.owner_id = self.admin.id.clone();
        rule.listen = SocketAddr::from(([0, 0, 0, 0], port));
        let mut rules = config.rules;
        rules.push(rule);
        self.store
            .set_config(&self.admin, &self.id(index), config.revision, rules)
            .unwrap();
    }
    fn group(&self, name: &str, members: &[usize]) -> GroupView {
        self.store
            .create_endpoint_group(&self.admin, group_input(name, self.ids(members)))
            .unwrap()
    }
    fn chain(&self, name: &str, layers: &[(&GroupView, Balance)]) -> ChainView {
        self.store
            .create_chain(&self.admin, chain_input(name, true, layers))
            .unwrap()
    }
    fn input(&self, entry: usize) -> BuildInput {
        BuildInput {
            entry_node_id: self.id(entry),
            name: "Web".into(),
            protocol: Protocol::Tcp,
            target: TARGET.into(),
            entry_port: None,
            owner_id: None,
            expected_revisions: None,
        }
    }
    fn view(&self, id: &str) -> ChainView {
        self.store
            .chains(&self.admin)
            .unwrap()
            .into_iter()
            .find(|view| view.id == id)
            .unwrap()
    }
    fn audits(&self, action: &str) -> usize {
        self.store
            .audit_log(&self.admin)
            .unwrap()
            .iter()
            .filter(|entry| entry["action"] == action)
            .count()
    }
    /// Each audited step of refresh `id` with who it ran as, oldest first.
    fn steps(&self, id: &str) -> Vec<(String, String)> {
        let mut steps: Vec<(String, String)> = self
            .store
            .audit_log(&self.admin)
            .unwrap()
            .iter()
            .filter(|entry| entry["action"] == "forwarding_chain.refresh")
            .filter_map(|entry| {
                let detail: Value = serde_json::from_str(entry["detail"].as_str()?).ok()?;
                (detail["refresh_id"] == id).then(|| {
                    (
                        detail["step"].as_str().unwrap().to_owned(),
                        entry["actor_id"].as_str().unwrap().to_owned(),
                    )
                })
            })
            .collect();
        steps.reverse();
        steps
    }
    fn step_names(&self, id: &str) -> Vec<String> {
        self.steps(id).into_iter().map(|(step, _)| step).collect()
    }
    fn at(&self, now: i64) {
        self.store.advance_chain_refreshes_at(now).unwrap();
    }
    fn cancel(&self, chain: &str, entry: &str, keep_stopped: bool) -> anyhow::Result<RefreshView> {
        self.store
            .cancel_chain_refresh(&self.admin, chain, entry, CancelInput { keep_stopped })
    }
    /// The same database opened by a new controller process.
    fn restart(self) -> Self {
        let Fixture {
            _temp,
            store,
            admin,
            nodes,
            tokens,
            shapes,
            leased,
            leases,
        } = self;
        drop(store);
        let store = Store::open(&_temp.path().join("controller.db")).unwrap();
        Fixture {
            _temp,
            store,
            admin,
            nodes,
            tokens,
            shapes,
            leased,
            leases,
        }
    }
    fn use_by(&self, chain: &str, entry: &str) -> UseView {
        self.view(chain)
            .uses
            .into_iter()
            .find(|u| u.entry_rule_id == entry)
            .unwrap()
    }
    fn auto_sync(&self, actor: &Actor, chain: &str, entry: &str) {
        self.store
            .set_chain_auto_sync(
                actor,
                chain,
                entry,
                AutoSyncInput {
                    auto_sync: true,
                    timeout_secs: None,
                },
            )
            .unwrap();
    }
}
fn sorted(mut values: Vec<String>) -> Vec<String> {
    values.sort();
    values
}
fn group_input(name: &str, members: Vec<String>) -> GroupInput {
    GroupInput {
        name: name.into(),
        description: String::new(),
        members,
    }
}
fn chain_input(name: &str, enabled: bool, layers: &[(&GroupView, Balance)]) -> ChainInput {
    ChainInput {
        name: name.into(),
        enabled,
        layers: layers
            .iter()
            .map(|(group, balance)| Layer {
                group_id: group.id.clone(),
                balance: *balance,
            })
            .collect(),
    }
}
fn status(error: anyhow::Error) -> u16 {
    error.downcast_ref::<Rejection>().unwrap().status
}
fn failed_nodes(error: &anyhow::Error) -> Vec<String> {
    error
        .downcast_ref::<LineErrors>()
        .unwrap()
        .0
        .iter()
        .map(|line| line.node_id.clone())
        .collect()
}
fn new_rule<'a>(plan: &'a ChainPlan, node: &str, rule_id: &str) -> &'a Rule {
    plan.batch
        .updates
        .iter()
        .find(|update| update.node_id == node)
        .unwrap()
        .rules
        .iter()
        .find(|rule| rule.id == rule_id)
        .unwrap()
}

/// Entry 0; layer 1 is servers [2, 1] by source hash, layer 2 is servers
/// [5, 3, 4] by least connections; server 6 is outside the chain. Server 3
/// already uses the first port of its range.
fn asymmetric() -> (Fixture, ChainView, GroupView, GroupView) {
    let f = Fixture::new(7);
    f.occupy(3, "existing", base_port(3));
    let first = f.group("Relays", &[2, 1]);
    let second = f.group("Exits", &[5, 3, 4]);
    let chain = f.chain(
        "Asia",
        &[
            (&first, Balance::SourceHash),
            (&second, Balance::LeastConnections),
        ],
    );
    (f, chain, first, second)
}

#[test]
fn plan_builds_every_layer_towards_every_server_of_the_next_layer() {
    let (f, chain, _, _) = asymmetric();
    let before = f.revisions();
    let publishes = f.audits("config.publish");
    let mut input = f.input(0);
    input.entry_port = Some(base_port(0) + 7);
    let plan = f.store.plan_chain(&f.admin, &chain.id, input).unwrap();

    // One rule per server, in path order: entry, layer 1, layer 2, each layer
    // in the order of its group.
    let order: Vec<(usize, usize)> = plan
        .hops
        .iter()
        .map(|hop| (hop.layer, f.index(&hop.node_id)))
        .collect();
    assert_eq!(order, [(0, 0), (1, 2), (1, 1), (2, 5), (2, 3), (2, 4)]);
    let nodes: Vec<usize> = plan
        .batch
        .updates
        .iter()
        .map(|update| f.index(&update.node_id))
        .collect();
    assert_eq!(nodes, [0, 2, 1, 5, 3, 4]);
    let hop = |index: usize| plan.hops.iter().find(|h| h.node_id == f.id(index)).unwrap();
    let ids: std::collections::HashSet<_> = plan.hops.iter().map(|h| &h.rule_id).collect();
    assert_eq!(ids.len(), 6, "every server gets its own rule");
    assert_eq!(plan.entry_rule_id, hop(0).rule_id);

    // Endpoints come from each server's forwarding defaults; server 3 skips
    // its taken first port; the entry uses the requested port.
    assert_eq!(hop(0).listen.to_string(), "0.0.0.0:30007");
    assert_eq!(hop(0).advertise, "srv0.example.net:30007");
    assert_eq!(hop(3).listen.port(), base_port(3) + 1);
    assert_eq!(
        hop(5).advertise,
        format!("srv5.example.net:{}", base_port(5))
    );

    let entry = new_rule(&plan, &f.id(0), &hop(0).rule_id);
    assert_eq!(entry.name, "Web · 1");
    assert_eq!(entry.balance, Balance::SourceHash, "layer 1's balance");
    let targets: Vec<(usize, String, String)> = entry
        .targets
        .iter()
        .map(|t| {
            let via = t.via.as_ref().unwrap();
            (
                f.index(&via.node_id),
                via.rule_id.clone(),
                t.address.clone(),
            )
        })
        .collect();
    assert_eq!(
        targets,
        [2, 1].map(|i| (i, hop(i).rule_id.clone(), hop(i).advertise.clone()))
    );
    for relay in [2, 1] {
        let rule = new_rule(&plan, &f.id(relay), &hop(relay).rule_id);
        assert_eq!(rule.name, "Web · 2");
        assert_eq!(rule.balance, Balance::LeastConnections, "layer 2's balance");
        assert_eq!(
            rule.advertise.as_deref(),
            Some(hop(relay).advertise.as_str())
        );
        let targets: Vec<(usize, String, String)> = rule
            .targets
            .iter()
            .map(|t| {
                let via = t.via.as_ref().unwrap();
                (
                    f.index(&via.node_id),
                    via.rule_id.clone(),
                    t.address.clone(),
                )
            })
            .collect();
        assert_eq!(
            targets,
            [5, 3, 4].map(|i| (i, hop(i).rule_id.clone(), hop(i).advertise.clone()))
        );
    }
    for exit in [5, 3, 4] {
        let rule = new_rule(&plan, &f.id(exit), &hop(exit).rule_id);
        assert_eq!(rule.name, "Web · 3");
        assert_eq!(rule.targets.len(), 1);
        assert_eq!(rule.targets[0].address, TARGET);
        assert!(rule.targets[0].via.is_none());
        assert_eq!(rule.balance, Balance::WeightedRoundRobin);
    }
    for update in &plan.batch.updates {
        let rule = update.rules.last().unwrap();
        assert_eq!(
            (rule.protocol, rule.enabled, rule.owner_id.as_str()),
            (Protocol::Tcp, true, f.admin.id.as_str())
        );
        assert!(rule.health_check.is_none() && rule.inbound_websocket.is_none());
    }
    // Existing rules stay; the preview adds exactly one rule per server.
    let server3 = plan
        .batch
        .updates
        .iter()
        .find(|u| u.node_id == f.id(3))
        .unwrap();
    assert_eq!(server3.rules[0].id, "existing");
    assert_eq!(plan.preview.changes.len(), 6);
    assert!(
        plan.preview
            .changes
            .iter()
            .all(|change| change.added.len() == 1
                && change.modified.is_empty()
                && change.removed.is_empty())
    );

    // Planning writes nothing.
    assert_eq!(f.revisions(), before);
    assert_eq!(f.audits("config.publish"), publishes);
    assert!(f.view(&chain.id).uses.is_empty());
}

#[test]
fn apply_publishes_every_server_in_one_batch_and_records_the_use() {
    let (f, chain, _, _) = asymmetric();
    let before = f.revisions();
    let batches = f.audits("config.batch_publish");
    let applied = f
        .store
        .apply_chain(&f.admin, &chain.id, f.input(0))
        .unwrap();
    let after = f.revisions();
    let bumped: Vec<u64> = before.iter().map(|revision| revision + 1).collect();
    assert_eq!(after[..6], bumped[..6], "every server of the forwarding");
    assert_eq!(
        after[6], before[6],
        "a server outside the chain is untouched"
    );
    assert_eq!(f.audits("config.batch_publish"), batches + 1, "one batch");
    assert_eq!(f.audits("forwarding_chain.apply"), 1);
    assert_eq!(applied.published.configs.len(), 6);

    // The published graph has 2 entry edges and 2 × 3 relay edges.
    let topology = f.store.topology(&f.admin).unwrap();
    assert_eq!(topology["graph"]["edges"].as_array().unwrap().len(), 8);
    let entry = f.rule(0, &applied.entry_rule_id);
    assert_eq!(entry.balance, Balance::SourceHash);
    for target in &entry.targets {
        let via = target.via.as_ref().unwrap();
        let relay = f.rule(f.index(&via.node_id), &via.rule_id);
        assert_eq!(relay.advertise.as_deref(), Some(target.address.as_str()));
        assert_eq!(relay.targets.len(), 3);
    }

    let view = f.view(&chain.id);
    assert_eq!(view.uses.len(), 1);
    let used = &view.uses[0];
    assert_eq!(used.entry_rule_id, applied.entry_rule_id);
    assert_eq!(used.name.as_deref(), Some("Web · 1"));
    assert!(!used.out_of_date && !used.missing && used.changes.is_empty());
    let layers: Vec<Vec<usize>> = used
        .layers
        .iter()
        .map(|hops| hops.iter().map(|hop| f.index(&hop.node_id)).collect())
        .collect();
    assert_eq!(layers, [vec![2, 1], vec![5, 3, 4]]);
    assert!(used.layers.iter().flatten().all(|hop| !hop.missing));

    // A second forwarding from the same chain gets the next free ports.
    let again = f
        .store
        .apply_chain(&f.admin, &chain.id, f.input(6))
        .unwrap();
    let exit = again
        .hops
        .iter()
        .find(|hop| hop.node_id == f.id(5))
        .unwrap();
    assert_eq!(exit.listen.port(), base_port(5) + 1);
    assert_eq!(f.view(&chain.id).uses.len(), 2);

    // Deleting the chain forgets the uses and keeps every rule.
    let rules: Vec<usize> = (0..7).map(|index| f.config(index).rules.len()).collect();
    f.store.delete_chain(&f.admin, &chain.id).unwrap();
    assert!(f.store.chains(&f.admin).unwrap().is_empty());
    assert_eq!(
        (0..7)
            .map(|index| f.config(index).rules.len())
            .collect::<Vec<_>>(),
        rules
    );
    assert_eq!(f.audits("forwarding_chain.delete"), 1);
}

#[test]
fn a_failure_on_one_server_publishes_nothing() {
    let (f, chain, _, _) = asymmetric();
    let check_unchanged = |before: &[u64]| {
        assert_eq!(f.revisions(), before);
        assert!(f.view(&chain.id).uses.is_empty());
        assert_eq!(f.audits("forwarding_chain.apply"), 0);
    };

    // The requested entry port is taken on the entry server.
    f.occupy(0, "busy-entry", base_port(0) + 7);
    let before = f.revisions();
    let mut input = f.input(0);
    input.entry_port = Some(base_port(0) + 7);
    let error = f.store.apply_chain(&f.admin, &chain.id, input).unwrap_err();
    assert_eq!(failed_nodes(&error), [f.id(0)]);
    assert_eq!(status(error), 409);
    check_unchanged(&before);

    // Server 4, the last exit, has no free port left.
    f.ports(4, 31000, 31000);
    f.occupy(4, "busy-exit", 31000);
    let before = f.revisions();
    let error = f
        .store
        .apply_chain(&f.admin, &chain.id, f.input(0))
        .unwrap_err();
    assert_eq!(failed_nodes(&error), [f.id(4)]);
    assert_eq!(status(error), 409);
    check_unchanged(&before);
    f.ports(4, base_port(4), base_port(4) + 49);

    // Server 3 changes after the plan: applying that plan is refused.
    let plan = f.store.plan_chain(&f.admin, &chain.id, f.input(0)).unwrap();
    let expected: BTreeMap<String, u64> = plan
        .batch
        .updates
        .iter()
        .map(|update| (update.node_id.clone(), update.expected_revision))
        .collect();
    f.occupy(3, "late", base_port(3) + 40);
    let before = f.revisions();
    let mut input = f.input(0);
    input.expected_revisions = Some(expected);
    let error = f.store.apply_chain(&f.admin, &chain.id, input).unwrap_err();
    assert_eq!(failed_nodes(&error), [f.id(3)]);
    assert_eq!(status(error), 409);
    check_unchanged(&before);

    // A fresh plan applies.
    let plan = f.store.plan_chain(&f.admin, &chain.id, f.input(0)).unwrap();
    let mut input = f.input(0);
    input.expected_revisions = Some(
        plan.batch
            .updates
            .iter()
            .map(|update| (update.node_id.clone(), update.expected_revision))
            .collect(),
    );
    let applied = f.store.apply_chain(&f.admin, &chain.id, input).unwrap();
    assert_eq!(applied.hops.len(), 6);
    assert_eq!(f.view(&chain.id).uses.len(), 1);
}

#[test]
fn chains_groups_and_entries_are_validated() {
    let f = Fixture::new(10);
    let groups: Vec<GroupView> = (1..=7)
        .map(|index| f.group(&format!("g{index}"), &[index]))
        .collect();
    let layers = |count: usize| -> Vec<(&GroupView, Balance)> {
        groups[..count]
            .iter()
            .map(|g| (g, Balance::WeightedRoundRobin))
            .collect()
    };
    let create = |input: ChainInput| f.store.create_chain(&f.admin, input);
    assert_eq!(
        status(create(chain_input("x", true, &layers(7))).unwrap_err()),
        400
    );
    assert_eq!(
        status(create(chain_input("x", true, &[])).unwrap_err()),
        400
    );
    let six = create(chain_input("six", true, &layers(6))).unwrap();
    assert_eq!(six.layers.len(), 6);
    let twice = [
        (&groups[0], Balance::WeightedRoundRobin),
        (&groups[0], Balance::Random),
    ];
    assert_eq!(
        status(create(chain_input("x", true, &twice)).unwrap_err()),
        400
    );
    // Server 2 in two layers through two different groups.
    let left = f.group("left", &[1, 2]);
    let right = f.group("right", &[2, 3]);
    let overlapping = [
        (&left, Balance::WeightedRoundRobin),
        (&right, Balance::WeightedRoundRobin),
    ];
    assert_eq!(
        status(create(chain_input("x", true, &overlapping)).unwrap_err()),
        400
    );
    // Groups need 1..32 distinct servers and a name.
    for (name, members) in [
        ("empty", vec![]),
        ("twice", f.ids(&[1, 1])),
        (" ", f.ids(&[1])),
    ] {
        let error = f
            .store
            .create_endpoint_group(&f.admin, group_input(name, members))
            .unwrap_err();
        assert_eq!(status(error), 400, "{name}");
    }

    // A server already in the chain cannot be its entry.
    let pair = f.chain(
        "pair",
        &[
            (&groups[0], Balance::WeightedRoundRobin),
            (&groups[1], Balance::WeightedRoundRobin),
        ],
    );
    let inside = f
        .store
        .plan_chain(&f.admin, &pair.id, f.input(2))
        .unwrap_err();
    assert!(
        inside.to_string().contains("entry server is in layer 2"),
        "{inside}"
    );
    assert_eq!(status(inside), 400);
    assert!(f.store.plan_chain(&f.admin, &pair.id, f.input(0)).is_ok());
    // Unsupported or invalid forwarding inputs.
    let mut bad = f.input(0);
    bad.target = "not a target".into();
    assert_eq!(
        status(f.store.plan_chain(&f.admin, &pair.id, bad).unwrap_err()),
        400
    );
    let mut bad = f.input(0);
    bad.name = " ".into();
    assert_eq!(
        status(f.store.plan_chain(&f.admin, &pair.id, bad).unwrap_err()),
        400
    );

    // A group change that puts a server in two layers of a chain is refused.
    let error = f
        .store
        .update_endpoint_group(&f.admin, &groups[0].id, group_input("g1", f.ids(&[1, 2])))
        .unwrap_err();
    assert_eq!(status(error), 409);
    // A group a chain uses cannot be deleted until the chain is gone.
    assert_eq!(
        status(
            f.store
                .delete_endpoint_group(&f.admin, &groups[1].id)
                .unwrap_err()
        ),
        409
    );
    f.store.delete_chain(&f.admin, &pair.id).unwrap();
    f.store.delete_chain(&f.admin, &six.id).unwrap();
    f.store
        .delete_endpoint_group(&f.admin, &groups[1].id)
        .unwrap();
    assert_eq!(f.audits("endpoint_group.delete"), 1);

    // A disabled chain builds nothing until it is enabled again.
    let off = f
        .store
        .create_chain(
            &f.admin,
            chain_input("off", false, &[(&groups[2], Balance::Random)]),
        )
        .unwrap();
    assert!(!off.enabled);
    assert_eq!(
        status(
            f.store
                .plan_chain(&f.admin, &off.id, f.input(0))
                .unwrap_err()
        ),
        409
    );
    assert_eq!(
        status(
            f.store
                .apply_chain(&f.admin, &off.id, f.input(0))
                .unwrap_err()
        ),
        409
    );
    f.store
        .update_chain(
            &f.admin,
            &off.id,
            chain_input("off", true, &[(&groups[2], Balance::Random)]),
        )
        .unwrap();
    let plan = f.store.plan_chain(&f.admin, &off.id, f.input(0)).unwrap();
    assert_eq!(plan.batch.updates[0].rules[0].balance, Balance::Random);

    // Lowest latency needs a probe: TCP gets a connect probe, UDP is refused.
    let fast = f.chain("fast", &[(&groups[3], Balance::LowestLatency)]);
    let mut both = f.input(0);
    both.protocol = Protocol::Both;
    assert_eq!(
        status(f.store.plan_chain(&f.admin, &fast.id, both).unwrap_err()),
        400
    );
    let plan = f.store.plan_chain(&f.admin, &fast.id, f.input(0)).unwrap();
    let entry = &plan.batch.updates[0].rules[0];
    assert_eq!(entry.balance, Balance::LowestLatency);
    assert_eq!(
        serde_json::to_value(&entry.health_check).unwrap()["tcp"],
        json!({"kind": "connect"})
    );
    assert!(plan.batch.updates[1].rules[0].health_check.is_none());

    // Groups and chains stay inside one tenant.
    let tenant = f.store.create_tenant(&f.admin, "isolated").unwrap();
    let (foreign, _) = f
        .store
        .create_node_with_settings(
            &f.admin,
            &tenant,
            "foreign",
            None,
            forwarding(9, 39000, 39049),
        )
        .unwrap();
    let mixed = f.store.create_endpoint_group(
        &f.admin,
        group_input("mixed", vec![f.id(1), foreign.id.clone()]),
    );
    assert_eq!(status(mixed.unwrap_err()), 400);
    let theirs = f
        .store
        .create_endpoint_group(&f.admin, group_input("theirs", vec![foreign.id.clone()]))
        .unwrap();
    assert_eq!(theirs.tenant_id, tenant);
    let across = [
        (&groups[4], Balance::WeightedRoundRobin),
        (&theirs, Balance::WeightedRoundRobin),
    ];
    assert_eq!(
        status(create(chain_input("x", true, &across)).unwrap_err()),
        400
    );
    let outsider = f
        .store
        .create_user(&f.admin, &tenant, "outsider", PASSWORD, Role::TenantAdmin)
        .unwrap();
    let borrowed = f
        .store
        .create_chain(
            &outsider,
            chain_input("x", true, &[(&groups[4], Balance::WeightedRoundRobin)]),
        )
        .unwrap_err();
    assert_eq!(status(borrowed), 404, "another tenant's group is invisible");
    let mut abroad = f.input(0);
    abroad.entry_node_id = foreign.id.clone();
    assert_eq!(
        status(f.store.plan_chain(&f.admin, &fast.id, abroad).unwrap_err()),
        400
    );

    // Deleting a member server is not blocked by its group, which then shows
    // it as missing; building from that group is refused.
    f.store.delete_node(&f.admin, &f.id(7)).unwrap();
    let group = f
        .store
        .endpoint_groups(&f.admin)
        .unwrap()
        .into_iter()
        .find(|g| g.id == groups[6].id)
        .unwrap();
    assert!(group.members[0].missing && group.members[0].node_name.is_none());
    let gone = f.chain("gone", &[(&groups[6], Balance::WeightedRoundRobin)]);
    assert_eq!(
        status(
            f.store
                .plan_chain(&f.admin, &gone.id, f.input(0))
                .unwrap_err()
        ),
        409
    );
}

#[test]
fn a_use_is_out_of_date_after_its_groups_change() {
    let (f, chain, _, second) = asymmetric();
    let applied = f
        .store
        .apply_chain(&f.admin, &chain.id, f.input(0))
        .unwrap();
    let before = f.revisions();
    // Server 4 leaves layer 2 and server 6 joins it.
    f.store
        .update_endpoint_group(
            &f.admin,
            &second.id,
            group_input("Exits", f.ids(&[5, 3, 6])),
        )
        .unwrap();
    assert_eq!(f.revisions(), before, "nothing is re-synced automatically");
    let used = f.view(&chain.id).uses.remove(0);
    assert!(used.out_of_date);
    assert_eq!(used.changes.len(), 1);
    assert_eq!(used.changes[0].layer, 2);
    assert_eq!(used.changes[0].added, [f.id(6)]);
    assert_eq!(used.changes[0].removed, [f.id(4)]);
    let relay = f.rule(1, &used.layers[0][1].rule_id);
    assert!(
        relay
            .targets
            .iter()
            .any(|t| t.via.as_ref().unwrap().node_id == f.id(4)),
        "the published forwarding still uses server 4"
    );
    // Only membership counts, not order.
    f.store
        .update_endpoint_group(
            &f.admin,
            &second.id,
            group_input("Exits", f.ids(&[4, 5, 3])),
        )
        .unwrap();
    let used = f.view(&chain.id).uses.remove(0);
    assert!(!used.out_of_date && used.changes.is_empty());

    // Deleting the entry server is not blocked by the use, which shows as
    // missing until the next save of the chain forgets it.
    f.store.delete_node(&f.admin, &f.id(0)).unwrap();
    let used = f.view(&chain.id).uses.remove(0);
    assert_eq!(used.entry_rule_id, applied.entry_rule_id);
    assert!(used.missing && used.name.is_none() && used.entry_node_name.is_none());
    let current = f.view(&chain.id);
    let input = ChainInput {
        name: current.name.clone(),
        enabled: true,
        layers: current
            .layers
            .iter()
            .map(|layer| Layer {
                group_id: layer.group_id.clone(),
                balance: layer.balance,
            })
            .collect(),
    };
    let saved = f.store.update_chain(&f.admin, &chain.id, input).unwrap();
    assert!(saved.uses.is_empty());
}

#[test]
fn tenants_are_isolated_and_viewers_cannot_change_chains() {
    let (f, chain, first, _) = asymmetric();
    let tenant = f.store.create_tenant(&f.admin, "isolated").unwrap();
    let outsider = f
        .store
        .create_user(&f.admin, &tenant, "outsider", PASSWORD, Role::TenantAdmin)
        .unwrap();
    let viewer = f
        .store
        .create_user(&f.admin, "default", "readonly", PASSWORD, Role::Viewer)
        .unwrap();
    assert!(f.store.endpoint_groups(&outsider).unwrap().is_empty());
    assert!(f.store.chains(&outsider).unwrap().is_empty());
    assert_eq!(f.store.endpoint_groups(&viewer).unwrap().len(), 2);
    assert_eq!(f.store.chains(&viewer).unwrap().len(), 1);
    let group = || group_input("Relays", f.ids(&[1, 2]));
    let layers = || chain_input("Asia", true, &[(&first, Balance::WeightedRoundRobin)]);
    for error in [
        f.store
            .update_endpoint_group(&outsider, &first.id, group())
            .unwrap_err(),
        f.store
            .delete_endpoint_group(&outsider, &first.id)
            .unwrap_err(),
        f.store
            .update_chain(&outsider, &chain.id, layers())
            .unwrap_err(),
        f.store.delete_chain(&outsider, &chain.id).unwrap_err(),
        f.store
            .plan_chain(&outsider, &chain.id, f.input(0))
            .unwrap_err(),
        f.store
            .apply_chain(&outsider, &chain.id, f.input(0))
            .unwrap_err(),
        f.store
            .create_endpoint_group(&outsider, group())
            .unwrap_err(),
    ] {
        assert_eq!(status(error), 404);
    }
    for error in [
        f.store.create_endpoint_group(&viewer, group()).unwrap_err(),
        f.store
            .update_endpoint_group(&viewer, &first.id, group())
            .unwrap_err(),
        f.store
            .delete_endpoint_group(&viewer, &first.id)
            .unwrap_err(),
        f.store.create_chain(&viewer, layers()).unwrap_err(),
        f.store
            .update_chain(&viewer, &chain.id, layers())
            .unwrap_err(),
        f.store.delete_chain(&viewer, &chain.id).unwrap_err(),
        f.store
            .plan_chain(&viewer, &chain.id, f.input(0))
            .unwrap_err(),
        f.store
            .apply_chain(&viewer, &chain.id, f.input(0))
            .unwrap_err(),
    ] {
        assert_eq!(status(error), 403);
    }
    assert_eq!(f.store.chains(&f.admin).unwrap()[0].layers.len(), 2);
}

async fn login(client: &reqwest::Client, origin: &str, username: &str) -> String {
    let body: Value = client
        .post(format!("{origin}/api/v1/auth/login"))
        .json(&json!({"username": username, "password": PASSWORD}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    body["token"].as_str().unwrap().to_string()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_api_plans_and_applies_a_chain_with_token_scopes() {
    let f = Fixture::new(4);
    f.store
        .create_user(&f.admin, "default", "readonly", PASSWORD, Role::Viewer)
        .unwrap();
    let stop = CancellationToken::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = api::router(AppState::new(f.store.clone()).with_shutdown(stop.clone()));
    let shutdown = stop.clone();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await
        .unwrap();
    });
    let origin = format!("http://{address}");
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let admin = login(&client, &origin, "admin").await;
    let viewer = login(&client, &origin, "readonly").await;
    let call = |method: reqwest::Method, path: &str, token: &str, body: Option<Value>| {
        let request = client
            .request(method, format!("{origin}/api/v1{path}"))
            .bearer_auth(token);
        let request = match body {
            Some(body) => request.json(&body),
            None => request,
        };
        async move {
            let response = request.send().await.unwrap();
            let status = response.status().as_u16();
            (status, response.json::<Value>().await.unwrap())
        }
    };
    use reqwest::Method;
    let (status, relays) = call(
        Method::POST,
        "/endpoint-groups",
        &admin,
        Some(json!({"name": "Relays", "description": "IX", "members": f.ids(&[2, 1])})),
    )
    .await;
    assert_eq!(status, 200, "{relays}");
    assert_eq!(relays["members"][0]["node_name"], "srv-2");
    let (status, _) = call(
        Method::POST,
        "/endpoint-groups",
        &viewer,
        Some(json!({"name": "Exits", "members": f.ids(&[3])})),
    )
    .await;
    assert_eq!(status, 403);
    let (_, exits) = call(
        Method::POST,
        "/endpoint-groups",
        &admin,
        Some(json!({"name": "Exits", "members": f.ids(&[3])})),
    )
    .await;
    let (status, chain) = call(
        Method::POST,
        "/chains",
        &admin,
        Some(json!({"name": "Asia", "layers": [
            {"group_id": relays["id"], "balance": "source_hash"},
            {"group_id": exits["id"]},
        ]})),
    )
    .await;
    assert_eq!(status, 200, "{chain}");
    assert_eq!(chain["enabled"], true);
    assert_eq!(chain["layers"][1]["balance"], "weighted_round_robin");
    let id = chain["id"].as_str().unwrap();
    let body = json!({"entry_node_id": f.id(0), "name": "Web", "protocol": "tcp", "target": TARGET, "entry_port": null});

    let (status, plan) = call(
        Method::POST,
        &format!("/chains/{id}/plan"),
        &admin,
        Some(body.clone()),
    )
    .await;
    assert_eq!(status, 200, "{plan}");
    assert_eq!(plan["batch"]["updates"].as_array().unwrap().len(), 4);
    assert_eq!(plan["preview"]["changes"].as_array().unwrap().len(), 4);
    assert_eq!(
        plan["hops"][0]["advertise"],
        format!("srv0.example.net:{}", base_port(0))
    );
    // A taken entry port names the entry server.
    f.occupy(0, "busy", base_port(0) + 3);
    let mut taken = body.clone();
    taken["entry_port"] = json!(base_port(0) + 3);
    let (status, refused) = call(
        Method::POST,
        &format!("/chains/{id}/apply"),
        &admin,
        Some(taken),
    )
    .await;
    assert_eq!(status, 409, "{refused}");
    assert_eq!(refused["lines"][0]["node_id"], f.id(0));

    // Tokens: `read` lists, `nodes:write` plans.
    let (reader, _) = f
        .store
        .create_api_token(&f.admin, "reader", &[Scope::Read], 1)
        .unwrap();
    let (writer, _) = f
        .store
        .create_api_token(&f.admin, "writer", &[Scope::NodesWrite], 1)
        .unwrap();
    assert_eq!(call(Method::GET, "/chains", &reader, None).await.0, 200);
    assert_eq!(
        call(Method::GET, "/endpoint-groups", &reader, None).await.0,
        200
    );
    assert_eq!(
        call(
            Method::POST,
            &format!("/chains/{id}/plan"),
            &reader,
            Some(body.clone())
        )
        .await
        .0,
        403
    );
    let (status, plan) = call(
        Method::POST,
        &format!("/chains/{id}/plan"),
        &writer,
        Some(body.clone()),
    )
    .await;
    assert_eq!(status, 200, "{plan}");
    let expected: Value = plan["batch"]["updates"]
        .as_array()
        .unwrap()
        .iter()
        .map(|u| {
            (
                u["node_id"].as_str().unwrap().to_owned(),
                u["expected_revision"].clone(),
            )
        })
        .collect::<serde_json::Map<_, _>>()
        .into();
    let mut apply = body.clone();
    apply["expected_revisions"] = expected;
    assert_eq!(
        call(
            Method::POST,
            &format!("/chains/{id}/apply"),
            &viewer,
            Some(apply.clone())
        )
        .await
        .0,
        403
    );
    let (status, applied) = call(
        Method::POST,
        &format!("/chains/{id}/apply"),
        &admin,
        Some(apply),
    )
    .await;
    assert_eq!(status, 200, "{applied}");
    let entry = applied["entry_rule_id"].as_str().unwrap();
    let (status, listed) = call(Method::GET, "/chains", &viewer, None).await;
    assert_eq!(status, 200);
    assert_eq!(listed[0]["uses"][0]["entry_rule_id"], entry);
    assert_eq!(listed[0]["uses"][0]["out_of_date"], false);

    // Refreshing it: automatic refresh, preview, confirmation, cancel.
    let refresh = format!("/chains/{id}/uses/{entry}");
    let sync = format!("{refresh}/sync");
    let on = json!({"auto_sync": true, "timeout_secs": 300});
    assert_eq!(
        call(Method::PUT, &sync, &reader, Some(on.clone())).await.0,
        403
    );
    let (status, synced) = call(Method::PUT, &sync, &writer, Some(on)).await;
    assert_eq!(status, 200, "{synced}");
    assert_eq!(synced["auto_sync"]["timeout_secs"], 300);
    let (_, listed) = call(Method::GET, "/chains", &reader, None).await;
    assert_eq!(listed[0]["uses"][0]["auto_sync"]["enabled_by"], "admin");
    let (_, synced) = call(
        Method::PUT,
        &sync,
        &writer,
        Some(json!({"auto_sync": false})),
    )
    .await;
    assert!(synced["auto_sync"].is_null());
    let relays_id = relays["id"].as_str().unwrap();
    let (status, _) = call(
        Method::PUT,
        &format!("/endpoint-groups/{relays_id}"),
        &admin,
        Some(json!({"name": "Relays", "members": f.ids(&[2])})),
    )
    .await;
    assert_eq!(status, 200);
    let plan_path = format!("{refresh}/refresh/plan");
    assert_eq!(
        call(Method::POST, &plan_path, &reader, Some(json!({})))
            .await
            .0,
        403
    );
    // The entry, which pauses, has never reported: its agent cannot be told
    // from one too old to pause targets. 409 naming it, until it reports as
    // 0.150.0 agents do.
    let (status, refused) = call(Method::POST, &plan_path, &writer, Some(json!({}))).await;
    assert_eq!(status, 409, "{refused}");
    assert!(
        refused["error"]
            .as_str()
            .unwrap()
            .contains("has not connected to the panel yet"),
        "{refused}"
    );
    let named: BTreeSet<&str> = refused["lines"]
        .as_array()
        .unwrap()
        .iter()
        .map(|line| line["node_id"].as_str().unwrap())
        .collect();
    assert_eq!(named, BTreeSet::from([f.id(0).as_str()]));
    f.enroll(&[0, 1, 2, 3]);
    f.report_all();
    let (status, plan) = call(Method::POST, &plan_path, &writer, Some(json!({}))).await;
    assert_eq!(status, 200, "{plan}");
    assert_eq!(plan["interrupts"], true);
    assert_eq!(plan["changes"][0]["removed"][0], f.id(1));
    let confirm = json!({"token": plan["token"], "expected_revisions": plan["expected_revisions"]});
    let start = format!("{refresh}/refresh");
    assert_eq!(
        call(Method::POST, &start, &viewer, Some(confirm.clone()))
            .await
            .0,
        403
    );
    let mut stale = confirm.clone();
    stale["token"] = json!("stale");
    assert_eq!(call(Method::POST, &start, &admin, Some(stale)).await.0, 409);
    let (status, started) = call(Method::POST, &start, &admin, Some(confirm)).await;
    assert_eq!(status, 200, "{started}");
    assert_eq!(started["phase"], "draining");
    assert_eq!(started["interrupted"], true);
    let cancel = format!("{refresh}/refresh/cancel");
    let keep = json!({"keep_stopped": true});
    assert_eq!(
        call(Method::POST, &cancel, &reader, Some(keep.clone()))
            .await
            .0,
        403
    );
    // Sent as the panel sends it: a JSON content type and no body.
    let panel = |body: &'static str| {
        let request = client
            .post(format!("{origin}/api/v1{cancel}"))
            .bearer_auth(&admin)
            .header("content-type", "application/json")
            .body(body);
        async move {
            let response = request.send().await.unwrap();
            let status = response.status().as_u16();
            (status, response.json::<Value>().await.unwrap())
        }
    };
    assert_eq!(panel("{").await.0, 400);
    assert_eq!(panel(r#"{"keep":true}"#).await.0, 422);
    assert_eq!(f.refresh(id).phase, RefreshPhase::Draining);
    let (status, cancelled) = panel("").await;
    assert_eq!(status, 200, "{cancelled}");
    assert_eq!(cancelled["outcome"], "cancelled");
    // Committed, not usable until the entry's agent applies it.
    assert_eq!(cancelled["stage"], "restore_confirming");
    assert_eq!(cancelled["interrupted"], true);
    f.report_all();
    f.advance();
    f.report_all();
    f.advance();
    let view = f.refresh(id);
    assert_eq!(view.phase, RefreshPhase::Finished);
    assert!(!view.interrupted);
    // A body of only white space is no body either: it reaches the
    // refresh, which can no longer be cancelled.
    let (status, done) = panel(" \n\t ").await;
    assert_eq!(status, 409, "{done}");
    assert!(
        done["error"]
            .as_str()
            .unwrap()
            .contains("can no longer be cancelled"),
        "{done}"
    );
    assert_eq!(call(Method::POST, &cancel, &admin, None).await.0, 409);
    assert_eq!(call(Method::POST, &cancel, &admin, Some(keep)).await.0, 409);

    // A used group cannot be deleted; deleting the chain keeps the rules.
    let (status, used) = call(
        Method::DELETE,
        &format!("/endpoint-groups/{}", exits["id"].as_str().unwrap()),
        &admin,
        None,
    )
    .await;
    assert_eq!(status, 409, "{used}");
    let (status, _) = call(Method::DELETE, &format!("/chains/{id}"), &admin, None).await;
    assert_eq!(status, 200);
    assert!(f.config(0).rules.iter().any(|rule| rule.id == entry));
    let (status, _) = call(
        Method::POST,
        &format!("/chains/{id}/plan"),
        &admin,
        Some(body),
    )
    .await;
    assert_eq!(status, 404);
    let (status, _) = call(
        Method::DELETE,
        &format!("/endpoint-groups/{}", exits["id"].as_str().unwrap()),
        &admin,
        None,
    )
    .await;
    assert_eq!(status, 200);
    stop.cancel();
}

/// Entry 0 → layer 1 [1, 2] → layer 2 [3]; servers 4 and 5 are spare. Every
/// server has an agent that reports, and the forwarding is applied.
fn running() -> (Fixture, ChainView, GroupView, GroupView, String) {
    let f = Fixture::new(6);
    f.enroll(&[0, 1, 2, 3, 4, 5]);
    f.report_all();
    let first = f.group("Relays", &[1, 2]);
    let second = f.group("Exits", &[3]);
    let chain = f.chain(
        "Asia",
        &[
            (&first, Balance::SourceHash),
            (&second, Balance::WeightedRoundRobin),
        ],
    );
    let applied = f
        .store
        .apply_chain(&f.admin, &chain.id, f.input(0))
        .unwrap();
    f.report_all();
    (f, chain, first, second, applied.entry_rule_id)
}
/// The rule id of server `index` in layer `layer` (from 1) of the use.
fn hop(f: &Fixture, chain: &str, layer: usize, index: usize) -> String {
    f.use_of(chain).layers[layer - 1]
        .iter()
        .find(|hop| hop.node_id == f.id(index))
        .unwrap()
        .rule_id
        .clone()
}
fn vias(rule: &Rule) -> Vec<String> {
    rule.targets
        .iter()
        .filter_map(|t| t.via.as_ref().map(|via| via.node_id.clone()))
        .collect()
}

#[test]
fn a_refresh_rewires_member_changes_and_keeps_manual_edits() {
    let (f, chain, first, _, entry) = running();
    let one = hop(&f, &chain.id, 1, 1);
    let two = hop(&f, &chain.id, 1, 2);
    let exit = hop(&f, &chain.id, 2, 3);
    // Manual edits on the entry and on a relay.
    f.edit_rule(0, &entry, |rule| {
        rule.name = "Web entry (edited)".into();
        rule.quota_bytes = Some(1 << 30);
        rule.allow_sources = vec!["198.51.100.0/24".parse().unwrap()];
    });
    f.edit_rule(1, &one, |rule| {
        rule.allow_sources = vec!["192.0.2.0/24".parse().unwrap()];
        rule.deny_sources = vec!["192.0.2.66/32".parse().unwrap()];
        rule.rate_bytes_per_sec = Some(1_000_000);
        rule.idle_timeout_secs = 77;
    });
    f.report_all();
    let epoch = f.rule(0, &entry).meter_epoch;

    // Editing the group changes no server, now or later, while automatic
    // refresh is off.
    let before = f.revisions();
    f.set_members(&first, &[1, 4]);
    f.advance();
    assert_eq!(f.revisions(), before);
    let view = f.use_of(&chain.id);
    assert!(view.out_of_date && view.auto_sync.is_none() && view.refresh.is_none());
    assert_eq!(view.changes[0].added, vec![f.id(4)]);
    assert_eq!(view.changes[0].removed, vec![f.id(2)]);

    // The preview names the cost: the entry must be idle as a whole.
    let plan = f.plan_refresh(&chain.id, &entry);
    assert!(plan.conflicts.is_empty(), "{:?}", plan.conflicts);
    assert!(plan.interrupts && !plan.up_to_date);
    assert_eq!(plan.timeout_secs, 600);
    let idle: Vec<_> = plan
        .idle_servers
        .iter()
        .map(|s| s.node_id.clone())
        .collect();
    assert_eq!(idle, vec![f.id(0)]);
    assert!(plan.idle_servers[0].idle && plan.idle_servers[0].online);
    assert_eq!(plan.hops.len(), 1);
    assert_eq!((plan.hops[0].layer, &plan.hops[0].node_id), (1, &f.id(4)));
    // The new relay copies the remaining relay's settings, not the defaults.
    let added = plan.preview.as_ref().unwrap().configs[0]
        .rules
        .iter()
        .find(|rule| rule.id == plan.hops[0].rule_id)
        .unwrap()
        .clone();
    let reference = f.rule(1, &one);
    assert_eq!(added.allow_sources, reference.allow_sources);
    assert_eq!(added.deny_sources, reference.deny_sources);
    assert_eq!(added.rate_bytes_per_sec, Some(1_000_000));
    assert_eq!(added.idle_timeout_secs, 77);
    assert_ne!(added.meter_epoch, reference.meter_epoch);
    assert_eq!(vias(&added), vec![f.id(3)]);
    assert_eq!(added.targets[0].via.as_ref().unwrap().rule_id, exit);
    let entry_change = plan.result.iter().find(|c| c.node_id == f.id(0)).unwrap();
    assert_eq!(entry_change.modified, vec![entry.clone()]);
    let planned_entry = entry_change.rule_changes[0].after.clone().unwrap();
    assert_eq!(vias(&planned_entry), vec![f.id(1), f.id(4)]);
    assert_eq!(
        plan.result
            .iter()
            .find(|c| c.node_id == f.id(2))
            .unwrap()
            .removed,
        vec![two.clone()]
    );

    // Confirming publishes only the new relay's rule; a repeated
    // confirmation returns the same refresh.
    let started = f.confirm(&chain.id, &entry, &plan).unwrap();
    assert_eq!(started.phase, RefreshPhase::Preparing);
    assert_eq!(f.confirm(&chain.id, &entry, &plan).unwrap().id, started.id);
    assert_eq!(f.config(0).revision, before[0]);
    assert_eq!(
        started.commits[0].revisions.keys().collect::<Vec<_>>(),
        vec![&f.id(4)]
    );
    let paused = |f: &Fixture| f.rule(0, &entry).targets.iter().all(|t| t.paused);
    assert!(!paused(&f));
    // Nothing pauses until the new relay's agent applied its rule.
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Preparing);
    assert!(f.refresh(&chain.id).waiting[0].node_id == f.id(4));
    f.report(4, 0);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.phase, RefreshPhase::Draining);
    assert!(view.interrupted && paused(&f));
    assert!(
        f.rule(0, &entry)
            .targets
            .iter()
            .all(|t| t.paused_until_ms == Some(view.deadline_ms))
    );
    // Sessions on the entry, of any rule, keep it draining.
    f.report(0, 3);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.phase, RefreshPhase::Draining);
    assert_eq!(view.servers[0].active_tcp, 3);
    assert!(!view.waiting.is_empty());
    f.report(0, 0);
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Stopping);
    assert!(!f.rule(0, &entry).enabled);
    // The stop must be applied before the rewire.
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Stopping);
    f.report(0, 0);
    f.advance();

    // Committed by the controller: until every agent applied the rewire the
    // refresh is confirming, not succeeded, and the forwarding interrupted.
    let view = f.refresh(&chain.id);
    assert_eq!(
        (view.phase, view.stage),
        (RefreshPhase::Confirming, "confirming")
    );
    assert_eq!(view.outcome, None);
    assert!(view.interrupted);
    let pending = |view: &RefreshView| {
        sorted(
            view.agents
                .iter()
                .filter(|a| a.step == RefreshStep::Rewire && a.state == "pending")
                .map(|a| a.node_id.clone())
                .collect(),
        )
    };
    // The entry is rewired, the removed relay's rule disabled.
    assert_eq!(pending(&view), sorted(f.ids(&[0, 2])));
    let rule = f.rule(0, &entry);
    assert!(rule.enabled && rule.targets.iter().all(|t| !t.paused));
    assert_eq!(vias(&rule), vec![f.id(1), f.id(4)]);
    // As previewed; confirmation generates the new rule's id again.
    let shape = |targets: &[relay_platform::model::Target]| {
        targets
            .iter()
            .map(|t| {
                (
                    t.address.clone(),
                    t.via.as_ref().map(|v| v.node_id.clone()),
                    t.weight,
                )
            })
            .collect::<Vec<_>>()
    };
    assert_eq!(shape(&rule.targets), shape(&planned_entry.targets));
    assert_eq!(rule.name, "Web entry (edited)");
    assert_eq!(rule.quota_bytes, Some(1 << 30));
    assert_eq!(rule.allow_sources, planned_entry.allow_sources);
    assert_eq!(rule.meter_epoch, epoch);
    assert_eq!(f.rule(1, &one), reference);
    assert!(!f.rule(2, &two).enabled);
    let listed = f.use_of(&chain.id);
    assert!(!listed.out_of_date);
    let relays: Vec<_> = listed.layers[0].iter().map(|h| h.node_id.clone()).collect();
    assert_eq!(relays, vec![f.id(1), f.id(4)]);
    // The entry applies it: the refresh succeeded. The removed relay's
    // agent is listed, but its rule carries none of the forwarding, so it
    // is not waited for; the rule goes once its server is idle.
    f.report(0, 0);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!((view.phase, view.stage), (RefreshPhase::Cleanup, "cleanup"));
    assert_eq!(pending(&view), vec![f.id(2)]);
    f.report(2, 1);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!((view.phase, view.stage), (RefreshPhase::Cleanup, "cleanup"));
    assert_eq!(view.outcome, Some(RefreshOutcome::Succeeded));
    assert!(!view.interrupted && view.problems.is_empty());
    assert_eq!(view.retire_pending.len(), 1);
    assert!(
        view.waiting[0]
            .error
            .contains("does not affect the forwarding")
    );
    f.report(2, 0);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(
        (view.phase, view.stage),
        (RefreshPhase::Finished, "finished")
    );
    assert!(!view.interrupted);
    assert!(f.config(2).rules.iter().all(|rule| rule.id != two));
    let admin = f.admin.id.as_str();
    let expected: Vec<(String, String)> = [
        ("start", admin),
        ("pause", admin),
        ("stop", admin),
        ("rewire", admin),
        ("confirmed", "chain-refresh"),
        ("cleanup", "chain-refresh"),
    ]
    .iter()
    .map(|(step, actor)| (step.to_string(), actor.to_string()))
    .collect();
    assert_eq!(f.steps(&view.id), expected);
    assert!(f.plan_refresh(&chain.id, &entry).up_to_date);
}

#[test]
fn a_refresh_below_the_first_layer_stops_everything_above_it_together() {
    let (f, chain, _, second, entry) = running();
    let one = hop(&f, &chain.id, 1, 1);
    let two = hop(&f, &chain.id, 1, 2);
    let exit = hop(&f, &chain.id, 2, 3);
    let entry_targets = f.rule(0, &entry).targets;
    // Layer 2 gains server 5. Only the relays get new next hops, but the
    // entry routes to them and an enabled rule may not route to a disabled
    // one: the entry stops with them, and all three servers must be idle.
    f.set_members(&second, &[3, 5]);
    let plan = f.plan_refresh(&chain.id, &entry);
    assert!(plan.conflicts.is_empty(), "{:?}", plan.conflicts);
    let idle: Vec<_> = plan
        .idle_servers
        .iter()
        .map(|s| s.node_id.clone())
        .collect();
    assert_eq!(sorted(idle), sorted(f.ids(&[0, 1, 2])));
    let started = f.confirm(&chain.id, &entry, &plan).unwrap();
    f.report_all();
    f.advance();
    let paused = |index: usize, id: &str| f.rule(index, id).targets.iter().all(|t| t.paused);
    assert!(paused(0, &entry) && paused(1, &one) && paused(2, &two));
    f.report_all();
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.phase, RefreshPhase::Stopping, "{:?}", view.error);
    for (index, id) in [(0, &entry), (1, &one), (2, &two)] {
        assert!(!f.rule(index, id).enabled);
    }
    f.report_all();
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.phase, RefreshPhase::Confirming);
    // The relays route to both exits; the entry keeps its routes; all are
    // enabled and resumed again.
    for (index, id) in [(1, &one), (2, &two)] {
        let rule = f.rule(index, id);
        assert!(rule.enabled && rule.targets.iter().all(|t| !t.paused));
        assert_eq!(vias(&rule), vec![f.id(3), f.id(5)]);
    }
    let rule = f.rule(0, &entry);
    assert!(rule.enabled && rule.targets == entry_targets);
    // The new exit copies the exit's settings and forwards to the target.
    let added = f.config(5).rules;
    assert_eq!(added.len(), 1);
    assert!(added[0].enabled && added[0].targets[0].address == TARGET);
    assert_eq!(
        f.rule(1, &one).targets[1].via.as_ref().unwrap().rule_id,
        added[0].id
    );
    assert_ne!(added[0].meter_epoch, f.rule(3, &exit).meter_epoch);
    f.report_all();
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(
        (view.phase, view.outcome),
        (RefreshPhase::Finished, Some(RefreshOutcome::Succeeded))
    );
    assert!(!view.interrupted && !f.use_of(&chain.id).out_of_date);
    assert_eq!(
        f.step_names(&started.id),
        ["start", "pause", "stop", "rewire", "confirmed"]
    );

    // A rule of a removed server that routes into what stops stops with it,
    // and one already disabled before the refresh stays disabled when the
    // forwarding is put back. Entry 0 → [1, 2] → [3] → [4]; the operator took
    // relay 2 out of the entry's routes and disabled it before removing it
    // from its group; layer 3 gains server 5.
    let f = Fixture::new(6);
    f.enroll(&[0, 1, 2, 3, 4, 5]);
    f.report_all();
    let first = f.group("Relays", &[1, 2]);
    let second = f.group("Middle", &[3]);
    let third = f.group("Exits", &[4]);
    let chain = f.chain(
        "Long",
        &[
            (&first, Balance::SourceHash),
            (&second, Balance::WeightedRoundRobin),
            (&third, Balance::WeightedRoundRobin),
        ],
    );
    let entry = f
        .store
        .apply_chain(&f.admin, &chain.id, f.input(0))
        .unwrap()
        .entry_rule_id;
    f.report_all();
    let two = hop(&f, &chain.id, 1, 2);
    f.edit_rule(0, &entry, |rule| rule.enabled = false);
    f.report_all();
    f.edit_rule(0, &entry, |rule| {
        rule.targets
            .retain(|t| t.via.as_ref().is_none_or(|via| via.node_id != f.id(2)));
        rule.enabled = true;
    });
    f.edit_rule(2, &two, |rule| rule.enabled = false);
    f.report_all();
    f.set_members(&first, &[1]);
    f.set_members(&third, &[4, 5]);
    let plan = f.plan_refresh(&chain.id, &entry);
    assert!(plan.conflicts.is_empty(), "{:?}", plan.conflicts);
    // Relay 2 leaves: not a server that must be idle.
    let idle: Vec<_> = plan
        .idle_servers
        .iter()
        .map(|s| s.node_id.clone())
        .collect();
    assert_eq!(sorted(idle), sorted(f.ids(&[0, 1, 3])));
    let started = f.confirm(&chain.id, &entry, &plan).unwrap();
    f.report_all();
    f.advance();
    f.report_all();
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Stopping);
    assert!(!f.rule(0, &entry).enabled);
    f.report(0, 1);
    f.at(started.deadline_ms);
    let view = f.refresh(&chain.id);
    assert_eq!(view.outcome, Some(RefreshOutcome::Failed));
    assert!(f.rule(0, &entry).enabled);
    assert!(f.rule(1, &hop(&f, &chain.id, 1, 1)).enabled);
    assert!(f.rule(3, &hop(&f, &chain.id, 2, 3)).enabled);
    assert!(!f.rule(2, &two).enabled, "disabled before the refresh");
    assert!(view.unresolved.is_empty());

    // Relay 2 moves from layer 1 to layer 3: its server has a rule the stop
    // disables and one the refresh adds. Put back while it has sessions, the
    // old rule is enabled with its old route and the new one only disabled,
    // which the idle exemption allows; the cleanup deletes it once idle.
    let f = Fixture::new(5);
    f.enroll(&[0, 1, 2, 3, 4]);
    f.report_all();
    let first = f.group("Relays", &[1, 2]);
    let second = f.group("Middle", &[3]);
    let third = f.group("Exits", &[4]);
    let chain = f.chain(
        "Long",
        &[
            (&first, Balance::SourceHash),
            (&second, Balance::WeightedRoundRobin),
            (&third, Balance::WeightedRoundRobin),
        ],
    );
    let entry = f
        .store
        .apply_chain(&f.admin, &chain.id, f.input(0))
        .unwrap()
        .entry_rule_id;
    f.report_all();
    let two = hop(&f, &chain.id, 1, 2);
    let before = f.rule(2, &two);
    f.set_members(&first, &[1]);
    f.set_members(&third, &[4, 2]);
    let plan = f.plan_refresh(&chain.id, &entry);
    assert!(plan.conflicts.is_empty(), "{:?}", plan.conflicts);
    let started = f.confirm(&chain.id, &entry, &plan).unwrap();
    let added = f
        .config(2)
        .rules
        .into_iter()
        .find(|rule| rule.id != two)
        .unwrap()
        .id;
    f.report_all();
    f.advance();
    f.report_all();
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Stopping);
    assert!(!f.rule(2, &two).enabled && f.rule(2, &added).enabled);
    f.report(3, 1);
    f.report(2, 1);
    f.at(started.deadline_ms);
    let view = f.refresh(&chain.id);
    assert_eq!(view.outcome, Some(RefreshOutcome::Failed));
    assert_eq!(view.stage, "restore_confirming", "{:?}", view.retry_error);
    assert_eq!(f.rule(2, &two), before);
    assert!(!f.rule(2, &added).enabled);
    f.report_all();
    f.advance();
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Finished);
    let rules = f.config(2).rules;
    assert_eq!(rules.len(), 1);
    assert_eq!(rules[0], before);
}

#[test]
fn a_refresh_that_cannot_finish_puts_the_forwarding_back() {
    let (f, chain, _, second, entry) = running();
    let one = hop(&f, &chain.id, 1, 1);
    let two = hop(&f, &chain.id, 1, 2);
    let enabled_and_resumed = |f: &Fixture| {
        [(0, &entry), (1, &one), (2, &two)]
            .iter()
            .all(|(index, id)| {
                let rule = f.rule(*index, id);
                rule.enabled && rule.targets.iter().all(|t| !t.paused)
            })
    };
    // Layer 2 gains server 5: both relays are rewired. The entry routes to
    // them, so it stops with them, and all three servers must be idle.
    f.set_members(&second, &[3, 5]);
    let plan = f.plan_refresh(&chain.id, &entry);
    let idle: Vec<_> = plan
        .idle_servers
        .iter()
        .map(|s| s.node_id.clone())
        .collect();
    assert_eq!(sorted(idle), sorted(f.ids(&[0, 1, 2])));

    // Cancelled while draining: the targets resume at once and the new
    // rule is disabled; once every agent applied that, it is deleted.
    let started = f.confirm(&chain.id, &entry, &plan).unwrap();
    let added = f.refresh(&chain.id).commits[0]
        .revisions
        .keys()
        .cloned()
        .collect::<Vec<_>>();
    assert_eq!(added, vec![f.id(5)]);
    f.report(5, 0);
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Draining);
    assert!(f.rule(0, &entry).targets.iter().all(|t| t.paused));
    assert!(f.rule(1, &one).targets.iter().all(|t| t.paused));
    let cancelled = f.cancel(&chain.id, &entry, false).unwrap();
    assert_eq!(cancelled.outcome, Some(RefreshOutcome::Cancelled));
    assert_eq!(cancelled.failed_in, Some(RefreshPhase::Draining));
    assert_eq!(
        (cancelled.phase, cancelled.stage),
        (RefreshPhase::Restoring, "restore_confirming")
    );
    assert!(cancelled.interrupted);
    assert!(enabled_and_resumed(&f));
    assert!(f.config(5).rules.iter().all(|rule| !rule.enabled));
    f.report_all();
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.phase, RefreshPhase::Cleanup);
    assert!(!view.interrupted);
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Finished);
    assert!(f.config(5).rules.is_empty());
    assert_eq!(
        f.step_names(&started.id),
        [
            "start",
            "pause",
            "cancel",
            "abort",
            "restore",
            "restore_committed",
            "restored",
            "cleanup"
        ]
    );
    assert_eq!(status(f.cancel(&chain.id, &entry, false).unwrap_err()), 409);

    // Timed out while stopped: relay 1 keeps sessions of another rule, so
    // the rewire waits. Past the deadline the relays are enabled again at
    // once, with the routes they had, although relay 1 is not idle.
    f.report_all();
    let plan = f.plan_refresh(&chain.id, &entry);
    let started = f
        .store
        .refresh_chain_use(
            &f.admin,
            &chain.id,
            &entry,
            RefreshInput {
                token: plan.token.clone(),
                expected_revisions: plan.expected_revisions.clone(),
                timeout_secs: Some(60),
            },
        )
        .unwrap();
    assert_eq!(started.deadline_ms - started.started_at_ms, 60_000);
    f.report_all();
    f.advance();
    f.report_all();
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Stopping);
    assert!(!f.rule(0, &entry).enabled);
    assert!(!f.rule(1, &one).enabled && !f.rule(2, &two).enabled);
    let before_restore = (f.rule(1, &one), f.rule(2, &two));
    f.report(0, 0);
    f.report(2, 0);
    f.report(1, 2);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.phase, RefreshPhase::Stopping);
    assert_eq!(view.waiting[0].node_id, f.id(1));
    f.at(started.deadline_ms + 1);
    let view = f.refresh(&chain.id);
    assert_eq!(
        (view.phase, view.stage),
        (RefreshPhase::Restoring, "restore_confirming")
    );
    assert_eq!(view.failed_in, Some(RefreshPhase::Stopping));
    assert!(
        view.error.as_deref().unwrap().contains("timed out"),
        "{view:?}"
    );
    assert_eq!(view.problems[0].node_id, f.id(1));
    assert!(enabled_and_resumed(&f));
    // Only `enabled` and the pause changed: the routes are the old ones.
    let mut expected = before_restore.0.clone();
    expected.enabled = true;
    expected.targets.iter_mut().for_each(|t| {
        t.paused = false;
        t.paused_until_ms = None;
    });
    assert_eq!(f.rule(1, &one), expected);
    assert!(
        view.servers
            .iter()
            .any(|s| s.node_id == f.id(1) && s.active_tcp == 2)
    );
    // Interrupted until every agent applied the restore.
    assert!(view.interrupted);
    for index in [0, 2, 5] {
        f.report(index, 0);
    }
    f.report(1, 2);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.phase, RefreshPhase::Cleanup);
    assert_eq!(view.outcome, Some(RefreshOutcome::Failed));
    assert!(!view.interrupted && view.unresolved.is_empty());
    assert!(enabled_and_resumed(&f));
    // The forwarding is as before, still out of date.
    assert!(f.use_of(&chain.id).out_of_date);
    assert_eq!(f.use_of(&chain.id).layers[1].len(), 1);
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Finished);
    let steps = f.steps(&started.id);
    let names: Vec<&str> = steps.iter().map(|(s, _)| s.as_str()).collect();
    assert_eq!(
        names,
        [
            "start",
            "pause",
            "stop",
            "abort",
            "restore",
            "restore_committed",
            "restored",
            "cleanup"
        ]
    );
    // Putting back runs as the controller, not as the user who started it.
    assert!(steps[4..].iter().all(|(_, actor)| actor == "chain-refresh"));

    // An agent that cannot apply the pause, as agents older than paused
    // targets: the refresh ends and the targets resume.
    f.report_all();
    let plan = f.plan_refresh(&chain.id, &entry);
    f.confirm(&chain.id, &entry, &plan).unwrap();
    f.report_all();
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Draining);
    let previous = f.config(0).revision - 1;
    f.report_as(0, Some(previous), Some("unknown field `paused`"), 0, false);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.outcome, Some(RefreshOutcome::Failed));
    assert!(view.error.unwrap().contains("could not apply the pause"));
    assert_eq!(view.problems[0].node_id, f.id(0));
    assert!(enabled_and_resumed(&f));
    f.report_all();
    f.advance();
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Finished);

    // The deadline passes while nothing is waited for: nothing is paused or
    // stopped late, before the pause and before the stop.
    let no_step = |f: &Fixture, step: relay_platform::chain::RefreshStep| {
        f.refresh(&chain.id).commits.iter().all(|c| c.step != step)
    };
    for (phase, step) in [
        (
            RefreshPhase::Preparing,
            relay_platform::chain::RefreshStep::Pause,
        ),
        (
            RefreshPhase::Draining,
            relay_platform::chain::RefreshStep::Stop,
        ),
    ] {
        f.report_all();
        let plan = f.plan_refresh(&chain.id, &entry);
        let started = f.confirm(&chain.id, &entry, &plan).unwrap();
        f.report_all();
        if phase == RefreshPhase::Draining {
            f.advance();
            f.report_all();
        }
        assert_eq!(f.refresh(&chain.id).phase, phase);
        assert!(f.refresh(&chain.id).waiting.is_empty());
        f.at(started.deadline_ms);
        let view = f.refresh(&chain.id);
        assert_eq!(view.outcome, Some(RefreshOutcome::Failed), "{view:?}");
        assert_eq!(view.failed_in, Some(phase));
        assert!(view.error.as_deref().unwrap().contains("timed out"));
        assert!(no_step(&f, step));
        assert!(enabled_and_resumed(&f));
        f.report_all();
        f.advance();
        f.advance();
        assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Finished);
    }
}

#[test]
fn offline_servers_and_old_agents_keep_the_forwarding_running() {
    // Server 2's agent enrolled but never reported: it is offline. It is
    // marked as able to pause targets, which only a report would show, so
    // the refresh gets past the preview and waits for it.
    let f = Fixture::new(6);
    f.enroll(&[0, 1, 2, 3, 4, 5]);
    for index in [0, 1, 3, 4, 5] {
        f.report(index, 0);
    }
    f.able_to_pause(&[2]);
    let first = f.group("Relays", &[1, 2]);
    let second = f.group("Exits", &[3]);
    let chain = f.chain(
        "Asia",
        &[
            (&first, Balance::SourceHash),
            (&second, Balance::WeightedRoundRobin),
        ],
    );
    let entry = f
        .store
        .apply_chain(&f.admin, &chain.id, f.input(0))
        .unwrap()
        .entry_rule_id;
    for index in [0, 1, 3] {
        f.report(index, 0);
    }
    f.set_members(&second, &[3, 4]);
    let plan = f.plan_refresh(&chain.id, &entry);
    let offline = plan
        .idle_servers
        .iter()
        .find(|s| s.node_id == f.id(2))
        .unwrap();
    assert!(!offline.online && !offline.idle);
    let started = f.confirm(&chain.id, &entry, &plan).unwrap();
    f.report(4, 0);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.phase, RefreshPhase::Preparing);
    assert!(view.waiting.iter().any(|w| w.node_id == f.id(2)));
    // Nothing paused; past the deadline it gives up without interrupting.
    assert!(f.rule(0, &entry).targets.iter().all(|t| !t.paused));
    f.store
        .advance_chain_refreshes_at(started.deadline_ms + 1)
        .unwrap();
    let view = f.refresh(&chain.id);
    assert_eq!(view.outcome, Some(RefreshOutcome::Failed));
    assert_eq!(view.failed_in, Some(RefreshPhase::Preparing));
    assert!(
        view.commits
            .iter()
            .all(|c| c.step != relay_platform::chain::RefreshStep::Pause)
    );
    assert!(f.rule(0, &entry).enabled);

    // New servers copy limits that need a newer agent: the preview names
    // the old agent and nothing is published.
    let (f, chain, first, _, entry) = running();
    for index in [1, 2] {
        f.report_as(index, None, None, 0, true);
    }
    let one = hop(&f, &chain.id, 1, 1);
    f.edit_rule(1, &one, |rule| {
        rule.rate_limits = Some(RateLimits {
            upload_bytes_per_sec: Some(500_000),
            ..Default::default()
        });
    });
    f.set_members(&first, &[1, 4]);
    let before = f.revisions();
    let plan = f.plan_refresh(&chain.id, &entry);
    assert!(
        plan.conflicts
            .iter()
            .any(|c| c.message.contains("too old") && c.node_id.as_deref() == Some(&f.id(4))),
        "{:?}",
        plan.conflicts
    );
    assert_eq!(
        status(f.confirm(&chain.id, &entry, &plan).unwrap_err()),
        409
    );
    assert_eq!(f.revisions(), before);
    f.report_as(4, None, None, 0, true);
    let plan = f.plan_refresh(&chain.id, &entry);
    assert!(plan.conflicts.is_empty(), "{:?}", plan.conflicts);
}

#[test]
fn a_refresh_refuses_conflicts_stale_previews_and_changes_by_others() {
    // Without agents the stop barrier lets these tests edit routes freely.
    let f = Fixture::new(7);
    f.able_to_pause(&[0, 1, 2, 3, 4, 5, 6]);
    let first = f.group("Relays", &[1, 2]);
    let second = f.group("Exits", &[3]);
    let chain = f.chain(
        "Asia",
        &[
            (&first, Balance::SourceHash),
            (&second, Balance::WeightedRoundRobin),
        ],
    );
    let entry = f
        .store
        .apply_chain(&f.admin, &chain.id, f.input(0))
        .unwrap()
        .entry_rule_id;
    let one = hop(&f, &chain.id, 1, 1);
    let up_to_date = f.plan_refresh(&chain.id, &entry);
    assert!(up_to_date.up_to_date && !up_to_date.interrupts);
    assert_eq!(
        status(f.confirm(&chain.id, &entry, &up_to_date).unwrap_err()),
        409
    );
    f.set_members(&first, &[1, 2, 4]);

    // A stale preview: a server's configuration or the group changed.
    let plan = f.plan_refresh(&chain.id, &entry);
    f.occupy(0, "other", base_port(0) + 20);
    let error = f.confirm(&chain.id, &entry, &plan).unwrap_err();
    assert_eq!(failed_nodes(&error), vec![f.id(0)]);
    assert_eq!(status(error), 409);
    let message = |error: anyhow::Error| error.downcast_ref::<Rejection>().unwrap().message.clone();
    let plan = f.plan_refresh(&chain.id, &entry);
    f.set_members(&first, &[2, 1, 4]);
    let error = f.confirm(&chain.id, &entry, &plan).unwrap_err();
    assert!(message(error).contains("groups or the forwarding changed"));
    let plan = f.plan_refresh(&chain.id, &entry);
    f.set_members(&first, &[1, 2, 5]);
    let error = f.confirm(&chain.id, &entry, &plan).unwrap_err();
    let mut nodes = failed_nodes(&error);
    nodes.sort();
    let mut expected = f.ids(&[4, 5]);
    expected.sort();
    assert_eq!(nodes, expected);
    assert!(message(error).contains("out of date"));

    // The entry no longer routes to a relay that stays: a manual edit.
    f.edit_rule(0, &entry, |rule| rule.enabled = false);
    f.edit_rule(0, &entry, |rule| {
        rule.enabled = true;
        rule.targets
            .retain(|t| t.via.as_ref().is_none_or(|via| via.node_id != f.id(1)));
    });
    let plan = f.plan_refresh(&chain.id, &entry);
    assert!(
        plan.conflicts
            .iter()
            .any(|c| c.message.contains("no longer routes") && c.rule_id.as_deref() == Some(&entry)),
        "{:?}",
        plan.conflicts
    );
    assert_eq!(
        status(f.confirm(&chain.id, &entry, &plan).unwrap_err()),
        409
    );
    f.set_members(&first, &[2, 5]);
    // Removing that relay from the group is consistent with the edit.
    assert!(f.plan_refresh(&chain.id, &entry).conflicts.is_empty());

    // A rule outside the forwarding routes into the relay that leaves.
    let mut foreign = f.rule(1, &one);
    let config = f.config(6);
    foreign.id = "foreign".into();
    foreign.meter_epoch = "foreign-epoch".into();
    foreign.advertise = None;
    foreign.listen = SocketAddr::from(([0, 0, 0, 0], base_port(6)));
    foreign.targets[0].address = f.rule(1, &one).advertise.unwrap();
    foreign.targets[0].via = Some(relay_platform::model::RuleRef {
        node_id: f.id(1),
        rule_id: one.clone(),
    });
    let mut rules = config.rules;
    rules.push(foreign);
    f.store
        .set_config(&f.admin, &f.id(6), config.revision, rules)
        .unwrap();
    let plan = f.plan_refresh(&chain.id, &entry);
    assert!(
        plan.conflicts
            .iter()
            .any(|c| c.rule_id.as_deref() == Some("foreign")),
        "{:?}",
        plan.conflicts
    );
    f.edit_rule(6, "foreign", |rule| rule.enabled = false);
    let config = f.config(6);
    f.store
        .set_config(&f.admin, &f.id(6), config.revision, vec![])
        .unwrap();

    // A disabled forwarding, a changed layer count.
    f.edit_rule(0, &entry, |rule| rule.enabled = false);
    let plan = f.plan_refresh(&chain.id, &entry);
    assert!(
        plan.conflicts
            .iter()
            .any(|c| c.message.contains("disabled"))
    );
    f.edit_rule(0, &entry, |rule| rule.enabled = true);
    let third = f.group("Last", &[6]);
    f.store
        .update_chain(
            &f.admin,
            &chain.id,
            chain_input(
                "Asia",
                true,
                &[
                    (&first, Balance::SourceHash),
                    (&second, Balance::WeightedRoundRobin),
                    (&third, Balance::WeightedRoundRobin),
                ],
            ),
        )
        .unwrap();
    let plan = f.plan_refresh(&chain.id, &entry);
    assert!(plan.conflicts.iter().any(|c| c.message.contains("layers")));
    f.store
        .update_chain(
            &f.admin,
            &chain.id,
            chain_input(
                "Asia",
                true,
                &[
                    (&first, Balance::SourceHash),
                    (&second, Balance::WeightedRoundRobin),
                ],
            ),
        )
        .unwrap();

    // Permissions: viewers cannot preview or change, other tenants see 404.
    let viewer = f
        .store
        .create_user(&f.admin, "default", "viewer", PASSWORD, Role::Viewer)
        .unwrap();
    let tenant = f.store.create_tenant(&f.admin, "Other").unwrap();
    let outsider = f
        .store
        .create_user(&f.admin, &tenant, "outsider", PASSWORD, Role::TenantAdmin)
        .unwrap();
    let input = || RefreshPlanInput::default();
    assert_eq!(
        status(
            f.store
                .plan_chain_refresh(&viewer, &chain.id, &entry, input())
                .unwrap_err()
        ),
        403
    );
    assert_eq!(
        status(
            f.store
                .plan_chain_refresh(&outsider, &chain.id, &entry, input())
                .unwrap_err()
        ),
        404
    );
    let sync = |actor: &Actor| {
        f.store.set_chain_auto_sync(
            actor,
            &chain.id,
            &entry,
            AutoSyncInput {
                auto_sync: true,
                timeout_secs: None,
            },
        )
    };
    assert_eq!(status(sync(&viewer).unwrap_err()), 403);
    assert_eq!(status(sync(&outsider).unwrap_err()), 404);
    assert_eq!(
        status(
            f.store
                .plan_chain_refresh(
                    &f.admin,
                    &chain.id,
                    &entry,
                    RefreshPlanInput {
                        timeout_secs: Some(30)
                    }
                )
                .unwrap_err()
        ),
        400
    );

    // While a refresh runs, another one or deleting the chain is refused;
    // a change by someone else before the rewire, even a new name, ends it.
    let plan = f.plan_refresh(&chain.id, &entry);
    assert!(plan.conflicts.is_empty(), "{:?}", plan.conflicts);
    f.confirm(&chain.id, &entry, &plan).unwrap();
    let view = f.refresh(&chain.id);
    // A new server without an agent cannot take traffic: it waits.
    assert_eq!(view.phase, RefreshPhase::Preparing, "{view:?}");
    assert!(view.waiting.iter().any(|w| w.node_id == f.id(5)));
    let other = f.store.refresh_chain_use(
        &f.admin,
        &chain.id,
        &entry,
        RefreshInput {
            token: "another".into(),
            expected_revisions: plan.expected_revisions.clone(),
            timeout_secs: None,
        },
    );
    assert_eq!(status(other.unwrap_err()), 409);
    assert_eq!(
        status(f.store.delete_chain(&f.admin, &chain.id).unwrap_err()),
        409
    );
    f.edit_rule(0, &entry, |rule| rule.name = "Renamed meanwhile".into());
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.outcome, Some(RefreshOutcome::Failed));
    assert_eq!(view.failed_in, Some(RefreshPhase::Preparing));
    assert!(view.error.as_deref().unwrap().contains("someone else"));
    assert_eq!(view.problems[0].node_id, f.id(0));
    assert!(view.unresolved.is_empty());
    // Their name stays; the new rule is disabled, then deleted.
    let renamed = f.rule(0, &entry);
    assert_eq!(renamed.name, "Renamed meanwhile");
    assert!(renamed.enabled && renamed.targets.iter().all(|t| !t.paused));
    assert!(f.config(5).rules.iter().all(|rule| !rule.enabled));
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Finished);
    assert!(f.config(5).rules.is_empty());

    // A disabled chain is not refreshed: a conflict in the preview.
    let chain_now = f.view(&chain.id);
    f.store
        .update_chain(
            &f.admin,
            &chain.id,
            chain_input(
                &chain_now.name,
                false,
                &[
                    (&first, Balance::SourceHash),
                    (&second, Balance::WeightedRoundRobin),
                ],
            ),
        )
        .unwrap();
    let plan = f.plan_refresh(&chain.id, &entry);
    assert!(
        plan.conflicts
            .iter()
            .any(|c| c.message.contains("chain is disabled")),
        "{:?}",
        plan.conflicts
    );
    assert_eq!(
        status(f.confirm(&chain.id, &entry, &plan).unwrap_err()),
        409
    );
    let _ = one;
}

#[test]
fn automatic_refresh_is_opt_in_backs_off_and_stops_without_permission() {
    let (f, chain, first, second, entry) = running();
    let ops = f
        .store
        .create_user(&f.admin, "default", "ops", PASSWORD, Role::TenantAdmin)
        .unwrap();
    let on = |actor: &Actor| {
        f.store
            .set_chain_auto_sync(
                actor,
                &chain.id,
                &entry,
                AutoSyncInput {
                    auto_sync: true,
                    timeout_secs: Some(120),
                },
            )
            .unwrap()
    };
    let view = on(&ops);
    assert_eq!(view.auto_sync.as_ref().unwrap().enabled_by, ops.id);
    assert_eq!(view.auto_sync.unwrap().timeout_secs, 120);
    assert_eq!(f.audits("forwarding_chain.auto_sync"), 1);

    // A group change starts a refresh as that user, run to the end.
    f.set_members(&first, &[1, 2, 4]);
    f.advance();
    let refresh = f.refresh(&chain.id);
    assert!(refresh.automatic && refresh.actor_id == ops.id);
    assert_eq!(refresh.deadline_ms - refresh.started_at_ms, 120_000);
    for _ in 0..4 {
        f.report_all();
        f.advance();
    }
    let listed = f.use_of(&chain.id);
    assert_eq!(
        listed.refresh.unwrap().outcome,
        Some(RefreshOutcome::Succeeded)
    );
    assert!(!listed.out_of_date);
    assert_eq!(listed.auto_sync.unwrap().failures, 0);

    // A refresh that cannot start backs off, and stops after three.
    let third = f.group("Last", &[5]);
    f.store
        .update_chain(
            &f.admin,
            &chain.id,
            chain_input(
                "Asia",
                true,
                &[
                    (&first, Balance::SourceHash),
                    (&second, Balance::WeightedRoundRobin),
                    (&third, Balance::WeightedRoundRobin),
                ],
            ),
        )
        .unwrap();
    f.advance();
    let sync = f.use_of(&chain.id).auto_sync.unwrap();
    assert_eq!(sync.failures, 1);
    assert!(sync.last_result.unwrap().contains("could not start"));
    let first_retry = sync.next_attempt_ms;
    f.advance();
    assert_eq!(f.use_of(&chain.id).auto_sync.unwrap().failures, 1);
    f.store.advance_chain_refreshes_at(first_retry).unwrap();
    let sync = f.use_of(&chain.id).auto_sync.unwrap();
    assert_eq!(sync.failures, 2);
    assert!(sync.next_attempt_ms - first_retry >= 10 * 60_000);
    f.store
        .advance_chain_refreshes_at(sync.next_attempt_ms)
        .unwrap();
    let listed = f.use_of(&chain.id);
    assert!(listed.auto_sync.is_none());
    assert!(
        listed
            .auto_sync_stopped
            .unwrap()
            .contains("3 automatic refreshes")
    );
    assert_eq!(f.audits("forwarding_chain.auto_sync_failure"), 3);
    let revisions = f.revisions();

    // Turned on again by a user who is then disabled: it stops itself
    // instead of acting with the old permission.
    f.store
        .update_chain(
            &f.admin,
            &chain.id,
            chain_input(
                "Asia",
                true,
                &[
                    (&first, Balance::SourceHash),
                    (&second, Balance::WeightedRoundRobin),
                ],
            ),
        )
        .unwrap();
    on(&ops);
    f.store.set_user_disabled(&f.admin, &ops.id, true).unwrap();
    f.set_members(&first, &[1, 2]);
    f.advance();
    let listed = f.use_of(&chain.id);
    assert!(listed.auto_sync.is_none());
    assert!(listed.auto_sync_stopped.unwrap().contains("disabled"));
    assert!(listed.out_of_date);
    assert_eq!(f.revisions()[0], revisions[0]);
}

/// Runs the refresh `running()` needs once relay 4 replaces relay 2 up to
/// its stop: the entry rule is disabled, its agent applied that, and the
/// entry reports a session of another rule, which holds the rewire.
fn stop_entry(f: &Fixture, chain: &str, first: &GroupView, entry: &str) -> RefreshView {
    f.set_members(first, &[1, 4]);
    let plan = f.plan_refresh(chain, entry);
    assert!(plan.conflicts.is_empty(), "{:?}", plan.conflicts);
    f.confirm(chain, entry, &plan).unwrap();
    f.report_all();
    f.advance();
    assert_eq!(f.refresh(chain).phase, RefreshPhase::Draining);
    f.report_all();
    f.advance();
    assert!(!f.rule(0, entry).enabled);
    f.report(0, 1);
    f.advance();
    let view = f.refresh(chain);
    assert_eq!(
        (view.phase, view.stage),
        (RefreshPhase::Stopping, "updating")
    );
    assert_eq!(view.waiting[0].node_id, f.id(0));
    view
}
fn message(error: &anyhow::Error) -> String {
    error.downcast_ref::<Rejection>().unwrap().message.clone()
}

#[test]
fn a_refresh_continues_after_a_restart_with_its_original_deadline() {
    // Stopped and waiting when the controller restarts: the deadline still
    // counts from the confirmation, and the restore runs at it.
    let (f, chain, first, _, entry) = running();
    let started = stop_entry(&f, &chain.id, &first, &entry);
    let f = f.restart();
    let view = f.refresh(&chain.id);
    assert_eq!(view.phase, RefreshPhase::Stopping);
    assert_eq!(view.deadline_ms, started.deadline_ms);
    f.at(started.deadline_ms - 1);
    let view = f.refresh(&chain.id);
    assert_eq!((view.phase, view.outcome), (RefreshPhase::Stopping, None));
    f.at(started.deadline_ms);
    let view = f.refresh(&chain.id);
    assert_eq!(view.stage, "restore_confirming");
    assert!(
        view.error
            .as_deref()
            .unwrap()
            .contains("timed out after 600 s"),
        "{view:?}"
    );
    assert!(f.rule(0, &entry).enabled);
    // Restarted while its agents confirm the restore, and in the cleanup.
    let f = f.restart();
    f.report_all();
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Cleanup);
    let f = f.restart();
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Finished);
    assert!(f.config(4).rules.is_empty());

    // Restarted while draining and while confirming: it goes on forward.
    f.report_all();
    let plan = f.plan_refresh(&chain.id, &entry);
    let started = f.confirm(&chain.id, &entry, &plan).unwrap();
    f.report_all();
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Draining);
    let f = f.restart();
    f.report_all();
    f.advance();
    f.report_all();
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Confirming);
    let f = f.restart();
    f.report_all();
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.outcome, Some(RefreshOutcome::Succeeded));
    assert_eq!(view.id, started.id);
    assert_eq!(vias(&f.rule(0, &entry)), vec![f.id(1), f.id(4)]);
}

/// Putting a forwarding back changes only the fields the refresh still
/// owns, decided write by write by revision: a write by someone else that
/// changed a field takes it over, even when a later write set it back.
#[test]
fn a_restore_puts_back_only_what_the_refresh_still_owns() {
    // A new name and a save of the same `enabled`: the save cannot ask to
    // keep the rule stopped, so it is enabled again, keeping the name.
    let (f, chain, first, _, entry) = running();
    stop_entry(&f, &chain.id, &first, &entry);
    f.edit_rule(0, &entry, |rule| rule.name = "Renamed".into());
    f.edit_rule(0, &entry, |rule| rule.enabled = false);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.outcome, Some(RefreshOutcome::Failed));
    assert_eq!(view.failed_in, Some(RefreshPhase::Stopping));
    assert!(view.error.as_deref().unwrap().contains("someone else"));
    let rule = f.rule(0, &entry);
    assert!(rule.enabled && rule.targets.iter().all(|t| !t.paused));
    assert_eq!(rule.name, "Renamed");
    assert_eq!(vias(&rule), vec![f.id(1), f.id(2)]);
    assert!(view.unresolved.is_empty());
    assert!(
        view.notes
            .iter()
            .any(|n| n.contains("a save cannot ask to keep it stopped")),
        "{:?}",
        view.notes
    );
    assert!(f.config(4).rules.iter().all(|r| !r.enabled));

    // Enabled and disabled again by someone else while the entry was idle:
    // the value the stop wrote, but theirs now. It stays disabled; the
    // pause is still the refresh's and is resumed.
    let (f, chain, first, _, entry) = running();
    stop_entry(&f, &chain.id, &first, &entry);
    f.report(0, 0);
    f.edit_rule(0, &entry, |rule| rule.enabled = true);
    f.edit_rule(0, &entry, |rule| rule.enabled = false);
    f.report(0, 1);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.outcome, Some(RefreshOutcome::Failed));
    assert!(view.error.as_deref().unwrap().contains("someone else"));
    let rule = f.rule(0, &entry);
    assert!(!rule.enabled && rule.targets.iter().all(|t| !t.paused));
    assert!(
        view.notes
            .iter()
            .any(|n| n.contains("enabled or disabled by someone else")),
        "{:?}",
        view.notes
    );
    // Never rewired: the operator's disable is not overridden.
    assert!(view.commits.iter().all(|c| c.step != RefreshStep::Rewire));

    // Enabled by someone else: left enabled, as they set it.
    let (f, chain, first, _, entry) = running();
    stop_entry(&f, &chain.id, &first, &entry);
    f.report(0, 0);
    f.edit_rule(0, &entry, |rule| rule.enabled = true);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.outcome, Some(RefreshOutcome::Failed));
    let rule = f.rule(0, &entry);
    assert!(rule.enabled && rule.targets.iter().all(|t| !t.paused));
    assert_eq!(vias(&rule), vec![f.id(1), f.id(2)]);
    assert!(
        view.notes
            .iter()
            .any(|n| n.contains("enabled or disabled by someone else"))
    );

    // Maintenance drains relay 1 during the refresh: `draining` is not the
    // refresh's and is kept.
    let (f, chain, first, _, entry) = running();
    stop_entry(&f, &chain.id, &first, &entry);
    f.store.drain_node(&f.admin, &f.id(1), true).unwrap();
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.outcome, Some(RefreshOutcome::Failed));
    let rule = f.rule(0, &entry);
    assert!(rule.enabled && rule.targets.iter().all(|t| !t.paused));
    let draining: Vec<(String, bool)> = rule
        .targets
        .iter()
        .map(|t| (t.via.as_ref().unwrap().node_id.clone(), t.draining))
        .collect();
    assert_eq!(draining, vec![(f.id(1), true), (f.id(2), false)]);

    // Renamed after the pause, before the stop: the same.
    let (f, chain, first, _, entry) = running();
    f.set_members(&first, &[1, 4]);
    let plan = f.plan_refresh(&chain.id, &entry);
    f.confirm(&chain.id, &entry, &plan).unwrap();
    f.report_all();
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Draining);
    f.edit_rule(0, &entry, |rule| rule.name = "Renamed while paused".into());
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.failed_in, Some(RefreshPhase::Draining));
    let rule = f.rule(0, &entry);
    assert!(rule.enabled && rule.targets.iter().all(|t| !t.paused));
    assert_eq!(rule.name, "Renamed while paused");
    assert!(view.commits.iter().all(|c| c.step != RefreshStep::Stop));

    // Someone renamed the rule the refresh added: it ends, and the restore
    // disables that rule but keeps their change; the cleanup does not delete
    // a rule someone else changed.
    let (f, chain, first, _, entry) = running();
    stop_entry(&f, &chain.id, &first, &entry);
    let added = f.config(4).rules[0].id.clone();
    f.edit_rule(4, &added, |rule| rule.name = "Kept by them".into());
    f.report_all();
    f.advance();
    assert_eq!(f.refresh(&chain.id).outcome, Some(RefreshOutcome::Failed));
    for _ in 0..3 {
        f.report_all();
        f.advance();
    }
    let view = f.refresh(&chain.id);
    assert_eq!(view.phase, RefreshPhase::Finished);
    let kept = f.rule(4, &added);
    assert!(!kept.enabled && kept.name == "Kept by them");
    assert!(
        view.notes
            .iter()
            .any(|n| n.contains("left in place") && n.contains("Kept by them")),
        "{:?}",
        view.notes
    );
}

#[test]
fn cancelling_can_keep_the_stopped_rules_stopped() {
    let (f, chain, first, _, entry) = running();
    let viewer = f
        .store
        .create_user(&f.admin, "default", "viewer", PASSWORD, Role::Viewer)
        .unwrap();
    let started = stop_entry(&f, &chain.id, &first, &entry);
    let keep = CancelInput { keep_stopped: true };
    assert_eq!(
        status(
            f.store
                .cancel_chain_refresh(&viewer, &chain.id, &entry, keep)
                .unwrap_err()
        ),
        403
    );
    let view = f.cancel(&chain.id, &entry, true).unwrap();
    assert_eq!(view.outcome, Some(RefreshOutcome::Cancelled));
    // The entry stays stopped; the pause is resumed, the new rule disabled.
    let rule = f.rule(0, &entry);
    assert!(!rule.enabled && rule.targets.iter().all(|t| !t.paused));
    assert!(f.config(4).rules.iter().all(|r| !r.enabled));
    assert_eq!(view.unresolved.len(), 1);
    assert_eq!(
        (&view.unresolved[0].node_id, &view.unresolved[0].rule_id),
        (&f.id(0), &entry)
    );
    assert!(view.unresolved[0].error.contains("keep its rules stopped"));
    assert!(view.unresolved[0].error.contains("no sessions"));
    assert!(
        f.steps(&started.id)
            .contains(&("cancel_keep_stopped".to_owned(), f.admin.id.clone()))
    );
    // Enabling it is the ordinary way, which still waits for an idle server.
    f.report(0, 1);
    let enable = |f: &Fixture| {
        let config = f.config(0);
        let mut rules = config.rules;
        rules.iter_mut().find(|r| r.id == entry).unwrap().enabled = true;
        f.store
            .set_config(&f.admin, &f.id(0), config.revision, rules)
    };
    let error = enable(&f).unwrap_err();
    assert!(message(&error).contains("topology stop is not confirmed"));
    assert_eq!(status(error), 409);
    f.report_all();
    f.advance();
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.phase, RefreshPhase::Finished);
    // Still interrupted: the entry is really disabled.
    assert!(view.interrupted);
    enable(&f).unwrap();
    assert!(!f.refresh(&chain.id).interrupted);

    // After the rewire neither cancelling nor keeping rules stopped works.
    let (f, chain, first, _, entry) = running();
    stop_entry(&f, &chain.id, &first, &entry);
    f.report(0, 0);
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Confirming);
    let error = f.cancel(&chain.id, &entry, true).unwrap_err();
    assert!(message(&error).contains("the ordinary way"), "{error}");
    assert_eq!(status(error), 409);
    assert_eq!(status(f.cancel(&chain.id, &entry, false).unwrap_err()), 409);

    // A server of the stopped rules deleted meanwhile has nothing left to
    // keep stopped: keeping the others stopped is not refused for it.
    let (f, chain, first, _, entry) = running();
    stop_entry(&f, &chain.id, &first, &entry);
    let revision = f
        .store
        .node_credential_status(&f.admin, &f.id(0))
        .unwrap()
        .revision;
    f.store
        .revoke_node_credential(
            &f.admin,
            &f.id(0),
            relay_platform::credential::RevokeCredential {
                operation_id: format!("retire-entry-{revision}"),
                expected_revision: revision,
                reason: "gone".into(),
            },
        )
        .unwrap();
    f.store.delete_node(&f.admin, &f.id(0)).unwrap();
    let view = f.cancel(&chain.id, &entry, true).unwrap();
    assert_eq!(view.outcome, Some(RefreshOutcome::Cancelled));
}

/// A restore is checked against the configuration it publishes into, in the
/// transaction that publishes it, with every check of an ordinary publish
/// but the idle one for exactly the rules it enables with their old routes.
#[test]
fn a_restore_is_checked_against_the_configuration_it_publishes_into() {
    // Rules outside the forwarding changed meanwhile, on its servers and
    // elsewhere: the refresh goes on, and the restore completes.
    let (f, chain, first, _, entry) = running();
    let started = stop_entry(&f, &chain.id, &first, &entry);
    f.occupy(5, "elsewhere", base_port(5) + 10);
    f.occupy(0, "beside", base_port(0) + 20);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!((view.phase, view.outcome), (RefreshPhase::Stopping, None));
    f.at(started.deadline_ms);
    let view = f.refresh(&chain.id);
    assert_eq!(view.stage, "restore_confirming");
    assert!(f.rule(0, &entry).enabled);
    assert!(f.rule(0, "beside").enabled && f.rule(5, "elsewhere").enabled);
    assert!(view.unresolved.is_empty() && view.retry_error.is_none());

    // A stop the agent confirms only after the restore was published does
    // not confirm the restore.
    let (f, chain, first, _, entry) = running();
    f.set_members(&first, &[1, 4]);
    let plan = f.plan_refresh(&chain.id, &entry);
    let started = f.confirm(&chain.id, &entry, &plan).unwrap();
    f.report_all();
    f.advance();
    f.report_all();
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.phase, RefreshPhase::Stopping);
    let stop = view
        .commits
        .iter()
        .find(|c| c.step == RefreshStep::Stop)
        .unwrap()
        .revisions[&f.id(0)];
    f.at(started.deadline_ms);
    assert_eq!(f.refresh(&chain.id).stage, "restore_confirming");
    f.report_as(0, Some(stop), None, 0, false);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.stage, "restore_confirming");
    assert!(view.interrupted);
    let agent = view.agents.iter().find(|a| a.node_id == f.id(0)).unwrap();
    assert_eq!((agent.step, agent.state), (RefreshStep::Restore, "pending"));
    f.report(0, 0);
    f.report(4, 0);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.phase, RefreshPhase::Cleanup);
    assert!(!view.interrupted);

    // Someone gave the entry's listener to another rule while the server was
    // idle: enabling the entry again would listen twice. The restore is
    // refused there and retried, shown as blocked, until that is resolved;
    // the rest is put back at once.
    let (f, chain, first, _, entry) = running();
    let started = stop_entry(&f, &chain.id, &first, &entry);
    f.report(0, 0);
    let port = f.rule(0, &entry).listen.port();
    f.occupy(0, "taker", port);
    f.report(0, 1);
    f.at(started.deadline_ms);
    let view = f.refresh(&chain.id);
    assert_eq!(
        (view.phase, view.stage),
        (RefreshPhase::Restoring, "restore_blocked")
    );
    assert!(
        view.retry_error
            .as_deref()
            .unwrap()
            .contains("duplicate listener"),
        "{view:?}"
    );
    assert!(view.interrupted && !f.rule(0, &entry).enabled);
    assert!(f.config(4).rules.iter().all(|r| !r.enabled));
    f.advance();
    assert_eq!(f.refresh(&chain.id).stage, "restore_blocked");
    let config = f.config(0);
    f.store
        .set_config(
            &f.admin,
            &f.id(0),
            config.revision,
            config
                .rules
                .into_iter()
                .filter(|r| r.id != "taker")
                .collect(),
        )
        .unwrap();
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.stage, "restore_confirming");
    assert!(view.retry_error.is_none() && f.rule(0, &entry).enabled);

    // Someone gave relay 1, on the path, another listener meanwhile: the
    // entry is not enabled into a path the refresh has not checked. It stays
    // stopped for an operator, with what to do; the rest is put back.
    let (f, chain, first, _, entry) = running();
    let one = hop(&f, &chain.id, 1, 1);
    stop_entry(&f, &chain.id, &first, &entry);
    f.edit_rule(1, &one, |rule| rule.enabled = false);
    f.report(1, 0);
    f.edit_rule(1, &one, |rule| {
        rule.listen = SocketAddr::from(([0, 0, 0, 0], base_port(1) + 30));
        rule.enabled = true;
    });
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.outcome, Some(RefreshOutcome::Failed));
    let rule = f.rule(0, &entry);
    assert!(!rule.enabled && rule.targets.iter().all(|t| !t.paused));
    assert!(f.config(4).rules.iter().all(|r| !r.enabled));
    let left: Vec<(String, String)> = view
        .unresolved
        .iter()
        .map(|u| (u.node_id.clone(), u.rule_id.clone()))
        .collect();
    assert_eq!(left, vec![(f.id(1), one.clone()), (f.id(0), entry.clone())]);
    assert!(view.unresolved[0].error.contains("another listener"));
    assert!(view.unresolved[1].error.contains("enable it"));
    f.report_all();
    f.advance();
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.phase, RefreshPhase::Finished);
    // Finished, but the forwarding really does not take connections.
    assert!(view.interrupted && view.unresolved.len() == 2);
}

/// A committed restore is not a restored forwarding: one an agent of the
/// path rejects or does not confirm in time is shown as such, with each
/// server's reason, and an operator can end a restore at any point. A
/// restore that could never be published leaves what it cannot put back to
/// an operator at once instead of retrying forever.
#[test]
fn a_restore_that_cannot_complete_is_shown_and_can_be_ended() {
    let pairs = |view: &RefreshView| -> BTreeSet<(String, String)> {
        view.unresolved
            .iter()
            .map(|u| (u.node_id.clone(), u.rule_id.clone()))
            .collect()
    };
    let count =
        |f: &Fixture, id: &str, step: &str| f.step_names(id).iter().filter(|s| *s == step).count();

    // Rejected by the entry's agent: not restored; then no longer rejected
    // but still not applied: overdue. Confirmed later, it goes on.
    let (f, chain, first, _, entry) = running();
    let started = stop_entry(&f, &chain.id, &first, &entry);
    f.at(started.deadline_ms);
    let view = f.refresh(&chain.id);
    assert_eq!(view.stage, "restore_confirming");
    assert!(view.interrupted && f.rule(0, &entry).enabled);
    let restore = f.config(0).revision;
    f.report_as(0, Some(restore - 1), Some("bind failed"), 0, false);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.stage, "restore_failed");
    assert!(view.interrupted);
    assert!(
        view.waiting
            .iter()
            .any(|w| w.node_id == f.id(0) && w.error.contains("bind failed")),
        "{:?}",
        view.waiting
    );
    f.report_as(0, Some(restore - 1), None, 0, false);
    f.advance();
    assert_eq!(f.refresh(&chain.id).stage, "restore_overdue");
    f.report_all();
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.phase, RefreshPhase::Cleanup);
    assert!(!view.interrupted);
    assert!(
        view.notes
            .iter()
            .any(|n| n.contains("after it was rejected or overdue"))
    );
    assert_eq!(count(&f, &view.id, "restore_rejected"), 1);

    // Not confirmed, with no error: overdue a minute after it was
    // committed, audited once. Ended by an operator then, what is published
    // stays; the forwarding counts as interrupted until the agent applies it.
    let (f, chain, first, _, entry) = running();
    let started = stop_entry(&f, &chain.id, &first, &entry);
    f.at(started.deadline_ms);
    f.at(started.deadline_ms + 59_999);
    assert_eq!(f.refresh(&chain.id).stage, "restore_confirming");
    f.at(started.deadline_ms + 60_000);
    let view = f.refresh(&chain.id);
    assert_eq!(view.stage, "restore_overdue");
    assert_eq!(view.waiting.len(), 1);
    assert_eq!(view.waiting[0].node_id, f.id(0));
    f.at(started.deadline_ms + 120_000);
    assert_eq!(count(&f, &started.id, "restore_overdue"), 1);
    let ended = f.cancel(&chain.id, &entry, false).unwrap();
    assert!(
        matches!(ended.phase, RefreshPhase::Cleanup | RefreshPhase::Finished),
        "{ended:?}"
    );
    assert!(ended.interrupted && ended.unresolved.is_empty());
    assert!(
        ended
            .notes
            .iter()
            .any(|n| n.contains("ended by an operator while agents had not confirmed"))
    );
    let steps = f.steps(&started.id);
    let at = |step: &str| steps.iter().find(|(s, _)| s == step).unwrap().1.clone();
    assert_eq!(at("end_restore"), f.admin.id);
    assert_eq!(at("restore_ended"), "chain-refresh");
    f.report_all();
    f.advance();
    assert!(!f.refresh(&chain.id).interrupted);

    // Refused by the controller (someone took the entry's listener): each
    // server's reason is listed, and an operator ends it. The entry stays
    // stopped with why and what to do; it is not retried any more.
    let (f, chain, first, _, entry) = running();
    let started = stop_entry(&f, &chain.id, &first, &entry);
    f.report(0, 0);
    let port = f.rule(0, &entry).listen.port();
    f.occupy(0, "taker", port);
    f.report(0, 1);
    f.at(started.deadline_ms);
    let view = f.refresh(&chain.id);
    assert_eq!(view.stage, "restore_blocked");
    assert_eq!(view.waiting.len(), 1);
    assert_eq!(view.waiting[0].node_id, f.id(0));
    assert!(view.waiting[0].error.contains("duplicate listener"));
    assert_eq!(
        status(f.cancel(&chain.id, &entry, true).unwrap_err()),
        409,
        "keeping rules stopped is for before the rewire"
    );
    let ended = f.cancel(&chain.id, &entry, false).unwrap();
    assert!(matches!(
        ended.phase,
        RefreshPhase::Cleanup | RefreshPhase::Finished
    ));
    assert_eq!(pairs(&ended), [(f.id(0), entry.clone())].into());
    let error = &ended.unresolved[0].error;
    assert!(
        error.contains("ended the restore")
            && error.contains("duplicate listener")
            && error.contains("enable it"),
        "{error}"
    );
    assert!(ended.interrupted && ended.retry_error.is_none());
    assert!(!f.rule(0, &entry).enabled && f.rule(0, "taker").enabled);
    assert!(f.config(4).rules.iter().all(|r| !r.enabled));
    let revision = f.config(0).revision;
    f.advance();
    assert_eq!(f.config(0).revision, revision);

    // Someone disabled the exit the relays route to after the stop (allowed,
    // as its upstream is stopped). Enabling the relays would be refused on
    // every try: they and the entry above them stay stopped for an operator
    // at once, with why; the pauses are resumed, and the refresh ends.
    let (f, chain, _, second, entry) = running();
    let one = hop(&f, &chain.id, 1, 1);
    let two = hop(&f, &chain.id, 1, 2);
    let exit = hop(&f, &chain.id, 2, 3);
    f.set_members(&second, &[3, 5]);
    let plan = f.plan_refresh(&chain.id, &entry);
    f.confirm(&chain.id, &entry, &plan).unwrap();
    f.report_all();
    f.advance();
    f.report_all();
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Stopping);
    f.edit_rule(3, &exit, |rule| rule.enabled = false);
    f.report_all();
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.outcome, Some(RefreshOutcome::Failed));
    assert!(view.error.as_deref().unwrap().contains("someone else"));
    assert_ne!(view.stage, "restore_blocked", "{:?}", view.retry_error);
    assert_eq!(
        pairs(&view),
        [
            (f.id(0), entry.clone()),
            (f.id(1), one.clone()),
            (f.id(2), two.clone())
        ]
        .into()
    );
    assert!(
        view.unresolved
            .iter()
            .all(|u| u.error.contains("its next hop")
                && u.error.contains("Enable that next hop first")),
        "{:?}",
        view.unresolved
    );
    for (index, id) in [(0, &entry), (1, &one), (2, &two)] {
        let rule = f.rule(index, id);
        assert!(!rule.enabled && rule.targets.iter().all(|t| !t.paused));
    }
    assert!(!f.rule(3, &exit).enabled, "their change stays");
    f.report_all();
    f.advance();
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.phase, RefreshPhase::Finished);
    assert!(view.interrupted);
}

/// Only the servers the forwarding runs on are waited for: a removed relay
/// whose agent is enrolled but gone, or a new server whose agent is, does not
/// keep a refresh from ending, nor anything else from going on.
#[test]
fn servers_off_the_path_do_not_hold_a_refresh() {
    // The removed relay never applies the rewire that disables its rule:
    // the refresh still succeeds; only its cleanup waits, which holds
    // nothing up.
    let (f, chain, first, _, entry) = running();
    let two = hop(&f, &chain.id, 1, 2);
    f.set_members(&first, &[1]);
    let plan = f.plan_refresh(&chain.id, &entry);
    assert!(plan.conflicts.is_empty(), "{:?}", plan.conflicts);
    f.confirm(&chain.id, &entry, &plan).unwrap();
    let alive = |f: &Fixture, up: &[usize]| {
        for index in up {
            f.report(*index, 0);
        }
    };
    for _ in 0..5 {
        alive(&f, &[0, 1, 3, 4, 5]);
        f.advance();
    }
    let view = f.refresh(&chain.id);
    assert_eq!(
        (view.phase, view.outcome),
        (RefreshPhase::Cleanup, Some(RefreshOutcome::Succeeded)),
        "{view:?}"
    );
    assert!(!view.interrupted && view.problems.is_empty());
    assert!(!f.rule(2, &two).enabled);
    assert!(
        view.agents
            .iter()
            .any(|a| a.node_id == f.id(2) && a.state == "pending")
    );
    assert!(
        view.waiting
            .iter()
            .any(|w| w.node_id == f.id(2) && w.error.contains("revoke and delete"))
    );
    // Another refresh of the forwarding starts and carries the cleanup on.
    f.set_members(&first, &[1, 4]);
    let plan = f.plan_refresh(&chain.id, &entry);
    let next = f.confirm(&chain.id, &entry, &plan).unwrap();
    assert_ne!(next.id, view.id);
    let record = f
        .store
        .metadata(&format!("chain_refresh:{entry}"))
        .unwrap()
        .unwrap();
    assert!(record.contains(&two));

    // The new server never applies its rule: the refresh waits for it
    // before pausing anything, gives up at its deadline, and the restore
    // that disables that rule does not wait for it either.
    let (f, chain, first, _, entry) = running();
    f.set_members(&first, &[1, 2, 4]);
    let plan = f.plan_refresh(&chain.id, &entry);
    let started = f.confirm(&chain.id, &entry, &plan).unwrap();
    alive(&f, &[0, 1, 2, 3, 5]);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.phase, RefreshPhase::Preparing);
    assert!(view.waiting.iter().any(|w| w.node_id == f.id(4)));
    f.at(started.deadline_ms);
    let view = f.refresh(&chain.id);
    assert_eq!(
        (view.phase, view.outcome),
        (RefreshPhase::Cleanup, Some(RefreshOutcome::Failed)),
        "{view:?}"
    );
    assert!(!view.interrupted);
    assert!(
        view.agents.iter().any(|a| a.node_id == f.id(4)
            && a.step == RefreshStep::Restore
            && a.state == "pending")
    );
    assert!(f.config(4).rules.iter().all(|r| !r.enabled));
    // Nothing is held up: the chain can be deleted.
    f.store.delete_chain(&f.admin, &chain.id).unwrap();
}

/// The restore runs every check of an ordinary publish but the idle one, on
/// the configuration as it is then: a speed-limit gate that applies since
/// the refresh began blocks it on a server whose agent does not enforce the
/// limit, visibly, and it goes on once that agent reports it does.
#[test]
fn a_gate_that_applies_since_the_start_blocks_the_restore_until_resolved() {
    let (f, chain, first, _, entry) = running();
    let started = stop_entry(&f, &chain.id, &first, &entry);
    // Every other server enforces upload limits; the entry's agent does
    // not, and with the entry stopped the rules' owner gets one.
    for index in 1..6 {
        f.report_as(index, None, None, 0, true);
    }
    f.store
        .set_user_rates(
            &f.admin,
            &f.admin.id,
            UserRateChange {
                upload_bytes_per_sec: Some(Some(1 << 20)),
                ..Default::default()
            },
        )
        .unwrap();
    f.at(started.deadline_ms);
    let view = f.refresh(&chain.id);
    assert_eq!(
        (view.phase, view.stage),
        (RefreshPhase::Restoring, "restore_blocked")
    );
    let error = view.retry_error.as_deref().unwrap();
    assert!(
        error.contains("srv-0") && error.contains("upload/download"),
        "{error}"
    );
    assert!(view.interrupted && !f.rule(0, &entry).enabled);
    assert!(f.config(4).rules.iter().all(|r| !r.enabled));
    f.advance();
    assert_eq!(f.refresh(&chain.id).stage, "restore_blocked");
    f.report_as(0, None, None, 1, true);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.stage, "restore_confirming");
    assert!(view.retry_error.is_none() && f.rule(0, &entry).enabled);
    // Put back in two commits: the rest at once, the entry once it passed.
    assert_eq!(
        f.step_names(&started.id),
        [
            "start",
            "pause",
            "stop",
            "abort",
            "restore",
            "restore",
            "restore_committed"
        ]
    );
}

/// A refused restore is not checked again on every pass: at once when what
/// its checks read changes (server revisions, apply errors, agents'
/// abilities), otherwise after 30 s. Lifting the owner's limit is none of
/// those, so the next 30 s retry picks it up.
#[test]
fn a_refused_restore_is_retried_on_a_change_or_after_30_seconds() {
    let (f, chain, first, _, entry) = running();
    let started = stop_entry(&f, &chain.id, &first, &entry);
    for index in 1..6 {
        f.report_as(index, None, None, 0, true);
    }
    let limit = |upload| {
        f.store
            .set_user_rates(
                &f.admin,
                &f.admin.id,
                UserRateChange {
                    upload_bytes_per_sec: Some(upload),
                    ..Default::default()
                },
            )
            .unwrap();
    };
    limit(Some(1 << 20));
    f.at(started.deadline_ms);
    assert_eq!(f.refresh(&chain.id).stage, "restore_blocked");
    let revisions: Vec<u64> = (0..6).map(|i| f.config(i).revision).collect();
    limit(None);
    assert_eq!(
        (0..6).map(|i| f.config(i).revision).collect::<Vec<_>>(),
        revisions
    );
    f.at(started.deadline_ms + 29_000);
    assert_eq!(f.refresh(&chain.id).stage, "restore_blocked");
    assert!(!f.rule(0, &entry).enabled);
    f.at(started.deadline_ms + 30_000);
    let view = f.refresh(&chain.id);
    assert_eq!(view.stage, "restore_confirming");
    assert!(view.retry_error.is_none() && f.rule(0, &entry).enabled);
}

/// Only a refresh's restore may enable a stopped rule while its server has
/// sessions: every ordinary way to publish is still refused under the same
/// conditions while the refresh runs.
#[test]
fn ordinary_publishes_still_wait_for_an_idle_server_during_a_refresh() {
    use relay_platform::{
        shared_rule::SharedRuleInput,
        template::TemplateInput,
        topology::{ConfigBatch, ConfigUpdate},
    };
    let (f, chain, first, _, entry) = running();
    stop_entry(&f, &chain.id, &first, &entry);
    let barrier = |error: anyhow::Error| {
        let text = format!("{error:#}");
        assert!(text.contains("topology stop is not confirmed"), "{text}");
        assert_eq!(status(error), 409);
    };
    let config = f.config(0);
    let mut enabled = config.rules.clone();
    enabled.iter_mut().find(|r| r.id == entry).unwrap().enabled = true;
    barrier(
        f.store
            .set_config(&f.admin, &f.id(0), config.revision, enabled.clone())
            .unwrap_err(),
    );
    barrier(
        f.store
            .publish_configs(
                &f.admin,
                ConfigBatch {
                    updates: vec![ConfigUpdate {
                        node_id: f.id(0),
                        expected_revision: config.revision,
                        rules: enabled,
                        rate_bytes_per_sec: None,
                        rate_limits: None,
                    }],
                },
            )
            .unwrap_err(),
    );
    // A template or a shared rule taking the stopped entry's listener.
    let port = f.rule(0, &entry).listen.port();
    let mut source = rule("192.0.2.50:80".parse().unwrap(), Protocol::Tcp);
    source.owner_id = f.admin.id.clone();
    let template = f
        .store
        .create_template(
            &f.admin,
            TemplateInput {
                tenant_id: None,
                name: "Preset".into(),
                description: String::new(),
                rule: source.clone(),
                variables: Default::default(),
            },
        )
        .unwrap();
    barrier(
        f.store
            .apply_template(
                &f.admin,
                &f.id(0),
                &template.id,
                config.revision,
                "Taker",
                SocketAddr::from(([0, 0, 0, 0], port)),
            )
            .unwrap_err(),
    );
    // A shared rule is refused earlier still: its precheck counts the
    // stopped rule's port as taken.
    source.owner_id = String::new();
    let error = f
        .store
        .create_shared_rule(
            &f.admin,
            SharedRuleInput {
                name: "Shared".into(),
                node_ids: vec![f.id(0)],
                listen_port: port,
                rule: source,
            },
        )
        .unwrap_err();
    assert!(format!("{error:#}").contains("already used"), "{error:#}");
    assert_eq!(status(error), 409);
    assert_eq!(f.config(0).revision, config.revision);
    // That 409 is the port check. The barrier itself on the shared-rule
    // path: a shared rule's line on the busy entry server that takes part in
    // the topology (it routes to relay 1 through `via`) may be disabled, but
    // enabling it again meets the same barrier.
    let one = hop(&f, &chain.id, 1, 1);
    let mut routed = rule("192.0.2.50:80".parse().unwrap(), Protocol::Tcp);
    routed.targets[0].address = f.rule(1, &one).advertise.unwrap();
    routed.targets[0].via = Some(relay_platform::model::RuleRef {
        node_id: f.id(1),
        rule_id: one.clone(),
    });
    let shared = f
        .store
        .create_shared_rule(
            &f.admin,
            SharedRuleInput {
                name: "Routed".into(),
                node_ids: vec![f.id(0)],
                listen_port: base_port(0) + 45,
                rule: routed,
            },
        )
        .unwrap();
    f.store
        .pause_shared_rule(&f.admin, &shared.id, true)
        .unwrap();
    f.report(0, 1);
    let paused = f.config(0).revision;
    barrier(
        f.store
            .pause_shared_rule(&f.admin, &shared.id, false)
            .unwrap_err(),
    );
    assert_eq!(f.config(0).revision, paused);
    // The refresh's own restore does not wait.
    f.cancel(&chain.id, &entry, false).unwrap();
    assert!(f.rule(0, &entry).enabled);
}

#[test]
fn after_the_rewire_a_refresh_only_goes_forward() {
    // The entry's agent rejects the rewire: blocked, never reversed, and
    // succeeded once the agent applies it.
    let (f, chain, first, _, entry) = running();
    let started = stop_entry(&f, &chain.id, &first, &entry);
    f.report(0, 0);
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Confirming);
    // Deleting the chain waits; it says when a confirming refresh can be
    // ended: once blocked, by a rejection or at its deadline.
    let error = f.store.delete_chain(&f.admin, &chain.id).unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("when an agent rejects the rewire, or at the refresh's deadline"),
        "{message}"
    );
    assert_eq!(status(error), 409);
    let rewired = f.config(0).revision;
    f.report_as(
        0,
        Some(rewired - 1),
        Some("address already in use"),
        0,
        false,
    );
    f.report(2, 0);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!((view.phase, view.stage), (RefreshPhase::Blocked, "blocked"));
    assert_eq!(view.outcome, Some(RefreshOutcome::Failed));
    assert_eq!(view.failed_in, Some(RefreshPhase::Confirming));
    assert!(
        view.error
            .as_deref()
            .unwrap()
            .contains("rejected the rewire")
    );
    assert_eq!(view.problems.len(), 1);
    assert_eq!(view.problems[0].node_id, f.id(0));
    assert!(view.problems[0].error.contains("address already in use"));
    assert!(view.interrupted);
    let agent = view.agents.iter().find(|a| a.node_id == f.id(0)).unwrap();
    assert_eq!((agent.step, agent.state), (RefreshStep::Rewire, "failed"));
    let rule = f.rule(0, &entry);
    assert!(rule.enabled);
    assert_eq!(vias(&rule), vec![f.id(1), f.id(4)]);
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Blocked);
    f.report(0, 0);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.outcome, Some(RefreshOutcome::Succeeded));
    assert_eq!(view.phase, RefreshPhase::Cleanup);
    assert!(view.failed_in.is_none() && view.problems.is_empty() && !view.interrupted);
    assert!(
        view.notes
            .iter()
            .any(|n| n.contains("after it was blocked") && n.contains("rejected the rewire")),
        "{:?}",
        view.notes
    );
    let names = f.step_names(&started.id);
    assert_eq!(names[names.len() - 3..], ["rewire", "blocked", "confirmed"]);

    // Not confirmed in time: blocked; an operator dismisses it as published.
    let (f, chain, first, _, entry) = running();
    let started = stop_entry(&f, &chain.id, &first, &entry);
    f.report(0, 0);
    f.advance();
    let view = f.refresh(&chain.id);
    let rewired_at = view
        .commits
        .iter()
        .find(|c| c.step == RefreshStep::Rewire)
        .unwrap()
        .at_ms;
    let due = started.deadline_ms.max(rewired_at + 60_000);
    f.at(due - 1);
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Confirming);
    f.at(due);
    let view = f.refresh(&chain.id);
    assert_eq!(view.stage, "blocked");
    assert!(
        view.error
            .as_deref()
            .unwrap()
            .contains("not every agent confirmed")
    );
    // Only the entry is waited for; the removed relay is not.
    let waiting: Vec<String> = view.problems.iter().map(|p| p.node_id.clone()).collect();
    assert_eq!(waiting, f.ids(&[0]));
    let view = f.cancel(&chain.id, &entry, false).unwrap();
    assert_eq!(view.phase, RefreshPhase::Cleanup);
    assert_eq!(view.outcome, Some(RefreshOutcome::Failed));
    assert!(
        view.notes
            .iter()
            .any(|n| n.contains("dismissed by an operator"))
    );
    let names = f.step_names(&started.id);
    assert_eq!(
        names[names.len() - 4..],
        ["rewire", "blocked", "cancel", "handed_over"]
    );
}

#[test]
fn apply_errors_refused_steps_and_lost_permission_put_the_forwarding_back() {
    let restored = |f: &Fixture, entry: &str| {
        let rule = f.rule(0, entry);
        rule.enabled && rule.targets.iter().all(|t| !t.paused)
    };
    // The new relay's agent cannot apply its rule.
    let (f, chain, first, _, entry) = running();
    f.set_members(&first, &[1, 4]);
    let plan = f.plan_refresh(&chain.id, &entry);
    f.confirm(&chain.id, &entry, &plan).unwrap();
    let added = f.config(4).revision;
    f.report_as(4, Some(added - 1), Some("port in use"), 0, false);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.failed_in, Some(RefreshPhase::Preparing));
    assert!(
        view.error
            .as_deref()
            .unwrap()
            .contains("could not apply its rule")
    );
    assert_eq!(view.problems[0].node_id, f.id(4));
    assert!(restored(&f, &entry));
    assert!(f.config(4).rules.iter().all(|r| !r.enabled));
    assert!(view.commits.iter().all(|c| c.step != RefreshStep::Pause));

    // The entry's agent cannot apply the stop.
    let (f, chain, first, _, entry) = running();
    f.set_members(&first, &[1, 4]);
    let plan = f.plan_refresh(&chain.id, &entry);
    f.confirm(&chain.id, &entry, &plan).unwrap();
    f.report_all();
    f.advance();
    f.report_all();
    f.advance();
    let stop = f.config(0).revision;
    f.report_as(0, Some(stop - 1), Some("cannot stop"), 0, false);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.failed_in, Some(RefreshPhase::Stopping));
    assert!(
        view.error
            .as_deref()
            .unwrap()
            .contains("could not apply the stop")
    );
    assert_eq!(view.problems[0].node_id, f.id(0));
    assert!(restored(&f, &entry));

    // A step refused when published: after the confirmation someone routed
    // a rule outside the forwarding into relay 1, which would have to stop.
    let (f, chain, _, second, entry) = running();
    let one = hop(&f, &chain.id, 1, 1);
    f.set_members(&second, &[3, 4]);
    let plan = f.plan_refresh(&chain.id, &entry);
    assert!(plan.conflicts.is_empty(), "{:?}", plan.conflicts);
    f.confirm(&chain.id, &entry, &plan).unwrap();
    let mut foreign = f.rule(1, &one);
    foreign.id = "foreign".into();
    foreign.meter_epoch = "foreign-epoch".into();
    foreign.advertise = None;
    foreign.listen = SocketAddr::from(([0, 0, 0, 0], base_port(5) + 10));
    foreign.targets[0].address = f.rule(1, &one).advertise.unwrap();
    foreign.targets[0].via = Some(relay_platform::model::RuleRef {
        node_id: f.id(1),
        rule_id: one.clone(),
    });
    let config = f.config(5);
    let mut rules = config.rules;
    rules.push(foreign);
    f.store
        .set_config(&f.admin, &f.id(5), config.revision, rules)
        .unwrap();
    f.report_all();
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Draining);
    f.report_all();
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.failed_in, Some(RefreshPhase::Draining));
    let error = view.error.as_deref().unwrap();
    assert!(
        error.contains("the stop step was refused") && error.contains("disabled next hop"),
        "{error}"
    );
    assert!(restored(&f, &entry));
    assert!(f.rule(1, &one).enabled && f.rule(1, &one).targets.iter().all(|t| !t.paused));
    assert!(f.config(4).rules.iter().all(|r| !r.enabled));

    // The user who started it loses permission after the stop: it stops
    // and the controller puts the forwarding back.
    let (f, chain, first, _, entry) = running();
    let ops = f
        .store
        .create_user(&f.admin, "default", "ops", PASSWORD, Role::TenantAdmin)
        .unwrap();
    f.set_members(&first, &[1, 4]);
    let plan = f
        .store
        .plan_chain_refresh(&ops, &chain.id, &entry, RefreshPlanInput::default())
        .unwrap();
    let started = f
        .store
        .refresh_chain_use(
            &ops,
            &chain.id,
            &entry,
            RefreshInput {
                token: plan.token.clone(),
                expected_revisions: plan.expected_revisions.clone(),
                timeout_secs: None,
            },
        )
        .unwrap();
    f.report_all();
    f.advance();
    f.report_all();
    f.advance();
    assert!(!f.rule(0, &entry).enabled);
    f.report(0, 1);
    f.store.set_user_disabled(&f.admin, &ops.id, true).unwrap();
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.failed_in, Some(RefreshPhase::Stopping));
    assert!(view.error.as_deref().unwrap().contains("lost permission"));
    assert!(restored(&f, &entry));
    let steps = f.steps(&started.id);
    let actor = |name: &str| steps.iter().find(|(s, _)| s == name).unwrap().1.clone();
    assert_eq!(actor("stop"), ops.id);
    assert_eq!(actor("abort"), "chain-refresh");
    assert_eq!(actor("restore"), "chain-refresh");
}

#[test]
fn refreshes_that_share_servers_do_not_run_together() {
    let (f, chain, _, second, entry) = running();
    let other = f
        .store
        .apply_chain(&f.admin, &chain.id, f.input(5))
        .unwrap()
        .entry_rule_id;
    f.report_all();
    f.set_members(&second, &[3, 4]);
    let plan = f.plan_refresh(&chain.id, &entry);
    assert!(plan.conflicts.is_empty(), "{:?}", plan.conflicts);
    // Both relays stop, and they carry the other forwarding too.
    assert!(
        plan.warnings
            .iter()
            .any(|w| w.node_id.as_deref() == Some(&f.id(1))
                && w.message.contains("other forwardings")),
        "{:?}",
        plan.warnings
    );
    f.confirm(&chain.id, &entry, &plan).unwrap();
    let plan = f.plan_refresh(&chain.id, &other);
    let error = f.confirm(&chain.id, &other, &plan).unwrap_err();
    assert!(message(&error).contains("another forwarding"), "{error}");
    assert_eq!(status(error), 409);
    // Automatic refresh of the other waits meanwhile, counting no failure.
    f.auto_sync(&f.admin, &chain.id, &other);
    f.advance();
    let listed = f.use_by(&chain.id, &other);
    assert!(listed.refresh.is_none());
    assert_eq!(listed.auto_sync.unwrap().failures, 0);
    for _ in 0..4 {
        f.report_all();
        f.advance();
    }
    let view = f.use_by(&chain.id, &entry).refresh.unwrap();
    assert_eq!(view.outcome, Some(RefreshOutcome::Succeeded));
    // Then it would wait on the first forwarding's sessions: an automatic
    // refresh does not start.
    f.report_all();
    f.advance();
    let listed = f.use_by(&chain.id, &other);
    assert!(listed.refresh.is_none());
    let sync = listed.auto_sync.unwrap();
    assert_eq!(sync.failures, 1);
    assert!(
        sync.last_result
            .as_deref()
            .unwrap()
            .contains("other forwardings"),
        "{sync:?}"
    );
}

#[test]
fn chains_and_removed_servers_can_be_deleted_after_a_refresh() {
    // The chain deleted while the refresh cleans up: the cleanup goes on and
    // its record is forgotten when done.
    let (f, chain, first, _, entry) = running();
    let two = hop(&f, &chain.id, 1, 2);
    stop_entry(&f, &chain.id, &first, &entry);
    f.report(0, 0);
    f.advance();
    f.report(0, 0);
    f.report(2, 1);
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Cleanup);
    f.store.delete_chain(&f.admin, &chain.id).unwrap();
    let key = format!("chain_refresh:{entry}");
    assert!(f.store.metadata(&key).unwrap().is_some());
    f.report(2, 0);
    f.advance();
    assert!(f.config(2).rules.iter().all(|r| r.id != two));
    assert!(f.store.metadata(&key).unwrap().is_none());

    // A removed server whose agent never enrolled: once the refresh is done
    // it can be deleted, although the refresh's record names it.
    let f = Fixture::new(6);
    let up = [0, 1, 3, 4];
    f.enroll(&up);
    let report = || {
        for index in up {
            f.report(index, 0);
        }
    };
    report();
    let first = f.group("Relays", &[1, 2]);
    let second = f.group("Exits", &[3]);
    let chain = f.chain(
        "Asia",
        &[
            (&first, Balance::SourceHash),
            (&second, Balance::WeightedRoundRobin),
        ],
    );
    let entry = f
        .store
        .apply_chain(&f.admin, &chain.id, f.input(0))
        .unwrap()
        .entry_rule_id;
    report();
    f.set_members(&first, &[1, 4]);
    let plan = f.plan_refresh(&chain.id, &entry);
    f.confirm(&chain.id, &entry, &plan).unwrap();
    for _ in 0..6 {
        report();
        f.advance();
    }
    let view = f.refresh(&chain.id);
    assert_eq!(view.phase, RefreshPhase::Finished);
    assert_eq!(view.outcome, Some(RefreshOutcome::Succeeded));
    let key = format!("chain_refresh:{entry}");
    assert!(f.store.metadata(&key).unwrap().unwrap().contains(&f.id(2)));
    f.store.delete_node(&f.admin, &f.id(2)).unwrap();
}

/// The refresh task keeps moving refreshes on when a stored record cannot
/// be read: each record is handled on its own.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_refresh_task_goes_on_past_a_record_it_cannot_read() {
    use std::time::Duration;
    use tokio::time::{Instant, sleep};
    let (f, chain, first, _, entry) = running();
    stop_entry(&f, &chain.id, &first, &entry);
    f.store
        .set_metadata("chain_refresh:unreadable", "{not json")
        .unwrap();
    f.store
        .set_metadata("chain_refresh:incomplete", r#"{"phase":"stopping"}"#)
        .unwrap();
    f.store.advance_chain_refreshes().unwrap();
    let stop = CancellationToken::new();
    let task = tokio::spawn(relay_platform::chain::run(
        f.store.clone(),
        Duration::from_millis(20),
        stop.clone(),
    ));
    // Cancelled: the restore is published at once, and the task sees its
    // agents confirm and cleans up.
    let view = f.cancel(&chain.id, &entry, false).unwrap();
    assert_eq!(view.stage, "restore_confirming");
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        f.report_all();
        if f.refresh(&chain.id).phase == RefreshPhase::Finished {
            break;
        }
        assert!(Instant::now() < until, "{:?}", f.refresh(&chain.id));
        sleep(Duration::from_millis(20)).await;
    }
    assert!(f.rule(0, &entry).enabled && f.config(4).rules.is_empty());
    assert!(!task.is_finished());
    stop.cancel();
    task.await.unwrap();
}

#[test]
fn automatic_refresh_runs_and_fails_like_a_confirmed_one() {
    let (f, chain, first, second, entry) = running();
    let ops = f
        .store
        .create_user(&f.admin, "default", "ops", PASSWORD, Role::TenantAdmin)
        .unwrap();
    // A manual refresh in progress: an automatic one does not start too.
    f.set_members(&first, &[1, 4]);
    let plan = f.plan_refresh(&chain.id, &entry);
    let manual = f.confirm(&chain.id, &entry, &plan).unwrap();
    f.auto_sync(&ops, &chain.id, &entry);
    f.advance();
    assert_eq!(f.refresh(&chain.id).id, manual.id);
    assert_eq!(f.use_of(&chain.id).auto_sync.unwrap().failures, 0);
    f.cancel(&chain.id, &entry, false).unwrap();
    f.report_all();
    f.advance();

    // Once that one is put back, it starts as the user who turned it on; it
    // times out with the entry busy and is put back. Its own commits are not
    // writes by someone else.
    let started = f.refresh(&chain.id);
    assert!(started.automatic && started.actor_id == ops.id && started.id != manual.id);
    f.report_all();
    f.advance();
    f.report_all();
    f.advance();
    assert!(!f.rule(0, &entry).enabled);
    f.report(0, 1);
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Stopping);
    f.at(started.deadline_ms);
    let view = f.refresh(&chain.id);
    assert_eq!(view.outcome, Some(RefreshOutcome::Failed));
    assert!(f.rule(0, &entry).enabled);
    assert!(
        view.notes.iter().all(|n| !n.contains("someone else")),
        "{:?}",
        view.notes
    );
    let sync = f.use_of(&chain.id).auto_sync.unwrap();
    assert_eq!(sync.failures, 1);
    assert!(sync.last_result.as_deref().unwrap().contains("timed out"));
    assert_eq!(sync.next_attempt_ms, started.deadline_ms + 5 * 60_000);
    assert_eq!(f.audits("forwarding_chain.auto_sync_failure"), 1);
    f.report_all();
    f.advance();
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Finished);
    // Not again before the backoff, though the group still differs.
    f.at(sync.next_attempt_ms - 1);
    assert_eq!(f.refresh(&chain.id).id, started.id);

    // Its user's own edits are writes by someone else, told by revision:
    // enabled and disabled again by that user, the entry stays disabled.
    f.at(sync.next_attempt_ms);
    let again = f.refresh(&chain.id);
    assert!(again.automatic && again.id != started.id);
    f.report_all();
    f.advance();
    f.report_all();
    f.advance();
    assert!(!f.rule(0, &entry).enabled);
    f.report(0, 0);
    let edit_as = |actor: &Actor, enabled: bool| {
        let config = f.config(0);
        let mut rules = config.rules;
        rules.iter_mut().find(|r| r.id == entry).unwrap().enabled = enabled;
        f.store
            .set_config(actor, &f.id(0), config.revision, rules)
            .unwrap();
    };
    edit_as(&ops, true);
    edit_as(&ops, false);
    f.report(0, 1);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.id, again.id);
    assert!(view.error.as_deref().unwrap().contains("someone else"));
    assert!(!f.rule(0, &entry).enabled);
    assert!(view.commits.iter().all(|c| c.step != RefreshStep::Rewire));
    f.report(0, 0);
    edit_as(&f.admin, true);

    // A disabled chain pauses automatic refresh without counting a failure.
    let failures = f.use_of(&chain.id).auto_sync.unwrap().failures;
    let layers = [
        (&first, Balance::SourceHash),
        (&second, Balance::WeightedRoundRobin),
    ];
    f.store
        .update_chain(&f.admin, &chain.id, chain_input("Asia", false, &layers))
        .unwrap();
    f.report_all();
    f.advance();
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Finished);
    f.at(i64::MAX / 4);
    let listed = f.use_of(&chain.id);
    assert_eq!(listed.refresh.unwrap().id, again.id);
    assert_eq!(listed.auto_sync.unwrap().failures, failures);
    f.store
        .update_chain(&f.admin, &chain.id, chain_input("Asia", true, &layers))
        .unwrap();

    // Its user deleted: it turns itself off instead of acting as them.
    f.store.delete_user(&f.admin, &ops.id).unwrap();
    f.at(i64::MAX / 2);
    let listed = f.use_of(&chain.id);
    assert!(listed.auto_sync.is_none());
    assert!(
        listed
            .auto_sync_stopped
            .unwrap()
            .contains("deleted or disabled")
    );
    assert_eq!(listed.refresh.unwrap().id, again.id);
}

/// A forwarding whose kept next hop has no advertised endpoint: the preview
/// names the conflict instead of failing, and the controller keeps serving
/// every tenant afterwards (its database lock is not poisoned).
#[test]
fn a_next_hop_without_an_endpoint_is_a_conflict_not_a_failure() {
    // Without agents the stop barrier lets the test edit routes freely.
    let f = Fixture::new(7);
    let first = f.group("Relays", &[1, 2]);
    let second = f.group("Exits", &[3, 4]);
    let chain = f.chain(
        "Asia",
        &[
            (&first, Balance::SourceHash),
            (&second, Balance::WeightedRoundRobin),
        ],
    );
    let entry = f
        .store
        .apply_chain(&f.admin, &chain.id, f.input(0))
        .unwrap()
        .entry_rule_id;
    // Layer 1 stops routing to server 4, which then gives up its endpoint:
    // stopped from the entry down, rerouted, and enabled again.
    let relays = [hop(&f, &chain.id, 1, 1), hop(&f, &chain.id, 1, 2)];
    f.edit_rule(0, &entry, |rule| rule.enabled = false);
    for (index, id) in [1, 2].into_iter().zip(&relays) {
        f.edit_rule(index, id, |rule| rule.enabled = false);
    }
    for (index, id) in [1, 2].into_iter().zip(&relays) {
        f.edit_rule(index, id, |rule| {
            rule.targets
                .retain(|t| t.via.as_ref().is_none_or(|via| via.node_id != f.id(4)));
            rule.enabled = true;
        });
    }
    f.edit_rule(0, &entry, |rule| rule.enabled = true);
    let exit = hop(&f, &chain.id, 2, 4);
    f.edit_rule(4, &exit, |rule| rule.enabled = false);
    f.edit_rule(4, &exit, |rule| {
        rule.advertise = None;
        rule.enabled = true;
    });
    // A tenant administrator adds a relay and previews.
    let ops = f
        .store
        .create_user(&f.admin, "default", "ops", PASSWORD, Role::TenantAdmin)
        .unwrap();
    f.set_members(&first, &[1, 2, 5]);
    // The entry and the new relay, which pause or get a rule, have agents
    // that can pause targets.
    f.enroll(&[0, 5]);
    f.report(0, 0);
    f.report(5, 0);
    let plan = f
        .store
        .plan_chain_refresh(&ops, &chain.id, &entry, RefreshPlanInput::default())
        .unwrap();
    assert!(
        plan.conflicts
            .iter()
            .any(|c| c.node_id.as_deref() == Some(&f.id(4))
                && c.message.contains("no advertised endpoint")),
        "{:?}",
        plan.conflicts
    );
    let confirm = f.store.refresh_chain_use(
        &ops,
        &chain.id,
        &entry,
        RefreshInput {
            token: plan.token.clone(),
            expected_revisions: plan.expected_revisions.clone(),
            timeout_secs: None,
        },
    );
    assert_eq!(status(confirm.unwrap_err()), 409);
    // An automatic refresh counts it as a failure and the task goes on.
    f.auto_sync(&ops, &chain.id, &entry);
    f.advance();
    let sync = f.use_of(&chain.id).auto_sync.unwrap();
    assert_eq!(sync.failures, 1);
    assert!(
        sync.last_result
            .as_deref()
            .unwrap()
            .contains("no advertised endpoint")
    );
    // Every tenant is still served.
    let tenant = f.store.create_tenant(&f.admin, "Other").unwrap();
    let outsider = f
        .store
        .create_user(&f.admin, &tenant, "outsider", PASSWORD, Role::TenantAdmin)
        .unwrap();
    assert!(f.store.chains(&outsider).unwrap().is_empty());
    let (node, _) = f.store.create_node(&f.admin, &tenant, "elsewhere").unwrap();
    f.store
        .create_endpoint_group(&outsider, group_input("Theirs", vec![node.id]))
        .unwrap();
    assert_eq!(
        f.plan_refresh(&chain.id, &entry).conflicts.len(),
        plan.conflicts.len()
    );
}

/// Agents older than 0.142.0 cannot take paused targets, and none reports
/// its version: a refresh asks for the reverse tunnel report that every
/// agent since 0.145.0 sends. Reports in the JSON shapes of 0.141.9 and
/// 0.144.0 are refused, as are servers that never reported; the preview,
/// the confirmation and an automatic run all stop before anything pauses.
#[test]
fn agents_that_cannot_pause_targets_are_refused_before_anything_changes() {
    let f = Fixture::new(5);
    f.enroll(&[0, 1, 2, 3, 4]);
    f.agent(0, Shape::V0_141_9);
    f.agent(3, Shape::V0_150_0);
    for index in [0, 1, 2, 3] {
        f.report(index, 0);
    }
    let first = f.group("Relays", &[1]);
    let second = f.group("Exits", &[2]);
    let chain = f.chain(
        "Asia",
        &[
            (&first, Balance::SourceHash),
            (&second, Balance::WeightedRoundRobin),
        ],
    );
    let entry = f
        .store
        .apply_chain(&f.admin, &chain.id, f.input(0))
        .unwrap()
        .entry_rule_id;
    for index in [0, 1, 2, 3] {
        f.report(index, 0);
    }
    f.set_members(&first, &[1, 3]);
    let before = f.revisions();
    let preview = || {
        f.store
            .plan_chain_refresh(&f.admin, &chain.id, &entry, RefreshPlanInput::default())
    };
    let confirm = || {
        f.store.refresh_chain_use(
            &f.admin,
            &chain.id,
            &entry,
            RefreshInput {
                token: "any".into(),
                expected_revisions: (0..5).map(|i| (f.id(i), before[i])).collect(),
                timeout_secs: None,
            },
        )
    };
    let refused = |error: anyhow::Error, server: usize, texts: &[&str]| {
        let message = format!("{error:#}");
        assert!(
            message.contains(
                "cannot be refreshed until these agents report they can take paused targets"
            ),
            "{message}"
        );
        for text in texts {
            assert!(message.contains(text), "{message}");
        }
        assert!(message.contains(&format!("srv-{server}")), "{message}");
        assert_eq!(failed_nodes(&error), vec![f.id(server)]);
        assert_eq!(status(error), 409);
    };
    let untouched = |f: &Fixture| {
        assert_eq!(f.revisions(), before);
        assert!(f.use_of(&chain.id).refresh.is_none());
        let rule = f.rule(0, &entry);
        assert!(rule.enabled && rule.targets.iter().all(|t| !t.paused));
    };
    // The entry, which would pause, reports as 0.141.9 and then 0.144.0:
    // too old either way (0.142.0 to 0.144.x are refused conservatively).
    for shape in [Shape::V0_141_9, Shape::V0_144_0] {
        f.agent(0, shape);
        f.report(0, 0);
        refused(
            preview().unwrap_err(),
            0,
            &["pauses targets on server srv-0", "too old"],
        );
        refused(confirm().unwrap_err(), 0, &["upgrade the agent to 0.145.0"]);
        untouched(&f);
    }
    // As 0.150.0: the entry passes; a new relay that never reported is
    // named as not connected yet.
    f.agent(0, Shape::V0_150_0);
    f.report(0, 0);
    f.set_members(&first, &[1, 3, 4]);
    let before = f.revisions();
    refused(
        preview().unwrap_err(),
        4,
        &[
            "adds rules to server srv-4",
            "has not connected to the panel yet",
        ],
    );
    assert_eq!(f.revisions(), before);
    // Automatic refresh waits for it, as for an agent not installed yet,
    // without counting a failure, and looks again 5 minutes later.
    f.auto_sync(&f.admin, &chain.id, &entry);
    f.advance();
    let sync = f.use_of(&chain.id).auto_sync.unwrap();
    assert_eq!(sync.failures, 0);
    let result = sync.last_result.clone().unwrap();
    assert!(
        result.starts_with("waiting:") && result.contains("has not connected"),
        "{result}"
    );
    assert_eq!(f.revisions(), before);
    assert!(f.use_of(&chain.id).refresh.is_none());
    // It connects as 0.144.0: too old, a failure.
    f.agent(4, Shape::V0_144_0);
    f.report(4, 0);
    f.at(sync.next_attempt_ms - 1);
    assert_eq!(f.use_of(&chain.id).auto_sync.unwrap().failures, 0);
    f.at(sync.next_attempt_ms);
    let sync = f.use_of(&chain.id).auto_sync.unwrap();
    assert_eq!(sync.failures, 1);
    let result = sync.last_result.unwrap();
    assert!(
        result.contains("could not start") && result.contains("too old"),
        "{result}"
    );
    assert_eq!(f.revisions(), before);
    assert!(f.use_of(&chain.id).refresh.is_none());
    // Once it reports as 0.150.0, the refresh goes ahead.
    f.agent(4, Shape::V0_150_0);
    f.report(4, 0);
    let plan = f.plan_refresh(&chain.id, &entry);
    assert!(plan.conflicts.is_empty(), "{:?}", plan.conflicts);
    let started = f.confirm(&chain.id, &entry, &plan).unwrap();
    assert_eq!(started.phase, RefreshPhase::Preparing);

    // A relay that pauses, above a changed second layer, is checked like
    // the entry.
    let f = Fixture::new(4);
    f.enroll(&[0, 1, 2, 3]);
    f.agent(1, Shape::V0_144_0);
    f.report_all();
    let first = f.group("Relays", &[1]);
    let second = f.group("Exits", &[2]);
    let chain = f.chain(
        "Asia",
        &[
            (&first, Balance::SourceHash),
            (&second, Balance::WeightedRoundRobin),
        ],
    );
    let entry = f
        .store
        .apply_chain(&f.admin, &chain.id, f.input(0))
        .unwrap()
        .entry_rule_id;
    f.report_all();
    f.set_members(&second, &[2, 3]);
    let error = f
        .store
        .plan_chain_refresh(&f.admin, &chain.id, &entry, RefreshPlanInput::default())
        .unwrap_err();
    let message = format!("{error:#}");
    assert!(
        message.contains("pauses targets on server srv-1") && message.contains("too old"),
        "{message}"
    );
    assert_eq!(failed_nodes(&error), vec![f.id(1)]);
    assert_eq!(status(error), 409);
}

/// Before the rewire, the stop also disables removed servers' rules that
/// route into what stops, and a restore enables them again while the entry
/// routes to them: their agents must apply it before the forwarding counts
/// as back. One that never applied the pause or the stop runs the
/// forwarding as it was and is not waited for.
#[test]
fn a_restore_waits_for_removed_servers_it_enables_again() {
    // Entry 0 → [1, 2] → [3] → [4]; relay 2 moves from layer 1 to layer 3.
    let moved = |f: &Fixture| {
        f.enroll(&[0, 1, 2, 3, 4]);
        f.report_all();
        let first = f.group("Relays", &[1, 2]);
        let second = f.group("Middle", &[3]);
        let third = f.group("Exits", &[4]);
        let chain = f.chain(
            "Long",
            &[
                (&first, Balance::SourceHash),
                (&second, Balance::WeightedRoundRobin),
                (&third, Balance::WeightedRoundRobin),
            ],
        );
        let entry = f
            .store
            .apply_chain(&f.admin, &chain.id, f.input(0))
            .unwrap()
            .entry_rule_id;
        f.report_all();
        let two = hop(f, &chain.id, 1, 2);
        f.set_members(&first, &[1]);
        f.set_members(&third, &[4, 2]);
        let plan = f.plan_refresh(&chain.id, &entry);
        assert!(plan.conflicts.is_empty(), "{:?}", plan.conflicts);
        let started = f.confirm(&chain.id, &entry, &plan).unwrap();
        (chain, entry, two, started)
    };
    let others = |f: &Fixture| {
        for index in [0, 1, 3, 4] {
            f.report(index, 0);
        }
    };

    // Relay 2 applied the stop, then does not apply the restore.
    let f = Fixture::new(5);
    let (chain, entry, two, started) = moved(&f);
    f.report_all();
    f.advance();
    f.report_all();
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Stopping);
    f.report_all();
    assert!(!f.rule(2, &two).enabled);
    f.report(3, 1);
    f.at(started.deadline_ms);
    assert!(f.rule(2, &two).enabled && f.rule(0, &entry).enabled);
    others(&f);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(
        (view.phase, view.stage),
        (RefreshPhase::Restoring, "restore_confirming")
    );
    assert!(view.interrupted);
    assert!(
        view.waiting.iter().any(|w| w.node_id == f.id(2)),
        "{:?}",
        view.waiting
    );
    let restored_at = view.commits.last().unwrap().at_ms;
    f.at(restored_at + 60_000);
    let view = f.refresh(&chain.id);
    assert_eq!(view.stage, "restore_overdue");
    assert!(view.interrupted && view.outcome == Some(RefreshOutcome::Failed));
    // Its agent rejects it: still not back.
    let restore = f.config(2).revision;
    f.report_as(2, Some(restore - 1), Some("bind failed"), 0, false);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.stage, "restore_failed");
    assert!(view.interrupted);
    // Applied: back, then the rule added on relay 2 is cleaned up.
    f.report(2, 0);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.phase, RefreshPhase::Cleanup);
    assert!(!view.interrupted);
    f.report_all();
    f.advance();
    f.report_all();
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Finished);

    // Ended before relay 2 applied the restore: the forwarding still counts
    // as interrupted, and the cleanup of the rule added on relay 2 waits
    // until relay 2 applied the restore.
    let f = Fixture::new(5);
    let (chain, entry, two, started) = moved(&f);
    f.report_all();
    f.advance();
    f.report_all();
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Stopping);
    f.report_all();
    f.report(3, 1);
    f.at(started.deadline_ms);
    others(&f);
    f.advance();
    assert_eq!(f.refresh(&chain.id).stage, "restore_confirming");
    let restore = f.config(2).revision;
    let ended = f.cancel(&chain.id, &entry, false).unwrap();
    assert_eq!(ended.phase, RefreshPhase::Cleanup);
    others(&f);
    f.report_as(2, Some(restore - 1), None, 0, false);
    f.advance();
    assert_eq!(f.config(2).revision, restore);
    let view = f.refresh(&chain.id);
    assert_eq!(view.phase, RefreshPhase::Cleanup);
    assert!(f.rule(2, &two).enabled);
    assert!(view.interrupted, "{:?}", view.agents);
    f.report_all();
    f.advance();
    assert!(f.config(2).revision > restore);
    let view = f.refresh(&chain.id);
    assert_eq!(view.phase, RefreshPhase::Finished);
    assert!(!view.interrupted);

    // Relay 2 applied the stop, then its agent restarts under a new lease
    // before the restore, which resets what it applied to 0: the restore
    // still waits for it, and sees the new process reject it.
    let f = Fixture::with_leases(5, &[2]);
    let (chain, entry, two, started) = moved(&f);
    f.report_all();
    f.advance();
    f.report_all();
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Stopping);
    f.report_all();
    f.report(3, 1);
    f.advance();
    f.new_lease(2);
    f.at(started.deadline_ms);
    assert!(f.rule(2, &two).enabled && f.rule(0, &entry).enabled);
    others(&f);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.stage, "restore_confirming");
    assert!(view.interrupted);
    assert!(
        view.waiting.iter().any(|w| w.node_id == f.id(2)),
        "{:?}",
        view.waiting
    );
    f.report_as(2, Some(0), Some("bind failed"), 0, false);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.stage, "restore_failed");
    assert!(view.interrupted);
    f.report(2, 0);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.phase, RefreshPhase::Cleanup);
    assert!(!view.interrupted);

    // Through the rewire: the entry no longer routes to relay 2's old rule,
    // which stays disabled, so the rewire does not wait for relay 2.
    let f = Fixture::new(5);
    let (chain, _entry, two, _started) = moved(&f);
    f.report_all();
    f.advance();
    f.report_all();
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Stopping);
    f.report_all();
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Confirming);
    others(&f);
    // Applied on the path: relay 2's stopped rule no longer counts.
    let view = f.refresh(&chain.id);
    assert_eq!(view.phase, RefreshPhase::Confirming);
    assert!(!view.interrupted && !f.rule(2, &two).enabled);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(
        (view.phase, view.outcome),
        (RefreshPhase::Cleanup, Some(RefreshOutcome::Succeeded))
    );
    assert!(!view.interrupted && !f.rule(2, &two).enabled);

    // Relay 2 applied only the rule the refresh added there, never the
    // pause or the stop: its data plane runs the forwarding as it was, so
    // the restore does not wait for it.
    let f = Fixture::new(5);
    let (chain, _entry, two, started) = moved(&f);
    f.report_all();
    f.advance();
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Draining);
    others(&f);
    f.advance();
    others(&f);
    assert_eq!(f.refresh(&chain.id).phase, RefreshPhase::Stopping);
    assert!(!f.rule(2, &two).enabled);
    f.report(3, 1);
    f.at(started.deadline_ms);
    others(&f);
    f.advance();
    let view = f.refresh(&chain.id);
    assert_eq!(view.phase, RefreshPhase::Cleanup, "{:?}", view.waiting);
    assert_eq!(view.outcome, Some(RefreshOutcome::Failed));
    assert!(!view.interrupted);
}

/// Ending a restore whose part on a new server was refused (another rule
/// routes to the rule the refresh added there) leaves that rule enabled:
/// it is listed for an operator, not taken for someone else's change.
#[test]
fn ending_a_restore_lists_an_added_rule_it_could_not_disable() {
    let (f, chain, first, _, entry) = running();
    stop_entry(&f, &chain.id, &first, &entry);
    let added = f.config(4).rules[0].id.clone();
    // Someone routes a rule on server 5 to the new relay.
    let config = f.config(5);
    let mut routed = rule("192.0.2.50:80".parse().unwrap(), Protocol::Tcp);
    routed.id = "routed".into();
    routed.meter_epoch = "routed-epoch".into();
    routed.owner_id = f.admin.id.clone();
    routed.listen = SocketAddr::from(([0, 0, 0, 0], base_port(5) + 30));
    routed.targets[0].address = f.rule(4, &added).advertise.unwrap();
    routed.targets[0].via = Some(relay_platform::model::RuleRef {
        node_id: f.id(4),
        rule_id: added.clone(),
    });
    let mut rules = config.rules;
    rules.push(routed);
    f.store
        .set_config(&f.admin, &f.id(5), config.revision, rules)
        .unwrap();
    let view = f.cancel(&chain.id, &entry, false).unwrap();
    assert_eq!(view.stage, "restore_blocked");
    assert!(view.waiting.iter().any(|w| w.node_id == f.id(4)));
    assert!(f.rule(0, &entry).enabled && f.rule(4, &added).enabled);
    let view = f.cancel(&chain.id, &entry, false).unwrap();
    f.report_all();
    f.advance();
    let view = if view.phase == RefreshPhase::Finished {
        view
    } else {
        f.refresh(&chain.id)
    };
    assert_eq!(view.phase, RefreshPhase::Finished);
    let left = view
        .unresolved
        .iter()
        .find(|u| u.node_id == f.id(4) && u.rule_id == added)
        .unwrap_or_else(|| panic!("{:?}", view.unresolved));
    assert!(
        left.error
            .contains("which this refresh added, is still enabled")
            && left.error.contains("delete it"),
        "{}",
        left.error
    );
    assert!(
        view.notes
            .iter()
            .all(|n| !n.contains("changed by someone else")),
        "{:?}",
        view.notes
    );
    assert!(f.rule(4, &added).enabled);
    let steps = f.step_names(&view.id);
    assert!(
        steps.ends_with(&["end_restore".into(), "restore_ended".into()]),
        "{steps:?}"
    );
}

/// An automatic-refresh pass that fails as a whole, as on a malformed
/// endpoint group record, is logged: the restore of another refresh in the
/// same pass goes on, and the pass does not fail.
#[test]
fn automatic_refresh_errors_do_not_hold_up_other_refreshes() {
    let (f, chain, first, _, entry) = running();
    f.auto_sync(&f.admin, &chain.id, &entry);
    let started = stop_entry(&f, &chain.id, &first, &entry);
    f.store
        .set_metadata("endpoint_group:broken", "{not json")
        .unwrap();
    f.at(started.deadline_ms);
    assert!(f.rule(0, &entry).enabled);
    assert!(f.step_names(&started.id).contains(&"restore".to_owned()));
    f.at(started.deadline_ms + 1);
}

/// A controller with its API on loopback and a real agent for each server
/// of `names`, each forwarding on three ports of 127.0.0.1 from `ports`,
/// once every agent reported; `task` also runs the refresh task.
struct Cluster {
    _temp: tempfile::TempDir,
    store: Store,
    admin: Actor,
    nodes: Vec<(Node, String)>,
    ports: Vec<u16>,
    agents: Vec<(
        CancellationToken,
        tokio::task::JoinHandle<anyhow::Result<()>>,
    )>,
    stop: CancellationToken,
}
async fn cluster(names: &[&str], task: bool) -> Cluster {
    use relay_platform::agent::{self, AgentOptions};
    use std::time::Duration;
    use tokio::time::{Instant, sleep};

    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let mut nodes = vec![];
    let mut ports = vec![];
    for name in names {
        let port = free_address().port();
        let settings = NodeSettings {
            forwarding: Some(ForwardingDefaults {
                host: "127.0.0.1".into(),
                listen_ip: None,
                port_start: port,
                port_end: port + 2,
                public_port_start: None,
            }),
            ..Default::default()
        };
        nodes.push(
            store
                .create_node_with_settings(&admin, "default", name, None, settings)
                .unwrap(),
        );
        ports.push(port);
    }
    let stop = CancellationToken::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let app = api::router(AppState::new(store.clone()).with_shutdown(stop.clone()));
    let shutdown = stop.clone();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await
        .unwrap();
    });
    if task {
        tokio::spawn(relay_platform::chain::run(
            store.clone(),
            Duration::from_millis(100),
            stop.clone(),
        ));
    }
    let mut agents = vec![];
    for (index, (node, token)) in nodes.iter().enumerate() {
        let secret = temp.path().join(format!("enroll-{index}.secret"));
        relay_platform::store::write_secret(&secret, token.as_bytes()).unwrap();
        let db = Store::open(&temp.path().join(format!("agent-{index}.db"))).unwrap();
        let options = AgentOptions {
            controller: origin.clone(),
            node_id: node.id.clone(),
            enrollment_token_file: Some(secret),
            ca_certificate: None,
            tls_directory: None,
            poll_interval: Duration::from_millis(50),
            controller_addresses: vec![],
            controller_proxy: None,
        };
        let halt = CancellationToken::new();
        agents.push((halt.clone(), tokio::spawn(agent::run(db, options, halt))));
    }
    let settled = || {
        store
            .nodes(&admin)
            .unwrap()
            .iter()
            .all(|n| n.last_seen_ms.is_some() && n.applied_revision == n.desired_revision)
    };
    let until = Instant::now() + Duration::from_secs(10);
    while !settled() {
        assert!(Instant::now() < until, "agents did not report");
        sleep(Duration::from_millis(20)).await;
    }
    Cluster {
        _temp: temp,
        store,
        admin,
        nodes,
        ports,
        agents,
        stop,
    }
}

/// Controller, refresh task and three real agents on loopback: entry →
/// relay → echo. Moving the layer from relay A to relay B pauses the entry
/// while an open session goes on, and finishes once it closes.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_agents_keep_open_sessions_and_switch_to_the_new_relay() {
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{Instant, sleep, timeout};

    let echo = tcp_echo().await;
    let Cluster {
        _temp,
        store,
        admin,
        nodes,
        mut agents,
        stop,
        ..
    } = cluster(&["entry", "relay-a", "relay-b"], true).await;
    let id = |index: usize| nodes[index].0.id.clone();
    let relays = store
        .create_endpoint_group(&admin, group_input("Relays", vec![id(1)]))
        .unwrap();
    let chain = store
        .create_chain(
            &admin,
            chain_input("Path", true, &[(&relays, Balance::WeightedRoundRobin)]),
        )
        .unwrap();
    let applied = store
        .apply_chain(
            &admin,
            &chain.id,
            BuildInput {
                entry_node_id: id(0),
                name: "Echo".into(),
                protocol: Protocol::Tcp,
                target: echo.address.to_string(),
                entry_port: None,
                owner_id: None,
                expected_revisions: None,
            },
        )
        .unwrap();
    let entry: SocketAddr = applied.hops[0].advertise.parse().unwrap();
    let roundtrip = |payload: &'static [u8]| async move {
        let attempt = async {
            let mut stream = TcpStream::connect(entry).await.ok()?;
            stream.write_all(payload).await.ok()?;
            let mut back = vec![0; payload.len()];
            stream.read_exact(&mut back).await.ok()?;
            Some(back == payload)
        };
        timeout(Duration::from_secs(2), attempt)
            .await
            .ok()
            .flatten()
            == Some(true)
    };
    let until = Instant::now() + Duration::from_secs(10);
    while !roundtrip(b"ready").await {
        assert!(Instant::now() < until, "the chain never forwarded");
        sleep(Duration::from_millis(50)).await;
    }
    let mut open = TcpStream::connect(entry).await.unwrap();
    open.write_all(b"one").await.unwrap();
    let mut back = [0; 3];
    open.read_exact(&mut back).await.unwrap();

    store
        .update_endpoint_group(&admin, &relays.id, group_input("Relays", vec![id(2)]))
        .unwrap();
    let plan = store
        .plan_chain_refresh(
            &admin,
            &chain.id,
            &applied.entry_rule_id,
            RefreshPlanInput::default(),
        )
        .unwrap();
    assert!(plan.conflicts.is_empty(), "{:?}", plan.conflicts);
    store
        .refresh_chain_use(
            &admin,
            &chain.id,
            &applied.entry_rule_id,
            RefreshInput {
                token: plan.token.clone(),
                expected_revisions: plan.expected_revisions.clone(),
                timeout_secs: Some(120),
            },
        )
        .unwrap();
    let refresh = || {
        store.chains(&admin).unwrap()[0].uses[0]
            .refresh
            .clone()
            .unwrap()
    };
    // Draining once the entry's agent applied the pause.
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        let view = refresh();
        let entry_node = store
            .nodes(&admin)
            .unwrap()
            .into_iter()
            .find(|n| n.id == id(0))
            .unwrap();
        if view.phase == RefreshPhase::Draining
            && entry_node.applied_revision == entry_node.desired_revision
        {
            break;
        }
        assert!(Instant::now() < until, "never drained: {view:?}");
        sleep(Duration::from_millis(20)).await;
    }
    // New connections are refused; the open session goes on and holds the
    // refresh.
    assert!(!roundtrip(b"new").await);
    open.write_all(b"two").await.unwrap();
    open.read_exact(&mut back).await.unwrap();
    assert_eq!(&back, b"two");
    sleep(Duration::from_millis(800)).await;
    let view = refresh();
    assert_eq!(view.phase, RefreshPhase::Draining);
    assert!(
        view.waiting.iter().any(|w| w.error.contains("TCP")),
        "{view:?}"
    );
    drop(open);
    let until = Instant::now() + Duration::from_secs(15);
    loop {
        let view = refresh();
        if view.phase == RefreshPhase::Finished {
            assert_eq!(view.outcome, Some(RefreshOutcome::Succeeded));
            break;
        }
        assert!(Instant::now() < until, "never finished: {view:?}");
        sleep(Duration::from_millis(50)).await;
    }
    // Relay A's rule is gone; with its agent stopped, the forwarding still
    // works, through relay B.
    assert!(store.config(&admin, &id(1), None).unwrap().rules.is_empty());
    let (halt, task) = agents.remove(1);
    halt.cancel();
    timeout(Duration::from_secs(5), task)
        .await
        .unwrap()
        .unwrap()
        .unwrap();
    let until = Instant::now() + Duration::from_secs(10);
    while !roundtrip(b"after").await {
        assert!(Instant::now() < until, "no forwarding through relay B");
        sleep(Duration::from_millis(50)).await;
    }
    for (halt, task) in agents {
        halt.cancel();
        let _ = timeout(Duration::from_secs(5), task).await;
    }
    stop.cancel();
}

/// Controller and three real agents on loopback: entry → relay A → echo,
/// and another rule on the entry server straight to echo. After the stop a
/// session of that other rule stays open past the deadline, sending and
/// receiving all along: the forwarding is put back by itself, new
/// connections go through relay A again, and the other session is not
/// touched. This one moves the refresh on itself and reaches the deadline by
/// passing that time instead of waiting a minute; the next one runs the
/// refresh task on the wall clock.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_agents_get_the_forwarding_back_when_another_session_outlasts_the_deadline() {
    another_session_outlasts_the_deadline(false).await;
}

/// The same with the controller's refresh task running as in production:
/// once the other session holds the stop, the test moves nothing on, a 60 s
/// deadline (the shortest allowed) passes on the wall clock and the task puts
/// the forwarding back by itself.
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn on_the_wall_clock_the_refresh_task_puts_the_forwarding_back_by_itself() {
    another_session_outlasts_the_deadline(true).await;
}

/// See the two tests above; `task` runs the refresh task and waits for real
/// time instead of moving the refresh on. The test moves the refresh to the
/// stop either way and starts the task only once the other session is
/// reported: started earlier, the task could find the entry idle before the
/// session opens and rewire, as it should.
async fn another_session_outlasts_the_deadline(task: bool) {
    use std::time::Duration;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpStream;
    use tokio::time::{Instant, sleep, timeout};

    let echo = tcp_echo().await;
    let Cluster {
        _temp,
        store,
        admin,
        nodes,
        ports,
        agents,
        stop,
    } = cluster(&["entry", "relay-a", "relay-b"], false).await;
    let id = |index: usize| nodes[index].0.id.clone();
    let relays = store
        .create_endpoint_group(&admin, group_input("Relays", vec![id(1)]))
        .unwrap();
    let chain = store
        .create_chain(
            &admin,
            chain_input("Path", true, &[(&relays, Balance::WeightedRoundRobin)]),
        )
        .unwrap();
    let applied = store
        .apply_chain(
            &admin,
            &chain.id,
            BuildInput {
                entry_node_id: id(0),
                name: "Echo".into(),
                protocol: Protocol::Tcp,
                target: echo.address.to_string(),
                entry_port: None,
                owner_id: None,
                expected_revisions: None,
            },
        )
        .unwrap();
    let entry_rule = applied.entry_rule_id.clone();
    let entry: SocketAddr = applied.hops[0].advertise.parse().unwrap();
    // Another rule of the entry server, outside the forwarding.
    let other_port = ports[0] + 2;
    let config = store.config(&admin, &id(0), None).unwrap();
    let mut other = rule(echo.address, Protocol::Tcp);
    other.id = "other".into();
    other.meter_epoch = "other-epoch".into();
    other.owner_id = admin.id.clone();
    other.listen = SocketAddr::from(([0, 0, 0, 0], other_port));
    let mut rules = config.rules;
    rules.push(other);
    store
        .set_config(&admin, &id(0), config.revision, rules)
        .unwrap();
    let other: SocketAddr = format!("127.0.0.1:{other_port}").parse().unwrap();
    let roundtrip = |address: SocketAddr, payload: &'static [u8]| async move {
        let attempt = async {
            let mut stream = TcpStream::connect(address).await.ok()?;
            stream.write_all(payload).await.ok()?;
            let mut back = vec![0; payload.len()];
            stream.read_exact(&mut back).await.ok()?;
            Some(back == payload)
        };
        timeout(Duration::from_secs(2), attempt)
            .await
            .ok()
            .flatten()
            == Some(true)
    };
    let until = Instant::now() + Duration::from_secs(10);
    while !(roundtrip(entry, b"ready").await && roundtrip(other, b"ready").await) {
        assert!(Instant::now() < until, "nothing forwarded");
        sleep(Duration::from_millis(50)).await;
    }
    let node = |index: usize| {
        store
            .nodes(&admin)
            .unwrap()
            .into_iter()
            .find(|n| n.id == id(index))
            .unwrap()
    };
    let refresh = || {
        store.chains(&admin).unwrap()[0].uses[0]
            .refresh
            .clone()
            .unwrap()
    };

    store
        .update_endpoint_group(&admin, &relays.id, group_input("Relays", vec![id(2)]))
        .unwrap();
    let plan = store
        .plan_chain_refresh(&admin, &chain.id, &entry_rule, RefreshPlanInput::default())
        .unwrap();
    assert!(plan.conflicts.is_empty(), "{:?}", plan.conflicts);
    // The preview warns that the other rule's sessions can hold it up.
    assert!(
        plan.warnings
            .iter()
            .any(|w| w.message.contains("other forwardings")),
        "{:?}",
        plan.warnings
    );
    let started = store
        .refresh_chain_use(
            &admin,
            &chain.id,
            &entry_rule,
            RefreshInput {
                token: plan.token.clone(),
                expected_revisions: plan.expected_revisions.clone(),
                timeout_secs: Some(60),
            },
        )
        .unwrap();
    // Moved on until the entry is stopped and its agent applied that.
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        if refresh().phase != RefreshPhase::Stopping {
            store.advance_chain_refreshes().unwrap();
        }
        let entry_node = node(0);
        if refresh().phase == RefreshPhase::Stopping
            && entry_node.applied_revision == entry_node.desired_revision
        {
            break;
        }
        assert!(Instant::now() < until, "never stopped: {:?}", refresh());
        sleep(Duration::from_millis(20)).await;
    }
    assert!(
        !store
            .config(&admin, &id(0), None)
            .unwrap()
            .rules
            .iter()
            .find(|r| r.id == entry_rule)
            .unwrap()
            .enabled
    );
    // A session of the other rule opens, stays open and sends and receives
    // every 250 ms until the end; any exchange that fails ends it.
    let mut open = TcpStream::connect(other).await.unwrap();
    let quiet = CancellationToken::new();
    let done = quiet.clone();
    let talker = tokio::spawn(async move {
        let mut sent = 0u32;
        loop {
            let message = format!("{sent:08}");
            let exchange = async {
                open.write_all(message.as_bytes()).await.ok()?;
                let mut back = [0; 8];
                open.read_exact(&mut back).await.ok()?;
                Some(back == message.as_bytes())
            };
            if timeout(Duration::from_secs(2), exchange)
                .await
                .ok()
                .flatten()
                != Some(true)
            {
                return Err(format!("exchange {sent} on the open session failed"));
            }
            sent += 1;
            tokio::select! {
                _ = done.cancelled() => return Ok(sent),
                _ = sleep(Duration::from_millis(250)) => {}
            }
        }
    });
    let until = Instant::now() + Duration::from_secs(10);
    while refresh()
        .servers
        .iter()
        .find(|s| s.node_id == id(0))
        .unwrap()
        .active_tcp
        == 0
    {
        assert!(Instant::now() < until, "the session was not reported");
        sleep(Duration::from_millis(20)).await;
    }
    // From here the refresh task runs as in production, at the tick
    // `cluster` gives it.
    if task {
        tokio::spawn(relay_platform::chain::run(
            store.clone(),
            Duration::from_millis(100),
            stop.clone(),
        ));
    }
    // It holds the rewire; the forwarding takes no new connections.
    for _ in 0..3 {
        if !task {
            store.advance_chain_refreshes().unwrap();
        }
        sleep(Duration::from_millis(200)).await;
    }
    let view = refresh();
    assert_eq!(view.phase, RefreshPhase::Stopping);
    assert!(view.waiting.iter().any(|w| w.node_id == id(0)), "{view:?}");
    assert!(view.interrupted);
    assert!(!roundtrip(entry, b"new").await);

    // Past the deadline it is put back at once, the session still open: by
    // the refresh task on the wall clock, or moved there by the test.
    if task {
        let now = || {
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_millis() as i64
        };
        let before = Duration::from_millis((started.deadline_ms - 2_000 - now()).max(0) as u64);
        sleep(before).await;
        let view = refresh();
        assert_eq!((view.phase, view.outcome), (RefreshPhase::Stopping, None));
        while refresh().outcome.is_none() {
            assert!(
                now() < started.deadline_ms + 5_000,
                "not put back by the deadline: {:?}",
                refresh()
            );
            sleep(Duration::from_millis(50)).await;
        }
        assert!(now() >= started.deadline_ms);
    } else {
        store
            .advance_chain_refreshes_at(started.deadline_ms)
            .unwrap();
    }
    let view = refresh();
    assert_eq!(view.outcome, Some(RefreshOutcome::Failed));
    assert!(view.error.as_deref().unwrap().contains("timed out"));
    let restored = store
        .config(&admin, &id(0), None)
        .unwrap()
        .rules
        .into_iter()
        .find(|r| r.id == entry_rule)
        .unwrap();
    assert!(restored.enabled);
    assert_eq!(vias(&restored), vec![id(1)]);
    let until = Instant::now() + Duration::from_secs(10);
    while !roundtrip(entry, b"after").await {
        assert!(Instant::now() < until, "the forwarding did not come back");
        sleep(Duration::from_millis(50)).await;
    }
    // Its agents confirm the restore and relay B's new rule goes.
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        if !task {
            store.advance_chain_refreshes().unwrap();
        }
        if refresh().phase == RefreshPhase::Finished {
            break;
        }
        assert!(Instant::now() < until, "never finished: {:?}", refresh());
        sleep(Duration::from_millis(50)).await;
    }
    let view = refresh();
    assert!(!view.interrupted && view.unresolved.is_empty());
    assert!(store.config(&admin, &id(2), None).unwrap().rules.is_empty());
    assert!(roundtrip(entry, b"again").await);
    // The other session went on all along: about four exchanges a second.
    quiet.cancel();
    let sent = talker.await.unwrap().unwrap();
    assert!(sent >= if task { 150 } else { 4 }, "{sent} exchanges");
    for (halt, task) in agents {
        halt.cancel();
        let _ = timeout(Duration::from_secs(5), task).await;
    }
    stop.cancel();
}
