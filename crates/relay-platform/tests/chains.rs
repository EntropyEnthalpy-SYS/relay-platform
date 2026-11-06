mod common;
use common::*;
use relay_platform::{
    api::{self, AppState},
    chain::{BuildInput, ChainInput, ChainPlan, ChainView, GroupInput, GroupView, Layer},
    model::{Balance, NodeConfig, Protocol, Rule},
    node::{ForwardingDefaults, NodeSettings, NodeUpdate},
    shared_rule::LineErrors,
    store::{Actor, Node, Rejection, Role, Scope, Store},
};
use serde_json::{Value, json};
use std::{collections::BTreeMap, net::SocketAddr};
use tokio_util::sync::CancellationToken;

const TARGET: &str = "192.0.2.80:443";

struct Fixture {
    _temp: tempfile::TempDir,
    store: Store,
    admin: Actor,
    nodes: Vec<Node>,
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
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("controller.db")).unwrap();
        store.set_kind("controller").unwrap();
        let admin = store.bootstrap(PASSWORD).unwrap();
        let nodes = (0..count)
            .map(|index| {
                let port = base_port(index);
                store
                    .create_node_with_settings(
                        &admin,
                        "default",
                        &format!("srv-{index}"),
                        None,
                        forwarding(index, port, port + 49),
                    )
                    .unwrap()
                    .0
            })
            .collect();
        Self {
            _temp: temp,
            store,
            admin,
            nodes,
        }
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
