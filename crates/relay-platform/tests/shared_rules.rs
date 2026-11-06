mod common;
use common::*;
use relay_platform::{
    api::{self, AppState},
    model::{NodeConfig, Protocol, Rule},
    node::{ForwardingDefaults, NodeSettings, NodeUpdate},
    shared_rule::{FromRuleInput, LineErrors, PrecheckInput, SharedRuleInput, SharedRuleView},
    store::{Actor, Node, Rejection, Role, Scope, Store},
};
use serde_json::{Value, json};
use std::net::SocketAddr;
use tokio_util::sync::CancellationToken;

struct Fixture {
    _temp: tempfile::TempDir,
    store: Store,
    admin: Actor,
    nodes: Vec<Node>,
}
impl Fixture {
    fn new(count: usize) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("controller.db")).unwrap();
        store.set_kind("controller").unwrap();
        let admin = store.bootstrap(PASSWORD).unwrap();
        let nodes = (0..count)
            .map(|index| {
                store
                    .create_node(&admin, "default", &format!("line-{index}"))
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
    /// Gives a node forwarding defaults: its port range and listen address.
    fn profile(&self, index: usize, start: u16, end: u16, listen_ip: Option<&str>) {
        let node = &self.nodes[index];
        self.store
            .update_node(
                &self.admin,
                &node.id,
                NodeUpdate {
                    expected_revision: node.profile.revision,
                    name: node.name.clone(),
                    settings: NodeSettings {
                        forwarding: Some(ForwardingDefaults {
                            host: format!("line{index}.example.net"),
                            listen_ip: listen_ip.map(|ip| ip.parse().unwrap()),
                            port_start: start,
                            port_end: end,
                            public_port_start: None,
                        }),
                        ..Default::default()
                    },
                },
            )
            .unwrap();
    }
    /// Adds an ordinary rule listening on `port..=end` to a node.
    fn ordinary(&self, index: usize, id: &str, port: u16, end: Option<u16>, enabled: bool) {
        let config = self.config(index);
        let mut rule = rule("192.0.2.50:80".parse().unwrap(), Protocol::Tcp);
        rule.id = id.into();
        rule.meter_epoch = format!("{id}-epoch");
        rule.owner_id = self.admin.id.clone();
        rule.name = id.into();
        rule.listen = SocketAddr::from(([0, 0, 0, 0], port));
        rule.listen_end_port = end;
        rule.enabled = enabled;
        let mut rules = config.rules;
        rules.push(rule);
        self.store
            .set_config(&self.admin, &self.id(index), config.revision, rules)
            .unwrap();
    }
    fn input(&self, name: &str, nodes: &[usize], port: u16, target: &str) -> SharedRuleInput {
        SharedRuleInput {
            name: name.into(),
            node_ids: self.ids(nodes),
            listen_port: port,
            rule: common_rule(target),
        }
    }
    fn create(&self, nodes: &[usize], port: u16) -> SharedRuleView {
        self.store
            .create_shared_rule(
                &self.admin,
                self.input("Web", nodes, port, "192.0.2.10:443"),
            )
            .unwrap()
    }
    fn view(&self, id: &str) -> SharedRuleView {
        self.store
            .shared_rules(&self.admin)
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
/// The common part of a shared rule as a client sends it.
fn common_rule(target: &str) -> Rule {
    let mut rule = rule(target.parse().unwrap(), Protocol::Tcp);
    rule.owner_id = String::new();
    rule.rate_bytes_per_sec = Some(125_000);
    rule
}
fn status(error: anyhow::Error) -> u16 {
    error.downcast_ref::<Rejection>().unwrap().status
}
fn member_rule(view: &SharedRuleView, index: usize) -> Rule {
    view.members[index].rule.clone().unwrap()
}

#[test]
fn create_publishes_the_same_rule_on_every_line_in_one_batch() {
    let f = Fixture::new(3);
    // Line 1 binds its forwarding listener to one address; the others have
    // no defaults and listen on every address.
    f.profile(1, 21000, 21999, Some("10.0.0.7"));
    let before = f.revisions();
    let batches = f.audits("config.batch_publish");
    let view = f.create(&[0, 1, 2], 21500);
    assert_eq!(view.listen_port, 21500);
    assert_eq!(view.members.len(), 3);
    assert!(view.drift.is_empty(), "{:?}", view.drift);
    let after = f.revisions();
    for index in 0..3 {
        assert_eq!(after[index], before[index] + 1);
        let config = f.config(index);
        assert_eq!(config.rules.len(), 1);
        let rule = &config.rules[0];
        assert_eq!(view.members[index].node_id, f.id(index));
        assert_eq!(view.members[index].rule_id, rule.id);
        assert_eq!(rule.name, "Web");
        assert_eq!(rule.listen.port(), 21500);
        assert_eq!(rule.targets[0].address, "192.0.2.10:443");
        assert_eq!(rule.rate_bytes_per_sec, Some(125_000));
        assert_eq!(rule.owner_id, f.admin.id);
        assert_ne!(rule.id, "rule-one", "a line must get a fresh rule id");
        assert_ne!(rule.meter_epoch, "epoch-one");
    }
    assert_eq!(
        f.config(1).rules[0].listen.to_string(),
        "10.0.0.7:21500",
        "the forwarding listen address of the node"
    );
    assert_eq!(f.config(0).rules[0].listen.to_string(), "0.0.0.0:21500");
    let ids: std::collections::HashSet<_> = (0..3)
        .map(|index| f.config(index).rules[0].id.clone())
        .collect();
    let epochs: std::collections::HashSet<_> = (0..3)
        .map(|index| f.config(index).rules[0].meter_epoch.clone())
        .collect();
    assert_eq!((ids.len(), epochs.len()), (3, 3));
    assert_eq!(f.audits("config.batch_publish"), batches + 1, "one batch");
    assert_eq!(f.audits("shared_rule.create"), 1);
    // Copyable entries: the node's forwarding host, unknown elsewhere.
    assert_eq!(
        view.members[1].entry.as_deref(),
        Some("line1.example.net:21500")
    );
    assert_eq!(view.members[0].entry, None);
}

#[test]
fn a_port_taken_on_one_line_fails_the_whole_create() {
    let f = Fixture::new(3);
    // A port range on line 1 covers the requested port without starting at it.
    f.ordinary(1, "range", 25998, Some(26002), false);
    let before = f.revisions();
    let error = f
        .store
        .create_shared_rule(
            &f.admin,
            f.input("Web", &[0, 1, 2], 26000, "192.0.2.10:443"),
        )
        .unwrap_err();
    let lines = error.downcast_ref::<LineErrors>().unwrap().0.clone();
    assert_eq!(status(error), 409);
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].node_id, f.id(1));
    assert_eq!(f.revisions(), before, "no node may change");
    assert!(f.store.shared_rules(&f.admin).unwrap().is_empty());
    // The same port on the other lines alone is fine.
    f.create(&[0, 2], 26000);
}

#[test]
fn precheck_picks_a_port_free_on_all_lines_inside_every_range() {
    let f = Fixture::new(3);
    f.profile(1, 25000, 26000, None);
    f.profile(2, 25500, 40000, None);
    // Line 0 keeps the default 20000–29999. The common range starts at 25500,
    // which line 0 uses; line 1 holds 25501–25503 as a range and line 2 a
    // disabled rule on 25504.
    f.ordinary(0, "first", 25500, None, true);
    f.ordinary(1, "range", 25501, Some(25503), true);
    f.ordinary(2, "stopped", 25504, None, false);
    let before = f.revisions();
    let check = |port: Option<u16>| {
        f.store
            .precheck_shared_rule(
                &f.admin,
                PrecheckInput {
                    id: None,
                    node_ids: f.ids(&[0, 1, 2]),
                    listen_port: port,
                    rule: common_rule("192.0.2.10:443"),
                },
            )
            .unwrap()
    };
    let picked = check(None);
    assert_eq!(picked.listen_port, Some(25505));
    assert!(picked.ok, "{picked:?}");
    assert!(
        picked
            .lines
            .iter()
            .all(|line| line.in_range && line.port_free && line.valid && !line.online)
    );
    assert_eq!(
        picked
            .lines
            .iter()
            .map(|line| (line.port_start, line.port_end))
            .collect::<Vec<_>>(),
        [(20000, 29999), (25000, 26000), (25500, 40000)]
    );
    let taken = check(Some(25502));
    assert!(!taken.ok);
    assert_eq!(
        taken
            .lines
            .iter()
            .map(|line| line.port_free)
            .collect::<Vec<_>>(),
        [true, false, true]
    );
    let outside = check(Some(30000));
    assert_eq!(
        outside
            .lines
            .iter()
            .map(|line| line.in_range)
            .collect::<Vec<_>>(),
        [false, false, true]
    );
    assert!(outside.ok, "a port outside a range is advice, not an error");
    assert_eq!(f.revisions(), before, "a precheck reserves nothing");
    // Ranges without a common free port report none.
    f.profile(0, 20000, 20010, None);
    let none = check(None);
    assert_eq!(none.listen_port, None);
    assert!(!none.ok && none.error.is_some());
}

#[test]
fn edits_keep_rule_ids_and_counters_until_the_port_changes() {
    let f = Fixture::new(3);
    f.profile(1, 21000, 21999, Some("10.0.0.7"));
    let view = f.create(&[0, 1, 2], 21500);
    let ids: Vec<_> = view.members.iter().map(|m| m.rule_id.clone()).collect();
    let epochs: Vec<_> = (0..3).map(|i| member_rule(&view, i).meter_epoch).collect();
    let mut input = f.input("Web v2", &[0, 1, 2], 21500, "192.0.2.20:8443");
    input.rule.max_connections = 77;
    let edited = f
        .store
        .update_shared_rule(&f.admin, &view.id, input)
        .unwrap();
    for index in 0..3 {
        let rule = f.config(index).rules[0].clone();
        assert_eq!(rule.id, ids[index]);
        assert_eq!(rule.meter_epoch, epochs[index], "counters continue");
        assert_eq!(rule.name, "Web v2");
        assert_eq!(rule.targets[0].address, "192.0.2.20:8443");
        assert_eq!(rule.max_connections, 77);
    }
    assert_eq!(edited.name, "Web v2");
    let moved = f
        .store
        .update_shared_rule(
            &f.admin,
            &view.id,
            f.input("Web v2", &[0, 1, 2], 21600, "192.0.2.20:8443"),
        )
        .unwrap();
    assert_eq!(moved.listen_port, 21600);
    for index in 0..3 {
        let rule = f.config(index).rules[0].clone();
        assert_eq!(rule.id, ids[index]);
        assert_eq!(rule.listen.port(), 21600);
        assert_ne!(
            rule.meter_epoch, epochs[index],
            "a new port restarts counters"
        );
    }
    assert_eq!(
        f.config(1).rules[0].listen.to_string(),
        "10.0.0.7:21600",
        "a line keeps its listen address"
    );
    assert_eq!(f.audits("shared_rule.update"), 2);
}

#[test]
fn lines_can_be_added_and_removed_but_not_all_removed() {
    let f = Fixture::new(4);
    f.ordinary(1, "neighbour", 9000, None, true);
    let view = f.create(&[0, 1, 2], 22000);
    let kept = view.members[0].rule_id.clone();
    let before = f.revisions();
    let changed = f
        .store
        .update_shared_rule(
            &f.admin,
            &view.id,
            f.input("Web", &[0, 2, 3], 22000, "192.0.2.10:443"),
        )
        .unwrap();
    assert_eq!(
        changed
            .members
            .iter()
            .map(|m| m.node_id.clone())
            .collect::<Vec<_>>(),
        f.ids(&[0, 2, 3])
    );
    assert_eq!(changed.members[0].rule_id, kept);
    let after = f.revisions();
    assert_eq!(after[0], before[0], "an unchanged line is not republished");
    assert_eq!(after[2], before[2]);
    assert_eq!(after[1], before[1] + 1);
    assert_eq!(after[3], before[3] + 1);
    let removed = f.config(1);
    assert_eq!(
        removed
            .rules
            .iter()
            .map(|r| r.id.as_str())
            .collect::<Vec<_>>(),
        ["neighbour"],
        "a removed line loses only its member rule"
    );
    assert_eq!(f.config(3).rules[0].listen.port(), 22000);
    let error = f
        .store
        .update_shared_rule(
            &f.admin,
            &view.id,
            f.input("Web", &[], 22000, "192.0.2.10:443"),
        )
        .unwrap_err();
    assert_eq!(status(error), 400);
    // A line whose rule was deleted on its own is dropped by the next save.
    let config = f.config(2);
    f.store
        .set_config(&f.admin, &f.id(2), config.revision, vec![])
        .unwrap();
    let listed = f.view(&view.id);
    assert!(listed.members[1].missing && listed.members[1].rule.is_none());
    let saved = f
        .store
        .update_shared_rule(
            &f.admin,
            &view.id,
            f.input("Web", &[0, 3], 22000, "192.0.2.10:443"),
        )
        .unwrap();
    assert_eq!(saved.members.len(), 2);
    assert!(f.config(2).rules.is_empty());
}

#[test]
fn pause_and_resume_switch_every_line() {
    let f = Fixture::new(2);
    let view = f.create(&[0, 1], 23000);
    let paused = f.store.pause_shared_rule(&f.admin, &view.id, true).unwrap();
    assert!(
        paused
            .members
            .iter()
            .all(|m| !m.rule.as_ref().unwrap().enabled)
    );
    assert!((0..2).all(|index| !f.config(index).rules[0].enabled));
    let before = f.revisions();
    f.store.pause_shared_rule(&f.admin, &view.id, true).unwrap();
    assert_eq!(f.revisions(), before, "pausing again changes nothing");
    f.store
        .pause_shared_rule(&f.admin, &view.id, false)
        .unwrap();
    assert!((0..2).all(|index| f.config(index).rules[0].enabled));
    assert_eq!(f.audits("shared_rule.pause"), 3);
}

#[test]
fn delete_removes_every_line_unless_the_rules_are_kept() {
    let f = Fixture::new(2);
    f.ordinary(0, "other", 9000, None, true);
    let view = f.create(&[0, 1], 24000);
    f.store
        .delete_shared_rule(&f.admin, &view.id, false)
        .unwrap();
    assert!(f.store.shared_rules(&f.admin).unwrap().is_empty());
    assert_eq!(
        f.config(0)
            .rules
            .iter()
            .map(|r| r.id.as_str())
            .collect::<Vec<_>>(),
        ["other"]
    );
    assert!(f.config(1).rules.is_empty());
    let kept = f.create(&[0, 1], 24000);
    let before = f.revisions();
    f.store
        .delete_shared_rule(&f.admin, &kept.id, true)
        .unwrap();
    assert_eq!(f.revisions(), before);
    assert!(f.store.shared_rules(&f.admin).unwrap().is_empty());
    assert_eq!(f.config(1).rules[0].id, kept.members[1].rule_id);
    assert_eq!(f.audits("shared_rule.delete"), 2);
    assert_eq!(
        status(
            f.store
                .delete_shared_rule(&f.admin, &kept.id, true)
                .unwrap_err()
        ),
        404
    );
}

#[test]
fn an_individual_edit_shows_as_drift_until_the_next_shared_save() {
    let f = Fixture::new(3);
    let view = f.create(&[0, 1, 2], 21500);
    let mut config = f.config(2);
    config.rules[0].targets[0].address = "192.0.2.99:443".into();
    config.rules[0].rate_bytes_per_sec = None;
    f.store
        .set_config(&f.admin, &f.id(2), config.revision, config.rules)
        .unwrap();
    let drifted = f.view(&view.id);
    assert_eq!(drifted.drift, ["rate_bytes_per_sec", "targets[0].address"]);
    assert!(drifted.members[0].drift.is_empty());
    assert!(drifted.members[1].drift.is_empty());
    assert_eq!(drifted.members[2].drift, drifted.drift);
    let saved = f
        .store
        .update_shared_rule(
            &f.admin,
            &view.id,
            f.input("Web", &[0, 1, 2], 21500, "192.0.2.10:443"),
        )
        .unwrap();
    assert!(saved.drift.is_empty(), "{:?}", saved.drift);
    assert_eq!(f.config(2).rules[0].targets[0].address, "192.0.2.10:443");
}

#[test]
fn extending_a_rule_keeps_it_as_the_first_line() {
    let f = Fixture::new(3);
    f.ordinary(0, "original", 21234, None, true);
    let before = f.revisions();
    let view = f
        .store
        .extend_rule(
            &f.admin,
            FromRuleInput {
                node_id: f.id(0),
                rule_id: "original".into(),
                add_node_ids: f.ids(&[1, 2]),
            },
        )
        .unwrap();
    assert_eq!(view.name, "original");
    assert_eq!(view.listen_port, 21234);
    assert_eq!(view.members[0].rule_id, "original");
    assert!(view.drift.is_empty(), "{:?}", view.drift);
    let after = f.revisions();
    assert_eq!(after[0], before[0], "the original rule is not touched");
    assert_eq!(f.config(0).rules[0].meter_epoch, "original-epoch");
    for index in 1..3 {
        let copy = &f.config(index).rules[0];
        assert_ne!(copy.id, "original");
        assert_eq!(copy.listen.port(), 21234);
        assert_eq!(copy.targets[0].address, "192.0.2.50:80");
    }
    let again = f.store.extend_rule(
        &f.admin,
        FromRuleInput {
            node_id: f.id(0),
            rule_id: "original".into(),
            add_node_ids: f.ids(&[1]),
        },
    );
    assert_eq!(status(again.unwrap_err()), 409);
    // A port range cannot be a shared rule.
    f.ordinary(1, "ranged", 23000, Some(23003), true);
    let ranged = f.store.extend_rule(
        &f.admin,
        FromRuleInput {
            node_id: f.id(1),
            rule_id: "ranged".into(),
            add_node_ids: f.ids(&[2]),
        },
    );
    assert_eq!(status(ranged.unwrap_err()), 400);
}

#[test]
fn tenants_are_isolated_and_viewers_cannot_change_shared_rules() {
    let f = Fixture::new(2);
    let view = f.create(&[0, 1], 21500);
    let tenant = f.store.create_tenant(&f.admin, "isolated").unwrap();
    let outsider = f
        .store
        .create_user(&f.admin, &tenant, "outsider", PASSWORD, Role::TenantAdmin)
        .unwrap();
    let viewer = f
        .store
        .create_user(&f.admin, "default", "readonly", PASSWORD, Role::Viewer)
        .unwrap();
    assert!(f.store.shared_rules(&outsider).unwrap().is_empty());
    assert_eq!(f.store.shared_rules(&viewer).unwrap().len(), 1);
    let input = || f.input("Web", &[0, 1], 21500, "192.0.2.10:443");
    for error in [
        f.store
            .update_shared_rule(&outsider, &view.id, input())
            .unwrap_err(),
        f.store
            .pause_shared_rule(&outsider, &view.id, true)
            .unwrap_err(),
        f.store
            .delete_shared_rule(&outsider, &view.id, false)
            .unwrap_err(),
        f.store.create_shared_rule(&outsider, input()).unwrap_err(),
    ] {
        assert_eq!(status(error), 404);
    }
    for error in [
        f.store
            .update_shared_rule(&viewer, &view.id, input())
            .unwrap_err(),
        f.store
            .pause_shared_rule(&viewer, &view.id, true)
            .unwrap_err(),
        f.store
            .delete_shared_rule(&viewer, &view.id, false)
            .unwrap_err(),
        f.store.create_shared_rule(&viewer, input()).unwrap_err(),
        f.store
            .precheck_shared_rule(
                &viewer,
                PrecheckInput {
                    id: None,
                    node_ids: f.ids(&[0]),
                    listen_port: None,
                    rule: common_rule("192.0.2.10:443"),
                },
            )
            .unwrap_err(),
    ] {
        assert_eq!(status(error), 403);
    }
    // Lines from two tenants cannot form one shared rule.
    let (foreign, _) = f.store.create_node(&f.admin, &tenant, "foreign").unwrap();
    let mut mixed = input();
    mixed.node_ids.push(foreign.id);
    mixed.listen_port = 21600;
    assert_eq!(
        status(f.store.create_shared_rule(&f.admin, mixed).unwrap_err()),
        400
    );
}

#[test]
fn a_deleted_node_leaves_its_line_missing() {
    let f = Fixture::new(2);
    let view = f.create(&[0, 1], 21500);
    f.store.delete_node(&f.admin, &f.id(1)).unwrap();
    let listed = f.view(&view.id);
    assert!(!listed.members[0].missing);
    assert!(listed.members[1].missing && listed.members[1].node_name.is_none());
    let saved = f
        .store
        .update_shared_rule(
            &f.admin,
            &view.id,
            f.input("Web", &[0], 21500, "192.0.2.10:443"),
        )
        .unwrap();
    assert_eq!(saved.members.len(), 1);
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
async fn the_api_creates_reports_conflicts_per_line_and_keeps_rules_on_delete() {
    let f = Fixture::new(3);
    f.ordinary(2, "busy", 26000, None, true);
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
    // Clients send only the common fields; identity is assigned per line.
    let rule = json!({"protocol": "tcp", "targets": [{"address": "192.0.2.10:443", "weight": 1}], "quota_bytes": null, "expires_at_ms": null, "rate_bytes_per_sec": null});
    let nodes = f.ids(&[0, 1, 2]);
    let (status, body) = call(
        reqwest::Method::POST,
        "/shared-rules",
        &admin,
        Some(json!({"name": "Web", "node_ids": nodes, "listen_port": 26000, "rule": rule})),
    )
    .await;
    assert_eq!(status, 409, "{body}");
    assert_eq!(body["lines"][0]["node_id"], f.id(2));
    let (status, check) = call(
        reqwest::Method::POST,
        "/shared-rules/precheck",
        &admin,
        Some(json!({"node_ids": nodes, "listen_port": null, "rule": rule})),
    )
    .await;
    assert_eq!(status, 200, "{check}");
    assert_eq!(check["listen_port"], 20000);
    // API tokens need the scopes of rules: `read` to list, `nodes:write` to check or change.
    let (reader, _) = f
        .store
        .create_api_token(&f.admin, "reader", &[Scope::Read], 1)
        .unwrap();
    let (writer, _) = f
        .store
        .create_api_token(&f.admin, "writer", &[Scope::NodesWrite], 1)
        .unwrap();
    let precheck = json!({"node_ids": nodes, "listen_port": 20000, "rule": rule});
    assert_eq!(
        call(reqwest::Method::GET, "/shared-rules", &reader, None)
            .await
            .0,
        200
    );
    assert_eq!(
        call(
            reqwest::Method::POST,
            "/shared-rules/precheck",
            &reader,
            Some(precheck.clone())
        )
        .await
        .0,
        403
    );
    assert_eq!(
        call(
            reqwest::Method::POST,
            "/shared-rules/precheck",
            &writer,
            Some(precheck)
        )
        .await
        .0,
        200
    );
    let (status, _) = call(
        reqwest::Method::POST,
        "/shared-rules",
        &viewer,
        Some(json!({"name": "Web", "node_ids": nodes, "listen_port": 20000, "rule": rule})),
    )
    .await;
    assert_eq!(status, 403);
    let (status, created) = call(
        reqwest::Method::POST,
        "/shared-rules",
        &admin,
        Some(json!({"name": "Web", "node_ids": nodes, "listen_port": 20000, "rule": rule})),
    )
    .await;
    assert_eq!(status, 200, "{created}");
    let id = created["id"].as_str().unwrap();
    let (status, listed) = call(reqwest::Method::GET, "/shared-rules", &viewer, None).await;
    assert_eq!(status, 200);
    assert_eq!(listed[0]["members"].as_array().unwrap().len(), 3);
    assert_eq!(listed[0]["drift"], json!([]));
    let (status, paused) = call(
        reqwest::Method::POST,
        &format!("/shared-rules/{id}/pause"),
        &admin,
        Some(json!({"paused": true})),
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(paused["members"][1]["rule"]["enabled"], false);
    let (status, _) = call(
        reqwest::Method::PUT,
        &format!("/shared-rules/{id}"),
        &admin,
        Some(json!({"name": "Web", "node_ids": [], "listen_port": 20000, "rule": rule})),
    )
    .await;
    assert_eq!(status, 400);
    let (status, _) = call(
        reqwest::Method::DELETE,
        &format!("/shared-rules/{id}?keep_rules=true"),
        &admin,
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert_eq!(f.config(0).rules.len(), 1, "kept as an ordinary rule");
    let (status, _) = call(
        reqwest::Method::POST,
        &format!("/shared-rules/{id}/pause"),
        &admin,
        Some(json!({"paused": false})),
    )
    .await;
    assert_eq!(status, 404);
    let kept = f.config(0).rules[0].id.clone();
    let (status, extended) = call(
        reqwest::Method::POST,
        "/shared-rules/from-rule",
        &admin,
        Some(json!({"node_id": f.id(0), "rule_id": kept, "add_node_ids": [f.id(2)]})),
    )
    .await;
    assert_eq!(status, 409, "line 2 already uses port 20000: {extended}");
    assert_eq!(extended["lines"][0]["node_id"], f.id(2));
    stop.cancel();
}
