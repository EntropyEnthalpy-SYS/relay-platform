use super::*;
use crate::node::{EndpointHop, NodeSettings, NodeUpdate};
use crate::topology::{ConfigBatch, ConfigUpdate};

struct Fixture {
    _tmp: tempfile::TempDir,
    db: Store,
    admin: Actor,
}
impl Fixture {
    fn new() -> Self {
        let tmp = tempfile::tempdir().unwrap();
        let db = Store::open(&tmp.path().join("controller.sqlite")).unwrap();
        let admin = db.bootstrap("endpoint-allocation-test-password").unwrap();
        Self {
            _tmp: tmp,
            db,
            admin,
        }
    }
    fn node(&self, name: &str, forwarding: Option<ForwardingDefaults>) -> String {
        self.db
            .create_node_with_settings(
                &self.admin,
                "default",
                name,
                None,
                NodeSettings {
                    forwarding,
                    ..Default::default()
                },
            )
            .unwrap()
            .0
            .id
    }
    fn allocate(&self, nodes: &[&str]) -> EndpointAllocation {
        self.db
            .allocate_endpoints(&self.admin, request(nodes))
            .unwrap()
    }
}
fn request(nodes: &[&str]) -> EndpointRequest {
    EndpointRequest {
        hops: nodes
            .iter()
            .map(|id| EndpointHop {
                node_id: (*id).into(),
                listen: None,
                advertise: None,
            })
            .collect(),
    }
}
fn defaults(host: &str) -> ForwardingDefaults {
    ForwardingDefaults {
        host: host.into(),
        ..Default::default()
    }
}
fn rule(id: &str, listen: &str, advertise: Option<&str>) -> Rule {
    serde_json::from_value(serde_json::json!({"id":id,"name":id,"tenant_id":"default","owner_id":"admin","listen":listen,"advertise":advertise,"protocol":"both","targets":[{"address":"192.0.2.250:80","weight":1}],"meter_epoch":"fixture"})).unwrap()
}
fn batch(node: &str, revision: u64, rules: Vec<Rule>) -> ConfigBatch {
    ConfigBatch {
        updates: vec![ConfigUpdate {
            node_id: node.into(),
            expected_revision: revision,
            rules,
            rate_bytes_per_sec: None,
        }],
    }
}

#[test]
fn defaults_validate_hosts_ipv6_nat_and_legacy_profile_compatibility() {
    let legacy: NodeSettings = serde_json::from_str("{}").unwrap();
    assert!(legacy.forwarding.is_none());
    for host in [
        "",
        "0.0.0.0",
        "::",
        "[::]",
        "::ffff:0.0.0.0",
        "255.255.255.255",
        "224.0.0.1",
        "example.com:9000",
        "https://example.com",
        "user@example.com",
        "example.com/path",
        " bad.example",
        "[[::1]]",
    ] {
        assert!(defaults(host).validate().is_err(), "accepted {host}");
    }
    let ipv6 = defaults("[2001:db8::10]");
    ipv6.validate().unwrap();
    assert_eq!(ipv6.endpoint(20000), "[2001:db8::10]:20000");
    assert_eq!(ipv6.bind_ip().to_string(), "::");
    assert_eq!(defaults("localhost").bind_ip().to_string(), "127.0.0.1");
    assert_eq!(defaults("127.0.0.1").bind_ip().to_string(), "127.0.0.1");
    assert_eq!(
        defaults("RELAY.Example.").endpoint(20000),
        "relay.example:20000"
    );
    let mut value = defaults("example.com");
    value.port_start = 1000;
    assert!(value.validate().is_err());
    value.port_start = 20000;
    value.public_port_start = Some(60000);
    assert!(value.validate().is_err());
    value.public_port_start = Some(0);
    assert!(value.validate().is_err());
    value.public_port_start = Some(40000);
    value.validate().unwrap();
    assert_eq!(value.public_port(20042), 40042);
}

#[test]
fn skips_disabled_ranges_gateway_public_ports_and_private_bridges() {
    let f = Fixture::new();
    let id = f.node("one", Some(defaults("relay.example")));
    let mut old = rule("range", "0.0.0.0:20000", Some("relay.example:20000"));
    old.listen_end_port = Some(20002);
    old.enabled = false;
    let mut gateway = rule("gateway", "127.0.0.1:20004", None);
    gateway.targets.clear();
    gateway.protocol_gateway = Some(serde_json::from_value(serde_json::json!({"listen":"0.0.0.0:20003","protocol":{"type":"trojan","password":"test-gateway-password"},"security":{"type":"certificate","identity":"server"}})).unwrap());
    f.db.set_config(&f.admin, &id, 0, vec![old, gateway])
        .unwrap();
    let plan = f.allocate(&[&id]);
    assert_eq!(plan.endpoints[0].listen.unwrap().port(), 20005);
    assert_eq!(plan.configs[0].revision, 1);
    assert_eq!(
        f.db.config(&f.admin, &id, None).unwrap().rules.len(),
        2,
        "allocation must not publish"
    );
}

#[test]
fn same_host_and_nat_ranges_are_allocated_in_path_order_and_manual_ports_reserved_first() {
    let f = Fixture::new();
    let mut nat = defaults("nat.example");
    nat.public_port_start = Some(40000);
    let a = f.node("one", Some(nat.clone()));
    let b = f.node("two", Some(nat));
    let plan = f.allocate(&[&a, &b]);
    assert_eq!(
        plan.endpoints[0].advertise.as_deref(),
        Some("nat.example:40000")
    );
    assert_eq!(
        plan.endpoints[1].advertise.as_deref(),
        Some("nat.example:40001")
    );
    assert_eq!(plan.endpoints[1].listen.unwrap().port(), 20001);
    let mut input = request(&[&a, &b]);
    input.hops[1].listen = Some("0.0.0.0:20000".parse().unwrap());
    input.hops[1].advertise = Some("nat.example:40000".into());
    let manual = f.db.allocate_endpoints(&f.admin, input).unwrap();
    assert_eq!(
        manual.endpoints[0].advertise.as_deref(),
        Some("nat.example:40001")
    );
    assert_eq!(manual.endpoints[1].source, "manual");
}

#[test]
fn two_previews_can_share_a_suggestion_but_stale_publication_is_rejected() {
    let f = Fixture::new();
    let mut value = defaults("relay.example");
    value.port_end = value.port_start + 1;
    let id = f.node("one", Some(value));
    let first = f.allocate(&[&id]);
    let second = f.allocate(&[&id]);
    assert_eq!(first.endpoints[0].listen, second.endpoints[0].listen);
    let rule = rule(
        "published",
        &first.endpoints[0].listen.unwrap().to_string(),
        first.endpoints[0].advertise.as_deref(),
    );
    f.db.publish_configs(
        &f.admin,
        batch(&id, first.configs[0].revision, vec![rule.clone()]),
    )
    .unwrap();
    let stale =
        f.db.publish_configs(
            &f.admin,
            batch(&id, second.configs[0].revision, vec![rule.clone()]),
        )
        .unwrap_err();
    assert_eq!(stale.downcast_ref::<Rejection>().unwrap().status, 409);
    let fresh = f.allocate(&[&id]);
    assert_eq!(fresh.endpoints[0].listen.unwrap().port(), 20001);
    let second_rule = self::rule("second", "0.0.0.0:20001", Some("relay.example:20001"));
    f.db.publish_configs(&f.admin, batch(&id, 1, vec![rule, second_rule]))
        .unwrap();
    assert_eq!(
        f.allocate(&[&id]).endpoints[0].error.as_deref(),
        Some("ports_exhausted")
    );
}

#[test]
fn reuses_unambiguous_existing_addresses_but_never_guesses_new_or_nat_nodes() {
    let f = Fixture::new();
    let a = f.node("named-192.0.2.1", None);
    assert_eq!(
        f.allocate(&[&a]).endpoints[0].error.as_deref(),
        Some("address_required")
    );
    let first = rule("old", "127.0.0.1:19001", None);
    f.db.set_config(&f.admin, &a, 0, vec![first.clone()])
        .unwrap();
    let plan = f.allocate(&[&a]);
    assert_eq!(
        plan.endpoints[0].advertise.as_deref(),
        Some("127.0.0.1:20000")
    );
    assert_eq!(
        plan.endpoints[0].listen.unwrap().ip().to_string(),
        "127.0.0.1"
    );
    let second = rule("other", "127.0.0.1:19002", Some("different.example:19002"));
    f.db.set_config(&f.admin, &a, 1, vec![first, second])
        .unwrap();
    assert_eq!(
        f.allocate(&[&a]).endpoints[0].error.as_deref(),
        Some("address_required")
    );
    let b = f.node("nat", None);
    let mapped = rule("mapped", "0.0.0.0:21000", Some("nat.example:31000"));
    f.db.set_config(&f.admin, &b, 0, vec![mapped]).unwrap();
    assert_eq!(
        f.allocate(&[&b]).endpoints[0].error.as_deref(),
        Some("address_required")
    );
}

#[test]
fn profile_changes_are_persisted_in_topology_and_do_not_rewrite_existing_rules() {
    let f = Fixture::new();
    let id = f.node("one", Some(defaults("first.example")));
    let old = rule("old", "0.0.0.0:19001", Some("first.example:19001"));
    f.db.set_config(&f.admin, &id, 0, vec![old.clone()])
        .unwrap();
    let node = f.db.nodes(&f.admin).unwrap().remove(0);
    f.db.update_node(
        &f.admin,
        &id,
        NodeUpdate {
            expected_revision: node.profile.revision,
            name: node.name,
            settings: NodeSettings {
                forwarding: Some(defaults("second.example")),
                ..node.profile.settings
            },
        },
    )
    .unwrap();
    assert_eq!(f.db.config(&f.admin, &id, None).unwrap().rules, vec![old]);
    assert_eq!(
        f.db.topology(&f.admin).unwrap()["nodes"][0]["profile"]["settings"]["forwarding"]["host"],
        "second.example"
    );
    assert_eq!(
        f.allocate(&[&id]).endpoints[0].advertise.as_deref(),
        Some("second.example:20000")
    );
}

#[test]
fn allocation_enforces_tenant_and_viewer_boundaries_and_duplicate_selection() {
    let f = Fixture::new();
    let id = f.node("one", Some(defaults("relay.example")));
    let viewer = Actor {
        role: Role::Viewer,
        ..f.admin.clone()
    };
    let outsider = Actor {
        tenant_id: "outside".into(),
        role: Role::TenantAdmin,
        ..f.admin.clone()
    };
    for actor in [&viewer, &outsider] {
        let error = f.db.allocate_endpoints(actor, request(&[&id])).unwrap_err();
        assert!(matches!(
            error.downcast_ref::<Rejection>().unwrap().status,
            403 | 404
        ));
    }
    assert!(
        f.db.allocate_endpoints(&f.admin, request(&[&id, &id]))
            .is_err()
    );
    assert!(f.db.allocate_endpoints(&f.admin, request(&[])).is_err());
}

#[test]
fn same_host_old_wildcard_listener_remains_occupied_outside_new_default_range() {
    let f = Fixture::new();
    let a = f.node(
        "existing",
        Some(ForwardingDefaults {
            port_start: 30000,
            port_end: 31000,
            ..defaults("same.example")
        }),
    );
    let b = f.node("new", Some(defaults("same.example")));
    f.db.set_config(&f.admin, &a, 0, vec![rule("old", "0.0.0.0:20000", None)])
        .unwrap();
    let plan = f.allocate(&[&b]);
    assert_eq!(
        plan.endpoints[0].advertise.as_deref(),
        Some("same.example:20001")
    );
}
