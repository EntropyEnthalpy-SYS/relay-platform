mod common;
use common::*;
use relay_platform::{
    model::*,
    store::{Actor, Rejection, Role, Store},
    topology::{self, ConfigBatch, ConfigUpdate},
};
use std::sync::{Arc, Barrier};

fn rejection<T>(result: anyhow::Result<T>) -> u16 {
    result
        .err()
        .expect("expected rejection")
        .downcast_ref::<Rejection>()
        .unwrap()
        .status
}
fn batch(configs: &[NodeConfig]) -> ConfigBatch {
    ConfigBatch {
        updates: configs
            .iter()
            .map(|c| ConfigUpdate {
                node_id: c.node_id.clone(),
                expected_revision: c.revision,
                rules: c.rules.clone(),
                rate_bytes_per_sec: None,
            })
            .collect(),
    }
}
struct Fixture {
    _temp: tempfile::TempDir,
    store: Store,
    admin: Actor,
    configs: Vec<NodeConfig>,
    tokens: Vec<String>,
}
impl Fixture {
    fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("controller.db")).unwrap();
        store.set_kind("controller").unwrap();
        let admin = store.bootstrap(PASSWORD).unwrap();
        let mut configs = Vec::new();
        let mut tokens = Vec::new();
        for i in 0..3 {
            let (node, token) = store
                .create_node(&admin, "default", &format!("hop-{i}"))
                .unwrap();
            let mut r = rule("127.0.0.1:38501".parse().unwrap(), Protocol::Both);
            r.id = format!("hop-{i}");
            r.advertise = Some(r.listen.to_string());
            configs.push(NodeConfig {
                api_version: 1,
                node_id: node.id,
                revision: 0,
                rules: vec![r],
                rate_bytes_per_sec: None,
            });
            tokens.push(token);
        }
        for i in 0..2 {
            let next = &configs[i + 1];
            let address = next.rules[0].advertise.clone().unwrap();
            let via = RuleRef {
                node_id: next.node_id.clone(),
                rule_id: next.rules[0].id.clone(),
            };
            configs[i].rules[0].targets[0].address = address;
            configs[i].rules[0].targets[0].via = Some(via);
        }
        Self {
            _temp: temp,
            store,
            admin,
            configs,
            tokens,
        }
    }
    fn publish(&mut self) {
        self.configs = self
            .store
            .publish_configs(&self.admin, batch(&self.configs))
            .unwrap()
            .configs;
    }
    fn enroll(&self) {
        for (config, token) in self.configs.iter().zip(&self.tokens) {
            self.store
                .enroll(&config.node_id, token, &relay_platform::store::secret())
                .unwrap();
        }
    }
    fn acknowledge(&self, active: u64) {
        for config in &self.configs {
            let page = self
                .store
                .reconcile(
                    &config.node_id,
                    ReconcileRequest {
                        lease: None,
                        ledger_id: None,
                        after: None,
                        expected_revision: None,
                    },
                )
                .unwrap();
            self.store
                .sync(
                    &config.node_id,
                    SyncRequest {
                        lease: None,
                        budget: None,
                        ledger_id: page.ledger_id,
                        need_config: false,
                        applied_revision: config.revision,
                        apply_error: None,
                        usage: vec![],
                        stats: EngineStats {
                            active_tcp: active,
                            ..Default::default()
                        },
                    },
                )
                .unwrap();
        }
    }
}

#[test]
fn draining_a_node_marks_every_route_into_it_without_tripping_the_rewire_barrier() {
    let mut f = Fixture::new();
    f.publish();
    let (entry, middle) = (f.configs[0].node_id.clone(), f.configs[1].node_id.clone());
    let drained = f.store.drain_node(&f.admin, &middle, true).unwrap();
    // Only the upstream hop changes; the drained node's own rules do not.
    assert_eq!(drained.configs.len(), 1);
    assert_eq!(drained.configs[0].node_id, entry);
    assert_eq!(drained.configs[0].revision, 2);
    assert!(drained.configs[0].rules[0].targets[0].draining);
    let config = |node: &str| f.store.config(&f.admin, node, None).unwrap();
    assert_eq!(config(&middle).revision, 1);
    assert!(
        f.store
            .drain_node(&f.admin, &middle, true)
            .unwrap()
            .configs
            .is_empty(),
        "draining twice publishes nothing"
    );
    assert_eq!(rejection(f.store.drain_node(&f.admin, &entry, true)), 409);
    let restored = f.store.drain_node(&f.admin, &middle, false).unwrap();
    assert_eq!(restored.configs[0].revision, 3);
    assert!(!config(&entry).rules[0].targets[0].draining);
    assert!(
        !serde_json::to_string(&config(&entry))
            .unwrap()
            .contains("draining"),
        "an undrained target serializes as before for older agents"
    );
}

#[test]
fn node_rate_survives_publishes_that_omit_it_and_null_clears_it() {
    let mut f = Fixture::new();
    f.publish();
    let node = f.configs[0].node_id.clone();
    let set: ConfigBatch = serde_json::from_value(serde_json::json!({"updates": [{
        "node_id": node, "expected_revision": 1, "rules": f.configs[0].rules,
        "rate_bytes_per_sec": 1_048_576
    }]}))
    .unwrap();
    let rate = |c: &NodeConfig| c.rate_bytes_per_sec;
    assert_eq!(
        rate(&f.store.publish_configs(&f.admin, set).unwrap().configs[0]),
        Some(1_048_576)
    );
    // Rule edits from clients that predate the field keep the cap.
    let kept = f
        .store
        .set_config(&f.admin, &node, 2, f.configs[0].rules.clone())
        .unwrap();
    assert_eq!(rate(&kept), Some(1_048_576));
    let clear: ConfigBatch = serde_json::from_value(serde_json::json!({"updates": [{
        "node_id": node, "expected_revision": 3, "rules": f.configs[0].rules,
        "rate_bytes_per_sec": null
    }]}))
    .unwrap();
    let cleared = &f.store.publish_configs(&f.admin, clear).unwrap().configs[0];
    assert_eq!(rate(cleared), None);
    assert!(!serde_json::to_value(cleared).unwrap()["rate_bytes_per_sec"].is_number());
    assert_eq!(
        rejection(f.store.set_config_with_rate(
            &f.admin,
            &node,
            4,
            f.configs[0].rules.clone(),
            Some(Some(0)),
        )),
        400
    );
}

#[test]
fn preview_is_read_only_and_batch_publish_preserves_history_and_edges() {
    let mut f = Fixture::new();
    let audit = f.store.audit_log(&f.admin).unwrap().len();
    let preview = f
        .store
        .preview_configs(&f.admin, batch(&f.configs))
        .unwrap();
    assert_eq!(preview.configs.len(), 3);
    assert!(
        preview
            .changes
            .iter()
            .all(|d| d.added.len() == 1 && d.from_revision == 0 && d.to_revision == 1)
    );
    assert_eq!(f.store.audit_log(&f.admin).unwrap().len(), audit);
    assert!(
        f.store
            .nodes(&f.admin)
            .unwrap()
            .iter()
            .all(|n| n.desired_revision == 0)
    );
    let connection = rusqlite::Connection::open(f._temp.path().join("controller.db")).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM rule_bindings", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
    f.publish();
    assert_eq!(
        serde_json::to_value(&preview.configs).unwrap(),
        serde_json::to_value(&f.configs).unwrap()
    );
    let topology = f.store.topology(&f.admin).unwrap();
    assert_eq!(topology["graph"]["edges"].as_array().unwrap().len(), 2);
    assert_eq!(topology["graph"]["roots"].as_array().unwrap().len(), 1);
    assert_eq!(topology["activation"], "asynchronous-per-node");
    for config in &f.configs {
        assert_eq!(f.store.history(&f.admin, &config.node_id).unwrap().len(), 2);
    }
}

#[test]
fn multipath_sessions_and_paths_must_drain_even_after_physical_tcp_count_reaches_zero() {
    let mut f = Fixture::new();
    f.publish();
    f.enroll();
    f.acknowledge(0);
    for c in &mut f.configs {
        c.rules[0].enabled = false;
    }
    f.publish();
    f.acknowledge(0);
    let mut enabled = f.configs.clone();
    for c in &mut enabled {
        c.rules[0].enabled = true;
    }
    let first = &f.configs[0];
    let page = f
        .store
        .reconcile(
            &first.node_id,
            ReconcileRequest {
                lease: None,
                ledger_id: None,
                after: None,
                expected_revision: None,
            },
        )
        .unwrap();
    for (sessions, paths) in [(1, 0), (0, 1)] {
        f.store
            .sync(
                &first.node_id,
                SyncRequest {
                    lease: None,
                    budget: None,
                    ledger_id: page.ledger_id.clone(),
                    need_config: false,
                    applied_revision: first.revision,
                    apply_error: None,
                    usage: vec![],
                    stats: EngineStats {
                        multipath: Some(relay_platform::multipath::Stats {
                            active_sessions: sessions,
                            active_paths: paths,
                            ..Default::default()
                        }),
                        ..Default::default()
                    },
                },
            )
            .unwrap();
        assert_eq!(
            rejection(f.store.publish_configs(&f.admin, batch(&enabled))),
            409
        );
    }
    f.acknowledge(0);
    f.store.publish_configs(&f.admin, batch(&enabled)).unwrap();
}

#[test]
fn stale_last_node_and_invalid_reference_do_not_partially_publish() {
    let f = Fixture::new();
    let mut input = batch(&f.configs);
    input.updates[2].expected_revision = 1;
    assert_eq!(rejection(f.store.publish_configs(&f.admin, input)), 409);
    let mut input = batch(&f.configs);
    input.updates[2].rules[0].targets[0].via = Some(RuleRef {
        node_id: "missing".into(),
        rule_id: "missing".into(),
    });
    assert_eq!(rejection(f.store.publish_configs(&f.admin, input)), 400);
    assert!(
        f.store
            .nodes(&f.admin)
            .unwrap()
            .iter()
            .all(|n| n.desired_revision == 0)
    );
    let connection = rusqlite::Connection::open(f._temp.path().join("controller.db")).unwrap();
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM rule_bindings", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
    let mut input = batch(&f.configs);
    input.updates.push(input.updates[0].clone());
    assert_eq!(rejection(f.store.publish_configs(&f.admin, input)), 400);
    assert_eq!(
        rejection(
            f.store
                .publish_configs(&f.admin, ConfigBatch { updates: vec![] })
        ),
        400
    );
}

#[test]
fn competing_batches_have_one_winner_without_lost_node_updates() {
    let f = Fixture::new();
    let gate = Arc::new(Barrier::new(2));
    let tasks: Vec<_> = (0..2)
        .map(|_| {
            let store = f.store.clone();
            let actor = f.admin.clone();
            let input = batch(&f.configs);
            let gate = gate.clone();
            std::thread::spawn(move || {
                gate.wait();
                store.publish_configs(&actor, input)
            })
        })
        .collect();
    let results: Vec<_> = tasks.into_iter().map(|t| t.join().unwrap()).collect();
    assert_eq!(results.iter().filter(|r| r.is_ok()).count(), 1);
    assert_eq!(
        rejection(results.into_iter().find(|r| r.is_err()).unwrap()),
        409
    );
    assert!(
        f.store
            .nodes(&f.admin)
            .unwrap()
            .iter()
            .all(|n| n.desired_revision == 1)
    );
}

#[test]
fn directed_cycles_raw_address_bypass_and_endpoint_aliases_are_rejected() {
    let f = Fixture::new();
    let mut configs = f.configs.clone();
    configs[2].rules[0].targets[0] = Target {
        priority: 0,
        max_sessions: None,
        address: configs[0].rules[0].advertise.clone().unwrap(),
        via: Some(RuleRef {
            node_id: configs[0].node_id.clone(),
            rule_id: configs[0].rules[0].id.clone(),
        }),
        ..configs[2].rules[0].targets[0].clone()
    };
    assert!(
        topology::validate(&configs)
            .unwrap_err()
            .to_string()
            .contains("cycle")
    );
    configs = f.configs.clone();
    configs[0].rules[0].targets[0].via = None;
    assert!(
        topology::validate(&configs)
            .unwrap_err()
            .to_string()
            .contains("explicit")
    );
    configs = f.configs.clone();
    configs[0].rules[0].targets[0].address = "127.0.0.1:38502".into();
    assert!(
        topology::validate(&configs)
            .unwrap_err()
            .to_string()
            .contains("differs")
    );
    configs = f.configs.clone();
    configs[2].rules[0].advertise = configs[1].rules[0].advertise.clone();
    assert!(
        topology::validate(&configs)
            .unwrap_err()
            .to_string()
            .contains("overlaps")
    );
    configs = f.configs.clone();
    configs[1].rules[0].advertise = Some("Relay.Example.:443".into());
    configs[0].rules[0].targets[0].address = "relay.example:443".into();
    assert!(topology::validate(&configs).is_ok());
    configs[0].rules[0].targets[0].via = None;
    assert!(topology::validate(&configs).is_err());
}

#[test]
fn multiple_entrances_and_weighted_candidates_are_distinct_from_sequential_hops() {
    let f = Fixture::new();
    let mut configs = f.configs.clone();
    let mut direct = configs[1].rules[0].targets[0].clone();
    direct.weight = 3;
    configs[0].rules[0].targets.push(direct);
    let graph = topology::validate(&configs).unwrap();
    assert_eq!(graph.edges.len(), 3);
    assert_eq!(graph.roots.len(), 1);
    configs[0].rules[0].targets.remove(0);
    let graph = topology::validate(&configs).unwrap();
    assert_eq!(graph.edges.len(), 2);
    assert_eq!(graph.roots.len(), 2);
    assert!(graph.edges.iter().any(|edge| edge.weight == 3));
}

#[test]
fn range_protocol_and_security_combinations_are_checked_at_both_ends() {
    let f = Fixture::new();
    let mut configs = f.configs.clone();
    configs[1].rules[0].protocol = Protocol::Tcp;
    assert!(topology::validate(&configs).is_err());
    configs = f.configs.clone();
    configs[0].rules[0].port_mapping = PortMapping::Offset;
    configs[0].rules[0].listen_end_port = Some(configs[0].rules[0].listen.port() + 2);
    assert!(
        topology::validate(&configs)
            .unwrap_err()
            .to_string()
            .contains("too short")
    );
    for config in &mut configs[1..] {
        config.rules[0].listen_end_port = Some(config.rules[0].listen.port() + 2);
    }
    assert!(topology::validate(&configs).is_ok());
    configs = f.configs.clone();
    for c in &mut configs {
        c.rules[0].protocol = Protocol::Tcp;
    }
    configs[1].rules[0].inbound_tls = Some(TlsServer {
        identity: "server".into(),
        client_ca: Some("ca".into()),
    });
    assert!(
        topology::validate(&configs)
            .unwrap_err()
            .to_string()
            .contains("TLS settings")
    );
    configs[0].rules[0].targets[0].tls = Some(TlsClient {
        server_name: "localhost".into(),
        ca: Some("root".into()),
        identity: None,
    });
    assert!(
        topology::validate(&configs)
            .unwrap_err()
            .to_string()
            .contains("client identity")
    );
    configs[0].rules[0].targets[0]
        .tls
        .as_mut()
        .unwrap()
        .identity = Some("client".into());
    assert!(topology::validate(&configs).is_ok());
    configs[1].rules[0].inbound_websocket = Some(WebSocketServer {
        path: "/hop".into(),
        host: Some("next.test".into()),
        allowed_origins: vec![],
    });
    assert!(topology::validate(&configs).is_err());
    configs[0].rules[0].targets[0].websocket = Some(WebSocketClient {
        path: "/hop".into(),
        host: "next.test".into(),
        origin: None,
    });
    assert!(topology::validate(&configs).is_ok());
    configs[0].rules[0].targets[0]
        .websocket
        .as_mut()
        .unwrap()
        .path = "/other".into();
    assert!(
        topology::validate(&configs)
            .unwrap_err()
            .to_string()
            .contains("path mismatch")
    );
    configs = f.configs.clone();
    configs[1].rules[0].inbound_proxy = Some(ProxyInbound {
        version: ProxyAccept::V2,
        trusted_sources: vec!["127.0.0.0/8".parse().unwrap()],
        placement: ProxyPlacement::BeforeTls,
        max_header_bytes: 4096,
        accept_prewarmed: false,
    });
    assert!(topology::validate(&configs).is_err());
    configs[0].rules[0].targets[0].proxy_protocol = Some(ProxyOutbound {
        version: ProxyVersion::V2,
        placement: ProxyPlacement::BeforeTls,
        checksum: true,
    });
    assert!(topology::validate(&configs).is_ok());
    configs[0].rules[0].targets[0].prewarm = Some(4);
    assert!(
        topology::validate(&configs)
            .unwrap_err()
            .to_string()
            .contains("pre-warmed")
    );
    configs[1].rules[0]
        .inbound_proxy
        .as_mut()
        .unwrap()
        .accept_prewarmed = true;
    assert!(topology::validate(&configs).is_ok());
}

#[test]
fn rewire_requires_disabled_revision_ack_and_zero_sessions_then_can_reverse_chain() {
    let mut f = Fixture::new();
    f.publish();
    f.enroll();
    f.acknowledge(1);
    let mut changed = f.configs.clone();
    changed[0].rules[0].targets[0] = changed[1].rules[0].targets[0].clone();
    assert_eq!(
        rejection(f.store.publish_configs(&f.admin, batch(&changed))),
        409
    );
    for config in &mut f.configs {
        config.rules[0].enabled = false;
    }
    f.publish();
    let mut enabled = f.configs.clone();
    for config in &mut enabled {
        config.rules[0].enabled = true;
    }
    assert_eq!(
        rejection(f.store.publish_configs(&f.admin, batch(&enabled))),
        409
    );
    f.acknowledge(1);
    assert_eq!(
        rejection(f.store.publish_configs(&f.admin, batch(&enabled))),
        409
    );
    f.acknowledge(0);
    let external = enabled[2].rules[0].targets[0].clone();
    for i in (1..3).rev() {
        enabled[i].rules[0].targets[0].address = enabled[i - 1].rules[0].advertise.clone().unwrap();
        enabled[i].rules[0].targets[0].via = Some(RuleRef {
            node_id: enabled[i - 1].node_id.clone(),
            rule_id: enabled[i - 1].rules[0].id.clone(),
        });
    }
    enabled[0].rules[0].targets = vec![external];
    let result = f.store.publish_configs(&f.admin, batch(&enabled)).unwrap();
    assert!(result.configs.iter().all(|c| c.revision == 3));
    assert_eq!(
        topology::validate(&result.configs).unwrap().roots[0].node_id,
        result.configs[2].node_id
    );
}

#[test]
fn tenant_read_isolation_and_write_permissions_include_batch_and_topology() {
    let mut f = Fixture::new();
    f.publish();
    let tenant = f.store.create_tenant(&f.admin, "isolated").unwrap();
    let member = f
        .store
        .create_user(&f.admin, &tenant, "member", PASSWORD, Role::TenantAdmin)
        .unwrap();
    let viewer = f
        .store
        .create_user(&f.admin, "default", "readonly", PASSWORD, Role::Viewer)
        .unwrap();
    assert_eq!(
        f.store.topology(&member).unwrap()["nodes"]
            .as_array()
            .unwrap()
            .len(),
        0
    );
    assert_eq!(
        rejection(f.store.preview_configs(&member, batch(&f.configs))),
        404
    );
    assert_eq!(
        rejection(f.store.publish_configs(&viewer, batch(&f.configs))),
        403
    );
    assert_eq!(
        rejection(f.store.preview_configs(&viewer, batch(&f.configs))),
        403
    );
    let (node, _) = f.store.create_node(&f.admin, &tenant, "other").unwrap();
    let mut other = f.configs[0].rules[0].clone();
    other.id = "other".into();
    other.tenant_id = tenant;
    other.owner_id = member.id;
    other.listen = free_address();
    other.advertise = Some(other.listen.to_string());
    let input = ConfigBatch {
        updates: vec![ConfigUpdate {
            node_id: node.id,
            expected_revision: 0,
            rules: vec![other],
            rate_bytes_per_sec: None,
        }],
    };
    assert_eq!(rejection(f.store.publish_configs(&f.admin, input)), 400);
}

#[test]
fn new_rule_identity_cannot_reuse_a_stopping_topology_listener() {
    let mut f = Fixture::new();
    f.publish();
    f.enroll();
    f.acknowledge(1);
    for config in &mut f.configs {
        config.rules[0].enabled = false;
    }
    f.publish();
    let mut changed = f.configs.clone();
    let mut replacement = changed[0].rules[0].clone();
    replacement.id = "replacement".into();
    replacement.enabled = true;
    replacement.advertise = None;
    replacement.targets = changed[2].rules[0].targets.clone();
    changed[0].rules.push(replacement);
    assert_eq!(
        rejection(f.store.publish_configs(&f.admin, batch(&changed))),
        409
    );
    f.acknowledge(0);
    assert!(f.store.publish_configs(&f.admin, batch(&changed)).is_ok());
}

#[test]
fn one_recovery_transaction_restores_the_entire_multi_node_publication() {
    let mut f = Fixture::new();
    let journal = f._temp.path().join("recovery.log");
    f.store.enable_recovery_log(&journal).unwrap();
    let backup = f._temp.path().join("baseline.sqlite");
    f.store.backup(&backup).unwrap();
    let before = f
        .store
        .recovery_log_status()
        .unwrap()
        .head
        .unwrap()
        .sequence;
    f.publish();
    assert_eq!(
        f.store
            .recovery_log_status()
            .unwrap()
            .head
            .unwrap()
            .sequence,
        before + 1
    );
    let expected = f.store.topology(&f.admin).unwrap();
    let expected_audit = f.store.audit_log(&f.admin).unwrap();
    drop(f.store);
    let output = f._temp.path().join("restored");
    let report = relay_platform::journal::restore_controller(&backup, &journal, &output).unwrap();
    assert_eq!(report.replayed_transactions, 1);
    let restored = Store::open(&output.join("controller.sqlite")).unwrap();
    assert_eq!(restored.topology(&f.admin).unwrap(), expected);
    assert_eq!(restored.audit_log(&f.admin).unwrap(), expected_audit);
}

#[test]
fn database_failure_on_last_node_rolls_back_all_rules_and_revisions() {
    let f = Fixture::new();
    let connection = rusqlite::Connection::open(f._temp.path().join("controller.db")).unwrap();
    connection.execute_batch(&format!("CREATE TRIGGER reject_last BEFORE UPDATE ON nodes WHEN NEW.id='{}' BEGIN SELECT RAISE(ABORT,'injected last-node storage failure'); END;",f.configs[2].node_id)).unwrap();
    assert!(
        f.store
            .publish_configs(&f.admin, batch(&f.configs))
            .is_err()
    );
    assert!(
        f.store
            .nodes(&f.admin)
            .unwrap()
            .iter()
            .all(|n| n.desired_revision == 0)
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM rule_bindings", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        0
    );
    assert_eq!(
        connection
            .query_row("SELECT COUNT(*) FROM config_history", [], |r| r
                .get::<_, u64>(0))
            .unwrap(),
        3
    );
}

#[test]
fn topology_reactivation_waits_for_cancelled_probe_io_to_finish() {
    let mut f = Fixture::new();
    f.publish();
    f.enroll();
    f.acknowledge(0);
    for c in &mut f.configs {
        c.rules[0].enabled = false;
    }
    f.publish();
    f.acknowledge(0);
    let first = &f.configs[0];
    let page = f
        .store
        .reconcile(
            &first.node_id,
            ReconcileRequest {
                lease: None,
                ledger_id: None,
                after: None,
                expected_revision: None,
            },
        )
        .unwrap();
    f.store
        .sync(
            &first.node_id,
            SyncRequest {
                lease: None,
                budget: None,
                ledger_id: page.ledger_id,
                need_config: false,
                applied_revision: first.revision,
                apply_error: None,
                usage: vec![],
                stats: EngineStats {
                    active_probes: 1,
                    ..Default::default()
                },
            },
        )
        .unwrap();
    let mut enabled = f.configs.clone();
    for c in &mut enabled {
        c.rules[0].enabled = true;
    }
    assert_eq!(
        rejection(f.store.publish_configs(&f.admin, batch(&enabled))),
        409
    );
    f.acknowledge(0);
    f.store.publish_configs(&f.admin, batch(&enabled)).unwrap();
}
