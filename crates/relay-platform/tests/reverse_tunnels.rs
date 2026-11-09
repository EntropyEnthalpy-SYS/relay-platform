//! Panel-managed reverse tunnels: records and their checks, what each agent
//! gets through sync and when, the API's roles and tenants, and real agents
//! carrying TCP and UDP through a metered tunnel on loopback. The kernel
//! side behind a NAT runs in scripts/check_linux_reverse_tunnel.py (root).
mod common;
use common::*;
use relay_platform::{
    agent::{self, AgentOptions},
    api::{self, AppState},
    model::*,
    node::{ForwardingDefaults, NodeSettings, NodeUpdate},
    reverse_mux::managed::{self, Identity},
    reverse_tunnel::{Desired, Report, State, TunnelInput, TunnelProtocol, TunnelView},
    shared_rule::{LineErrors, SharedRuleInput},
    store::{Actor, Node, Rejection, Role, Scope, Store, write_secret},
};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    path::Path,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{Instant, sleep, timeout},
};
use tokio_util::sync::CancellationToken;

fn status<T: std::fmt::Debug>(result: anyhow::Result<T>) -> u16 {
    result
        .unwrap_err()
        .downcast_ref::<Rejection>()
        .unwrap()
        .status
}
fn ledger(db: &Store, node: &str) -> String {
    db.reconcile(
        node,
        ReconcileRequest {
            lease: None,
            ledger_id: None,
            after: None,
            expected_revision: None,
        },
    )
    .unwrap()
    .ledger_id
}
/// One agent report; `None` is an agent older than reverse tunnels.
fn sync(db: &Store, node: &str, report: Option<Report>) -> Desired {
    let stats = EngineStats {
        reverse_tunnel: report,
        ..EngineStats::default()
    };
    db.sync(
        node,
        SyncRequest {
            logs: None,
            lease: None,
            budget: None,
            ledger_id: ledger(db, node),
            need_config: false,
            applied_revision: 0,
            apply_error: None,
            usage: vec![],
            stats,
        },
    )
    .unwrap()
    .reverse_tunnels
    .expect("this controller always sends tunnels")
}
/// A server that is switched off (pausing needs a strict lease).
fn paused_node(store: &Store, admin: &Actor) -> String {
    let (node, _) = store
        .create_node_with_lease(
            admin,
            "default",
            "paused",
            Some(relay_platform::lease::LeasePolicy::default()),
        )
        .unwrap();
    store
        .update_node(
            admin,
            &node.id,
            NodeUpdate {
                expected_revision: node.profile.revision,
                name: node.name.clone(),
                settings: NodeSettings {
                    enabled: false,
                    ..Default::default()
                },
            },
        )
        .unwrap();
    node.id
}
fn able(fingerprint: Option<&str>) -> Report {
    Report {
        managed: true,
        fingerprint: fingerprint.map(str::to_owned),
        tunnels: vec![],
    }
}

struct Fixture {
    _temp: tempfile::TempDir,
    store: Store,
    admin: Actor,
    nodes: Vec<Node>,
    enrollments: Vec<String>,
}
impl Fixture {
    fn new(count: usize) -> Self {
        let temp = tempfile::tempdir().unwrap();
        let store = Store::open(&temp.path().join("controller.db")).unwrap();
        store.set_kind("controller").unwrap();
        let admin = store.bootstrap(PASSWORD).unwrap();
        let (nodes, enrollments) = (0..count)
            .map(|index| {
                store
                    .create_node(&admin, "default", &format!("line-{index}"))
                    .unwrap()
            })
            .unzip();
        Self {
            _temp: temp,
            store,
            admin,
            nodes,
            enrollments,
        }
    }
    fn id(&self, index: usize) -> String {
        self.nodes[index].id.clone()
    }
    fn config(&self, index: usize) -> NodeConfig {
        self.store
            .config(&self.admin, &self.id(index), None)
            .unwrap()
    }
    fn settings(&self, index: usize, settings: NodeSettings) {
        let node = self
            .store
            .nodes(&self.admin)
            .unwrap()
            .into_iter()
            .find(|n| n.id == self.id(index))
            .unwrap();
        self.store
            .update_node(
                &self.admin,
                &node.id,
                NodeUpdate {
                    expected_revision: node.profile.revision,
                    name: node.name.clone(),
                    settings,
                },
            )
            .unwrap();
    }
    /// Public server behind a cloud NAT: local ports 20000–29999 appear as
    /// 40000–49999 at gw.example.net, and rules bind 203.0.113.5.
    fn behind_nat(&self, index: usize) {
        self.settings(
            index,
            NodeSettings {
                forwarding: Some(ForwardingDefaults {
                    host: "gw.example.net".into(),
                    listen_ip: Some("203.0.113.5".parse().unwrap()),
                    port_start: 20000,
                    port_end: 29999,
                    public_port_start: Some(40000),
                }),
                ..Default::default()
            },
        );
    }
    fn ordinary(&self, index: usize, id: &str, port: u16) -> anyhow::Result<NodeConfig> {
        let config = self.config(index);
        let mut rule = rule("192.0.2.50:80".parse().unwrap(), Protocol::Tcp);
        rule.id = id.into();
        rule.meter_epoch = format!("{id}-epoch");
        rule.owner_id = self.admin.id.clone();
        rule.name = id.into();
        rule.listen = SocketAddr::from(([0, 0, 0, 0], port));
        let mut rules = config.rules;
        rules.push(rule);
        self.store
            .set_config(&self.admin, &self.id(index), config.revision, rules)
    }
    fn shared(&self, nodes: &[usize], port: u16) -> anyhow::Result<()> {
        let mut rule = rule("192.0.2.10:443".parse().unwrap(), Protocol::Tcp);
        rule.owner_id = String::new();
        self.store
            .create_shared_rule(
                &self.admin,
                SharedRuleInput {
                    name: format!("shared-{port}"),
                    node_ids: nodes.iter().map(|i| self.id(*i)).collect(),
                    listen_port: port,
                    rule,
                },
            )
            .map(|_| ())
    }
    fn input(&self, public: usize, private: usize, port: u16) -> TunnelInput {
        TunnelInput {
            name: format!("tunnel-{port}"),
            public_node_id: self.id(public),
            private_node_id: self.id(private),
            public_port: port,
            listen_ip: None,
            protocol: TunnelProtocol::Tcp,
            target: "127.0.0.1:8080".into(),
            tunnel_port: None,
            enabled: None,
        }
    }
    fn create(&self, input: TunnelInput) -> anyhow::Result<TunnelView> {
        self.store.create_reverse_tunnel(&self.admin, input)
    }
    fn view(&self, id: &str) -> TunnelView {
        self.store
            .reverse_tunnels(&self.admin)
            .unwrap()
            .into_iter()
            .find(|v| v.id == id)
            .unwrap()
    }
    fn tunnel_rules(&self, index: usize) -> Vec<Rule> {
        self.config(index)
            .rules
            .into_iter()
            .filter(|r| r.reverse_tunnel.is_some())
            .collect()
    }
}

#[test]
fn tunnels_are_checked_against_servers_tenants_and_ports_in_both_directions() {
    let f = Fixture::new(3);
    let other = f.store.create_tenant(&f.admin, "other").unwrap();
    let (foreign, _) = f.store.create_node(&f.admin, &other, "foreign").unwrap();
    // The same server at both ends, and servers of two tenants.
    assert_eq!(status(f.create(f.input(0, 0, 22000))), 400);
    let mut cross = f.input(0, 1, 22000);
    cross.private_node_id = foreign.id.clone();
    assert_eq!(status(f.create(cross)), 400);
    let mut same_ports = f.input(0, 1, 22000);
    same_ports.tunnel_port = Some(22000);
    assert_eq!(status(f.create(same_ports)), 400);

    // Rules and shared rules hold ports first: both the public and the
    // tunnel port must be free.
    f.ordinary(0, "busy", 21000).unwrap();
    f.shared(&[0, 2], 21100).unwrap();
    assert_eq!(status(f.create(f.input(0, 1, 21000))), 409);
    assert_eq!(status(f.create(f.input(0, 1, 21100))), 409);
    let mut on_rule = f.input(0, 1, 22000);
    on_rule.tunnel_port = Some(21000);
    assert_eq!(status(f.create(on_rule)), 409);
    let mut on_shared = f.input(0, 1, 22000);
    on_shared.tunnel_port = Some(21100);
    assert_eq!(status(f.create(on_shared)), 409);
    // The same port on another public server is free.
    f.create(f.input(1, 0, 21000)).unwrap();

    // Two tunnels share one tunnel port on one public server.
    let first = f.create(f.input(0, 1, 22000)).unwrap();
    let second = f.create(f.input(0, 2, 22001)).unwrap();
    assert_eq!(
        (first.tunnel_port, second.tunnel_port),
        (29123, 29123),
        "the default tunnel port, like Zero Forwarder"
    );
    // But no tunnel takes another's public port, or a tunnel port as its
    // public port.
    assert_eq!(status(f.create(f.input(0, 2, 22000))), 409);
    let mut on_tunnel_port = f.input(0, 2, 29123);
    on_tunnel_port.tunnel_port = Some(29124);
    assert_eq!(status(f.create(on_tunnel_port)), 409);
    let mut taken_tunnel_port = f.input(0, 2, 22002);
    taken_tunnel_port.tunnel_port = Some(22001);
    assert_eq!(status(f.create(taken_tunnel_port)), 409);
    // An edit may keep its own port but not move onto another tunnel's.
    let mut moved = f.input(0, 1, 22001);
    moved.name = first.name.clone();
    assert_eq!(
        status(f.store.update_reverse_tunnel(&f.admin, &first.id, moved)),
        409
    );
    let mut renamed = f.input(0, 1, 22000);
    renamed.name = "renamed".into();
    assert_eq!(
        f.store
            .update_reverse_tunnel(&f.admin, &first.id, renamed)
            .unwrap()
            .name,
        "renamed"
    );

    // Now the other way: rules and shared rules cannot take tunnel ports,
    // even while the tunnels are not running yet.
    assert!(f.tunnel_rules(0).is_empty(), "no agent reported yet");
    assert_eq!(status(f.ordinary(0, "on-public", 22001)), 409);
    assert_eq!(status(f.ordinary(0, "on-tunnel", 29123)), 409);
    let error = f.shared(&[2, 0], 29123).unwrap_err();
    let lines = error.downcast_ref::<LineErrors>().unwrap().0.clone();
    assert_eq!(lines.len(), 1);
    assert_eq!(lines[0].node_id, f.id(0), "only the public server is taken");
    f.ordinary(2, "elsewhere", 29123).unwrap();

    // A paused server cannot run tunnels.
    let mut to_paused = f.input(0, 2, 22003);
    to_paused.private_node_id = paused_node(&f.store, &f.admin);
    assert_eq!(status(f.create(to_paused)), 409);
}

#[test]
fn nothing_is_sent_until_both_agents_can_and_the_public_key_is_reported() {
    let f = Fixture::new(3);
    f.behind_nat(0);
    let (public, private, third) = (f.id(0), f.id(1), f.id(2));
    let mut input = f.input(0, 1, 22000);
    input.protocol = TunnelProtocol::TcpUdp;
    input.target = "192.168.10.20:8080".into();
    let tunnel = f.create(input).unwrap();
    let mut udp_only = f.input(0, 2, 22001);
    udp_only.protocol = TunnelProtocol::Udp;
    let udp = f.create(udp_only).unwrap();
    let token = f
        .store
        .metadata(&format!("reverse_tunnel_token:{}", tunnel.id))
        .unwrap()
        .unwrap();
    assert_eq!(token.len(), 64, "32 random bytes");
    assert!(token.bytes().all(|b| b.is_ascii_hexdigit()));
    assert_eq!(tunnel.entry.as_deref(), Some("gw.example.net:42000"));

    // Agents older than the feature report nothing: nothing to run.
    let empty = |d: &Desired| d.listeners.is_empty() && d.dials.is_empty();
    assert!(empty(&sync(&f.store, &public, None)));
    assert!(empty(&sync(&f.store, &private, None)));
    let view = f.view(&tunnel.id);
    assert_eq!(view.state, State::Waiting);
    assert!(
        view.reason
            .unwrap()
            .contains("public server's agent is too old")
    );
    let key = Identity::generate().unwrap().fingerprint();
    // The public agent can, but the private one is still too old; the
    // public one is asked to make its key.
    let desired = sync(&f.store, &public, Some(able(None)));
    assert!(desired.key && empty(&desired));
    let view = f.view(&tunnel.id);
    assert!(
        view.reason
            .unwrap()
            .contains("private server's agent is too old")
    );
    assert!(!sync(&f.store, &private, Some(able(None))).key);
    assert_eq!(
        f.view(&tunnel.id).reason.as_deref(),
        Some("waiting for the public server's key")
    );
    assert!(f.tunnel_rules(0).is_empty());
    // A malformed fingerprint is not a key.
    assert!(empty(&sync(&f.store, &public, Some(able(Some("zz"))))));
    assert!(empty(&sync(&f.store, &private, Some(able(None)))));

    // The key arrives: the public server gets the public end and one
    // listener on the shared tunnel port, admitting the tunnels whose
    // private ends can run them (the third server is still too old).
    let revision = f.config(0).revision;
    let desired = sync(&f.store, &public, Some(able(Some(&key))));
    assert_eq!(desired.listeners.len(), 1);
    assert_eq!(
        desired.listeners[0].listen,
        "203.0.113.5:29123".parse::<SocketAddr>().unwrap()
    );
    let admitted: Vec<(&str, &str)> = desired.listeners[0]
        .tunnels
        .iter()
        .map(|t| (t.id.as_str(), t.token.as_str()))
        .collect();
    assert_eq!(admitted, [(tunnel.id.as_str(), token.as_str())]);
    assert!(desired.dials.is_empty());
    assert!(f.config(0).revision > revision);
    let rules = f.tunnel_rules(0);
    assert_eq!(rules.len(), 1);
    let end = &rules[0];
    assert!(end.id.starts_with("rt-"));
    assert_eq!(end.reverse_tunnel.as_deref(), Some(tunnel.id.as_str()));
    assert_eq!(end.listen, "203.0.113.5:22000".parse().unwrap());
    assert_eq!(end.protocol, Protocol::Both);
    assert_eq!(end.targets[0].address, "192.168.10.20:8080");
    assert_eq!(end.owner_id, f.admin.id);
    // The private server dials the tunnel port where the cloud NAT maps it,
    // pinning the reported key.
    let dials = sync(&f.store, &private, Some(able(None))).dials;
    assert_eq!(dials.len(), 1);
    assert_eq!(dials[0].id, tunnel.id);
    assert_eq!(dials[0].server, "gw.example.net:49123");
    assert_eq!(dials[0].fingerprint, key);
    assert_eq!(dials[0].token, token);
    assert_eq!(dials[0].target, "192.168.10.20:8080");
    assert_eq!(dials[0].protocol, TunnelProtocol::TcpUdp);
    assert!(sync(&f.store, &third, None).dials.is_empty());
    let view = f.view(&tunnel.id);
    assert_eq!(view.rule_id.as_deref(), Some(end.id.as_str()));
    assert_eq!(
        view.reason.as_deref(),
        Some("waiting for the private server to connect")
    );
    // The third server upgrades: its UDP tunnel joins the same listener.
    let dials = sync(&f.store, &third, Some(able(None))).dials;
    assert_eq!((dials.len(), dials[0].protocol), (1, TunnelProtocol::Udp));
    let desired = sync(&f.store, &public, Some(able(Some(&key))));
    assert_eq!(desired.listeners.len(), 1);
    assert_eq!(desired.listeners[0].tunnels.len(), 2);
    assert_eq!(f.tunnel_rules(0).len(), 2);

    // The token never leaves for anything but the two agents.
    let views = serde_json::to_string(&f.store.reverse_tunnels(&f.admin).unwrap()).unwrap();
    let audit = serde_json::to_string(&f.store.audit_log(&f.admin).unwrap()).unwrap();
    let config = serde_json::to_string(&f.config(0)).unwrap();
    for text in [&views, &audit, &config] {
        assert!(!text.contains(&token));
    }

    // The rule editor may set the public end's limits but not what the
    // tunnel decides; a public end left out of an edit comes back.
    let mut config = f.config(0);
    let rule = config
        .rules
        .iter_mut()
        .find(|r| r.reverse_tunnel.as_deref() == Some(tunnel.id.as_str()))
        .unwrap();
    rule.rate_bytes_per_sec = Some(250_000);
    rule.deny_sources = vec!["198.51.100.0/24".parse().unwrap()];
    let limited = f
        .store
        .set_config(&f.admin, &public, config.revision, config.rules.clone())
        .unwrap();
    let mut retargeted = limited.rules.clone();
    for rule in &mut retargeted {
        if rule.reverse_tunnel.as_deref() == Some(tunnel.id.as_str()) {
            rule.targets[0].address = "192.0.2.99:80".into();
        }
    }
    assert_eq!(
        status(
            f.store
                .set_config(&f.admin, &public, limited.revision, retargeted)
        ),
        400
    );
    let without: Vec<Rule> = limited
        .rules
        .iter()
        .filter(|r| r.reverse_tunnel.is_none())
        .cloned()
        .collect();
    f.store
        .set_config(&f.admin, &public, limited.revision, without)
        .unwrap();
    let kept = f
        .tunnel_rules(0)
        .into_iter()
        .find(|r| r.reverse_tunnel.as_deref() == Some(tunnel.id.as_str()))
        .unwrap();
    assert_eq!(
        (kept.id.as_str(), kept.rate_bytes_per_sec),
        (end.id.as_str(), Some(250_000))
    );
    // Editing the tunnel keeps the limits, the rule and its meter period.
    let mut edit = f.input(0, 1, 22000);
    edit.name = tunnel.name.clone();
    edit.protocol = TunnelProtocol::Tcp;
    edit.target = "192.168.10.21:9090".into();
    f.store
        .update_reverse_tunnel(&f.admin, &tunnel.id, edit.clone())
        .unwrap();
    let edited = f
        .tunnel_rules(0)
        .into_iter()
        .find(|r| r.reverse_tunnel.as_deref() == Some(tunnel.id.as_str()))
        .unwrap();
    assert_eq!(
        (edited.id.as_str(), edited.meter_epoch.as_str()),
        (end.id.as_str(), end.meter_epoch.as_str())
    );
    assert_eq!(edited.rate_bytes_per_sec, Some(250_000));
    assert_eq!(edited.protocol, Protocol::Tcp);
    assert_eq!(edited.targets[0].address, "192.168.10.21:9090");
    assert_eq!(
        sync(&f.store, &private, Some(able(None))).dials[0].target,
        "192.168.10.21:9090"
    );
    assert_eq!(
        f.store
            .metadata(&format!("reverse_tunnel_token:{}", tunnel.id))
            .unwrap()
            .as_ref(),
        Some(&token),
        "the same servers keep the token"
    );

    // Disabled: the listener drops the tunnel, the private server stops
    // dialing and the public end stops listening.
    edit.enabled = Some(false);
    f.store
        .update_reverse_tunnel(&f.admin, &tunnel.id, edit.clone())
        .unwrap();
    assert!(sync(&f.store, &private, Some(able(None))).dials.is_empty());
    let desired = sync(&f.store, &public, Some(able(Some(&key))));
    assert_eq!(desired.listeners[0].tunnels.len(), 1);
    assert_ne!(desired.listeners[0].tunnels[0].id, tunnel.id);
    let disabled = f
        .tunnel_rules(0)
        .into_iter()
        .find(|r| r.reverse_tunnel.as_deref() == Some(tunnel.id.as_str()))
        .unwrap();
    assert!(!disabled.enabled);
    assert_eq!(f.view(&tunnel.id).state, State::Disabled);
    // Deleted: its public end, token and every trace in sync go.
    f.store.delete_reverse_tunnel(&f.admin, &tunnel.id).unwrap();
    f.store.delete_reverse_tunnel(&f.admin, &udp.id).unwrap();
    assert!(f.tunnel_rules(0).is_empty());
    assert!(
        f.store
            .metadata(&format!("reverse_tunnel_token:{}", tunnel.id))
            .unwrap()
            .is_none()
    );
    let desired = sync(&f.store, &public, Some(able(Some(&key))));
    assert!(!desired.key && empty(&desired));
    assert!(empty(&sync(&f.store, &third, Some(able(None)))));
    let actions: Vec<String> = f
        .store
        .audit_log(&f.admin)
        .unwrap()
        .iter()
        .filter_map(|e| e["action"].as_str().map(str::to_owned))
        .filter(|a| a.starts_with("reverse_tunnel."))
        .collect();
    for action in [
        "reverse_tunnel.create",
        "reverse_tunnel.update",
        "reverse_tunnel.delete",
    ] {
        assert!(actions.iter().any(|a| a == action), "{actions:?}");
    }
    let audit = serde_json::to_string(&f.store.audit_log(&f.admin).unwrap()).unwrap();
    assert!(!audit.contains(&token));
}

#[test]
fn changing_servers_renews_the_token_and_the_watch_wakes_both_ends() {
    let f = Fixture::new(3);
    f.behind_nat(0);
    let (public, private) = (f.id(0), f.id(1));
    let mut credentials = vec![];
    for (node, token) in f.nodes.iter().zip(&f.enrollments) {
        let credential = relay_platform::store::secret();
        f.store.enroll(&node.id, token, &credential).unwrap();
        credentials.push(credential);
    }
    let key = Identity::generate().unwrap().fingerprint();
    sync(&f.store, &public, Some(able(Some(&key))));
    sync(&f.store, &private, Some(able(None)));
    sync(&f.store, &f.id(2), Some(able(None)));
    for credential in &credentials {
        f.store.node_watch(credential).unwrap();
    }
    let tunnel = f.create(f.input(0, 1, 22000)).unwrap();
    // A change wakes both ends' watches once, so they sync at once.
    assert!(f.store.node_watch(&credentials[0]).unwrap().2);
    assert!(f.store.node_watch(&credentials[1]).unwrap().2);
    assert!(!f.store.node_watch(&credentials[1]).unwrap().2, "once");
    assert!(!f.store.node_watch(&credentials[2]).unwrap().2);
    let token = |f: &Fixture| {
        f.store
            .metadata(&format!("reverse_tunnel_token:{}", tunnel.id))
            .unwrap()
            .unwrap()
    };
    let before = token(&f);
    let mut moved = f.input(0, 2, 22000);
    moved.name = tunnel.name.clone();
    f.store
        .update_reverse_tunnel(&f.admin, &tunnel.id, moved)
        .unwrap();
    assert_ne!(
        token(&f),
        before,
        "another server must not keep a working token"
    );
    assert!(
        f.store.node_watch(&credentials[1]).unwrap().2,
        "the old end stops"
    );
    assert!(
        f.store.node_watch(&credentials[2]).unwrap().2,
        "the new end starts"
    );
    assert!(sync(&f.store, &private, Some(able(None))).dials.is_empty());
    assert_eq!(sync(&f.store, &f.id(2), Some(able(None))).dials.len(), 1);
}

#[test]
fn deleting_a_server_is_not_blocked_and_shows_it_missing() {
    let f = Fixture::new(3);
    let key = Identity::generate().unwrap().fingerprint();
    sync(&f.store, &f.id(0), Some(able(Some(&key))));
    sync(&f.store, &f.id(1), Some(able(None)));
    let tunnel = f.create(f.input(0, 1, 22000)).unwrap();
    assert_eq!(f.tunnel_rules(0).len(), 1);
    f.store.delete_node(&f.admin, &f.id(1)).unwrap();
    let view = f.view(&tunnel.id);
    assert!(view.private_missing && !view.public_missing);
    assert_eq!(view.state, State::Error);
    assert_eq!(
        view.reason.as_deref(),
        Some("the private server was deleted")
    );
    assert!(f.tunnel_rules(0).is_empty(), "the public end goes with it");
    assert!(
        sync(&f.store, &f.id(0), Some(able(Some(&key))))
            .listeners
            .is_empty()
    );
    f.store.delete_node(&f.admin, &f.id(0)).unwrap();
    assert!(f.view(&tunnel.id).public_missing);
    // The record can still be removed by someone who may write the tenant.
    f.store.delete_reverse_tunnel(&f.admin, &tunnel.id).unwrap();
    assert!(f.store.reverse_tunnels(&f.admin).unwrap().is_empty());
}

async fn serve(store: Store) -> (SocketAddr, CancellationToken) {
    let stop = CancellationToken::new();
    let router = api::router(AppState::new(store).with_shutdown(stop.clone()));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let shutdown = stop.clone();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await
        .unwrap();
    });
    (address, stop)
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
struct Api {
    client: reqwest::Client,
    origin: String,
}
impl Api {
    async fn call(
        &self,
        method: reqwest::Method,
        path: &str,
        token: &str,
        body: Option<Value>,
    ) -> (u16, Value) {
        let request = self
            .client
            .request(method, format!("{}/api/v1{path}", self.origin))
            .bearer_auth(token);
        let request = match body {
            Some(body) => request.json(&body),
            None => request,
        };
        let response = request.send().await.unwrap();
        let status = response.status().as_u16();
        let text = response.text().await.unwrap();
        (
            status,
            serde_json::from_str(&text).unwrap_or(Value::String(text)),
        )
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_api_checks_input_roles_scopes_and_tenants() {
    let f = Fixture::new(3);
    f.ordinary(0, "busy", 21000).unwrap();
    f.store
        .create_user(&f.admin, "default", "readonly", PASSWORD, Role::Viewer)
        .unwrap();
    let other = f.store.create_tenant(&f.admin, "other").unwrap();
    f.store
        .create_user(&f.admin, &other, "neighbour", PASSWORD, Role::TenantAdmin)
        .unwrap();
    let (foreign, _) = f.store.create_node(&f.admin, &other, "foreign").unwrap();
    let (foreign_two, _) = f.store.create_node(&f.admin, &other, "foreign-2").unwrap();
    let (address, stop) = serve(f.store.clone()).await;
    let api = Api {
        client: reqwest::Client::builder().no_proxy().build().unwrap(),
        origin: format!("http://{address}"),
    };
    let admin = login(&api.client, &api.origin, "admin").await;
    let viewer = login(&api.client, &api.origin, "readonly").await;
    let neighbour = login(&api.client, &api.origin, "neighbour").await;
    let (reader, _) = f
        .store
        .create_api_token(&f.admin, "reader", &[Scope::Read], 1)
        .unwrap();
    let (writer, _) = f
        .store
        .create_api_token(&f.admin, "writer", &[Scope::NodesWrite], 1)
        .unwrap();
    let body = |port: u16| {
        json!({"name": "Home NAS", "public_node_id": f.id(0), "private_node_id": f.id(1),
               "public_port": port, "protocol": "tcp_udp", "target": "192.168.10.20:8080"})
    };
    use reqwest::Method;
    // Invalid input is 400; a taken port 409.
    for bad in [
        json!({"name": "x", "public_node_id": f.id(0), "private_node_id": f.id(1), "public_port": 22000, "protocol": "sctp", "target": "127.0.0.1:80"}),
        json!({"name": "x", "public_node_id": f.id(0), "private_node_id": f.id(1), "public_port": 22000, "protocol": "tcp", "target": "127.0.0.1:80", "token": "mine"}),
        json!({"name": "x", "public_node_id": f.id(0), "private_node_id": f.id(0), "public_port": 22000, "protocol": "tcp", "target": "127.0.0.1:80"}),
        json!({"name": "x", "public_node_id": f.id(0), "private_node_id": f.id(1), "public_port": 22000, "protocol": "tcp", "target": "nowhere"}),
        json!({"name": "x", "public_node_id": f.id(0), "private_node_id": foreign.id, "public_port": 22000, "protocol": "tcp", "target": "127.0.0.1:80"}),
    ] {
        let (code, reply) = api
            .call(Method::POST, "/reverse-tunnels", &admin, Some(bad))
            .await;
        assert_eq!(code, 400, "{reply}");
    }
    let (code, reply) = api
        .call(Method::POST, "/reverse-tunnels", &admin, Some(body(21000)))
        .await;
    assert_eq!(code, 409, "{reply}");
    // Read-only accounts and read-scoped tokens may list but not change.
    assert_eq!(
        api.call(Method::POST, "/reverse-tunnels", &viewer, Some(body(22000)))
            .await
            .0,
        403
    );
    assert_eq!(
        api.call(Method::POST, "/reverse-tunnels", &reader, Some(body(22000)))
            .await
            .0,
        403
    );
    let (code, created) = api
        .call(Method::POST, "/reverse-tunnels", &writer, Some(body(22000)))
        .await;
    assert_eq!(code, 200, "{created}");
    let id = created["id"].as_str().unwrap().to_owned();
    assert_eq!(created["tunnel_port"], 29123);
    assert_eq!(created["enabled"], true);
    assert_eq!(created["state"], "waiting");
    assert!(created.get("token").is_none());
    for token in [&viewer, &reader] {
        let (code, listed) = api.call(Method::GET, "/reverse-tunnels", token, None).await;
        assert_eq!(code, 200);
        assert_eq!(listed[0]["id"], id.as_str());
        assert_eq!(
            listed[0]["reason"],
            "the public server has not connected to the panel yet"
        );
    }
    let secret = f
        .store
        .metadata(&format!("reverse_tunnel_token:{id}"))
        .unwrap()
        .unwrap();
    let (_, listed) = api
        .call(Method::GET, "/reverse-tunnels", &admin, None)
        .await;
    assert!(!listed.to_string().contains(&secret));
    // Another tenant sees nothing, cannot change it and cannot use its servers.
    let (code, listed) = api
        .call(Method::GET, "/reverse-tunnels", &neighbour, None)
        .await;
    assert_eq!((code, listed), (200, json!([])));
    let path = format!("/reverse-tunnels/{id}");
    assert_eq!(
        api.call(Method::PUT, &path, &neighbour, Some(body(22000)))
            .await
            .0,
        404
    );
    assert_eq!(
        api.call(Method::DELETE, &path, &neighbour, None).await.0,
        404
    );
    let mut theirs = body(22000);
    theirs["private_node_id"] = foreign.id.clone().into();
    theirs["public_node_id"] = foreign_two.id.clone().into();
    let (code, mine) = api
        .call(
            Method::POST,
            "/reverse-tunnels",
            &neighbour,
            Some(theirs.clone()),
        )
        .await;
    assert_eq!(code, 200, "{mine}");
    assert_eq!(mine["tenant_id"], other.as_str());
    theirs["public_node_id"] = f.id(0).into();
    assert_eq!(
        api.call(Method::POST, "/reverse-tunnels", &neighbour, Some(theirs))
            .await
            .0,
        404
    );
    // A paused server cannot run tunnels: 409.
    let mut paused = body(22000);
    paused["private_node_id"] = paused_node(&f.store, &f.admin).into();
    let (code, reply) = api.call(Method::PUT, &path, &admin, Some(paused)).await;
    assert_eq!(code, 409, "{reply}");
    let mut disabled = body(22000);
    disabled["enabled"] = false.into();
    let (code, updated) = api.call(Method::PUT, &path, &writer, Some(disabled)).await;
    assert_eq!(code, 200, "{updated}");
    assert_eq!(updated["state"], "disabled");
    assert_eq!(api.call(Method::DELETE, &path, &viewer, None).await.0, 403);
    assert_eq!(api.call(Method::DELETE, &path, &admin, None).await.0, 200);
    assert_eq!(api.call(Method::DELETE, &path, &admin, None).await.0, 404);
    let (_, listed) = api
        .call(Method::GET, "/reverse-tunnels", &admin, None)
        .await;
    assert_eq!(
        listed.as_array().unwrap().len(),
        1,
        "only the other tenant's"
    );
    stop.cancel();
}

/// A TCP relay in front of the tunnel listener whose connections the test
/// can cut, as a network outage would. Counts the connections it carried
/// to the listener.
struct Cutter {
    address: SocketAddr,
    carried: Arc<AtomicUsize>,
    cut: Arc<Mutex<CancellationToken>>,
    stop: CancellationToken,
}
impl Cutter {
    async fn start(to: SocketAddr) -> Self {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let carried = Arc::new(AtomicUsize::new(0));
        let cut = Arc::new(Mutex::new(CancellationToken::new()));
        let stop = CancellationToken::new();
        let (count, cuts, done) = (carried.clone(), cut.clone(), stop.clone());
        tokio::spawn(async move {
            loop {
                let accepted =
                    tokio::select! {_ = done.cancelled() => break, a = listener.accept() => a};
                let Ok((mut inbound, _)) = accepted else {
                    break;
                };
                let cut = cuts.lock().unwrap().clone();
                let count = count.clone();
                tokio::spawn(async move {
                    let Ok(mut outbound) = TcpStream::connect(to).await else {
                        return;
                    };
                    count.fetch_add(1, Ordering::SeqCst);
                    tokio::select! {
                        _ = cut.cancelled() => {}
                        _ = tokio::io::copy_bidirectional(&mut inbound, &mut outbound) => {}
                    }
                });
            }
        });
        Self {
            address,
            carried,
            cut,
            stop,
        }
    }
    fn cut(&self) {
        let mut cut = self.cut.lock().unwrap();
        cut.cancel();
        *cut = CancellationToken::new();
    }
}
impl Drop for Cutter {
    fn drop(&mut self) {
        self.stop.cancel();
        self.cut.lock().unwrap().cancel();
    }
}

/// One TCP exchange, `None` when the connection fails or is cut.
async fn try_exchange(address: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    timeout(Duration::from_secs(3), async {
        let mut stream = TcpStream::connect(address).await.ok()?;
        stream.write_all(payload).await.ok()?;
        stream.shutdown().await.ok()?;
        let mut bytes = vec![];
        stream.read_to_end(&mut bytes).await.ok()?;
        Some(bytes)
    })
    .await
    .ok()?
}
async fn datagram(address: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(payload, address).await.ok()?;
    let mut buffer = vec![0; 65536];
    let length = timeout(Duration::from_secs(1), socket.recv(&mut buffer))
        .await
        .ok()?
        .ok()?;
    buffer.truncate(length);
    Some(buffer)
}
fn agent_options(origin: &str, node: &str, token: &Path) -> AgentOptions {
    AgentOptions {
        controller: origin.into(),
        node_id: node.into(),
        enrollment_token_file: Some(token.into()),
        ca_certificate: None,
        tls_directory: None,
        poll_interval: Duration::from_millis(50),
        controller_addresses: vec![],
        controller_proxy: None,
    }
}
async fn wait_for(api: &Api, token: &str, what: &str, check: impl Fn(&Value) -> bool) -> Value {
    let until = Instant::now() + Duration::from_secs(20);
    loop {
        let (_, listed) = api
            .call(reqwest::Method::GET, "/reverse-tunnels", token, None)
            .await;
        let view = listed[0].clone();
        if check(&view) {
            return view;
        }
        assert!(Instant::now() < until, "waiting for {what}: {view}");
        sleep(Duration::from_millis(100)).await;
    }
}
async fn wait_status(client: &managed::Client, failing: bool) -> managed::Status {
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        if let Some(status) = client.status().into_iter().next()
            && status.error.is_some() == failing
        {
            return status;
        }
        assert!(Instant::now() < until, "{:?}", client.status());
        sleep(Duration::from_millis(50)).await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_agents_carry_metered_tcp_and_udp_through_the_tunnel() {
    let temp = tempfile::tempdir().unwrap();
    let control = Store::open(&temp.path().join("controller.db")).unwrap();
    control.set_kind("controller").unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    let (address, stop_api) = serve(control.clone()).await;
    let api = Api {
        client: reqwest::Client::builder().no_proxy().build().unwrap(),
        origin: format!("http://{address}"),
    };
    let token = login(&api.client, &api.origin, "admin").await;
    let (public, public_enrollment) = control.create_node(&admin, "default", "public").unwrap();
    let (private, private_enrollment) = control.create_node(&admin, "default", "private").unwrap();
    // The private server reaches the tunnel port through a relay standing in
    // for the internet (the public server's NAT maps the port onto it).
    let tunnel_port = free_address().port();
    let public_port = free_address().port();
    let cutter = Cutter::start(SocketAddr::from(([127, 0, 0, 1], tunnel_port))).await;
    let node = control
        .nodes(&admin)
        .unwrap()
        .into_iter()
        .find(|n| n.id == public.id)
        .unwrap();
    control
        .update_node(
            &admin,
            &public.id,
            NodeUpdate {
                expected_revision: node.profile.revision,
                name: node.name.clone(),
                settings: NodeSettings {
                    forwarding: Some(ForwardingDefaults {
                        host: "127.0.0.1".into(),
                        listen_ip: None,
                        port_start: tunnel_port,
                        port_end: tunnel_port,
                        public_port_start: Some(cutter.address.port()),
                    }),
                    ..Default::default()
                },
            },
        )
        .unwrap();
    let (tcp_target, _udp_target) = tcp_udp_echo().await;
    let (code, created) = api
        .call(
            reqwest::Method::POST,
            "/reverse-tunnels",
            &token,
            Some(json!({"name": "Home lab", "public_node_id": public.id, "private_node_id": private.id,
                        "public_port": public_port, "protocol": "tcp_udp",
                        "target": tcp_target.address.to_string(), "tunnel_port": tunnel_port})),
        )
        .await;
    assert_eq!(code, 200, "{created}");
    let id = created["id"].as_str().unwrap().to_owned();
    let entry: SocketAddr = created["entry"].as_str().unwrap().parse().unwrap();
    assert_eq!(entry, SocketAddr::from(([127, 0, 0, 1], public_port)));

    let mut agents = vec![];
    let mut stores = vec![];
    for (name, node, enrollment) in [
        ("public", &public.id, &public_enrollment),
        ("private", &private.id, &private_enrollment),
    ] {
        let secret = temp.path().join(format!("{name}.secret"));
        write_secret(&secret, enrollment.as_bytes()).unwrap();
        let db = Store::open(&temp.path().join(format!("{name}.db"))).unwrap();
        let stop = CancellationToken::new();
        agents.push((
            stop.clone(),
            tokio::spawn(agent::run(
                db.clone(),
                agent_options(&api.origin, node, &secret),
                stop,
            )),
        ));
        stores.push(db);
    }
    let view = wait_for(&api, &token, "the tunnel", |v| v["state"] == "connected").await;
    assert!(view["connected_for_secs"].as_u64().is_some(), "{view}");
    assert!(view["reason"].is_null());

    // TCP and UDP through the public port reach the private side's target.
    let payload: Vec<u8> = (0..3000u32).map(|i| (i * 7 % 251) as u8).collect();
    assert_eq!(exchange(entry, &payload).await, payload);
    let (mut sent, mut received) = (0u64, 0u64);
    let packet = vec![0x5a; 700];
    let until = Instant::now() + Duration::from_secs(10);
    loop {
        sent += 1;
        if let Some(reply) = datagram(entry, &packet).await {
            assert_eq!(reply, packet);
            received += 1;
            break;
        }
        assert!(Instant::now() < until, "no UDP reply through the tunnel");
    }
    // The public end is metered like any rule, onto the usage pages.
    let up = 3000 + sent * 700;
    let down = 3000 + received * 700;
    let view = wait_for(&api, &token, "the usage report", |v| {
        v["upload_bytes"] == up && v["download_bytes"] == down
    })
    .await;
    let rule_id = view["rule_id"].as_str().unwrap();
    let usage = control
        .rule_usage(&admin)
        .unwrap()
        .into_iter()
        .find(|u| u.rule_id == rule_id)
        .expect("the public end is on the usage page");
    assert_eq!(
        (
            usage.node_id.as_str(),
            usage.upload_bytes,
            usage.download_bytes
        ),
        (public.id.as_str(), up, down)
    );

    // Source rules of the public end apply to tunnel clients too.
    let config = control.config(&admin, &public.id, None).unwrap();
    let mut rules = config.rules.clone();
    rules[0].deny_sources = vec!["127.0.0.0/8".parse().unwrap()];
    let denied = control
        .set_config(&admin, &public.id, config.revision, rules)
        .unwrap();
    let until = Instant::now() + Duration::from_secs(10);
    while try_exchange(entry, b"blocked?").await.as_deref() == Some(b"blocked?") {
        assert!(Instant::now() < until, "the deny rule never applied");
        sleep(Duration::from_millis(100)).await;
    }
    let mut rules = denied.rules.clone();
    rules[0].deny_sources = vec![];
    control
        .set_config(&admin, &public.id, denied.revision, rules)
        .unwrap();

    // Only the pinned key and the right token open the tunnel.
    let saved = stores[0]
        .metadata("agent_reverse_tunnel_key")
        .unwrap()
        .unwrap();
    let fingerprint = Identity::from_saved(&saved).unwrap().fingerprint();
    let secret = control
        .metadata(&format!("reverse_tunnel_token:{id}"))
        .unwrap()
        .unwrap();
    let rogue = |fingerprint: String, token: String| {
        let client = managed::Client::default();
        client.reconcile(&[managed::Dial {
            id: id.clone(),
            server: format!("127.0.0.1:{tunnel_port}"),
            fingerprint,
            token,
            target: "127.0.0.1:9".into(),
            tcp: true,
            udp: false,
        }]);
        client
    };
    let impostor = rogue(Identity::generate().unwrap().fingerprint(), secret.clone());
    let refused = wait_status(&impostor, true).await;
    assert!(refused.error.unwrap().contains("does not match"));
    let guesser = rogue(fingerprint.clone(), "00".repeat(32));
    let refused = wait_status(&guesser, true).await;
    assert!(refused.error.unwrap().contains("rejected the tunnel token"));
    drop((impostor, guesser));
    let until = Instant::now() + Duration::from_secs(10);
    while try_exchange(entry, &payload).await.as_deref() != Some(&payload[..]) {
        assert!(Instant::now() < until, "the tunnel stopped working");
        sleep(Duration::from_millis(100)).await;
    }

    // The tunnel connection drops: the private server dials again.
    let dials = cutter.carried.load(Ordering::SeqCst);
    assert_eq!(dials, 1, "one connection carried everything so far");
    cutter.cut();
    let until = Instant::now() + Duration::from_secs(15);
    while cutter.carried.load(Ordering::SeqCst) == dials
        || try_exchange(entry, &payload).await.as_deref() != Some(&payload[..])
    {
        assert!(Instant::now() < until, "no reconnect");
        sleep(Duration::from_millis(100)).await;
    }
    wait_for(&api, &token, "the reconnected tunnel", |v| {
        v["state"] == "connected"
    })
    .await;

    // Disabled: the public port closes and the private server stops dialing.
    let (code, _) = api
        .call(
            reqwest::Method::PUT,
            &format!("/reverse-tunnels/{id}"),
            &token,
            Some(json!({"name": "Home lab", "public_node_id": public.id, "private_node_id": private.id,
                        "public_port": public_port, "protocol": "tcp_udp",
                        "target": tcp_target.address.to_string(), "tunnel_port": tunnel_port,
                        "enabled": false})),
        )
        .await;
    assert_eq!(code, 200);
    let until = Instant::now() + Duration::from_secs(10);
    while TcpStream::connect(entry).await.is_ok()
        || TcpStream::connect(("127.0.0.1", tunnel_port)).await.is_ok()
    {
        assert!(Instant::now() < until, "the ports stayed open");
        sleep(Duration::from_millis(100)).await;
    }
    let view = wait_for(&api, &token, "disabled", |v| v["state"] == "disabled").await;
    assert!(view["upload_bytes"].as_u64().unwrap() >= up);
    sleep(Duration::from_millis(500)).await;
    let after = cutter.carried.load(Ordering::SeqCst);
    sleep(Duration::from_secs(2)).await;
    assert_eq!(
        cutter.carried.load(Ordering::SeqCst),
        after,
        "still dialing"
    );
    assert_eq!(
        api.call(
            reqwest::Method::DELETE,
            &format!("/reverse-tunnels/{id}"),
            &token,
            None
        )
        .await
        .0,
        200
    );
    for (stop, task) in agents {
        stop.cancel();
        timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    stop_api.cancel();
}

/// A TCP and UDP echo on one port that counts what reached it.
struct Counted {
    address: SocketAddr,
    tcp: Arc<AtomicUsize>,
    udp: Arc<AtomicUsize>,
    stop: CancellationToken,
}
impl Counted {
    async fn start() -> Self {
        let (listener, socket) = loop {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            if let Ok(socket) = UdpSocket::bind(listener.local_addr().unwrap()).await {
                break (listener, socket);
            }
        };
        let address = listener.local_addr().unwrap();
        let (tcp, udp) = (Arc::new(AtomicUsize::new(0)), Arc::new(AtomicUsize::new(0)));
        let stop = CancellationToken::new();
        let (count, done) = (tcp.clone(), stop.clone());
        tokio::spawn(async move {
            loop {
                let accepted =
                    tokio::select! {_ = done.cancelled() => break, a = listener.accept() => a};
                let Ok((mut stream, _)) = accepted else {
                    break;
                };
                count.fetch_add(1, Ordering::SeqCst);
                tokio::spawn(async move {
                    let (mut read, mut write) = stream.split();
                    let _ = tokio::io::copy(&mut read, &mut write).await;
                });
            }
        });
        let (count, done) = (udp.clone(), stop.clone());
        tokio::spawn(async move {
            let mut buffer = vec![0; 65536];
            loop {
                let received = tokio::select! {_ = done.cancelled() => break, r = socket.recv_from(&mut buffer) => r};
                let Ok((length, peer)) = received else {
                    break;
                };
                count.fetch_add(1, Ordering::SeqCst);
                let _ = socket.send_to(&buffer[..length], peer).await;
            }
        });
        Self {
            address,
            tcp,
            udp,
            stop,
        }
    }
    fn reached(&self) -> (usize, usize) {
        (
            self.tcp.load(Ordering::SeqCst),
            self.udp.load(Ordering::SeqCst),
        )
    }
}
impl Drop for Counted {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
/// One TCP exchange from the loopback address `source`.
async fn exchange_from(source: [u8; 4], address: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    timeout(Duration::from_secs(3), async {
        let socket = tokio::net::TcpSocket::new_v4().ok()?;
        socket.bind(SocketAddr::from((source, 0))).ok()?;
        let mut stream = socket.connect(address).await.ok()?;
        stream.write_all(payload).await.ok()?;
        stream.shutdown().await.ok()?;
        let mut bytes = vec![];
        stream.read_to_end(&mut bytes).await.ok()?;
        Some(bytes)
    })
    .await
    .ok()?
}
/// One UDP datagram and its reply, from the loopback address `source`.
async fn datagram_from(source: [u8; 4], address: SocketAddr, payload: &[u8]) -> Option<Vec<u8>> {
    let socket = UdpSocket::bind(SocketAddr::from((source, 0)))
        .await
        .unwrap();
    socket.send_to(payload, address).await.ok()?;
    let mut buffer = vec![0; 65536];
    let length = timeout(Duration::from_secs(1), socket.recv(&mut buffer))
        .await
        .ok()?
        .ok()?;
    buffer.truncate(length);
    Some(buffer)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_private_end_holds_its_targets_to_its_outbound_set() {
    let temp = tempfile::tempdir().unwrap();
    let control = Store::open(&temp.path().join("controller.db")).unwrap();
    control.set_kind("controller").unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    let (address, stop_api) = serve(control.clone()).await;
    let api = Api {
        client: reqwest::Client::builder().no_proxy().build().unwrap(),
        origin: format!("http://{address}"),
    };
    let token = login(&api.client, &api.origin, "admin").await;
    let (public, public_enrollment) = control.create_node(&admin, "default", "public").unwrap();
    let (private, private_enrollment) = control.create_node(&admin, "default", "private").unwrap();
    let tunnel_port = free_address().port();
    let public_port = free_address().port();
    let node = control
        .nodes(&admin)
        .unwrap()
        .into_iter()
        .find(|n| n.id == public.id)
        .unwrap();
    control
        .update_node(
            &admin,
            &public.id,
            NodeUpdate {
                expected_revision: node.profile.revision,
                name: node.name.clone(),
                settings: NodeSettings {
                    forwarding: Some(ForwardingDefaults {
                        host: "127.0.0.1".into(),
                        listen_ip: None,
                        port_start: tunnel_port,
                        port_end: tunnel_port,
                        public_port_start: None,
                    }),
                    ..Default::default()
                },
            },
        )
        .unwrap();
    // A named target: the private server resolves it, and the set judges
    // the name and every address it resolves to.
    let target = Counted::start().await;
    let port = target.address.port();
    let (code, created) = api
        .call(
            reqwest::Method::POST,
            "/reverse-tunnels",
            &token,
            Some(json!({"name": "Home lab", "public_node_id": public.id, "private_node_id": private.id,
                        "public_port": public_port, "protocol": "tcp_udp",
                        "target": format!("localhost:{port}"), "tunnel_port": tunnel_port})),
        )
        .await;
    assert_eq!(code, 200, "{created}");
    let entry: SocketAddr = created["entry"].as_str().unwrap().parse().unwrap();
    let mut agents = vec![];
    for (name, node, enrollment) in [
        ("public", &public.id, &public_enrollment),
        ("private", &private.id, &private_enrollment),
    ] {
        let secret = temp.path().join(format!("{name}.secret"));
        write_secret(&secret, enrollment.as_bytes()).unwrap();
        let db = Store::open(&temp.path().join(format!("{name}.db"))).unwrap();
        let stop = CancellationToken::new();
        agents.push((
            stop.clone(),
            tokio::spawn(agent::run(
                db,
                agent_options(&api.origin, node, &secret),
                stop,
            )),
        ));
    }
    let view = wait_for(&api, &token, "the tunnel", |v| v["state"] == "connected").await;
    let rule_id = view["rule_id"].as_str().unwrap().to_owned();
    let node_view = |id: String| {
        let api = &api;
        let token = &token;
        async move {
            let (_, nodes) = api.call(reqwest::Method::GET, "/nodes", token, None).await;
            nodes
                .as_array()
                .unwrap()
                .iter()
                .find(|n| n["id"] == id)
                .unwrap()
                .clone()
        }
    };
    let works = |source: [u8; 4]| async move {
        exchange_from(source, entry, b"through").await.as_deref() == Some(&b"through"[..])
            && datagram_from(source, entry, b"datagram").await.as_deref() == Some(&b"datagram"[..])
    };
    let until = Instant::now() + Duration::from_secs(10);
    while !works([127, 0, 0, 1]).await {
        assert!(Instant::now() < until, "the open tunnel never answered");
    }
    // Shown as covered: this agent holds tunnels to the outbound set.
    let private_view = node_view(private.id.clone()).await;
    assert_eq!(
        private_view["firewall"]["uncovered"],
        json!([]),
        "{private_view}"
    );

    // Bound and confirmed on the private server: neither TCP nor UDP from
    // the public port reaches the target any more.
    let set_rules = |destination: &str, port: u16| json!([{"action": "deny", "match": {"destinations": [destination], "ports": [port.to_string()]}}]);
    let (code, set) = api
        .call(
            reqwest::Method::POST,
            "/firewall/sets",
            &token,
            Some(
                json!({"name": "No lab", "scope": "system", "direction": "outbound",
                        "default_action": "allow", "rules": set_rules("localhost", port)}),
            ),
        )
        .await;
    assert_eq!(code, 200, "{set}");
    let set_id = set["id"].as_str().unwrap().to_owned();
    let (code, bound) = api
        .call(
            reqwest::Method::PUT,
            &format!("/nodes/{}/firewall", private.id),
            &token,
            Some(json!({"inbound_set_id": null, "outbound_set_id": set_id})),
        )
        .await;
    assert_eq!(code, 200, "{bound}");
    let confirmed = |revision: Option<Value>| {
        let node_view = &node_view;
        let private = private.id.clone();
        async move {
            let until = Instant::now() + Duration::from_secs(20);
            loop {
                let view = node_view(private.clone()).await;
                if view["firewall"]["state"] == "applied"
                    && revision
                        .as_ref()
                        .is_none_or(|r| view["firewall"]["desired_hash"] != *r)
                {
                    return view;
                }
                assert!(Instant::now() < until, "not confirmed: {view}");
                sleep(Duration::from_millis(50)).await;
            }
        }
    };
    let first = confirmed(None).await;
    let before = target.reached();
    assert_eq!(
        exchange_from([127, 0, 0, 2], entry, b"through")
            .await
            .unwrap_or_default(),
        b"",
        "the public end closed the refused TCP connection"
    );
    // One refused datagram, one record: the public end learns why the
    // association ended before it ends.
    assert_eq!(
        datagram_from([127, 0, 0, 3], entry, b"datagram").await,
        None
    );
    sleep(Duration::from_millis(300)).await;
    assert_eq!(
        target.reached(),
        before,
        "nothing reached the refused target"
    );
    // The public end records the refusal against the tunnel's client.
    let blocks = |source: &'static str| {
        let api = &api;
        let token = &token;
        let path = format!("/nodes/{}/blocks?rule_id={rule_id}", public.id);
        async move {
            let until = Instant::now() + Duration::from_secs(20);
            loop {
                let (_, view) = api.call(reqwest::Method::GET, &path, token, None).await;
                if let Some(block) = view["blocks"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .find(|b| b["source"] == source && b["reason"] == "firewall")
                {
                    return block.clone();
                }
                assert!(Instant::now() < until, "no record for {source}: {view}");
                sleep(Duration::from_millis(50)).await;
            }
        }
    };
    let detail = "reverse tunnel private server: server outbound rule set: rule 1 denies (No lab)";
    let tcp = blocks("127.0.0.2").await;
    assert_eq!(
        (tcp["protocol"].as_str(), tcp["detail"].as_str()),
        (Some("tcp"), Some(detail))
    );
    let udp = blocks("127.0.0.3").await;
    assert_eq!(
        (
            udp["protocol"].as_str(),
            udp["detail"].as_str(),
            udp["count"].as_u64()
        ),
        (Some("udp"), Some(detail), Some(1))
    );

    // Edits reach the private server without publishing anything. Its
    // addresses are judged too, not only the name it was given.
    let edit = |revision: u64, destinations: &[&str]| {
        let api = &api;
        let token = &token;
        let path = format!("/firewall/sets/{set_id}");
        let mut rules = set_rules("", port);
        rules[0]["match"]["destinations"] = json!(destinations);
        let body = json!({"name": "No lab", "direction": "outbound", "default_action": "allow",
                          "expected_revision": revision, "rules": rules});
        async move {
            let (code, edited) = api
                .call(reqwest::Method::PUT, &path, token, Some(body))
                .await;
            assert_eq!(code, 200, "{edited}");
        }
    };
    // localhost resolves to 127.0.0.1 and ::1 here; refusing ::1 leaves the
    // address the target listens on.
    edit(1, &["::1/128"]).await;
    let second = confirmed(Some(first["firewall"]["desired_hash"].clone())).await;
    let until = Instant::now() + Duration::from_secs(10);
    while !works([127, 0, 0, 4]).await {
        assert!(
            Instant::now() < until,
            "the edited set never let the target through"
        );
    }
    edit(2, &["127.0.0.0/8", "::1/128"]).await;
    let third = confirmed(Some(second["firewall"]["desired_hash"].clone())).await;
    let before = target.reached();
    assert_eq!(
        exchange_from([127, 0, 0, 5], entry, b"through")
            .await
            .unwrap_or_default(),
        b""
    );
    assert_eq!(
        datagram_from([127, 0, 0, 5], entry, b"datagram").await,
        None
    );
    sleep(Duration::from_millis(300)).await;
    assert_eq!(target.reached(), before, "refused by its addresses");
    assert_eq!(
        third["desired_revision"], first["desired_revision"],
        "no configuration was published"
    );
    for (stop, task) in agents {
        stop.cancel();
        timeout(Duration::from_secs(10), task)
            .await
            .unwrap()
            .unwrap()
            .unwrap();
    }
    stop_api.cancel();
}

/// One sync of an agent that carries tunnels and enforces rule sets, also
/// on the paths `covers` names (none, as 0.150.0).
fn sync_covering(db: &Store, node: &str, report: Report, covers: &[&str]) -> Desired {
    let stats = EngineStats {
        reverse_tunnel: Some(report),
        firewall: Some(relay_platform::firewall::Report {
            covers: covers.iter().map(|c| c.to_string()).collect(),
            ..Default::default()
        }),
        ..EngineStats::default()
    };
    db.sync(
        node,
        SyncRequest {
            logs: None,
            lease: None,
            budget: None,
            ledger_id: ledger(db, node),
            need_config: false,
            applied_revision: 0,
            apply_error: None,
            usage: vec![],
            stats,
        },
    )
    .unwrap()
    .reverse_tunnels
    .expect("this controller always sends tunnels")
}
fn refusal<T: std::fmt::Debug>(result: anyhow::Result<T>) -> (u16, String) {
    let error = result.unwrap_err();
    let rejection = error.downcast_ref::<Rejection>().expect("a rejection");
    (rejection.status, rejection.message.clone())
}

#[test]
fn a_private_server_bound_to_an_outbound_set_needs_an_agent_that_holds_its_tunnels_to_it() {
    use relay_platform::firewall::{COVERS, ServerBinding, SetInput};
    let f = Fixture::new(2);
    f.behind_nat(0);
    let (public, private) = (f.id(0), f.id(1));
    let key = Identity::generate().unwrap().fingerprint();
    sync_covering(&f.store, &public, able(Some(&key)), &COVERS);
    // The private agent enforces rule sets but not on tunnels, as 0.150.0.
    sync_covering(&f.store, &private, able(None), &[]);
    let set: SetInput = serde_json::from_value(json!({
        "name": "No lab", "scope": "system", "direction": "outbound", "default_action": "allow",
        "rules": [{"action": "deny", "match": {"destinations": ["192.168.10.0/24"]}}]}))
    .unwrap();
    let set = f.store.create_firewall_set(&f.admin, set).unwrap().set.id;
    let bind = |outbound: Option<&str>| {
        f.store.bind_node_firewall(
            &f.admin,
            &private,
            ServerBinding {
                inbound_set_id: None,
                outbound_set_id: outbound.map(str::to_owned),
            },
        )
    };
    let uncovered = || f.store.node_firewall(&f.admin, &private).unwrap().uncovered;
    // Nothing dials from it yet: the binding holds everything it does.
    bind(Some(&set)).unwrap();
    let refused = (
        409,
        "the agent on server line-1 does not apply its outbound firewall rule set to reverse tunnels; upgrade it first".to_owned(),
    );
    assert_eq!(refusal(f.create(f.input(0, 1, 22000))), refused);
    // A switched-off tunnel dials nothing; switching it on would.
    let mut off = f.input(0, 1, 22000);
    off.enabled = Some(false);
    let tunnel = f.create(off.clone()).unwrap();
    let mut on = off.clone();
    on.enabled = Some(true);
    assert_eq!(
        refusal(
            f.store
                .update_reverse_tunnel(&f.admin, &tunnel.id, on.clone())
        ),
        refused
    );
    assert_eq!(uncovered(), Vec::<String>::new());
    // Once the agent covers tunnels, it goes through.
    sync_covering(&f.store, &private, able(None), &COVERS);
    f.store
        .update_reverse_tunnel(&f.admin, &tunnel.id, on.clone())
        .unwrap();
    assert_eq!(uncovered(), Vec::<String>::new());
    assert_eq!(
        sync_covering(&f.store, &private, able(None), &COVERS)
            .dials
            .len(),
        1
    );
    // The agent is downgraded: the tunnel keeps running and the server says
    // what its set does not hold; only edits that change what it dials, or
    // a new set over it, wait for the agent.
    let dials = sync_covering(&f.store, &private, able(None), &[]).dials;
    assert_eq!(dials.len(), 1, "a running tunnel is not stopped");
    assert_eq!(uncovered(), ["reverse_tunnels"]);
    let mut renamed = on.clone();
    renamed.name = "renamed".into();
    f.store
        .update_reverse_tunnel(&f.admin, &tunnel.id, renamed.clone())
        .unwrap();
    let mut retargeted = renamed.clone();
    retargeted.target = "192.168.10.21:8080".into();
    assert_eq!(
        refusal(
            f.store
                .update_reverse_tunnel(&f.admin, &tunnel.id, retargeted)
        ),
        refused
    );
    bind(None).unwrap();
    assert_eq!(uncovered(), Vec::<String>::new());
    assert_eq!(refusal(bind(Some(&set))), refused);
}
