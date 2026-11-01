//! WireGuard networks through the store and sync: the switch, node keys
//! reported by agents, rendered interfaces, member states and deletion rules.
//! The kernel side runs in scripts/check_linux_wireguard.py (root only).
mod common;
use common::*;
use relay_platform::{
    model::*,
    store::{Actor, Rejection, Role, Store},
    wireguard::{self, Desired, Report},
};
use serde_json::json;

fn rejection<T: std::fmt::Debug>(result: anyhow::Result<T>) -> u16 {
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
/// One agent report; returns what the controller wants the node to have.
fn sync(db: &Store, node: &str, ledger: &str, report: Option<Report>) -> Desired {
    let stats = EngineStats {
        wireguard: report,
        ..EngineStats::default()
    };
    db.sync(
        node,
        SyncRequest {
            logs: None,
            lease: None,
            budget: None,
            ledger_id: ledger.into(),
            need_config: false,
            applied_revision: 0,
            apply_error: None,
            usage: vec![],
            stats,
        },
    )
    .unwrap()
    .wireguard
    .expect("this controller always sends a desired state")
}
fn report(private_key: &str, applied: &str) -> Report {
    Report {
        public_key: Some(wireguard::public_key(private_key).unwrap()),
        ready: true,
        applied: applied.into(),
        ..Report::default()
    }
}
fn input<T: serde::de::DeserializeOwned>(value: serde_json::Value) -> T {
    serde_json::from_value(value).unwrap()
}

#[test]
fn nodes_join_with_reported_keys_and_get_their_peers_through_sync() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("controller.db");
    let db = Store::open(&path).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let mut nodes = vec![];
    for name in ["hub", "home", "spare"] {
        let (node, _) = db.create_node(&admin, "default", name).unwrap();
        let ledger = ledger(&db, &node.id);
        nodes.push((node.id, ledger, wireguard::private_key()));
    }
    let [
        (hub, hub_ledger, hub_key),
        (home, home_ledger, home_key),
        (spare, spare_ledger, spare_key),
    ] = nodes.try_into().unwrap();
    // Older controllers reject unknown statistics: an agent without a
    // report sends exactly what it sent before.
    assert!(
        serde_json::to_value(EngineStats::default())
            .unwrap()
            .get("wireguard")
            .is_none()
    );

    // Off: an empty, disabled state, and every change is refused.
    let off = sync(&db, &hub, &hub_ledger, None);
    assert!(!off.enabled && off.interfaces.is_empty());
    let network = json!({"name":"office","cidr":"10.88.0.0/24"});
    assert_eq!(
        rejection(db.create_wireguard_network(&admin, input(network.clone()))),
        409
    );
    db.set_feature(&admin, "wireguard", true).unwrap();
    let tenant_admin = Actor {
        role: Role::TenantAdmin,
        ..admin.clone()
    };
    assert_eq!(
        rejection(db.create_wireguard_network(&tenant_admin, input(network.clone()))),
        403
    );
    assert_eq!(rejection(db.wireguard(&tenant_admin)), 403);
    let office = db.create_wireguard_network(&admin, input(network)).unwrap();
    assert_eq!(
        rejection(db.create_wireguard_network(
            &admin,
            input(json!({"name":"inner","cidr":"10.88.0.128/25"}))
        )),
        409,
        "overlapping ranges are refused"
    );
    let add =
        |value: serde_json::Value| db.create_wireguard_member(&admin, &office.id, input(value));

    // A node joins only after its agent reported a key.
    assert!(sync(&db, &home, &home_ledger, None).enabled);
    assert_eq!(rejection(add(json!({"kind":"node","node_id":home}))), 409);
    sync(&db, &home, &home_ledger, Some(report(&home_key, "")));
    sync(&db, &hub, &hub_ledger, Some(report(&hub_key, "")));
    sync(&db, &spare, &spare_ledger, Some(report(&spare_key, "")));
    assert_eq!(
        rejection(add(json!({"kind":"device","name":"phone"}))),
        409,
        "a device needs a public node to connect to"
    );
    assert_eq!(
        rejection(add(
            json!({"kind":"node","node_id":hub,"endpoint":"10.88.0.9"})
        )),
        400,
        "an endpoint inside the network would route the tunnel through itself"
    );
    let hub_member = add(json!({"kind":"node","node_id":hub,"endpoint":"203.0.113.1"}))
        .unwrap()
        .member;
    add(json!({"kind":"node","node_id":home})).unwrap();
    assert_eq!(
        (
            hub_member.address.to_string(),
            hub_member.endpoint.as_deref()
        ),
        ("10.88.0.1".to_string(), Some("203.0.113.1:51820"))
    );
    assert_eq!(rejection(add(json!({"kind":"node","node_id":home}))), 409);

    // A device gets its key pair once; the panel keeps only the public key.
    let phone = add(json!({"kind":"device","name":"phone"})).unwrap();
    let config = phone.config.clone().unwrap();
    let private = config
        .lines()
        .find_map(|line| line.strip_prefix("PrivateKey = "))
        .unwrap()
        .to_string();
    assert_eq!(
        phone.member.public_key,
        Some(wireguard::public_key(&private).unwrap())
    );
    assert_eq!(phone.member.via.as_deref(), Some(hub_member.id.as_str()));
    assert!(config.contains("Endpoint = 203.0.113.1:51820\nAllowedIPs = 10.88.0.0/24\n"));
    assert!(
        phone
            .qr_svg
            .as_deref()
            .is_some_and(|svg| svg.contains("<svg"))
    );
    let own_key = add(json!({"kind":"device","name":"laptop","public_key":wireguard::public_key(&wireguard::private_key()).unwrap()})).unwrap();
    assert!(own_key.qr_svg.is_none() && !own_key.config.unwrap().contains(&private));
    let rekeyed = db.rekey_wireguard_device(&admin, &phone.member.id).unwrap();
    assert_ne!(rekeyed.member.public_key, phone.member.public_key);
    let raw = rusqlite::Connection::open(&path).unwrap();
    let leaked: i64 = raw
        .query_row(
            "SELECT (SELECT COUNT(*) FROM metadata WHERE instr(value,?1)>0)+(SELECT COUNT(*) FROM audit WHERE instr(detail,?1)>0)",
            [&private],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(leaked, 0, "a device private key is never stored");

    // The node behind NAT gets one peer: the hub, carrying both devices.
    let desired = sync(&db, &home, &home_ledger, Some(report(&home_key, "")));
    let [interface] = desired.interfaces.as_slice() else {
        panic!("{desired:?}");
    };
    assert_eq!(
        interface.name,
        format!("rwg-{}", &office.id.replace('-', "")[..8])
    );
    assert_eq!(
        (interface.address.to_string(), interface.prefix),
        ("10.88.0.2".to_string(), 24)
    );
    let [peer] = interface.peers.as_slice() else {
        panic!("{interface:?}");
    };
    assert_eq!(peer.public_key, wireguard::public_key(&hub_key).unwrap());
    assert_eq!(
        (peer.endpoint.as_deref(), peer.keepalive),
        (Some("203.0.113.1:51820"), Some(25))
    );
    let allowed: Vec<String> = peer.allowed_ips.iter().map(ToString::to_string).collect();
    assert_eq!(allowed, ["10.88.0.1/32", "10.88.0.3/32", "10.88.0.4/32"]);
    let hub_desired = sync(&db, &hub, &hub_ledger, Some(report(&hub_key, "")));
    assert!(hub_desired.interfaces[0].forwarding);
    assert_eq!(hub_desired.interfaces[0].peers.len(), 3);

    // States follow what each agent applied.
    let state = |label: &str| {
        db.wireguard(&admin).unwrap().networks[0]
            .members
            .iter()
            .find(|m| m.label == label)
            .unwrap()
            .state
    };
    assert_eq!(state("home"), "updating");
    sync(
        &db,
        &home,
        &home_ledger,
        Some(report(&home_key, &desired.digest)),
    );
    assert_eq!(state("home"), "up");
    assert_eq!(state("phone"), "idle");
    let view = db.wireguard(&admin).unwrap();
    let pair = view.networks[0]
        .pairs
        .iter()
        .find(|p| (p.a.as_str(), p.b.as_str()) == ("hub", "home"))
        .unwrap();
    assert_eq!(pair.path, "direct");
    assert!(view.nodes.iter().all(|n| n.key_reported));

    // A hub keeps its endpoint while devices use it, and nodes in a network
    // cannot be deleted; the stored key goes with a deleted node.
    assert_eq!(
        rejection(db.update_wireguard_member(
            &admin,
            &hub_member.id,
            input(json!({"kind":"node"}))
        )),
        409
    );
    assert_eq!(
        rejection(db.delete_wireguard_member(&admin, &hub_member.id)),
        409
    );
    let moved = db
        .update_wireguard_member(
            &admin,
            &hub_member.id,
            input(json!({"kind":"node","endpoint":"vpn.example.com:51999"})),
        )
        .unwrap();
    assert_eq!(
        (moved.address, moved.endpoint.as_deref()),
        (hub_member.address, Some("vpn.example.com:51999"))
    );
    let moved = sync(&db, &home, &home_ledger, Some(report(&home_key, "")));
    assert_eq!(
        moved.interfaces[0].peers[0].endpoint.as_deref(),
        Some("vpn.example.com:51999")
    );
    let spare_member = add(json!({"kind":"node","node_id":spare})).unwrap().member;
    assert_eq!(rejection(db.delete_node(&admin, &spare)), 409);
    db.delete_wireguard_member(&admin, &spare_member.id)
        .unwrap();
    db.delete_node(&admin, &spare).unwrap();
    let kept: i64 = raw
        .query_row(
            "SELECT COUNT(*) FROM metadata WHERE key=?1",
            [format!("wg_node_key:{spare}")],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(kept, 0);

    // The switch stays on while a network exists; afterwards nodes get an
    // empty, disabled state and remove their links.
    assert_eq!(rejection(db.set_feature(&admin, "wireguard", false)), 409);
    db.delete_wireguard_network(&admin, &office.id).unwrap();
    db.set_feature(&admin, "wireguard", false).unwrap();
    let after = sync(
        &db,
        &home,
        &home_ledger,
        Some(report(&home_key, &desired.digest)),
    );
    assert!(!after.enabled && after.interfaces.is_empty());
}

/// What `key` sees of the peers `(key, endpoint, handshake, rx)` on `network`.
fn seen(private_key: &str, network: &str, peers: &[(&str, Option<&str>, u64, u64)]) -> Report {
    Report {
        interfaces: vec![wireguard::InterfaceReport {
            network_id: network.into(),
            name: wireguard::interface_name(network),
            error: None,
            peers: peers
                .iter()
                .map(
                    |(key, endpoint, handshake, rx_bytes)| wireguard::PeerReport {
                        public_key: wireguard::public_key(key).unwrap(),
                        endpoint: endpoint.map(str::to_string),
                        handshake: *handshake,
                        rx_bytes: *rx_bytes,
                        tx_bytes: 0,
                    },
                )
                .collect(),
        }],
        probes: true,
        ..report(private_key, "")
    }
}
/// Each peer of the node's only interface as `endpoint keepalive allowed`, by key.
fn entries(desired: &Desired) -> std::collections::BTreeMap<String, String> {
    desired.interfaces[0]
        .peers
        .iter()
        .map(|p| {
            let allowed: Vec<String> = p.allowed_ips.iter().map(|n| n.addr().to_string()).collect();
            (
                p.public_key.clone(),
                format!(
                    "{} {} {}",
                    p.endpoint.as_deref().unwrap_or("-"),
                    p.keepalive.unwrap_or(0),
                    allowed.join(",")
                ),
            )
        })
        .collect()
}

#[test]
fn nat_traversal_moves_a_pair_behind_nats_off_the_relay_and_back() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("controller.db")).unwrap();
    let admin = db.bootstrap(PASSWORD).unwrap();
    let (mut nodes, mut credentials) = (vec![], vec![]);
    for name in ["relay", "a", "b"] {
        let (node, token) = db.create_node(&admin, "default", name).unwrap();
        let credential = relay_platform::store::secret();
        db.enroll(&node.id, &token, &credential).unwrap();
        let ledger = ledger(&db, &node.id);
        nodes.push((node.id, ledger, wireguard::private_key()));
        credentials.push(credential);
    }
    let [
        (relay, relay_ledger, relay_key),
        (a, a_ledger, a_key),
        (b, b_ledger, b_key),
    ] = nodes.try_into().unwrap();
    let b_credential = credentials.pop().unwrap();
    let public = |key: &str| wireguard::public_key(key).unwrap();

    // NAT traversal works on top of WireGuard networking.
    assert_eq!(
        rejection(db.set_feature(&admin, "nat-traversal", true)),
        409
    );
    db.set_feature(&admin, "wireguard", true).unwrap();
    for (node, ledger, key) in [
        (&relay, &relay_ledger, &relay_key),
        (&a, &a_ledger, &a_key),
        (&b, &b_ledger, &b_key),
    ] {
        sync(&db, node, ledger, Some(report(key, "")));
    }
    let office = db
        .create_wireguard_network(
            &admin,
            input(json!({"name":"office","cidr":"10.88.0.0/24"})),
        )
        .unwrap();
    for value in [
        json!({"kind":"node","node_id":relay,"endpoint":"203.0.113.1"}),
        json!({"kind":"node","node_id":a}),
        json!({"kind":"node","node_id":b}),
    ] {
        db.create_wireguard_member(&admin, &office.id, input(value))
            .unwrap();
    }
    // The relay hears both through their NATs; `a` and `b` reach it.
    let relay_sees = seen(
        &relay_key,
        &office.id,
        &[
            (&a_key, Some("198.51.100.2:40001"), 1000, 1),
            (&b_key, Some("198.51.100.3:40002"), 1000, 1),
        ],
    );
    let via_relay = |key: &str| {
        seen(
            key,
            &office.id,
            &[(&relay_key, Some("203.0.113.1:51820"), 1000, 1)],
        )
    };
    sync(&db, &relay, &relay_ledger, Some(relay_sees.clone()));
    sync(&db, &b, &b_ledger, Some(via_relay(&b_key)));
    let relayed = sync(&db, &a, &a_ledger, Some(via_relay(&a_key)));
    assert_eq!(
        entries(&relayed),
        [(
            public(&relay_key),
            "203.0.113.1:51820 25 10.88.0.1,10.88.0.3".to_string()
        )]
        .into()
    );
    let view = db.wireguard(&admin).unwrap();
    let pair = |view: &wireguard::View| {
        let pair = view.networks[0]
            .pairs
            .iter()
            .find(|p| p.a == "a" && p.b == "b")
            .unwrap();
        (pair.path, pair.punched)
    };
    assert_eq!(pair(&view), ("relayed", false), "switched off: no attempt");

    db.set_feature(&admin, "nat-traversal", true).unwrap();
    sync(&db, &a, &a_ledger, Some(via_relay(&a_key)));
    // The probe: `a` gets an entry at `b`'s NAT address that carries nothing
    // yet, and `b`'s watch returns so it gets its entry at once.
    let probing = sync(&db, &a, &a_ledger, Some(via_relay(&a_key)));
    assert_eq!(
        entries(&probing),
        [
            (
                public(&relay_key),
                "203.0.113.1:51820 25 10.88.0.1,10.88.0.3".to_string()
            ),
            (public(&b_key), "198.51.100.3:40002 25 ".to_string()),
        ]
        .into()
    );
    assert!(db.node_watch(&b_credential).unwrap().1);
    assert!(!db.node_watch(&b_credential).unwrap().1, "once");
    assert_eq!(pair(&db.wireguard(&admin).unwrap()), ("probing", false));
    let b_probing = sync(&db, &b, &b_ledger, Some(via_relay(&b_key)));
    assert_eq!(
        entries(&b_probing)[&public(&a_key)],
        "198.51.100.2:40001 25 "
    );

    // Both sides handshake through their NATs: traffic leaves the relay.
    let punched = |key: &str, other: &str, rx| {
        seen(
            key,
            &office.id,
            &[
                (&relay_key, Some("203.0.113.1:51820"), 1000, 1),
                (other, Some("198.51.100.9:1"), 2000, rx),
            ],
        )
    };
    sync(&db, &b, &b_ledger, Some(punched(&b_key, &a_key, 92)));
    let direct = sync(&db, &a, &a_ledger, Some(punched(&a_key, &b_key, 92)));
    assert_eq!(
        entries(&direct),
        [
            (
                public(&relay_key),
                "203.0.113.1:51820 25 10.88.0.1".to_string()
            ),
            (
                public(&b_key),
                "198.51.100.3:40002 25 10.88.0.3".to_string()
            ),
        ]
        .into()
    );
    assert_eq!(pair(&db.wireguard(&admin).unwrap()), ("direct", true));
    assert!(db.node_watch(&b_credential).unwrap().1);

    // Switching it off puts the pair back on the relay.
    db.set_feature(&admin, "nat-traversal", false).unwrap();
    let back = sync(&db, &a, &a_ledger, Some(punched(&a_key, &b_key, 184)));
    assert_eq!(entries(&back), entries(&relayed));
    // WireGuard stays on while NAT traversal is on, even without networks.
    db.set_feature(&admin, "nat-traversal", true).unwrap();
    db.delete_wireguard_network(&admin, &office.id).unwrap();
    assert_eq!(rejection(db.set_feature(&admin, "wireguard", false)), 409);
    db.set_feature(&admin, "nat-traversal", false).unwrap();
    db.set_feature(&admin, "wireguard", false).unwrap();
}
