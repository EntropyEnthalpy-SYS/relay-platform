mod common;
#[path = "common/tls.rs"]
mod tls;
use common::*;
use relay_platform::{
    engine::Engine,
    model::*,
    multipath::{self, ClientConfig, Limits, Mode, PathConfig, ServerConfig},
    store::Store,
    topology,
    transport::PreparedTls,
};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};

fn port_pair() -> SocketAddr {
    loop {
        let first = free_address();
        if std::net::TcpListener::bind((first.ip(), first.port() + 1)).is_ok() {
            return first;
        }
    }
}
fn limits() -> Limits {
    Limits {
        window_frames: 16,
        max_sessions: 4,
        retransmit_ms: 100,
        stall_timeout_ms: 3000,
    }
}
fn rules(backend: SocketAddr, mode: Mode, websocket: bool) -> (Rule, Rule) {
    let mut server = rule(backend, Protocol::Tcp);
    server.id = "mp-exit".into();
    server.listen = port_pair();
    server.listen_end_port = Some(server.listen.port() + 1);
    server.connect_timeout_ms = 5000;
    server.inbound_tls = Some(TlsServer {
        identity: "server".into(),
        client_ca: Some("root".into()),
    });
    server.inbound_multipath = Some(ServerConfig {
        limits: limits(),
        max_paths: 2,
        allow_replication: true,
    });
    let mut client = rule(server.listen, Protocol::Tcp);
    client.id = "mp-entry".into();
    client.connect_timeout_ms = 5000;
    client.targets[0].tls = Some(TlsClient {
        server_name: "relay.test".into(),
        ca: Some("root".into()),
        identity: Some("client".into()),
    });
    let mut second = client.targets[0].clone();
    second.address = SocketAddr::new(server.listen.ip(), server.listen.port() + 1).to_string();
    client.targets.push(second);
    client.outbound_multipath = Some(ClientConfig {
        limits: limits(),
        mode,
        min_paths: 2,
        paths: vec![
            PathConfig {
                upload_weight: 1,
                download_weight: 1,
                outbound_bind: None
            };
            2
        ],
    });
    if websocket {
        server.inbound_websocket = Some(WebSocketServer {
            path: "/mp".into(),
            host: Some("relay.test".into()),
            allowed_origins: vec![],
        });
        for target in &mut client.targets {
            target.websocket = Some(WebSocketClient {
                path: "/mp".into(),
                host: "relay.test".into(),
                origin: None,
            });
        }
    }
    (client, server)
}
fn node(rule: Rule, name: &str) -> NodeConfig {
    let mut config = config(rule);
    config.node_id = name.into();
    config
}
async fn quiet(engine: &Engine) {
    timeout(Duration::from_secs(3), async {
        loop {
            let stats = engine.stats();
            if stats.active_tcp == 0
                && stats.multipath.as_ref().unwrap().active_sessions == 0
                && stats.multipath.as_ref().unwrap().active_paths == 0
            {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn real_mtls_and_wss_multipath_preserve_one_connection_and_count_logical_payload_once_per_hop()
 {
    let cert = tls::Certificates::new();
    for (mode, ws) in [(Mode::Stripe, false), (Mode::Replicate, true)] {
        let temp = tempfile::tempdir().unwrap();
        let echo = tcp_echo().await;
        let (mut client_rule, mut server_rule) = rules(echo.address, mode, ws);
        client_rule.quota_bytes = Some(2 * (524_288 + 37));
        server_rule.quota_bytes = client_rule.quota_bytes;
        let entry_db = Store::open(&temp.path().join("entry.db")).unwrap();
        let exit_db = Store::open(&temp.path().join("exit.db")).unwrap();
        let entry = Engine::with_tls_directory(entry_db.clone(), Some(cert.root.clone()));
        let exit = Engine::with_tls_directory(exit_db.clone(), Some(cert.root.clone()));
        let address = client_rule.listen;
        exit.apply(node(server_rule, "exit")).await.unwrap();
        entry.apply(node(client_rule, "entry")).await.unwrap();
        let bytes: Vec<_> = (0..524_288 + 37).map(|i| (i % 251) as u8).collect();
        assert_eq!(exchange(address, &bytes).await, bytes);
        quiet(&entry).await;
        quiet(&exit).await;
        assert_eq!(entry.stats().accepted_tcp, 1);
        assert_eq!(exit.stats().accepted_tcp, 2);
        for engine in [&entry, &exit] {
            let stats = engine.stats().multipath.unwrap();
            assert_eq!(stats.sessions, 1);
            assert_eq!(stats.delivered_payload_bytes, bytes.len() as u64);
            assert!(stats.path_sent_payload_bytes[0] > 0 && stats.path_sent_payload_bytes[1] > 0);
            assert!(stats.peak_reorder_bytes <= 16 * multipath::CHUNK_BYTES as u64);
            if mode == Mode::Replicate {
                assert_eq!(stats.replicated_payload_bytes, bytes.len() as u64);
            }
        }
        entry.shutdown().await.unwrap();
        exit.shutdown().await.unwrap();
        for db in [&entry_db, &exit_db] {
            let usage = db.agent_usage(false).unwrap();
            assert_eq!(usage.len(), 1);
            assert_eq!(usage[0].upload_bytes, bytes.len() as u64);
            assert_eq!(usage[0].download_bytes, bytes.len() as u64);
        }
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn directional_path_selection_is_observable_and_policy_change_cancels_active_groups() {
    let cert = tls::Certificates::new();
    let temp = tempfile::tempdir().unwrap();
    let echo = tcp_echo().await;
    let (mut client_rule, server_rule) = rules(echo.address, Mode::Stripe, false);
    let policy = client_rule.outbound_multipath.as_mut().unwrap();
    policy.paths[0].download_weight = 0;
    policy.paths[1].upload_weight = 0;
    let entry = Engine::with_tls_directory(
        Store::open(&temp.path().join("entry.db")).unwrap(),
        Some(cert.root.clone()),
    );
    let exit = Engine::with_tls_directory(
        Store::open(&temp.path().join("exit.db")).unwrap(),
        Some(cert.root.clone()),
    );
    exit.apply(node(server_rule, "exit")).await.unwrap();
    let mut config = node(client_rule, "entry");
    entry.apply(config.clone()).await.unwrap();
    let mut stream = TcpStream::connect(config.rules[0].listen).await.unwrap();
    stream.write_all(&[42; 131_072]).await.unwrap();
    let mut response = vec![0; 131_072];
    timeout(Duration::from_secs(3), stream.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(response, vec![42; 131_072]);
    // Senders count a frame after writing it, so the reply can arrive first.
    let until = tokio::time::Instant::now() + Duration::from_secs(2);
    let (up, down) = loop {
        let up = entry.stats().multipath.unwrap();
        let down = exit.stats().multipath.unwrap();
        if up.path_sent_payload_bytes.iter().sum::<u64>() >= 131_072
            && down.path_sent_payload_bytes.iter().sum::<u64>() >= 131_072
            || tokio::time::Instant::now() > until
        {
            break (up, down);
        }
        tokio::time::sleep(Duration::from_millis(10)).await;
    };
    // The selected path may count a final frame just after the reply arrives.
    // This test is about directional selection, not an exact byte ledger.
    assert!(up.path_sent_payload_bytes[0] >= 131_072);
    assert_eq!(up.path_sent_payload_bytes[1], 0);
    assert_eq!(down.path_sent_payload_bytes[0], 0);
    assert!(down.path_sent_payload_bytes[1] >= 131_072);
    config.revision += 1;
    config.rules[0].outbound_multipath.as_mut().unwrap().paths[0].upload_weight = 2;
    entry.apply(config).await.unwrap();
    let mut byte = [0];
    assert!(!matches!(
        timeout(Duration::from_secs(2), stream.read(&mut byte))
            .await
            .unwrap(),
        Ok(1)
    ));
    drop(stream);
    quiet(&entry).await;
    quiet(&exit).await;
    entry.shutdown().await.unwrap();
    exit.shutdown().await.unwrap();
}

#[test]
fn multipath_validation_preserves_graph_identity_security_and_resource_limits() {
    let (mut entry, mut exit) = rules("127.0.0.1:10101".parse().unwrap(), Mode::Stripe, false);
    exit.advertise = Some(exit.listen.to_string());
    for target in &mut entry.targets {
        target.via = Some(RuleRef {
            node_id: "exit".into(),
            rule_id: exit.id.clone(),
        });
    }
    let configs = vec![node(entry.clone(), "entry"), node(exit.clone(), "exit")];
    assert_eq!(topology::validate(&configs).unwrap().edges.len(), 2);
    let mut invalid = configs.clone();
    invalid[1].rules[0].inbound_multipath = None;
    assert!(topology::validate(&invalid).is_err());
    invalid = configs.clone();
    invalid[1].rules[0]
        .inbound_multipath
        .as_mut()
        .unwrap()
        .max_paths = 1;
    assert!(topology::validate(&invalid).is_err());
    invalid = configs.clone();
    invalid[1].rules[0].tenant_id = "different".into();
    assert!(topology::validate(&invalid).is_err());
    for fault in 0..8 {
        let mut r = entry.clone();
        match fault {
            0 => r.protocol = Protocol::Both,
            1 => r.targets[1].tls.as_mut().unwrap().identity = Some("another-client".into()),
            2 => r.port_mapping = PortMapping::Offset,
            3 => r.targets[1].via = None,
            4 => r.outbound_multipath.as_mut().unwrap().limits.max_sessions = 1024,
            5 => r.outbound_multipath.as_mut().unwrap().paths[1].download_weight = 1001,
            6 => r.outbound_multipath.as_mut().unwrap().min_paths = 3,
            _ => {
                r.outbound_multipath.as_mut().unwrap().paths[1].outbound_bind = Some(OutboundBind {
                    ip: None,
                    interface: Some("../bad".into()),
                })
            }
        }
        assert!(r.validate().is_err(), "fault {fault} accepted");
    }
    exit.inbound_tls.as_mut().unwrap().client_ca = None;
    assert!(exit.validate().is_err());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn health_checks_use_the_aggregation_protocol_and_keep_source_probe_bytes_out_of_business_usage()
 {
    let cert = tls::Certificates::new();
    let temp = tempfile::tempdir().unwrap();
    let echo = tcp_echo().await;
    let (mut client_rule, server_rule) = rules(echo.address, Mode::Stripe, false);
    client_rule.health_check = Some(serde_json::from_value(serde_json::json!({
        "interval_ms":500,"timeout_ms":300,"unhealthy_threshold":1,"healthy_threshold":1,
        "recovery_delay_ms":0,"max_age_ms":1000,
        "tcp":{"kind":"exchange","request_base64":"UElORw==","expected_base64":"UElORw==","half_close":true}
    })).unwrap());
    let entry_db = Store::open(&temp.path().join("entry.db")).unwrap();
    let exit_db = Store::open(&temp.path().join("exit.db")).unwrap();
    let entry = Engine::with_tls_directory(entry_db.clone(), Some(cert.root.clone()));
    let exit = Engine::with_tls_directory(exit_db.clone(), Some(cert.root.clone()));
    let address = client_rule.listen;
    exit.apply(node(server_rule, "exit")).await.unwrap();
    entry.apply(node(client_rule, "entry")).await.unwrap();
    timeout(Duration::from_secs(3), async {
        loop {
            let stats = entry.stats();
            if stats.target_health.len() == 2
                && stats
                    .target_health
                    .iter()
                    .all(|r| r.eligible && r.probe_received_bytes >= 4)
            {
                break;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(entry_db.agent_usage(false).unwrap().is_empty());
    assert_eq!(exchange(address, b"business").await, b"business");
    entry.shutdown().await.unwrap();
    exit.shutdown().await.unwrap();
    let usage = entry_db.agent_usage(false).unwrap();
    assert_eq!((usage[0].upload_bytes, usage[0].download_bytes), (8, 8));
    let downstream = exit_db.agent_usage(false).unwrap();
    assert!(downstream[0].upload_bytes >= 16 && downstream[0].download_bytes >= 16);
    assert_eq!(entry.stats().active_probes, 0);
    assert_eq!(exit.stats().multipath.unwrap().active_sessions, 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn initial_path_minimum_and_session_capacity_fail_without_leaking_backend_sessions() {
    let cert = tls::Certificates::new();
    let temp = tempfile::tempdir().unwrap();
    let echo = tcp_echo().await;
    let (mut client_rule, server_rule) = rules(echo.address, Mode::Stripe, false);
    client_rule
        .outbound_multipath
        .as_mut()
        .unwrap()
        .limits
        .max_sessions = 1;
    client_rule.targets[1].address = free_address().to_string(); // one refused candidate
    let entry_db = Store::open(&temp.path().join("entry.db")).unwrap();
    let entry = Engine::with_tls_directory(entry_db.clone(), Some(cert.root.clone()));
    let exit = Engine::with_tls_directory(
        Store::open(&temp.path().join("exit.db")).unwrap(),
        Some(cert.root.clone()),
    );
    exit.apply(node(server_rule, "exit")).await.unwrap();
    let mut cfg = node(client_rule, "entry");
    entry.apply(cfg.clone()).await.unwrap();
    let address = cfg.rules[0].listen;
    let mut rejected = TcpStream::connect(address).await.unwrap();
    rejected.write_all(b"rejected").await.unwrap();
    let mut byte = [0];
    assert!(!matches!(
        timeout(Duration::from_secs(3), rejected.read(&mut byte))
            .await
            .unwrap(),
        Ok(1)
    ));
    quiet(&exit).await;
    assert_eq!(exit.stats().multipath.unwrap().sessions, 0);
    assert!(entry_db.agent_usage(false).unwrap().is_empty());
    cfg.revision += 1;
    cfg.rules[0].outbound_multipath.as_mut().unwrap().min_paths = 1;
    entry.apply(cfg.clone()).await.unwrap();
    let mut admitted = TcpStream::connect(address).await.unwrap();
    admitted.write_all(b"a").await.unwrap();
    admitted.read_exact(&mut byte).await.unwrap();
    let mut over_limit = TcpStream::connect(address).await.unwrap();
    over_limit.write_all(b"b").await.unwrap();
    assert!(!matches!(
        timeout(Duration::from_secs(3), over_limit.read(&mut byte))
            .await
            .unwrap(),
        Ok(1)
    ));
    admitted.shutdown().await.unwrap();
    let mut rest = vec![];
    admitted.read_to_end(&mut rest).await.unwrap();
    quiet(&entry).await;
    quiet(&exit).await;
    assert_eq!(exchange(address, b"again").await, b"again");
    entry.shutdown().await.unwrap();
    exit.shutdown().await.unwrap();
}

#[tokio::test]
async fn join_is_bound_to_verified_tls_identity_and_bad_joins_never_open_a_backend() {
    let cert = tls::Certificates::new();
    cert.issue("other-client");
    let temp = tempfile::tempdir().unwrap();
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let (mut rule_client, rule_server) = rules(backend.local_addr().unwrap(), Mode::Stripe, false);
    let address = rule_server.listen;
    let exit = Engine::with_tls_directory(
        Store::open(&temp.path().join("exit.db")).unwrap(),
        Some(cert.root.clone()),
    );
    exit.apply(node(rule_server, "exit")).await.unwrap();
    // A TLS handshake can finish locally before the peer sends its client-auth rejection.
    if let Ok(mut unauthorized) = cert
        .connector(false)
        .connect(
            tokio_rustls::rustls::pki_types::ServerName::try_from("relay.test").unwrap(),
            TcpStream::connect(address).await.unwrap(),
        )
        .await
    {
        let _ = unauthorized.write_all(b"RLYMP001").await;
        let _ = unauthorized.flush().await;
        let mut byte = [0];
        assert!(!matches!(
            timeout(Duration::from_secs(2), unauthorized.read(&mut byte))
                .await
                .unwrap(),
            Ok(1)
        ));
    }
    let policy = PreparedTls::load(&rule_client, Some(&cert.root)).unwrap();
    let mut leader = policy
        .connect(0, TcpStream::connect(address).await.unwrap())
        .await
        .unwrap();
    let mut hello = [0u8; 84];
    hello[..8].copy_from_slice(b"RLYMP001");
    hello[8] = 1;
    hello[12..14].copy_from_slice(&8u16.to_be_bytes());
    hello[14..16].copy_from_slice(&1u16.to_be_bytes());
    hello[16..18].copy_from_slice(&1u16.to_be_bytes());
    hello[20..52].fill(19);
    leader.write_all(&hello).await.unwrap();
    leader.flush().await.unwrap();
    let mut reply = [0; 42];
    leader.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..8], b"RLYMPA01");
    hello[8] = 2;
    hello[9] = 1;
    hello[52..84].copy_from_slice(&reply[10..42]);
    for case in 0..3 {
        let mut request = hello;
        if case == 0 {
            rule_client.targets[0].tls.as_mut().unwrap().identity = Some("other-client".into());
        } else {
            rule_client.targets[0].tls.as_mut().unwrap().identity = Some("client".into());
        }
        if case == 1 {
            request[52] ^= 1;
        }
        if case == 2 {
            request[9] = 0;
        }
        let client = PreparedTls::load(&rule_client, Some(&cert.root)).unwrap();
        let mut joined = client
            .connect(0, TcpStream::connect(address).await.unwrap())
            .await
            .unwrap();
        joined.write_all(&request).await.unwrap();
        joined.flush().await.unwrap();
        let mut byte = [0];
        assert!(!matches!(
            timeout(Duration::from_secs(2), joined.read(&mut byte))
                .await
                .unwrap(),
            Ok(1)
        ));
    }
    assert!(
        timeout(Duration::from_millis(100), backend.accept())
            .await
            .is_err()
    );
    drop(leader);
    exit.shutdown().await.unwrap();
    assert_eq!(exit.stats().multipath.unwrap().active_sessions, 0);
}
