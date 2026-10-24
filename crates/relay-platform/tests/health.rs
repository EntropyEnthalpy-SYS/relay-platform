mod common;
#[allow(dead_code)]
#[path = "common/tls.rs"]
mod tls;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use common::*;
use relay_platform::{
    engine::Engine,
    health::{HealthCheck, Status},
    model::*,
    store::Store,
};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{Instant, sleep, timeout},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

fn total(db: &Store) -> u64 {
    db.agent_usage(false)
        .unwrap()
        .iter()
        .map(|r| r.upload_bytes + r.download_bytes)
        .sum()
}

fn policy(protocol: Protocol) -> HealthCheck {
    let mut value = serde_json::json!({"interval_ms":100,"timeout_ms":60,"unhealthy_threshold":2,"healthy_threshold":2,"recovery_delay_ms":250,"max_age_ms":1000});
    if protocol.tcp() {
        value["tcp"] = serde_json::json!({"kind":"exchange","request_base64":STANDARD.encode(b"PING"),"expected_base64":STANDARD.encode(b"PONG"),"half_close":false});
    }
    if protocol.udp() {
        value["udp"] = serde_json::json!({"request_base64":STANDARD.encode(b"PING"),"expected_base64":STANDARD.encode(b"PONG")});
    }
    serde_json::from_value(value).unwrap()
}
struct Service {
    address: SocketAddr,
    tcp: Arc<AtomicUsize>,
    udp: Arc<AtomicUsize>,
    stop: CancellationToken,
    tasks: TaskTracker,
}
impl Service {
    async fn new(marker: u8) -> Self {
        loop {
            match Self::at(marker, free_address()).await {
                Ok(service) => return service,
                Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
                Err(error) => panic!("service fixture: {error}"),
            }
        }
    }
    async fn at(marker: u8, address: SocketAddr) -> std::io::Result<Self> {
        let listener = TcpListener::bind(address).await?;
        let socket = UdpSocket::bind(address).await?;
        let tcp = Arc::new(AtomicUsize::new(0));
        let udp = Arc::new(AtomicUsize::new(0));
        let stop = CancellationToken::new();
        let tasks = TaskTracker::new();
        let (mode, cancel, tracker) = (tcp.clone(), stop.clone(), tasks.clone());
        tasks.spawn(async move {
            loop {
                let pair =
                    tokio::select! {_=cancel.cancelled()=>break,pair=listener.accept()=>pair};
                let Ok((mut stream, _)) = pair else {
                    break;
                };
                let mode = mode.clone();
                let cancel = cancel.clone();
                tracker.spawn(async move {
                    let run = async {
                        let mut data = [0; 4];
                        while stream.read_exact(&mut data).await.is_ok() {
                            let reply = if data == *b"PING" {
                                match mode.load(Ordering::SeqCst) {
                                    0 => *b"PONG",
                                    1 => *b"FAIL",
                                    _ => {
                                        std::future::pending::<()>().await;
                                        unreachable!()
                                    }
                                }
                            } else {
                                [marker; 4]
                            };
                            if stream.write_all(&reply).await.is_err() {
                                break;
                            }
                        }
                    };
                    tokio::select! {_=cancel.cancelled()=>{},_=run=>{}}
                });
            }
        });
        let (mode, cancel) = (udp.clone(), stop.clone());
        tasks.spawn(async move{let mut data=[0;2048];loop{let packet=tokio::select!{_=cancel.cancelled()=>break,packet=socket.recv_from(&mut data)=>packet};let Ok((n,peer))=packet else{break;};let reply=if &data[..n]==b"PING"{match mode.load(Ordering::SeqCst){0=>*b"PONG",1=>*b"FAIL",_=>continue}}else{[marker;4]};let _=socket.send_to(&reply,peer).await;}});
        Ok(Self {
            address,
            tcp,
            udp,
            stop,
            tasks,
        })
    }
    async fn shutdown(self) {
        self.stop.cancel();
        self.tasks.close();
        self.tasks.wait().await;
    }
}
impl Drop for Service {
    fn drop(&mut self) {
        self.stop.cancel();
    }
}
async fn reports(
    engine: &Engine,
    predicate: impl Fn(&[relay_platform::health::TargetHealthReport]) -> bool,
) {
    timeout(Duration::from_secs(6), async {
        loop {
            let stats = engine.stats();
            if predicate(&stats.target_health) {
                return;
            }
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
}
async fn marked(address: SocketAddr) -> [u8; 4] {
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(b"DATA").await.unwrap();
    let mut response = [0; 4];
    timeout(Duration::from_secs(2), client.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    response
}
fn two(first: &Service, second: &Service, protocol: Protocol) -> Rule {
    let mut r = rule(first.address, protocol);
    let mut other = r.targets[0].clone();
    other.address = second.address.to_string();
    other.priority = 10;
    r.targets.push(other);
    r.health_check = Some(policy(protocol));
    r
}

#[test]
fn probe_policy_bounds_protocol_coverage_and_endpoint_cardinality_are_validated() {
    let mut r = rule("127.0.0.1:45000".parse().unwrap(), Protocol::Both);
    r.health_check = Some(policy(Protocol::Tcp));
    assert!(r.validate().is_err());
    r.health_check = Some(policy(Protocol::Both));
    r.validate().unwrap();
    let h = r.health_check.as_mut().unwrap();
    h.timeout_ms = 101;
    assert!(r.validate().is_err());
    r.health_check.as_mut().unwrap().timeout_ms = 60;
    r.health_check
        .as_mut()
        .unwrap()
        .udp
        .as_mut()
        .unwrap()
        .expected_base64 = STANDARD.encode(vec![0; 1025]);
    assert!(r.validate().is_err());
    r.health_check = Some(policy(Protocol::Both));
    r.targets[0].max_sessions = Some(0);
    assert!(r.validate().is_err());
    r.targets[0].max_sessions = None;
    let seed = r.targets[0].clone();
    r.targets = (0..32)
        .map(|n| {
            let mut t = seed.clone();
            t.address = format!("127.0.0.1:{}", 45000 + n * 100);
            t
        })
        .collect();
    r.port_mapping = PortMapping::Offset;
    r.listen_end_port = Some(r.listen.port() + 4);
    assert!(config(r.clone()).validate().is_err());
    r.listen_end_port = Some(r.listen.port() + 3);
    config(r).validate().unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_application_health_fails_over_and_holds_recovery_without_killing_established_stream() {
    let a = Service::new(b'A').await;
    let b = Service::new(b'B').await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let r = two(&a, &b, Protocol::Tcp);
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    reports(&engine, |r| {
        r.len() == 2 && r.iter().all(|r| r.status == Status::Healthy)
    })
    .await;
    assert_eq!(
        total(&db),
        0,
        "local diagnostic payload is counted separately"
    );
    assert_eq!(marked(address).await, *b"AAAA");
    let mut held = TcpStream::connect(address).await.unwrap();
    held.write_all(b"DATA").await.unwrap();
    held.read_exact(&mut [0; 4]).await.unwrap();
    a.tcp.store(1, Ordering::SeqCst);
    reports(&engine, |r| r[0].status == Status::Unhealthy).await;
    assert_eq!(marked(address).await, *b"BBBB");
    held.write_all(b"DATA").await.unwrap();
    let mut response = [0; 4];
    held.read_exact(&mut response).await.unwrap();
    assert_eq!(&response, b"AAAA");
    a.tcp.store(0, Ordering::SeqCst);
    reports(&engine, |r| r[0].status == Status::Recovering).await;
    assert_eq!(marked(address).await, *b"BBBB");
    a.tcp.store(1, Ordering::SeqCst);
    reports(&engine, |r| r[0].status == Status::Unhealthy).await;
    a.tcp.store(0, Ordering::SeqCst);
    let start = Instant::now();
    reports(&engine, |r| r[0].status == Status::Healthy).await;
    assert!(start.elapsed() >= Duration::from_millis(250));
    assert_eq!(marked(address).await, *b"AAAA");
    a.tcp.store(2, Ordering::SeqCst);
    b.tcp.store(1, Ordering::SeqCst);
    reports(&engine, |r| r.iter().all(|r| r.status == Status::Unhealthy)).await;
    let mut refused = TcpStream::connect(address).await.unwrap();
    let _ = refused.write_all(b"DATA").await;
    let result = timeout(Duration::from_secs(1), refused.read(&mut [0; 4]))
        .await
        .unwrap();
    assert!(matches!(result, Ok(0) | Err(_)));
    drop(held);
    engine.shutdown().await.unwrap();
    assert_eq!(total(&db), 48);
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_health_is_independent_and_retires_existing_session_without_replaying_packets() {
    let a = Service::new(b'A').await;
    let b = Service::new(b'B').await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let r = two(&a, &b, Protocol::Both);
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    reports(&engine, |r| {
        r.len() == 4 && r.iter().all(|r| r.status == Status::Healthy)
    })
    .await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client.connect(address).await.unwrap();
    client.send(b"DATA").await.unwrap();
    let mut reply = [0; 4];
    timeout(Duration::from_secs(1), client.recv(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"AAAA");
    a.udp.store(1, Ordering::SeqCst);
    reports(&engine, |r| {
        r.iter().any(|r| {
            r.target_index == 0 && r.protocol == Protocol::Udp && r.status == Status::Unhealthy
        })
    })
    .await;
    timeout(Duration::from_secs(1), async {
        while engine.stats().active_udp != 0 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    client.send(b"DATA").await.unwrap();
    timeout(Duration::from_secs(1), client.recv(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"BBBB");
    assert_eq!(marked(address).await, *b"AAAA");
    engine.shutdown().await.unwrap();
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn target_capacity_survives_target_removal_readdition_and_priority_edit() {
    let a = Service::new(b'A').await;
    let b = Service::new(b'B').await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = two(&a, &b, Protocol::Tcp);
    r.health_check = None;
    r.targets[0].max_sessions = Some(1);
    let address = r.listen;
    let mut c = config(r);
    engine.apply(c.clone()).await.unwrap();
    let mut held = TcpStream::connect(address).await.unwrap();
    held.write_all(b"DATA").await.unwrap();
    held.read_exact(&mut [0; 4]).await.unwrap();
    assert_eq!(marked(address).await, *b"BBBB");
    let first = c.rules[0].targets.remove(0);
    c.revision += 1;
    engine.apply(c.clone()).await.unwrap();
    assert_eq!(marked(address).await, *b"BBBB");
    c.rules[0].targets.insert(0, first);
    c.revision += 1;
    engine.apply(c.clone()).await.unwrap();
    assert_eq!(marked(address).await, *b"BBBB");
    c.rules[0].name = "changed name, same capacity".into();
    c.revision += 1;
    engine.apply(c).await.unwrap();
    assert_eq!(marked(address).await, *b"BBBB");
    drop(held);
    timeout(Duration::from_secs(2), async {
        while engine.stats().active_tcp != 0 {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(marked(address).await, *b"AAAA");
    engine.shutdown().await.unwrap();
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test]
async fn failed_staging_keeps_old_health_and_disabled_rules_stop_probes() {
    let a = Service::new(b'A').await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(a.address, Protocol::Tcp);
    r.health_check = Some(policy(Protocol::Tcp));
    let mut c = config(r);
    engine.apply(c.clone()).await.unwrap();
    reports(&engine, |r| r.len() == 1 && r[0].eligible).await;
    let occupied = TcpListener::bind(free_address()).await.unwrap();
    let mut bad = c.clone();
    bad.revision += 1;
    bad.rules[0]
        .health_check
        .as_mut()
        .unwrap()
        .healthy_threshold = 20;
    let mut extra = rule(a.address, Protocol::Tcp);
    extra.id = "conflict".into();
    extra.listen = occupied.local_addr().unwrap();
    bad.rules.push(extra);
    assert!(engine.apply(bad).await.is_err());
    assert_eq!(engine.revision().await, 1);
    assert!(engine.stats().target_health[0].eligible);
    c.rules[0].enabled = false;
    c.revision += 1;
    engine.apply(c).await.unwrap();
    timeout(Duration::from_secs(1), async {
        while engine.stats().active_probes != 0 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert!(engine.stats().target_health.is_empty());
    engine.shutdown().await.unwrap();
    a.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn health_probe_concurrency_and_shutdown_are_bounded() {
    let mut services = vec![];
    for _ in 0..32 {
        let service = Service::new(b'A').await;
        service.tcp.store(2, Ordering::SeqCst);
        services.push(service);
    }
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(services[0].address, Protocol::Tcp);
    let target = r.targets[0].clone();
    r.targets = services
        .iter()
        .map(|s| {
            let mut t = target.clone();
            t.address = s.address.to_string();
            t
        })
        .collect();
    let mut h = policy(Protocol::Tcp);
    h.interval_ms = 1000;
    h.timeout_ms = 1000;
    h.max_age_ms = 3000;
    r.health_check = Some(h);
    engine.apply(config(r)).await.unwrap();
    timeout(Duration::from_secs(2), async {
        while engine.stats().active_probes < 16 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(engine.stats().active_probes, 16);
    assert_eq!(engine.stats().target_health.len(), 32);
    timeout(Duration::from_millis(500), engine.shutdown())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(engine.stats().active_probes, 0);
    for service in services {
        service.shutdown().await;
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mutual_wss_proxy_probe_checks_end_to_end_reply_and_downstream_metering() {
    let certificates = tls::Certificates::new();
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::with_tls_directory(db.clone(), Some(certificates.root.clone()));
    let mut exit = rule(echo.address, Protocol::Tcp);
    exit.id = "exit".into();
    exit.inbound_tls = Some(TlsServer {
        identity: "server".into(),
        client_ca: Some("root".into()),
    });
    exit.inbound_websocket = Some(WebSocketServer {
        path: "/health-stream".into(),
        host: Some("relay.test".into()),
        allowed_origins: vec![],
    });
    exit.inbound_proxy = Some(ProxyInbound {
        version: ProxyAccept::V2,
        trusted_sources: vec!["127.0.0.0/8".parse().unwrap()],
        placement: ProxyPlacement::InsideTls,
        max_header_bytes: 4096,
    });
    let mut entry = rule(exit.listen, Protocol::Tcp);
    entry.id = "entry".into();
    entry.targets[0].tls = Some(TlsClient {
        server_name: "relay.test".into(),
        ca: Some("root".into()),
        identity: Some("client".into()),
    });
    entry.targets[0].websocket = Some(WebSocketClient {
        path: "/health-stream".into(),
        host: "relay.test".into(),
        origin: None,
    });
    entry.targets[0].proxy_protocol = Some(ProxyOutbound {
        version: ProxyVersion::V2,
        placement: ProxyPlacement::InsideTls,
        checksum: true,
    });
    let mut h = policy(Protocol::Tcp);
    h.tcp = Some(relay_platform::health::StreamProbe::Exchange {
        request_base64: STANDARD.encode(b"PING"),
        expected_base64: STANDARD.encode(b"PING"),
        half_close: true,
    });
    h.interval_ms = 250;
    h.timeout_ms = 200;
    entry.health_check = Some(h);
    let listen = entry.listen;
    let mut c = config(entry);
    c.rules.push(exit);
    engine.apply(c.clone()).await.unwrap();
    reports(&engine, |r| r.len() == 1 && r[0].eligible).await;
    let usage = db.agent_usage(false).unwrap();
    assert_eq!(
        usage
            .iter()
            .filter(|r| r.rule_id == "entry")
            .map(|r| r.upload_bytes + r.download_bytes)
            .sum::<u64>(),
        0
    );
    assert!(
        usage
            .iter()
            .find(|r| r.rule_id == "exit")
            .unwrap()
            .upload_bytes
            >= 8
    );
    assert_eq!(exchange(listen, b"payload").await, b"payload");
    c.rules[0].targets[0].websocket.as_mut().unwrap().path = "/wrong".into();
    c.revision += 1;
    engine.apply(c).await.unwrap();
    reports(&engine, |r| r[0].status == Status::Unhealthy).await;
    assert_eq!(
        engine.stats().target_health[0].last_error,
        Some(relay_platform::health::Failure::Transport)
    );
    engine.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn offset_ports_have_independent_health_and_fixed_mapping_shares_one_observation() {
    let (a, b) = loop {
        let address = free_address();
        let Ok(a) = Service::at(b'A', address).await else {
            continue;
        };
        let mut next = address;
        next.set_port(address.port() + 1);
        let Ok(b) = Service::at(b'B', next).await else {
            drop(a);
            continue;
        };
        break (a, b);
    };
    b.tcp.store(1, Ordering::SeqCst);
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(a.address, Protocol::Tcp);
    r.listen_end_port = Some(r.listen.port() + 1);
    r.port_mapping = PortMapping::Offset;
    r.health_check = Some(policy(Protocol::Tcp));
    let entry = r.listen;
    let mut c = config(r);
    engine.apply(c.clone()).await.unwrap();
    reports(&engine, |r| {
        r.len() == 2 && r[0].status == Status::Healthy && r[1].status == Status::Unhealthy
    })
    .await;
    assert_eq!(marked(entry).await, *b"AAAA");
    let mut second = entry;
    second.set_port(entry.port() + 1);
    let mut refused = TcpStream::connect(second).await.unwrap();
    let _ = refused.write_all(b"DATA").await;
    let result = timeout(Duration::from_secs(1), refused.read(&mut [0; 4]))
        .await
        .unwrap();
    assert!(matches!(result, Ok(0) | Err(_)));
    c.revision += 1;
    c.rules[0].port_mapping = PortMapping::Fixed;
    engine.apply(c).await.unwrap();
    reports(&engine, |r| r.len() == 1 && r[0].eligible).await;
    assert_eq!(marked(second).await, *b"AAAA");
    engine.shutdown().await.unwrap();
    a.shutdown().await;
    b.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn controller_health_reports_are_scoped_validated_and_aged_without_changing_saved_samples() {
    use relay_platform::store::{Rejection, Role};
    let service = Service::new(b'A').await;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("controller.db");
    let controller = Store::open(&path).unwrap();
    controller.set_kind("controller").unwrap();
    let admin = controller.bootstrap(PASSWORD).unwrap();
    let (node, _) = controller
        .create_node(&admin, "default", "health-node")
        .unwrap();
    let mut r = rule(service.address, Protocol::Tcp);
    r.health_check = Some(policy(Protocol::Tcp));
    let c = controller.set_config(&admin, &node.id, 0, vec![r]).unwrap();
    let local = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(local.clone());
    engine.apply(c.clone()).await.unwrap();
    reports(&engine, |r| r.len() == 1 && r[0].eligible).await;
    assert_eq!(marked(c.rules[0].listen).await, *b"AAAA");
    let page = controller
        .reconcile(
            &node.id,
            ReconcileRequest {
                ledger_id: None,
                after: None,
                expected_revision: None,
            },
        )
        .unwrap();
    let request = |stats: EngineStats| SyncRequest {
        budget: None,
        ledger_id: page.ledger_id.clone(),
        need_config: false,
        applied_revision: 1,
        apply_error: None,
        usage: local.agent_usage(false).unwrap(),
        stats,
    };
    let mut bad = engine.stats();
    bad.target_health[0].rule_id = "not-this-node".into();
    assert_eq!(
        controller
            .sync(&node.id, request(bad))
            .unwrap_err()
            .downcast_ref::<Rejection>()
            .unwrap()
            .status,
        400
    );
    assert!(controller.reported_usage(&admin).unwrap().is_empty());
    controller.sync(&node.id, request(engine.stats())).unwrap();
    let visible = controller.node_health(&admin, &node.id).unwrap();
    assert_eq!(visible["reports"][0]["status"], "healthy");
    assert_eq!(visible["reports"][0]["probe_kind"], "tcp_exchange");
    assert_eq!(visible["expected_endpoints"], 1);
    let mut duplicate = engine.stats();
    duplicate
        .target_health
        .push(duplicate.target_health[0].clone());
    assert_eq!(
        controller
            .sync(&node.id, request(duplicate))
            .unwrap_err()
            .downcast_ref::<Rejection>()
            .unwrap()
            .status,
        400
    );
    let viewer = controller
        .create_user(&admin, "default", "health-viewer", PASSWORD, Role::Viewer)
        .unwrap();
    assert!(controller.node_health(&viewer, &node.id).is_ok());
    let tenant = controller.create_tenant(&admin, "other").unwrap();
    let other = controller
        .create_user(&admin, &tenant, "other-health", PASSWORD, Role::TenantAdmin)
        .unwrap();
    assert_eq!(
        controller
            .node_health(&other, &node.id)
            .unwrap_err()
            .downcast_ref::<Rejection>()
            .unwrap()
            .status,
        404
    );
    let connection = rusqlite::Connection::open(path).unwrap();
    connection
        .execute(
            "UPDATE nodes SET last_seen_ms=?1 WHERE id=?2",
            rusqlite::params![now_ms() - 5000, node.id],
        )
        .unwrap();
    let before: String = connection
        .query_row(
            "SELECT stats_json FROM nodes WHERE id=?1",
            [&node.id],
            |r| r.get(0),
        )
        .unwrap();
    let stale = controller.node_health(&admin, &node.id).unwrap();
    assert_eq!(stale["reports"][0]["status"], "stale");
    assert_eq!(stale["reports"][0]["eligible"], false);
    let after: String = connection
        .query_row(
            "SELECT stats_json FROM nodes WHERE id=?1",
            [&node.id],
            |r| r.get(0),
        )
        .unwrap();
    assert_eq!(before, after);
    engine.shutdown().await.unwrap();
    service.shutdown().await;
}

#[tokio::test]
async fn ordinary_restart_does_not_trust_old_healthy_observations() {
    let service = Service::new(b'A').await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let mut r = rule(service.address, Protocol::Tcp);
    r.health_check = Some(policy(Protocol::Tcp));
    let c = config(r);
    let engine = Engine::new(db.clone());
    engine.apply(c.clone()).await.unwrap();
    reports(&engine, |r| r.len() == 1 && r[0].eligible).await;
    engine.shutdown().await.unwrap();
    service.tcp.store(1, Ordering::SeqCst);
    let restarted = Engine::new(db);
    restarted.apply(c).await.unwrap();
    assert!(!restarted.stats().target_health[0].eligible);
    reports(&restarted, |r| r[0].status == Status::Unhealthy).await;
    restarted.shutdown().await.unwrap();
    service.shutdown().await;
}
