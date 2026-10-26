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
    /// Milliseconds each TCP reply waits, to give targets different latency.
    delay: Arc<std::sync::atomic::AtomicU64>,
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
        let delay = Arc::new(std::sync::atomic::AtomicU64::new(0));
        let (mode, cancel, tracker, wait) =
            (tcp.clone(), stop.clone(), tasks.clone(), delay.clone());
        let probes = Arc::new(AtomicUsize::new(0));
        tasks.spawn(async move {
            loop {
                let pair =
                    tokio::select! {_=cancel.cancelled()=>break,pair=listener.accept()=>pair};
                let Ok((mut stream, _)) = pair else {
                    break;
                };
                let mode = mode.clone();
                let cancel = cancel.clone();
                let wait = wait.clone();
                let probes = probes.clone();
                tracker.spawn(async move {
                    let run = async {
                        let mut data = [0; 4];
                        while stream.read_exact(&mut data).await.is_ok() {
                            let reply = if data == *b"PING" {
                                match mode.load(Ordering::SeqCst) {
                                    0 => *b"PONG",
                                    1 => *b"FAIL",
                                    // Lossy: every fourth probe fails, never two in a row.
                                    3 if probes.fetch_add(1, Ordering::SeqCst) % 4 == 3 => *b"FAIL",
                                    3 => *b"PONG",
                                    _ => {
                                        std::future::pending::<()>().await;
                                        unreachable!()
                                    }
                                }
                            } else {
                                [marker; 4]
                            };
                            sleep(Duration::from_millis(wait.load(Ordering::SeqCst))).await;
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
            delay,
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
async fn lowest_latency_prefers_the_faster_target_and_follows_a_lasting_change() {
    let slow = Service::new(b'S').await;
    let fast = Service::new(b'F').await;
    slow.delay.store(40, Ordering::SeqCst);
    let mut r = two(&slow, &fast, Protocol::Tcp);
    r.targets[1].priority = 0;
    r.balance = Balance::LowestLatency;
    let mut unmeasured = r.clone();
    unmeasured.health_check = None;
    assert!(unmeasured.validate().is_err());
    r.health_check.as_mut().unwrap().timeout_ms = 95;
    let address = r.listen;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    engine.apply(config(r)).await.unwrap();
    reports(&engine, |r| {
        r.len() == 2
            && r.iter()
                .all(|r| r.status == Status::Healthy && r.latency_ewma_us.is_some())
    })
    .await;
    // The faster target is listed second and still takes every new session.
    for _ in 0..4 {
        assert_eq!(marked(address).await, *b"FFFF");
    }
    fast.delay.store(80, Ordering::SeqCst);
    let until = Instant::now() + Duration::from_secs(5);
    while marked(address).await != *b"SSSS" {
        assert!(
            Instant::now() < until,
            "selection never followed the latency change"
        );
        sleep(Duration::from_millis(50)).await;
    }
    for _ in 0..4 {
        assert_eq!(marked(address).await, *b"SSSS");
    }
    engine.shutdown().await.unwrap();
    slow.shutdown().await;
    fast.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn lowest_latency_avoids_a_faster_target_that_loses_probes() {
    let clean = Service::new(b'C').await;
    let lossy = Service::new(b'L').await;
    clean.delay.store(20, Ordering::SeqCst);
    lossy.tcp.store(3, Ordering::SeqCst);
    let mut r = two(&clean, &lossy, Protocol::Tcp);
    r.targets[1].priority = 0;
    r.balance = Balance::LowestLatency;
    let address = r.listen;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    engine.apply(config(r)).await.unwrap();
    // The lossy target stays healthy: its failures never reach two in a row.
    reports(&engine, |r| {
        r.len() == 2
            && r.iter().all(|r| r.status == Status::Healthy)
            && r[1].window_failures >= 1
            && r[0].window_checks >= 4
    })
    .await;
    let report = engine.stats().target_health;
    assert!(report[1].latency_ewma_us < report[0].latency_ewma_us);
    assert_eq!(report[0].window_failures, 0);
    for _ in 0..4 {
        assert_eq!(marked(address).await, *b"CCCC");
    }
    engine.shutdown().await.unwrap();
    clean.shutdown().await;
    lossy.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn weighted_balancing_skips_a_lossy_target_while_a_clean_one_has_the_same_priority() {
    let clean = Service::new(b'C').await;
    let lossy = Service::new(b'L').await;
    let backup = Service::new(b'B').await;
    lossy.tcp.store(3, Ordering::SeqCst);
    let mut r = two(&clean, &lossy, Protocol::Tcp);
    r.targets[1].priority = 0;
    let mut third = r.targets[0].clone();
    third.address = backup.address.to_string();
    third.priority = 5;
    r.targets.push(third);
    let address = r.listen;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    engine.apply(config(r)).await.unwrap();
    reports(&engine, |r| {
        r.len() == 3 && r.iter().all(|r| r.status == Status::Healthy) && r[1].window_failures >= 2
    })
    .await;
    let report = engine.stats().target_health;
    assert_eq!(
        (
            report[0].selection_reason.as_str(),
            report[1].selection_reason.as_str()
        ),
        ("eligible", "degraded")
    );
    assert!(report[1].eligible);
    // Equal weights would alternate; the lossy one now waits behind the clean one.
    for _ in 0..6 {
        assert_eq!(marked(address).await, *b"CCCC");
    }
    // Without a clean target at that priority the lossy one is still used
    // before the lower-priority backup.
    clean.tcp.store(1, Ordering::SeqCst);
    reports(&engine, |r| r[0].status == Status::Unhealthy).await;
    for _ in 0..4 {
        assert_eq!(marked(address).await, *b"LLLL");
    }
    engine.shutdown().await.unwrap();
    for service in [clean, lossy, backup] {
        service.shutdown().await;
    }
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn udp_probes_through_a_relay_hold_one_session_there() {
    let service = Service::new(b'A').await;
    let temp = tempfile::tempdir().unwrap();
    let downstream = Engine::new(Store::open(&temp.path().join("down.db")).unwrap());
    let mut relay = rule(service.address, Protocol::Udp);
    relay.udp_max_sessions = 3;
    relay.idle_timeout_secs = 60;
    let relay_address = relay.listen;
    downstream.apply(config(relay)).await.unwrap();
    let upstream = Engine::new(Store::open(&temp.path().join("up.db")).unwrap());
    let mut probed = rule(relay_address, Protocol::Udp);
    probed.health_check = Some(policy(Protocol::Udp));
    upstream.apply(config(probed)).await.unwrap();
    reports(&upstream, |r| {
        r.len() == 1 && r[0].status == Status::Healthy
    })
    .await;
    // Twenty probe intervals: a new session per probe would exhaust the cap of three.
    sleep(Duration::from_millis(2000)).await;
    let report = &upstream.stats().target_health[0];
    assert_eq!(report.status, Status::Healthy);
    assert_eq!(report.consecutive_failures, 0);
    assert!(report.completed_checks >= 15, "{}", report.completed_checks);
    assert_eq!(downstream.stats().active_udp, 1);
    upstream.shutdown().await.unwrap();
    downstream.shutdown().await.unwrap();
    service.shutdown().await;
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
        accept_prewarmed: false,
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
    let until = Instant::now() + Duration::from_secs(3);
    let usage = loop {
        let usage = db.agent_usage(false).unwrap();
        if usage
            .iter()
            .any(|r| r.rule_id == "exit" && r.upload_bytes >= 8)
        {
            break usage;
        }
        assert!(
            Instant::now() < until,
            "probe traffic never reached the exit ledger"
        );
        sleep(Duration::from_millis(20)).await;
    };
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
                lease: None,
                ledger_id: None,
                after: None,
                expected_revision: None,
            },
        )
        .unwrap();
    let request = |stats: EngineStats| SyncRequest {
        lease: None,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_target_failing_at_first_is_accepted_without_waiting_a_whole_interval_or_the_recovery_delay()
 {
    // A downstream relay that is still starting fails the first probes.
    let a = Service::new(b'A').await;
    a.tcp.store(1, Ordering::SeqCst);
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(a.address, Protocol::Tcp);
    let mut check = policy(Protocol::Tcp);
    (
        check.interval_ms,
        check.timeout_ms,
        check.recovery_delay_ms,
        check.max_age_ms,
    ) = (1000, 60, 5000, 3000);
    r.health_check = Some(check);
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    reports(&engine, |r| r[0].status == Status::Unhealthy).await;
    a.tcp.store(0, Ordering::SeqCst);
    let start = Instant::now();
    reports(&engine, |r| r[0].status == Status::Healthy).await;
    // Two successes at the configured 1 s interval, or the 5 s recovery
    // delay, would each take longer.
    assert!(
        start.elapsed() < Duration::from_millis(900),
        "{:?}",
        start.elapsed()
    );
    assert_eq!(marked(address).await, *b"AAAA");
    engine.shutdown().await.unwrap();
    a.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_silent_udp_target_on_a_fast_path_is_removed_within_two_seconds() {
    let a = Service::new(b'A').await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(a.address, Protocol::Udp);
    let mut check = policy(Protocol::Udp);
    (check.interval_ms, check.timeout_ms, check.max_age_ms) = (1000, 1000, 3000);
    r.health_check = Some(check);
    engine.apply(config(r)).await.unwrap();
    // Five replies give the target a probe timeout of its own.
    timeout(Duration::from_secs(8), async {
        while engine
            .stats()
            .target_health
            .first()
            .is_none_or(|r| r.status != Status::Healthy || r.successful_checks < 5)
        {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    a.udp.store(2, Ordering::SeqCst);
    let silent = Instant::now();
    timeout(Duration::from_secs(6), async {
        while engine.stats().target_health[0].status != Status::Unhealthy {
            sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    // With the full 1 s timeout on both failing probes, removal takes more
    // than 2 s; with 250 ms each it takes at most about 1.5 s.
    assert!(
        silent.elapsed() < Duration::from_millis(1800),
        "{:?}",
        silent.elapsed()
    );
    engine.shutdown().await.unwrap();
    a.shutdown().await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_healthy_target_that_fails_once_is_rechecked_without_waiting_a_whole_interval() {
    let a = Service::new(b'A').await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(a.address, Protocol::Tcp);
    let mut check = policy(Protocol::Tcp);
    (check.interval_ms, check.timeout_ms, check.max_age_ms) = (1000, 60, 3000);
    r.health_check = Some(check);
    engine.apply(config(r)).await.unwrap();
    reports(&engine, |r| r[0].status == Status::Healthy).await;
    a.tcp.store(1, Ordering::SeqCst);
    reports(&engine, |r| r[0].consecutive_failures == 1).await;
    let first_failure = Instant::now();
    reports(&engine, |r| r[0].status == Status::Unhealthy).await;
    // The second failing probe would otherwise come a full second later.
    assert!(
        first_failure.elapsed() < Duration::from_millis(600),
        "{:?}",
        first_failure.elapsed()
    );
    // Once removed, the target is probed at the configured interval again.
    let checks = engine.stats().target_health[0].completed_checks;
    sleep(Duration::from_millis(1500)).await;
    let later = engine.stats().target_health[0].completed_checks;
    assert!(later - checks <= 2, "{checks} -> {later}");
    engine.shutdown().await.unwrap();
    a.shutdown().await;
}
