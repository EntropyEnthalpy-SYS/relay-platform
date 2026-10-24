mod common;
use common::*;
use hickory_resolver::proto::{
    op::{Message, ResponseCode},
    rr::{
        Name, RData, Record, RecordType,
        rdata::{A, AAAA, SOA},
    },
};
use relay_platform::{engine::Engine, model::*, store::Store};
use std::{
    net::{IpAddr, SocketAddr},
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    task::JoinHandle,
    time::{sleep, timeout},
};

fn free_range() -> SocketAddr {
    for _ in 0..100 {
        let first = free_address();
        if first.port() == u16::MAX {
            continue;
        }
        let second = SocketAddr::new(first.ip(), first.port() + 1);
        if let (Ok(_a), Ok(_b), Ok(_c), Ok(_d)) = (
            std::net::TcpListener::bind(first),
            std::net::UdpSocket::bind(first),
            std::net::TcpListener::bind(second),
            std::net::UdpSocket::bind(second),
        ) {
            return first;
        }
    }
    panic!("cannot allocate two consecutive ports");
}
fn next(address: SocketAddr) -> SocketAddr {
    SocketAddr::new(address.ip(), address.port() + 1)
}
async fn udp_exchange(address: SocketAddr, bytes: &[u8]) -> Vec<u8> {
    let socket = UdpSocket::bind(if address.is_ipv4() {
        "127.0.0.1:0"
    } else {
        "[::1]:0"
    })
    .await
    .unwrap();
    socket.connect(address).await.unwrap();
    socket.send(bytes).await.unwrap();
    let mut buf = vec![0; 65536];
    let count = timeout(Duration::from_secs(3), socket.recv(&mut buf))
        .await
        .unwrap()
        .unwrap();
    buf.truncate(count);
    buf
}
async fn expect_tcp_rejected(address: SocketAddr) {
    let mut stream = TcpStream::connect(address).await.unwrap();
    let _ = stream.write_all(b"must-not-forward").await;
    let result = timeout(Duration::from_secs(2), stream.read(&mut [0; 32]))
        .await
        .expect("rejected connection remained open");
    assert!(
        matches!(result, Ok(0) | Err(_)),
        "unexpected forwarded payload: {result:?}"
    );
}

#[tokio::test]
async fn port_ranges_offset_tcp_udp_and_shared_meter() {
    let target = free_range();
    let _t0 = tcp_echo_at(&target.to_string(), None).await;
    let _t1 = tcp_echo_at(&next(target).to_string(), Some(b'B')).await;
    let _u0 = udp_echo_at(&target.to_string()).await;
    let _u1 = udp_echo_at(&next(target).to_string()).await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let mut r = rule(target, Protocol::Both);
    r.listen = free_range();
    r.listen_end_port = Some(r.listen.port() + 1);
    r.port_mapping = PortMapping::Offset;
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    assert_eq!(exchange(address, b"first").await, b"first");
    assert_eq!(exchange(next(address), b"second").await, b"Bsecond");
    assert_eq!(udp_exchange(address, b"udp-one").await, b"udp-one");
    assert_eq!(udp_exchange(next(address), b"udp-two").await, b"udp-two");
    engine.shutdown().await.unwrap();
    let usage = db.agent_usage(false).unwrap();
    assert_eq!(usage.len(), 1);
    assert_eq!((usage[0].upload_bytes, usage[0].download_bytes), (25, 26));
}

#[tokio::test]
async fn fixed_range_quota_and_connection_limits_cannot_multiply() {
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let mut r = rule(echo.address, Protocol::Tcp);
    r.listen = free_range();
    r.listen_end_port = Some(r.listen.port() + 1);
    r.quota_bytes = Some(16);
    r.max_connections = 1;
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    let mut first = TcpStream::connect(address).await.unwrap();
    first.write_all(b"four").await.unwrap();
    first.read_exact(&mut [0; 4]).await.unwrap();
    expect_tcp_rejected(next(address)).await;
    drop(first);
    timeout(Duration::from_secs(2), async {
        while engine.stats().active_tcp != 0 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(exchange(next(address), b"four").await, b"four");
    expect_tcp_rejected(address).await;
    engine.shutdown().await.unwrap();
    let usage = db.agent_usage(false).unwrap();
    assert_eq!(usage.len(), 1);
    assert_eq!(usage[0].upload_bytes + usage[0].download_bytes, 16);
}

#[tokio::test]
async fn udp_session_limit_is_shared_across_range() {
    let echo = udp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(echo.address, Protocol::Udp);
    r.listen = free_range();
    r.listen_end_port = Some(r.listen.port() + 1);
    r.udp_max_sessions = 1;
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    assert_eq!(udp_exchange(address, b"one").await, b"one");
    let blocked = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    blocked.send_to(b"two", next(address)).await.unwrap();
    assert!(
        timeout(Duration::from_millis(150), blocked.recv(&mut [0; 8]))
            .await
            .is_err()
    );
    assert_eq!(engine.stats().active_udp, 1);
    assert_eq!(engine.stats().dropped_datagrams, 1);
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn range_stage_failure_releases_new_sockets_and_preserves_old_config() {
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let original = config(rule(echo.address, Protocol::Tcp));
    engine.apply(original.clone()).await.unwrap();
    let range = free_range();
    let _occupied = std::net::TcpListener::bind(next(range)).unwrap();
    let mut revised = original.clone();
    revised.revision = 2;
    let mut additional = rule(echo.address, Protocol::Both);
    additional.id = "range".into();
    additional.listen = range;
    additional.listen_end_port = Some(range.port() + 1);
    revised.rules.push(additional);
    assert!(engine.apply(revised).await.is_err());
    let _released_tcp = std::net::TcpListener::bind(range).unwrap();
    let _released_udp = std::net::UdpSocket::bind(range).unwrap();
    assert_eq!(engine.revision().await, 1);
    assert_eq!(db.agent_config().unwrap().unwrap().revision, 1);
    assert_eq!(
        exchange(original.rules[0].listen, b"still-live").await,
        b"still-live"
    );
    engine.shutdown().await.unwrap();
}

#[test]
fn range_limits_overlap_and_static_cycle_validation() {
    let mut c = config(rule("127.0.0.1:32101".parse().unwrap(), Protocol::Both));
    c.rules[0].listen = "0.0.0.0:32100".parse().unwrap();
    c.rules[0].listen_end_port = Some(32101);
    assert!(c.validate().is_err(), "range includes its own fixed target");
    c.rules[0].listen_end_port = None;
    let mut second = rule("127.0.0.1:32100".parse().unwrap(), Protocol::Both);
    second.id = "second".into();
    second.listen = "127.0.0.1:32101".parse().unwrap();
    c.rules.push(second);
    assert!(c.validate().is_err(), "literal two-hop cycle");
    c.rules[1].targets[0].address = "[::ffff:127.0.0.1]:32100".into();
    assert!(
        c.validate().is_err(),
        "mapped IPv4 alias cannot bypass cycle check"
    );
    c.rules[1].targets[0].address = "192.0.2.1:32100".into();
    c.validate().unwrap(); // A remote address using the same port is not a local cycle.
    c.rules[1].listen.set_port(32100);
    assert!(c.validate().is_err(), "wildcard/specific listener overlap");
    c.rules.pop();
    c.rules[0].targets[0].address = "192.0.2.1:65535".into();
    c.rules[0].listen_end_port = Some(32101);
    c.rules[0].port_mapping = PortMapping::Offset;
    assert!(c.validate().is_err(), "offset overflow");
    c.rules[0].port_mapping = PortMapping::Fixed;
    c.rules[0].listen_end_port = Some(32356);
    assert!(c.validate().is_err(), "more than 256 ports");
}

#[tokio::test]
async fn outbound_ip_and_loopback_interface_tcp_udp_ipv4_ipv6() {
    for local in ["127.0.0.1:0", "[::1]:0"] {
        let (echo, _udp) = tcp_udp_echo_at(local).await;
        let interface = if_addrs::get_if_addrs()
            .unwrap()
            .into_iter()
            .find(|i| i.ip() == echo.address.ip())
            .unwrap()
            .name;
        let temp = tempfile::tempdir().unwrap();
        let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
        let mut r = rule(echo.address, Protocol::Both);
        r.outbound_bind = Some(OutboundBind {
            ip: Some(echo.address.ip()),
            interface: Some(interface),
        });
        let address = r.listen;
        engine.apply(config(r)).await.unwrap();
        assert_eq!(exchange(address, b"bound-tcp").await, b"bound-tcp");
        assert_eq!(udp_exchange(address, b"bound-udp").await, b"bound-udp");
        engine.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn invalid_bind_rejects_config_without_unbound_fallback() {
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let original = config(rule(echo.address, Protocol::Tcp));
    engine.apply(original.clone()).await.unwrap();
    for bind in [
        OutboundBind {
            ip: None,
            interface: Some("relay-interface-does-not-exist".into()),
        },
        OutboundBind {
            ip: Some("192.0.2.246".parse().unwrap()),
            interface: None,
        },
    ] {
        let mut revised = original.clone();
        revised.revision = 2;
        revised.rules[0].outbound_bind = Some(bind);
        assert!(engine.apply(revised).await.is_err());
        assert_eq!(db.agent_config().unwrap().unwrap().revision, 1);
        assert_eq!(exchange(original.rules[0].listen, b"old").await, b"old");
    }
    let mut mismatch = original.clone();
    mismatch.rules[0].outbound_bind = Some(OutboundBind {
        ip: Some("::1".parse().unwrap()),
        interface: None,
    });
    assert!(mismatch.validate().is_err());
    engine.shutdown().await.unwrap();
}

struct DnsStub {
    address: SocketAddr,
    ips: Arc<Mutex<Vec<IpAddr>>>,
    count: Arc<AtomicUsize>,
    task: JoinHandle<()>,
}
impl Drop for DnsStub {
    fn drop(&mut self) {
        self.task.abort();
    }
}
impl DnsStub {
    async fn new(ips: Vec<IpAddr>, ttl: u32) -> Self {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let address = socket.local_addr().unwrap();
        let ips = Arc::new(Mutex::new(ips));
        let answers = ips.clone();
        let count = Arc::new(AtomicUsize::new(0));
        let queries = count.clone();
        let task = tokio::spawn(async move {
            let mut buf = [0; 4096];
            loop {
                let (n, peer) = socket.recv_from(&mut buf).await.unwrap();
                let request = Message::from_vec(&buf[..n]).unwrap();
                queries.fetch_add(1, Ordering::SeqCst);
                let mut response = Message::response(request.metadata.id, request.metadata.op_code);
                response.metadata.authoritative = true;
                response.metadata.recursion_available = true;
                response.metadata.recursion_desired = request.metadata.recursion_desired;
                response.queries = request.queries.clone();
                response.edns = request.edns.clone();
                let ips = answers.lock().unwrap().clone();
                if ips.is_empty() {
                    response.metadata.response_code = ResponseCode::NXDomain;
                }
                for query in &request.queries {
                    for ip in &ips {
                        let data = match (query.query_type(), ip) {
                            (RecordType::A, IpAddr::V4(ip)) => Some(RData::A(A(*ip))),
                            (RecordType::AAAA, IpAddr::V6(ip)) => Some(RData::AAAA(AAAA(*ip))),
                            _ => None,
                        };
                        if let Some(data) = data {
                            response.add_answer(Record::from_rdata(
                                query.name().clone(),
                                ttl,
                                data,
                            ));
                        }
                    }
                }
                if response.answers.is_empty() {
                    let name = Name::from_ascii("relay.test.").unwrap();
                    response.add_authority(Record::from_rdata(
                        name.clone(),
                        ttl,
                        RData::SOA(SOA::new(name.clone(), name, 1, 60, 60, 60, ttl)),
                    ));
                }
                socket
                    .send_to(&response.to_vec().unwrap(), peer)
                    .await
                    .unwrap();
            }
        });
        Self {
            address,
            ips,
            count,
            task,
        }
    }
    fn policy(&self) -> DnsCache {
        DnsCache {
            servers: vec![self.address],
            capacity: 32,
            max_ttl_secs: 300,
            negative_max_ttl_secs: 5,
        }
    }
}

#[tokio::test]
async fn dns_cache_uses_authoritative_ttl_and_shares_across_rules() {
    let first = tcp_echo().await;
    let _second = tcp_echo_at(&format!("[::1]:{}", first.address.port()), Some(b'V')).await;
    let dns = DnsStub::new(vec![first.address.ip()], 1).await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(first.address, Protocol::Tcp);
    r.targets[0].address = format!("cache.relay.test.:{}", first.address.port());
    r.dns_cache = Some(dns.policy());
    let address = r.listen;
    let mut c = config(r.clone());
    r.id = "second".into();
    r.listen = free_address();
    let other = r.listen;
    c.rules.push(r);
    engine.apply(c).await.unwrap();
    assert_eq!(exchange(address, b"one").await, b"one");
    let count = dns.count.load(Ordering::SeqCst);
    *dns.ips.lock().unwrap() = vec!["::1".parse().unwrap()];
    assert_eq!(exchange(other, b"two").await, b"two");
    assert_eq!(
        dns.count.load(Ordering::SeqCst),
        count,
        "identical policies share cached answers"
    );
    sleep(Duration::from_millis(1150)).await;
    assert_eq!(exchange(address, b"three").await, b"Vthree");
    assert!(dns.count.load(Ordering::SeqCst) > count);
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn dns_negative_cache_expires_and_failed_target_falls_back() {
    let echo = tcp_echo().await;
    let dns = DnsStub::new(vec![], 30).await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(echo.address, Protocol::Tcp);
    r.targets[0].address = format!("missing.relay.test.:{}", echo.address.port());
    let mut policy = dns.policy();
    policy.negative_max_ttl_secs = 1;
    r.dns_cache = Some(policy);
    let address = r.listen;
    let mut c = config(r.clone());
    engine.apply(c.clone()).await.unwrap();
    expect_tcp_rejected(address).await;
    let count = dns.count.load(Ordering::SeqCst);
    *dns.ips.lock().unwrap() = vec![echo.address.ip()];
    expect_tcp_rejected(address).await;
    assert_eq!(dns.count.load(Ordering::SeqCst), count);
    sleep(Duration::from_millis(1150)).await;
    assert_eq!(exchange(address, b"found").await, b"found");
    c.revision = 2;
    c.rules[0].targets[0].address = format!("never.relay.test.:{}", echo.address.port());
    c.rules[0].targets.push(Target {
        priority: 0,
        max_sessions: None,
        address: echo.address.to_string(),
        weight: 1,
        tls: None,
        proxy_protocol: None,
        websocket: None,
        via: None,
    });
    *dns.ips.lock().unwrap() = vec![];
    engine.apply(c).await.unwrap();
    assert_eq!(exchange(address, b"fallback").await, b"fallback");
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn dns_rebinding_to_local_listener_is_rejected_after_ttl() {
    let echo = tcp_echo().await;
    let dns = DnsStub::new(vec![echo.address.ip()], 1).await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(echo.address, Protocol::Tcp);
    r.listen = format!("[::1]:{}", echo.address.port()).parse().unwrap();
    r.targets[0].address = format!("changing.relay.test.:{}", echo.address.port());
    r.dns_cache = Some(dns.policy());
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    assert_eq!(exchange(address, b"before").await, b"before");
    *dns.ips.lock().unwrap() = vec!["::1".parse().unwrap()];
    sleep(Duration::from_millis(1150)).await;
    expect_tcp_rejected(address).await;
    assert_eq!(
        engine.stats().accepted_tcp,
        2,
        "loop protection must reject before dialing its own listener"
    );
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn dns_two_hop_cycles_stop_but_acyclic_local_chains_forward() {
    let echo = tcp_echo().await;
    let dns = DnsStub::new(vec![echo.address.ip()], 30).await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut a = rule(echo.address, Protocol::Tcp);
    let mut b = rule(echo.address, Protocol::Tcp);
    b.id = "second".into();
    a.targets[0].address = format!("a.relay.test.:{}", b.listen.port());
    a.dns_cache = Some(dns.policy());
    b.targets[0].address = format!("b.relay.test.:{}", a.listen.port());
    b.dns_cache = Some(dns.policy());
    let address = a.listen;
    let mut c = config(a);
    c.rules.push(b);
    engine.apply(c.clone()).await.unwrap();
    expect_tcp_rejected(address).await;
    assert_eq!(
        engine.stats().accepted_tcp,
        2,
        "two-hop cycle should close before a third accept"
    );
    c.revision = 2;
    c.rules[1].targets[0].address = echo.address.to_string();
    engine.apply(c).await.unwrap();
    assert_eq!(exchange(address, b"chain").await, b"chain");
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn udp_dns_cycle_drops_before_recursive_datagram() {
    let dns = DnsStub::new(vec!["127.0.0.1".parse().unwrap()], 30).await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule("127.0.0.1:1".parse().unwrap(), Protocol::Udp);
    r.targets[0].address = format!("udp.relay.test.:{}", r.listen.port());
    r.dns_cache = Some(dns.policy());
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(b"loop", address).await.unwrap();
    timeout(Duration::from_secs(2), async {
        while engine.stats().dropped_datagrams == 0 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(engine.stats().forwarded_upload_bytes, 0);
    assert_eq!(engine.stats().dropped_datagrams, 1);
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn ipv6_wildcard_is_v6_only_and_ipv4_can_share_port() {
    let (echo, _udp) = tcp_udp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let a = rule(echo.address, Protocol::Both);
    let address = a.listen;
    let mut b = a.clone();
    b.id = "v6".into();
    b.listen = format!("[::]:{}", address.port()).parse().unwrap();
    let mut c = config(a);
    c.rules.push(b);
    engine.apply(c).await.unwrap();
    let v6 = format!("[::1]:{}", address.port()).parse().unwrap();
    for address in [address, v6] {
        assert_eq!(exchange(address, b"tcp").await, b"tcp");
        assert_eq!(udp_exchange(address, b"udp").await, b"udp");
    }
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn dns_positive_ttl_cap_and_zero_ttl_udp() {
    let (echo, _udp) = tcp_udp_echo().await;
    let dns = DnsStub::new(vec![echo.address.ip()], 30).await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(echo.address, Protocol::Both);
    r.targets[0].address = format!("caps.relay.test.:{}", echo.address.port());
    let mut policy = dns.policy();
    policy.max_ttl_secs = 1;
    r.dns_cache = Some(policy);
    let address = r.listen;
    let mut c = config(r);
    engine.apply(c.clone()).await.unwrap();
    assert_eq!(exchange(address, b"one").await, b"one");
    let count = dns.count.load(Ordering::SeqCst);
    assert_eq!(udp_exchange(address, b"two").await, b"two");
    assert_eq!(dns.count.load(Ordering::SeqCst), count);
    sleep(Duration::from_millis(1150)).await;
    assert_eq!(exchange(address, b"three").await, b"three");
    assert!(
        dns.count.load(Ordering::SeqCst) > count,
        "configured cap shortens a 30-second TTL"
    );
    c.revision = 2;
    c.rules[0].dns_cache.as_mut().unwrap().max_ttl_secs = 0;
    engine.apply(c).await.unwrap();
    assert_eq!(udp_exchange(address, b"four").await, b"four");
    let count = dns.count.load(Ordering::SeqCst);
    assert_eq!(udp_exchange(address, b"five").await, b"five");
    assert!(
        dns.count.load(Ordering::SeqCst) > count,
        "zero cap must not reuse positive answers"
    );
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn active_old_generation_edges_remain_protected_until_drained() {
    let echo = tcp_echo().await;
    let dns = DnsStub::new(vec![echo.address.ip()], 30).await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut a = rule(echo.address, Protocol::Tcp);
    let mut b = rule(echo.address, Protocol::Tcp);
    b.id = "second".into();
    b.dns_cache = Some(dns.policy());
    let (first, second) = (a.listen, b.listen);
    a.targets[0].address = format!("old.relay.test.:{}", second.port());
    a.dns_cache = Some(dns.policy());
    let mut c = config(a);
    c.rules.push(b);
    engine.apply(c.clone()).await.unwrap();
    let mut old = TcpStream::connect(first).await.unwrap();
    old.write_all(b"alive").await.unwrap();
    old.read_exact(&mut [0; 5]).await.unwrap();
    c.revision = 2;
    c.rules[0].targets[0].address = echo.address.to_string();
    c.rules[1].targets[0].address = format!("new.relay.test.:{}", first.port());
    engine.apply(c).await.unwrap();
    expect_tcp_rejected(second).await;
    old.write_all(b"alive").await.unwrap();
    old.read_exact(&mut [0; 5]).await.unwrap();
    drop(old);
    timeout(Duration::from_secs(2), async {
        while engine.stats().active_tcp != 0 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(exchange(second, b"drained").await, b"drained");
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn bound_source_ip_is_observed_by_target_and_dns_family_falls_back() {
    let listener = tokio::net::TcpListener::bind("[::1]:0").await.unwrap();
    let target = listener.local_addr().unwrap();
    let udp = UdpSocket::bind(target).await.unwrap();
    let dns = DnsStub::new(
        vec!["127.0.0.1".parse().unwrap(), "::1".parse().unwrap()],
        30,
    )
    .await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(target, Protocol::Both);
    r.targets[0].address = format!("families.relay.test.:{}", target.port());
    r.dns_cache = Some(dns.policy());
    r.outbound_bind = Some(OutboundBind {
        ip: Some(target.ip()),
        interface: None,
    });
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    let mut client = TcpStream::connect(address).await.unwrap();
    let (mut destination, peer) = timeout(Duration::from_secs(3), listener.accept())
        .await
        .unwrap()
        .unwrap();
    assert_eq!(peer.ip(), target.ip());
    destination.write_all(b"source-confirmed").await.unwrap();
    let mut bytes = [0; 16];
    client.read_exact(&mut bytes).await.unwrap();
    assert_eq!(&bytes, b"source-confirmed");
    let udp_client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    udp_client.send_to(b"source", address).await.unwrap();
    let (size, peer) = timeout(Duration::from_secs(3), udp.recv_from(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(peer.ip(), target.ip());
    assert_eq!(&bytes[..size], b"source");
    udp.send_to(b"ok", peer).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(3), udp_client.recv(&mut bytes))
            .await
            .unwrap()
            .unwrap(),
        2
    );
    drop(client);
    drop(destination);
    engine.shutdown().await.unwrap();
}
