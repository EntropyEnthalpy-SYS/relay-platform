mod common;
use common::*;
use relay_platform::{engine::Engine, model::*, store::Store};
use std::{sync::Arc, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpStream, UdpSocket},
    time::{Instant, sleep, timeout},
};

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn tcp_binary_payload_half_close_and_durable_bidirectional_metering() {
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let r = rule(echo.address, Protocol::Tcp);
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    let payload: Vec<u8> = (0..1024 * 1024).map(|n| (n % 251) as u8).collect();
    assert_eq!(exchange(address, &payload).await, payload);
    engine.shutdown().await.unwrap();
    let usage = db.agent_usage(false).unwrap();
    assert_eq!(usage[0].upload_bytes, 1024 * 1024);
    assert_eq!(usage[0].download_bytes, 1024 * 1024);
    assert_eq!(engine.stats().forwarded_download_bytes, 1024 * 1024);
}

#[tokio::test]
async fn udp_preserves_datagrams_empty_payloads_and_peer_isolation() {
    let echo = udp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let r = rule(echo.address, Protocol::Udp);
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    // macOS defaults net.inet.udp.maxdgram to 9216; Linux exercises a 60 KB datagram.
    let largest = if cfg!(target_os = "linux") {
        60_000
    } else {
        8192
    };
    let mut expected = 0;
    for peer in 0..4u8 {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.connect(address).await.unwrap();
        for size in [0, 1, 511, 4096, largest] {
            let payload = vec![peer; size];
            socket.send(&payload).await.unwrap();
            let mut buf = vec![0; 65536];
            let n = timeout(Duration::from_secs(3), socket.recv(&mut buf))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buf[..n], payload);
            expected += size as u64;
        }
    }
    engine.shutdown().await.unwrap();
    let u = db.agent_usage(false).unwrap();
    assert_eq!(u[0].upload_bytes, expected);
    assert_eq!(u[0].download_bytes, expected);
    assert_eq!(engine.stats().active_udp, 0);
}

#[tokio::test]
async fn failed_config_keeps_old_listener_and_persisted_revision() {
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let original = config(rule(echo.address, Protocol::Tcp));
    let address = original.rules[0].listen;
    engine.apply(original.clone()).await.unwrap();
    let occupied = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let mut update = original.clone();
    update.revision = 2;
    let mut extra = rule(echo.address, Protocol::Tcp);
    extra.id = "rule-two".into();
    extra.listen = occupied.local_addr().unwrap();
    update.rules.push(extra);
    assert!(engine.apply(update).await.is_err());
    assert_eq!(engine.revision().await, 1);
    assert_eq!(db.agent_config().unwrap().unwrap().revision, 1);
    assert_eq!(
        exchange(address, b"old-listener-still-works").await,
        b"old-listener-still-works"
    );
    let mut same_revision = original;
    same_revision.rules[0].name = "changed-without-version".into();
    assert!(engine.apply(same_revision).await.is_err());
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn routing_updates_preserve_existing_connections_and_shutdown_cancels_all_generations() {
    let first = tcp_echo_at("127.0.0.1:0", Some(b'A')).await;
    let second = tcp_echo_at("127.0.0.1:0", Some(b'B')).await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut c = config(rule(first.address, Protocol::Tcp));
    let address = c.rules[0].listen;
    engine.apply(c.clone()).await.unwrap();
    let mut old = TcpStream::connect(address).await.unwrap();
    let mut mark = [0];
    timeout(Duration::from_secs(2), old.read_exact(&mut mark))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mark[0], b'A');
    c.revision = 2;
    c.rules[0].targets[0].address = second.address.to_string();
    engine.apply(c.clone()).await.unwrap();
    let mut new = TcpStream::connect(address).await.unwrap();
    timeout(Duration::from_secs(2), new.read_exact(&mut mark))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(mark[0], b'B');
    old.write_all(b"alive").await.unwrap();
    let mut bytes = [0; 5];
    timeout(Duration::from_secs(2), old.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bytes, b"alive");
    c.revision = 3;
    c.rules[0].name = "third-generation".into();
    c.rules[0].targets.push(Target {
        address: first.address.to_string(),
        weight: 1,
        tls: None,
        proxy_protocol: None,
        websocket: None,
    });
    engine.apply(c).await.unwrap();
    old.write_all(b"alive").await.unwrap();
    timeout(Duration::from_secs(2), old.read_exact(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(
        &bytes, b"alive",
        "adding a plaintext target must not cancel existing routing generations"
    );
    timeout(Duration::from_secs(2), engine.shutdown())
        .await
        .expect("shutdown leaked an old routing generation")
        .unwrap();
    assert_eq!(engine.stats().active_tcp, 0);
}

#[tokio::test]
async fn deleting_a_rule_terminates_existing_connections() {
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut c = config(rule(echo.address, Protocol::Tcp));
    let address = c.rules[0].listen;
    engine.apply(c.clone()).await.unwrap();
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(b"1").await.unwrap();
    let mut buf = [0];
    stream.read_exact(&mut buf).await.unwrap();
    c.revision = 2;
    c.rules.clear();
    engine.apply(c).await.unwrap();
    let n = timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .unwrap();
    assert!(matches!(n, Ok(0) | Err(_)));
    assert!(TcpStream::connect(address).await.is_err());
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn udp_enforces_combined_quota_without_partial_datagrams() {
    let echo = udp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let mut r = rule(echo.address, Protocol::Udp);
    r.quota_bytes = Some(30);
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(address).await.unwrap();
    let mut buf = [0; 100];
    socket.send(&[42; 10]).await.unwrap();
    assert_eq!(
        timeout(Duration::from_secs(2), socket.recv(&mut buf))
            .await
            .unwrap()
            .unwrap(),
        10
    );
    socket.send(&[7; 10]).await.unwrap();
    assert!(
        timeout(Duration::from_millis(200), socket.recv(&mut buf))
            .await
            .is_err()
    );
    engine.shutdown().await.unwrap();
    let u = db.agent_usage(false).unwrap();
    assert_eq!(u[0].upload_bytes, 20);
    assert_eq!(u[0].download_bytes, 10);
    assert_eq!(engine.stats().forwarded_download_bytes, 10);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn concurrent_tcp_sessions_cannot_multiply_the_rule_quota() {
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Arc::new(Engine::new(db.clone()));
    let mut r = rule(echo.address, Protocol::Tcp);
    r.quota_bytes = Some(10_000);
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    let mut tasks = vec![];
    for _ in 0..16 {
        tasks.push(tokio::spawn(async move {
            let mut socket = TcpStream::connect(address).await.unwrap();
            let _ = socket.write_all(&[4; 2048]).await;
            let _ = socket.shutdown().await;
            let mut received = vec![];
            let _ = timeout(Duration::from_secs(3), socket.read_to_end(&mut received)).await;
        }));
    }
    for task in tasks {
        task.await.unwrap();
    }
    engine.shutdown().await.unwrap();
    let u = db.agent_usage(false).unwrap();
    assert_eq!(u[0].upload_bytes + u[0].download_bytes, 10_000);
    assert!(
        engine.stats().forwarded_upload_bytes + engine.stats().forwarded_download_bytes <= 10_000
    );
}

#[tokio::test]
async fn ipv6_and_dns_targets_transfer_real_bytes() {
    let echo = tcp_echo_at("[::1]:0", None).await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let held = std::net::TcpListener::bind("[::1]:0").unwrap();
    let address = held.local_addr().unwrap();
    drop(held);
    let mut r = rule(echo.address, Protocol::Tcp);
    r.listen = address;
    engine.apply(config(r)).await.unwrap();
    assert_eq!(exchange(address, b"ipv6").await, b"ipv6");
    engine.shutdown().await.unwrap();
    let echo = tcp_echo().await;
    let temp2 = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp2.path().join("agent.db")).unwrap());
    let mut r = rule(echo.address, Protocol::Tcp);
    r.targets[0].address = format!("localhost:{}", echo.address.port());
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    assert_eq!(exchange(address, b"dns").await, b"dns");
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn source_acl_denies_before_any_billable_payload() {
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let mut r = rule(echo.address, Protocol::Tcp);
    r.deny_sources = vec!["127.0.0.0/8".parse().unwrap()];
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    let mut stream = TcpStream::connect(address).await.unwrap();
    let _ = stream.write_all(b"blocked").await;
    let mut buf = [0; 32];
    let result = timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .unwrap();
    assert!(matches!(result, Ok(0) | Err(_)));
    engine.shutdown().await.unwrap();
    assert!(db.agent_usage(false).unwrap().is_empty());
    assert_eq!(engine.stats().rejected_connections, 1);
}

#[tokio::test]
async fn shared_rate_limit_includes_both_directions_and_declares_burst() {
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(echo.address, Protocol::Tcp);
    r.rate_bytes_per_sec = Some(64 * 1024);
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    let started = Instant::now();
    let payload = vec![9; 96 * 1024];
    assert_eq!(exchange(address, &payload).await, payload);
    let elapsed = started.elapsed();
    assert!(
        elapsed >= Duration::from_millis(1850),
        "192 KiB minus a 64 KiB burst requires at least 2 seconds at 64 KiB/s, observed {elapsed:?}"
    );
    assert!(elapsed < Duration::from_secs(5));
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn udp_session_limit_and_idle_reclamation_are_real() {
    let echo = udp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(echo.address, Protocol::Udp);
    r.udp_max_sessions = 1;
    r.idle_timeout_secs = 1;
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buf = [0; 8];
    a.send_to(b"A", address).await.unwrap();
    timeout(Duration::from_secs(1), a.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    b.send_to(b"B", address).await.unwrap();
    assert!(
        timeout(Duration::from_millis(100), b.recv_from(&mut buf))
            .await
            .is_err()
    );
    sleep(Duration::from_millis(1100)).await;
    b.send_to(b"B", address).await.unwrap();
    let (n, _) = timeout(Duration::from_secs(1), b.recv_from(&mut buf))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buf[..n], b"B");
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn weighted_target_selection_and_connect_failure_fallback() {
    let a = tcp_echo_at("127.0.0.1:0", Some(b'A')).await;
    let b = tcp_echo_at("127.0.0.1:0", Some(b'B')).await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(a.address, Protocol::Tcp);
    r.targets = vec![
        Target {
            address: a.address.to_string(),
            weight: 2,
            tls: None,
            proxy_protocol: None,
            websocket: None,
        },
        Target {
            address: b.address.to_string(),
            weight: 1,
            tls: None,
            proxy_protocol: None,
            websocket: None,
        },
    ];
    let address = r.listen;
    let mut c = config(r);
    engine.apply(c.clone()).await.unwrap();
    let mut markers = vec![];
    for _ in 0..6 {
        let mut s = TcpStream::connect(address).await.unwrap();
        let mut m = [0];
        timeout(Duration::from_secs(1), s.read_exact(&mut m))
            .await
            .unwrap()
            .unwrap();
        markers.push(m[0]);
    }
    assert_eq!(markers, b"AABAAB");
    c.revision = 2;
    c.rules[0].targets = vec![
        Target {
            address: free_address().to_string(),
            weight: 1,
            tls: None,
            proxy_protocol: None,
            websocket: None,
        },
        Target {
            address: b.address.to_string(),
            weight: 1,
            tls: None,
            proxy_protocol: None,
            websocket: None,
        },
    ];
    engine.apply(c).await.unwrap();
    let mut s = TcpStream::connect(address).await.unwrap();
    let mut m = [0];
    timeout(Duration::from_secs(1), s.read_exact(&mut m))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(m[0], b'B');
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn failed_meter_transaction_never_forwards_uncommitted_payload() {
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("agent.db");
    let db = Store::open(&path).unwrap();
    let engine = Engine::new(db.clone());
    let r = rule(echo.address, Protocol::Tcp);
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    let fault = rusqlite::Connection::open(&path).unwrap();
    fault.execute_batch("CREATE TRIGGER fail_meter BEFORE UPDATE OF upload_bytes ON agent_meters BEGIN SELECT RAISE(ABORT,'injected transaction failure'); END;").unwrap();
    let mut stream = TcpStream::connect(address).await.unwrap();
    stream.write_all(b"must-not-forward").await.unwrap();
    let mut buf = [0; 32];
    let result = timeout(Duration::from_secs(2), stream.read(&mut buf))
        .await
        .unwrap();
    assert!(matches!(result, Ok(0) | Err(_)));
    engine.shutdown().await.unwrap();
    assert!(db.agent_usage(false).unwrap().is_empty());
    assert_eq!(engine.stats().forwarded_upload_bytes, 0);
}

#[tokio::test]
async fn dual_protocol_listener_and_ipv6_udp_are_independently_verified() {
    let tcp = tcp_echo_at("[::1]:0", None).await;
    let _udp = udp_echo_at(&tcp.address.to_string()).await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let reserve = std::net::TcpListener::bind("[::1]:0").unwrap();
    let address = reserve.local_addr().unwrap();
    drop(reserve);
    let mut r = rule(tcp.address, Protocol::Both);
    r.listen = address;
    engine.apply(config(r)).await.unwrap();
    assert_eq!(exchange(address, b"tcp").await, b"tcp");
    let socket = UdpSocket::bind("[::1]:0").await.unwrap();
    socket.send_to(b"udp", address).await.unwrap();
    let mut buffer = [0; 10];
    let (n, _) = timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer[..n], b"udp");
    engine.shutdown().await.unwrap();
    let usage = db.agent_usage(false).unwrap();
    assert_eq!(usage[0].upload_bytes + usage[0].download_bytes, 12);
}

#[tokio::test]
async fn source_hash_is_stable_and_least_connections_uses_active_sessions() {
    let a = tcp_echo_at("127.0.0.1:0", Some(b'A')).await;
    let b = tcp_echo_at("127.0.0.1:0", Some(b'B')).await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(a.address, Protocol::Tcp);
    r.targets.push(Target {
        address: b.address.to_string(),
        weight: 1,
        tls: None,
        proxy_protocol: None,
        websocket: None,
    });
    r.balance = Balance::SourceHash;
    let address = r.listen;
    let mut c = config(r);
    engine.apply(c.clone()).await.unwrap();
    let mut markers = vec![];
    for _ in 0..6 {
        let mut stream = TcpStream::connect(address).await.unwrap();
        let mut marker = [0];
        timeout(Duration::from_secs(2), stream.read_exact(&mut marker))
            .await
            .unwrap()
            .unwrap();
        markers.push(marker[0]);
    }
    assert!(markers.iter().all(|m| *m == markers[0]));
    c.revision = 2;
    c.rules[0].balance = Balance::LeastConnections;
    engine.apply(c).await.unwrap();
    let mut first = TcpStream::connect(address).await.unwrap();
    let mut second = TcpStream::connect(address).await.unwrap();
    let mut ma = [0];
    let mut mb = [0];
    timeout(Duration::from_secs(2), first.read_exact(&mut ma))
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(2), second.read_exact(&mut mb))
        .await
        .unwrap()
        .unwrap();
    assert_ne!(ma, mb);
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn moving_udp_listener_releases_the_old_port_even_while_a_session_is_throttled() {
    let echo = udp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(echo.address, Protocol::Udp);
    r.rate_bytes_per_sec = Some(1);
    let old_address = r.listen;
    let mut c = config(r);
    engine.apply(c.clone()).await.unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buffer = [0; 8192];
    for _ in 0..8 {
        socket.send_to(&[1; 4096], old_address).await.unwrap();
        timeout(Duration::from_secs(1), socket.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
    }
    socket.send_to(&[1; 4096], old_address).await.unwrap();
    sleep(Duration::from_millis(20)).await;
    assert_eq!(engine.stats().active_udp, 1);
    c.revision = 2;
    c.rules[0].listen = free_address();
    engine.apply(c).await.unwrap();
    let until = Instant::now() + Duration::from_secs(1);
    loop {
        if let Ok(rebound) = UdpSocket::bind(old_address).await {
            drop(rebound);
            break;
        }
        assert!(
            Instant::now() < until,
            "old UDP socket leaked behind the limiter"
        );
        sleep(Duration::from_millis(5)).await;
    }
    engine.shutdown().await.unwrap();
}
