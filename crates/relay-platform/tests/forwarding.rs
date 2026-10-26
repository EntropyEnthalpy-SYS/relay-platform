mod common;
use common::*;
use relay_platform::{
    engine::Engine,
    model::*,
    store::{Store, secret},
};
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
async fn udp_bursts_reach_the_target_without_drops() {
    let echo = udp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let r = rule(echo.address, Protocol::Udp);
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(address).await.unwrap();
    // Each burst arrives before the session runs; together they pass far more
    // bytes through one session than it may hold at once.
    for round in 0..8u8 {
        for n in 0..32u8 {
            socket.send(&[round, n].repeat(600)).await.unwrap();
        }
        let mut seen = Vec::new();
        let mut buf = [0; 2048];
        while seen.len() < 32 {
            let size = timeout(Duration::from_secs(3), socket.recv(&mut buf))
                .await
                .expect("a datagram from the burst was lost")
                .unwrap();
            assert_eq!(size, 1200);
            assert_eq!(buf[0], round);
            seen.push(buf[1]);
        }
        seen.sort();
        assert_eq!(seen, (0..32).collect::<Vec<_>>());
    }
    assert_eq!(engine.stats().dropped_datagrams, 0);
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn throttled_udp_session_drops_datagrams_that_waited_too_long() {
    let echo = udp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(echo.address, Protocol::Udp);
    r.rate_bytes_per_sec = Some(24_000);
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.connect(address).await.unwrap();
    // Seconds of traffic at this rate, sent at once, fit in the queue; the
    // datagrams that would leave late are dropped instead.
    for _ in 0..128 {
        socket.send(&[0; 1200]).await.unwrap();
    }
    let until = Instant::now() + Duration::from_secs(2);
    while engine.stats().dropped_datagrams == 0 {
        assert!(Instant::now() < until, "late datagrams were still sent");
        sleep(Duration::from_millis(10)).await;
    }
    engine.shutdown().await.unwrap();
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
        priority: 0,
        max_sessions: None,
        address: first.address.to_string(),
        weight: 1,
        tls: None,
        proxy_protocol: None,
        websocket: None,
        via: None,
        prewarm: None,
        draining: false,
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn node_rate_limit_is_shared_by_every_rule_and_can_be_cleared() {
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let a = rule(echo.address, Protocol::Tcp);
    let mut b = rule(echo.address, Protocol::Tcp);
    b.id = "rule-two".into();
    let (first, second) = (a.listen, b.listen);
    let mut c = config(a);
    c.rules.push(b);
    c.rate_bytes_per_sec = Some(128 * 1024);
    engine.apply(c.clone()).await.unwrap();
    let payload = vec![7; 96 * 1024];
    let both = || async {
        let started = Instant::now();
        let (x, y) = tokio::join!(exchange(first, &payload), exchange(second, &payload));
        assert_eq!((x.len(), y.len()), (payload.len(), payload.len()));
        started.elapsed()
    };
    let elapsed = both().await;
    // Each rule alone moves 192 KiB, which a per-rule 128 KiB/s bucket would
    // pass in about 0.5 s; one node bucket needs (384 - 128) / 128 = 2 s.
    assert!(
        elapsed >= Duration::from_millis(1850),
        "both rules must share one 128 KiB/s node bucket, observed {elapsed:?}"
    );
    assert!(elapsed < Duration::from_secs(5));
    c.revision = 2;
    c.rate_bytes_per_sec = None;
    engine.apply(c).await.unwrap();
    let elapsed = both().await;
    assert!(
        elapsed < Duration::from_millis(500),
        "cleared node cap still throttles: {elapsed:?}"
    );
    engine.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn capped_bulk_connections_share_the_rate_evenly() {
    use std::sync::atomic::{AtomicU64, Ordering};
    let sink = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = sink.local_addr().unwrap();
    let arrived: Arc<std::sync::Mutex<Vec<Arc<AtomicU64>>>> = Default::default();
    let counters = arrived.clone();
    let sink_task = tokio::spawn(async move {
        while let Ok((mut conn, _)) = sink.accept().await {
            let count = Arc::new(AtomicU64::new(0));
            counters.lock().unwrap().push(count.clone());
            tokio::spawn(async move {
                let mut buf = vec![0; 1 << 16];
                while let Ok(n @ 1..) = conn.read(&mut buf).await {
                    count.fetch_add(n as u64, Ordering::Relaxed);
                }
            });
        }
    });
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let echo = tcp_echo().await;
    let r = rule(target, Protocol::Tcp);
    let mut interactive = rule(echo.address, Protocol::Tcp);
    interactive.id = "interactive".into();
    let (address, interactive_address) = (r.listen, interactive.listen);
    let mut c = config(r);
    c.rules.push(interactive);
    c.rate_bytes_per_sec = Some(8 << 20);
    engine.apply(c).await.unwrap();
    let senders: Vec<_> = (0..8)
        .map(|_| {
            tokio::spawn(async move {
                let mut s = TcpStream::connect(address).await.unwrap();
                let chunk = vec![0; 1 << 16];
                while s.write_all(&chunk).await.is_ok() {}
            })
        })
        .collect();
    // Past the start-up burst, every connection is backlogged behind the cap.
    sleep(Duration::from_secs(1)).await;
    let snapshot = || -> Vec<u64> {
        arrived
            .lock()
            .unwrap()
            .iter()
            .map(|c| c.load(Ordering::Relaxed))
            .collect()
    };
    let before = snapshot();
    // Small sends skip the line: queued behind 8 x 64 KiB each way, this
    // round trip would take over 120 ms.
    let started = Instant::now();
    assert_eq!(exchange(interactive_address, b"ping").await, b"ping");
    let round_trip = started.elapsed();
    assert!(
        round_trip < Duration::from_millis(40),
        "interactive send waited behind bulk: {round_trip:?}"
    );
    sleep(Duration::from_secs(2)).await;
    let shares: Vec<u64> = snapshot().iter().zip(&before).map(|(a, b)| a - b).collect();
    assert_eq!(shares.len(), 8);
    let (min, max) = (*shares.iter().min().unwrap(), *shares.iter().max().unwrap());
    // About 32 turns of 64 KiB per connection in the window; one turn more or
    // less is noise, losing races for whole refills is not.
    assert!(
        min * 10 >= max * 8,
        "uneven shares under one cap: {shares:?}"
    );
    senders.iter().for_each(|s| s.abort());
    sink_task.abort();
    engine.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_node_cap_is_shared_evenly_between_users_not_connections() {
    use std::sync::atomic::{AtomicU64, Ordering};
    // One sink per user counts the bytes that user's connections deliver.
    let sink = || async {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let count = Arc::new(AtomicU64::new(0));
        let total = count.clone();
        let task = tokio::spawn(async move {
            while let Ok((mut conn, _)) = listener.accept().await {
                let total = total.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0; 1 << 16];
                    while let Ok(n @ 1..) = conn.read(&mut buf).await {
                        total.fetch_add(n as u64, Ordering::Relaxed);
                    }
                });
            }
        });
        (address, count, task)
    };
    let (alice_sink, alice_bytes, alice_task) = sink().await;
    let (bob_sink, bob_bytes, bob_task) = sink().await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut alice = rule(alice_sink, Protocol::Tcp);
    alice.owner_id = "alice".into();
    let mut bob = rule(bob_sink, Protocol::Tcp);
    (bob.id, bob.owner_id) = ("bob-rule".into(), "bob".into());
    let (alice_address, bob_address) = (alice.listen, bob.listen);
    let mut c = config(alice);
    c.rules.push(bob);
    c.rate_bytes_per_sec = Some(8 << 20);
    engine.apply(c).await.unwrap();
    let send = |address| {
        tokio::spawn(async move {
            let mut s = TcpStream::connect(address).await.unwrap();
            let chunk = vec![0; 1 << 16];
            while s.write_all(&chunk).await.is_ok() {}
        })
    };
    let mut senders = vec![send(alice_address)];
    senders.extend((0..4).map(|_| send(bob_address)));
    sleep(Duration::from_secs(1)).await;
    let before = (
        alice_bytes.load(Ordering::Relaxed),
        bob_bytes.load(Ordering::Relaxed),
    );
    sleep(Duration::from_secs(2)).await;
    let alice_share = alice_bytes.load(Ordering::Relaxed) - before.0;
    let bob_share = bob_bytes.load(Ordering::Relaxed) - before.1;
    // Taking turns per connection would give Alice a fifth; per user, half.
    assert!(
        alice_share * 10 >= bob_share * 8 && bob_share * 10 >= alice_share * 8,
        "alice {alice_share} vs bob {bob_share}"
    );
    // Two seconds at 8 MiB/s, plus whatever socket buffers absorbed.
    assert!(alice_share + bob_share <= 20 << 20, "cap exceeded");
    senders.iter().for_each(|s| s.abort());
    alice_task.abort();
    bob_task.abort();
    engine.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_user_limit_spans_nodes_and_follows_the_busy_one() {
    use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
    const CAP: u64 = 4 << 20;
    let temp = tempfile::tempdir().unwrap();
    let controller = Store::open(&temp.path().join("controller.db")).unwrap();
    controller.set_kind("controller").unwrap();
    let admin = controller.bootstrap(PASSWORD).unwrap();
    // A tenant administrator cannot lift or set limits, not even their own.
    let tenant_admin = controller
        .create_user(
            &admin,
            "default",
            "tenant-admin",
            PASSWORD,
            relay_platform::store::Role::TenantAdmin,
        )
        .unwrap();
    let denied = controller
        .set_user_rate(&tenant_admin, &tenant_admin.id, None)
        .unwrap_err();
    assert_eq!(
        denied
            .downcast_ref::<relay_platform::store::Rejection>()
            .unwrap()
            .status,
        403
    );
    controller
        .set_user_rate(&admin, &admin.id, Some(CAP))
        .unwrap();
    // Two agents, each with one rule of the same user to its own counting sink.
    let mut nodes = vec![];
    for name in ["a", "b"] {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let sink = listener.local_addr().unwrap();
        let count = Arc::new(AtomicU64::new(0));
        let total = count.clone();
        tokio::spawn(async move {
            while let Ok((mut conn, _)) = listener.accept().await {
                let total = total.clone();
                tokio::spawn(async move {
                    let mut buf = vec![0; 1 << 16];
                    while let Ok(n @ 1..) = conn.read(&mut buf).await {
                        total.fetch_add(n as u64, Ordering::Relaxed);
                    }
                });
            }
        });
        let (node, enrollment) = controller.create_node(&admin, "default", name).unwrap();
        controller.enroll(&node.id, &enrollment, &secret()).unwrap();
        let mut r = rule(sink, Protocol::Tcp);
        (r.id, r.owner_id) = (format!("rule-{name}"), admin.id.clone());
        let listen = r.listen;
        let desired = controller.set_config(&admin, &node.id, 0, vec![r]).unwrap();
        let ledger = controller
            .reconcile(
                &node.id,
                ReconcileRequest {
                    lease: None,
                    ledger_id: None,
                    after: None,
                    expected_revision: None,
                },
            )
            .unwrap()
            .ledger_id;
        let engine = Engine::new(Store::open(&temp.path().join(format!("{name}.db"))).unwrap());
        engine.apply(desired).await.unwrap();
        nodes.push((node.id, ledger, Arc::new(engine), listen, count));
    }
    // A node that never syncs keeps its share reserved until it is paused.
    // Pausing needs a strict lease, which makes the paused agent stop.
    let (gone, _) = controller
        .create_node_with_lease(
            &admin,
            "default",
            "gone",
            Some(relay_platform::lease::LeasePolicy::default()),
        )
        .unwrap();
    let mut r = rule("127.0.0.1:9".parse().unwrap(), Protocol::Tcp);
    (r.id, r.owner_id) = ("rule-gone".into(), admin.id.clone());
    controller.set_config(&admin, &gone.id, 0, vec![r]).unwrap();
    // A later hop of a chain (it declares an advertised address) does not
    // count: the entry already limited that traffic.
    let (hop, enrollment) = controller.create_node(&admin, "default", "hop").unwrap();
    controller.enroll(&hop.id, &enrollment, &secret()).unwrap();
    let mut r = rule("127.0.0.1:9".parse().unwrap(), Protocol::Tcp);
    (r.id, r.owner_id) = ("rule-hop".into(), admin.id.clone());
    r.advertise = Some(r.listen.to_string());
    controller.set_config(&admin, &hop.id, 0, vec![r]).unwrap();
    let ledger = controller
        .reconcile(
            &hop.id,
            ReconcileRequest {
                lease: None,
                ledger_id: None,
                after: None,
                expected_revision: None,
            },
        )
        .unwrap()
        .ledger_id;
    let reply = controller
        .sync(
            &hop.id,
            SyncRequest {
                lease: None,
                budget: None,
                ledger_id: ledger,
                need_config: false,
                applied_revision: 1,
                apply_error: None,
                usage: vec![],
                stats: EngineStats::default(),
            },
        )
        .unwrap();
    assert_eq!(reply.user_rates, Some(vec![]));
    let view = controller.user_rate(&admin, &admin.id).unwrap();
    assert_eq!(view.nodes.len(), 3);
    assert!(view.nodes.iter().all(|n| n.seen_ms_ago.is_none()));
    controller
        .update_node(
            &admin,
            &gone.id,
            relay_platform::node::NodeUpdate {
                expected_revision: gone.profile.revision,
                name: "gone".into(),
                settings: relay_platform::node::NodeSettings {
                    enabled: false,
                    ..Default::default()
                },
            },
        )
        .unwrap();
    // Each agent syncs every 250 ms, as the agent loop does, and applies its share.
    let syncing = Arc::new(AtomicBool::new(true));
    let sync_task = {
        let syncing = syncing.clone();
        let agents: Vec<_> = nodes
            .iter()
            .map(|(id, ledger, engine, ..)| (id.clone(), ledger.clone(), engine.clone()))
            .collect();
        let controller = controller.clone();
        tokio::spawn(async move {
            while syncing.load(Ordering::Relaxed) {
                for (id, ledger, engine) in &agents {
                    let sent = Instant::now();
                    let reply = controller
                        .sync(
                            id,
                            SyncRequest {
                                lease: None,
                                budget: None,
                                ledger_id: ledger.clone(),
                                need_config: false,
                                applied_revision: 1,
                                apply_error: None,
                                usage: vec![],
                                stats: engine.stats(),
                            },
                        )
                        .unwrap();
                    engine.set_user_shares(&reply.user_rates.unwrap(), sent);
                }
                sleep(Duration::from_millis(250)).await;
            }
        })
    };
    let send = |address| {
        tokio::spawn(async move {
            let mut s = TcpStream::connect(address).await.unwrap();
            let chunk = vec![0; 1 << 16];
            while s.write_all(&chunk).await.is_ok() {}
        })
    };
    let delivered = || {
        (
            nodes[0].4.load(Ordering::Relaxed),
            nodes[1].4.load(Ordering::Relaxed),
        )
    };
    let measure = |seconds| async move {
        let before = delivered();
        sleep(Duration::from_secs(seconds)).await;
        let after = delivered();
        (after.0 - before.0, after.1 - before.1)
    };
    // Only "a" is busy: it gets most of the user's limit, not an even half.
    let mut senders = vec![send(nodes[0].3)];
    sleep(Duration::from_secs(2)).await;
    let (a, b) = measure(2).await;
    assert_eq!(b, 0);
    assert!(a >= CAP * 2 * 7 / 10, "busy node got {a} of {}", CAP * 2);
    // Two seconds at the cap, plus what one token bucket and socket buffers hold.
    assert!(a <= CAP * 2 + (3 << 20), "cap exceeded: {a}");
    // Both busy: together they stay within the limit and split it.
    senders.push(send(nodes[1].3));
    sleep(Duration::from_secs(2)).await;
    let (a, b) = measure(2).await;
    assert!(a + b <= CAP * 2 + (3 << 20), "cap exceeded: {a} + {b}");
    assert!(a + b >= CAP * 2 * 7 / 10, "limit underused: {a} + {b}");
    assert!(a.min(b) * 10 >= (a + b) * 3, "uneven split: {a} vs {b}");
    let view = controller.user_rate(&admin, &admin.id).unwrap();
    let seen: Vec<_> = view.nodes.iter().map(|n| n.node_id.as_str()).collect();
    assert_eq!(seen.len(), 2, "{seen:?}");
    assert!(!seen.contains(&gone.id.as_str()));
    // Removing the limit lifts it on both nodes at their next sync.
    controller.set_user_rate(&admin, &admin.id, None).unwrap();
    sleep(Duration::from_secs(1)).await;
    let (a, b) = measure(1).await;
    assert!(a + b > CAP * 4, "limit still applied: {a} + {b}");
    syncing.store(false, Ordering::Relaxed);
    sync_task.await.unwrap();
    senders.iter().for_each(|s| s.abort());
    for (_, _, engine, _, _) in &nodes {
        engine.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn a_user_share_drops_to_its_fallback_when_the_lease_runs_out() {
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let share = UserShare {
        tenant_id: "default".into(),
        owner_id: "admin".into(),
        rate_bytes_per_sec: 1 << 20,
        fallback_bytes_per_sec: 64 << 10,
    };
    let enforced = |engine: &Engine| {
        let stats = engine.stats();
        assert_eq!(stats.user_rates.len(), 1);
        stats.user_rates[0].enforced_bytes_per_sec
    };
    engine.set_user_shares(std::slice::from_ref(&share), Instant::now());
    assert!(engine.expire_user_shares());
    assert_eq!(enforced(&engine), Some(1 << 20));
    // The lease counts from when the request left, not when the reply came.
    let sent = Instant::now()
        .checked_sub(relay_platform::user_rate::LEASE + Duration::from_millis(1))
        .unwrap();
    engine.set_user_shares(std::slice::from_ref(&share), sent);
    engine.expire_user_shares();
    assert_eq!(enforced(&engine), Some(64 << 10));
    // A restarted agent starts from the fallback until the controller answers.
    let restarted = Engine::new(Store::open(&temp.path().join("other.db")).unwrap());
    restarted.restore_user_shares(std::slice::from_ref(&share));
    assert_eq!(enforced(&restarted), Some(64 << 10));
    // A controller reply without the user lifts the limit.
    engine.set_user_shares(&[], Instant::now());
    assert!(!engine.expire_user_shares());
    assert!(engine.stats().user_rates.is_empty());
    // A rule with an advertised address is a later hop and is not limited.
    let echo = tcp_echo().await;
    let mut hop = rule(echo.address, Protocol::Tcp);
    hop.advertise = Some(hop.listen.to_string());
    let address = hop.listen;
    engine.apply(config(hop)).await.unwrap();
    let tight = UserShare {
        rate_bytes_per_sec: 64 << 10,
        ..share
    };
    engine.set_user_shares(&[tight], Instant::now());
    let started = Instant::now();
    let payload = vec![3; 256 << 10];
    assert_eq!(exchange(address, &payload).await, payload);
    // 512 KiB at the 64 KiB/s fallback, if it applied, would take 7 s.
    assert!(started.elapsed() < Duration::from_secs(2));
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn udp_moves_to_the_next_target_when_the_system_reports_a_closed_port() {
    let primary = udp_echo().await;
    let backup = udp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    // No health checks: only the refused send or receive can move traffic.
    let mut r = rule(primary.address, Protocol::Udp);
    let mut second = r.targets[0].clone();
    second.address = backup.address.to_string();
    second.priority = 1;
    r.targets.push(second);
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    assert_eq!(udp_exchange(address, b"first").await, b"first");
    drop(primary);
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut buf = [0; 64];
    let started = Instant::now();
    let reply = timeout(Duration::from_secs(3), async {
        loop {
            client.send_to(b"again", address).await.unwrap();
            if let Ok(Ok((n, _))) =
                timeout(Duration::from_millis(50), client.recv_from(&mut buf)).await
            {
                return buf[..n].to_vec();
            }
        }
    })
    .await
    .expect("traffic never reached the backup after the primary port closed");
    assert_eq!(reply, b"again");
    assert!(started.elapsed() < Duration::from_secs(1));
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
async fn draining_target_keeps_its_sessions_and_takes_new_ones_only_as_a_last_resort() {
    let a = tcp_echo_at("127.0.0.1:0", Some(b'A')).await;
    let b = tcp_echo_at("127.0.0.1:0", Some(b'B')).await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(a.address, Protocol::Tcp);
    let mut backup = r.targets[0].clone();
    backup.address = b.address.to_string();
    backup.priority = 1;
    r.targets.push(backup);
    let address = r.listen;
    let mut c = config(r);
    engine.apply(c.clone()).await.unwrap();
    async fn marker(s: &mut TcpStream) -> u8 {
        let mut m = [0];
        timeout(Duration::from_secs(1), s.read_exact(&mut m))
            .await
            .unwrap()
            .unwrap();
        m[0]
    }
    let mut held = TcpStream::connect(address).await.unwrap();
    assert_eq!(marker(&mut held).await, b'A');
    c.revision = 2;
    c.rules[0].targets[0].draining = true;
    engine.apply(c.clone()).await.unwrap();
    // A draining primary goes behind even a lower-priority backup.
    for _ in 0..3 {
        let mut s = TcpStream::connect(address).await.unwrap();
        assert_eq!(marker(&mut s).await, b'B');
    }
    held.write_all(b"still").await.unwrap();
    let mut echoed = [0; 5];
    timeout(Duration::from_secs(1), held.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echoed, b"still", "draining must not end existing sessions");
    c.revision = 3;
    c.rules[0].targets[1].draining = true;
    engine.apply(c).await.unwrap();
    // With every target draining, priority decides again instead of refusing.
    let mut s = TcpStream::connect(address).await.unwrap();
    assert_eq!(marker(&mut s).await, b'A');
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
            priority: 0,
            max_sessions: None,
            address: a.address.to_string(),
            weight: 2,
            tls: None,
            proxy_protocol: None,
            websocket: None,
            via: None,
            prewarm: None,
            draining: false,
        },
        Target {
            priority: 0,
            max_sessions: None,
            address: b.address.to_string(),
            weight: 1,
            tls: None,
            proxy_protocol: None,
            websocket: None,
            via: None,
            prewarm: None,
            draining: false,
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
            priority: 0,
            max_sessions: None,
            address: free_address().to_string(),
            weight: 1,
            tls: None,
            proxy_protocol: None,
            websocket: None,
            via: None,
            prewarm: None,
            draining: false,
        },
        Target {
            priority: 0,
            max_sessions: None,
            address: b.address.to_string(),
            weight: 1,
            tls: None,
            proxy_protocol: None,
            websocket: None,
            via: None,
            prewarm: None,
            draining: false,
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
    fault.execute_batch("CREATE TRIGGER fail_meter BEFORE INSERT ON metadata WHEN NEW.key GLOB 'meter_reservation:*' BEGIN SELECT RAISE(ABORT,'injected transaction failure'); END;").unwrap();
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
async fn abrupt_stop_counts_forwarded_bytes_from_the_durable_reservation() {
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let r = rule(echo.address, Protocol::Tcp);
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    assert_eq!(
        exchange(address, b"reserved-bytes").await,
        b"reserved-bytes"
    );
    // Snapshot the disk as a power cut would leave it, before any usage flush.
    let crashed = temp.path().join("crashed.db");
    rusqlite::Connection::open(temp.path().join("agent.db"))
        .unwrap()
        .execute("VACUUM INTO ?1", [crashed.to_str().unwrap()])
        .unwrap();
    std::fs::set_permissions(
        &crashed,
        std::os::unix::fs::PermissionsExt::from_mode(0o600),
    )
    .unwrap();
    engine.shutdown().await.unwrap();
    let restarted = Store::open(&crashed).unwrap();
    restarted.settle_meter_reservations().unwrap();
    let usage = restarted.agent_usage(false).unwrap();
    assert!(usage[0].upload_bytes + usage[0].download_bytes >= 28);
    assert_eq!(restarted.settle_meter_reservations().unwrap(), 0);
}

#[tokio::test]
async fn dual_protocol_listener_and_ipv6_udp_are_independently_verified() {
    let (tcp, _udp) = tcp_udp_echo_at("[::1]:0").await;
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
async fn stalled_primary_falls_back_within_one_connect_and_is_tried_last_afterwards() {
    // A listener whose accept queue is full silently drops new SYNs, so a
    // connect to it hangs instead of being refused.
    let stalled = tokio::net::TcpSocket::new_v4().unwrap();
    stalled.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let stalled = stalled.listen(1).unwrap();
    let stalled_address = stalled.local_addr().unwrap();
    let mut queued = vec![];
    while let Ok(Ok(stream)) = timeout(
        Duration::from_millis(200),
        TcpStream::connect(stalled_address),
    )
    .await
    {
        queued.push(stream);
    }
    let backup = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(stalled_address, Protocol::Tcp);
    r.connect_timeout_ms = 5000;
    r.targets.push(Target {
        priority: 1,
        max_sessions: None,
        address: backup.address.to_string(),
        weight: 1,
        tls: None,
        proxy_protocol: None,
        websocket: None,
        via: None,
        prewarm: None,
        draining: false,
    });
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    // The backup is dialed after the 1 s hedge delay, not after half of the
    // 5 s connect timeout.
    let started = Instant::now();
    assert_eq!(exchange(address, b"first").await, b"first");
    assert!(started.elapsed() < Duration::from_millis(1600));
    let started = Instant::now();
    assert_eq!(exchange(address, b"second").await, b"second");
    assert!(started.elapsed() < Duration::from_millis(500));
    engine.shutdown().await.unwrap();
    drop((queued, stalled));
}

#[tokio::test]
async fn source_hash_is_stable_and_least_connections_uses_active_sessions() {
    let a = tcp_echo_at("127.0.0.1:0", Some(b'A')).await;
    let b = tcp_echo_at("127.0.0.1:0", Some(b'B')).await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(a.address, Protocol::Tcp);
    r.targets.push(Target {
        priority: 0,
        max_sessions: None,
        address: b.address.to_string(),
        weight: 1,
        tls: None,
        proxy_protocol: None,
        websocket: None,
        via: None,
        prewarm: None,
        draining: false,
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

async fn udp_exchange(address: std::net::SocketAddr, payload: &[u8]) -> Vec<u8> {
    let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    socket.send_to(payload, address).await.unwrap();
    let mut buf = [0; 2048];
    let (n, _) = timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
        .await
        .expect("UDP exchange timed out")
        .unwrap();
    buf[..n].to_vec()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn listen_address_moves_between_one_address_and_all_addresses_on_the_same_port() {
    let (echo, _udp_echo) = tcp_udp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let mut c = config(rule(echo.address, Protocol::Both));
    let port = c.rules[0].listen.port();
    let one = format!("127.0.0.1:{port}").parse().unwrap();
    // Linux routes all of 127.0.0.0/8 locally, so only a wildcard listener answers here.
    let other = format!("127.0.0.2:{port}").parse().unwrap();
    let all = format!("0.0.0.0:{port}").parse().unwrap();
    c.rules[0].listen = one;
    engine.apply(c.clone()).await.unwrap();
    assert!(TcpStream::connect(other).await.is_err());

    c.revision = 2;
    c.rules[0].listen = all;
    engine.apply(c.clone()).await.unwrap();
    assert_eq!(exchange(other, b"wildcard").await, b"wildcard");
    assert_eq!(udp_exchange(other, b"datagram").await, b"datagram");

    c.revision = 3;
    c.rules[0].listen = one;
    engine.apply(c.clone()).await.unwrap();
    assert!(TcpStream::connect(other).await.is_err());
    assert_eq!(exchange(one, b"specific").await, b"specific");

    // The wildcard cannot be bound while another program holds 127.0.0.2 on
    // this port: both old listeners return and the revision stays.
    let occupied = std::net::TcpListener::bind(other).unwrap();
    c.revision = 4;
    c.rules[0].listen = all;
    assert!(engine.apply(c.clone()).await.is_err());
    assert_eq!(engine.revision().await, 3);
    assert_eq!(db.agent_config().unwrap().unwrap().revision, 3);
    assert_eq!(exchange(one, b"restored").await, b"restored");
    assert_eq!(udp_exchange(one, b"restored-udp").await, b"restored-udp");
    drop(occupied);
    engine.apply(c).await.unwrap();
    assert_eq!(exchange(other, b"after-retry").await, b"after-retry");
    engine.shutdown().await.unwrap();
}
