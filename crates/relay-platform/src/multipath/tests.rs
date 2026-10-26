use super::*;
use crate::transport::BoxStream;
use std::{sync::Arc, time::Duration};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::task::TaskTracker;

fn limits() -> Limits {
    Limits {
        window_frames: 8,
        max_sessions: 2,
        retransmit_ms: 50,
        stall_timeout_ms: 1500,
    }
}
fn path(stream: impl crate::transport::Stream + 'static, slot: usize) -> Path {
    Path {
        stream: Box::new(stream),
        slot,
        send_weight: 1,
        receive_weight: 1,
    }
}
async fn exchange(mut client: BoxStream, mut server: BoxStream, bytes: Vec<u8>) {
    let echo = tokio::spawn(async move {
        let (mut read, mut write) = tokio::io::split(&mut server);
        tokio::io::copy(&mut read, &mut write).await.unwrap();
        write.shutdown().await.unwrap();
    });
    let (mut read, mut write) = tokio::io::split(&mut client);
    let send = async {
        write.write_all(&bytes).await.unwrap();
        write.shutdown().await.unwrap();
    };
    let receive = async {
        let mut data = vec![];
        read.read_to_end(&mut data).await.unwrap();
        assert_eq!(data, bytes);
    };
    tokio::join!(send, receive);
    echo.await.unwrap();
}
async fn drain(tasks: TaskTracker, stats: &[Arc<Counters>]) {
    tasks.close();
    tokio::time::timeout(Duration::from_secs(2), tasks.wait())
        .await
        .unwrap();
    for counters in stats {
        assert_eq!(counters.snapshot().active_paths, 0);
        assert_eq!(counters.snapshot().active_sessions, 0);
    }
}
#[tokio::test]
async fn stripes_and_replicates_one_stream_with_bounded_windows_and_half_close() {
    for mode in [Mode::Stripe, Mode::Replicate] {
        let tasks = TaskTracker::new();
        let a = Arc::new(Counters::default());
        let b = Arc::new(Counters::default());
        let mut client = vec![];
        let mut server = vec![];
        for slot in 0..2 {
            let (c, s) = tokio::io::duplex(32 * 1024);
            client.push(path(c, slot));
            server.push(path(s, slot));
        }
        let client = bridge(
            client,
            limits(),
            mode,
            a.clone(),
            tasks.clone(),
            Box::new(()),
        );
        let server = bridge(
            server,
            limits(),
            mode,
            b.clone(),
            tasks.clone(),
            Box::new(()),
        );
        let payload: Vec<_> = (0..2 * 1024 * 1024 + 17).map(|i| (i % 251) as u8).collect();
        let n = payload.len() as u64;
        tokio::time::timeout(Duration::from_secs(12), exchange(client, server, payload))
            .await
            .unwrap();
        drain(tasks, &[a.clone(), b.clone()]).await;
        for counters in [a, b] {
            let stats = counters.snapshot();
            assert_eq!(stats.delivered_payload_bytes, n);
            assert!(stats.path_sent_payload_bytes[0] > 0 && stats.path_sent_payload_bytes[1] > 0);
            assert!(stats.peak_reorder_bytes <= 8 * CHUNK_BYTES as u64);
            assert!(stats.peak_send_window_bytes <= 8 * CHUNK_BYTES as u64);
            if mode == Mode::Replicate {
                assert_eq!(stats.replicated_payload_bytes, n);
                assert!(stats.duplicate_payload_bytes > 0);
            }
        }
    }
}
#[tokio::test]
async fn lost_path_replays_unacknowledged_chunks_without_corrupting_one_connection() {
    let tasks = TaskTracker::new();
    let a = Arc::new(Counters::default());
    let b = Arc::new(Counters::default());
    let (c0, mut broken_c) = tokio::io::duplex(32 * 1024);
    let (s0, broken_s) = tokio::io::duplex(32 * 1024);
    let (c1, s1) = tokio::io::duplex(32 * 1024);
    let failure = tokio::spawn(async move {
        let mut byte = [0];
        broken_c.read_exact(&mut byte).await.unwrap();
        tokio::time::sleep(Duration::from_millis(40)).await;
        drop((broken_c, broken_s));
    });
    let client = bridge(
        vec![path(c0, 0), path(c1, 1)],
        limits(),
        Mode::Stripe,
        a.clone(),
        tasks.clone(),
        Box::new(()),
    );
    let server = bridge(
        vec![path(s0, 0), path(s1, 1)],
        limits(),
        Mode::Stripe,
        b.clone(),
        tasks.clone(),
        Box::new(()),
    );
    let payload: Vec<_> = (0..1024 * 1024 + 19).map(|i| (i % 239) as u8).collect();
    tokio::time::timeout(Duration::from_secs(10), exchange(client, server, payload))
        .await
        .unwrap();
    failure.await.unwrap();
    drain(tasks, &[a.clone(), b.clone()]).await;
    assert_eq!(a.snapshot().failed_paths, 1);
    assert_eq!(b.snapshot().failed_paths, 1);
    assert!(a.snapshot().retransmitted_payload_bytes > 0);
    assert!(b.snapshot().peak_reorder_bytes > 0);
}

#[tokio::test]
async fn a_live_but_blocked_preferred_path_cannot_starve_the_other_path() {
    let tasks = TaskTracker::new();
    let a = Arc::new(Counters::default());
    let b = Arc::new(Counters::default());
    let (client_blocked, client_sink) = tokio::io::duplex(1024);
    let (server_blocked, server_sink) = tokio::io::duplex(1024);
    let (client_good, server_good) = tokio::io::duplex(32768);
    let mut preferred_up = path(client_blocked, 0);
    preferred_up.send_weight = 10;
    let mut preferred_down = path(server_blocked, 0);
    preferred_down.send_weight = 10;
    let mut client = bridge(
        vec![preferred_up, path(client_good, 1)],
        limits(),
        Mode::Stripe,
        a.clone(),
        tasks.clone(),
        Box::new(()),
    );
    let mut server = bridge(
        vec![preferred_down, path(server_good, 1)],
        limits(),
        Mode::Stripe,
        b.clone(),
        tasks.clone(),
        Box::new(()),
    );
    let echo = tokio::spawn(async move {
        let (mut read, mut write) = tokio::io::split(&mut server);
        tokio::io::copy(&mut read, &mut write).await.unwrap();
        write.shutdown().await.unwrap();
    });
    let payload = vec![23; 128 * 1024];
    let (mut read, mut write) = tokio::io::split(&mut client);
    // Payload must use the surviving lane before the blocked writer's 1500 ms timeout.
    tokio::time::timeout(Duration::from_secs(1), async {
        let send = write.write_all(&payload);
        let receive = async {
            let mut output = vec![0; payload.len()];
            read.read_exact(&mut output).await.unwrap();
            assert_eq!(output, payload);
        };
        let (sent, ()) = tokio::join!(send, receive);
        sent.unwrap();
    })
    .await
    .unwrap();
    tokio::time::timeout(Duration::from_secs(3), async {
        let finish = write.shutdown();
        let receive = async {
            let mut rest = vec![];
            read.read_to_end(&mut rest).await.unwrap();
            assert!(rest.is_empty());
        };
        let (finished, ()) = tokio::join!(finish, receive);
        finished.unwrap();
    })
    .await
    .unwrap();
    drop(client);
    echo.await.unwrap();
    drop((client_sink, server_sink));
    drain(tasks, &[a.clone(), b.clone()]).await;
    assert!(
        a.snapshot().retransmitted_payload_bytes > 0
            && b.snapshot().retransmitted_payload_bytes > 0
    );
}
#[tokio::test]
async fn invalid_or_out_of_window_frames_fail_instead_of_allocating_or_returning_clean_eof() {
    for bad in [0, 1, 2, 3] {
        let tasks = TaskTracker::new();
        let stats = Arc::new(Counters::default());
        let (client, mut peer) = tokio::io::duplex(4096);
        let mut stream = bridge(
            vec![path(client, 0)],
            limits(),
            Mode::Stripe,
            stats.clone(),
            tasks.clone(),
            Box::new(()),
        );
        let mut header = [0; 16];
        header[0] = 1;
        let (seq, length): (u64, u32) = match bad {
            0 => (8, 1),                      // beyond bounded sequence window
            1 => (0, CHUNK_BYTES as u32 + 1), // reject before allocation/read
            2 => {
                header[0] = 3;
                (1, 0)
            } // ACK for nonexistent data
            _ => {
                header[1] = 1;
                (0, 1)
            }
        };
        header[4..12].copy_from_slice(&seq.to_be_bytes());
        header[12..].copy_from_slice(&length.to_be_bytes());
        peer.write_all(&header).await.unwrap();
        if bad == 0 {
            peer.write_all(b"x").await.unwrap();
        }
        let mut result = vec![];
        assert!(
            tokio::time::timeout(Duration::from_secs(2), stream.read_to_end(&mut result))
                .await
                .unwrap()
                .is_err()
        );
        assert!(result.is_empty());
        assert_eq!(stats.snapshot().peak_reorder_bytes, 0);
        drop((stream, peer));
        drain(tasks, &[stats]).await;
    }
}
#[tokio::test]
async fn stopped_reader_bounds_payload_and_all_path_loss_is_an_error() {
    let tasks = TaskTracker::new();
    let stats = Arc::new(Counters::default());
    let (c, peer) = tokio::io::duplex(1024);
    let mut stream = bridge(
        vec![path(c, 0)],
        limits(),
        Mode::Stripe,
        stats.clone(),
        tasks.clone(),
        Box::new(()),
    );
    let result = tokio::time::timeout(
        Duration::from_secs(3),
        stream.write_all(&vec![7; 4 * 1024 * 1024]),
    )
    .await
    .unwrap();
    assert!(result.is_err());
    assert!(stats.snapshot().peak_send_window_bytes <= 8 * CHUNK_BYTES as u64);
    drop((stream, peer));
    drain(tasks, &[stats]).await;
}

#[tokio::test]
async fn selective_receipts_retransmit_only_the_gap_and_reject_out_of_window_bits() {
    for invalid in [false, true] {
        let tasks = TaskTracker::new();
        let stats = Arc::new(Counters::default());
        let (client, mut peer) = tokio::io::duplex(256 * 1024);
        let mut spec = limits();
        spec.window_frames = 4;
        spec.retransmit_ms = 100;
        let mut app = bridge(
            vec![path(client, 0)],
            spec,
            Mode::Stripe,
            stats.clone(),
            tasks.clone(),
            Box::new(()),
        );
        app.write_all(&vec![17; 4 * CHUNK_BYTES]).await.unwrap();
        for seq in 0..4 {
            let frame = wire::Frame::read(&mut peer).await.unwrap();
            assert_eq!(frame.sequence(), seq);
            assert_eq!(frame.payload().len(), CHUNK_BYTES);
        }
        let mut mask = [0; 32];
        mask[0] = if invalid { 0b1_0000 } else { 0b1110 };
        wire::write(
            &mut peer,
            &wire::Frame::Ack(0, mask),
            wire::CopyKind::Primary,
            0,
            &Counters::default(),
        )
        .await
        .unwrap();
        if invalid {
            let mut byte = [0];
            assert!(
                tokio::time::timeout(Duration::from_secs(1), app.read(&mut byte))
                    .await
                    .unwrap()
                    .is_err()
            );
        } else {
            for _ in 0..3 {
                let retransmission =
                    tokio::time::timeout(Duration::from_millis(500), wire::Frame::read(&mut peer))
                        .await
                        .unwrap()
                        .unwrap();
                assert_eq!(retransmission.sequence(), 0);
                assert_eq!(retransmission.payload().len(), CHUNK_BYTES);
            }
            assert!(stats.snapshot().peak_send_window_bytes <= 4 * CHUNK_BYTES as u64);
        }
        drop((app, peer));
        drain(tasks, &[stats]).await;
    }
}

#[tokio::test]
async fn selective_receipts_do_not_release_the_bounded_window_before_cumulative_delivery() {
    let tasks = TaskTracker::new();
    let stats = Arc::new(Counters::default());
    let (client, mut peer) = tokio::io::duplex(256 * 1024);
    let mut spec = limits();
    spec.window_frames = 4;
    spec.retransmit_ms = 100;
    let mut app = bridge(
        vec![path(client, 0)],
        spec,
        Mode::Stripe,
        stats.clone(),
        tasks.clone(),
        Box::new(()),
    );
    app.write_all(&vec![9; 4 * CHUNK_BYTES]).await.unwrap();
    for seq in 0..4 {
        assert_eq!(wire::Frame::read(&mut peer).await.unwrap().sequence(), seq);
    }
    let mut mask = [0; 32];
    mask[0] = 0b1111;
    wire::write(
        &mut peer,
        &wire::Frame::Ack(0, mask),
        wire::CopyKind::Primary,
        0,
        &Counters::default(),
    )
    .await
    .unwrap();
    app.write_all(&vec![8; 4 * CHUNK_BYTES]).await.unwrap(); // bounded application bridge only
    assert!(
        tokio::time::timeout(Duration::from_millis(250), wire::Frame::read(&mut peer))
            .await
            .is_err()
    );
    assert_eq!(stats.snapshot().sent_payload_bytes, 4 * CHUNK_BYTES as u64);
    wire::write(
        &mut peer,
        &wire::Frame::Ack(4, [0; 32]),
        wire::CopyKind::Primary,
        0,
        &Counters::default(),
    )
    .await
    .unwrap();
    for seq in 4..8 {
        let frame = tokio::time::timeout(Duration::from_secs(1), wire::Frame::read(&mut peer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(frame.sequence(), seq);
        assert!(frame.payload().iter().all(|&byte| byte == 8));
    }
    drop((app, peer));
    drain(tasks, &[stats]).await;
}

/// A stream pair whose bytes arrive `delay` after they were written, in order,
/// and not before `closed_until` for that direction (first to second, then
/// back). Writes never block, like large socket buffers.
fn delayed_pair(
    delay: Duration,
    closed_until: [tokio::time::Instant; 2],
) -> (tokio::io::DuplexStream, tokio::io::DuplexStream) {
    let (a, a_inner) = tokio::io::duplex(1 << 20);
    let (b_inner, b) = tokio::io::duplex(1 << 20);
    let (a_read, a_write) = tokio::io::split(a_inner);
    let (b_read, b_write) = tokio::io::split(b_inner);
    for ((mut from, mut to), closed_until) in [(a_read, b_write), (b_read, a_write)]
        .into_iter()
        .zip(closed_until)
    {
        let (queue, mut due) = tokio::sync::mpsc::unbounded_channel();
        tokio::spawn(async move {
            let mut buffer = vec![0; 65536];
            while let Ok(n @ 1..) = from.read(&mut buffer).await {
                let _ = queue.send((tokio::time::Instant::now() + delay, buffer[..n].to_vec()));
            }
        });
        tokio::spawn(async move {
            while let Some((at, bytes)) = due.recv().await {
                tokio::time::sleep_until(at.max(closed_until)).await;
                if to.write_all(&bytes).await.is_err() {
                    return;
                }
            }
            let _ = to.shutdown().await;
        });
    }
    (a, b)
}
#[tokio::test]
async fn a_round_trip_longer_than_the_retransmit_interval_is_not_copied_onto_other_paths() {
    let tasks = TaskTracker::new();
    let a = Arc::new(Counters::default());
    let b = Arc::new(Counters::default());
    let spec = Limits {
        window_frames: 32,
        ..limits()
    };
    let mut client = vec![];
    let mut server = vec![];
    for slot in 0..2 {
        let (c, s) = delayed_pair(Duration::from_millis(100), [tokio::time::Instant::now(); 2]);
        client.push(path(c, slot));
        server.push(path(s, slot));
    }
    let client = bridge(
        client,
        spec.clone(),
        Mode::Stripe,
        a.clone(),
        tasks.clone(),
        Box::new(()),
    );
    let server = bridge(
        server,
        spec,
        Mode::Stripe,
        b.clone(),
        tasks.clone(),
        Box::new(()),
    );
    let payload: Vec<_> = (0..4 * 1024 * 1024).map(|i| (i % 241) as u8).collect();
    let n = payload.len() as u64;
    tokio::time::timeout(Duration::from_secs(20), exchange(client, server, payload))
        .await
        .unwrap();
    drain(tasks, &[a.clone(), b.clone()]).await;
    for counters in [a, b] {
        let stats = counters.snapshot();
        assert_eq!(stats.delivered_payload_bytes, n);
        // Only the first window goes out before a round trip is measured.
        assert!(
            stats.retransmitted_payload_bytes <= n / 4,
            "{} of {n} bytes retransmitted on a path that lost nothing",
            stats.retransmitted_payload_bytes
        );
    }
}
#[tokio::test]
async fn a_path_that_stops_delivering_one_way_gets_fewer_new_frames_until_it_recovers() {
    let tasks = TaskTracker::new();
    let a = Arc::new(Counters::default());
    let b = Arc::new(Counters::default());
    let spec = Limits {
        window_frames: 32,
        stall_timeout_ms: 30_000,
        ..limits()
    };
    let now = tokio::time::Instant::now();
    let opens = now + Duration::from_millis(1000);
    // Only the client's frames stop; the server's still arrive on it.
    let (silent_client, silent_server) = delayed_pair(Duration::ZERO, [opens, now]);
    let (good_client, good_server) = delayed_pair(Duration::from_millis(50), [now; 2]);
    let client = bridge(
        vec![path(silent_client, 0), path(good_client, 1)],
        spec.clone(),
        Mode::Stripe,
        a.clone(),
        tasks.clone(),
        Box::new(()),
    );
    let server = bridge(
        vec![path(silent_server, 0), path(good_server, 1)],
        spec,
        Mode::Stripe,
        b.clone(),
        tasks.clone(),
        Box::new(()),
    );
    let silent_sent = tokio::spawn({
        let a = a.clone();
        async move {
            tokio::time::sleep_until(opens - Duration::from_millis(50)).await;
            a.snapshot().path_sent_payload_bytes[0]
        }
    });
    let payload: Vec<_> = (0..12 * 1024 * 1024).map(|i| (i % 239) as u8).collect();
    let n = payload.len() as u64;
    tokio::time::timeout(Duration::from_secs(20), exchange(client, server, payload))
        .await
        .unwrap();
    let silent_sent = silent_sent.await.unwrap();
    drain(tasks, &[a.clone(), b.clone()]).await;
    for counters in [&a, &b] {
        let stats = counters.snapshot();
        assert_eq!(stats.delivered_payload_bytes, n);
        // Without suspicion the silent path keeps taking new frames, and
        // without its own timeout the slower path's frames are copied too:
        // either way about 40% is resent.
        assert!(
            stats.retransmitted_payload_bytes <= n / 6,
            "{} of {n} bytes resent",
            stats.retransmitted_payload_bytes
        );
    }
    // Once a retry is acknowledged, it carries new frames again.
    let recovered = a.snapshot().path_sent_payload_bytes[0] - silent_sent;
    assert!(
        recovered >= n / 16,
        "{recovered} bytes sent on the recovered path"
    );
}
