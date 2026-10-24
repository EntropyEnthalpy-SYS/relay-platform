mod common;
#[path = "common/tls.rs"]
mod tls;
use base64::{Engine as _, engine::general_purpose::STANDARD};
use common::*;
use relay_platform::{engine::Engine, model::*, store::Store, websocket};
use std::time::Duration;
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};

fn server_spec() -> WebSocketServer {
    WebSocketServer {
        path: "/relay?version=1".into(),
        host: Some("relay.test:8080".into()),
        allowed_origins: vec!["https://console.example".into()],
    }
}
fn client_spec() -> WebSocketClient {
    WebSocketClient {
        path: "/relay?version=1".into(),
        host: "relay.test:8080".into(),
        origin: Some("https://console.example".into()),
    }
}
fn request() -> String {
    "GET /relay?version=1 HTTP/1.1\r\nHost: relay.test:8080\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\nSec-WebSocket-Protocol: relay-stream-v1\r\nOrigin: https://console.example\r\n\r\n".into()
}
async fn header<S: AsyncRead + Unpin>(stream: &mut S) -> String {
    timeout(Duration::from_secs(3), async {
        let mut result = Vec::new();
        while !result.ends_with(b"\r\n\r\n") {
            result.push(stream.read_u8().await.unwrap());
            assert!(result.len() <= 16384);
        }
        String::from_utf8(result).unwrap()
    })
    .await
    .unwrap()
}
fn response(request: &str) -> String {
    let key = request
        .lines()
        .find_map(|line| {
            line.split_once(':')
                .filter(|(key, _)| key.eq_ignore_ascii_case("Sec-WebSocket-Key"))
                .map(|(_, value)| value.trim())
        })
        .unwrap();
    // Independent handshake digest uses ring rather than Tungstenite's encoder.
    let digest = ring::digest::digest(
        &ring::digest::SHA1_FOR_LEGACY_USE_ONLY,
        format!("{key}258EAFA5-E914-47DA-95CA-C5AB0DC85B11").as_bytes(),
    );
    format!(
        "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: {}\r\nSec-WebSocket-Protocol: relay-stream-v1\r\n\r\n",
        STANDARD.encode(digest)
    )
}
fn frame(opcode: u8, fin: bool, masked: bool, data: &[u8]) -> Vec<u8> {
    let mut result = vec![opcode | if fin { 128 } else { 0 }];
    let flag = if masked { 128 } else { 0 };
    if data.len() < 126 {
        result.push(flag | data.len() as u8);
    } else if data.len() <= 65535 {
        result.push(flag | 126);
        result.extend_from_slice(&(data.len() as u16).to_be_bytes());
    } else {
        result.push(flag | 127);
        result.extend_from_slice(&(data.len() as u64).to_be_bytes());
    }
    let mask = [0x11, 0x22, 0x33, 0x44];
    if masked {
        result.extend_from_slice(&mask);
    }
    result.extend(
        data.iter()
            .enumerate()
            .map(|(i, b)| if masked { b ^ mask[i % 4] } else { *b }),
    );
    result
}
async fn read_frame<S: AsyncRead + Unpin>(stream: &mut S, masked: bool) -> (u8, Vec<u8>) {
    timeout(Duration::from_secs(3), async {
        let a = stream.read_u8().await.unwrap();
        let b = stream.read_u8().await.unwrap();
        assert_eq!(a & 0x70, 0);
        assert_eq!(b & 0x80 != 0, masked);
        let size = match b & 0x7f {
            126 => usize::from(stream.read_u16().await.unwrap()),
            127 => stream.read_u64().await.unwrap() as usize,
            other => other as usize,
        };
        assert!(size <= websocket::MAX_PAYLOAD + 1);
        let mut mask = [0; 4];
        if masked {
            stream.read_exact(&mut mask).await.unwrap();
        }
        let mut data = vec![0; size];
        stream.read_exact(&mut data).await.unwrap();
        if masked {
            for (i, b) in data.iter_mut().enumerate() {
                *b ^= mask[i % 4];
            }
        }
        (a & 15, data)
    })
    .await
    .unwrap()
}
async fn raw_client<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) {
    stream.write_all(request().as_bytes()).await.unwrap();
    let response = header(stream).await;
    assert!(response.starts_with("HTTP/1.1 101"));
    assert!(
        response
            .to_ascii_lowercase()
            .contains("sec-websocket-accept: s3pplmbitxaq9kygzzhzrbk+xoo=")
    );
    assert!(response.contains("relay-stream-v1"));
}
async fn reply<S: AsyncRead + AsyncWrite + Unpin>(stream: &mut S) -> Vec<u8> {
    let mut output = vec![];
    let mut ended = false;
    loop {
        let (opcode, data) = read_frame(stream, false).await;
        match opcode {
            2 if data.first() == Some(&0) => {
                assert!(!ended);
                output.extend_from_slice(&data[1..]);
            }
            2 if data == [1] => {
                assert!(!ended);
                ended = true;
            }
            8 => {
                assert!(ended);
                stream
                    .write_all(&frame(8, true, true, &data))
                    .await
                    .unwrap();
                return output;
            }
            10 => assert_eq!(data, b"probe"),
            other => panic!("unexpected opcode {other}"),
        }
    }
}
fn total(store: &Store) -> u64 {
    store
        .agent_usage(false)
        .unwrap()
        .iter()
        .map(|r| r.upload_bytes + r.download_bytes)
        .sum()
}

#[tokio::test]
async fn raw_client_fragmentation_ping_half_close_and_exact_metering() {
    let backend = TcpListener::bind(free_address()).await.unwrap();
    let target = backend.local_addr().unwrap();
    let payload: Vec<u8> = (0..131111).map(|i| (i % 251) as u8).collect();
    let expected = payload.clone();
    let server = tokio::spawn(async move {
        let (mut stream, _) = backend.accept().await.unwrap();
        let mut received = vec![];
        stream.read_to_end(&mut received).await.unwrap();
        assert_eq!(received, expected);
        received.reverse();
        stream.write_all(&received).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let mut r = rule(target, Protocol::Tcp);
    r.inbound_websocket = Some(server_spec());
    let listen = r.listen;
    engine.apply(config(r)).await.unwrap();
    let mut client = TcpStream::connect(listen).await.unwrap();
    raw_client(&mut client).await;
    for (i, chunk) in payload.chunks(65536).enumerate() {
        let mut data = vec![0];
        data.extend_from_slice(chunk);
        if i == 0 {
            client
                .write_all(&frame(2, false, true, &data[..100]))
                .await
                .unwrap();
            client
                .write_all(&frame(9, true, true, b"probe"))
                .await
                .unwrap();
            client
                .write_all(&frame(0, true, true, &data[100..]))
                .await
                .unwrap();
        } else {
            client
                .write_all(&frame(2, true, true, &data))
                .await
                .unwrap();
        }
    }
    client.write_all(&frame(2, true, true, &[1])).await.unwrap();
    let result = reply(&mut client).await;
    assert_eq!(result, payload.iter().rev().copied().collect::<Vec<_>>());
    server.await.unwrap();
    engine.shutdown().await.unwrap();
    assert_eq!(total(&db), 2 * payload.len() as u64);
    assert_eq!(engine.stats().failed_connections, 0);
}

#[tokio::test]
async fn raw_server_observes_masking_host_origin_records_and_full_half_close() {
    let backend = TcpListener::bind(free_address()).await.unwrap();
    let target = backend.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut socket, _) = backend.accept().await.unwrap();
        let request = header(&mut socket).await;
        assert!(request.starts_with("GET /relay?version=1 HTTP/1.1"));
        assert!(
            request
                .to_ascii_lowercase()
                .contains("host: relay.test:8080")
        );
        assert!(
            request
                .to_ascii_lowercase()
                .contains("origin: https://console.example")
        );
        socket
            .write_all(response(&request).as_bytes())
            .await
            .unwrap();
        let mut bytes = vec![];
        loop {
            let (opcode, data) = read_frame(&mut socket, true).await;
            assert_eq!(opcode, 2);
            if data == [1] {
                break;
            }
            assert_eq!(data[0], 0);
            bytes.extend_from_slice(&data[1..]);
        }
        bytes.reverse();
        for chunk in bytes.chunks(65536) {
            let mut message = vec![0];
            message.extend_from_slice(chunk);
            socket
                .write_all(&frame(2, true, false, &message))
                .await
                .unwrap();
        }
        socket
            .write_all(&frame(2, true, false, &[1]))
            .await
            .unwrap();
        let (opcode, data) = read_frame(&mut socket, true).await;
        assert_eq!(opcode, 8);
        socket
            .write_all(&frame(8, true, false, &data))
            .await
            .unwrap();
        bytes.len()
    });
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let mut r = rule(target, Protocol::Tcp);
    r.targets[0].websocket = Some(client_spec());
    let listen = r.listen;
    engine.apply(config(r)).await.unwrap();
    let payload: Vec<u8> = (0..70003).map(|i| (i % 251) as u8).collect();
    let mut client = TcpStream::connect(listen).await.unwrap();
    client.write_all(&payload).await.unwrap();
    client.shutdown().await.unwrap();
    let mut received = vec![];
    timeout(Duration::from_secs(3), client.read_to_end(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(received, payload.iter().rev().copied().collect::<Vec<_>>());
    assert_eq!(server.await.unwrap(), payload.len());
    engine.shutdown().await.unwrap();
    assert_eq!(total(&db), 2 * payload.len() as u64);
    assert_eq!(engine.stats().failed_connections, 0);
}

#[tokio::test]
async fn ws_and_mutual_wss_hops_preserve_payload_with_both_proxy_positions() {
    let cert = tls::Certificates::new();
    let echo = tcp_echo().await;
    for (secure, position) in [
        (false, None),
        (false, Some(ProxyPlacement::BeforeTls)),
        (true, None),
        (true, Some(ProxyPlacement::BeforeTls)),
        (true, Some(ProxyPlacement::InsideTls)),
    ] {
        let temp = tempfile::tempdir().unwrap();
        let exit_db = Store::open(&temp.path().join("exit.db")).unwrap();
        let exit = Engine::with_tls_directory(exit_db.clone(), Some(cert.root.clone()));
        let mut end = rule(echo.address, Protocol::Tcp);
        end.inbound_websocket = Some(server_spec());
        if secure {
            end.inbound_tls = Some(TlsServer {
                identity: "server".into(),
                client_ca: Some("root".into()),
            });
        }
        if let Some(placement) = position {
            end.inbound_proxy = Some(ProxyInbound {
                version: ProxyAccept::V2,
                trusted_sources: vec!["127.0.0.0/8".parse().unwrap()],
                placement,
                max_header_bytes: 4096,
            });
            end.allow_sources = vec!["198.51.100.7/32".parse().unwrap()];
        }
        let hop = end.listen;
        exit.apply(config(end)).await.unwrap();
        let entry_db = Store::open(&temp.path().join("entry.db")).unwrap();
        let entry = Engine::with_tls_directory(entry_db.clone(), Some(cert.root.clone()));
        let mut start = rule(hop, Protocol::Tcp);
        start.targets[0].websocket = Some(client_spec());
        if secure {
            start.targets[0].tls = Some(TlsClient {
                server_name: "relay.test".into(),
                ca: Some("root".into()),
                identity: Some("client".into()),
            });
        }
        if let Some(placement) = position {
            start.inbound_proxy = Some(ProxyInbound {
                version: ProxyAccept::V1,
                trusted_sources: vec!["127.0.0.0/8".parse().unwrap()],
                placement: ProxyPlacement::BeforeTls,
                max_header_bytes: 4096,
            });
            start.targets[0].proxy_protocol = Some(ProxyOutbound {
                version: ProxyVersion::V2,
                placement,
                checksum: true,
            });
        }
        let address = start.listen;
        entry.apply(config(start)).await.unwrap();
        let mut client = TcpStream::connect(address).await.unwrap();
        if position.is_some() {
            client
                .write_all(b"PROXY TCP4 198.51.100.7 203.0.113.9 12345 443\r\n")
                .await
                .unwrap();
        }
        client.write_all(b"\0websocket binary\xff").await.unwrap();
        client.shutdown().await.unwrap();
        let mut result = vec![];
        timeout(Duration::from_secs(3), client.read_to_end(&mut result))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(
            result, b"\0websocket binary\xff",
            "secure={secure} position={position:?}"
        );
        entry.shutdown().await.unwrap();
        exit.shutdown().await.unwrap();
        assert_eq!(total(&entry_db), 36);
        assert_eq!(total(&exit_db), 36);
        assert_eq!(entry.stats().failed_connections, 0);
        assert_eq!(exit.stats().failed_connections, 0);
    }
}

#[tokio::test]
async fn transport_flush_waits_for_wire_backpressure() {
    let (server, mut peer) = tokio::io::duplex(256);
    let task = tokio::spawn(async move {
        websocket::accept(Box::new(server), &server_spec(), Duration::from_secs(1))
            .await
            .unwrap()
    });
    raw_client(&mut peer).await;
    let mut stream = task.await.unwrap();
    stream.write_all(&vec![5; 65536]).await.unwrap();
    assert!(
        timeout(Duration::from_millis(30), stream.flush())
            .await
            .is_err()
    );
    let drain = tokio::spawn(async move {
        let (opcode, data) = read_frame(&mut peer, false).await;
        assert_eq!(opcode, 2);
        assert_eq!(data[0], 0);
        assert_eq!(&data[1..], vec![5; 65536]);
        peer
    });
    timeout(Duration::from_secs(2), stream.flush())
        .await
        .unwrap()
        .unwrap();
    let mut peer = drain.await.unwrap();
    drop(stream);
    assert_eq!(
        timeout(Duration::from_secs(1), peer.read(&mut [0; 1]))
            .await
            .unwrap()
            .unwrap(),
        0
    );
}

async fn idle(engine: &Engine) {
    timeout(Duration::from_secs(3), async {
        while engine.stats().active_tcp != 0 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}
async fn closed<S: AsyncRead + Unpin>(stream: &mut S) {
    let mut rest = vec![];
    let _ = timeout(Duration::from_secs(3), stream.read_to_end(&mut rest))
        .await
        .expect("connection remained open");
}

#[tokio::test]
async fn handshake_path_host_origin_subprotocol_key_and_header_limit_reject_before_target() {
    let backend = TcpListener::bind(free_address()).await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let mut r = rule(backend.local_addr().unwrap(), Protocol::Tcp);
    r.inbound_websocket = Some(server_spec());
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    let inputs = [
        request().replace("GET /relay?version=1", "GET /wrong"),
        request().replace("Host: relay.test:8080", "Host: wrong.test"),
        request().replace("https://console.example", "https://other.example"),
        request().replace("https://console.example", "null"),
        request().replace("Sec-WebSocket-Protocol: relay-stream-v1\r\n", ""),
        request().replace("relay-stream-v1", "unknown-v1"),
        request().replace("dGhlIHNhbXBsZSBub25jZQ==", "invalid-key"),
        request().replace("Sec-WebSocket-Version: 13", "Sec-WebSocket-Version: 12"),
        request().replace("GET ", "POST "),
        request().replace(
            "Host: relay.test:8080",
            "Host: relay.test:8080\r\nHost: other.test",
        ),
        request().replace(
            "\r\n\r\n",
            &format!("\r\nX-Pad: {}\r\n\r\n", "a".repeat(16384)),
        ),
    ];
    for request in inputs {
        let mut client = TcpStream::connect(address).await.unwrap();
        let _ = client.write_all(request.as_bytes()).await;
        let mut result = vec![];
        let _ = timeout(Duration::from_secs(3), client.read_to_end(&mut result))
            .await
            .unwrap();
        assert!(!result.starts_with(b"HTTP/1.1 101"));
    }
    idle(&engine).await;
    assert!(
        timeout(Duration::from_millis(30), backend.accept())
            .await
            .is_err()
    );
    engine.shutdown().await.unwrap();
    assert_eq!(total(&db), 0);
    assert_eq!(engine.stats().failed_connections, 11);
}

#[tokio::test]
async fn coalesced_upgrade_response_and_reverse_half_close_preserve_large_payload() {
    let backend = TcpListener::bind(free_address()).await.unwrap();
    let target = backend.local_addr().unwrap();
    let server = tokio::spawn(async move {
        let (mut peer, _) = backend.accept().await.unwrap();
        let upgrade = header(&mut peer).await;
        let mut wire = response(&upgrade).into_bytes();
        let mut message = vec![0];
        message.extend(vec![0x9a; 65536]);
        wire.extend(frame(2, true, false, &message));
        wire.extend(frame(2, true, false, &[1]));
        peer.write_all(&wire).await.unwrap();
        assert_eq!(read_frame(&mut peer, true).await, (2, b"\0late".to_vec()));
        assert_eq!(read_frame(&mut peer, true).await, (2, vec![1]));
        let (opcode, data) = read_frame(&mut peer, true).await;
        assert_eq!(opcode, 8);
        peer.write_all(&frame(8, true, false, &data)).await.unwrap();
    });
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let mut r = rule(target, Protocol::Tcp);
    r.targets[0].websocket = Some(client_spec());
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    let mut client = TcpStream::connect(address).await.unwrap();
    let mut greeting = vec![];
    timeout(Duration::from_secs(3), client.read_to_end(&mut greeting))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(greeting, vec![0x9a; 65536]);
    client.write_all(b"late").await.unwrap();
    client.shutdown().await.unwrap();
    server.await.unwrap();
    idle(&engine).await;
    engine.shutdown().await.unwrap();
    assert_eq!(total(&db), 65540);
    assert_eq!(engine.stats().failed_connections, 0);
}

#[tokio::test]
async fn malformed_records_frames_and_early_close_never_become_payload() {
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let mut r = rule(echo.address, Protocol::Tcp);
    r.inbound_websocket = Some(server_spec());
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    let mut oversize = vec![0x82, 0xff];
    oversize.extend_from_slice(&(websocket::MAX_PAYLOAD as u64 + 2).to_be_bytes());
    oversize.extend_from_slice(&[1, 2, 3, 4]);
    let mut after_fin = frame(2, true, true, &[1]);
    after_fin.extend(frame(2, true, true, &[0, 9]));
    let mut duplicate_fin = frame(2, true, true, &[1]);
    duplicate_fin.extend(frame(2, true, true, &[1]));
    let mut reserved = frame(2, true, true, &[0, 9]);
    reserved[0] |= 0x40;
    let inputs = [
        frame(2, true, true, &[]),
        frame(2, true, true, &[0]),
        frame(2, true, true, &[1, 9]),
        frame(2, true, true, &[2, 9]),
        frame(1, true, true, b"text"),
        frame(2, true, false, &[0, 9]),
        frame(0, true, true, &[0, 9]),
        frame(8, true, true, &[]),
        oversize,
        after_fin,
        duplicate_fin,
        reserved,
    ];
    for bytes in inputs {
        let mut client = TcpStream::connect(address).await.unwrap();
        raw_client(&mut client).await;
        let _ = client.write_all(&bytes).await;
        closed(&mut client).await;
    }
    idle(&engine).await;
    engine.shutdown().await.unwrap();
    assert_eq!(total(&db), 0);
    assert_eq!(engine.stats().failed_connections, 12);
}

#[tokio::test]
async fn ping_after_remote_fin_is_served_while_application_reply_is_waiting() {
    let backend = TcpListener::bind(free_address()).await.unwrap();
    let address = backend.local_addr().unwrap();
    let (received, wait) = tokio::sync::oneshot::channel();
    let (release, resume) = tokio::sync::oneshot::channel();
    let target = tokio::spawn(async move {
        let (mut stream, _) = backend.accept().await.unwrap();
        let mut bytes = vec![];
        stream.read_to_end(&mut bytes).await.unwrap();
        assert!(bytes.is_empty());
        received.send(()).unwrap();
        resume.await.unwrap();
        stream.write_all(b"later").await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let mut r = rule(address, Protocol::Tcp);
    r.inbound_websocket = Some(server_spec());
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    let mut client = TcpStream::connect(address).await.unwrap();
    raw_client(&mut client).await;
    client.write_all(&frame(2, true, true, &[1])).await.unwrap();
    timeout(Duration::from_secs(2), wait)
        .await
        .unwrap()
        .unwrap();
    client
        .write_all(&frame(9, true, true, b"probe"))
        .await
        .unwrap();
    assert_eq!(
        read_frame(&mut client, false).await,
        (10, b"probe".to_vec())
    );
    release.send(()).unwrap();
    assert_eq!(reply(&mut client).await, b"later");
    target.await.unwrap();
    idle(&engine).await;
    engine.shutdown().await.unwrap();
    assert_eq!(total(&db), 5);
}

#[tokio::test]
async fn bounded_incoming_queue_backpressures_and_drop_stops_the_driver() {
    let (server, mut peer) = tokio::io::duplex(256);
    let task = tokio::spawn(async move {
        websocket::accept(Box::new(server), &server_spec(), Duration::from_secs(1))
            .await
            .unwrap()
    });
    raw_client(&mut peer).await;
    let mut stream = task.await.unwrap();
    let mut data = vec![0];
    data.extend(vec![7; 65536]);
    let bytes = frame(2, true, true, &data);
    peer.write_all(&bytes).await.unwrap();
    peer.write_all(&bytes).await.unwrap();
    assert!(
        timeout(Duration::from_millis(30), peer.write_all(&bytes))
            .await
            .is_err()
    );
    let mut first = vec![0; 65536];
    stream.read_exact(&mut first).await.unwrap();
    assert_eq!(first, vec![7; 65536]);
    drop(stream);
    closed(&mut peer).await;
}

#[tokio::test]
async fn slow_upgrade_releases_connection_slot_and_invalid_update_keeps_old_rule() {
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let mut r = rule(echo.address, Protocol::Tcp);
    r.inbound_websocket = Some(server_spec());
    r.connect_timeout_ms = 100;
    r.max_connections = 1;
    let address = r.listen;
    engine.apply(config(r.clone())).await.unwrap();
    let mut slow = TcpStream::connect(address).await.unwrap();
    slow.write_all(b"GET /").await.unwrap();
    timeout(Duration::from_secs(1), async {
        while engine.stats().active_tcp != 1 {
            sleep(Duration::from_millis(2)).await;
        }
    })
    .await
    .unwrap();
    let mut excess = TcpStream::connect(address).await.unwrap();
    closed(&mut excess).await;
    closed(&mut slow).await;
    idle(&engine).await;
    assert_eq!(engine.stats().rejected_connections, 1);
    let mut broken = config(r.clone());
    broken.revision = 2;
    broken.rules[0].inbound_websocket.as_mut().unwrap().path = "bad path".into();
    assert!(engine.apply(broken).await.is_err());
    assert_eq!(db.agent_config().unwrap().unwrap().revision, 1);
    let mut client = TcpStream::connect(address).await.unwrap();
    raw_client(&mut client).await;
    client
        .write_all(&frame(2, true, true, b"\0ok"))
        .await
        .unwrap();
    client.write_all(&frame(2, true, true, &[1])).await.unwrap();
    assert_eq!(reply(&mut client).await, b"ok");
    idle(&engine).await;
    engine.shutdown().await.unwrap();
    assert_eq!(total(&db), 4);
}

#[tokio::test]
async fn path_policy_change_revokes_open_streams_without_disabling_plain_target_updates() {
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let mut r = rule(echo.address, Protocol::Tcp);
    r.inbound_websocket = Some(server_spec());
    let address = r.listen;
    engine.apply(config(r.clone())).await.unwrap();
    let mut client = TcpStream::connect(address).await.unwrap();
    raw_client(&mut client).await;
    client
        .write_all(&frame(2, true, true, b"\0ok"))
        .await
        .unwrap();
    assert_eq!(read_frame(&mut client, false).await, (2, b"\0ok".to_vec()));
    let second = tcp_echo().await;
    let mut alternate = r.targets[0].clone();
    alternate.address = second.address.to_string();
    r.targets.push(alternate);
    let mut changed = config(r.clone());
    changed.revision = 2;
    engine.apply(changed).await.unwrap();
    client
        .write_all(&frame(2, true, true, b"\0live"))
        .await
        .unwrap();
    assert_eq!(
        read_frame(&mut client, false).await,
        (2, b"\0live".to_vec())
    );
    r.inbound_websocket.as_mut().unwrap().path = "/changed".into();
    let mut changed = config(r);
    changed.revision = 3;
    engine.apply(changed).await.unwrap();
    closed(&mut client).await;
    idle(&engine).await;
    engine.shutdown().await.unwrap();
    assert_eq!(total(&db), 12);
}

#[tokio::test]
async fn wss_requires_valid_client_certificate_before_http_upgrade() {
    let certificates = tls::Certificates::new();
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::with_tls_directory(db.clone(), Some(certificates.root.clone()));
    let mut r = rule(echo.address, Protocol::Tcp);
    r.inbound_websocket = Some(server_spec());
    r.inbound_tls = Some(TlsServer {
        identity: "server".into(),
        client_ca: Some("root".into()),
    });
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    for authenticated in [false, true] {
        let socket = TcpStream::connect(address).await.unwrap();
        let connection = certificates
            .connector(authenticated)
            .connect("relay.test".try_into().unwrap(), socket)
            .await;
        if authenticated {
            let mut client = connection.unwrap();
            raw_client(&mut client).await;
            client
                .write_all(&frame(2, true, true, b"\0secure"))
                .await
                .unwrap();
            client.write_all(&frame(2, true, true, &[1])).await.unwrap();
            assert_eq!(reply(&mut client).await, b"secure");
        } else if let Ok(mut client) = connection {
            let _ = client.write_all(request().as_bytes()).await;
            let mut bytes = vec![];
            let _ = timeout(Duration::from_secs(2), client.read_to_end(&mut bytes))
                .await
                .unwrap();
            assert!(!bytes.starts_with(b"HTTP/1.1 101"));
        }
    }
    idle(&engine).await;
    engine.shutdown().await.unwrap();
    assert_eq!(total(&db), 12);
}

#[tokio::test]
async fn quotas_count_only_unwrapped_application_bytes_across_sessions() {
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let mut r = rule(echo.address, Protocol::Tcp);
    r.inbound_websocket = Some(server_spec());
    r.quota_bytes = Some(8);
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    for exhausted in [false, true] {
        let mut client = TcpStream::connect(address).await.unwrap();
        raw_client(&mut client).await;
        let mut wire = frame(2, true, true, b"\0four");
        wire.extend(frame(2, true, true, &[1]));
        let _ = client.write_all(&wire).await;
        if exhausted {
            closed(&mut client).await;
        } else {
            assert_eq!(reply(&mut client).await, b"four");
        }
        idle(&engine).await;
    }
    engine.shutdown().await.unwrap();
    assert_eq!(total(&db), 8);
    assert_eq!(engine.stats().forwarded_upload_bytes, 4);
    assert_eq!(engine.stats().forwarded_download_bytes, 4);
    assert_eq!(engine.stats().failed_connections, 1);
}

#[tokio::test]
async fn missing_close_ack_has_a_bounded_deadline() {
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let mut r = rule(echo.address, Protocol::Tcp);
    r.inbound_websocket = Some(server_spec());
    r.connect_timeout_ms = 100;
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    let mut client = TcpStream::connect(address).await.unwrap();
    raw_client(&mut client).await;
    client.write_all(&frame(2, true, true, &[1])).await.unwrap();
    assert_eq!(read_frame(&mut client, false).await, (2, vec![1]));
    assert_eq!(read_frame(&mut client, false).await.0, 8);
    closed(&mut client).await;
    idle(&engine).await;
    engine.shutdown().await.unwrap();
    assert_eq!(total(&db), 0);
    assert_eq!(engine.stats().failed_connections, 1);
}

#[test]
fn invalid_ws_configurations_are_rejected_without_optional_protocol_fallback() {
    let mut r = rule("127.0.0.1:34567".parse().unwrap(), Protocol::Tcp);
    r.inbound_websocket = Some(server_spec());
    assert!(r.validate().is_ok());
    for protocol in [Protocol::Udp, Protocol::Both] {
        r.protocol = protocol;
        assert!(r.validate().is_err());
    }
    r.protocol = Protocol::Tcp;
    for path in [
        "",
        "no-slash",
        "//other",
        "/bad#fragment",
        "/line\r\nInjected:yes",
        "/raw space",
    ] {
        r.inbound_websocket.as_mut().unwrap().path = path.into();
        assert!(r.validate().is_err(), "{path:?}");
    }
    r.inbound_websocket = Some(server_spec());
    for host in ["", "user@host", "host/path", "host:99999", "host\r\nX:1"] {
        r.inbound_websocket.as_mut().unwrap().host = Some(host.into());
        assert!(r.validate().is_err(), "{host:?}");
    }
    r.inbound_websocket = Some(server_spec());
    for origin in [
        "null",
        "*",
        "https://app.test/",
        "https://app.test/path",
        "https://user@app.test",
        "ftp://app.test",
    ] {
        r.inbound_websocket.as_mut().unwrap().allowed_origins = vec![origin.into()];
        assert!(r.validate().is_err(), "{origin:?}");
    }
    r.inbound_websocket = None;
    r.targets[0].websocket = Some(client_spec());
    r.protocol = Protocol::Both;
    assert!(r.validate().is_err());
    r.protocol = Protocol::Tcp;
    assert!(r.validate().is_ok());
    let mut json = serde_json::to_value(config(r)).unwrap();
    json["rules"][0]["targets"][0]["websocket"]["unsupported"] = true.into();
    assert!(serde_json::from_value::<NodeConfig>(json).is_err());
}

#[tokio::test]
async fn blocked_control_flush_cannot_hold_half_closed_stream_indefinitely() {
    let (server, mut peer) = tokio::io::duplex(64);
    let task = tokio::spawn(async move {
        websocket::accept(Box::new(server), &server_spec(), Duration::from_millis(100))
            .await
            .unwrap()
    });
    raw_client(&mut peer).await;
    let mut stream = task.await.unwrap();
    stream.shutdown().await.unwrap();
    assert_eq!(read_frame(&mut peer, false).await, (2, vec![1]));
    // A maximum-size Pong cannot fit the deliberately blocked write channel.
    // The peer then finishes its application direction but stops reading.
    let mut wire = frame(9, true, true, &[7; 125]);
    wire.extend(frame(2, true, true, &[1]));
    peer.write_all(&wire).await.unwrap();
    assert!(
        timeout(Duration::from_secs(1), stream.read(&mut [0; 1]))
            .await
            .expect("blocked control flush escaped its deadline")
            .is_err()
    );
}

#[tokio::test]
async fn outbound_upgrade_mismatch_never_forwards_application_or_falls_back() {
    for mistake in ["accept", "subprotocol", "extensions"] {
        let backend = TcpListener::bind(free_address()).await.unwrap();
        let target = backend.local_addr().unwrap();
        let server = tokio::spawn(async move {
            let (mut socket, _) = backend.accept().await.unwrap();
            let request = header(&mut socket).await;
            let valid = response(&request);
            let invalid = match mistake {
                "accept" => valid.replace("Sec-WebSocket-Accept:", "X-Ignored:"),
                "subprotocol" => valid.replace("relay-stream-v1", "other-v1"),
                _ => valid.replace(
                    "\r\n\r\n",
                    "\r\nSec-WebSocket-Extensions: permessage-deflate\r\n\r\n",
                ),
            };
            socket.write_all(invalid.as_bytes()).await.unwrap();
            let mut rest = vec![];
            let _ = timeout(Duration::from_secs(3), socket.read_to_end(&mut rest))
                .await
                .unwrap();
            assert!(rest.is_empty());
        });
        let temp = tempfile::tempdir().unwrap();
        let db = Store::open(&temp.path().join("agent.db")).unwrap();
        let engine = Engine::new(db.clone());
        let mut r = rule(target, Protocol::Tcp);
        r.targets[0].websocket = Some(client_spec());
        let listen = r.listen;
        engine.apply(config(r)).await.unwrap();
        let mut client = TcpStream::connect(listen).await.unwrap();
        client.write_all(b"must-not-be-sent").await.unwrap();
        closed(&mut client).await;
        server.await.unwrap();
        idle(&engine).await;
        engine.shutdown().await.unwrap();
        assert_eq!(total(&db), 0);
        assert_eq!(engine.stats().failed_connections, 1);
    }
}

#[tokio::test]
async fn outbound_wss_rejects_wrong_server_name_missing_identity_and_wrong_http_host() {
    let certificates = tls::Certificates::new();
    let echo = tcp_echo().await;
    for mistake in ["server-name", "client-identity", "host"] {
        let temp = tempfile::tempdir().unwrap();
        let exit_db = Store::open(&temp.path().join("exit.db")).unwrap();
        let exit = Engine::with_tls_directory(exit_db.clone(), Some(certificates.root.clone()));
        let mut end = rule(echo.address, Protocol::Tcp);
        end.inbound_websocket = Some(server_spec());
        end.inbound_tls = Some(TlsServer {
            identity: "server".into(),
            client_ca: Some("root".into()),
        });
        let hop = end.listen;
        exit.apply(config(end)).await.unwrap();
        let db = Store::open(&temp.path().join("entry.db")).unwrap();
        let entry = Engine::with_tls_directory(db.clone(), Some(certificates.root.clone()));
        let mut start = rule(hop, Protocol::Tcp);
        start.targets[0].websocket = Some(client_spec());
        start.targets[0].tls = Some(TlsClient {
            server_name: if mistake == "server-name" {
                "wrong.test"
            } else {
                "relay.test"
            }
            .into(),
            ca: Some("root".into()),
            identity: if mistake == "client-identity" {
                None
            } else {
                Some("client".into())
            },
        });
        if mistake == "host" {
            start.targets[0].websocket.as_mut().unwrap().host = "wrong.test".into();
        }
        let address = start.listen;
        entry.apply(config(start)).await.unwrap();
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(b"reject-wss").await.unwrap();
        closed(&mut client).await;
        idle(&entry).await;
        entry.shutdown().await.unwrap();
        exit.shutdown().await.unwrap();
        assert_eq!(total(&db), 0);
        assert_eq!(total(&exit_db), 0);
    }
}

#[tokio::test]
async fn pings_do_not_extend_application_idle_timeout() {
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let mut r = rule(echo.address, Protocol::Tcp);
    r.inbound_websocket = Some(server_spec());
    r.idle_timeout_secs = 1;
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    let mut client = TcpStream::connect(address).await.unwrap();
    raw_client(&mut client).await;
    let started = tokio::time::Instant::now();
    let mut count = 0;
    for _ in 0..15 {
        if client
            .write_all(&frame(9, true, true, b"probe"))
            .await
            .is_err()
        {
            break;
        }
        let mut head = [0; 2];
        if timeout(Duration::from_millis(500), client.read_exact(&mut head))
            .await
            .unwrap()
            .is_err()
        {
            break;
        }
        assert_eq!(head, [0x8a, 5]);
        let mut bytes = [0; 5];
        client.read_exact(&mut bytes).await.unwrap();
        assert_eq!(&bytes, b"probe");
        count += 1;
        sleep(Duration::from_millis(100)).await;
    }
    assert!(count > 2 && count < 15);
    assert!(started.elapsed() < Duration::from_secs(2));
    idle(&engine).await;
    engine.shutdown().await.unwrap();
    assert_eq!(total(&db), 0);
}

#[tokio::test]
async fn moving_websocket_policy_between_existing_targets_revokes_old_sessions() {
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let exit = Engine::new(Store::open(&temp.path().join("exit.db")).unwrap());
    let mut end = rule(echo.address, Protocol::Tcp);
    end.inbound_websocket = Some(server_spec());
    let hop = end.listen;
    exit.apply(config(end)).await.unwrap();
    let db = Store::open(&temp.path().join("entry.db")).unwrap();
    let entry = Engine::new(db.clone());
    let mut r = rule(hop, Protocol::Tcp);
    r.targets[0].websocket = Some(client_spec());
    let mut alternate = r.targets[0].clone();
    alternate.address = echo.address.to_string();
    alternate.websocket = None;
    r.targets.push(alternate);
    let address = r.listen;
    entry.apply(config(r.clone())).await.unwrap();
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(b"x").await.unwrap();
    let mut byte = [0];
    timeout(Duration::from_secs(2), client.read_exact(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&byte, b"x");
    r.targets[1].websocket = r.targets[0].websocket.take();
    let mut update = config(r);
    update.revision = 2;
    entry.apply(update).await.unwrap();
    closed(&mut client).await;
    idle(&entry).await;
    entry.shutdown().await.unwrap();
    exit.shutdown().await.unwrap();
    assert_eq!(total(&db), 2);
}
