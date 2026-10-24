mod common;
#[path = "common/tls.rs"]
mod tls;
use common::*;
use relay_platform::{
    engine::Engine,
    model::*,
    proxy::{self, ConnectionInfo},
    store::Store,
};
use std::{
    collections::HashSet,
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::{sleep, timeout},
};

const V1: &[u8] = b"PROXY TCP4 198.51.100.7 203.0.113.9 12345 443\r\n";
// CRC32C fixture independently computed with the reflected Castagnoli polynomial.
const V2_CRC_HEX: &str = "0d0a0d0a000d0a515549540a21110013c6336407cb007109303901bb030004376c844a";
fn hex(text: &str) -> Vec<u8> {
    text.as_bytes()
        .as_chunks::<2>()
        .0
        .iter()
        .map(|c| u8::from_str_radix(std::str::from_utf8(c).unwrap(), 16).unwrap())
        .collect()
}
fn claimed() -> ConnectionInfo {
    ConnectionInfo {
        source: "198.51.100.7:12345".parse().unwrap(),
        destination: "203.0.113.9:443".parse().unwrap(),
    }
}
fn original() -> ConnectionInfo {
    ConnectionInfo {
        source: "127.0.0.1:10000".parse().unwrap(),
        destination: "127.0.0.1:20000".parse().unwrap(),
    }
}
fn inbound(version: ProxyAccept) -> ProxyInbound {
    ProxyInbound {
        version,
        trusted_sources: vec!["127.0.0.0/8".parse().unwrap(), "::1/128".parse().unwrap()],
        placement: ProxyPlacement::BeforeTls,
        max_header_bytes: 4096,
    }
}
fn outbound(version: ProxyVersion) -> ProxyOutbound {
    ProxyOutbound {
        version,
        placement: ProxyPlacement::BeforeTls,
        checksum: false,
    }
}

#[tokio::test]
async fn moving_proxy_policy_between_existing_targets_cancels_old_sessions() {
    let backend = TcpListener::bind(free_address()).await.unwrap();
    let other = TcpListener::bind(free_address()).await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let mut r = rule(backend.local_addr().unwrap(), Protocol::Tcp);
    r.targets[0].proxy_protocol = Some(outbound(ProxyVersion::V1));
    let mut alternate = r.targets[0].clone();
    alternate.address = other.local_addr().unwrap().to_string();
    alternate.proxy_protocol = None;
    r.targets.push(alternate);
    let address = r.listen;
    engine.apply(config(r.clone())).await.unwrap();
    let server = tokio::spawn(async move {
        let (mut stream, _) = backend.accept().await.unwrap();
        proxy::read_tcp(&mut stream, &inbound(ProxyAccept::V1), original())
            .await
            .unwrap();
        let mut byte = [0];
        stream.read_exact(&mut byte).await.unwrap();
        stream.write_all(&byte).await.unwrap();
        rejected(&mut stream).await;
    });
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(b"x").await.unwrap();
    let mut byte = [0];
    timeout(Duration::from_secs(3), client.read_exact(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(byte, *b"x");
    // The filtered list of non-null policies is unchanged, but each existing
    // target now has a different transport policy.
    r.targets[1].proxy_protocol = r.targets[0].proxy_protocol.take();
    let mut update = config(r);
    update.revision = 2;
    engine.apply(update).await.unwrap();
    rejected(&mut client).await;
    server.await.unwrap();
    engine.shutdown().await.unwrap();
    assert_eq!(total(&db), 2);
}

fn v2_frame(source: SocketAddr, destination: SocketAddr, tcp: bool) -> Vec<u8> {
    // Wire fixture does not call the production encoder.
    let mut b = b"\r\n\r\n\0\r\nQUIT\n".to_vec();
    b.push(0x21);
    let size: u16 = if source.is_ipv4() { 12 } else { 36 };
    b.push((if source.is_ipv4() { 0x10 } else { 0x20 }) | if tcp { 1 } else { 2 });
    b.extend_from_slice(&size.to_be_bytes());
    for ip in [source.ip(), destination.ip()] {
        match ip {
            IpAddr::V4(ip) => b.extend_from_slice(&ip.octets()),
            IpAddr::V6(ip) => b.extend_from_slice(&ip.octets()),
        }
    }
    b.extend_from_slice(&source.port().to_be_bytes());
    b.extend_from_slice(&destination.port().to_be_bytes());
    b
}
async fn read_reply(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = vec![];
    timeout(Duration::from_secs(3), stream.read_to_end(&mut bytes))
        .await
        .unwrap()
        .unwrap();
    bytes
}
async fn rejected(stream: &mut TcpStream) {
    let result = timeout(Duration::from_secs(3), stream.read(&mut [0; 32]))
        .await
        .expect("rejected stream remained open");
    assert!(
        matches!(result, Ok(0) | Err(_)),
        "unexpected payload: {result:?}"
    );
}
async fn wait_idle(engine: &Engine) {
    timeout(Duration::from_secs(2), async {
        while engine.stats().active_tcp != 0 {
            sleep(Duration::from_millis(5)).await;
        }
    })
    .await
    .unwrap();
}
fn total(db: &Store) -> u64 {
    db.agent_usage(false)
        .unwrap()
        .iter()
        .map(|u| u.upload_bytes + u.download_bytes)
        .sum()
}

#[tokio::test]
async fn golden_wire_frames_and_fragmented_parser_preserve_following_payload() {
    let mut out = outbound(ProxyVersion::V2);
    out.checksum = true;
    let golden = hex(V2_CRC_HEX);
    assert_eq!(proxy::encode(&out, true, claimed()).unwrap(), golden);
    assert_eq!(
        proxy::encode(&outbound(ProxyVersion::V1), true, claimed()).unwrap(),
        V1
    );
    assert_eq!(
        proxy::decode_v2(&golden, true, 4096, original()).unwrap(),
        (claimed(), 35)
    );
    for header in [
        V1.to_vec(),
        golden,
        b"PROXY TCP6 2001:db8::7 2001:db8::9 65535 0\r\n".to_vec(),
    ] {
        let (mut send, mut read) = tokio::io::duplex(32);
        let copy = header.clone();
        let writer = tokio::spawn(async move {
            for chunk in copy.chunks(3) {
                send.write_all(chunk).await.unwrap();
                tokio::task::yield_now().await;
            }
            send.write_all(b"\0payload\xff").await.unwrap();
        });
        let result = proxy::read_tcp(&mut read, &inbound(ProxyAccept::Any), original())
            .await
            .unwrap();
        if header.starts_with(b"PROXY TCP6") {
            assert_eq!(result.source, "[2001:db8::7]:65535".parse().unwrap());
        } else {
            assert_eq!(result, claimed());
        }
        let mut payload = vec![];
        read.read_to_end(&mut payload).await.unwrap();
        assert_eq!(payload, b"\0payload\xff");
        writer.await.unwrap();
    }
}

#[tokio::test]
async fn unknown_local_unspec_and_unsupported_unix_use_real_endpoints() {
    for line in [
        b"PROXY UNKNOWN\r\n".as_slice(),
        b"PROXY UNKNOWN ignored information\r\n",
    ] {
        let mut bytes = line;
        assert_eq!(
            proxy::read_tcp(&mut bytes, &inbound(ProxyAccept::Any), original())
                .await
                .unwrap(),
            original()
        );
    }
    let mut local = b"\r\n\r\n\0\r\nQUIT\n\x20\xff\0\x03abcPAYLOAD".to_vec();
    assert_eq!(
        proxy::decode_v2(&local, true, 4096, original()).unwrap(),
        (original(), 19)
    );
    local[12] = 0x21;
    local[13] = 0;
    assert_eq!(
        proxy::decode_v2(&local, true, 4096, original()).unwrap(),
        (original(), 19)
    );
    let mut unix = b"\r\n\r\n\0\r\nQUIT\n\x21\x31\0\xd8".to_vec();
    unix.extend_from_slice(&[0; 216]);
    assert_eq!(
        proxy::decode_v2(&unix, true, 4096, original()).unwrap().0,
        original()
    );
}

#[tokio::test]
async fn malformed_truncated_oversized_and_wrong_transport_headers_fail() {
    let good = hex(V2_CRC_HEX);
    for end in 0..good.len() {
        assert!(proxy::decode_v2(&good[..end], true, 4096, original()).is_err());
    }
    for (offset, value) in [
        (0, 0),
        (12, 0x31),
        (12, 0x22),
        (13, 0x41),
        (13, 0x13),
        (34, 0),
    ] {
        let mut bad = good.clone();
        bad[offset] = value;
        assert!(
            proxy::decode_v2(&bad, true, 4096, original()).is_err(),
            "offset {offset}"
        );
    }
    assert!(proxy::decode_v2(&good, false, 4096, original()).is_err());
    assert!(proxy::decode_v2(&good, true, 34, original()).is_err());
    let mut tlv = v2_frame(claimed().source, claimed().destination, true);
    tlv.extend_from_slice(&[0xea, 0, 2, 1]);
    tlv[14..16].copy_from_slice(&16u16.to_be_bytes());
    assert!(proxy::decode_v2(&tlv, true, 4096, original()).is_err());
    for raw in [
        b"PROXY TCP4 198.51.100.7 203.0.113.9 01 443\r\n".as_slice(),
        b"PROXY TCP4 ::1 ::1 1 2\r\n",
        b"PROXY TCP4 1.2.3.4 5.6.7.8 1 2\n",
        b"PROXY  TCP4 1.2.3.4 5.6.7.8 1 2\r\n",
        b"GET / HTTP/1.1\r\n",
    ] {
        let mut bytes = raw;
        assert!(
            proxy::read_tcp(&mut bytes, &inbound(ProxyAccept::Any), original())
                .await
                .is_err()
        );
    }
    let mut boundary = b"PROXY UNKNOWN ".to_vec();
    boundary.resize(105, b'x');
    boundary.extend_from_slice(b"\r\n");
    assert_eq!(
        proxy::read_tcp(
            &mut boundary.as_slice(),
            &inbound(ProxyAccept::Any),
            original()
        )
        .await
        .unwrap(),
        original()
    );
    boundary.insert(14, b'x');
    assert!(
        proxy::read_tcp(
            &mut boundary.as_slice(),
            &inbound(ProxyAccept::Any),
            original()
        )
        .await
        .is_err()
    );
    let mut input = V1;
    assert!(
        proxy::read_tcp(&mut input, &inbound(ProxyAccept::V2), original())
            .await
            .is_err()
    );
    assert!(
        proxy::read_tcp(&mut good.as_slice(), &inbound(ProxyAccept::V1), original())
            .await
            .is_err()
    );
}

#[tokio::test]
async fn maximum_v2_header_is_bounded_and_tlvs_never_become_payload() {
    let mut header = v2_frame(claimed().source, claimed().destination, true);
    header.extend_from_slice(&[4, 0xff, 0xf0]);
    header.resize(65551, 0);
    header[14..16].copy_from_slice(&65535u16.to_be_bytes());
    assert!(proxy::decode_v2(&header, true, 4096, original()).is_err());
    assert_eq!(
        proxy::decode_v2(&header, true, 65551, original()).unwrap(),
        (claimed(), 65551)
    );
    let mut policy = inbound(ProxyAccept::V2);
    policy.max_header_bytes = 65551;
    header.extend_from_slice(b"body");
    let mut input = header.as_slice();
    assert_eq!(
        proxy::read_tcp(&mut input, &policy, original())
            .await
            .unwrap(),
        claimed()
    );
    assert_eq!(input, b"body");
}

#[tokio::test]
async fn tcp_claimed_acl_is_applied_only_after_trusted_peer_and_not_billed_as_payload() {
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let mut r = rule(echo.address, Protocol::Tcp);
    r.inbound_proxy = Some(inbound(ProxyAccept::Any));
    r.allow_sources = vec!["198.51.100.0/24".parse().unwrap()];
    r.deny_sources = vec!["198.51.100.8/32".parse().unwrap()];
    let address = r.listen;
    let mut c = config(r);
    engine.apply(c.clone()).await.unwrap();
    for header in [V1.to_vec(), hex(V2_CRC_HEX)] {
        let mut client = TcpStream::connect(address).await.unwrap();
        for chunk in header.chunks(2) {
            client.write_all(chunk).await.unwrap();
        }
        client.write_all(b"hello\0\xff").await.unwrap();
        client.shutdown().await.unwrap();
        assert_eq!(read_reply(&mut client).await, b"hello\0\xff");
    }
    for header in [
        b"PROXY TCP4 198.51.100.8 203.0.113.9 1 443\r\n".to_vec(),
        b"PROXY TCP6 ::ffff:198.51.100.8 ::ffff:203.0.113.9 1 443\r\n".to_vec(),
        b"PROXY UNKNOWN\r\n".to_vec(),
        b"plain application\r\n".to_vec(),
    ] {
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(&header).await.unwrap();
        let _ = client.write_all(b"denied").await;
        rejected(&mut client).await;
    }
    c.revision = 2;
    c.rules[0].inbound_proxy.as_mut().unwrap().trusted_sources =
        vec!["192.0.2.0/24".parse().unwrap()];
    engine.apply(c).await.unwrap();
    let mut client = TcpStream::connect(address).await.unwrap();
    let _ = client.write_all(V1).await;
    rejected(&mut client).await;
    engine.shutdown().await.unwrap();
    assert_eq!(total(&db), 28);
}

#[tokio::test]
async fn tcp_output_matches_independent_v1_v2_and_crc_fixtures_once_per_connection() {
    for (version, checksum) in [
        (ProxyVersion::V1, false),
        (ProxyVersion::V2, false),
        (ProxyVersion::V2, true),
    ] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut expected = if version == ProxyVersion::V1 {
            V1.to_vec()
        } else {
            hex(V2_CRC_HEX)
        };
        if version == ProxyVersion::V2 && !checksum {
            expected.truncate(28);
            expected[14..16].copy_from_slice(&12u16.to_be_bytes());
        }
        let address = listener.local_addr().unwrap();
        let backend = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            let mut got = vec![0; expected.len()];
            stream.read_exact(&mut got).await.unwrap();
            assert_eq!(got, expected);
            let mut body = vec![];
            stream.read_to_end(&mut body).await.unwrap();
            stream.write_all(&body).await.unwrap();
        });
        let temp = tempfile::tempdir().unwrap();
        let db = Store::open(&temp.path().join("agent.db")).unwrap();
        let engine = Engine::new(db.clone());
        let mut r = rule(address, Protocol::Tcp);
        r.inbound_proxy = Some(inbound(ProxyAccept::V1));
        r.targets[0].proxy_protocol = Some(ProxyOutbound {
            version,
            checksum,
            placement: ProxyPlacement::BeforeTls,
        });
        let listen = r.listen;
        engine.apply(config(r)).await.unwrap();
        let mut client = TcpStream::connect(listen).await.unwrap();
        client.write_all(V1).await.unwrap();
        client
            .write_all(b"PROXY stays application data\0\xff")
            .await
            .unwrap();
        client.shutdown().await.unwrap();
        assert_eq!(
            read_reply(&mut client).await,
            b"PROXY stays application data\0\xff"
        );
        backend.await.unwrap();
        engine.shutdown().await.unwrap();
        assert_eq!(total(&db), 60);
    }
}

#[tokio::test]
async fn tcp_output_without_input_header_uses_actual_client_and_wildcard_destination() {
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(backend.local_addr().unwrap(), Protocol::Tcp);
    let port = r.listen.port();
    r.listen.set_ip("0.0.0.0".parse().unwrap());
    r.targets[0].proxy_protocol = Some(outbound(ProxyVersion::V2));
    engine.apply(config(r)).await.unwrap();
    let mut client = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
    let source = client.local_addr().unwrap();
    let destination = client.peer_addr().unwrap();
    let (mut target, _) = timeout(Duration::from_secs(3), backend.accept())
        .await
        .unwrap()
        .unwrap();
    let mut header = [0; 28];
    target.read_exact(&mut header).await.unwrap();
    assert_eq!(header.as_slice(), v2_frame(source, destination, true));
    target.write_all(b"ok").await.unwrap();
    client.read_exact(&mut [0; 2]).await.unwrap();
    drop(target);
    drop(client);
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn slow_headers_release_slots_and_proxy_policy_changes_cancel_old_sessions() {
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(echo.address, Protocol::Tcp);
    r.inbound_proxy = Some(inbound(ProxyAccept::V1));
    r.connect_timeout_ms = 100;
    r.max_connections = 1;
    let address = r.listen;
    let mut c = config(r);
    engine.apply(c.clone()).await.unwrap();
    let mut slow = TcpStream::connect(address).await.unwrap();
    slow.write_all(b"P").await.unwrap();
    rejected(&mut slow).await;
    wait_idle(&engine).await;
    let mut live = TcpStream::connect(address).await.unwrap();
    live.write_all(V1).await.unwrap();
    live.write_all(b"ok").await.unwrap();
    timeout(Duration::from_secs(2), live.read_exact(&mut [0; 2]))
        .await
        .unwrap()
        .unwrap();
    c.revision = 2;
    c.rules[0].inbound_proxy.as_mut().unwrap().trusted_sources =
        vec!["192.0.2.0/24".parse().unwrap()];
    engine.apply(c).await.unwrap();
    rejected(&mut live).await;
    engine.shutdown().await.unwrap();
    assert_eq!(engine.stats().active_tcp, 0);
}

#[tokio::test]
async fn proxy_v1_v2_before_and_inside_mutual_tls_preserve_identity_and_payload() {
    let cert = tls::Certificates::new();
    let echo = tcp_echo().await;
    for version in [ProxyVersion::V1, ProxyVersion::V2] {
        for placement in [ProxyPlacement::BeforeTls, ProxyPlacement::InsideTls] {
            let temp = tempfile::tempdir().unwrap();
            let exit_db = Store::open(&temp.path().join("exit.db")).unwrap();
            let exit = Engine::with_tls_directory(exit_db.clone(), Some(cert.root.clone()));
            let mut er = rule(echo.address, Protocol::Tcp);
            er.inbound_tls = Some(TlsServer {
                identity: "server".into(),
                client_ca: Some("root".into()),
            });
            let mut incoming = inbound(if version == ProxyVersion::V1 {
                ProxyAccept::V1
            } else {
                ProxyAccept::V2
            });
            incoming.placement = placement;
            er.inbound_proxy = Some(incoming);
            er.allow_sources = vec!["198.51.100.7/32".parse().unwrap()];
            let hop = er.listen;
            exit.apply(config(er)).await.unwrap();
            let entry_db = Store::open(&temp.path().join("entry.db")).unwrap();
            let entry = Engine::with_tls_directory(entry_db.clone(), Some(cert.root.clone()));
            let mut r = rule(hop, Protocol::Tcp);
            r.inbound_proxy = Some(inbound(ProxyAccept::V1));
            r.targets[0].tls = Some(TlsClient {
                server_name: "relay.test".into(),
                ca: Some("root".into()),
                identity: Some("client".into()),
            });
            r.targets[0].proxy_protocol = Some(ProxyOutbound {
                version,
                placement,
                checksum: version == ProxyVersion::V2,
            });
            let address = r.listen;
            entry.apply(config(r)).await.unwrap();
            let mut client = TcpStream::connect(address).await.unwrap();
            client.write_all(V1).await.unwrap();
            client.write_all(b"ping").await.unwrap();
            let mut pong = [0; 4];
            timeout(Duration::from_secs(3), client.read_exact(&mut pong))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&pong, b"ping");
            client.shutdown().await.unwrap();
            assert!(read_reply(&mut client).await.is_empty());
            entry.shutdown().await.unwrap();
            exit.shutdown().await.unwrap();
            assert_eq!(total(&entry_db), 8);
            assert_eq!(total(&exit_db), 8);
        }
    }
}

#[tokio::test]
async fn mismatched_tls_proxy_placement_fails_without_forwarding_payload() {
    let cert = tls::Certificates::new();
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("exit.db")).unwrap();
    let exit = Engine::with_tls_directory(db.clone(), Some(cert.root.clone()));
    let mut er = rule(echo.address, Protocol::Tcp);
    er.inbound_tls = Some(TlsServer {
        identity: "server".into(),
        client_ca: None,
    });
    let mut input = inbound(ProxyAccept::V2);
    input.placement = ProxyPlacement::InsideTls;
    er.inbound_proxy = Some(input);
    let hop = er.listen;
    exit.apply(config(er)).await.unwrap();
    let entry = Engine::with_tls_directory(
        Store::open(&temp.path().join("entry.db")).unwrap(),
        Some(cert.root.clone()),
    );
    let mut r = rule(hop, Protocol::Tcp);
    r.targets[0].tls = Some(TlsClient {
        server_name: "relay.test".into(),
        ca: Some("root".into()),
        identity: None,
    });
    r.targets[0].proxy_protocol = Some(outbound(ProxyVersion::V2));
    let address = r.listen;
    entry.apply(config(r)).await.unwrap();
    let mut client = TcpStream::connect(address).await.unwrap();
    client.write_all(b"do-not-forward").await.unwrap();
    rejected(&mut client).await;
    entry.shutdown().await.unwrap();
    exit.shutdown().await.unwrap();
    assert_eq!(total(&db), 0);
}

#[tokio::test]
async fn udp_headers_are_per_packet_sessions_include_original_identity_and_replies_use_real_peer() {
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let mut r = rule(backend.local_addr().unwrap(), Protocol::Udp);
    r.inbound_proxy = Some(inbound(ProxyAccept::V2));
    r.targets[0].proxy_protocol = Some(outbound(ProxyVersion::V2));
    r.allow_sources = vec!["198.51.100.0/24".parse().unwrap()];
    r.udp_max_sessions = 2;
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut peers = HashSet::new();
    let mut buf = [0; 4096];
    for (source, payload) in [
        ("198.51.100.7:1", b"one".as_slice()),
        ("198.51.100.8:2", b"two"),
        ("198.51.100.7:1", b"third"),
    ] {
        let header = v2_frame(source.parse().unwrap(), claimed().destination, false);
        let mut wire = header.clone();
        wire.extend_from_slice(payload);
        client.send_to(&wire, address).await.unwrap();
        let (n, peer) = timeout(Duration::from_secs(3), backend.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], wire);
        peers.insert(peer);
        backend.send_to(payload, peer).await.unwrap();
        let (n, reply_from) = timeout(Duration::from_secs(3), client.recv_from(&mut buf))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buf[..n], payload);
        assert_eq!(reply_from, address);
    }
    assert_eq!(peers.len(), 2);
    assert_eq!(engine.stats().active_udp, 2);
    client.send_to(b"missing header", address).await.unwrap();
    let mut denied = v2_frame(
        "198.51.100.9:3".parse().unwrap(),
        claimed().destination,
        false,
    );
    denied.extend_from_slice(b"over session cap");
    client.send_to(&denied, address).await.unwrap();
    assert!(
        timeout(Duration::from_millis(150), backend.recv_from(&mut buf))
            .await
            .is_err()
    );
    engine.shutdown().await.unwrap();
    assert_eq!(total(&db), 22);
    assert_eq!(engine.stats().dropped_datagrams, 2);
}

#[tokio::test]
async fn udp_same_claim_from_distinct_proxies_keeps_reply_channels_separate() {
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(backend.local_addr().unwrap(), Protocol::Udp);
    r.inbound_proxy = Some(inbound(ProxyAccept::V2));
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut target_peers = HashSet::new();
    let mut buffer = [0; 128];
    for (client, body) in [(&first, b"first".as_slice()), (&second, b"second")] {
        let mut bytes = v2_frame(claimed().source, claimed().destination, false);
        bytes.extend_from_slice(body);
        client.send_to(&bytes, address).await.unwrap();
        let (n, peer) = timeout(Duration::from_secs(3), backend.recv_from(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..n], body);
        target_peers.insert(peer);
        backend.send_to(body, peer).await.unwrap();
        let n = timeout(Duration::from_secs(3), client.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..n], body);
    }
    assert_eq!(target_peers.len(), 2);
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn udp_wildcard_tracks_real_destination_and_reply_source_for_ipv4_ipv6() {
    for bind in ["0.0.0.0", "::"] {
        let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let temp = tempfile::tempdir().unwrap();
        let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
        let mut r = rule(backend.local_addr().unwrap(), Protocol::Udp);
        r.listen.set_ip(bind.parse().unwrap());
        r.targets[0].proxy_protocol = Some(outbound(ProxyVersion::V2));
        let port = r.listen.port();
        engine.apply(config(r)).await.unwrap();
        let mut destinations: Vec<IpAddr> = vec![if bind == "::" {
            "::1".parse().unwrap()
        } else {
            "127.0.0.1".parse().unwrap()
        }];
        if bind != "::"
            && let Some(ip) = if_addrs::get_if_addrs()
                .unwrap()
                .into_iter()
                .map(|i| i.ip())
                .find(|ip| {
                    ip.is_ipv4() && !ip.is_loopback() && !ip.is_unspecified() && !ip.is_multicast()
                })
        {
            destinations.push(ip);
        }
        let client = UdpSocket::bind(if bind == "::" {
            "[::1]:0"
        } else {
            "127.0.0.1:0"
        })
        .await
        .unwrap();
        let source = client.local_addr().unwrap();
        let mut buffer = [0; 128];
        for ip in destinations {
            let destination = SocketAddr::new(ip, port);
            client.send_to(b"wildcard", destination).await.unwrap();
            let (n, peer) = timeout(Duration::from_secs(3), backend.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            let mut expected = v2_frame(source, destination, false);
            expected.extend_from_slice(b"wildcard");
            assert_eq!(&buffer[..n], expected);
            backend.send_to(b"reply", peer).await.unwrap();
            let (n, peer) = timeout(Duration::from_secs(3), client.recv_from(&mut buffer))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&buffer[..n], b"reply");
            assert_eq!(
                peer, destination,
                "reply must originate at the IP that received the query"
            );
        }
        engine.shutdown().await.unwrap();
    }
}

#[tokio::test]
async fn udp_malformed_crc_wrong_transport_and_denied_sources_do_not_reach_target() {
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    let mut r = rule(backend.local_addr().unwrap(), Protocol::Udp);
    r.inbound_proxy = Some(inbound(ProxyAccept::V2));
    r.allow_sources = vec!["192.0.2.0/24".parse().unwrap()];
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut bad_crc = hex(V2_CRC_HEX);
    bad_crc[13] = 0x12;
    for frame in [
        V1.to_vec(),
        vec![0; 15],
        hex(V2_CRC_HEX),
        bad_crc,
        v2_frame(claimed().source, claimed().destination, false),
    ] {
        client.send_to(&frame, address).await.unwrap();
    }
    assert!(
        timeout(Duration::from_millis(150), backend.recv(&mut [0; 128]))
            .await
            .is_err()
    );
    engine.shutdown().await.unwrap();
    assert_eq!(total(&db), 0);
    assert_eq!(engine.stats().dropped_datagrams, 5);
}

#[tokio::test]
async fn udp_proxy_hop_preserves_empty_datagrams_ipv6_claims_and_shared_quota() {
    let echo = udp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let exit_db = Store::open(&temp.path().join("exit.db")).unwrap();
    let exit = Engine::new(exit_db.clone());
    let mut er = rule(echo.address, Protocol::Udp);
    er.inbound_proxy = Some(inbound(ProxyAccept::V2));
    er.allow_sources = vec!["2001:db8::/32".parse().unwrap()];
    er.quota_bytes = Some(8);
    let hop = er.listen;
    exit.apply(config(er)).await.unwrap();
    let entry_db = Store::open(&temp.path().join("entry.db")).unwrap();
    let entry = Engine::new(entry_db.clone());
    let mut r = rule(hop, Protocol::Udp);
    r.inbound_proxy = Some(inbound(ProxyAccept::V2));
    let mut policy = outbound(ProxyVersion::V2);
    policy.checksum = true;
    r.targets[0].proxy_protocol = Some(policy);
    let address = r.listen;
    entry.apply(config(r)).await.unwrap();
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let prefix = v2_frame(
        "[2001:db8::7]:1".parse().unwrap(),
        "[2001:db8::9]:443".parse().unwrap(),
        false,
    );
    let mut buffer = [0; 16];
    for payload in [b"".as_slice(), b"four"] {
        let mut wire = prefix.clone();
        wire.extend_from_slice(payload);
        client.send_to(&wire, address).await.unwrap();
        let n = timeout(Duration::from_secs(3), client.recv(&mut buffer))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&buffer[..n], payload);
    }
    let mut wire = prefix;
    wire.extend_from_slice(b"denied");
    client.send_to(&wire, address).await.unwrap();
    assert!(
        timeout(Duration::from_millis(150), client.recv(&mut buffer))
            .await
            .is_err()
    );
    entry.shutdown().await.unwrap();
    exit.shutdown().await.unwrap();
    assert_eq!(total(&exit_db), 8);
    assert_eq!(total(&entry_db), 14);
}

#[test]
fn unsupported_proxy_combinations_and_missing_trust_are_rejected() {
    let mut c = config(rule("127.0.0.1:30001".parse().unwrap(), Protocol::Both));
    c.rules[0].inbound_proxy = Some(inbound(ProxyAccept::Any));
    assert!(c.validate().is_err());
    c.rules[0].inbound_proxy = Some(inbound(ProxyAccept::V2));
    c.validate().unwrap();
    c.rules[0]
        .inbound_proxy
        .as_mut()
        .unwrap()
        .trusted_sources
        .clear();
    assert!(c.validate().is_err());
    c.rules[0].inbound_proxy = Some(inbound(ProxyAccept::V2));
    c.rules[0].targets[0].proxy_protocol = Some(outbound(ProxyVersion::V1));
    assert!(c.validate().is_err());
    c.rules[0].protocol = Protocol::Tcp;
    c.rules[0].targets[0]
        .proxy_protocol
        .as_mut()
        .unwrap()
        .checksum = true;
    assert!(c.validate().is_err());
    c.rules[0].targets[0].proxy_protocol = Some(outbound(ProxyVersion::V2));
    c.rules[0].inbound_proxy.as_mut().unwrap().placement = ProxyPlacement::InsideTls;
    assert!(c.validate().is_err());
    c.rules[0].inbound_proxy.as_mut().unwrap().placement = ProxyPlacement::BeforeTls;
    c.rules[0].targets[0]
        .proxy_protocol
        .as_mut()
        .unwrap()
        .placement = ProxyPlacement::InsideTls;
    assert!(c.validate().is_err());
    c.rules[0].targets[0]
        .proxy_protocol
        .as_mut()
        .unwrap()
        .placement = ProxyPlacement::BeforeTls;
    c.rules[0].inbound_proxy.as_mut().unwrap().max_header_bytes = 65552;
    assert!(c.validate().is_err());
}

#[tokio::test]
async fn source_hash_uses_claimed_ip_and_normalizes_mapped_ipv4() {
    let a = tcp_echo_at("127.0.0.1:0", Some(b'A')).await;
    let b = tcp_echo_at("127.0.0.1:0", Some(b'B')).await;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(a.address, Protocol::Tcp);
    r.inbound_proxy = Some(inbound(ProxyAccept::V1));
    r.balance = Balance::SourceHash;
    r.targets.push(Target {
        address: b.address.to_string(),
        weight: 1,
        tls: None,
        proxy_protocol: None,
        websocket: None,
    });
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    for (header, expected) in [
        (
            b"PROXY TCP4 198.51.100.1 203.0.113.9 1 443\r\n".as_slice(),
            b'A',
        ),
        (b"PROXY TCP4 198.51.100.4 203.0.113.9 2 443\r\n", b'B'),
        (
            b"PROXY TCP6 ::ffff:198.51.100.1 ::ffff:203.0.113.9 3 443\r\n",
            b'A',
        ),
    ] {
        let mut client = TcpStream::connect(address).await.unwrap();
        client.write_all(header).await.unwrap();
        let mut mark = [0];
        timeout(Duration::from_secs(3), client.read_exact(&mut mark))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(mark[0], expected);
    }
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn inside_tls_proxy_does_not_bypass_required_client_certificate() {
    use tokio_rustls::rustls::pki_types::ServerName;
    let cert = tls::Certificates::new();
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::with_tls_directory(db.clone(), Some(cert.root.clone()));
    let mut r = rule(echo.address, Protocol::Tcp);
    r.inbound_tls = Some(TlsServer {
        identity: "server".into(),
        client_ca: Some("root".into()),
    });
    let mut policy = inbound(ProxyAccept::V1);
    policy.placement = ProxyPlacement::InsideTls;
    r.inbound_proxy = Some(policy);
    r.allow_sources = vec!["198.51.100.7/32".parse().unwrap()];
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    let raw = TcpStream::connect(address).await.unwrap();
    let mut client = cert
        .connector(true)
        .connect(ServerName::try_from("relay.test").unwrap(), raw)
        .await
        .unwrap();
    client.write_all(V1).await.unwrap();
    client.write_all(b"good").await.unwrap();
    client.flush().await.unwrap();
    let mut reply = [0; 4];
    timeout(Duration::from_secs(3), client.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"good");
    drop(client);
    timeout(Duration::from_secs(3), async {
        let raw = TcpStream::connect(address).await.unwrap();
        if let Ok(mut missing) = cert
            .connector(false)
            .connect(ServerName::try_from("relay.test").unwrap(), raw)
            .await
        {
            let _ = missing.write_all(V1).await;
            let _ = missing.write_all(b"forged").await;
            let _ = missing.flush().await;
            assert!(matches!(missing.read(&mut [0; 32]).await, Ok(0) | Err(_)));
        }
    })
    .await
    .unwrap();
    engine.shutdown().await.unwrap();
    assert_eq!(total(&db), 8);
}
