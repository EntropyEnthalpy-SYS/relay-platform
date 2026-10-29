mod common;
use common::*;
use relay_platform::{engine::Engine, model::*, shadowsocks, socks5, store::Store};
use std::net::SocketAddr;
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    time::timeout,
};

#[test]
fn socks5_rules_require_tcp_no_targets_and_paired_credentials() {
    let mut rule = rule("127.0.0.1:9000".parse().unwrap(), Protocol::Tcp);
    rule.inbound_socks5 = Some(socks5::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: false,
    });
    assert!(
        rule.validate().is_err(),
        "a SOCKS5 server must not keep fixed targets"
    );
    rule.targets.clear();
    rule.validate().unwrap();
    rule.protocol = Protocol::Both;
    rule.validate().unwrap();
    rule.listen_end_port = Some(rule.listen.port() + 1);
    assert!(
        rule.validate().is_err(),
        "SOCKS5 UDP requires a single listen port"
    );
    rule.listen_end_port = None;
    rule.protocol = Protocol::Tcp;
    rule.inbound_socks5 = Some(socks5::ServerConfig {
        username: Some("user".into()),
        password: None,
        allow_private_destinations: false,
    });
    assert!(rule.validate().is_err());
    rule.inbound_socks5 = None;
    rule.inbound_shadowsocks = Some(relay_platform::shadowsocks::ServerConfig {
        method: relay_platform::shadowsocks::Method::Blake3Aes128Gcm,
        password: "AAECAwQFBgcICQoLDA0ODw==".into(),
        allow_private_destinations: false,
        udp_over_tcp: false,
    });
    rule.inbound_socks5 = Some(socks5::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: false,
    });
    assert!(
        rule.validate().is_err(),
        "inbound protocols must be exclusive"
    );
}

#[tokio::test]
async fn socks5_connect_reaches_a_real_target_and_relays_bytes() {
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let accept = tokio::spawn(async move {
        loop {
            let Ok((mut socket, _)) = backend.accept().await else {
                break;
            };
            tokio::spawn(async move {
                let mut buffer = [0u8; 64];
                while let Ok(read) = socket.read(&mut buffer).await {
                    if read == 0 {
                        break;
                    }
                    if socket.write_all(&buffer[..read]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let mut rule = rule(backend_address, Protocol::Tcp);
    rule.targets.clear();
    rule.inbound_socks5 = Some(socks5::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: true,
    });
    let listen = rule.listen;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    engine.apply(config(rule)).await.unwrap();

    let mut client = timeout(Duration::from_secs(2), TcpStream::connect(listen))
        .await
        .unwrap()
        .unwrap();
    client.write_all(&[5, 1, 0]).await.unwrap();
    let mut selected = [0u8; 2];
    client.read_exact(&mut selected).await.unwrap();
    assert_eq!(selected, [5, 0]);
    let port = backend_address.port();
    client
        .write_all(&[5, 1, 0, 1, 127, 0, 0, 1, (port >> 8) as u8, port as u8])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    client.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[0], 5);
    assert_eq!(reply[1], 0, "SOCKS5 CONNECT failed");
    client.write_all(b"hello socks5").await.unwrap();
    let mut echoed = [0u8; 12];
    timeout(Duration::from_secs(2), client.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echoed, b"hello socks5");
    engine.shutdown().await.unwrap();
    accept.abort();
}

#[tokio::test]
async fn socks5_udp_associate_relays_a_datagram_to_a_real_target() {
    let backend = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let _echo = tokio::spawn(async move {
        let mut buffer = [0u8; 128];
        loop {
            let Ok((size, peer)) = backend.recv_from(&mut buffer).await else {
                break;
            };
            if backend.send_to(&buffer[..size], peer).await.is_err() {
                break;
            }
        }
    });
    let mut rule = rule(backend_address, Protocol::Both);
    rule.targets.clear();
    rule.inbound_socks5 = Some(socks5::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: true,
    });
    let listen = rule.listen;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    engine.apply(config(rule)).await.unwrap();

    let mut control = TcpStream::connect(listen).await.unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut selected = [0u8; 2];
    control.read_exact(&mut selected).await.unwrap();
    assert_eq!(selected, [5, 0]);
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut bind = [0u8; 10];
    timeout(Duration::from_secs(2), control.read_exact(&mut bind))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&bind[..4], &[5, 0, 0, 1]);
    let relay = std::net::SocketAddr::from((
        [bind[4], bind[5], bind[6], bind[7]],
        u16::from_be_bytes([bind[8], bind[9]]),
    ));
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let packet =
        socks5::encode_udp_datagram(&shadowsocks::Destination::Ip(backend_address), b"udp-ping");
    client.send_to(&packet, relay).await.unwrap();
    let mut reply = [0u8; 128];
    let (size, _) = timeout(Duration::from_secs(2), client.recv_from(&mut reply))
        .await
        .unwrap()
        .unwrap();
    let datagram = socks5::parse_udp_datagram(&reply[..size]).unwrap();
    assert_eq!(datagram.payload, b"udp-ping");
    assert_eq!(
        datagram.destination.to_string(),
        backend_address.to_string()
    );
    // The association reuses one outbound socket for many datagrams.
    let mut expected = std::collections::HashSet::new();
    for sequence in 0..16u8 {
        let payload = format!("udp-{sequence}");
        expected.insert(payload.clone());
        client
            .send_to(
                &socks5::encode_udp_datagram(
                    &shadowsocks::Destination::Ip(backend_address),
                    payload.as_bytes(),
                ),
                relay,
            )
            .await
            .unwrap();
    }
    for _ in 0..16 {
        let (size, _) = timeout(Duration::from_secs(2), client.recv_from(&mut reply))
            .await
            .unwrap()
            .unwrap();
        let datagram = socks5::parse_udp_datagram(&reply[..size]).unwrap();
        assert!(expected.remove(std::str::from_utf8(&datagram.payload).unwrap()));
    }
    assert!(expected.is_empty());

    let _ = control.shutdown().await;
    drop(control);
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn socks5_bind_accepts_an_inbound_connection_and_relays_bytes() {
    let mut rule = rule("127.0.0.1:9000".parse().unwrap(), Protocol::Tcp);
    rule.targets.clear();
    rule.inbound_socks5 = Some(socks5::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: true,
    });
    let listen = rule.listen;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    engine.apply(config(rule)).await.unwrap();
    let mut control = TcpStream::connect(listen).await.unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut selected = [0u8; 2];
    control.read_exact(&mut selected).await.unwrap();
    assert_eq!(selected, [5, 0]);
    control
        .write_all(&[5, 2, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut first = [0u8; 10];
    timeout(Duration::from_secs(2), control.read_exact(&mut first))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&first[..4], &[5, 0, 0, 1]);
    let bind = SocketAddr::from((
        [first[4], first[5], first[6], first[7]],
        u16::from_be_bytes([first[8], first[9]]),
    ));
    let mut inbound = TcpStream::connect(bind).await.unwrap();
    let mut second = [0u8; 10];
    timeout(Duration::from_secs(2), control.read_exact(&mut second))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&second[..4], &[5, 0, 0, 1]);
    inbound.write_all(b"from-inbound").await.unwrap();
    let mut buffer = [0u8; 12];
    timeout(Duration::from_secs(2), control.read_exact(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&buffer, b"from-inbound");
    control.write_all(b"from-control").await.unwrap();
    let mut reply = [0u8; 12];
    timeout(Duration::from_secs(2), inbound.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"from-control");
    drop(inbound);
    drop(control);
    engine.shutdown().await.unwrap();
}

async fn socks5_control(listen: SocketAddr) -> TcpStream {
    let mut control = TcpStream::connect(listen).await.unwrap();
    control.write_all(&[5, 1, 0]).await.unwrap();
    let mut selected = [0u8; 2];
    control.read_exact(&mut selected).await.unwrap();
    assert_eq!(selected, [5, 0]);
    control
}

async fn socks5_udp_associate(listen: SocketAddr) -> (TcpStream, SocketAddr) {
    let mut control = socks5_control(listen).await;
    control
        .write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut reply = [0u8; 10];
    control.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply[..4], &[5, 0, 0, 1]);
    (
        control,
        SocketAddr::from((
            [reply[4], reply[5], reply[6], reply[7]],
            u16::from_be_bytes([reply[8], reply[9]]),
        )),
    )
}

fn udp_packet(target: SocketAddr, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, 0, 0, 1];
    packet.extend_from_slice(
        &target
            .ip()
            .to_string()
            .parse::<std::net::Ipv4Addr>()
            .unwrap()
            .octets(),
    );
    packet.extend_from_slice(&target.port().to_be_bytes());
    packet.extend_from_slice(payload);
    packet
}

#[tokio::test]
async fn socks5_udp_associations_are_isolated_behind_one_ip() {
    let mut rule = rule("127.0.0.1:9000".parse().unwrap(), Protocol::Both);
    rule.targets.clear();
    rule.inbound_socks5 = Some(socks5::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: true,
    });
    let listen = rule.listen;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    engine.apply(config(rule)).await.unwrap();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (a_control, a_relay) = socks5_udp_associate(listen).await;
    let (b_control, b_relay) = socks5_udp_associate(listen).await;
    assert_ne!(a_relay, b_relay);
    let a = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let b = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    a.send_to(
        &udp_packet(target.local_addr().unwrap(), b"A-only"),
        a_relay,
    )
    .await
    .unwrap();
    let mut target_buffer = [0u8; 64];
    let (body_size, outbound) = target.recv_from(&mut target_buffer).await.unwrap();
    assert_eq!(&target_buffer[..body_size], b"A-only");
    target
        .send_to(&target_buffer[..body_size], outbound)
        .await
        .unwrap();
    let mut reply = [0u8; 64];
    let (size, _) = timeout(Duration::from_secs(2), a.recv_from(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply[10..size], b"A-only");
    b.send_to(
        &udp_packet(target.local_addr().unwrap(), b"B-only"),
        b_relay,
    )
    .await
    .unwrap();
    let (body_size, outbound) = target.recv_from(&mut target_buffer).await.unwrap();
    assert_eq!(&target_buffer[..body_size], b"B-only");
    target
        .send_to(&target_buffer[..body_size], outbound)
        .await
        .unwrap();
    let (size, _) = timeout(Duration::from_secs(2), b.recv_from(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply[10..size], b"B-only");
    assert!(
        timeout(Duration::from_millis(150), a.recv_from(&mut reply))
            .await
            .is_err()
    );
    drop(a_control);
    drop(b_control);
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn socks5_udp_replies_stop_with_the_control_connection() {
    let mut rule = rule("127.0.0.1:9000".parse().unwrap(), Protocol::Both);
    rule.targets.clear();
    rule.idle_timeout_secs = 1;
    rule.inbound_socks5 = Some(socks5::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: true,
    });
    let listen = rule.listen;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    engine.apply(config(rule)).await.unwrap();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let (control, relay) = socks5_udp_associate(listen).await;
    let client = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    client
        .send_to(&udp_packet(target.local_addr().unwrap(), b"before"), relay)
        .await
        .unwrap();
    let mut target_buffer = [0u8; 64];
    let (body_size, outbound) = target.recv_from(&mut target_buffer).await.unwrap();
    target
        .send_to(&target_buffer[..body_size], outbound)
        .await
        .unwrap();
    let mut reply = [0u8; 64];
    timeout(Duration::from_secs(2), client.recv_from(&mut reply))
        .await
        .unwrap()
        .unwrap();
    drop(control);
    tokio::time::sleep(Duration::from_millis(1300)).await;
    target.send_to(b"after-close", outbound).await.unwrap();
    assert!(
        timeout(Duration::from_millis(300), client.recv_from(&mut reply))
            .await
            .is_err()
    );
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn socks5_bind_rejects_a_peer_outside_the_requested_policy() {
    let mut rule = rule("127.0.0.1:9000".parse().unwrap(), Protocol::Tcp);
    rule.targets.clear();
    rule.connect_timeout_ms = 100;
    rule.deny_destinations = vec!["127.0.0.0/8".into()];
    rule.inbound_socks5 = Some(socks5::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: false,
    });
    let listen = rule.listen;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    engine.apply(config(rule)).await.unwrap();
    let mut control = socks5_control(listen).await;
    control
        .write_all(&[5, 2, 0, 1, 203, 0, 113, 55, 0xa4, 0x10])
        .await
        .unwrap();
    let mut bind_reply = [0u8; 10];
    control.read_exact(&mut bind_reply).await.unwrap();
    assert_eq!(&bind_reply[..4], &[5, 0, 0, 1]);
    let bind = SocketAddr::from((
        [bind_reply[4], bind_reply[5], bind_reply[6], bind_reply[7]],
        u16::from_be_bytes([bind_reply[8], bind_reply[9]]),
    ));
    let inbound = TcpStream::connect(bind).await.unwrap();
    let mut failure = [0u8; 10];
    timeout(Duration::from_secs(2), control.read_exact(&mut failure))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(failure[1], 5);
    drop(inbound);
    drop(control);
    engine.shutdown().await.unwrap();
}
