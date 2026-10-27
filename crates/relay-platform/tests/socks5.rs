mod common;
use common::*;
use relay_platform::{engine::Engine, model::*, shadowsocks, socks5, store::Store};
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
        if let Ok((size, peer)) = backend.recv_from(&mut buffer).await {
            let _ = backend.send_to(&buffer[..size], peer).await;
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
    let _ = control.shutdown().await;
    drop(control);
    engine.shutdown().await.unwrap();
}
