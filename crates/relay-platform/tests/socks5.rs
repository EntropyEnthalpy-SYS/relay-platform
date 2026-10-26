mod common;
use common::*;
use relay_platform::{engine::Engine, model::*, socks5, store::Store};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
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
    assert!(
        rule.validate().is_err(),
        "UDP ASSOCIATE is not implemented yet"
    );
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
