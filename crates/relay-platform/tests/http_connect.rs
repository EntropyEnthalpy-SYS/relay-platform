mod common;
use common::*;
use relay_platform::{engine::Engine, http_connect, model::*, store::Store};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::timeout,
};

#[test]
fn http_connect_rules_require_tcp_no_targets_and_paired_credentials() {
    let mut rule = rule("127.0.0.1:9000".parse().unwrap(), Protocol::Tcp);
    rule.inbound_http_connect = Some(http_connect::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: false,
    });
    assert!(
        rule.validate().is_err(),
        "proxy inbound must not keep fixed targets"
    );
    rule.targets.clear();
    rule.validate().unwrap();
    rule.protocol = Protocol::Both;
    assert!(rule.validate().is_err(), "HTTP CONNECT is TCP only");
    rule.protocol = Protocol::Tcp;
    rule.inbound_http_connect = Some(http_connect::ServerConfig {
        username: Some("user".into()),
        password: None,
        allow_private_destinations: false,
    });
    assert!(rule.validate().is_err());
    rule.inbound_http_connect = None;
    rule.inbound_socks5 = Some(relay_platform::socks5::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: false,
    });
    rule.inbound_http_connect = Some(http_connect::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: false,
    });
    assert!(rule.validate().is_err(), "proxy inbounds must be exclusive");
}

#[tokio::test]
async fn http_connect_reaches_a_real_target_and_relays_bytes() {
    let backend = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let backend_address = backend.local_addr().unwrap();
    let accept = tokio::spawn(async move {
        while let Ok((mut socket, _)) = backend.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 64];
                while let Ok(read) = socket.read(&mut buffer).await {
                    if read == 0 || socket.write_all(&buffer[..read]).await.is_err() {
                        break;
                    }
                }
            });
        }
    });
    let mut rule = rule(backend_address, Protocol::Tcp);
    rule.targets.clear();
    rule.inbound_http_connect = Some(http_connect::ServerConfig {
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
    client
        .write_all(
            format!(
                "CONNECT 127.0.0.1:{} HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
                backend_address.port()
            )
            .as_bytes(),
        )
        .await
        .unwrap();
    let mut response = vec![];
    let mut byte = [0u8; 1];
    while !response.ends_with(b"\r\n\r\n") {
        client.read_exact(&mut byte).await.unwrap();
        response.push(byte[0]);
        assert!(response.len() < 2048);
    }
    assert!(
        response.starts_with(b"HTTP/1.1 200"),
        "{}",
        String::from_utf8_lossy(&response)
    );
    client.write_all(b"hello http connect").await.unwrap();
    let mut echoed = [0u8; 18];
    timeout(Duration::from_secs(2), client.read_exact(&mut echoed))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&echoed, b"hello http connect");
    engine.shutdown().await.unwrap();
    accept.abort();
}
