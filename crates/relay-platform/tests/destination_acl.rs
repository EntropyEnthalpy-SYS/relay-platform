mod common;
use common::*;
use relay_platform::{engine::Engine, model::*, store::Store};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::mpsc,
    time::timeout,
};

async fn echo_listener() -> (
    std::net::SocketAddr,
    mpsc::UnboundedReceiver<()>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (tx, rx) = mpsc::unbounded_channel();
    let task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            let _ = tx.send(());
            let mut buffer = [0u8; 16];
            if let Ok(read) = socket.read(&mut buffer).await {
                let _ = socket.write_all(&buffer[..read]).await;
            }
        }
    });
    (address, rx, task)
}

#[tokio::test]
async fn destination_deny_prevents_the_target_connection() {
    let (target, mut accepted, backend) = echo_listener().await;
    let mut rule = rule(target, Protocol::Tcp);
    rule.deny_destinations = vec!["127.0.0.1".into()];
    let listen = rule.listen;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    engine.apply(config(rule)).await.unwrap();
    let mut client = TcpStream::connect(listen).await.unwrap();
    client.write_all(b"blocked").await.unwrap();
    assert!(
        timeout(Duration::from_millis(300), accepted.recv())
            .await
            .is_err()
    );
    let mut reply = [0u8; 1];
    if let Ok(Ok(read)) = timeout(Duration::from_millis(300), client.read(&mut reply)).await {
        assert_eq!(read, 0, "denied destination must not return data");
    }
    engine.shutdown().await.unwrap();
    backend.abort();
}

#[tokio::test]
async fn destination_allowlist_permits_a_matching_ip() {
    let (target, mut accepted, backend) = echo_listener().await;
    let mut rule = rule(target, Protocol::Tcp);
    rule.allow_destinations = vec!["127.0.0.0/8".into()];
    let listen = rule.listen;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    engine.apply(config(rule)).await.unwrap();
    let mut client = TcpStream::connect(listen).await.unwrap();
    client.write_all(b"allowed").await.unwrap();
    timeout(Duration::from_secs(2), accepted.recv())
        .await
        .unwrap()
        .unwrap();
    let mut reply = [0u8; 7];
    timeout(Duration::from_secs(2), client.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"allowed");
    engine.shutdown().await.unwrap();
    backend.abort();
}
