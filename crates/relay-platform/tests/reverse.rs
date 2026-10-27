use relay_platform::reverse;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn reverse_tunnel_bridges_two_sequential_public_connections() {
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control.local_addr().unwrap();
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public_addr = public.local_addr().unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        for _ in 0..2 {
            let (mut stream, _) = target.accept().await.unwrap();
            let mut buffer = [0u8; 64];
            let size = stream.read(&mut buffer).await.unwrap();
            stream.write_all(&buffer[..size]).await.unwrap();
            stream.shutdown().await.unwrap();
        }
    });
    let server = tokio::spawn(reverse::serve(control, public, "test-token".into()));
    let client = tokio::spawn(reverse::client(
        control_addr,
        target_addr.to_string(),
        "test-token".into(),
    ));
    for payload in [b"first".as_slice(), b"second".as_slice()] {
        let mut exposed = timeout(Duration::from_secs(2), TcpStream::connect(public_addr))
            .await
            .unwrap()
            .unwrap();
        exposed.write_all(payload).await.unwrap();
        let mut reply = vec![0u8; payload.len()];
        timeout(Duration::from_secs(2), exposed.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(reply, payload);
        drop(exposed);
    }
    timeout(Duration::from_secs(2), echo)
        .await
        .unwrap()
        .unwrap();
    server.abort();
    client.abort();
}

#[tokio::test]
async fn reverse_tunnel_rejects_a_bad_token() {
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control.local_addr().unwrap();
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = tokio::spawn(reverse::serve(control, public, "right-token".into()));
    let mut stream = TcpStream::connect(control_addr).await.unwrap();
    stream.write_all(b"REVERSE wrong-token\n").await.unwrap();
    let mut reply = [0u8; 5];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"DENY\n");
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn reverse_session_pool_serves_two_public_connections_concurrently() {
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control.local_addr().unwrap();
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public_addr = public.local_addr().unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let mut tasks = Vec::new();
        for _ in 0..2 {
            let (mut stream, _) = target.accept().await.unwrap();
            tasks.push(tokio::spawn(async move {
                let mut buffer = [0u8; 64];
                let size = stream.read(&mut buffer).await.unwrap();
                stream.write_all(&buffer[..size]).await.unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
    });
    let server = tokio::spawn(reverse::serve(control, public, "pool-token".into()));
    let client = tokio::spawn(reverse::client_pool(
        control_addr,
        target_addr.to_string(),
        "pool-token".into(),
        2,
    ));
    let first = timeout(Duration::from_secs(2), TcpStream::connect(public_addr))
        .await
        .unwrap()
        .unwrap();
    let second = timeout(Duration::from_secs(2), TcpStream::connect(public_addr))
        .await
        .unwrap()
        .unwrap();
    let mut a = first;
    let mut b = second;
    a.write_all(b"alpha").await.unwrap();
    b.write_all(b"bravo").await.unwrap();
    let mut ar = [0u8; 5];
    let mut br = [0u8; 5];
    timeout(Duration::from_secs(2), a.read_exact(&mut ar))
        .await
        .unwrap()
        .unwrap();
    timeout(Duration::from_secs(2), b.read_exact(&mut br))
        .await
        .unwrap()
        .unwrap();
    assert_eq!((&ar, &br), (b"alpha", b"bravo"));
    timeout(Duration::from_secs(2), echo)
        .await
        .unwrap()
        .unwrap();
    server.abort();
    client.abort();
}
