use http_body_util::Empty;
use hyper::{Request, body::Bytes, client::conn::http2::handshake};
use hyper_util::rt::{TokioExecutor, TokioIo};
use relay_platform::{http_connect, http2_connect};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2c_connect_tunnels_to_a_private_target() {
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut buffer = [0u8; 64];
        let size = stream.read(&mut buffer).await.unwrap();
        stream.write_all(&buffer[..size]).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let proxy = tokio::spawn(http2_connect::serve(
        listener,
        http_connect::ServerConfig {
            username: None,
            password: None,
            allow_private_destinations: true,
        },
    ));
    let tcp = TcpStream::connect(proxy_addr).await.unwrap();
    let (mut sender, connection) = handshake(TokioExecutor::new(), TokioIo::new(tcp))
        .await
        .unwrap();
    tokio::spawn(connection);
    let request = Request::builder()
        .method(hyper::Method::CONNECT)
        .uri(format!("http://{target_addr}"))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let mut response = sender.send_request(request).await.unwrap();
    assert_eq!(response.status(), hyper::StatusCode::OK);
    let upgraded = timeout(Duration::from_secs(2), hyper::upgrade::on(&mut response))
        .await
        .unwrap()
        .unwrap();
    let mut tunnel = TokioIo::new(upgraded);
    tunnel.write_all(b"h2-connect").await.unwrap();
    let mut reply = [0u8; 10];
    timeout(Duration::from_secs(2), tunnel.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"h2-connect");
    timeout(Duration::from_secs(2), echo)
        .await
        .unwrap()
        .unwrap();
    proxy.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2c_connect_enforces_basic_auth() {
    use base64::{Engine as _, engine::general_purpose::STANDARD};
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut buffer = [0u8; 64];
        let size = stream.read(&mut buffer).await.unwrap();
        stream.write_all(&buffer[..size]).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let proxy_addr = listener.local_addr().unwrap();
    let proxy = tokio::spawn(http2_connect::serve(
        listener,
        http_connect::ServerConfig {
            username: Some("user".into()),
            password: Some("pass".into()),
            allow_private_destinations: true,
        },
    ));
    let tcp = TcpStream::connect(proxy_addr).await.unwrap();
    let (mut sender, connection) = handshake(TokioExecutor::new(), TokioIo::new(tcp))
        .await
        .unwrap();
    tokio::spawn(connection);
    let unauthorized = Request::builder()
        .method(hyper::Method::CONNECT)
        .uri(format!("http://{target_addr}"))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let response = sender.send_request(unauthorized).await.unwrap();
    assert_eq!(
        response.status(),
        hyper::StatusCode::PROXY_AUTHENTICATION_REQUIRED
    );
    let credentials = STANDARD.encode("user:pass");
    let authorized = Request::builder()
        .method(hyper::Method::CONNECT)
        .uri(format!("http://{target_addr}"))
        .header("proxy-authorization", format!("Basic {credentials}"))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let mut response = sender.send_request(authorized).await.unwrap();
    assert_eq!(response.status(), hyper::StatusCode::OK);
    let upgraded = timeout(Duration::from_secs(2), hyper::upgrade::on(&mut response))
        .await
        .unwrap()
        .unwrap();
    let mut tunnel = TokioIo::new(upgraded);
    tunnel.write_all(b"auth").await.unwrap();
    let mut reply = [0u8; 4];
    timeout(Duration::from_secs(2), tunnel.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"auth");
    timeout(Duration::from_secs(2), echo)
        .await
        .unwrap()
        .unwrap();
    proxy.abort();
}
