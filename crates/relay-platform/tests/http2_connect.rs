#[allow(dead_code)]
#[path = "common/tls.rs"]
mod tls;
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn h2_connect_over_tls_tunnels_to_a_private_target() {
    let certs = tls::Certificates::new();
    let acceptor = http2_connect::tls_acceptor_h2(
        &certs.root.join("server/cert.pem"),
        &certs.root.join("server/key.pem"),
        None,
    )
    .unwrap();
    let (connector, name) =
        http2_connect::tls_connector_h2(&certs.root.join("root/ca.pem"), "relay.test").unwrap();
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
    let proxy = tokio::spawn(http2_connect::serve_tls(
        listener,
        http_connect::ServerConfig {
            username: None,
            password: None,
            allow_private_destinations: true,
        },
        acceptor,
    ));
    let tcp = TcpStream::connect(proxy_addr).await.unwrap();
    let tls = connector.connect(name, tcp).await.unwrap();
    let (mut sender, connection) = handshake(TokioExecutor::new(), TokioIo::new(tls))
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
    tunnel.write_all(b"h2-tls").await.unwrap();
    let mut reply = [0u8; 6];
    timeout(Duration::from_secs(2), tunnel.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"h2-tls");
    timeout(Duration::from_secs(2), echo)
        .await
        .unwrap()
        .unwrap();
    proxy.abort();
}

async fn multiplexed_h2_lifetime(tls_enabled: bool) {
    use tokio::io::{AsyncRead, AsyncWrite};
    async fn exercise<S>(stream: S, target: std::net::SocketAddr)
    where
        S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
    {
        let (mut sender, connection) = handshake(TokioExecutor::new(), TokioIo::new(stream))
            .await
            .unwrap();
        let driver = tokio::spawn(connection);
        let mut tunnels = Vec::new();
        for _ in 0..3 {
            let request = Request::builder()
                .method(hyper::Method::CONNECT)
                .uri(format!("http://{target}"))
                .body(Empty::<Bytes>::new())
                .unwrap();
            let mut response = sender.send_request(request).await.unwrap();
            assert_eq!(response.status(), hyper::StatusCode::OK);
            tunnels.push(TokioIo::new(
                hyper::upgrade::on(&mut response).await.unwrap(),
            ));
        }
        let mut half_closed = tunnels.pop().unwrap();
        half_closed.write_all(b"half").await.unwrap();
        let mut response = [0u8; 4];
        half_closed.read_exact(&mut response).await.unwrap();
        assert_eq!(&response, b"half");
        half_closed.shutdown().await.unwrap();
        let mut after_eof = Vec::new();
        timeout(
            Duration::from_secs(2),
            half_closed.read_to_end(&mut after_eof),
        )
        .await
        .unwrap()
        .unwrap();
        assert_eq!(after_eof, b"after-eof");
        let start = std::time::Instant::now();
        let mut rounds = 0;
        while start.elapsed() < Duration::from_secs(31) {
            for (index, tunnel) in tunnels.iter_mut().enumerate() {
                let payload = [index as u8; 256];
                tunnel.write_all(&payload).await.unwrap();
                let mut reply = [0u8; 256];
                timeout(Duration::from_secs(1), tunnel.read_exact(&mut reply))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(reply, payload);
            }
            rounds += 1;
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert!(rounds > 100);
        // A fresh CONNECT on the same established connection still works.
        let request = Request::builder()
            .method(hyper::Method::CONNECT)
            .uri(format!("http://{target}"))
            .body(Empty::<Bytes>::new())
            .unwrap();
        assert_eq!(
            sender.send_request(request).await.unwrap().status(),
            hyper::StatusCode::OK
        );
        driver.abort();
    }
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        while let Ok((mut socket, _)) = target.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 1024];
                loop {
                    match socket.read(&mut buffer).await {
                        Ok(0) => {
                            let _ = socket.write_all(b"after-eof").await;
                            return;
                        }
                        Ok(size) => {
                            if socket.write_all(&buffer[..size]).await.is_err() {
                                return;
                            }
                        }
                        Err(_) => return,
                    }
                }
            });
        }
    });
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = http_connect::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: true,
    };
    let certs = tls::Certificates::new();
    let server = if tls_enabled {
        let acceptor = http2_connect::tls_acceptor_h2(
            &certs.root.join("server/cert.pem"),
            &certs.root.join("server/key.pem"),
            None,
        )
        .unwrap();
        tokio::spawn(http2_connect::serve_tls(listener, config, acceptor))
    } else {
        tokio::spawn(http2_connect::serve(listener, config))
    };
    // A silent peer must still be closed by the handshake deadline.
    let mut silent = TcpStream::connect(addr).await.unwrap();
    let silent_check = tokio::spawn(async move {
        let mut byte = [0u8; 1];
        assert_eq!(
            timeout(Duration::from_secs(12), silent.read(&mut byte))
                .await
                .unwrap()
                .unwrap(),
            0
        );
    });
    if tls_enabled {
        let (connector, name) =
            http2_connect::tls_connector_h2(&certs.root.join("root/ca.pem"), "relay.test").unwrap();
        let stream = connector
            .connect(name, TcpStream::connect(addr).await.unwrap())
            .await
            .unwrap();
        assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        exercise(stream, target_addr).await;
    } else {
        exercise(TcpStream::connect(addr).await.unwrap(), target_addr).await;
    }
    silent_check.await.unwrap();
    echo.abort();
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn h2c_and_tls_keep_multiple_streams_and_half_close_alive_past_thirty_seconds() {
    tokio::join!(
        multiplexed_h2_lifetime(false),
        multiplexed_h2_lifetime(true)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn incomplete_settings_expire_and_oversized_initial_frames_are_rejected() {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let server = tokio::spawn(http2_connect::serve(
        listener,
        http_connect::ServerConfig {
            username: None,
            password: None,
            allow_private_destinations: true,
        },
    ));
    let mut incomplete = TcpStream::connect(addr).await.unwrap();
    incomplete
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    incomplete
        .write_all(&[0, 0, 6, 4, 0, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut oversized = TcpStream::connect(addr).await.unwrap();
    oversized
        .write_all(b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n")
        .await
        .unwrap();
    oversized
        .write_all(&[1, 0, 2, 4, 0, 0, 0, 0, 0])
        .await
        .unwrap();
    let mut byte = [0u8; 1];
    assert_eq!(
        timeout(Duration::from_secs(1), oversized.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    assert_eq!(
        timeout(Duration::from_secs(12), incomplete.read(&mut byte))
            .await
            .unwrap()
            .unwrap(),
        0
    );
    server.abort();
}

#[test]
fn h2_connect_dns_deadline_does_not_close_a_neighbor_stream() {
    let rt = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap();
    rt.block_on(async {
        let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let target_addr = target.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut socket, _) = target.accept().await.unwrap();
            let mut buffer = [0u8; 32];
            while let Ok(size) = socket.read(&mut buffer).await {
                if size == 0 {
                    break;
                }
                if socket.write_all(&buffer[..size]).await.is_err() {
                    break;
                }
            }
        });
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let addr = listener.local_addr().unwrap();
        let server = tokio::spawn(http2_connect::serve(
            listener,
            http_connect::ServerConfig {
                username: None,
                password: None,
                allow_private_destinations: true,
            },
        ));
        let (mut sender, connection) = handshake(
            TokioExecutor::new(),
            TokioIo::new(TcpStream::connect(addr).await.unwrap()),
        )
        .await
        .unwrap();
        let driver = tokio::spawn(connection);
        let request = Request::builder()
            .method(hyper::Method::CONNECT)
            .uri(format!("http://{target_addr}"))
            .body(Empty::<Bytes>::new())
            .unwrap();
        let mut response = sender.send_request(request).await.unwrap();
        assert_eq!(response.status(), hyper::StatusCode::OK);
        let mut tunnel = TokioIo::new(hyper::upgrade::on(&mut response).await.unwrap());
        let (release, held) = std::sync::mpsc::channel();
        let (started, ready) = tokio::sync::oneshot::channel();
        let blocker = tokio::task::spawn_blocking(move || {
            started.send(()).unwrap();
            let _ = held.recv_timeout(Duration::from_secs(15));
        });
        ready.await.unwrap();
        let request = Request::builder()
            .method(hyper::Method::CONNECT)
            .uri(format!("http://localhost:{}", target_addr.port()))
            .body(Empty::<Bytes>::new())
            .unwrap();
        let pending = tokio::spawn(async move {
            timeout(Duration::from_secs(12), sender.send_request(request))
                .await
                .unwrap()
                .unwrap()
                .status()
        });
        for _ in 0..55 {
            tunnel.write_all(b"live").await.unwrap();
            let mut reply = [0u8; 4];
            timeout(Duration::from_secs(1), tunnel.read_exact(&mut reply))
                .await
                .unwrap()
                .unwrap();
            assert_eq!(&reply, b"live");
            tokio::time::sleep(Duration::from_millis(200)).await;
        }
        assert_eq!(pending.await.unwrap(), hyper::StatusCode::BAD_GATEWAY);
        release.send(()).unwrap();
        blocker.await.unwrap();
        driver.abort();
        server.abort();
        echo.abort();
    });
}
