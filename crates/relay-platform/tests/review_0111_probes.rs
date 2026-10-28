//! Review-only acceptance probes. A failing assertion demonstrates the release defect.
//! All sockets are loopback; no host configuration or production state is changed.
#[allow(dead_code)]
#[path = "common/tls.rs"]
mod tls;
use http_body_util::Empty;
use hyper::{Request, body::Bytes, client::conn::http2::handshake};
use hyper_util::rt::{TokioExecutor, TokioIo};
use relay_platform::{http_connect, http2_connect, reverse_mux, shadowsocks::Destination, socks5};
use serde_json::json;
use std::{
    net::SocketAddr,
    sync::Arc,
    time::{Duration, Instant},
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
    time::{sleep, timeout},
};

async fn tcp_echo() -> (SocketAddr, JoinHandle<()>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let task = tokio::spawn(async move {
        while let Ok((mut socket, _)) = listener.accept().await {
            tokio::spawn(async move {
                let mut buffer = [0u8; 1024];
                loop {
                    match socket.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(size) => {
                            if socket.write_all(&buffer[..size]).await.is_err() {
                                return;
                            }
                        }
                    }
                }
            });
        }
    });
    (addr, task)
}

async fn open_h2<S>(socket: S, target: SocketAddr) -> TokioIo<hyper::upgrade::Upgraded>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    let (mut sender, connection) = handshake(TokioExecutor::new(), TokioIo::new(socket))
        .await
        .unwrap();
    tokio::spawn(connection);
    let req = Request::builder()
        .method(hyper::Method::CONNECT)
        .uri(format!("http://{target}"))
        .body(Empty::<Bytes>::new())
        .unwrap();
    let mut response = sender.send_request(req).await.unwrap();
    assert_eq!(response.status(), hyper::StatusCode::OK);
    let upgraded = timeout(Duration::from_secs(2), hyper::upgrade::on(&mut response))
        .await
        .unwrap()
        .unwrap();
    TokioIo::new(upgraded)
}

async fn exercise_h2(tls_enabled: bool) -> serde_json::Value {
    let (target, echo) = tcp_echo().await;
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let addr = listener.local_addr().unwrap();
    let config = http_connect::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: true,
    };
    let certs = tls::Certificates::new();
    let (server, mut stream) = if tls_enabled {
        let acceptor = http2_connect::tls_acceptor_h2(
            &certs.root.join("server/cert.pem"),
            &certs.root.join("server/key.pem"),
            None,
        )
        .unwrap();
        let (connector, name) =
            http2_connect::tls_connector_h2(&certs.root.join("root/ca.pem"), "relay.test").unwrap();
        let server = tokio::spawn(http2_connect::serve_tls(listener, config, acceptor));
        let tls = connector
            .connect(name, TcpStream::connect(addr).await.unwrap())
            .await
            .unwrap();
        assert_eq!(tls.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
        (server, open_h2(tls, target).await)
    } else {
        let server = tokio::spawn(http2_connect::serve(listener, config));
        (
            server,
            open_h2(TcpStream::connect(addr).await.unwrap(), target).await,
        )
    };
    let started = Instant::now();
    let mut rounds = 0;
    let mut failure = None;
    while started.elapsed() < Duration::from_secs(12) {
        let exchange = async {
            stream.write_all(b"ping").await?;
            let mut reply = [0u8; 4];
            stream.read_exact(&mut reply).await?;
            assert_eq!(&reply, b"ping");
            Ok::<(), std::io::Error>(())
        };
        match timeout(Duration::from_secs(1), exchange).await {
            Ok(Ok(())) => rounds += 1,
            Ok(Err(error)) => {
                failure = Some(error.to_string());
                break;
            }
            Err(error) => {
                failure = Some(error.to_string());
                break;
            }
        }
        sleep(Duration::from_millis(250)).await;
    }
    let elapsed = started.elapsed().as_secs_f64();
    let mut direct = TcpStream::connect(target).await.unwrap();
    direct.write_all(b"live").await.unwrap();
    let mut reply = [0u8; 4];
    timeout(Duration::from_secs(1), direct.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"live");
    server.abort();
    echo.abort();
    json!({"transport":if tls_enabled {"h2+TLS"}else{"h2c"},"elapsed_seconds":elapsed,"successful_echoes":rounds,"failure":failure,"backend_still_healthy":true})
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn review_http2_active_tunnels_survive_more_than_ten_seconds() {
    let clear = exercise_h2(false).await;
    let tls = exercise_h2(true).await;
    println!(
        "REVIEW_JSON {}",
        json!({"probe":"http2_lifetime","cases":[clear.clone(),tls.clone()]})
    );
    assert!(
        clear["failure"].is_null() && tls["failure"].is_null(),
        "healthy HTTP/2 tunnels must survive 12 seconds of continuous traffic"
    );
}

struct Mux {
    tcp: SocketAddr,
    udp: SocketAddr,
    target: SocketAddr,
    server: JoinHandle<anyhow::Result<()>>,
    client: JoinHandle<anyhow::Result<()>>,
    echo: JoinHandle<()>,
}
impl Drop for Mux {
    fn drop(&mut self) {
        self.server.abort();
        self.client.abort();
        self.echo.abort();
    }
}
async fn mux(socks: bool, max_streams: usize) -> Mux {
    reverse_mux::set_max_controls(1024);
    reverse_mux::set_max_total_streams(4096);
    reverse_mux::set_max_stream_bytes(0);
    reverse_mux::set_udp_idle_secs(2);
    reverse_mux::set_udp_rate_pps(0);
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control.local_addr().unwrap();
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let tcp = public.local_addr().unwrap();
    let udp = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
    let udp_addr = udp.local_addr().unwrap();
    let (target, echo) = tcp_echo().await;
    let token = "review-loopback-token".to_string();
    let server = tokio::spawn(reverse_mux::serve_mux_plain_udp(
        control,
        public,
        token.clone(),
        udp,
        max_streams,
        60,
        vec![],
    ));
    let client = if socks {
        tokio::spawn(reverse_mux::client_mux_udp_socks5_with_allowlist(
            control_addr,
            target.to_string(),
            token,
            true,
            vec!["127.0.0.1/32".parse().unwrap()],
        ))
    } else {
        tokio::spawn(reverse_mux::client_mux(
            control_addr,
            target.to_string(),
            token,
        ))
    };
    sleep(Duration::from_millis(150)).await;
    assert!(!client.is_finished(), "mux client failed before probe");
    Mux {
        tcp,
        udp: udp_addr,
        target,
        server,
        client,
        echo,
    }
}
async fn tcp_ping(socket: &mut TcpStream) -> std::io::Result<()> {
    socket.write_all(b"ping").await?;
    let mut reply = [0u8; 4];
    socket.read_exact(&mut reply).await?;
    assert_eq!(&reply, b"ping");
    Ok(())
}

#[test]
fn review_slow_udp_dns_does_not_block_existing_tcp() {
    let runtime = tokio::runtime::Builder::new_multi_thread()
        .worker_threads(4)
        .max_blocking_threads(1)
        .enable_all()
        .build()
        .unwrap();
    runtime.block_on(async {
        let mux = mux(true, 8).await;
        let backend = Arc::new(UdpSocket::bind("127.0.0.1:0").await.unwrap());
        let destination = backend.local_addr().unwrap();
        let backend_copy = backend.clone();
        let udp_echo = tokio::spawn(async move {
            let mut buffer = [0u8; 1024];
            while let Ok((size,peer)) = backend_copy.recv_from(&mut buffer).await { backend_copy.send_to(&buffer[..size],peer).await.unwrap(); }
        });
        let mut tcp = TcpStream::connect(mux.tcp).await.unwrap();
        timeout(Duration::from_secs(1),tcp_ping(&mut tcp)).await.unwrap().unwrap();
        let public = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        public.connect(mux.udp).await.unwrap();
        public.send(&socks5::encode_udp_datagram(&Destination::Ip(destination), b"baseline")).await.unwrap();
        let mut buffer = [0u8; 1024];
        timeout(Duration::from_secs(1), public.recv(&mut buffer)).await.unwrap().unwrap();
        // Tokio's OS hostname lookup uses spawn_blocking. Hold only that pool;
        // the four async workers and all established TCP/UDP sockets stay live.
        let (release, held) = std::sync::mpsc::channel();
        let (started, ready) = tokio::sync::oneshot::channel();
        let hold = tokio::task::spawn_blocking(move || { started.send(()).unwrap(); let _ = held.recv_timeout(Duration::from_secs(5)); });
        ready.await.unwrap();
        public.send(&socks5::encode_udp_datagram(&Destination::Domain("localhost".into(),destination.port()), b"dns")).await.unwrap();
        sleep(Duration::from_millis(200)).await;
        let mut direct = TcpStream::connect(mux.target).await.unwrap();
        timeout(Duration::from_secs(1), tcp_ping(&mut direct)).await.unwrap().unwrap();
        tcp.write_all(b"ping").await.unwrap();
        let mut reply = [0u8; 4];
        let during_delay = timeout(Duration::from_millis(500),tcp.read_exact(&mut reply)).await;
        let stalled = during_delay.is_err();
        release.send(()).unwrap();
        hold.await.unwrap();
        let recovery = Instant::now();
        if stalled { timeout(Duration::from_secs(1),tcp.read_exact(&mut reply)).await.unwrap().unwrap(); }
        else { during_delay.unwrap().unwrap(); }
        assert_eq!(&reply,b"ping");
        let recovery_ms = recovery.elapsed().as_secs_f64()*1000.0;
        timeout(Duration::from_secs(1), public.recv(&mut buffer)).await.unwrap().unwrap();
        println!("REVIEW_JSON {}",json!({"probe":"udp_dns_hol","tcp_echo_baseline":true,"direct_tcp_while_dns_held":true,"tcp_neighbor_stalled_500ms":stalled,"recovery_after_dns_release_ms":recovery_ms,"udp_recovered":true}));
        udp_echo.abort();
        assert!(!stalled, "a delayed UDP lookup must not stop an established TCP neighbor on the shared mux");
    });
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn review_udp_replies_must_come_from_a_contacted_peer() {
    let mux = mux(true, 8).await;
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let other = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let public = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    public.connect(mux.udp).await.unwrap();
    public
        .send(&socks5::encode_udp_datagram(
            &Destination::Ip(target.local_addr().unwrap()),
            b"legitimate",
        ))
        .await
        .unwrap();
    let mut buffer = [0u8; 1024];
    let (_, relay_addr) = timeout(Duration::from_secs(1), target.recv_from(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    target
        .send_to(b"authorized-reply", relay_addr)
        .await
        .unwrap();
    let size = timeout(Duration::from_secs(1), public.recv(&mut buffer))
        .await
        .unwrap()
        .unwrap();
    let legit = socks5::parse_udp_datagram(&buffer[..size]).unwrap();
    assert_eq!(legit.payload, b"authorized-reply");
    other
        .send_to(b"unsolicited-reply", relay_addr)
        .await
        .unwrap();
    let received = timeout(Duration::from_millis(500), public.recv(&mut buffer)).await;
    let mut accepted = false;
    let mut source = String::new();
    if let Ok(Ok(size)) = received {
        let reply = socks5::parse_udp_datagram(&buffer[..size]).unwrap();
        accepted = reply.payload == b"unsolicited-reply";
        source = reply.destination.to_string();
    }
    println!(
        "REVIEW_JSON {}",
        json!({"probe":"udp_unsolicited_reply","contacted_peer":target.local_addr().unwrap().to_string(),"uncontacted_peer":other.local_addr().unwrap().to_string(),"returned_source":source,"unsolicited_payload_delivered":accepted,"same_allowed_ip_different_port":true})
    );
    assert!(
        !accepted,
        "an uncontacted UDP sender must not inject a reply into this association"
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn review_udp_open_failure_releases_stream_capacity() {
    let mux = mux(false, 1).await;
    let mut before = TcpStream::connect(mux.tcp).await.unwrap();
    timeout(Duration::from_secs(1), tcp_ping(&mut before))
        .await
        .unwrap()
        .unwrap();
    drop(before);
    sleep(Duration::from_millis(150)).await;
    assert_eq!(reverse_mux::stats().active_streams, 0);
    let public = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    public.connect(mux.udp).await.unwrap();
    public.send(b"client-does-not-support-udp").await.unwrap();
    sleep(Duration::from_millis(250)).await;
    let active_after_fail = reverse_mux::stats().active_streams;
    let mut tcp = TcpStream::connect(mux.tcp).await.unwrap();
    let rejected = !matches!(
        timeout(Duration::from_millis(500), tcp_ping(&mut tcp)).await,
        Ok(Ok(()))
    );
    drop(tcp);
    sleep(Duration::from_secs(3)).await;
    let active_after_idle = reverse_mux::stats().active_streams;
    let mut tcp = TcpStream::connect(mux.tcp).await.unwrap();
    timeout(Duration::from_secs(1), tcp_ping(&mut tcp))
        .await
        .unwrap()
        .unwrap();
    println!(
        "REVIEW_JSON {}",
        json!({"probe":"udp_failed_open_capacity","stream_limit":1,"active_after_client_fail":active_after_fail,"valid_tcp_rejected":rejected,"configured_udp_idle_secs":2,"active_after_idle_sweep":active_after_idle,"valid_tcp_after_idle":true})
    );
    assert_eq!(
        active_after_fail, 0,
        "a failed UDP OPEN must immediately release its stream permit"
    );
}
