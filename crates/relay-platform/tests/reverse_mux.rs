mod common;
#[allow(dead_code)]
#[path = "common/tls.rs"]
mod tls;
use relay_platform::reverse_mux;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tokio::time::timeout;

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn one_control_connection_multiplexes_two_public_connections() {
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
                stream.shutdown().await.unwrap();
            }));
        }
        for task in tasks {
            task.await.unwrap();
        }
    });
    let server = tokio::spawn(reverse_mux::serve_mux(control, public, "mux-token".into()));
    let client = tokio::spawn(reverse_mux::client_mux(
        control_addr,
        target_addr.to_string(),
        "mux-token".into(),
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

#[tokio::test]
async fn mux_stream_limit_is_validated() {
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let error = reverse_mux::serve_mux_with_limit(control, public, "mux-token".into(), 0)
        .await
        .unwrap_err();
    assert!(error.to_string().contains("max streams"));
}

#[tokio::test]
async fn mux_idle_timeout_is_validated() {
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let error =
        reverse_mux::serve_mux_with_options(control, public, "mux-token".into(), 1, 0, vec![])
            .await
            .unwrap_err();
    assert!(error.to_string().contains("idle timeout"));
}

#[tokio::test]
async fn mux_server_rejects_a_bad_token() {
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control.local_addr().unwrap();
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = tokio::spawn(reverse_mux::serve_mux(
        control,
        public,
        "right-token".into(),
    ));
    let mut stream = TcpStream::connect(control_addr).await.unwrap();
    stream
        .write_all(b"REVERSE-MUX wrong-token\n")
        .await
        .unwrap();
    let mut reply = [0u8; 5];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(&reply, b"DENY\n");
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn tls_control_connection_still_multiplexes_public_streams() {
    let certs = tls::Certificates::new();
    let acceptor = reverse_mux::tls_acceptor(
        &certs.root.join("server/cert.pem"),
        &certs.root.join("server/key.pem"),
    )
    .unwrap();
    let (connector, name) =
        reverse_mux::tls_connector(&certs.root.join("root/ca.pem"), "relay.test").unwrap();
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control.local_addr().unwrap();
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public_addr = public.local_addr().unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut buffer = [0u8; 64];
        let size = stream.read(&mut buffer).await.unwrap();
        stream.write_all(&buffer[..size]).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let server = tokio::spawn(reverse_mux::serve_mux_tls(
        control,
        public,
        "mux-tls-token".into(),
        acceptor,
        8,
        300,
        vec![],
    ));
    let client = tokio::spawn(reverse_mux::client_mux_tls(
        control_addr,
        target_addr.to_string(),
        "mux-tls-token".into(),
        connector,
        name,
    ));
    let mut exposed = timeout(Duration::from_secs(3), TcpStream::connect(public_addr))
        .await
        .unwrap()
        .unwrap();
    exposed.write_all(b"secure").await.unwrap();
    let mut reply = [0u8; 6];
    timeout(Duration::from_secs(3), exposed.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"secure");
    timeout(Duration::from_secs(3), echo)
        .await
        .unwrap()
        .unwrap();
    server.abort();
    client.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn mtls_control_requires_a_client_identity() {
    let certs = tls::Certificates::new();
    let acceptor = reverse_mux::tls_acceptor_with_client_ca(
        &certs.root.join("server/cert.pem"),
        &certs.root.join("server/key.pem"),
        &certs.root.join("root/ca.pem"),
    )
    .unwrap();
    let (connector, name) = reverse_mux::tls_connector_with_identity(
        &certs.root.join("root/ca.pem"),
        "relay.test",
        &certs.root.join("client/cert.pem"),
        &certs.root.join("client/key.pem"),
    )
    .unwrap();
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control.local_addr().unwrap();
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public_addr = public.local_addr().unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut buffer = [0u8; 64];
        let size = stream.read(&mut buffer).await.unwrap();
        stream.write_all(&buffer[..size]).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let server = tokio::spawn(reverse_mux::serve_mux_tls(
        control,
        public,
        "mux-mtls-token".into(),
        acceptor,
        8,
        300,
        vec![],
    ));
    let client = tokio::spawn(reverse_mux::client_mux_tls(
        control_addr,
        target_addr.to_string(),
        "mux-mtls-token".into(),
        connector,
        name,
    ));
    let mut exposed = timeout(Duration::from_secs(3), TcpStream::connect(public_addr))
        .await
        .unwrap()
        .unwrap();
    exposed.write_all(b"mutual").await.unwrap();
    let mut reply = [0u8; 6];
    timeout(Duration::from_secs(3), exposed.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"mutual");
    timeout(Duration::from_secs(3), echo)
        .await
        .unwrap()
        .unwrap();
    server.abort();
    client.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn public_tls_terminates_before_the_public_stream() {
    let certs = tls::Certificates::new();
    let acceptor = reverse_mux::tls_acceptor(
        &certs.root.join("server/cert.pem"),
        &certs.root.join("server/key.pem"),
    )
    .unwrap();
    let (connector, name) =
        reverse_mux::tls_connector(&certs.root.join("root/ca.pem"), "relay.test").unwrap();
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control.local_addr().unwrap();
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public_addr = public.local_addr().unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut buffer = [0u8; 64];
        let size = stream.read(&mut buffer).await.unwrap();
        stream.write_all(&buffer[..size]).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let server = tokio::spawn(reverse_mux::serve_mux_public_tls(
        control,
        public,
        "public-tls-token".into(),
        acceptor,
        8,
        300,
        vec![],
    ));
    let client = tokio::spawn(reverse_mux::client_mux(
        control_addr,
        target_addr.to_string(),
        "public-tls-token".into(),
    ));
    let tcp = TcpStream::connect(public_addr).await.unwrap();
    let mut exposed = connector.connect(name, tcp).await.unwrap();
    exposed.write_all(b"public").await.unwrap();
    let mut reply = [0u8; 6];
    timeout(Duration::from_secs(3), exposed.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"public");
    timeout(Duration::from_secs(3), echo)
        .await
        .unwrap()
        .unwrap();
    server.abort();
    client.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn public_cidr_allowlist_closes_denied_sources() {
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control.local_addr().unwrap();
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public_addr = public.local_addr().unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let server = tokio::spawn(reverse_mux::serve_mux_with_options(
        control,
        public,
        "cidr-token".into(),
        8,
        300,
        vec!["10.0.0.0/8".parse().unwrap()],
    ));
    let client = tokio::spawn(reverse_mux::client_mux(
        control_addr,
        target_addr.to_string(),
        "cidr-token".into(),
    ));
    let mut exposed = timeout(Duration::from_secs(2), TcpStream::connect(public_addr))
        .await
        .unwrap()
        .unwrap();
    let mut byte = [0u8; 1];
    let read = timeout(Duration::from_secs(2), exposed.read(&mut byte))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(read, 0);
    server.abort();
    client.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn half_close_keeps_the_reverse_direction_open() {
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control.local_addr().unwrap();
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public_addr = public.local_addr().unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let backend = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await.unwrap();
        stream.write_all(b"response-after-eof:").await.unwrap();
        stream.write_all(&request).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let server = tokio::spawn(reverse_mux::serve_mux(
        control,
        public,
        "half-close-token".into(),
    ));
    let client = tokio::spawn(reverse_mux::client_mux(
        control_addr,
        target_addr.to_string(),
        "half-close-token".into(),
    ));
    let mut exposed = timeout(Duration::from_secs(3), TcpStream::connect(public_addr))
        .await
        .unwrap()
        .unwrap();
    exposed.write_all(b"request-body").await.unwrap();
    exposed.shutdown().await.unwrap();
    let mut reply = Vec::new();
    timeout(Duration::from_secs(3), exposed.read_to_end(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, b"response-after-eof:request-body");
    timeout(Duration::from_secs(3), backend)
        .await
        .unwrap()
        .unwrap();
    server.abort();
    client.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn silent_tls_handshake_does_not_block_the_control_accept() {
    let certs = tls::Certificates::new();
    let acceptor = reverse_mux::tls_acceptor(
        &certs.root.join("server/cert.pem"),
        &certs.root.join("server/key.pem"),
    )
    .unwrap();
    let (_connector, _name) =
        reverse_mux::tls_connector(&certs.root.join("root/ca.pem"), "relay.test").unwrap();
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control.local_addr().unwrap();
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = tokio::spawn(reverse_mux::serve_mux_tls(
        control,
        public,
        "tls-silent-token".into(),
        acceptor,
        8,
        300,
        vec![],
    ));
    let silent = TcpStream::connect(control_addr).await.unwrap();
    let tcp = TcpStream::connect(control_addr).await.unwrap();
    let (connector, name) =
        reverse_mux::tls_connector(&certs.root.join("root/ca.pem"), "relay.test").unwrap();
    let mut legitimate = connector.connect(name, tcp).await.unwrap();
    legitimate
        .write_all(b"REVERSE-MUX tls-silent-token\n")
        .await
        .unwrap();
    let mut reply = [0u8; 6];
    timeout(Duration::from_secs(2), legitimate.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"READY\n");
    drop(silent);
    server.abort();
}

#[test]
fn mux_metrics_identify_the_tunnel_process() {
    let text = reverse_mux::metrics_text();
    assert!(text.contains("relay_reverse_mux_process_available 1"));
    assert!(text.contains("relay_reverse_mux_bytes{direction=\"public_to_target\"} "));
    assert!(text.contains("relay_reverse_mux_control_limit_rejections_total "));
    assert!(text.contains("relay_reverse_mux_stream_limit_rejections_total "));
    assert!(text.contains("relay_reverse_mux_stream_byte_limit_resets_total "));
    assert!(text.contains("relay_reverse_mux_udp_dropped_total "));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn established_tls_controls_do_not_consume_pending_handshake_slots() {
    let certs = tls::Certificates::new();
    let acceptor = reverse_mux::tls_acceptor(
        &certs.root.join("server/cert.pem"),
        &certs.root.join("server/key.pem"),
    )
    .unwrap();
    let (connector, name) =
        reverse_mux::tls_connector(&certs.root.join("root/ca.pem"), "relay.test").unwrap();
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = control.local_addr().unwrap();
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = tokio::spawn(reverse_mux::serve_mux_tls(
        control,
        public,
        "slots".into(),
        acceptor,
        8,
        30,
        vec![],
    ));
    let mut established = Vec::new();
    for index in 0..80 {
        let mut stream = timeout(Duration::from_secs(2), async {
            connector
                .connect(name.clone(), TcpStream::connect(address).await.unwrap())
                .await
        })
        .await
        .unwrap()
        .unwrap();
        stream.write_all(b"REVERSE-MUX slots\n").await.unwrap();
        let mut ready = [0; 6];
        timeout(Duration::from_secs(2), stream.read_exact(&mut ready))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&ready, b"READY\n", "control {index}");
        established.push(stream);
    }
    // All 80 remain open concurrently; the 65th must not depend on closing one.
    assert_eq!(established.len(), 80);
    drop(established);
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn pending_authentication_stays_bounded_and_releases_slots_on_failure() {
    let certs = tls::Certificates::new();
    let acceptor = reverse_mux::tls_acceptor(
        &certs.root.join("server/cert.pem"),
        &certs.root.join("server/key.pem"),
    )
    .unwrap();
    let (connector, name) =
        reverse_mux::tls_connector(&certs.root.join("root/ca.pem"), "relay.test").unwrap();
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = control.local_addr().unwrap();
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = tokio::spawn(reverse_mux::serve_mux_tls(
        control,
        public,
        "slots".into(),
        acceptor,
        8,
        30,
        vec![],
    ));
    let mut pending = Vec::new();
    for _ in 0..64 {
        let stream = timeout(Duration::from_secs(2), async {
            connector
                .connect(name.clone(), TcpStream::connect(address).await.unwrap())
                .await
        })
        .await
        .unwrap()
        .unwrap();
        pending.push(stream); // TLS complete, token authentication still pending.
    }
    let rejected = timeout(Duration::from_secs(2), async {
        connector
            .connect(name.clone(), TcpStream::connect(address).await.unwrap())
            .await
    })
    .await
    .unwrap();
    assert!(
        rejected.is_err(),
        "unauthenticated controls must retain the 64-slot bound"
    );
    let mut denied = pending.pop().unwrap();
    denied.write_all(b"REVERSE-MUX wrong\n").await.unwrap();
    let mut response = [0; 5];
    timeout(Duration::from_secs(2), denied.read_exact(&mut response))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&response, b"DENY\n");
    drop(denied);
    // A failed authentication returns its permit while all other 63 are pending.
    let mut replacement = timeout(Duration::from_secs(2), async {
        connector
            .connect(name, TcpStream::connect(address).await.unwrap())
            .await
    })
    .await
    .unwrap()
    .unwrap();
    replacement.write_all(b"REVERSE-MUX slots\n").await.unwrap();
    let mut ready = [0; 6];
    timeout(Duration::from_secs(2), replacement.read_exact(&mut ready))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&ready, b"READY\n");
    drop(pending);
    drop(replacement);
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn healthy_bulk_transfer_and_half_close_keep_all_bytes() {
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control.local_addr().unwrap();
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public_addr = public.local_addr().unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let data = vec![0x5a; 8 * 1024 * 1024];
    let expected = data.clone();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut request = Vec::new();
        stream.read_to_end(&mut request).await.unwrap();
        assert!(
            request == expected,
            "bulk request length: {} expected: {}",
            request.len(),
            expected.len()
        );
        stream.write_all(&request).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let server = tokio::spawn(reverse_mux::serve_mux(control, public, "bulk".into()));
    let client = tokio::spawn(reverse_mux::client_mux(
        control_addr,
        target_addr.to_string(),
        "bulk".into(),
    ));
    timeout(Duration::from_secs(10), async {
        let mut stream = TcpStream::connect(public_addr).await.unwrap();
        stream.write_all(&data).await.unwrap();
        stream.shutdown().await.unwrap();
        let mut response = Vec::new();
        stream.read_to_end(&mut response).await.unwrap();
        assert!(
            response == data,
            "bulk response length: {} expected: {}",
            response.len(),
            data.len()
        );
        echo.await.unwrap();
    })
    .await
    .unwrap();
    client.abort();
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn silent_plain_control_does_not_block_the_accept() {
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control.local_addr().unwrap();
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let server = tokio::spawn(reverse_mux::serve_mux(
        control,
        public,
        "plain-silent-token".into(),
    ));
    let silent = TcpStream::connect(control_addr).await.unwrap();
    let mut legitimate = TcpStream::connect(control_addr).await.unwrap();
    legitimate
        .write_all(b"REVERSE-MUX plain-silent-token\n")
        .await
        .unwrap();
    let mut reply = [0u8; 6];
    timeout(Duration::from_secs(2), legitimate.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"READY\n");
    drop(silent);
    server.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn silent_public_tls_handshake_does_not_block_neighbors() {
    let certs = tls::Certificates::new();
    let acceptor = reverse_mux::tls_acceptor(
        &certs.root.join("server/cert.pem"),
        &certs.root.join("server/key.pem"),
    )
    .unwrap();
    let (connector, name) =
        reverse_mux::tls_connector(&certs.root.join("root/ca.pem"), "relay.test").unwrap();
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control.local_addr().unwrap();
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public_addr = public.local_addr().unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut buffer = [0u8; 64];
        let size = stream.read(&mut buffer).await.unwrap();
        stream.write_all(&buffer[..size]).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let server = tokio::spawn(reverse_mux::serve_mux_public_tls(
        control,
        public,
        "public-silent-token".into(),
        acceptor,
        8,
        300,
        vec![],
    ));
    let client = tokio::spawn(reverse_mux::client_mux(
        control_addr,
        target_addr.to_string(),
        "public-silent-token".into(),
    ));
    let silent = TcpStream::connect(public_addr).await.unwrap();
    let tcp = TcpStream::connect(public_addr).await.unwrap();
    let mut exposed = connector.connect(name, tcp).await.unwrap();
    exposed.write_all(b"neighbor").await.unwrap();
    let mut reply = [0u8; 8];
    timeout(Duration::from_secs(2), exposed.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"neighbor");
    drop(silent);
    timeout(Duration::from_secs(3), echo)
        .await
        .unwrap()
        .unwrap();
    server.abort();
    client.abort();
}

#[test]
fn max_controls_rejects_an_extra_established_control() {
    use std::io::{Read, Write};
    use std::net::{TcpListener as StdListener, TcpStream as StdStream};
    use std::process::{Command, Stdio};
    use std::time::Duration as StdDuration;
    let control = StdListener::bind("127.0.0.1:0").unwrap();
    let control_port = control.local_addr().unwrap().port();
    drop(control);
    let public = StdListener::bind("127.0.0.1:0").unwrap();
    let public_port = public.local_addr().unwrap().port();
    drop(public);
    let temp = tempfile::tempdir().unwrap();
    let token = temp.path().join("token");
    std::fs::write(&token, "limit-token\n").unwrap();
    let mut child = Command::new(env!("CARGO_BIN_EXE_relay"))
        .args([
            "reverse-mux-server",
            "--control-listen",
            &format!("127.0.0.1:{control_port}"),
            "--public-listen",
            &format!("127.0.0.1:{public_port}"),
            "--token-file",
            token.to_str().unwrap(),
            "--max-controls",
            "1",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut first = None;
    for _ in 0..100 {
        if let Ok(stream) = StdStream::connect(("127.0.0.1", control_port)) {
            first = Some(stream);
            break;
        }
        std::thread::sleep(StdDuration::from_millis(20));
    }
    let mut first = first.expect("server did not listen");
    first
        .set_read_timeout(Some(StdDuration::from_secs(2)))
        .unwrap();
    first.write_all(b"REVERSE-MUX limit-token\n").unwrap();
    let mut ready = [0u8; 6];
    first.read_exact(&mut ready).unwrap();
    assert_eq!(&ready, b"READY\n");
    let mut second = StdStream::connect(("127.0.0.1", control_port)).unwrap();
    second
        .set_read_timeout(Some(StdDuration::from_secs(2)))
        .unwrap();
    second.write_all(b"REVERSE-MUX limit-token\n").unwrap();
    let mut denied = [0u8; 5];
    second.read_exact(&mut denied).unwrap();
    assert_eq!(&denied, b"DENY\n");
    child.kill().ok();
    child.wait().ok();
}

#[test]
fn max_total_streams_rejects_a_second_public_stream() {
    use std::io::{Read, Write};
    use std::net::{TcpListener as StdListener, TcpStream as StdStream};
    use std::process::{Command, Stdio};
    use std::time::Duration as StdDuration;
    let control = StdListener::bind("127.0.0.1:0").unwrap();
    let control_port = control.local_addr().unwrap().port();
    drop(control);
    let public = StdListener::bind("127.0.0.1:0").unwrap();
    let public_port = public.local_addr().unwrap().port();
    drop(public);
    let target = StdListener::bind("127.0.0.1:0").unwrap();
    let target_port = target.local_addr().unwrap().port();
    let temp = tempfile::tempdir().unwrap();
    let token = temp.path().join("token");
    std::fs::write(&token, "stream-limit-token\n").unwrap();
    let mut server = Command::new(env!("CARGO_BIN_EXE_relay"))
        .args([
            "reverse-mux-server",
            "--control-listen",
            &format!("127.0.0.1:{control_port}"),
            "--public-listen",
            &format!("127.0.0.1:{public_port}"),
            "--token-file",
            token.to_str().unwrap(),
            "--max-total-streams",
            "1",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut client = Command::new(env!("CARGO_BIN_EXE_relay"))
        .args([
            "reverse-mux-client",
            "--server",
            &format!("127.0.0.1:{control_port}"),
            "--target",
            &format!("127.0.0.1:{target_port}"),
            "--token-file",
            token.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut first = None;
    for _ in 0..100 {
        if let Ok(stream) = StdStream::connect(("127.0.0.1", public_port)) {
            first = Some(stream);
            break;
        }
        std::thread::sleep(StdDuration::from_millis(20));
    }
    let mut first = first.expect("public listener did not open");
    let (mut backend, _) = target.accept().unwrap();
    backend
        .set_read_timeout(Some(StdDuration::from_secs(3)))
        .unwrap();
    first.write_all(b"one").unwrap();
    let mut received = [0u8; 3];
    backend.read_exact(&mut received).unwrap();
    assert_eq!(&received, b"one");
    let mut second = StdStream::connect(("127.0.0.1", public_port)).unwrap();
    second
        .set_read_timeout(Some(StdDuration::from_secs(3)))
        .unwrap();
    let mut end = [0u8; 1];
    let read = second.read(&mut end).unwrap();
    assert_eq!(read, 0);
    drop(first);
    server.kill().ok();
    client.kill().ok();
    server.wait().ok();
    client.wait().ok();
}

#[test]
fn max_stream_bytes_resets_only_the_over_limit_stream() {
    use std::io::{Read, Write};
    use std::net::{TcpListener as StdListener, TcpStream as StdStream};
    use std::process::{Command, Stdio};
    use std::time::Duration as StdDuration;
    let control = StdListener::bind("127.0.0.1:0").unwrap();
    let control_port = control.local_addr().unwrap().port();
    drop(control);
    let public = StdListener::bind("127.0.0.1:0").unwrap();
    let public_port = public.local_addr().unwrap().port();
    drop(public);
    let target = StdListener::bind("127.0.0.1:0").unwrap();
    let target_port = target.local_addr().unwrap().port();
    let temp = tempfile::tempdir().unwrap();
    let token = temp.path().join("token");
    std::fs::write(&token, "byte-limit-token\n").unwrap();
    let mut server = Command::new(env!("CARGO_BIN_EXE_relay"))
        .args([
            "reverse-mux-server",
            "--control-listen",
            &format!("127.0.0.1:{control_port}"),
            "--public-listen",
            &format!("127.0.0.1:{public_port}"),
            "--token-file",
            token.to_str().unwrap(),
            "--max-stream-bytes",
            "1",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut client = Command::new(env!("CARGO_BIN_EXE_relay"))
        .args([
            "reverse-mux-client",
            "--server",
            &format!("127.0.0.1:{control_port}"),
            "--target",
            &format!("127.0.0.1:{target_port}"),
            "--token-file",
            token.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut public_stream = None;
    for _ in 0..100 {
        if let Ok(stream) = StdStream::connect(("127.0.0.1", public_port)) {
            public_stream = Some(stream);
            break;
        }
        std::thread::sleep(StdDuration::from_millis(20));
    }
    let mut public_stream = public_stream.expect("public listener did not open");
    let (mut backend, _) = target.accept().unwrap();
    backend
        .set_read_timeout(Some(StdDuration::from_secs(3)))
        .unwrap();
    public_stream.write_all(b"a").unwrap();
    let mut first = [0u8; 1];
    backend.read_exact(&mut first).unwrap();
    assert_eq!(&first, b"a");
    public_stream.write_all(b"b").unwrap();
    let mut end = [0u8; 1];
    assert_eq!(backend.read(&mut end).unwrap(), 0);
    public_stream
        .set_read_timeout(Some(StdDuration::from_secs(3)))
        .unwrap();
    let _ = public_stream.read(&mut end);
    drop(public_stream);
    server.kill().ok();
    client.kill().ok();
    server.wait().ok();
    client.wait().ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn udp_datagrams_round_trip_through_the_mux() {
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control.local_addr().unwrap();
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let public_udp_addr = public_udp.local_addr().unwrap();
    let target = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        let (size, peer) = target.recv_from(&mut buffer).await.unwrap();
        target.send_to(&buffer[..size], peer).await.unwrap();
    });
    let server = tokio::spawn(reverse_mux::serve_mux_plain_udp(
        control,
        public,
        "udp-mux-token".into(),
        std::sync::Arc::new(public_udp),
        8,
        300,
        vec![],
    ));
    let client = tokio::spawn(reverse_mux::client_mux_udp(
        control_addr,
        "127.0.0.1:9".into(),
        "udp-mux-token".into(),
        Some(target_addr.to_string()),
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    probe.connect(public_udp_addr).await.unwrap();
    probe.send(b"udp-ping").await.unwrap();
    let mut reply = [0u8; 16];
    let size = timeout(Duration::from_secs(3), probe.recv(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply[..size], b"udp-ping");
    timeout(Duration::from_secs(3), echo)
        .await
        .unwrap()
        .unwrap();
    server.abort();
    client.abort();
}

#[test]
fn udp_cli_forwards_a_datagram_to_the_udp_target() {
    use std::net::{TcpListener as StdListener, TcpStream as StdStream, UdpSocket as StdUdp};
    use std::process::{Command, Stdio};
    use std::sync::mpsc;
    use std::time::Duration as StdDuration;
    let control = StdListener::bind("127.0.0.1:0").unwrap();
    let control_port = control.local_addr().unwrap().port();
    drop(control);
    let public = StdListener::bind("127.0.0.1:0").unwrap();
    let public_port = public.local_addr().unwrap().port();
    drop(public);
    let public_udp = StdUdp::bind("127.0.0.1:0").unwrap();
    let public_udp_port = public_udp.local_addr().unwrap().port();
    drop(public_udp);
    let target = StdUdp::bind("127.0.0.1:0").unwrap();
    let target_port = target.local_addr().unwrap().port();
    target
        .set_read_timeout(Some(StdDuration::from_secs(3)))
        .unwrap();
    let (ready_tx, ready_rx) = mpsc::channel();
    let echo = std::thread::spawn(move || {
        ready_tx.send(()).unwrap();
        let mut buffer = [0u8; 64];
        let (size, peer) = target.recv_from(&mut buffer).unwrap();
        target.send_to(&buffer[..size], peer).unwrap();
    });
    ready_rx.recv().unwrap();
    let temp = tempfile::tempdir().unwrap();
    let token = temp.path().join("token");
    std::fs::write(&token, "udp-cli-token\n").unwrap();
    let mut server = Command::new(env!("CARGO_BIN_EXE_relay"))
        .args([
            "reverse-mux-server",
            "--control-listen",
            &format!("127.0.0.1:{control_port}"),
            "--public-listen",
            &format!("127.0.0.1:{public_port}"),
            "--udp-listen",
            &format!("127.0.0.1:{public_udp_port}"),
            "--token-file",
            token.to_str().unwrap(),
            "--max-controls",
            "1",
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut client = Command::new(env!("CARGO_BIN_EXE_relay"))
        .args([
            "reverse-mux-client",
            "--server",
            &format!("127.0.0.1:{control_port}"),
            "--target",
            "127.0.0.1:9",
            "--udp-target",
            &format!("127.0.0.1:{target_port}"),
            "--token-file",
            token.to_str().unwrap(),
        ])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .unwrap();
    let mut connected = None;
    for _ in 0..100 {
        if let Ok(stream) = StdStream::connect(("127.0.0.1", control_port)) {
            connected = Some(stream);
            break;
        }
        std::thread::sleep(StdDuration::from_millis(20));
    }
    let connected = connected.expect("server did not listen");
    connected
        .set_read_timeout(Some(StdDuration::from_secs(3)))
        .unwrap();
    // Wait for the client to authenticate and the UDP listener to accept.
    std::thread::sleep(StdDuration::from_millis(300));
    let probe = StdUdp::bind("127.0.0.1:0").unwrap();
    probe
        .set_read_timeout(Some(StdDuration::from_secs(3)))
        .unwrap();
    probe
        .send_to(b"udp-cli", ("127.0.0.1", public_udp_port))
        .unwrap();
    let mut reply = [0u8; 16];
    let (size, _) = probe.recv_from(&mut reply).unwrap();
    assert_eq!(&reply[..size], b"udp-cli");
    echo.join().unwrap();
    drop(connected);
    server.kill().ok();
    client.kill().ok();
    server.wait().ok();
    client.wait().ok();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn public_tls_mtls_requires_a_client_identity() {
    let certs = tls::Certificates::new();
    let acceptor = reverse_mux::tls_acceptor_with_client_ca(
        &certs.root.join("server/cert.pem"),
        &certs.root.join("server/key.pem"),
        &certs.root.join("root/ca.pem"),
    )
    .unwrap();
    let (connector, name) =
        reverse_mux::tls_connector(&certs.root.join("root/ca.pem"), "relay.test").unwrap();
    let (identity, identity_name) = reverse_mux::tls_connector_with_identity(
        &certs.root.join("root/ca.pem"),
        "relay.test",
        &certs.root.join("client/cert.pem"),
        &certs.root.join("client/key.pem"),
    )
    .unwrap();
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control.local_addr().unwrap();
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public_addr = public.local_addr().unwrap();
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target_addr = target.local_addr().unwrap();
    let echo = tokio::spawn(async move {
        let (mut stream, _) = target.accept().await.unwrap();
        let mut buffer = [0u8; 64];
        let size = stream.read(&mut buffer).await.unwrap();
        stream.write_all(&buffer[..size]).await.unwrap();
        stream.shutdown().await.unwrap();
    });
    let server = tokio::spawn(reverse_mux::serve_mux_public_tls(
        control,
        public,
        "public-mtls-token".into(),
        acceptor,
        8,
        300,
        vec![],
    ));
    let client = tokio::spawn(reverse_mux::client_mux(
        control_addr,
        target_addr.to_string(),
        "public-mtls-token".into(),
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let tcp = TcpStream::connect(public_addr).await.unwrap();
    if let Ok(mut unauthenticated) = connector.connect(name, tcp).await {
        let _ = unauthenticated.write_all(b"no-identity").await;
        let mut byte = [0u8; 1];
        let result = timeout(Duration::from_secs(1), unauthenticated.read(&mut byte)).await;
        assert!(result.is_err() || matches!(result, Ok(Err(_))) || matches!(result, Ok(Ok(0))));
    }
    let tcp = TcpStream::connect(public_addr).await.unwrap();
    let mut exposed = identity.connect(identity_name, tcp).await.unwrap();
    exposed.write_all(b"mtls").await.unwrap();
    let mut reply = [0u8; 4];
    timeout(Duration::from_secs(2), exposed.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&reply, b"mtls");
    timeout(Duration::from_secs(2), echo)
        .await
        .unwrap()
        .unwrap();
    server.abort();
    client.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 6)]
async fn udp_socks5_mode_reaches_two_targets() {
    use relay_platform::shadowsocks::Destination;
    let control = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let control_addr = control.local_addr().unwrap();
    let public = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let public_udp = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let public_udp_addr = public_udp.local_addr().unwrap();
    let first = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let first_addr = first.local_addr().unwrap();
    let second = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let second_addr = second.local_addr().unwrap();
    let one = tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        let (size, peer) = first.recv_from(&mut buffer).await.unwrap();
        first.send_to(&buffer[..size], peer).await.unwrap();
    });
    let two = tokio::spawn(async move {
        let mut buffer = [0u8; 64];
        let (size, peer) = second.recv_from(&mut buffer).await.unwrap();
        second.send_to(&buffer[..size], peer).await.unwrap();
    });
    let server = tokio::spawn(reverse_mux::serve_mux_plain_udp(
        control,
        public,
        "udp-socks-token".into(),
        std::sync::Arc::new(public_udp),
        8,
        300,
        vec![],
    ));
    let client = tokio::spawn(reverse_mux::client_mux_udp_socks5(
        control_addr,
        "127.0.0.1:9".into(),
        "udp-socks-token".into(),
    ));
    tokio::time::sleep(Duration::from_millis(100)).await;
    let probe = tokio::net::UdpSocket::bind("127.0.0.1:0").await.unwrap();
    probe.connect(public_udp_addr).await.unwrap();
    for (target, payload) in [
        (first_addr, b"one".as_slice()),
        (second_addr, b"two".as_slice()),
    ] {
        let request =
            relay_platform::socks5::encode_udp_datagram(&Destination::Ip(target), payload);
        probe.send(&request).await.unwrap();
        let mut reply = [0u8; 128];
        let size = timeout(Duration::from_secs(3), probe.recv(&mut reply))
            .await
            .unwrap()
            .unwrap();
        let parsed = relay_platform::socks5::parse_udp_datagram(&reply[..size]).unwrap();
        assert_eq!(parsed.destination, Destination::Ip(target));
        assert_eq!(parsed.payload, payload);
    }
    timeout(Duration::from_secs(3), one).await.unwrap().unwrap();
    timeout(Duration::from_secs(3), two).await.unwrap().unwrap();
    server.abort();
    client.abort();
}
