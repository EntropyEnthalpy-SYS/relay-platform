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
