mod common;
#[path = "common/tls.rs"]
mod tls;
use common::*;
use relay_platform::{engine::Engine, model::*, store::Store};
use std::{sync::Arc, time::Duration};
use tls::Certificates;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    time::{sleep, timeout},
};
use tokio_rustls::rustls::pki_types::ServerName;

fn server_policy() -> TlsServer {
    TlsServer {
        identity: "server".into(),
        client_ca: Some("root".into()),
    }
}
fn client_policy() -> TlsClient {
    TlsClient {
        server_name: "relay.test".into(),
        ca: Some("root".into()),
        identity: Some("client".into()),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn mutually_authenticated_tls_hop_preserves_binary_half_close_and_payload_accounting() {
    let cert = Certificates::new();
    let tmp = tempfile::tempdir().unwrap();
    let echo = tcp_echo().await;
    let exit_db = Store::open(&tmp.path().join("exit.db")).unwrap();
    let exit = Engine::with_tls_directory(exit_db.clone(), Some(cert.root.clone()));
    let mut out_rule = rule(echo.address, Protocol::Tcp);
    out_rule.inbound_tls = Some(server_policy());
    let encrypted_hop = out_rule.listen;
    exit.apply(config(out_rule)).await.unwrap();
    let entry_db = Store::open(&tmp.path().join("entry.db")).unwrap();
    let entry = Engine::with_tls_directory(entry_db.clone(), Some(cert.root.clone()));
    let mut in_rule = rule(encrypted_hop, Protocol::Tcp);
    in_rule.targets[0].tls = Some(client_policy());
    let forwarding = in_rule.listen;
    entry.apply(config(in_rule)).await.unwrap();
    // Neither application half closes while waiting for this reply: buffered TLS
    // writes must be explicitly flushed for request/response applications.
    let mut stream = TcpStream::connect(forwarding).await.unwrap();
    stream.write_all(b"ping").await.unwrap();
    let mut pong = [0; 4];
    timeout(Duration::from_secs(3), stream.read_exact(&mut pong))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&pong, b"ping");
    stream.shutdown().await.unwrap();
    let mut rest = vec![];
    stream.read_to_end(&mut rest).await.unwrap();
    let payload: Vec<u8> = (0..1_048_576).map(|i| (i % 251) as u8).collect();
    assert_eq!(exchange(forwarding, &payload).await, payload);
    entry.shutdown().await.unwrap();
    exit.shutdown().await.unwrap();
    for db in [&entry_db, &exit_db] {
        let u = db.agent_usage(false).unwrap();
        assert_eq!(u[0].upload_bytes, 1_048_580);
        assert_eq!(u[0].download_bytes, 1_048_580);
    }
}

async fn assert_tls_refused(
    connector: tokio_rustls::TlsConnector,
    address: std::net::SocketAddr,
    name: &str,
) {
    timeout(Duration::from_secs(3), async {
        let stream = TcpStream::connect(address).await.unwrap();
        match connector
            .connect(ServerName::try_from(name.to_owned()).unwrap(), stream)
            .await
        {
            Err(_) => {}
            Ok(mut stream) => {
                // TLS 1.3 clients can finish locally before receiving an mTLS rejection.
                let _ = stream.write_all(b"forbidden").await;
                let _ = stream.flush().await;
                let mut byte = [0];
                assert!(
                    !matches!(stream.read(&mut byte).await, Ok(1)),
                    "unauthorized TLS client received application data"
                );
            }
        }
    })
    .await
    .unwrap();
}

#[tokio::test]
async fn tls_rejects_missing_client_identity_wrong_authority_and_wrong_server_name() {
    let cert = Certificates::new();
    let other = Certificates::new();
    let tmp = tempfile::tempdir().unwrap();
    // No target connection should be opened before inbound client authentication.
    let target = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let db = Store::open(&tmp.path().join("agent.db")).unwrap();
    let engine = Engine::with_tls_directory(db.clone(), Some(cert.root.clone()));
    let mut r = rule(target.local_addr().unwrap(), Protocol::Tcp);
    r.inbound_tls = Some(server_policy());
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    assert_tls_refused(cert.connector(false), address, "relay.test").await;
    assert_tls_refused(other.connector(true), address, "relay.test").await;
    assert_tls_refused(
        cert.connector_with_identity(Some(&other)),
        address,
        "relay.test",
    )
    .await;
    assert_tls_refused(cert.connector(true), address, "wrong.invalid").await;
    assert!(
        timeout(Duration::from_millis(100), target.accept())
            .await
            .is_err()
    );
    assert!(db.agent_usage(false).unwrap().is_empty());
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn outbound_tls_failure_does_not_forward_payload_or_fall_back_to_plaintext() {
    let cert = Certificates::new();
    let tmp = tempfile::tempdir().unwrap();
    let echo = tcp_echo().await;
    let exit = Engine::with_tls_directory(
        Store::open(&tmp.path().join("exit.db")).unwrap(),
        Some(cert.root.clone()),
    );
    let mut exit_rule = rule(echo.address, Protocol::Tcp);
    exit_rule.inbound_tls = Some(server_policy());
    let hop = exit_rule.listen;
    exit.apply(config(exit_rule)).await.unwrap();
    let db = Store::open(&tmp.path().join("entry.db")).unwrap();
    let entry = Engine::with_tls_directory(db.clone(), Some(cert.root.clone()));
    let mut r = rule(hop, Protocol::Tcp);
    let mut tls = client_policy();
    tls.server_name = "wrong.invalid".into();
    r.targets[0].tls = Some(tls);
    let address = r.listen;
    entry.apply(config(r.clone())).await.unwrap();
    let result = timeout(Duration::from_secs(3), async {
        let mut stream = TcpStream::connect(address).await.unwrap();
        stream.write_all(b"must-not-escape").await.unwrap();
        let mut bytes = Vec::new();
        let read = stream.read_to_end(&mut bytes).await;
        assert!(read.is_err() || bytes.is_empty());
    })
    .await;
    assert!(result.is_ok());
    assert!(db.agent_usage(false).unwrap().is_empty());
    let mut plain = r.targets[0].clone();
    plain.address = echo.address.to_string();
    plain.tls = None;
    r.targets.push(plain);
    assert!(r.validate().is_err());
    r.targets.pop();
    r.protocol = Protocol::Both;
    assert!(r.validate().is_err());
    entry.shutdown().await.unwrap();
    exit.shutdown().await.unwrap();
}

#[tokio::test]
async fn invalid_tls_updates_keep_old_listener_and_material_rotation_ends_old_sessions() {
    let cert = Certificates::new();
    let tmp = tempfile::tempdir().unwrap();
    let echo = tcp_echo().await;
    let db = Store::open(&tmp.path().join("agent.db")).unwrap();
    let engine = Arc::new(Engine::with_tls_directory(
        db.clone(),
        Some(cert.root.clone()),
    ));
    let mut r = rule(echo.address, Protocol::Tcp);
    r.inbound_tls = Some(server_policy());
    let address = r.listen;
    let mut c = config(r);
    engine.apply(c.clone()).await.unwrap();
    let connector = cert.connector(true);
    let mut stream = connector
        .connect(
            ServerName::try_from("relay.test").unwrap(),
            TcpStream::connect(address).await.unwrap(),
        )
        .await
        .unwrap();
    stream.write_all(b"one").await.unwrap();
    stream.flush().await.unwrap();
    let mut read = [0; 3];
    stream.read_exact(&mut read).await.unwrap();
    let mut invalid = c.clone();
    invalid.revision = 2;
    invalid.rules[0].inbound_tls.as_mut().unwrap().identity = "absent".into();
    assert!(engine.apply(invalid).await.is_err());
    assert_eq!(engine.revision().await, 1);
    assert_eq!(db.agent_config().unwrap().unwrap().revision, 1);
    stream.write_all(b"two").await.unwrap();
    stream.flush().await.unwrap();
    stream.read_exact(&mut read).await.unwrap();
    assert_eq!(&read, b"two");
    // Reissue the same profile: a new config revision reloads files even if the ID
    // is unchanged, detects new material and cancels all old runtime generations.
    cert.issue("server");
    c.revision = 2;
    engine.apply(c.clone()).await.unwrap();
    assert!(
        !matches!(timeout(Duration::from_secs(3),stream.read(&mut read)).await.unwrap(),Ok(n) if n>0)
    );
    let mut replacement = connector
        .connect(
            ServerName::try_from("relay.test").unwrap(),
            TcpStream::connect(address).await.unwrap(),
        )
        .await
        .unwrap();
    replacement.write_all(b"new").await.unwrap();
    replacement.flush().await.unwrap();
    replacement.read_exact(&mut read).await.unwrap();
    assert_eq!(&read, b"new");
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn slow_tls_handshake_is_bounded_and_releases_connection_capacity() {
    let cert = Certificates::new();
    let tmp = tempfile::tempdir().unwrap();
    let echo = tcp_echo().await;
    let engine = Engine::with_tls_directory(
        Store::open(&tmp.path().join("agent.db")).unwrap(),
        Some(cert.root.clone()),
    );
    let mut r = rule(echo.address, Protocol::Tcp);
    r.inbound_tls = Some(server_policy());
    r.connect_timeout_ms = 100;
    r.max_connections = 1;
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    let mut stalled = TcpStream::connect(address).await.unwrap();
    let mut byte = [0];
    assert!(!matches!(
        timeout(Duration::from_secs(2), stalled.read(&mut byte))
            .await
            .unwrap(),
        Ok(1)
    ));
    for _ in 0..50 {
        if engine.stats().active_tcp == 0 {
            break;
        }
        sleep(Duration::from_millis(10)).await;
    }
    assert_eq!(engine.stats().active_tcp, 0);
    let mut valid = cert
        .connector(true)
        .connect(
            ServerName::try_from("relay.test").unwrap(),
            TcpStream::connect(address).await.unwrap(),
        )
        .await
        .unwrap();
    valid.write_all(b"a").await.unwrap();
    valid.flush().await.unwrap();
    valid.read_exact(&mut byte).await.unwrap();
    assert_eq!(byte[0], b'a');
    engine.shutdown().await.unwrap();
}

#[test]
fn tls_profiles_reject_paths_mismatched_keys_and_public_private_keys() {
    let cert = Certificates::new();
    let mut r = rule("127.0.0.1:8888".parse().unwrap(), Protocol::Tcp);
    r.inbound_tls = Some(server_policy());
    relay_platform::transport::PreparedTls::load(&r, Some(&cert.root)).unwrap();
    std::fs::copy(
        cert.root.join("client/key.pem"),
        cert.root.join("server/key.pem"),
    )
    .unwrap();
    assert!(relay_platform::transport::PreparedTls::load(&r, Some(&cert.root)).is_err());
    cert.issue("server");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(
            cert.root.join("server/key.pem"),
            std::fs::Permissions::from_mode(0o644),
        )
        .unwrap();
        assert!(relay_platform::transport::PreparedTls::load(&r, Some(&cert.root)).is_err());
    }
    r.inbound_tls.as_mut().unwrap().identity = "../../arbitrary-file".into();
    assert!(r.validate().is_err());
    assert!(relay_platform::transport::PreparedTls::load(&r, Some(&cert.root)).is_err());
}

#[tokio::test]
async fn tls12_and_tls13_negotiate_explicitly_and_transfer_application_bytes() {
    use tokio_rustls::{
        TlsConnector,
        rustls::{
            self, ClientConfig, RootCertStore,
            pki_types::{CertificateDer, pem::PemObject},
        },
    };
    let cert = Certificates::new();
    let tmp = tempfile::tempdir().unwrap();
    let echo = tcp_echo().await;
    let engine = Engine::with_tls_directory(
        Store::open(&tmp.path().join("agent.db")).unwrap(),
        Some(cert.root.clone()),
    );
    let mut r = rule(echo.address, Protocol::Tcp);
    r.inbound_tls = Some(TlsServer {
        identity: "server".into(),
        client_ca: None,
    });
    let address = r.listen;
    engine.apply(config(r)).await.unwrap();
    for version in [&rustls::version::TLS12, &rustls::version::TLS13] {
        let mut roots = RootCertStore::empty();
        for c in
            CertificateDer::pem_slice_iter(&std::fs::read(cert.root.join("root/ca.pem")).unwrap())
        {
            roots.add(c.unwrap()).unwrap();
        }
        let client =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_protocol_versions(&[version])
                .unwrap()
                .with_root_certificates(roots)
                .with_no_client_auth();
        let connector = TlsConnector::from(Arc::new(client));
        let mut stream = connector
            .connect(
                ServerName::try_from("relay.test").unwrap(),
                TcpStream::connect(address).await.unwrap(),
            )
            .await
            .unwrap();
        assert_eq!(stream.get_ref().1.protocol_version(), Some(version.version));
        stream.write_all(b"version-checked").await.unwrap();
        stream.flush().await.unwrap();
        let mut reply = [0; 15];
        timeout(Duration::from_secs(2), stream.read_exact(&mut reply))
            .await
            .unwrap()
            .unwrap();
        assert_eq!(&reply, b"version-checked");
    }
    engine.shutdown().await.unwrap();
}
