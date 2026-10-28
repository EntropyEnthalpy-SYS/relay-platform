mod common;
#[allow(dead_code)]
#[path = "common/tls.rs"]
mod tls;
use common::*;
use http_body_util::Empty;
use hyper::{
    Request, StatusCode,
    body::Bytes,
    client::conn::http2::{SendRequest, handshake},
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use relay_platform::{
    engine::Engine, http2_connect::ServerConfig, model::*, store::Store, template::TemplateInput,
};
use sha2::{Digest, Sha256};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::{Instant, timeout},
};

fn h2rule() -> Rule {
    let mut r = rule("127.0.0.1:9".parse().unwrap(), Protocol::Tcp);
    r.targets.clear();
    r.inbound_http2_connect = Some(ServerConfig {
        username: None,
        password: None,
        bearer_token_sha256: vec![format!("{:x}", Sha256::digest(b"test-token"))],
        allow_private_destinations: true,
        max_concurrent_streams: 8,
        socket_buffer_bytes: Some(32768),
    });
    r
}
async fn client(address: SocketAddr) -> SendRequest<Empty<Bytes>> {
    let stream = TcpStream::connect(address).await.unwrap();
    let (sender, connection) = handshake(TokioExecutor::new(), TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(connection);
    sender
}
async fn request(
    sender: &mut SendRequest<Empty<Bytes>>,
    target: impl ToString,
    auth: &str,
) -> hyper::Response<hyper::body::Incoming> {
    let request = Request::builder()
        .method("CONNECT")
        .uri(format!("http://{}", target.to_string()))
        .header("proxy-authorization", auth)
        .body(Empty::<Bytes>::new())
        .unwrap();
    timeout(Duration::from_secs(3), sender.send_request(request))
        .await
        .unwrap()
        .unwrap()
}
async fn tunnel(
    sender: &mut SendRequest<Empty<Bytes>>,
    target: SocketAddr,
) -> TokioIo<hyper::upgrade::Upgraded> {
    let mut response = request(sender, target, "Bearer test-token").await;
    assert_eq!(response.status(), StatusCode::OK);
    TokioIo::new(hyper::upgrade::on(&mut response).await.unwrap())
}
async fn exchange(tunnel: &mut TokioIo<hyper::upgrade::Upgraded>, payload: &[u8]) {
    tunnel.write_all(payload).await.unwrap();
    let mut reply = vec![0; payload.len()];
    timeout(Duration::from_secs(8), tunnel.read_exact(&mut reply))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(reply, payload);
}

#[test]
fn validates_managed_h2_and_roundtrips_templates() {
    let mut rule = h2rule();
    rule.validate().unwrap();
    let original = rule.clone();
    rule.inbound_http2_connect
        .as_mut()
        .unwrap()
        .socket_buffer_bytes = Some(1024);
    assert!(rule.validate().is_err());
    rule = original.clone();
    rule.protocol = Protocol::Both;
    assert!(rule.validate().is_err());
    rule = original.clone();
    rule.inbound_http_connect = Some(relay_platform::http_connect::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: true,
    });
    assert!(rule.validate().is_err());
    rule = original.clone();
    rule.inbound_http2_connect
        .as_mut()
        .unwrap()
        .bearer_token_sha256
        .push("not-a-digest".into());
    assert!(rule.validate().is_err());
    rule = original;
    rule.quota_bytes = Some(4096);
    rule.rate_bytes_per_sec = Some(1024);
    rule.deny_destination_ports = vec!["25".into()];
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let (node, _) = store.create_node(&admin, "default", "h2").unwrap();
    let template = store
        .create_template(
            &admin,
            TemplateInput {
                tenant_id: None,
                name: "Managed H2".into(),
                description: "".into(),
                rule: rule.clone(),
                variables: Default::default(),
            },
        )
        .unwrap();
    let initial = store.set_config(&admin, &node.id, 0, vec![]).unwrap();
    let applied = store
        .apply_template(
            &admin,
            &node.id,
            &template.id,
            initial.revision,
            "H2 clone",
            free_address(),
        )
        .unwrap();
    assert_eq!(
        applied.rules[0].inbound_http2_connect,
        rule.inbound_http2_connect
    );
    assert_eq!(applied.rules[0].quota_bytes, rule.quota_bytes);
    assert_eq!(
        applied.rules[0].deny_destination_ports,
        rule.deny_destination_ports
    );
}

#[tokio::test]
async fn h2_bearer_auth_stream_limits_meter_and_quota_are_shared() {
    let echo = tcp_echo().await;
    let mut rule = h2rule();
    rule.inbound_http2_connect
        .as_mut()
        .unwrap()
        .max_concurrent_streams = 2;
    rule.quota_bytes = Some(40);
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone());
    engine.apply(config(rule.clone())).await.unwrap();
    let mut first = client(rule.listen).await;
    let mut second = client(rule.listen).await;
    assert_eq!(
        request(&mut first, echo.address, "Bearer wrong")
            .await
            .status(),
        StatusCode::PROXY_AUTHENTICATION_REQUIRED
    );
    let mut a = tunnel(&mut first, echo.address).await;
    let mut b = tunnel(&mut first, echo.address).await;
    assert_eq!(engine.stats().active_http2_streams, 2);
    assert_eq!(
        request(&mut second, echo.address, "Bearer test-token")
            .await
            .status(),
        StatusCode::TOO_MANY_REQUESTS
    );
    exchange(&mut a, b"1234567890").await;
    exchange(&mut b, b"abcdefghij").await;
    assert_eq!(engine.stats().forwarded_upload_bytes, 20);
    assert_eq!(engine.stats().forwarded_download_bytes, 20);
    let _ = a.write_all(b"over-quota").await;
    let mut one = [0; 1];
    let closed = timeout(Duration::from_secs(2), a.read(&mut one))
        .await
        .unwrap();
    assert!(closed.is_err() || closed.unwrap() == 0);
    engine.shutdown().await.unwrap();
    assert_eq!(engine.stats().active_http2_streams, 0);
    let usage = db.agent_usage(false).unwrap();
    assert_eq!(usage[0].upload_bytes + usage[0].download_bytes, 40);
}

#[tokio::test]
async fn h2_rotation_revokes_live_tunnels_and_old_credentials() {
    let echo = tcp_echo().await;
    let mut rule = h2rule();
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    engine.apply(config(rule.clone())).await.unwrap();
    let mut sender = client(rule.listen).await;
    let mut stream = tunnel(&mut sender, echo.address).await;
    exchange(&mut stream, b"before rotation").await;
    rule.inbound_http2_connect
        .as_mut()
        .unwrap()
        .bearer_token_sha256 = vec![format!("{:x}", Sha256::digest(b"replacement"))];
    let mut next = config(rule.clone());
    next.revision = 2;
    engine.apply(next).await.unwrap();
    let mut byte = [0];
    let ended = timeout(Duration::from_secs(2), stream.read(&mut byte))
        .await
        .unwrap();
    assert!(ended.is_err() || ended.unwrap() == 0);
    let mut sender = client(rule.listen).await;
    assert_eq!(
        request(&mut sender, echo.address, "Bearer test-token")
            .await
            .status(),
        StatusCode::PROXY_AUTHENTICATION_REQUIRED
    );
    assert_eq!(
        request(&mut sender, echo.address, "Bearer replacement")
            .await
            .status(),
        StatusCode::OK
    );
    engine.shutdown().await.unwrap();
    assert_eq!(engine.stats().active_http2_streams, 0);
}

#[tokio::test]
async fn h2_destination_acls_private_policy_and_source_acl_apply() {
    let echo = tcp_echo().await;
    let mut rule = h2rule();
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    for mode in 0..4 {
        rule.deny_destinations.clear();
        rule.deny_destination_ports.clear();
        rule.inbound_http2_connect
            .as_mut()
            .unwrap()
            .allow_private_destinations = true;
        match mode {
            0 => rule.deny_destinations = vec!["127.0.0.0/8".into()],
            1 => rule.deny_destination_ports = vec![echo.address.port().to_string()],
            2 => rule.deny_destinations = vec!["localhost".into()],
            _ => {
                rule.inbound_http2_connect
                    .as_mut()
                    .unwrap()
                    .allow_private_destinations = false
            }
        }
        let mut config = config(rule.clone());
        config.revision = mode + 1;
        engine.apply(config).await.unwrap();
        let mut sender = client(rule.listen).await;
        let target = if mode == 2 {
            format!("localhost:{}", echo.address.port())
        } else {
            echo.address.to_string()
        };
        assert_ne!(
            request(&mut sender, target, "Bearer test-token")
                .await
                .status(),
            StatusCode::OK
        );
    }
    rule.deny_sources = vec!["127.0.0.0/8".parse().unwrap()];
    let mut config = config(rule.clone());
    config.revision = 5;
    engine.apply(config).await.unwrap();
    let mut stream = TcpStream::connect(rule.listen).await.unwrap();
    let mut byte = [0];
    let result = timeout(Duration::from_secs(2), stream.read(&mut byte))
        .await
        .unwrap();
    assert!(result.is_err() || result.unwrap() == 0);
    engine.shutdown().await.unwrap();
    assert_eq!(engine.stats().forwarded_upload_bytes, 0);
}

#[tokio::test]
async fn h2_rate_limit_is_shared_across_connections() {
    let echo = tcp_echo().await;
    let mut rule = h2rule();
    rule.rate_bytes_per_sec = Some(16_384);
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    engine.apply(config(rule.clone())).await.unwrap();
    let mut first = client(rule.listen).await;
    let mut second = client(rule.listen).await;
    let mut a = tunnel(&mut first, echo.address).await;
    let mut b = tunnel(&mut second, echo.address).await;
    let start = Instant::now();
    let payload = vec![42; 32_768];
    tokio::join!(exchange(&mut a, &payload), exchange(&mut b, &payload));
    assert!(
        start.elapsed() >= Duration::from_secs(3),
        "aggregate throttle was bypassed: {:?}",
        start.elapsed()
    );
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn managed_h2_tls_alpn_and_expiry_close_live_tunnels() {
    let certificates = tls::Certificates::new();
    let echo = tcp_echo().await;
    let mut rule = h2rule();
    rule.inbound_tls = Some(TlsServer {
        identity: "server".into(),
        client_ca: None,
    });
    rule.expires_at_ms = Some(now_ms() + 1500);
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::with_tls_directory(
        Store::open(&temp.path().join("agent.db")).unwrap(),
        Some(certificates.root.clone()),
    );
    engine.apply(config(rule.clone())).await.unwrap();
    let (connector, name) = relay_platform::http2_connect::tls_connector_h2(
        &certificates.root.join("root/ca.pem"),
        "relay.test",
    )
    .unwrap();
    let stream = connector
        .connect(name, TcpStream::connect(rule.listen).await.unwrap())
        .await
        .unwrap();
    assert_eq!(stream.get_ref().1.alpn_protocol(), Some(&b"h2"[..]));
    let (mut sender, connection) = handshake(TokioExecutor::new(), TokioIo::new(stream))
        .await
        .unwrap();
    tokio::spawn(connection);
    let mut tunnel = tunnel(&mut sender, echo.address).await;
    exchange(&mut tunnel, b"tls").await;
    let mut byte = [0];
    let result = timeout(Duration::from_secs(3), tunnel.read(&mut byte))
        .await
        .unwrap();
    assert!(result.is_err() || result.unwrap() == 0);
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn managed_h2_requires_h2_alpn_and_valid_client_certificate() {
    use std::{fs, sync::Arc};
    use tokio_rustls::rustls::{
        ClientConfig, RootCertStore,
        pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
    };
    let certificates = tls::Certificates::new();
    let echo = tcp_echo().await;
    let mut rule = h2rule();
    rule.inbound_tls = Some(TlsServer {
        identity: "server".into(),
        client_ca: Some("root".into()),
    });
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::with_tls_directory(
        Store::open(&temp.path().join("agent.db")).unwrap(),
        Some(certificates.root.clone()),
    );
    engine.apply(config(rule.clone())).await.unwrap();
    for (with_identity, h2) in [(false, true), (true, false), (true, true)] {
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(
            &fs::read(certificates.root.join("root/ca.pem")).unwrap(),
        ) {
            roots.add(cert.unwrap()).unwrap();
        }
        let builder = ClientConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_root_certificates(roots);
        let mut cfg = if with_identity {
            builder
                .with_client_auth_cert(
                    CertificateDer::pem_slice_iter(
                        &fs::read(certificates.root.join("client/cert.pem")).unwrap(),
                    )
                    .collect::<Result<Vec<_>, _>>()
                    .unwrap(),
                    PrivateKeyDer::from_pem_slice(
                        &fs::read(certificates.root.join("client/key.pem")).unwrap(),
                    )
                    .unwrap(),
                )
                .unwrap()
        } else {
            builder.with_no_client_auth()
        };
        if h2 {
            cfg.alpn_protocols = vec![b"h2".to_vec()];
        }
        let connector = tokio_rustls::TlsConnector::from(Arc::new(cfg));
        let stream = connector
            .connect(
                ServerName::try_from("relay.test").unwrap(),
                TcpStream::connect(rule.listen).await.unwrap(),
            )
            .await;
        if let Ok(stream) = stream {
            let (mut sender, connection) = handshake(TokioExecutor::new(), TokioIo::new(stream))
                .await
                .unwrap();
            tokio::spawn(connection);
            if with_identity && h2 {
                let mut stream = tunnel(&mut sender, echo.address).await;
                exchange(&mut stream, b"mutual TLS").await;
            } else {
                let request = Request::builder()
                    .method("CONNECT")
                    .uri(format!("http://{}", echo.address))
                    .header("proxy-authorization", "Bearer test-token")
                    .body(Empty::<Bytes>::new())
                    .unwrap();
                assert!(
                    timeout(Duration::from_secs(2), sender.send_request(request))
                        .await
                        .unwrap()
                        .is_err()
                );
            }
        } else {
            assert!(!with_identity || !h2);
        }
    }
    engine.shutdown().await.unwrap();
}

#[tokio::test]
async fn managed_h2_idle_connection_and_rule_disable_release_streams() {
    let echo = tcp_echo().await;
    let mut rule = h2rule();
    rule.idle_timeout_secs = 1;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    engine.apply(config(rule.clone())).await.unwrap();
    let _empty = client(rule.listen).await;
    timeout(Duration::from_secs(3), async {
        while engine.stats().active_tcp != 0 {
            tokio::time::sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .unwrap();
    let mut sender = client(rule.listen).await;
    let mut stream = tunnel(&mut sender, echo.address).await;
    exchange(&mut stream, b"live").await;
    rule.enabled = false;
    let mut next = config(rule);
    next.revision = 2;
    engine.apply(next).await.unwrap();
    let mut byte = [0];
    let ended = timeout(Duration::from_secs(2), stream.read(&mut byte))
        .await
        .unwrap();
    assert!(ended.is_err() || ended.unwrap() == 0);
    engine.shutdown().await.unwrap();
    assert_eq!(engine.stats().active_http2_streams, 0);
}
