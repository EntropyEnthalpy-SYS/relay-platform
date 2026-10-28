mod common;
#[allow(dead_code)]
#[path = "common/tls.rs"]
mod tls;
use relay_platform::{
    alerts::{Channel, Target},
    email::{self, Config, Security},
    store::Store,
    telemetry::Severity,
};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncBufReadExt, AsyncRead, AsyncWrite, AsyncWriteExt, BufReader},
    net::TcpListener,
    task::JoinHandle,
    time::timeout,
};

fn config(address: SocketAddr) -> Config {
    Config {
        host: address.ip().to_string(),
        port: address.port(),
        security: Security::LocalRelay,
        from: "relay@example.test".into(),
        to: vec!["one@example.test".into(), "two@example.test".into()],
        username: String::new(),
        password: String::new(),
        ca_pem: String::new(),
    }
}
async fn conversation<S: AsyncRead + AsyncWrite + Unpin>(stream: S) -> Vec<String> {
    let mut stream = BufReader::new(stream);
    let mut received = vec![];
    stream.write_all(b"220 fixture ESMTP\r\n").await.unwrap();
    let mut data = false;
    loop {
        let mut line = String::new();
        if stream.read_line(&mut line).await.unwrap_or(0) == 0 {
            break;
        }
        received.push(line.clone());
        let response = if data {
            if line == ".\r\n" {
                data = false;
                b"250 queued\r\n".as_slice()
            } else {
                continue;
            }
        } else if line.starts_with("EHLO") {
            b"250-fixture\r\n250 8BITMIME\r\n".as_slice()
        } else if line == "DATA\r\n" {
            data = true;
            b"354 send data\r\n".as_slice()
        } else if line == "QUIT\r\n" {
            let _ = stream.write_all(b"221 bye\r\n").await;
            break;
        } else {
            b"250 ok\r\n".as_slice()
        };
        if stream.write_all(response).await.is_err() {
            break;
        }
    }
    received
}
async fn plain() -> (Config, JoinHandle<Vec<String>>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let cfg = config(listener.local_addr().unwrap());
    let task = tokio::spawn(async move { conversation(listener.accept().await.unwrap().0).await });
    (cfg, task)
}

#[test]
fn validation_rejects_header_injection_plaintext_auth_and_remote_plaintext() {
    let mut cfg = config("127.0.0.1:25".parse().unwrap());
    cfg.validate().unwrap();
    cfg.host = "smtp.example.test".into();
    assert!(cfg.validate().is_err());
    cfg.host = "localhost".into();
    assert!(cfg.validate().is_err());
    cfg.host = "127.0.0.1".into();
    cfg.username = "user".into();
    cfg.password = "secret".into();
    assert!(cfg.validate().is_err());
    cfg.security = Security::Starttls;
    cfg.validate().unwrap();
    cfg.from = "user@example.test\r\nBcc: victim@example.test".into();
    assert!(cfg.validate().is_err());
    assert!(!format!("{cfg:?}").contains("secret"));
    assert!(cfg.public().password.is_empty());
}

#[tokio::test]
async fn local_smtp_delivers_to_each_recipient_and_reports_success() {
    let (cfg, server) = plain().await;
    email::send(&cfg, "Relay fixture", "relay-notification-payload")
        .await
        .unwrap();
    let lines = timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap();
    let transcript = lines.join("");
    assert!(transcript.contains("RCPT TO:<one@example.test>"));
    assert!(transcript.contains("RCPT TO:<two@example.test>"));
    assert!(transcript.contains("relay-notification-payload"));
}

#[tokio::test]
async fn starttls_downgrade_never_sends_credentials_or_message() {
    let (mut cfg, server) = plain().await;
    cfg.security = Security::Starttls;
    cfg.username = "fixture-user".into();
    cfg.password = "fixture-secret".into();
    assert!(
        email::send(&cfg, "Relay fixture", "must-not-leak")
            .await
            .is_err()
    );
    let transcript = timeout(Duration::from_secs(3), server)
        .await
        .unwrap()
        .unwrap()
        .join("");
    assert!(
        !transcript.contains("AUTH")
            && !transcript.contains("MAIL FROM")
            && !transcript.contains("must-not-leak")
    );
}

#[tokio::test]
async fn implicit_tls_validates_the_server_before_delivering() {
    use tokio_rustls::{
        TlsAcceptor,
        rustls::{
            ServerConfig,
            pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
        },
    };
    let cert = tls::Certificates::new();
    for trusted in [false, true] {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let mut cfg = config(listener.local_addr().unwrap());
        cfg.security = Security::ImplicitTls;
        if trusted {
            cfg.ca_pem = std::fs::read_to_string(cert.root.join("root/ca.pem")).unwrap();
        }
        let certificates = CertificateDer::pem_slice_iter(
            &std::fs::read(cert.root.join("server/cert.pem")).unwrap(),
        )
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
        let key = PrivateKeyDer::from_pem_slice(
            &std::fs::read(cert.root.join("server/key.pem")).unwrap(),
        )
        .unwrap();
        let server = ServerConfig::builder_with_provider(Arc::new(
            tokio_rustls::rustls::crypto::ring::default_provider(),
        ))
        .with_safe_default_protocol_versions()
        .unwrap()
        .with_no_client_auth()
        .with_single_cert(certificates, key)
        .unwrap();
        let task = tokio::spawn(async move {
            let stream = listener.accept().await.unwrap().0;
            match TlsAcceptor::from(Arc::new(server)).accept(stream).await {
                Ok(tls) => conversation(tls).await,
                Err(_) => vec![],
            }
        });
        let result = email::send(&cfg, "TLS fixture", "encrypted-notification").await;
        assert_eq!(result.is_ok(), trusted, "{result:?}");
        let transcript = timeout(Duration::from_secs(3), task)
            .await
            .unwrap()
            .unwrap()
            .join("");
        assert_eq!(transcript.contains("encrypted-notification"), trusted);
    }
}

#[test]
fn saved_channel_redacts_password_and_never_reuses_it_for_a_changed_server() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    let actor = store.bootstrap(common::PASSWORD).unwrap();
    let mut cfg = config("127.0.0.1:587".parse().unwrap());
    cfg.security = Security::Starttls;
    cfg.username = "fixture-user".into();
    cfg.password = "fixture-secret".into();
    let channel = Channel {
        tenant_id: None,
        id: String::new(),
        name: "SMTP fixture".into(),
        enabled: true,
        min_severity: Severity::Warning,
        target: Target::Smtp {
            config: cfg.clone(),
        },
    };
    let view = store
        .save_alert_channel(&actor, None, channel.clone())
        .unwrap();
    assert!(view.secret_set);
    assert!(
        !serde_json::to_string(&view)
            .unwrap()
            .contains("fixture-secret")
    );
    cfg.password.clear();
    let mut edit = Channel {
        target: Target::Smtp {
            config: cfg.clone(),
        },
        ..channel
    };
    store
        .save_alert_channel(&actor, Some(&view.id), edit.clone())
        .unwrap();
    let Target::Smtp { config: stored } = store.alert_channel(&actor, &view.id).unwrap().target
    else {
        panic!()
    };
    assert_eq!(stored.password, "fixture-secret");
    cfg.host = "different.example.test".into();
    edit.target = Target::Smtp { config: cfg };
    assert!(
        store
            .save_alert_channel(&actor, Some(&view.id), edit)
            .is_err()
    );
}
