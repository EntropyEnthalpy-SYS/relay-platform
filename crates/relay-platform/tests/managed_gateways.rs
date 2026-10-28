mod common;
#[allow(dead_code)]
#[path = "common/tls.rs"]
mod tls;
use anyhow::Context;
use common::*;
use relay_platform::{
    engine::Engine,
    gateway::{Config, Security, WireProtocol},
    model::*,
    store::Store,
};
use serde_json::json;
use std::{
    net::SocketAddr,
    path::{Path, PathBuf},
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    process::Command,
    time::{sleep, timeout},
};

fn gateway(protocol: WireProtocol) -> Rule {
    let mut rule = rule("127.0.0.1:9".parse().unwrap(), Protocol::Tcp);
    rule.targets.clear();
    rule.protocol_gateway = Some(Config {
        listen: free_address(),
        protocol,
        security: Security::Certificate {
            identity: "server".into(),
            server_name: Some("relay.test".into()),
        },
        allow_private_destinations: true,
    });
    rule
}

#[test]
fn reality_exports_only_client_material_and_debug_redacts_credentials() {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    // RFC 7748 Alice public key test vector, independent of the protocol engine.
    let decode = |s: &str| {
        (0..s.len())
            .step_by(2)
            .map(|n| u8::from_str_radix(&s[n..n + 2], 16).unwrap())
            .collect::<Vec<_>>()
    };
    let private = URL_SAFE_NO_PAD.encode(decode(
        "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a",
    ));
    let public = URL_SAFE_NO_PAD.encode(decode(
        "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a",
    ));
    assert_eq!(
        relay_platform::gateway::reality_public_key(&private).unwrap(),
        public
    );
    let mut r = gateway(vless());
    let gw = r.protocol_gateway.as_mut().unwrap();
    gw.security = Security::Reality {
        server_name: "relay.test".into(),
        handshake: "127.0.0.1:443".into(),
        private_key: private.clone(),
        short_id: "aabbccdd".into(),
    };
    let export = gw.client_outbound("relay.test", "client").unwrap();
    assert_eq!(export["tls"]["reality"]["public_key"], public);
    let rendered = export.to_string();
    assert!(!rendered.contains(&private));
    assert!(!rendered.contains("handshake"));
    assert!(!format!("{r:?}").contains(&private));
    let secret = WireProtocol::Trojan {
        password: "must-not-appear-in-debug".into(),
    };
    assert!(!format!("{secret:?}").contains("must-not-appear-in-debug"));
}

async fn udp_request(
    proxy: SocketAddr,
    target: SocketAddr,
    payload: &[u8],
) -> anyhow::Result<Vec<u8>> {
    timeout(Duration::from_secs(8), async {
        let mut control = TcpStream::connect(proxy).await?;
        control.write_all(&[5, 1, 0]).await?;
        let mut selected = [0; 2];
        control.read_exact(&mut selected).await?;
        anyhow::ensure!(selected == [5, 0], "SOCKS greeting rejected");
        control.write_all(&[5, 3, 0, 1, 0, 0, 0, 0, 0, 0]).await?;
        let mut bind = [0; 10];
        control.read_exact(&mut bind).await?;
        anyhow::ensure!(bind[..4] == [5, 0, 0, 1], "UDP association rejected");
        let address = SocketAddr::from((
            [bind[4], bind[5], bind[6], bind[7]],
            u16::from_be_bytes([bind[8], bind[9]]),
        ));
        let socket = UdpSocket::bind("127.0.0.1:0").await?;
        let packet = relay_platform::socks5::encode_udp_datagram(
            &relay_platform::shadowsocks::Destination::Ip(target),
            payload,
        );
        socket.send_to(&packet, address).await?;
        let mut response = [0; 65536];
        let (n, _) = socket.recv_from(&mut response).await?;
        let datagram = relay_platform::socks5::parse_udp_datagram(&response[..n])?;
        anyhow::ensure!(
            datagram.destination.to_string() == target.to_string(),
            "wrong UDP destination"
        );
        anyhow::Ok(datagram.payload.to_vec())
    })
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the pinned engine; set RELAY_TEST_PROTOCOL_ENGINE and run explicitly"]
async fn five_protocols_carry_udp_through_native_acl_and_accounting() {
    let executable = PathBuf::from(std::env::var_os("RELAY_TEST_PROTOCOL_ENGINE").unwrap());
    let certs = tls::Certificates::new();
    let protocols = [
        vless(),
        WireProtocol::Hysteria2 {
            password: "test-udp-password-1234".into(),
        },
        WireProtocol::Tuic {
            uuid: "bf000d23-0752-40b4-affe-68f7707a9661".into(),
            password: "test-udp-password-1234".into(),
        },
        WireProtocol::Trojan {
            password: "test-udp-password-1234".into(),
        },
        WireProtocol::Vmess {
            uuid: "bf000d23-0752-40b4-affe-68f7707a9661".into(),
        },
    ];
    for protocol in protocols {
        let kind = protocol.kind();
        let temp = tempfile::tempdir().unwrap();
        let db = Store::open(&temp.path().join("agent.db")).unwrap();
        let engine = Engine::with_tls_directory(db.clone(), Some(certs.root.clone()))
            .with_protocol_engine(executable.clone());
        let mut r = gateway(protocol);
        r.protocol = Protocol::Both;
        let echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        let target = echo.local_addr().unwrap();
        let task = tokio::spawn(async move {
            let mut data = [0; 2048];
            loop {
                let (n, peer) = echo.recv_from(&mut data).await.unwrap();
                echo.send_to(&data[..n], peer).await.unwrap();
            }
        });
        r.allow_destination_ports = vec![target.port().to_string()];
        engine.apply(config(r.clone())).await.unwrap();
        let (mut process, local) = client(&executable, &certs.root, &r, false).await;
        let payload = vec![0x42; 1024];
        for _ in 0..3 {
            assert_eq!(
                udp_request(local, target, &payload)
                    .await
                    .unwrap_or_else(|e| panic!("{kind} UDP: {e:#}")),
                payload
            );
        }
        process.kill().await.unwrap();
        engine.shutdown().await.unwrap();
        task.abort();
        let usage = db.agent_usage(false).unwrap();
        assert_eq!(usage.len(), 1, "{kind}");
        assert_eq!(usage[0].upload_bytes, 3072, "{kind}");
        assert_eq!(usage[0].download_bytes, 3072, "{kind}");
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the pinned engine; set RELAY_TEST_PROTOCOL_ENGINE and run explicitly"]
async fn policies_crash_restart_and_failed_update_preserve_accounting_boundary() {
    let executable = PathBuf::from(std::env::var_os("RELAY_TEST_PROTOCOL_ENGINE").unwrap());
    let certs = tls::Certificates::new();
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::with_tls_directory(db.clone(), Some(certs.root.clone()))
        .with_protocol_engine(executable.clone());
    let echo = tcp_echo().await;
    let mut r = gateway(vless());
    let mut revision = 0;
    for policy in ["source", "destination", "quota", "expiry", "private"] {
        let mut blocked = r.clone();
        match policy {
            "source" => blocked.deny_sources = vec!["127.0.0.0/8".parse().unwrap()],
            "destination" => blocked.deny_destinations = vec!["127.0.0.0/8".into()],
            "quota" => blocked.quota_bytes = Some(0),
            "expiry" => blocked.expires_at_ms = Some(now_ms() - 1),
            _ => {
                blocked
                    .protocol_gateway
                    .as_mut()
                    .unwrap()
                    .allow_private_destinations = false
            }
        }
        revision += 1;
        let mut cfg = config(blocked.clone());
        cfg.revision = revision;
        engine.apply(cfg).await.unwrap();
        let (mut process, local) = client(&executable, &certs.root, &blocked, false).await;
        assert!(
            request(local, echo.address, b"must-not-pass")
                .await
                .is_err(),
            "{policy} bypassed"
        );
        process.kill().await.unwrap();
    }
    assert!(
        db.agent_usage(false)
            .unwrap()
            .iter()
            .all(|u| u.upload_bytes == 0 && u.download_bytes == 0)
    );
    r.rate_bytes_per_sec = Some(65536);
    revision += 1;
    let mut cfg = config(r.clone());
    cfg.revision = revision;
    engine.apply(cfg.clone()).await.unwrap();
    let (mut process, local) = client(&executable, &certs.root, &r, false).await;
    let payload = vec![0x56; 128 * 1024];
    let start = std::time::Instant::now();
    assert_eq!(
        request(local, echo.address, &payload).await.unwrap(),
        payload
    );
    assert!(
        start.elapsed() >= Duration::from_secs(2),
        "native aggregate rate limit was bypassed"
    );
    let pid = engine.stats().protocol_gateway.unwrap().process_id.unwrap();
    #[cfg(unix)]
    assert!(
        Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status()
            .await
            .unwrap()
            .success()
    );
    timeout(Duration::from_secs(12), async {
        loop {
            let m = engine.stats().protocol_gateway.unwrap();
            if m.running && m.process_id != Some(pid) && m.restarts > 0 {
                break;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .unwrap();
    assert_eq!(
        request(local, echo.address, b"restart").await.unwrap(),
        b"restart"
    );
    let occupied = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let mut bad = cfg.clone();
    bad.revision += 1;
    bad.rules[0].protocol_gateway.as_mut().unwrap().listen = occupied.local_addr().unwrap();
    assert!(engine.apply(bad).await.is_err());
    assert_eq!(engine.revision().await, revision);
    assert_eq!(
        request(local, echo.address, b"rollback").await.unwrap(),
        b"rollback"
    );
    let pid = engine.stats().protocol_gateway.unwrap().process_id;
    let mut bad = cfg.clone();
    bad.revision += 1;
    bad.rules[0].protocol_gateway.as_mut().unwrap().security = Security::Certificate {
        identity: "missing".into(),
        server_name: None,
    };
    assert!(engine.apply(bad).await.is_err());
    assert_eq!(engine.stats().protocol_gateway.unwrap().process_id, pid);
    process.kill().await.unwrap();
    engine.shutdown().await.unwrap();
    let usage = db.agent_usage(false).unwrap();
    assert_eq!(usage[0].upload_bytes, 128 * 1024 + 7 + 8);
    assert_eq!(usage[0].download_bytes, 128 * 1024 + 7 + 8);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the pinned engine; set RELAY_TEST_PROTOCOL_ENGINE and run explicitly"]
async fn reality_vision_authenticates_against_an_owned_tls13_handshake_origin() {
    async fn camouflage(certs: &tls::Certificates, address: SocketAddr) -> anyhow::Result<()> {
        timeout(Duration::from_secs(3), async {
            let mut stream = certs
                .connector(false)
                .connect(
                    "relay.test".try_into().unwrap(),
                    TcpStream::connect(address).await?,
                )
                .await?;
            stream
                .write_all(b"GET / HTTP/1.1\r\nHost: relay.test\r\n\r\n")
                .await?;
            let expected = b"HTTP/1.1 200 OK\r\n";
            let mut response = vec![0; expected.len()];
            stream.read_exact(&mut response).await?;
            anyhow::ensure!(response == expected, "camouflage response differs");
            anyhow::Ok(())
        })
        .await?
    }
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    let executable = PathBuf::from(std::env::var_os("RELAY_TEST_PROTOCOL_ENGINE").unwrap());
    let certs = tls::Certificates::new();
    let temp = tempfile::tempdir().unwrap();
    use tokio_rustls::{
        TlsAcceptor,
        rustls::{
            self,
            pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
        },
    };
    let chain =
        CertificateDer::pem_slice_iter(&std::fs::read(certs.root.join("server/cert.pem")).unwrap())
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
    let key =
        PrivateKeyDer::from_pem_slice(&std::fs::read(certs.root.join("server/key.pem")).unwrap())
            .unwrap();
    let mut tls_config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .unwrap();
    tls_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(std::sync::Arc::new(tls_config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = listener.local_addr().unwrap();
    let server = tokio::spawn(async move {
        loop {
            let (socket, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            tokio::spawn(async move {
                let _ = timeout(Duration::from_secs(8), async {
                    if let Ok(mut stream) = acceptor.accept(socket).await {
                        let mut data = [0; 2048];
                        let _ = stream.read(&mut data).await;
                        let _ = stream
                            .write_all(b"HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n")
                            .await;
                    }
                })
                .await;
            });
        }
    });
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone()).with_protocol_engine(executable.clone());
    let mut r = gateway(WireProtocol::Vless {
        uuid: "bf000d23-0752-40b4-affe-68f7707a9661".into(),
        vision: true,
    });
    r.protocol_gateway.as_mut().unwrap().security = Security::Reality {
        server_name: "relay.test".into(),
        handshake: origin.to_string(),
        private_key: URL_SAFE_NO_PAD.encode([11; 32]),
        short_id: "0123456789abcdef".into(),
    };
    engine.apply(config(r.clone())).await.unwrap();
    let echo = tcp_echo().await;
    let (mut process, local) = client(&executable, &certs.root, &r, false).await;
    assert_eq!(
        request(local, echo.address, b"verified-reality")
            .await
            .unwrap(),
        b"verified-reality"
    );
    let independent = std::env::var_os("RELAY_TEST_MIHOMO");
    if let Some(path) = &independent {
        let (mut client, proxy) = mihomo_client(Path::new(path), &certs.root, &r).await;
        assert_eq!(
            request(proxy, echo.address, b"verified-reality")
                .await
                .unwrap(),
            b"verified-reality"
        );
        client.kill().await.unwrap();
    }
    process.kill().await.unwrap();
    camouflage(&certs, r.protocol_gateway.as_ref().unwrap().listen)
        .await
        .unwrap();
    let mut wrong = r.clone();
    wrong.protocol_gateway.as_mut().unwrap().security = Security::Reality {
        server_name: "relay.test".into(),
        handshake: origin.to_string(),
        private_key: URL_SAFE_NO_PAD.encode([12; 32]),
        short_id: "0123456789abcdef".into(),
    };
    let (mut bad, local) = client(&executable, &certs.root, &wrong, false).await;
    assert!(request(local, echo.address, b"wrong-key").await.is_err());
    bad.kill().await.unwrap();
    // Both camouflage TLS bytes and authenticated payload use the native
    // bridge. Blocking that origin or exhausting the rule budget must prevent
    // Reality from completing a handshake; no direct fallback is permitted.
    let mut baseline = None;
    for (index, policy) in ["quota", "destination"].iter().enumerate() {
        let mut blocked = r.clone();
        if *policy == "quota" {
            blocked.quota_bytes = Some(0);
        } else {
            blocked.deny_destination_ports = vec![origin.port().to_string()];
        }
        let mut cfg = config(blocked.clone());
        cfg.revision = index as u64 + 2;
        engine.apply(cfg).await.unwrap();
        let usage = db.agent_usage(false).unwrap();
        baseline.get_or_insert((usage[0].upload_bytes, usage[0].download_bytes));
        let (mut denied, proxy) = client(&executable, &certs.root, &blocked, false).await;
        assert!(
            request(proxy, echo.address, b"blocked-handshake")
                .await
                .is_err(),
            "Reality camouflage bypassed {policy}"
        );
        denied.kill().await.unwrap();
        assert!(
            camouflage(&certs, blocked.protocol_gateway.as_ref().unwrap().listen)
                .await
                .is_err(),
            "unauthenticated camouflage bypassed {policy}"
        );
    }
    engine.shutdown().await.unwrap();
    server.abort();
    let usage = db.agent_usage(false).unwrap();
    let expected = if independent.is_some() { 32 } else { 16 };
    assert!(
        usage[0].upload_bytes > expected,
        "camouflage upload was unmetered"
    );
    assert!(
        usage[0].download_bytes > expected,
        "camouflage download was unmetered"
    );
    assert_eq!(
        (usage[0].upload_bytes, usage[0].download_bytes),
        baseline.unwrap()
    );
}
fn vless() -> WireProtocol {
    WireProtocol::Vless {
        uuid: "bf000d23-0752-40b4-affe-68f7707a9661".into(),
        vision: false,
    }
}
#[test]
fn gateways_require_private_bridges_tls_authentication_and_exclusive_transports() {
    let r = gateway(vless());
    r.validate().unwrap();
    let parsed: Rule = serde_json::from_value(serde_json::to_value(&r).unwrap()).unwrap();
    assert_eq!(parsed, r);
    let mut invalid = r.clone();
    invalid.listen.set_ip("0.0.0.0".parse().unwrap());
    assert!(invalid.validate().is_err());
    let mut invalid = r.clone();
    invalid.inbound_socks5 = Some(relay_platform::socks5::ServerConfig {
        username: None,
        password: None,
        allow_private_destinations: true,
    });
    assert!(invalid.validate().is_err());
    let mut invalid = r.clone();
    invalid.protocol_gateway.as_mut().unwrap().protocol = WireProtocol::Trojan {
        password: "short".into(),
    };
    assert!(invalid.validate().is_err());
    let mut invalid = r.clone();
    invalid.protocol_gateway.as_mut().unwrap().listen = invalid.listen;
    assert!(config(invalid).validate().is_err());
    let mut shared = r.clone();
    shared.id = "other".into();
    shared.listen = free_address();
    let mut conflict = config(r);
    conflict.rules.push(shared);
    assert!(conflict.validate().is_err());
}
#[tokio::test]
async fn missing_local_engine_rejects_before_binding_or_persisting() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db).with_protocol_engine(PathBuf::from("/no-such-relay-engine"));
    let r = gateway(vless());
    let bridge = r.listen;
    assert!(engine.apply(config(r)).await.is_err());
    assert_eq!(engine.revision().await, 0);
    assert!(TcpStream::connect(bridge).await.is_err());
    engine.shutdown().await.unwrap();
}
async fn client(
    executable: &Path,
    root: &Path,
    r: &Rule,
    wrong_auth: bool,
) -> (tokio::process::Child, SocketAddr) {
    let gw = r.protocol_gateway.as_ref().unwrap();
    let listen = free_address();
    let mut candidate = r.clone();
    if wrong_auth {
        let protocol = &mut candidate.protocol_gateway.as_mut().unwrap().protocol;
        match protocol {
            WireProtocol::Vless { uuid, .. } | WireProtocol::Vmess { uuid } => {
                *uuid = "bf000d23-0752-40b4-affe-68f7707a9662".into()
            }
            WireProtocol::Tuic { password, .. }
            | WireProtocol::Hysteria2 { password }
            | WireProtocol::AnyTls { password }
            | WireProtocol::Trojan { password } => *password = "incorrect-password-1234".into(),
        }
    }
    let rendered = relay_platform::subscription::render(
        relay_platform::subscription::Format::SingBox,
        &relay_platform::subscription::Template {
            host: Some("127.0.0.1".into()),
            ..Default::default()
        },
        &[relay_platform::subscription::Candidate {
            node_name: "test".into(),
            node_tags: vec![],
            rule: candidate,
        }],
    )
    .unwrap();
    let mut document: serde_json::Value = serde_json::from_str(&rendered.content).unwrap();
    document["log"] = json!({"level":"error"});
    document["inbounds"] =
        json!([{"type":"socks","tag":"local","listen":"127.0.0.1","listen_port":listen.port()}]);
    if matches!(gw.security, Security::Certificate { .. }) {
        document["outbounds"][0]["tls"]["certificate_path"] =
            root.join("root/ca.pem").to_str().unwrap().into();
    }
    let path = root.join(format!("client-{}.json", uuid::Uuid::new_v4()));
    relay_platform::store::write_secret(&path, &serde_json::to_vec(&document).unwrap()).unwrap();
    let mut process = Command::new(executable)
        .args(["run", "-c"])
        .arg(path)
        .kill_on_drop(true)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .unwrap();
    for _ in 0..100 {
        assert!(
            process.try_wait().unwrap().is_none(),
            "protocol client exited"
        );
        if TcpStream::connect(listen).await.is_ok() {
            return (process, listen);
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!("protocol client never listened");
}
async fn request(proxy: SocketAddr, target: SocketAddr, message: &[u8]) -> anyhow::Result<Vec<u8>> {
    timeout(Duration::from_secs(6), async {
        let mut stream = TcpStream::connect(proxy).await?;
        stream.write_all(&[5, 1, 0]).await?;
        let mut selected = [0; 2];
        stream
            .read_exact(&mut selected)
            .await
            .context("SOCKS greeting")?;
        anyhow::ensure!(selected == [5, 0], "SOCKS greeting rejected");
        let ip = match target.ip() {
            std::net::IpAddr::V4(ip) => ip.octets(),
            _ => unreachable!(),
        };
        let mut request = vec![5, 1, 0, 1];
        request.extend(ip);
        request.extend(target.port().to_be_bytes());
        stream.write_all(&request).await?;
        let mut reply = [0; 10];
        stream
            .read_exact(&mut reply)
            .await
            .context("SOCKS CONNECT response")?;
        anyhow::ensure!(reply[1] == 0, "CONNECT refused");
        stream.write_all(message).await?;
        let mut received = vec![0; message.len()];
        stream
            .read_exact(&mut received)
            .await
            .context("application response")?;
        anyhow::Ok(received)
    })
    .await?
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the pinned engine; set RELAY_TEST_PROTOCOL_ENGINE and run explicitly"]
async fn six_tls_protocols_forward_through_native_accounting_and_reject_wrong_credentials() {
    let executable =
        PathBuf::from(std::env::var_os("RELAY_TEST_PROTOCOL_ENGINE").expect("engine fixture path"));
    let certs = tls::Certificates::new();
    let uuid = "bf000d23-0752-40b4-affe-68f7707a9661".to_owned();
    let password = "test-protocol-password-only-1234".to_owned();
    let protocols = [
        vless(),
        WireProtocol::Hysteria2 {
            password: password.clone(),
        },
        WireProtocol::Tuic {
            uuid: uuid.clone(),
            password: password.clone(),
        },
        WireProtocol::AnyTls {
            password: password.clone(),
        },
        WireProtocol::Trojan { password },
        WireProtocol::Vmess { uuid },
    ];
    for protocol in protocols {
        let kind = protocol.kind();
        let temp = tempfile::tempdir().unwrap();
        let db = Store::open(&temp.path().join("agent.db")).unwrap();
        let engine = Engine::with_tls_directory(db.clone(), Some(certs.root.clone()))
            .with_protocol_engine(executable.clone());
        let r = gateway(protocol);
        let echo = tcp_echo().await;
        engine
            .apply(config(r.clone()))
            .await
            .unwrap_or_else(|e| panic!("{kind}: {e:#}"));
        assert!(engine.stats().protocol_gateway.unwrap().running);
        // The private bridge refuses a client that has no generated credential.
        let mut unauthorized = TcpStream::connect(r.listen).await.unwrap();
        unauthorized.write_all(&[5, 1, 0]).await.unwrap();
        let mut denial = [0; 2];
        unauthorized.read_exact(&mut denial).await.unwrap();
        assert_eq!(denial, [5, 255]);
        drop(unauthorized);
        let (mut good, local) = client(&executable, &certs.root, &r, false).await;
        let payload = vec![0x4d; 128 * 1024];
        assert_eq!(
            request(local, echo.address, &payload)
                .await
                .unwrap_or_else(|e| panic!("{kind} transfer: {e:#}")),
            payload
        );
        let (mut bad, denied) = client(&executable, &certs.root, &r, true).await;
        assert!(
            request(denied, echo.address, b"denied").await.is_err(),
            "{kind} accepted invalid credentials"
        );
        bad.kill().await.unwrap();
        good.kill().await.unwrap();
        engine.shutdown().await.unwrap();
        let usage = db.agent_usage(false).unwrap();
        assert_eq!(usage.len(), 1);
        assert_eq!(usage[0].upload_bytes, payload.len() as u64, "{kind} upload");
        assert_eq!(
            usage[0].download_bytes,
            payload.len() as u64,
            "{kind} download"
        );
    }
}

async fn mihomo_client(
    executable: &Path,
    root: &Path,
    rule: &Rule,
) -> (tokio::process::Child, SocketAddr) {
    use relay_platform::subscription::{self, Candidate, Format, Template};
    let rendered = subscription::render(
        Format::Clash,
        &Template {
            host: Some("127.0.0.1".into()),
            ..Default::default()
        },
        &[Candidate {
            node_name: "test".into(),
            node_tags: vec![],
            rule: rule.clone(),
        }],
    )
    .unwrap();
    let yaml: serde_yaml::Value = serde_yaml::from_str(&rendered.content).unwrap();
    let mut document = serde_json::to_value(yaml).unwrap();
    let listen = free_address();
    document["socks-port"] = listen.port().into();
    document["allow-lan"] = false.into();
    document["bind-address"] = "127.0.0.1".into();
    document["log-level"] = "warning".into();
    document["mode"] = "rule".into();
    document["dns"] = json!({"enable":false});
    // mihomo binds its SOCKS listener while tunnel.Status is still Suspend/Inner
    // (hub/executor.ApplyConfig), silently closing requests until OnRunning.
    // Probe a fixture-only DIRECT echo route, not the protocol under test, so
    // readiness retries cannot hide an authentication or protocol failure.
    let readiness = tcp_echo().await;
    document["rules"].as_array_mut().unwrap().insert(
        0,
        format!("DST-PORT,{},DIRECT", readiness.address.port()).into(),
    );
    // Some QUIC clients initialize before mihomo loads its custom CA list.
    // Pin our owned certificate instead; verification stays enabled.
    if matches!(
        rule.protocol_gateway.as_ref().unwrap().security,
        Security::Certificate { .. }
    ) {
        use sha2::{Digest, Sha256};
        use tokio_rustls::rustls::pki_types::{CertificateDer, pem::PemObject};
        let pem = std::fs::read(root.join("server/cert.pem")).unwrap();
        let cert = CertificateDer::pem_slice_iter(&pem)
            .next()
            .unwrap()
            .unwrap();
        document["proxies"][0]["fingerprint"] =
            format!("{:x}", Sha256::digest(cert.as_ref())).into();
    }
    let directory = root.join(format!("mihomo-{}", uuid::Uuid::new_v4()));
    std::fs::create_dir(&directory).unwrap();
    let path = directory.join("config.json");
    relay_platform::store::write_secret(&path, &serde_json::to_vec(&document).unwrap()).unwrap();
    let mut process = Command::new(executable)
        .arg("-d")
        .arg(&directory)
        .arg("-f")
        .arg(&path)
        .stdin(std::process::Stdio::null())
        .stdout(if std::env::var_os("RELAY_TEST_CLIENT_LOG").is_some() {
            std::process::Stdio::inherit()
        } else {
            std::process::Stdio::null()
        })
        .stderr(if std::env::var_os("RELAY_TEST_CLIENT_LOG").is_some() {
            std::process::Stdio::inherit()
        } else {
            std::process::Stdio::null()
        })
        .kill_on_drop(true)
        .spawn()
        .unwrap();
    for _ in 0..100 {
        assert!(
            process.try_wait().unwrap().is_none(),
            "mihomo client exited"
        );
        if request(listen, readiness.address, b"fixture-ready")
            .await
            .is_ok_and(|reply| reply == b"fixture-ready")
        {
            return (process, listen);
        }
        sleep(Duration::from_millis(20)).await;
    }
    panic!("mihomo client never listened");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires pinned sing-box server and mihomo client; set RELAY_TEST_PROTOCOL_ENGINE and RELAY_TEST_MIHOMO"]
async fn independent_mihomo_client_uses_exported_tls_configs_for_tcp_and_udp() {
    let executable = PathBuf::from(std::env::var_os("RELAY_TEST_PROTOCOL_ENGINE").unwrap());
    let mihomo = PathBuf::from(std::env::var_os("RELAY_TEST_MIHOMO").unwrap());
    let certs = tls::Certificates::new();
    let protocols = [
        vless(),
        WireProtocol::Hysteria2 {
            password: "independent-client-password".into(),
        },
        WireProtocol::Tuic {
            uuid: "bf000d23-0752-40b4-affe-68f7707a9661".into(),
            password: "independent-client-password".into(),
        },
        WireProtocol::AnyTls {
            password: "independent-client-password".into(),
        },
        WireProtocol::Trojan {
            password: "independent-client-password".into(),
        },
        WireProtocol::Vmess {
            uuid: "bf000d23-0752-40b4-affe-68f7707a9661".into(),
        },
    ];
    for protocol in protocols {
        let kind = protocol.kind();
        let temp = tempfile::tempdir().unwrap();
        let db = Store::open(&temp.path().join("agent.db")).unwrap();
        let engine = Engine::with_tls_directory(db.clone(), Some(certs.root.clone()))
            .with_protocol_engine(executable.clone());
        let udp = !matches!(protocol, WireProtocol::AnyTls { .. });
        let mut rule = gateway(protocol);
        if udp {
            rule.protocol = Protocol::Both;
        }
        engine.apply(config(rule.clone())).await.unwrap();
        let (mut process, local) = mihomo_client(&mihomo, &certs.root, &rule).await;
        let echo = tcp_echo().await;
        let payload = vec![0x47; 32768];
        assert_eq!(
            request(local, echo.address, &payload)
                .await
                .unwrap_or_else(|e| panic!("mihomo {kind} TCP: {e:#}")),
            payload
        );
        let mut size = 32768;
        if udp {
            let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
            let target = socket.local_addr().unwrap();
            let echo = tokio::spawn(async move {
                let mut data = [0; 4096];
                let (n, peer) = socket.recv_from(&mut data).await.unwrap();
                socket.send_to(&data[..n], peer).await.unwrap();
            });
            assert_eq!(
                udp_request(local, target, b"independent-udp")
                    .await
                    .unwrap_or_else(|e| panic!("mihomo {kind} UDP: {e:#}")),
                b"independent-udp"
            );
            echo.await.unwrap();
            size += 15;
        }
        process.kill().await.unwrap();
        engine.shutdown().await.unwrap();
        let usage = db.agent_usage(false).unwrap();
        assert_eq!(usage[0].upload_bytes, size, "mihomo {kind}");
        assert_eq!(usage[0].download_bytes, size, "mihomo {kind}");
    }
}
