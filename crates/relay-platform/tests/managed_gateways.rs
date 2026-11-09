mod common;
#[allow(dead_code)]
#[path = "common/tls.rs"]
mod tls;
use anyhow::Context;
use common::*;
use relay_platform::{
    engine::Engine,
    firewall,
    gateway::{Config, CongestionControl, Masquerade, Obfuscation, Security, WireProtocol},
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
        extra_short_ids: vec![],
        max_time_difference_secs: None,
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
            obfs: None,
            masquerade: None,
        },
        WireProtocol::Tuic {
            uuid: "bf000d23-0752-40b4-affe-68f7707a9661".into(),
            password: "test-udp-password-1234".into(),
            congestion_control: CongestionControl::default(),
            zero_rtt_handshake: false,
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
    // Clients present the first short ID; the server accepts all of them.
    r.protocol_gateway.as_mut().unwrap().security = Security::Reality {
        server_name: "relay.test".into(),
        handshake: origin.to_string(),
        private_key: URL_SAFE_NO_PAD.encode([11; 32]),
        short_id: "0123456789abcdef".into(),
        extra_short_ids: vec!["aa".into(), "fedcba98".into()],
        max_time_difference_secs: Some(60),
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
        extra_short_ids: vec![],
        max_time_difference_secs: None,
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
/// In a process of its own: it closes listeners and binds their ports
/// again, which a process another test starts could hold for that while
/// (see [`an_engine_whose_ports_cannot_be_read_keeps_the_gateway_closed`]).
#[cfg(target_os = "linux")]
#[test]
fn a_failed_engine_start_reopens_the_wildcard_listener_it_replaced() {
    in_own_process("a_failed_engine_start_reopens_the_wildcard_listener_it_replaced_worker");
}
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run by a_failed_engine_start_reopens_the_wildcard_listener_it_replaced in a process of its own"]
async fn a_failed_engine_start_reopens_the_wildcard_listener_it_replaced_worker() {
    if !is_worker("a_failed_engine_start_reopens_the_wildcard_listener_it_replaced_worker") {
        return;
    }
    // Moving a listener from the wildcard to one address on the same port
    // closes the wildcard and stages the new address. When the protocol
    // engine then fails to start, the staged socket must close before the
    // wildcard reopens, or the port stays closed while the old revision is
    // reported. The stand-in engine fails at once while `go` exists, and
    // otherwise first says `started` and waits for `go`.
    use std::os::unix::fs::PermissionsExt;
    let certificates = tls::Certificates::new();
    let temp = tempfile::tempdir().unwrap();
    let (started, go) = (temp.path().join("started"), temp.path().join("go"));
    let executable = temp.path().join("sing-box");
    std::fs::write(
        &executable,
        format!(
            "#!/bin/sh\ncase \"$1\" in\n  version) echo 'sing-box version {}' ;;\n  check) exit 0 ;;\n  run) touch '{}'; while [ ! -e '{}' ]; do sleep 0.05; done; exit 1 ;;\nesac\n",
            relay_platform::gateway::ENGINE_VERSION,
            started.display(),
            go.display()
        ),
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    std::fs::write(&go, "").unwrap();
    let (echo, _udp_echo) = tcp_udp_echo().await;
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = std::sync::Arc::new(
        Engine::with_tls_directory(db.clone(), Some(certificates.root.clone()))
            .with_protocol_engine(executable),
    );
    let mut forward = rule(echo.address, Protocol::Both);
    // Not 127.0.0.1, not even to probe the port: some sandboxes mirror
    // listeners there and hold the port for a moment after they close, which
    // the wildcard would then meet.
    let one = free_address_on(std::net::Ipv4Addr::new(127, 0, 0, 3));
    let port = one.port();
    let other: SocketAddr = format!("127.0.0.2:{port}").parse().unwrap();
    forward.listen = format!("0.0.0.0:{port}").parse().unwrap();
    let first = config(forward);
    engine.apply(first.clone()).await.unwrap();
    let udp = |payload: &'static [u8]| async move {
        let socket = UdpSocket::bind("127.0.0.1:0").await.unwrap();
        socket.send_to(payload, other).await.unwrap();
        let mut buf = [0; 64];
        let (n, _) = timeout(Duration::from_secs(5), socket.recv_from(&mut buf))
            .await
            .expect("UDP exchange timed out")
            .unwrap();
        buf[..n].to_vec()
    };
    assert_eq!(exchange(other, b"wildcard").await, b"wildcard");

    let mut moved = first.clone();
    moved.revision = 2;
    moved.rules[0].listen = one;
    let mut gw = gateway(vless());
    gw.id = "gw".into();
    moved.rules.push(gw);
    let error = engine.apply(moved.clone()).await.unwrap_err();
    assert!(
        format!("{error:#}").contains("protocol engine"),
        "{error:#}"
    );
    assert!(
        !error.to_string().contains("could not be reopened"),
        "{error}"
    );
    assert_eq!(engine.revision().await, 1);
    assert_eq!(db.agent_config().unwrap().unwrap().revision, 1);
    // Only the wildcard answers 127.0.0.2, so both old listeners are back.
    assert_eq!(exchange(other, b"tcp-back").await, b"tcp-back");
    assert_eq!(udp(b"udp-back").await, b"udp-back");

    // Another program takes 127.0.0.2 on the port while the wildcard is
    // closed for the move: the wildcard cannot come back, and the error,
    // which the agent reports, says so rather than only keeping revision 1.
    std::fs::remove_file(&go).unwrap();
    std::fs::remove_file(&started).unwrap();
    let attempt = tokio::spawn({
        let (engine, moved) = (engine.clone(), moved.clone());
        async move { engine.apply(moved).await }
    });
    timeout(Duration::from_secs(10), async {
        while !started.exists() {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the engine never started");
    let taken = std::net::TcpListener::bind(other).unwrap();
    std::fs::write(&go, "").unwrap();
    let error = attempt.await.unwrap().unwrap_err().to_string();
    let lost = format!("TCP 0.0.0.0:{port} of rule rule-one");
    assert!(
        error.starts_with("listeners of the running revision are closed and could not be reopened")
            && error.contains(&lost),
        "{error}"
    );
    assert_eq!(engine.revision().await, 1);
    assert!(TcpStream::connect(one).await.is_err());
    // Every later failed change still names it.
    let error = engine.apply(moved.clone()).await.unwrap_err().to_string();
    assert!(error.contains(&lost), "{error}");
    // Once the port is free, a change that wants the wildcard binds it and
    // the report clears.
    drop(taken);
    let mut back = first.clone();
    back.revision = 3;
    engine.apply(back).await.unwrap();
    assert_eq!(exchange(other, b"tcp-again").await, b"tcp-again");
    assert_eq!(udp(b"udp-again").await, b"udp-again");
    // A change that fails later has nothing closed to report.
    let mut again = moved;
    again.revision = 4;
    let error = engine.apply(again).await.unwrap_err().to_string();
    assert!(!error.contains("could not be reopened"), "{error}");
    assert_eq!(exchange(other, b"tcp-last").await, b"tcp-last");
    engine.shutdown().await.unwrap();
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
    client_from(executable, root, r, wrong_auth, None).await
}
/// A protocol client whose connections to the gateway leave from `source`
/// (a loopback address), so the gateway sees that client address.
async fn client_from(
    executable: &Path,
    root: &Path,
    r: &Rule,
    wrong_auth: bool,
    source: Option<&str>,
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
            | WireProtocol::Hysteria2 { password, .. }
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
    if let Some(source) = source {
        document["outbounds"][0]["inet4_bind_address"] = source.into();
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
            obfs: Some(Obfuscation::Salamander {
                password: "test-obfuscation-password-5678".into(),
            }),
            masquerade: Some(Masquerade::Fixed {
                status_code: 404,
                content: "not found".into(),
            }),
        },
        WireProtocol::Tuic {
            uuid: uuid.clone(),
            password: password.clone(),
            congestion_control: CongestionControl::Cubic,
            zero_rtt_handshake: true,
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
            obfs: Some(Obfuscation::Salamander {
                password: "independent-obfuscation-password".into(),
            }),
            masquerade: None,
        },
        WireProtocol::Tuic {
            uuid: "bf000d23-0752-40b4-affe-68f7707a9661".into(),
            password: "independent-client-password".into(),
            congestion_control: CongestionControl::NewReno,
            zero_rtt_handshake: true,
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

/// A TCP echo that counts the connections it accepted.
async fn counting_echo() -> (
    SocketAddr,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = accepted.clone();
    let task = tokio::spawn(async move {
        while let Ok((mut stream, _)) = listener.accept().await {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            tokio::spawn(async move {
                let (mut read, mut write) = stream.split();
                let _ = tokio::io::copy(&mut read, &mut write).await;
            });
        }
    });
    (address, accepted, task)
}
fn inbound_set(
    id: &str,
    default_action: firewall::Action,
    action: firewall::Action,
    sources: &[&str],
) -> firewall::Spec {
    firewall::Spec {
        id: id.into(),
        name: id.into(),
        direction: firewall::Direction::Inbound,
        default_action,
        rules: if sources.is_empty() {
            vec![]
        } else {
            vec![firewall::SetRule {
                action,
                matches: firewall::Match {
                    sources: sources.iter().map(|s| s.parse().unwrap()).collect(),
                    ..Default::default()
                },
            }]
        },
    }
}
fn desired(
    hash: &str,
    server: Option<firewall::Spec>,
    rule_sets: Vec<firewall::Spec>,
) -> firewall::Desired {
    firewall::Desired {
        hash: hash.into(),
        policy: Some(firewall::Policy {
            server_inbound: server.as_ref().map(|s| s.id.clone()),
            server_outbound: None,
            sets: server.into_iter().chain(rule_sets).collect(),
        }),
    }
}
/// A SOCKS5 CONNECT through a protocol client, held open after one echo.
async fn hold(proxy: SocketAddr, target: SocketAddr) -> anyhow::Result<TcpStream> {
    timeout(Duration::from_secs(6), async {
        let mut stream = TcpStream::connect(proxy).await?;
        stream.write_all(&[5, 1, 0]).await?;
        let mut selected = [0; 2];
        stream.read_exact(&mut selected).await?;
        let std::net::IpAddr::V4(ip) = target.ip() else {
            unreachable!()
        };
        let mut request = vec![5, 1, 0, 1];
        request.extend(ip.octets());
        request.extend(target.port().to_be_bytes());
        stream.write_all(&request).await?;
        let mut reply = [0; 10];
        stream.read_exact(&mut reply).await?;
        anyhow::ensure!(reply[1] == 0, "CONNECT refused");
        echo_once(&mut stream, b"held").await?;
        anyhow::Ok(stream)
    })
    .await?
}
async fn echo_once(stream: &mut TcpStream, message: &[u8]) -> anyhow::Result<()> {
    stream.write_all(message).await?;
    let mut received = vec![0; message.len()];
    timeout(Duration::from_secs(5), stream.read_exact(&mut received)).await??;
    anyhow::ensure!(received == message, "wrong echo");
    Ok(())
}

/// A TLS 1.3 origin for Reality's handshake that counts the connections it
/// accepted and answers one HTTP request on each.
async fn tls_origin(
    certs: &tls::Certificates,
) -> (
    SocketAddr,
    std::sync::Arc<std::sync::atomic::AtomicUsize>,
    tokio::task::JoinHandle<()>,
) {
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
    let mut config = rustls::ServerConfig::builder_with_provider(std::sync::Arc::new(
        rustls::crypto::ring::default_provider(),
    ))
    .with_protocol_versions(&[&rustls::version::TLS13])
    .unwrap()
    .with_no_client_auth()
    .with_single_cert(chain, key)
    .unwrap();
    config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let acceptor = TlsAcceptor::from(std::sync::Arc::new(config));
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let accepted = std::sync::Arc::new(std::sync::atomic::AtomicUsize::new(0));
    let count = accepted.clone();
    let task = tokio::spawn(async move {
        while let Ok((socket, _)) = listener.accept().await {
            count.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
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
    (address, accepted, task)
}
fn reality(origin: SocketAddr) -> Security {
    use base64::{Engine as _, engine::general_purpose::URL_SAFE_NO_PAD};
    Security::Reality {
        server_name: "relay.test".into(),
        handshake: origin.to_string(),
        private_key: URL_SAFE_NO_PAD.encode([11; 32]),
        short_id: "0123456789abcdef".into(),
        extra_short_ids: vec![],
        max_time_difference_secs: Some(60),
    }
}
/// The loopback address of `source`'s family on `port`.
fn loopback(source: std::net::IpAddr, port: u16) -> SocketAddr {
    if source.is_ipv4() {
        SocketAddr::from(([127, 0, 0, 1], port))
    } else {
        SocketAddr::from((std::net::Ipv6Addr::LOCALHOST, port))
    }
}
/// What a TLS client at `source` that does not authenticate sees of a
/// Reality gateway on `port`: the origin's answer, through the engine.
async fn camouflage_from(
    certs: &tls::Certificates,
    source: std::net::IpAddr,
    port: u16,
) -> anyhow::Result<()> {
    timeout(Duration::from_secs(3), async {
        let socket = if source.is_ipv4() {
            tokio::net::TcpSocket::new_v4()?
        } else {
            tokio::net::TcpSocket::new_v6()?
        };
        socket.bind(SocketAddr::new(source, 0))?;
        let tcp = socket.connect(loopback(source, port)).await?;
        let mut stream = certs
            .connector(false)
            .connect("relay.test".try_into().unwrap(), tcp)
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
/// A UDP socket at the loopback address `source`.
async fn probe_socket(source: &str) -> UdpSocket {
    UdpSocket::bind(SocketAddr::new(source.parse().unwrap(), 0))
        .await
        .unwrap()
}
/// The connection ID a stand-in engine's QUIC answers choose.
const ENGINE_ID: &[u8] = &[0xe1, 0xe2, 0xe3, 0xe4];
/// A QUIC long-header packet (Initial, version 1) from connection
/// `source` to `destination`.
fn quic_long(destination: &[u8], source: &[u8]) -> Vec<u8> {
    let mut packet = vec![0xc0, 0, 0, 0, 1, destination.len() as u8];
    packet.extend(destination);
    packet.push(source.len() as u8);
    packet.extend(source);
    packet.extend([0; 32]);
    packet
}
/// A QUIC server's first answer, which chooses connection `id`.
fn quic_answer(id: &[u8]) -> Vec<u8> {
    quic_long(&[7; 8], id)
}
/// A QUIC short-header packet to connection `id`, as a client sends once
/// it has heard the server's answer.
fn quic_to(id: &[u8]) -> Vec<u8> {
    let mut packet = vec![0x40];
    packet.extend(id);
    packet.extend([0; 32]);
    packet
}
/// A real QUIC version 1 Initial from connection `source` to `destination`:
/// a TLS ClientHello for relay.test with ALPN h3, encrypted with the
/// Initial keys and padded to 1200 bytes, what a QUIC client sends first.
/// Anyone can make one; it authenticates nobody.
fn quic_initial(destination: &[u8], source: &[u8]) -> Vec<u8> {
    use tokio_rustls::rustls::{self, quic};
    fn varint(out: &mut Vec<u8>, n: usize) {
        out.extend(((n as u16) | 0x4000).to_be_bytes());
    }
    let provider = std::sync::Arc::new(rustls::crypto::ring::default_provider());
    let mut config = rustls::ClientConfig::builder_with_provider(provider)
        .with_protocol_versions(&[&rustls::version::TLS13])
        .unwrap()
        .with_root_certificates(rustls::RootCertStore::empty())
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h3".to_vec()];
    // Transport parameters: initial_source_connection_id.
    let mut parameters = vec![0x0f, source.len() as u8];
    parameters.extend(source);
    let mut tls = quic::ClientConnection::new(
        std::sync::Arc::new(config),
        quic::Version::V1,
        "relay.test".try_into().unwrap(),
        parameters,
    )
    .unwrap();
    let mut hello = vec![];
    tls.write_hs(&mut hello);
    let keys = rustls::crypto::ring::cipher_suite::TLS13_AES_128_GCM_SHA256
        .tls13()
        .unwrap()
        .quic_suite()
        .unwrap()
        .keys(destination, rustls::Side::Client, quic::Version::V1);
    // A CRYPTO frame at offset 0, then PADDING.
    let mut payload = vec![0x06, 0x00];
    varint(&mut payload, hello.len());
    payload.extend(&hello);
    let mut header = vec![0xc3, 0, 0, 0, 1, destination.len() as u8];
    header.extend(destination);
    header.push(source.len() as u8);
    header.extend(source);
    header.push(0);
    let tag = keys.local.packet.tag_len();
    payload.resize(1200 - header.len() - 2 - 4 - tag, 0);
    varint(&mut header, 4 + payload.len() + tag);
    let number = header.len();
    header.extend([0; 4]);
    let tag = keys
        .local
        .packet
        .encrypt_in_place(0, &header, &mut payload)
        .unwrap();
    let mut packet = header;
    packet.extend(&payload);
    packet.extend(tag.as_ref());
    let (head, rest) = packet.split_at_mut(number);
    let (number, after) = rest.split_at_mut(4);
    keys.local
        .header
        .encrypt_in_place(&after[..16], &mut head[0], number)
        .unwrap();
    packet
}
/// The source connection ID of a QUIC long-header packet.
fn quic_source_id(packet: &[u8]) -> Option<Vec<u8>> {
    if packet.first()? & 0x80 == 0 {
        return None;
    }
    let at = 6 + *packet.get(5)? as usize;
    let length = *packet.get(at)? as usize;
    packet.get(at + 1..at + 1 + length).map(<[u8]>::to_vec)
}
/// Whether the QUIC stack behind `port` answers a datagram from `socket`.
/// Any QUIC server answers a long-header packet of a version it does not
/// speak with a version negotiation packet, before any handshake.
async fn version_negotiation(socket: &UdpSocket, port: u16) -> bool {
    let mut packet = vec![0xc0, 0x1a, 0x2a, 0x3a, 0x4a, 8];
    packet.extend([1; 8]);
    packet.push(8);
    packet.extend([2; 8]);
    packet.resize(1200, 0);
    let source = socket.local_addr().unwrap().ip();
    socket
        .send_to(&packet, loopback(source, port))
        .await
        .unwrap();
    let mut reply = [0; 1500];
    // Version 0 names version negotiation; the reply echoes our ids.
    matches!(
        timeout(Duration::from_secs(1), socket.recv(&mut reply)).await,
        Ok(Ok(n)) if n > 14 && reply[1..5] == [0; 4] && reply[6..14] == [2; 8]
    )
}
/// The engine's block records.
fn blocks(engine: &Engine) -> Vec<relay_platform::connections::Block> {
    let cursor = relay_platform::connections::Cursor {
        stream: String::new(),
        seq: 0,
    };
    engine
        .connection_report(&[], &cursor, None)
        .blocks
        .map(|batch| batch.entries)
        .unwrap_or_default()
}
fn blocked(engine: &Engine, source: &str, detail: &str) -> bool {
    blocks(engine)
        .iter()
        .any(|b| b.source.to_string() == source && b.reason == "firewall" && b.detail == detail)
}
async fn engine_pid(engine: &Engine, not: Option<u32>) -> u32 {
    timeout(Duration::from_secs(15), async {
        loop {
            let m = engine.stats().protocol_gateway.unwrap();
            if m.running
                && let Some(pid) = m.process_id
                && Some(pid) != not
            {
                return pid;
            }
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the engine runs")
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the pinned engine; set RELAY_TEST_PROTOCOL_ENGINE and run explicitly"]
async fn gateway_clients_are_judged_by_their_own_address_before_the_engine() {
    use firewall::Action::{Allow, Deny};
    let executable = PathBuf::from(std::env::var_os("RELAY_TEST_PROTOCOL_ENGINE").unwrap());
    let certs = tls::Certificates::new();
    let (origin, handshakes, origin_task) = tls_origin(&certs).await;
    let handshakes = || handshakes.load(std::sync::atomic::Ordering::SeqCst);
    let udp_target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_address = udp_target.local_addr().unwrap();
    let udp_task = tokio::spawn(async move {
        let mut data = [0; 2048];
        while let Ok((n, peer)) = udp_target.recv_from(&mut data).await {
            let _ = udp_target.send_to(&data[..n], peer).await;
        }
    });
    let ip = |text: &str| -> std::net::IpAddr { text.parse().unwrap() };
    let protocols = [
        // Over TCP, with Reality: an unauthenticated client would make the
        // engine dial the origin.
        vless(),
        // Over QUIC: the engine answers any client's datagram.
        WireProtocol::Hysteria2 {
            password: "test-udp-password-1234".into(),
            obfs: None,
            masquerade: None,
        },
    ];
    for protocol in protocols {
        let kind = protocol.kind();
        let quic = protocol.uses_udp_socket();
        let temp = tempfile::tempdir().unwrap();
        let db = Store::open(&temp.path().join("agent.db")).unwrap();
        let engine = Engine::with_tls_directory(db.clone(), Some(certs.root.clone()))
            .with_protocol_engine(executable.clone());
        let (target, accepted, echo) = counting_echo().await;
        let mut r = gateway(protocol);
        let gateway = r.protocol_gateway.as_mut().unwrap();
        let port = gateway.listen.port();
        // On every address, as the engine listened before: IPv4 clients
        // arrive IPv4-mapped.
        gateway.listen = SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port));
        if quic {
            r.protocol = Protocol::Both;
        } else {
            gateway.security = reality(origin);
        }
        // The server's set lets only 127.0.0.1 in.
        engine.firewall().apply(Some(desired(
            "one",
            Some(inbound_set("server", Deny, Allow, &["127.0.0.1/32"])),
            vec![],
        )));
        engine.apply(config(r.clone())).await.unwrap();
        assert_eq!(engine.firewall().applied_hash().as_deref(), Some("one"));
        let (mut first, from_first) =
            client_from(&executable, &certs.root, &r, false, Some("127.0.0.1")).await;
        let (mut second, from_second) =
            client_from(&executable, &certs.root, &r, false, Some("127.0.0.2")).await;
        assert_eq!(
            request(from_first, target, b"allowed").await.unwrap(),
            b"allowed",
            "{kind}"
        );
        let reached = accepted.load(std::sync::atomic::Ordering::SeqCst);
        assert!(
            request(from_second, target, b"refused").await.is_err(),
            "{kind}: the refused source got through"
        );
        if quic {
            assert_eq!(
                udp_request(from_first, udp_address, b"udp").await.unwrap(),
                b"udp"
            );
            assert!(
                udp_request(from_second, udp_address, b"udp").await.is_err(),
                "{kind}: a refused source's UDP got through"
            );
        }
        assert_eq!(
            accepted.load(std::sync::atomic::Ordering::SeqCst),
            reached,
            "{kind}: the target saw the refused client"
        );
        // What the engine does for anyone it sees, it never did for the
        // refused: no QUIC answer, no Reality handshake or fallback.
        if quic {
            assert!(version_negotiation(&probe_socket("127.0.0.1").await, port).await);
            for refused in ["127.0.0.2", "::1"] {
                assert!(
                    !version_negotiation(&probe_socket(refused).await, port).await,
                    "the engine answered {refused}"
                );
            }
        } else {
            let before = handshakes();
            camouflage_from(&certs, ip("127.0.0.1"), port)
                .await
                .unwrap();
            assert_eq!(handshakes(), before + 1, "the fallback reached the origin");
            for refused in ["127.0.0.2", "::1"] {
                assert!(camouflage_from(&certs, ip(refused), port).await.is_err());
            }
            assert_eq!(
                handshakes(),
                before + 1,
                "the engine dialed for a refused client"
            );
        }
        // Recorded with each client's own address, IPv4-mapped or not.
        let detail = "server inbound rule set: default action denies (server)";
        for refused in ["127.0.0.2", "::1"] {
            assert!(
                blocked(&engine, refused, detail),
                "{kind}: {:?}",
                blocks(&engine)
            );
        }
        // A policy edit holds at once, without restarting the engine.
        let mut held = hold(from_first, target).await.unwrap();
        let pid = engine_pid(&engine, None).await;
        engine.firewall().apply(Some(desired(
            "two",
            Some(inbound_set("server", Allow, Deny, &["127.0.0.1/32"])),
            vec![],
        )));
        assert_eq!(engine.firewall().applied_hash().as_deref(), Some("two"));
        assert!(
            request(from_first, target, b"refused now").await.is_err(),
            "{kind}: the newly refused source got through"
        );
        assert_eq!(
            request(from_second, target, b"allowed now").await.unwrap(),
            b"allowed now",
            "{kind}"
        );
        if quic {
            // Every datagram is judged: the open QUIC connection ends too.
            assert!(echo_once(&mut held, b"cut").await.is_err());
            assert!(udp_request(from_first, udp_address, b"udp").await.is_err());
            assert_eq!(
                udp_request(from_second, udp_address, b"udp").await.unwrap(),
                b"udp"
            );
            assert!(!version_negotiation(&probe_socket("127.0.0.1").await, port).await);
            for allowed in ["127.0.0.2", "::1"] {
                assert!(version_negotiation(&probe_socket(allowed).await, port).await);
            }
        } else {
            // A TCP connection is judged when it opens, as for native rules.
            echo_once(&mut held, b"still open").await.unwrap();
            assert!(
                camouflage_from(&certs, ip("127.0.0.1"), port)
                    .await
                    .is_err()
            );
            for allowed in ["127.0.0.2", "::1"] {
                camouflage_from(&certs, ip(allowed), port).await.unwrap();
            }
        }
        drop(held);
        assert_eq!(
            engine_pid(&engine, None).await,
            pid,
            "{kind}: the engine restarted"
        );
        assert!(blocked(
            &engine,
            "127.0.0.1",
            "server inbound rule set: rule 1 denies (server)"
        ));
        // The rule's own set: only 127.0.0.2 passes, with no server set.
        let mut bound = r.clone();
        bound.firewall_inbound_set = Some("office".into());
        let mut cfg = config(bound);
        cfg.revision = 2;
        engine.firewall().apply(Some(desired(
            "three",
            None,
            vec![inbound_set("office", Deny, Allow, &["127.0.0.2/32"])],
        )));
        engine.apply(cfg).await.unwrap();
        first.kill().await.unwrap();
        second.kill().await.unwrap();
        // (A source's refusals join its record for a minute: a new one.)
        let (mut first, from_first) =
            client_from(&executable, &certs.root, &r, false, Some("127.0.0.5")).await;
        let (mut second, from_second) =
            client_from(&executable, &certs.root, &r, false, Some("127.0.0.2")).await;
        assert!(request(from_first, target, b"x").await.is_err(), "{kind}");
        assert_eq!(
            request(from_second, target, b"y").await.unwrap(),
            b"y",
            "{kind}"
        );
        assert!(blocked(
            &engine,
            "127.0.0.5",
            "rule inbound rule set: default action denies (office)"
        ));
        // No set at all: everyone passes again, as before rule sets.
        let mut cfg = config(r.clone());
        cfg.revision = 3;
        engine.firewall().apply(Some(desired("four", None, vec![])));
        engine.apply(cfg).await.unwrap();
        first.kill().await.unwrap();
        second.kill().await.unwrap();
        let (mut first, from_first) =
            client_from(&executable, &certs.root, &r, false, Some("127.0.0.1")).await;
        assert_eq!(
            request(from_first, target, b"x").await.unwrap(),
            b"x",
            "{kind}"
        );
        // The engine restarts on another port: what was passed to the old
        // one ends, and the same client is passed to the new one.
        let probe = probe_socket("127.0.0.3").await;
        let mut held = hold(from_first, target).await.unwrap();
        if quic {
            assert!(version_negotiation(&probe, port).await);
        }
        let pid = engine_pid(&engine, None).await;
        assert!(
            Command::new("kill")
                .args(["-KILL", &pid.to_string()])
                .status()
                .await
                .unwrap()
                .success()
        );
        assert!(echo_once(&mut held, b"gone").await.is_err(), "{kind}");
        engine_pid(&engine, Some(pid)).await;
        if quic {
            let until = std::time::Instant::now() + Duration::from_secs(10);
            while !version_negotiation(&probe, port).await {
                assert!(
                    std::time::Instant::now() < until,
                    "the association stayed on the old port"
                );
            }
        } else {
            first.kill().await.unwrap();
            let (again, from_again) =
                client_from(&executable, &certs.root, &r, false, Some("127.0.0.1")).await;
            first = again;
            assert_eq!(request(from_again, target, b"z").await.unwrap(), b"z");
        }
        first.kill().await.unwrap();
        engine.shutdown().await.unwrap();
        echo.abort();
    }
    udp_task.abort();
    origin_task.abort();
}

/// Whether a TLS handshake from `source` with the gateway at `port`
/// completes, and how many bytes the server sent at all.
async fn tls_hello_from(certs: &tls::Certificates, source: &str, port: u16) -> (bool, usize) {
    use std::{
        pin::Pin,
        sync::atomic::{AtomicUsize, Ordering},
        task::{Context, Poll},
    };
    use tokio::io::{AsyncRead, AsyncWrite, ReadBuf};
    /// A connection that counts what its peer sent.
    struct Counted(TcpStream, std::sync::Arc<AtomicUsize>);
    impl AsyncRead for Counted {
        fn poll_read(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            buf: &mut ReadBuf<'_>,
        ) -> Poll<std::io::Result<()>> {
            let before = buf.filled().len();
            let polled = Pin::new(&mut self.0).poll_read(cx, buf);
            self.1
                .fetch_add(buf.filled().len() - before, Ordering::SeqCst);
            polled
        }
    }
    impl AsyncWrite for Counted {
        fn poll_write(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
            data: &[u8],
        ) -> Poll<std::io::Result<usize>> {
            Pin::new(&mut self.0).poll_write(cx, data)
        }
        fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_flush(cx)
        }
        fn poll_shutdown(
            mut self: Pin<&mut Self>,
            cx: &mut Context<'_>,
        ) -> Poll<std::io::Result<()>> {
            Pin::new(&mut self.0).poll_shutdown(cx)
        }
    }
    let heard = std::sync::Arc::new(AtomicUsize::new(0));
    let Ok(tcp) = connect_from(source, port).await else {
        return (false, 0);
    };
    let shook = timeout(
        Duration::from_secs(3),
        certs.connector(false).connect(
            "relay.test".try_into().unwrap(),
            Counted(tcp, heard.clone()),
        ),
    )
    .await
    .is_ok_and(|handshake| handshake.is_ok());
    (shook, heard.load(Ordering::SeqCst))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the pinned engine; set RELAY_TEST_PROTOCOL_ENGINE and run explicitly"]
async fn tuic_anytls_trojan_and_vmess_refuse_before_their_handshake() {
    use firewall::Action::{Allow, Deny};
    let executable = PathBuf::from(std::env::var_os("RELAY_TEST_PROTOCOL_ENGINE").unwrap());
    let certs = tls::Certificates::new();
    let uuid = "bf000d23-0752-40b4-affe-68f7707a9661".to_owned();
    let password = "test-protocol-password-only-1234".to_owned();
    let protocols = [
        WireProtocol::Tuic {
            uuid: uuid.clone(),
            password: password.clone(),
            congestion_control: CongestionControl::Cubic,
            zero_rtt_handshake: false,
        },
        WireProtocol::AnyTls {
            password: password.clone(),
        },
        WireProtocol::Trojan { password },
        WireProtocol::Vmess { uuid },
    ];
    for protocol in protocols {
        let kind = protocol.kind();
        let quic = protocol.uses_udp_socket();
        let temp = tempfile::tempdir().unwrap();
        let db = Store::open(&temp.path().join("agent.db")).unwrap();
        let engine = Engine::with_tls_directory(db, Some(certs.root.clone()))
            .with_protocol_engine(executable.clone());
        let mut r = gateway(protocol);
        let gateway = r.protocol_gateway.as_mut().unwrap();
        let port = gateway.listen.port();
        gateway.listen = SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port));
        // The server's set lets only 127.0.0.1 in.
        engine.firewall().apply(Some(desired(
            "one",
            Some(inbound_set("server", Deny, Allow, &["127.0.0.1/32"])),
            vec![],
        )));
        engine
            .apply(config(r.clone()))
            .await
            .unwrap_or_else(|e| panic!("{kind}: {e:#}"));
        // What the engine does for anyone it sees, it does not do for the
        // refused: no QUIC answer, no TLS ServerHello, not a byte.
        if quic {
            assert!(
                version_negotiation(&probe_socket("127.0.0.1").await, port).await,
                "{kind}: the engine did not answer an allowed source"
            );
            for refused in ["127.0.0.2", "::1"] {
                assert!(
                    !version_negotiation(&probe_socket(refused).await, port).await,
                    "{kind}: the engine answered {refused}"
                );
            }
        } else {
            let (shook, heard) = tls_hello_from(&certs, "127.0.0.1", port).await;
            assert!(
                shook && heard > 0,
                "{kind}: no TLS handshake for an allowed source"
            );
            for refused in ["127.0.0.2", "::1"] {
                assert_eq!(
                    tls_hello_from(&certs, refused, port).await,
                    (false, 0),
                    "{kind}: {refused} heard from the engine"
                );
            }
        }
        let detail = "server inbound rule set: default action denies (server)";
        for refused in ["127.0.0.2", "::1"] {
            assert!(
                blocked(&engine, refused, detail),
                "{kind} {refused}: {:?}",
                blocks(&engine)
            );
        }
        engine.shutdown().await.unwrap();
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the pinned engine; set RELAY_TEST_PROTOCOL_ENGINE and run explicitly"]
async fn reality_fallback_is_metered_on_the_bridge_and_held_to_the_outbound_set() {
    let executable = PathBuf::from(std::env::var_os("RELAY_TEST_PROTOCOL_ENGINE").unwrap());
    let certs = tls::Certificates::new();
    let (origin, handshakes, origin_task) = tls_origin(&certs).await;
    let handshakes = || handshakes.load(std::sync::atomic::Ordering::SeqCst);
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(db.clone()).with_protocol_engine(executable.clone());
    let mut r = gateway(vless());
    r.protocol_gateway.as_mut().unwrap().security = reality(origin);
    let port = r.protocol_gateway.as_ref().unwrap().listen.port();
    let localhost: std::net::IpAddr = "127.0.0.1".parse().unwrap();
    // The server's outbound set refuses the origin: the fallback cannot
    // reach it, and the bridge records why.
    let refuse = firewall::Spec {
        id: "no-origin".into(),
        name: "no-origin".into(),
        direction: firewall::Direction::Outbound,
        default_action: firewall::Action::Allow,
        rules: vec![firewall::SetRule {
            action: firewall::Action::Deny,
            matches: firewall::Match {
                destinations: vec!["127.0.0.1".into()],
                ports: vec![origin.port().to_string()],
                ..Default::default()
            },
        }],
    };
    engine.firewall().apply(Some(firewall::Desired {
        hash: "refuse".into(),
        policy: Some(firewall::Policy {
            server_inbound: None,
            server_outbound: Some(refuse.id.clone()),
            sets: vec![refuse],
        }),
    }));
    engine.apply(config(r.clone())).await.unwrap();
    assert!(camouflage_from(&certs, localhost, port).await.is_err());
    assert_eq!(handshakes(), 0, "the fallback reached a refused origin");
    assert!(
        blocks(&engine).iter().any(|b| b.rule_id == r.id
            && b.reason == "firewall"
            && b.detail == "server outbound rule set: rule 1 denies (no-origin)"),
        "{:?}",
        blocks(&engine)
    );
    // Applying a configuration settles the meter: nothing was carried.
    let mut cfg = config(r.clone());
    cfg.revision = 2;
    engine.apply(cfg).await.unwrap();
    assert!(
        db.agent_usage(false)
            .unwrap()
            .iter()
            .all(|u| u.upload_bytes == 0 && u.download_bytes == 0)
    );
    // Without the set the origin answers through the bridge, which meters
    // both directions of the fallback.
    engine.firewall().apply(Some(desired("open", None, vec![])));
    camouflage_from(&certs, localhost, port).await.unwrap();
    assert_eq!(handshakes(), 1);
    engine.shutdown().await.unwrap();
    origin_task.abort();
    let usage = db.agent_usage(false).unwrap();
    assert!(
        usage[0].upload_bytes > 100 && usage[0].download_bytes > 100,
        "the fallback was not metered: {usage:?}"
    );
}

/// A stand-in for the engine at `dir`/sing-box: it names the ports in
/// `dir`/ports as listening, once starts without naming any after `broken`
/// appears, and once says nothing at all after `silent` appears. The test
/// itself listens on the ports it names.
#[cfg(target_os = "linux")]
fn fake_engine(dir: &Path, ports: &[(&Rule, SocketAddr)]) -> PathBuf {
    use std::os::unix::fs::PermissionsExt;
    let executable = dir.join("sing-box");
    std::fs::write(
        &executable,
        "#!/bin/sh\n\
         dir=$(dirname \"$0\")\n\
         case \"$1\" in\n\
         version) echo 'sing-box version 1.14.4';;\n\
         check) exit 0;;\n\
         run)\n\
           if [ -e \"$dir/slow\" ]; then rm -f \"$dir/slow\"; touch \"$dir/slowed\"; sleep 1; fi\n\
           if [ -e \"$dir/silent\" ]; then rm -f \"$dir/silent\"; exec sleep 600; fi\n\
           if [ -e \"$dir/late\" ]; then rm -f \"$dir/late\"; echo 'INFO[0000] sing-box started (0.00s)' >&2; cat \"$dir/ports\" >&2; exec sleep 600; fi\n\
           if [ -e \"$dir/broken\" ]; then rm -f \"$dir/broken\"; else cat \"$dir/ports\" >&2; fi\n\
           echo 'INFO[0000] sing-box started (0.00s)' >&2\n\
           exec sleep 600;;\n\
         esac\n",
    )
    .unwrap();
    std::fs::set_permissions(&executable, std::fs::Permissions::from_mode(0o755)).unwrap();
    name_ports(dir, ports);
    executable
}
/// What the fake engine at `dir` says it listens on from its next start.
#[cfg(target_os = "linux")]
fn name_ports(dir: &Path, ports: &[(&Rule, SocketAddr)]) {
    let lines: String = ports
        .iter()
        .map(|(rule, address)| {
            let gateway = rule.protocol_gateway.as_ref().unwrap();
            let transport = if gateway.protocol.uses_udp_socket() {
                "udp"
            } else {
                "tcp"
            };
            format!(
                "INFO[0000] inbound/{}[in-{}]: {transport} server started at {address}\n",
                gateway.protocol.kind(),
                rule.id
            )
        })
        .collect();
    std::fs::write(dir.join("ports"), lines).unwrap();
}
#[cfg(target_os = "linux")]
async fn kill_engine(engine: &Engine) -> u32 {
    let pid = engine_pid(engine, None).await;
    assert!(
        Command::new("kill")
            .args(["-KILL", &pid.to_string()])
            .status()
            .await
            .unwrap()
            .success()
    );
    engine_pid(engine, Some(pid)).await
}
/// Lets this process hold as many open descriptors as the agent's service
/// unit lets it (`LimitNOFILE=65536`), and at least `descriptors`. Tests
/// share the process, and the public listeners' budget is half of it.
#[cfg(target_os = "linux")]
fn raise_descriptor_limit(descriptors: u64) {
    use nix::libc;
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid rlimit that both calls only read or fill
    // for their duration.
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
        assert!(
            limit.rlim_max >= descriptors,
            "the hard descriptor limit {} is under {descriptors}",
            limit.rlim_max
        );
        limit.rlim_cur = limit.rlim_cur.max(limit.rlim_max.min(65536));
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0);
    }
}
/// A TCP connection to `port` on loopback from `source`.
async fn connect_from(source: &str, port: u16) -> std::io::Result<TcpStream> {
    let source: std::net::IpAddr = source.parse().unwrap();
    let socket = if source.is_ipv4() {
        tokio::net::TcpSocket::new_v4()?
    } else {
        tokio::net::TcpSocket::new_v6()?
    };
    socket.bind(SocketAddr::new(source, 0))?;
    socket.connect(loopback(source, port)).await
}
/// The next connection the fake engine's port takes, if one comes soon.
async fn passed(engine: &TcpListener) -> Option<TcpStream> {
    timeout(Duration::from_millis(500), engine.accept())
        .await
        .ok()
        .map(|accepted| accepted.unwrap().0)
}
async fn read_all(stream: &mut TcpStream) -> Vec<u8> {
    let mut bytes = vec![];
    timeout(Duration::from_secs(3), stream.read_to_end(&mut bytes))
        .await
        .expect("an end")
        .expect("a clean end");
    bytes
}

/// The sockets listening on TCP `port` (their inodes) and every process
/// descriptor that holds one, with the process's name, from /proc.
#[cfg(target_os = "linux")]
fn listening_holders(port: u16) -> String {
    let suffix = format!(":{port:04X}");
    let inodes: Vec<String> = ["/proc/net/tcp", "/proc/net/tcp6"]
        .iter()
        .flat_map(|table| {
            std::fs::read_to_string(table)
                .unwrap_or_default()
                .lines()
                .skip(1)
                .filter_map(|line| {
                    let fields: Vec<&str> = line.split_whitespace().collect();
                    (fields.get(1)?.ends_with(&suffix) && *fields.get(3)? == "0A")
                        .then(|| fields.get(9).map(|inode| inode.to_string()))?
                })
                .collect::<Vec<_>>()
        })
        .collect();
    let mut holders = vec![];
    for process in std::fs::read_dir("/proc").into_iter().flatten().flatten() {
        let pid = process.file_name().to_string_lossy().into_owned();
        if !pid.bytes().all(|b| b.is_ascii_digit()) {
            continue;
        }
        let name = std::fs::read_to_string(process.path().join("comm")).unwrap_or_default();
        for fd in std::fs::read_dir(process.path().join("fd"))
            .into_iter()
            .flatten()
            .flatten()
        {
            let Ok(target) = std::fs::read_link(fd.path()) else {
                continue;
            };
            let target = target.to_string_lossy();
            if inodes
                .iter()
                .any(|inode| target == format!("socket:[{inode}]"))
            {
                holders.push(format!(
                    "pid {pid} ({}) fd {}",
                    name.trim(),
                    fd.file_name().to_string_lossy()
                ));
            }
        }
    }
    format!(
        "listening inodes {inodes:?} held by {holders:?}; this process is pid {}",
        std::process::id()
    )
}
/// Runs the ignored test `worker` in a process of its own: no other test
/// shares its descriptors or forks while it holds them. The process must
/// have run exactly that test (a name that matches none passes nothing),
/// within two minutes; its errors show as they come.
#[cfg(target_os = "linux")]
fn in_own_process(worker: &str) {
    use std::io::Read;
    let mut child = std::process::Command::new(std::env::current_exe().unwrap())
        .args([
            "--exact",
            worker,
            "--ignored",
            "--test-threads=1",
            "--nocapture",
        ])
        .env("RELAY_TEST_WORKER", worker)
        .stdout(std::process::Stdio::piped())
        .spawn()
        .unwrap();
    let mut out = child.stdout.take().unwrap();
    let (sent, read) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        let mut text = String::new();
        let _ = out.read_to_string(&mut text);
        let _ = sent.send(text);
    });
    let deadline = std::time::Instant::now() + Duration::from_secs(120);
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break Some(status);
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(Duration::from_millis(50));
    };
    // What it printed, unless a process it left behind still holds its
    // output open.
    let stdout = read
        .recv_timeout(Duration::from_secs(5))
        .unwrap_or_default();
    assert!(
        status.is_some_and(|s| s.success()) && stdout.contains("test result: ok. 1 passed;"),
        "{worker}: {}\n{stdout}",
        status.map_or("still running after 120 s, stopped".into(), |s| s
            .to_string()),
    );
}
/// Whether this process runs `worker` for [`in_own_process`].
#[cfg(target_os = "linux")]
fn is_worker(worker: &str) -> bool {
    std::env::var("RELAY_TEST_WORKER").as_deref() == Ok(worker)
}
/// After a failed start, the gateway's public port refuses connections. In
/// a process of its own: a test that starts a process forks, and until the
/// fork runs its program it holds a copy of every descriptor of the test
/// process, so a listener another test just closed can take a connection
/// for that while.
#[cfg(target_os = "linux")]
#[test]
fn an_engine_whose_ports_cannot_be_read_keeps_the_gateway_closed() {
    in_own_process("closed_gateway_worker");
}
#[cfg(target_os = "linux")]
#[tokio::test]
#[ignore = "run by an_engine_whose_ports_cannot_be_read_keeps_the_gateway_closed in a process of its own"]
async fn closed_gateway_worker() {
    if !is_worker("closed_gateway_worker") {
        return;
    }
    let certs = tls::Certificates::new();
    let r = gateway(vless());
    let public = r.protocol_gateway.as_ref().unwrap().listen;
    let mut udp = gateway(WireProtocol::Hysteria2 {
        password: "test-udp-password-1234".into(),
        obfs: None,
        masquerade: None,
    });
    udp.id = "other".into();
    // A UDP inbound's port under this gateway's tag stands for nothing.
    let mut wrong = udp.clone();
    wrong.id = r.id.clone();
    let loopback: SocketAddr = "127.0.0.1:443".parse().unwrap();
    // With both gateways, a start that named only this one's port is not
    // ready either.
    let mut both = config(r.clone());
    both.rules.push(udp.clone());
    let cases = [
        ("no port", vec![], config(r.clone())),
        (
            "not loopback",
            vec![(&r, "0.0.0.0:443".parse().unwrap())],
            config(r.clone()),
        ),
        (
            "another transport",
            vec![(&wrong, loopback)],
            config(r.clone()),
        ),
        ("another gateway", vec![(&udp, loopback)], config(r.clone())),
        ("one of two", vec![(&r, loopback)], both),
        // Ports count only before the line saying the engine started.
        (
            "port after the start line",
            vec![(&r, loopback)],
            config(r.clone()),
        ),
    ];
    for (case, ports, config) in cases {
        let temp = tempfile::tempdir().unwrap();
        let executable = fake_engine(temp.path(), &ports);
        if case == "port after the start line" {
            std::fs::write(temp.path().join("late"), "").unwrap();
        }
        let db = Store::open(&temp.path().join("agent.db")).unwrap();
        let engine = Engine::with_tls_directory(db, Some(certs.root.clone()))
            .with_protocol_engine(executable);
        let error = engine.apply(config).await.expect_err(case);
        assert!(error.to_string().contains("ready"), "{case}: {error:#}");
        assert_eq!(engine.revision().await, 0, "{case}");
        if TcpStream::connect(public).await.is_ok() {
            // Who holds a socket listening there.
            let holders = listening_holders(public.port());
            let listening = std::process::Command::new("ss")
                .args(["-ltnpe", &format!("sport = :{}", public.port())])
                .output()
                .map(|out| String::from_utf8_lossy(&out.stdout).into_owned());
            panic!("{case}: {public} accepted a connection; {holders}; ss: {listening:?}");
        }
        engine.shutdown().await.unwrap();
    }
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn the_public_listener_passes_judged_clients_to_the_engine_start_it_knows() {
    let certs = tls::Certificates::new();
    use firewall::Action::{Allow, Deny};
    let temp = tempfile::tempdir().unwrap();
    let r = gateway(vless());
    let port = r.protocol_gateway.as_ref().unwrap().listen.port();
    // The fake engine's first port is the test's own listener.
    let first = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let executable = fake_engine(temp.path(), &[(&r, first.local_addr().unwrap())]);
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine =
        Engine::with_tls_directory(db, Some(certs.root.clone())).with_protocol_engine(executable);
    engine.firewall().apply(Some(desired(
        "one",
        Some(inbound_set("server", Allow, Deny, &["127.0.0.2/32"])),
        vec![],
    )));
    engine.apply(config(r.clone())).await.unwrap();
    // A refused client is never passed on and its record names it. It is
    // reset at once, maybe before its connect returns.
    if let Ok(mut refused) = connect_from("127.0.0.2", port).await {
        let _ = refused.write_all(b"client hello").await;
        let mut nothing = vec![];
        let ended = timeout(Duration::from_secs(3), refused.read_to_end(&mut nothing))
            .await
            .expect("the refused client was held open");
        assert!(
            ended.is_err() || nothing.is_empty(),
            "the refused client was answered"
        );
    }
    assert!(
        passed(&first).await.is_none(),
        "a refused client was passed on"
    );
    assert!(blocked(
        &engine,
        "127.0.0.2",
        "server inbound rule set: rule 1 denies (server)"
    ));
    // Both directions end as each side ends them. The client first:
    let mut client = connect_from("127.0.0.1", port).await.unwrap();
    let mut inside = passed(&first).await.expect("passed on");
    client.write_all(b"abc").await.unwrap();
    client.shutdown().await.unwrap();
    assert_eq!(read_all(&mut inside).await, b"abc");
    inside.write_all(b"after your end").await.unwrap();
    inside.shutdown().await.unwrap();
    assert_eq!(read_all(&mut client).await, b"after your end");
    // and the engine first.
    let mut client = connect_from("127.0.0.1", port).await.unwrap();
    let mut inside = passed(&first).await.expect("passed on");
    inside.write_all(b"hello").await.unwrap();
    inside.shutdown().await.unwrap();
    assert_eq!(read_all(&mut client).await, b"hello");
    client.write_all(b"late").await.unwrap();
    client.shutdown().await.unwrap();
    assert_eq!(read_all(&mut inside).await, b"late");
    // A start that names no port, or says nothing: the configuration is not
    // applied and the previous one comes back, passing clients again.
    let mut changed = config(r.clone());
    changed.revision = 2;
    for flag in ["broken", "silent"] {
        std::fs::write(temp.path().join(flag), "").unwrap();
        assert!(engine.apply(changed.clone()).await.is_err(), "{flag}");
        assert_eq!(engine.revision().await, 1, "{flag}");
        let _client = connect_from("127.0.0.1", port).await.unwrap();
        assert!(passed(&first).await.is_some(), "{flag}: not restored");
    }
    // The engine restarts on another port. What was passed to the old start
    // ends though its port is still open, and new clients go to the new one.
    let mut held = connect_from("127.0.0.1", port).await.unwrap();
    let _held_inside = passed(&first).await.expect("passed on");
    let second = TcpListener::bind("127.0.0.1:0").await.unwrap();
    name_ports(temp.path(), &[(&r, second.local_addr().unwrap())]);
    kill_engine(&engine).await;
    let mut rest = vec![];
    timeout(Duration::from_secs(3), held.read_to_end(&mut rest))
        .await
        .expect("the connection to the old start ended")
        .ok();
    let _client = connect_from("127.0.0.1", port).await.unwrap();
    assert!(
        passed(&second).await.is_some(),
        "not passed to the new start"
    );
    assert!(passed(&first).await.is_none(), "passed to the old start");
    engine.shutdown().await.unwrap();
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gateway_udp_associations_are_judged_limited_and_expire() {
    /// The public listener's bound on client associations, when the rule's
    /// `udp_max_sessions` is lower, and on those of one address.
    const BOUND: usize = 4096;
    const PER_SOURCE: usize = 64;
    raise_descriptor_limit(2 * BOUND as u64 + 1024);
    let certs = tls::Certificates::new();
    use firewall::Action::{Allow, Deny};
    let temp = tempfile::tempdir().unwrap();
    let mut r = gateway(WireProtocol::Hysteria2 {
        password: "test-udp-password-1234".into(),
        obfs: None,
        masquerade: None,
    });
    r.udp_max_sessions = 1;
    let port = r.protocol_gateway.as_ref().unwrap().listen.port();
    let first = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let executable = fake_engine(temp.path(), &[(&r, first.local_addr().unwrap())]);
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine =
        Engine::with_tls_directory(db, Some(certs.root.clone())).with_protocol_engine(executable);
    engine.firewall().apply(Some(desired(
        "one",
        Some(inbound_set("server", Allow, Deny, &["127.0.0.2/32"])),
        vec![],
    )));
    engine.apply(config(r.clone())).await.unwrap();
    let gateway = SocketAddr::from(([127, 0, 0, 1], port));
    /// What the fake engine's port takes next, and from where.
    async fn arrives(engine: &UdpSocket) -> Option<(Vec<u8>, SocketAddr)> {
        let mut buffer = [0; 2048];
        let (n, from) = timeout(Duration::from_millis(500), engine.recv_from(&mut buffer))
            .await
            .ok()?
            .ok()?;
        Some((buffer[..n].to_vec(), from))
    }
    async fn reply(client: &UdpSocket) -> Option<Vec<u8>> {
        let mut buffer = [0; 2048];
        let n = timeout(Duration::from_millis(500), client.recv(&mut buffer))
            .await
            .ok()?
            .ok()?;
        Some(buffer[..n].to_vec())
    }
    // A client at `source` whose first datagram the engine answers, as a
    // QUIC server does, and which shows it heard that answer; and where the
    // engine sees it.
    let answered = |source: String| {
        let first = &first;
        async move {
            let client = probe_socket(&source).await;
            client.send_to(source.as_bytes(), gateway).await.unwrap();
            let (data, inside) = arrives(first).await.expect("passed on");
            assert_eq!(data, source.as_bytes());
            first
                .send_to(&quic_answer(ENGINE_ID), inside)
                .await
                .unwrap();
            assert_eq!(
                reply(&client).await,
                Some(quic_answer(ENGINE_ID)),
                "{source}"
            );
            client.send_to(&quic_to(ENGINE_ID), gateway).await.unwrap();
            assert_eq!(
                arrives(first).await,
                Some((quic_to(ENGINE_ID), inside)),
                "{source}"
            );
            (client, inside)
        }
    };
    let (a, a_inside) = answered("127.0.0.1".into()).await;
    assert!(a_inside.ip().is_loopback() && a_inside.port() != a.local_addr().unwrap().port());
    // A client's association is not one of the rule's UDP sessions, which
    // the bridge counts: with a limit of one, more clients still get in.
    let (b, b_inside) = answered("127.0.0.5".into()).await;
    let _c = answered("127.0.0.6".into()).await;
    // Refused by the set.
    let refused = probe_socket("127.0.0.2").await;
    refused.send_to(b"no", gateway).await.unwrap();
    assert_eq!(arrives(&first).await, None, "passed on anyway");
    assert!(blocked(
        &engine,
        "127.0.0.2",
        "server inbound rule set: rule 1 denies (server)"
    ));
    // A client whose port changes (NAT rebinding) is a new association at
    // once; the old one stays until it idles.
    let (rebound, rebound_inside) = answered("127.0.0.4".into()).await;
    let (_moved, moved_inside) = answered("127.0.0.4".into()).await;
    assert_ne!(rebound_inside, moved_inside);
    // The listener holds at most its bound of associations: fill it with
    // answered ones, one client at a time, and the next is refused.
    for n in 5..BOUND {
        let _ = answered(format!("127.1.{}.{}", n >> 8, n & 0xff)).await;
    }
    // Each datagram is refused and recorded, those sent together too.
    let over = probe_socket("127.0.0.3").await;
    send_joined(&over, &datagrams(&[100, 100, 50]), gateway);
    assert_eq!(arrives(&first).await, None, "passed on over the bound");
    let records = blocks(&engine);
    let refused: Vec<_> = records
        .iter()
        .filter(|b| b.source.to_string() == "127.0.0.3")
        .collect();
    assert!(
        refused.iter().all(|b| b.reason == "udp_session_limit"
            && b.detail == format!("limit {BOUND} client associations"))
            && refused.iter().map(|b| b.count).sum::<u64>() == 3,
        "{records:?}"
    );
    // A full listener keeps the associations it has.
    b.send_to(b"b2", gateway).await.unwrap();
    let (data, inside) = arrives(&first)
        .await
        .expect("an open association still carries");
    assert_eq!((data.as_slice(), inside), (&b"b2"[..], b_inside));
    // Every datagram is judged, either way: once the set refuses 127.0.0.1,
    // the engine's next datagram does not reach it and ends its
    // association, whose place goes to the next client.
    engine.firewall().apply(Some(desired(
        "two",
        Some(inbound_set("server", Allow, Deny, &["127.0.0.1/32"])),
        vec![],
    )));
    first.send_to(b"late", a_inside).await.unwrap();
    assert_eq!(
        reply(&a).await,
        None,
        "the engine still reached a refused client"
    );
    over.send_to(b"in now", gateway).await.unwrap();
    let (data, over_inside) = arrives(&first).await.expect("its place freed");
    assert_eq!(data, b"in now");
    a.send_to(b"a2", gateway).await.unwrap();
    assert_eq!(arrives(&first).await, None);
    let next = probe_socket("127.0.0.8").await;
    next.send_to(b"waiting", gateway).await.unwrap();
    assert_eq!(arrives(&first).await, None, "passed on over the bound");
    // Associations with nothing either way expire after the engine's QUIC
    // idle timeout, the one left behind by a port change too, and their
    // places go to the next clients.
    sleep(Duration::from_secs(32)).await;
    first.send_to(b"to the expired", over_inside).await.unwrap();
    assert_eq!(reply(&over).await, None);
    first
        .send_to(b"to the old port", rebound_inside)
        .await
        .unwrap();
    assert_eq!(reply(&rebound).await, None);
    next.send_to(b"expired", gateway).await.unwrap();
    assert_eq!(
        arrives(&first).await.map(|(data, _)| data).as_deref(),
        Some(&b"expired"[..])
    );
    // One address holds a few associations at most, and one the engine
    // never answers ends soon, whatever its client sends.
    let mut quiet = vec![];
    for _ in 0..PER_SOURCE - 2 {
        let client = probe_socket("127.0.0.7").await;
        client.send_to(b"quiet", gateway).await.unwrap();
        assert!(arrives(&first).await.is_some());
        quiet.push(client);
    }
    let _two_more = [
        answered("127.0.0.7".into()).await,
        answered("127.0.0.7".into()).await,
    ];
    let extra = probe_socket("127.0.0.7").await;
    extra.send_to(b"extra", gateway).await.unwrap();
    assert_eq!(
        arrives(&first).await,
        None,
        "passed on over the address's bound"
    );
    assert!(
        blocks(&engine)
            .iter()
            .any(|b| b.source.to_string() == "127.0.0.7"
                && b.detail == format!("limit {PER_SOURCE} client associations from one address")),
        "{:?}",
        blocks(&engine)
    );
    for _ in 0..2 {
        sleep(Duration::from_secs(2)).await;
        for client in &quiet {
            client.send_to(b"still quiet", gateway).await.unwrap();
        }
    }
    sleep(Duration::from_secs(2)).await;
    while timeout(Duration::from_millis(200), first.recv_from(&mut [0; 2048]))
        .await
        .is_ok()
    {}
    extra.send_to(b"extra", gateway).await.unwrap();
    assert_eq!(
        arrives(&first).await.map(|(data, _)| data).as_deref(),
        Some(&b"extra"[..]),
        "the unanswered associations kept their places"
    );
    // The engine restarts on another port: a client with an association to
    // the old start is passed to the new one, not to the old one, which is
    // still open.
    let second = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    name_ports(temp.path(), &[(&r, second.local_addr().unwrap())]);
    kill_engine(&engine).await;
    extra.send_to(b"moved", gateway).await.unwrap();
    assert_eq!(
        arrives(&second).await.map(|(data, _)| data).as_deref(),
        Some(&b"moved"[..])
    );
    assert_eq!(arrives(&first).await, None);
    engine.shutdown().await.unwrap();
}

/// An association lives past its first seconds only once its client shows
/// it hears the engine: by addressing the connection the engine's QUIC
/// answer chose, or, where obfuscation hides QUIC headers, by any datagram
/// after an answer. A client that keeps sending what it sent first, as one
/// that sent from an address it does not hold (spoofed) does, shows
/// nothing.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn associations_last_once_their_client_shows_it_hears_the_engine() {
    let certs = tls::Certificates::new();
    let temp = tempfile::tempdir().unwrap();
    let hysteria2 = |id: &str, obfs: Option<Obfuscation>| {
        let mut rule = gateway(WireProtocol::Hysteria2 {
            password: "test-udp-password-1234".into(),
            obfs,
            masquerade: None,
        });
        rule.id = id.into();
        rule
    };
    let plain = hysteria2("plain", None);
    let opaque = hysteria2(
        "opaque",
        Some(Obfuscation::Salamander {
            password: "test-obfs-password-1234".into(),
        }),
    );
    let plain_engine = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let opaque_engine = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let executable = fake_engine(
        temp.path(),
        &[
            (&plain, plain_engine.local_addr().unwrap()),
            (&opaque, opaque_engine.local_addr().unwrap()),
        ],
    );
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine =
        Engine::with_tls_directory(db, Some(certs.root.clone())).with_protocol_engine(executable);
    let mut cfg = config(plain.clone());
    cfg.rules.push(opaque.clone());
    engine.apply(cfg).await.unwrap();
    let public = |rule: &Rule| {
        SocketAddr::from((
            [127, 0, 0, 1],
            rule.protocol_gateway.as_ref().unwrap().listen.port(),
        ))
    };
    async fn arrives(engine: &UdpSocket) -> SocketAddr {
        let mut buffer = [0; 2048];
        timeout(Duration::from_secs(1), engine.recv_from(&mut buffer))
            .await
            .expect("not passed on")
            .unwrap()
            .1
    }
    /// A client whose first datagram the engine answers with `answer`, if
    /// any, and which then sends `then`, if any; and where the engine sees
    /// it.
    async fn opened(
        engine: &UdpSocket,
        gateway: SocketAddr,
        answer: Option<&[u8]>,
        then: Option<&[u8]>,
    ) -> (UdpSocket, SocketAddr) {
        let client = probe_socket("127.0.0.1").await;
        client.send_to(b"first", gateway).await.unwrap();
        let inside = arrives(engine).await;
        if let Some(answer) = answer {
            engine.send_to(answer, inside).await.unwrap();
            timeout(Duration::from_secs(1), client.recv(&mut [0; 2048]))
                .await
                .expect("the answer did not come back")
                .unwrap();
        }
        if let Some(then) = then {
            client.send_to(then, gateway).await.unwrap();
            assert_eq!(arrives(engine).await, inside);
        }
        (client, inside)
    }
    let answer = quic_answer(ENGINE_ID);
    let (plain_at, opaque_at) = (public(&plain), public(&opaque));
    let shown = [
        // To the connection the engine chose, by a short header or a long.
        (
            "short header",
            &plain_engine,
            plain_at,
            opened(
                &plain_engine,
                plain_at,
                Some(&answer[..]),
                Some(&quic_to(ENGINE_ID)[..]),
            )
            .await,
        ),
        (
            "long header",
            &plain_engine,
            plain_at,
            opened(
                &plain_engine,
                plain_at,
                Some(&answer[..]),
                Some(&quic_long(ENGINE_ID, &[7; 8])[..]),
            )
            .await,
        ),
        (
            "obfuscated",
            &opaque_engine,
            opaque_at,
            opened(
                &opaque_engine,
                opaque_at,
                Some(&b"answer"[..]),
                Some(&b"then"[..]),
            )
            .await,
        ),
    ];
    let unshown = [
        (
            "sent its first datagram again",
            &plain_engine,
            plain_at,
            opened(
                &plain_engine,
                plain_at,
                Some(&answer[..]),
                Some(&b"first"[..]),
            )
            .await,
        ),
        (
            "addressed another connection",
            &plain_engine,
            plain_at,
            opened(
                &plain_engine,
                plain_at,
                Some(&answer[..]),
                Some(&quic_to(&[1, 2, 3, 4])[..]),
            )
            .await,
        ),
        (
            "an answer that is not QUIC",
            &plain_engine,
            plain_at,
            opened(
                &plain_engine,
                plain_at,
                Some(&b"answer"[..]),
                Some(&quic_to(ENGINE_ID)[..]),
            )
            .await,
        ),
        (
            "never answered",
            &plain_engine,
            plain_at,
            opened(&plain_engine, plain_at, None, Some(&quic_to(ENGINE_ID)[..])).await,
        ),
        (
            "obfuscated, nothing after the answer",
            &opaque_engine,
            opaque_at,
            opened(&opaque_engine, opaque_at, Some(&b"answer"[..]), None).await,
        ),
    ];
    sleep(Duration::from_secs(6)).await;
    for (case, engine, gateway, (client, inside)) in &shown {
        client.send_to(b"later", gateway).await.unwrap();
        assert_eq!(arrives(engine).await, *inside, "{case}: ended");
    }
    for (case, engine, gateway, (client, inside)) in &unshown {
        client.send_to(b"later", gateway).await.unwrap();
        assert_ne!(arrives(engine).await, *inside, "{case}: kept");
    }
    // Once shown, an association idles out from its last datagram, not its
    // first: one that keeps sending outlives the 31 s an idle one gets.
    let (_, engine_port, gateway, (client, inside)) = &shown[0];
    for _ in 0..4 {
        sleep(Duration::from_secs(8)).await;
        client.send_to(b"still", gateway).await.unwrap();
        assert_eq!(arrives(engine_port).await, *inside, "ended while in use");
    }
    engine.shutdown().await.unwrap();
}

/// An association the engine keeps busy takes turns with the rest of the
/// Agent: on a runtime of one thread, the listener still passes the
/// client's datagrams on.
#[cfg(target_os = "linux")]
#[tokio::test]
async fn a_busy_association_takes_turns_with_the_rest_of_the_agent() {
    let certs = tls::Certificates::new();
    let temp = tempfile::tempdir().unwrap();
    let r = gateway(WireProtocol::Hysteria2 {
        password: "test-udp-password-1234".into(),
        obfs: None,
        masquerade: None,
    });
    let port = r.protocol_gateway.as_ref().unwrap().listen.port();
    let engine_side = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let executable = fake_engine(temp.path(), &[(&r, engine_side.local_addr().unwrap())]);
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine =
        Engine::with_tls_directory(db, Some(certs.root.clone())).with_protocol_engine(executable);
    engine.apply(config(r.clone())).await.unwrap();
    // The client and the stand-in engine run on threads of their own. The
    // engine answers the client's first datagram with as many as three
    // threads can send, more than one thread passes on, for three seconds;
    // meanwhile the client sends a datagram every 10 ms, as a QUIC client
    // acknowledges what it receives. Those reach the engine during the flood
    // only if the busy association lets the listener's task run.
    let gateway_address = SocketAddr::from(([127, 0, 0, 1], port));
    let client = std::net::UdpSocket::bind("127.0.0.1:0").unwrap();
    let acknowledged = tokio::task::spawn_blocking(move || {
        use std::time::Instant;
        client.send_to(b"first", gateway_address).unwrap();
        let mut buffer = [0; 2048];
        engine_side
            .set_read_timeout(Some(Duration::from_secs(5)))
            .unwrap();
        let (n, inside) = engine_side.recv_from(&mut buffer).unwrap();
        assert_eq!(&buffer[..n], b"first");
        engine_side
            .set_read_timeout(Some(Duration::from_millis(100)))
            .unwrap();
        let replies = datagrams(&[1200; 40]);
        let started = Instant::now();
        let (counted, until) = (
            started + Duration::from_secs(1),
            started + Duration::from_secs(3),
        );
        std::thread::scope(|scope| {
            for _ in 0..3 {
                scope.spawn(|| {
                    while Instant::now() < until {
                        send_joined(&engine_side, &replies, inside);
                    }
                });
            }
            scope.spawn(|| {
                while Instant::now() < until {
                    client.send_to(b"ack", gateway_address).unwrap();
                    std::thread::sleep(Duration::from_millis(10));
                }
            });
            // What reaches the engine in the flood's last two seconds.
            let mut acknowledged = 0;
            while Instant::now() < until {
                if let Ok((n, _)) = engine_side.recv_from(&mut buffer)
                    && &buffer[..n] == b"ack"
                    && Instant::now() >= counted
                {
                    acknowledged += 1;
                }
            }
            acknowledged
        })
    })
    .await
    .unwrap();
    assert!(
        acknowledged >= 10,
        "{acknowledged} of the client's datagrams reached the engine in two seconds"
    );
    engine.shutdown().await.unwrap();
}

/// A stand-in engine port that keeps the connections it takes, handed to
/// the test as they come.
async fn engine_port() -> (SocketAddr, tokio::sync::mpsc::UnboundedReceiver<TcpStream>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let (taken, receiver) = tokio::sync::mpsc::unbounded_channel();
    tokio::spawn(async move {
        while let Ok((stream, _)) = listener.accept().await {
            if taken.send(stream).is_err() {
                return;
            }
        }
    });
    (address, receiver)
}
/// The next connection [`engine_port`] took, if one comes soon.
async fn taken(inside: &mut tokio::sync::mpsc::UnboundedReceiver<TcpStream>) -> Option<TcpStream> {
    timeout(Duration::from_millis(500), inside.recv())
        .await
        .ok()
        .flatten()
}
/// Connects from `source` and expects the gateway to refuse at once,
/// answering nothing.
async fn refused_from(source: &str, port: u16) {
    if let Ok(mut client) = connect_from(source, port).await {
        let _ = client.write_all(b"client hello").await;
        let mut nothing = vec![];
        let ended = timeout(Duration::from_secs(3), client.read_to_end(&mut nothing))
            .await
            .expect("the refused client was held open");
        assert!(
            ended.is_err() || nothing.is_empty(),
            "{source} was answered"
        );
    }
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gateway_tcp_clients_are_held_per_address_and_freed_once_one_side_ends() {
    const PER_SOURCE: usize = 256;
    raise_descriptor_limit(4096);
    let certs = tls::Certificates::new();
    let temp = tempfile::tempdir().unwrap();
    let mut r = gateway(vless());
    r.idle_timeout_secs = 1;
    let port = r.protocol_gateway.as_ref().unwrap().listen.port();
    let (engine_address, mut inside) = engine_port().await;
    let executable = fake_engine(temp.path(), &[(&r, engine_address)]);
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine =
        Engine::with_tls_directory(db, Some(certs.root.clone())).with_protocol_engine(executable);
    engine.apply(config(r.clone())).await.unwrap();
    let mut clients = vec![];
    let mut insides = vec![];
    for n in 0..PER_SOURCE {
        clients.push(connect_from("127.0.0.1", port).await.unwrap());
        insides.push(
            taken(&mut inside)
                .await
                .unwrap_or_else(|| panic!("connection {n} was not passed on")),
        );
    }
    // One more from the same address is refused and recorded; one from
    // another address is not.
    refused_from("127.0.0.1", port).await;
    assert!(
        taken(&mut inside).await.is_none(),
        "passed on over the address's bound"
    );
    assert!(
        blocks(&engine)
            .iter()
            .any(|b| b.source.to_string() == "127.0.0.1"
                && b.reason == "connection_limit"
                && b.detail == format!("limit {PER_SOURCE} client connections from one address")),
        "{:?}",
        blocks(&engine)
    );
    let _other = connect_from("127.0.0.2", port).await.unwrap();
    assert!(
        taken(&mut inside).await.is_some(),
        "another address was refused"
    );
    // Client connections use TCP keepalive: the kernel's keepalive timer
    // runs on the gateway's side of one, due within a minute.
    let public = SocketAddr::from(([127, 0, 0, 1], port));
    let (kind, due) = tcp_timer(public, clients[1].local_addr().unwrap()).expect("no such socket");
    assert_eq!(kind, 2, "no keepalive timer");
    assert!((50.0..=60.0).contains(&due), "keepalive due in {due} s");
    // An open connection has no idle limit, however quiet.
    sleep(Duration::from_secs(2)).await;
    clients[1].write_all(b"still open").await.unwrap();
    let mut received = [0; 10];
    timeout(Duration::from_secs(3), insides[1].read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received, b"still open");
    // The engine ends a connection whose client then stays quiet: the
    // client sees the end at once, and once quiet past the rule's idle
    // timeout its place comes back.
    drop(insides.remove(0));
    let mut quiet = clients.remove(0);
    assert_eq!(read_all(&mut quiet).await, b"");
    refused_from("127.0.0.1", port).await;
    sleep(Duration::from_secs(2)).await;
    let _back = connect_from("127.0.0.1", port).await.unwrap();
    assert!(
        taken(&mut inside).await.is_some(),
        "the quiet client kept its place"
    );
    // A client that ends its direction first still gets what the engine
    // sends; once the engine is quiet past the idle timeout, the
    // connection ends and its place comes back.
    let (mut ending, mut engine_side) = (clients.remove(0), insides.remove(0));
    ending.shutdown().await.unwrap();
    assert_eq!(read_all(&mut engine_side).await, b"");
    engine_side.write_all(b"after the end").await.unwrap();
    let mut received = [0; 13];
    timeout(Duration::from_secs(3), ending.read_exact(&mut received))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&received, b"after the end");
    refused_from("127.0.0.1", port).await;
    sleep(Duration::from_secs(2)).await;
    assert_eq!(read_all(&mut ending).await, b"", "the connection was held");
    let _again = connect_from("127.0.0.1", port).await.unwrap();
    assert!(
        taken(&mut inside).await.is_some(),
        "the client that ended first kept its place"
    );
    drop(engine_side);
    engine.shutdown().await.unwrap();
}
/// The kind and the seconds left of the kernel's timer on the TCP socket
/// from `local` to `remote` (IPv4), from /proc/net/tcp: kind 2 is the
/// keepalive timer of an idle connection.
#[cfg(target_os = "linux")]
fn tcp_timer(local: SocketAddr, remote: SocketAddr) -> Option<(u8, f64)> {
    let hex = |address: SocketAddr| match address {
        SocketAddr::V4(v4) => Some(format!(
            "{:08X}:{:04X}",
            u32::from_le_bytes(v4.ip().octets()),
            v4.port()
        )),
        SocketAddr::V6(_) => None,
    };
    let (local, remote) = (hex(local)?, hex(remote)?);
    std::fs::read_to_string("/proc/net/tcp")
        .ok()?
        .lines()
        .skip(1)
        .find_map(|line| {
            let fields: Vec<&str> = line.split_whitespace().collect();
            if fields.get(1) != Some(&local.as_str()) || fields.get(2) != Some(&remote.as_str()) {
                return None;
            }
            let (kind, due) = fields.get(5)?.split_once(':')?;
            // In clock ticks of 1/100 s.
            Some((
                u8::from_str_radix(kind, 16).ok()?,
                u64::from_str_radix(due, 16).ok()? as f64 / 100.0,
            ))
        })
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dual_stack_gateways_judge_ipv4_clients_by_their_ipv4_address() {
    use firewall::Action::{Allow, Deny};
    let certs = tls::Certificates::new();
    let temp = tempfile::tempdir().unwrap();
    let mut tcp = gateway(vless());
    tcp.id = "tcp-gw".into();
    let mut udp = gateway(WireProtocol::Hysteria2 {
        password: "test-udp-password-1234".into(),
        obfs: None,
        masquerade: None,
    });
    udp.id = "udp-gw".into();
    // On every address: IPv4 clients arrive IPv4-mapped.
    for r in [&mut tcp, &mut udp] {
        let gateway = r.protocol_gateway.as_mut().unwrap();
        gateway.listen = SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, gateway.listen.port()));
    }
    let (tcp_port, udp_port) = (
        tcp.protocol_gateway.as_ref().unwrap().listen.port(),
        udp.protocol_gateway.as_ref().unwrap().listen.port(),
    );
    let (engine_tcp, mut inside) = engine_port().await;
    let engine_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let executable = fake_engine(
        temp.path(),
        &[(&tcp, engine_tcp), (&udp, engine_udp.local_addr().unwrap())],
    );
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine =
        Engine::with_tls_directory(db, Some(certs.root.clone())).with_protocol_engine(executable);
    engine.firewall().apply(Some(desired(
        "one",
        Some(inbound_set("server", Deny, Allow, &["127.0.0.1/32"])),
        vec![],
    )));
    let mut both = config(tcp.clone());
    both.rules.push(udp.clone());
    engine.apply(both).await.unwrap();
    let _allowed = connect_from("127.0.0.1", tcp_port).await.unwrap();
    assert!(taken(&mut inside).await.is_some(), "127.0.0.1 was refused");
    let allowed = probe_socket("127.0.0.1").await;
    allowed
        .send_to(b"allowed", loopback("127.0.0.1".parse().unwrap(), udp_port))
        .await
        .unwrap();
    let mut buffer = [0; 64];
    let (n, _) = timeout(Duration::from_secs(1), engine_udp.recv_from(&mut buffer))
        .await
        .expect("127.0.0.1 was refused")
        .unwrap();
    assert_eq!(&buffer[..n], b"allowed");
    for refused in ["127.0.0.2", "::1"] {
        refused_from(refused, tcp_port).await;
        assert!(
            taken(&mut inside).await.is_none(),
            "{refused} was passed on"
        );
        probe_socket(refused)
            .await
            .send_to(b"refused", loopback(refused.parse().unwrap(), udp_port))
            .await
            .unwrap();
    }
    assert!(
        timeout(
            Duration::from_millis(500),
            engine_udp.recv_from(&mut buffer)
        )
        .await
        .is_err(),
        "a refused datagram was passed on"
    );
    // Recorded under the address the client has, never IPv4-mapped.
    let detail = "server inbound rule set: default action denies (server)";
    let records = blocks(&engine);
    for refused in ["127.0.0.2", "::1"] {
        for (rule, protocol) in [("tcp-gw", "gateway"), ("udp-gw", "gateway")] {
            assert!(
                records.iter().any(|b| b.rule_id == rule
                    && b.protocol == protocol
                    && b.source.to_string() == refused
                    && b.detail == detail),
                "{rule} {refused}: {records:?}"
            );
        }
    }
    assert!(
        records
            .iter()
            .all(|b| !b.source.to_string().starts_with("::ffff:")),
        "{records:?}"
    );
    // Datagrams sent together, as QUIC stacks send them (one send the kernel
    // splits, UDP GSO), arrive one by one either way.
    let gateway_address = loopback("127.0.0.1".parse().unwrap(), udp_port);
    let mut buffer = vec![0; 2048];
    let sizes = [1200, 1200, 1200, 1200, 100];
    send_joined(&allowed, &datagrams(&sizes), gateway_address);
    let mut inside = None;
    for (i, size) in sizes.into_iter().enumerate() {
        let (n, from) = timeout(Duration::from_secs(1), engine_udp.recv_from(&mut buffer))
            .await
            .expect("not passed on")
            .unwrap();
        assert_eq!(buffer[..n], vec![i as u8; size], "datagram {i}");
        inside = Some(from);
    }
    let sizes = [1000, 1000, 1000, 10];
    send_joined(&engine_udp, &datagrams(&sizes), inside.unwrap());
    for (i, size) in sizes.into_iter().enumerate() {
        let (n, from) = timeout(Duration::from_secs(1), allowed.recv_from(&mut buffer))
            .await
            .expect("not passed back")
            .unwrap();
        assert_eq!(buffer[..n], vec![i as u8; size], "datagram {i}");
        assert_eq!(from, gateway_address);
    }
    // A refused client's sent together are refused together, each recorded.
    let refused = |engine: &Engine| -> u64 {
        blocks(engine)
            .iter()
            .filter(|b| b.rule_id == "udp-gw" && b.source.to_string() == "127.0.0.2")
            .map(|b| b.count)
            .sum()
    };
    let before = refused(&engine);
    let sizes = [1200, 1200, 1200, 1200, 100];
    send_joined(
        &probe_socket("127.0.0.2").await,
        &datagrams(&sizes),
        gateway_address,
    );
    assert!(
        timeout(
            Duration::from_millis(500),
            engine_udp.recv_from(&mut buffer)
        )
        .await
        .is_err(),
        "refused datagrams were passed on"
    );
    assert_eq!(refused(&engine) - before, sizes.len() as u64);
    engine.shutdown().await.unwrap();
}
/// Datagrams of `sizes`, back to back, the `i`th all `i`.
#[cfg(target_os = "linux")]
fn datagrams(sizes: &[usize]) -> Vec<u8> {
    let mut data = vec![];
    for (i, &size) in sizes.iter().enumerate() {
        data.resize(data.len() + size, i as u8);
    }
    data
}
/// Sends `data` to `to` in one send that the kernel splits into datagrams of
/// its first datagram's size.
#[cfg(target_os = "linux")]
fn send_joined(socket: &impl std::os::fd::AsRawFd, data: &[u8], to: SocketAddr) {
    use nix::sys::socket::{ControlMessage, MsgFlags, SockaddrStorage, sendmsg};
    let segment = data.iter().take_while(|&&b| b == data[0]).count() as u16;
    let sent = sendmsg(
        socket.as_raw_fd(),
        &[std::io::IoSlice::new(data)],
        &[ControlMessage::UdpGsoSegments(&segment)],
        MsgFlags::empty(),
        Some(&SockaddrStorage::from(to)),
    )
    .unwrap();
    assert_eq!(sent, data.len());
}

/// In a process of its own: it closes listeners and binds their ports
/// again, which a process another test starts could hold for that while
/// (see [`an_engine_whose_ports_cannot_be_read_keeps_the_gateway_closed`]).
#[cfg(target_os = "linux")]
#[test]
fn gateways_move_between_ipv4_and_every_address_and_hand_their_ports_to_rules() {
    in_own_process(
        "gateways_move_between_ipv4_and_every_address_and_hand_their_ports_to_rules_worker",
    );
}
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run by gateways_move_between_ipv4_and_every_address_and_hand_their_ports_to_rules in a process of its own"]
async fn gateways_move_between_ipv4_and_every_address_and_hand_their_ports_to_rules_worker() {
    if !is_worker(
        "gateways_move_between_ipv4_and_every_address_and_hand_their_ports_to_rules_worker",
    ) {
        return;
    }
    let certs = tls::Certificates::new();
    let temp = tempfile::tempdir().unwrap();
    let mut tcp = gateway(vless());
    tcp.id = "tcp-gw".into();
    let mut udp = gateway(WireProtocol::Hysteria2 {
        password: "test-udp-password-1234".into(),
        obfs: None,
        masquerade: None,
    });
    udp.id = "udp-gw".into();
    let (tcp_port, udp_port) = (
        tcp.protocol_gateway.as_ref().unwrap().listen.port(),
        udp.protocol_gateway.as_ref().unwrap().listen.port(),
    );
    let (engine_tcp, mut inside) = engine_port().await;
    let engine_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let executable = fake_engine(
        temp.path(),
        &[(&tcp, engine_tcp), (&udp, engine_udp.local_addr().unwrap())],
    );
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine =
        Engine::with_tls_directory(db, Some(certs.root.clone())).with_protocol_engine(executable);
    let at = |ip: std::net::IpAddr, revision: u64| {
        let (mut tcp, mut udp) = (tcp.clone(), udp.clone());
        tcp.protocol_gateway.as_mut().unwrap().listen = SocketAddr::new(ip, tcp_port);
        udp.protocol_gateway.as_mut().unwrap().listen = SocketAddr::new(ip, udp_port);
        let mut cfg = config(tcp);
        cfg.rules.push(udp);
        cfg.revision = revision;
        cfg
    };
    /// A UDP client at `source` with an association the engine answered,
    /// which holds the listener it came through.
    async fn associated(engine: &UdpSocket, source: &str, port: u16) -> UdpSocket {
        let client = probe_socket(source).await;
        client
            .send_to(b"hello", loopback(source.parse().unwrap(), port))
            .await
            .unwrap();
        let mut buffer = [0; 64];
        let (_, inside) = timeout(Duration::from_secs(1), engine.recv_from(&mut buffer))
            .await
            .expect("not passed on")
            .unwrap();
        engine.send_to(b"answer", inside).await.unwrap();
        timeout(Duration::from_secs(1), client.recv(&mut buffer))
            .await
            .expect("not answered")
            .unwrap();
        client
    }
    /// Many associations the engine has not answered yet, each of which
    /// holds the listener: a listener that moves reopens its port only once
    /// every one of them has ended.
    async fn crowd(engine: &UdpSocket, port: u16) -> Vec<UdpSocket> {
        let mut clients = vec![];
        let mut buffer = [0; 64];
        for host in 1..=8 {
            let source = format!("127.0.3.{host}");
            for _ in 0..48 {
                let client = probe_socket(&source).await;
                client
                    .send_to(b"crowd", loopback(source.parse().unwrap(), port))
                    .await
                    .unwrap();
                timeout(Duration::from_secs(1), engine.recv_from(&mut buffer))
                    .await
                    .expect("not passed on")
                    .unwrap();
                clients.push(client);
            }
        }
        clients
    }
    raise_descriptor_limit(8192);
    let v4: std::net::IpAddr = std::net::Ipv4Addr::UNSPECIFIED.into();
    let v6: std::net::IpAddr = std::net::Ipv6Addr::UNSPECIFIED.into();
    engine.apply(at(v4, 1)).await.unwrap();
    let _held = connect_from("127.0.0.1", tcp_port).await.unwrap();
    assert!(taken(&mut inside).await.is_some());
    let _association = associated(&engine_udp, "127.0.0.1", udp_port).await;
    // Two datagrams at once on a new association both reach the engine, as
    // a large ClientHello in two does.
    let pair = probe_socket("127.0.0.3").await;
    for data in [&b"one"[..], b"two"] {
        pair.send_to(data, loopback(pair.local_addr().unwrap().ip(), udp_port))
            .await
            .unwrap();
    }
    for expected in [&b"one"[..], b"two"] {
        let mut buffer = [0; 64];
        let (n, _) = timeout(Duration::from_secs(1), engine_udp.recv_from(&mut buffer))
            .await
            .expect("a datagram of a new association was dropped")
            .unwrap();
        assert_eq!(&buffer[..n], expected);
    }
    let _crowd = crowd(&engine_udp, udp_port).await;
    // To [::], which also takes IPv4, while connections and associations
    // are open, and back.
    engine.apply(at(v6, 2)).await.unwrap();
    for source in ["127.0.0.1", "::1"] {
        let _client = connect_from(source, tcp_port).await.unwrap();
        assert!(taken(&mut inside).await.is_some(), "{source}");
    }
    let _association = associated(&engine_udp, "::1", udp_port).await;
    let _crowd = crowd(&engine_udp, udp_port).await;
    engine.apply(at(v4, 3)).await.unwrap();
    let _association = associated(&engine_udp, "127.0.0.1", udp_port).await;
    let _crowd = crowd(&engine_udp, udp_port).await;
    engine.apply(at(v6, 4)).await.unwrap();
    let _association = associated(&engine_udp, "127.0.0.1", udp_port).await;
    let _crowd = crowd(&engine_udp, udp_port).await;
    // The gateways go and forwarding rules take their ports on IPv4 alone,
    // in one change.
    let (target, _, echo) = counting_echo().await;
    let udp_echo = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let udp_target = udp_echo.local_addr().unwrap();
    let udp_task = tokio::spawn(async move {
        let mut data = [0; 2048];
        while let Ok((n, peer)) = udp_echo.recv_from(&mut data).await {
            let _ = udp_echo.send_to(&data[..n], peer).await;
        }
    });
    let mut native_tcp = rule(target, Protocol::Tcp);
    native_tcp.id = "native-tcp".into();
    native_tcp.listen = SocketAddr::new(v4, tcp_port);
    let mut native_udp = rule(udp_target, Protocol::Udp);
    native_udp.id = "native-udp".into();
    native_udp.listen = SocketAddr::new(v4, udp_port);
    let mut cfg = config(native_tcp);
    cfg.rules.push(native_udp);
    cfg.revision = 5;
    engine.apply(cfg).await.unwrap();
    let mut client = TcpStream::connect(("127.0.0.1", tcp_port)).await.unwrap();
    echo_once(&mut client, b"forwarded").await.unwrap();
    let client = probe_socket("127.0.0.1").await;
    client
        .send_to(b"forwarded", ("127.0.0.1", udp_port))
        .await
        .unwrap();
    let mut buffer = [0; 64];
    let n = timeout(Duration::from_secs(2), client.recv(&mut buffer))
        .await
        .expect("no UDP echo")
        .unwrap();
    assert_eq!(&buffer[..n], b"forwarded");
    engine.shutdown().await.unwrap();
    echo.abort();
    udp_task.abort();
}

/// A gateway moving from `0.0.0.0` to `[::]` on its port closes its IPv4
/// listeners first; when the engine then fails to start, or the new
/// configuration cannot be saved, they open again and the revision stays.
/// In a process of its own: it closes listeners and binds their ports
/// again, which a process another test starts could hold for that while
/// (see [`an_engine_whose_ports_cannot_be_read_keeps_the_gateway_closed`]).
#[cfg(target_os = "linux")]
#[test]
fn a_gateway_that_fails_to_move_to_every_address_is_back_on_ipv4() {
    in_own_process("a_gateway_that_fails_to_move_to_every_address_is_back_on_ipv4_worker");
}
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run by a_gateway_that_fails_to_move_to_every_address_is_back_on_ipv4 in a process of its own"]
async fn a_gateway_that_fails_to_move_to_every_address_is_back_on_ipv4_worker() {
    if !is_worker("a_gateway_that_fails_to_move_to_every_address_is_back_on_ipv4_worker") {
        return;
    }
    let certs = tls::Certificates::new();
    let temp = tempfile::tempdir().unwrap();
    let mut tcp = gateway(vless());
    tcp.id = "tcp-gw".into();
    let mut udp = gateway(WireProtocol::Hysteria2 {
        password: "test-udp-password-1234".into(),
        obfs: None,
        masquerade: None,
    });
    udp.id = "udp-gw".into();
    let (tcp_port, udp_port) = (
        tcp.protocol_gateway.as_ref().unwrap().listen.port(),
        udp.protocol_gateway.as_ref().unwrap().listen.port(),
    );
    let (engine_tcp, mut inside) = engine_port().await;
    let engine_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let executable = fake_engine(
        temp.path(),
        &[(&tcp, engine_tcp), (&udp, engine_udp.local_addr().unwrap())],
    );
    let database = temp.path().join("agent.db");
    let engine = std::sync::Arc::new(
        Engine::with_tls_directory(Store::open(&database).unwrap(), Some(certs.root.clone()))
            .with_protocol_engine(executable),
    );
    let at = |ip: std::net::IpAddr, revision: u64| {
        let (mut tcp, mut udp) = (tcp.clone(), udp.clone());
        tcp.protocol_gateway.as_mut().unwrap().listen = SocketAddr::new(ip, tcp_port);
        udp.protocol_gateway.as_mut().unwrap().listen = SocketAddr::new(ip, udp_port);
        let mut cfg = config(tcp);
        cfg.rules.push(udp);
        cfg.revision = revision;
        cfg
    };
    let v4: std::net::IpAddr = std::net::Ipv4Addr::UNSPECIFIED.into();
    let v6: std::net::IpAddr = std::net::Ipv6Addr::UNSPECIFIED.into();
    engine.apply(at(v4, 1)).await.unwrap();
    let process = || engine.stats().protocol_gateway.unwrap().process_id;
    // Both public listeners pass IPv4 clients to the engine.
    async fn both_pass(
        inside: &mut tokio::sync::mpsc::UnboundedReceiver<TcpStream>,
        engine_udp: &UdpSocket,
        ports: (u16, u16),
        case: &str,
    ) {
        let _client = connect_from("127.0.0.1", ports.0)
            .await
            .unwrap_or_else(|error| panic!("{case}: TCP: {error}"));
        assert!(taken(inside).await.is_some(), "{case}: TCP");
        let client = probe_socket("127.0.0.1").await;
        client
            .send_to(case.as_bytes(), ("127.0.0.1", ports.1))
            .await
            .unwrap();
        let mut buffer = [0; 64];
        let (n, _) = timeout(Duration::from_secs(1), engine_udp.recv_from(&mut buffer))
            .await
            .unwrap_or_else(|_| panic!("{case}: UDP"))
            .unwrap();
        assert_eq!(&buffer[..n], case.as_bytes());
    }
    both_pass(&mut inside, &engine_udp, (tcp_port, udp_port), "before").await;
    // The engine does not start for the new configuration.
    let before = process();
    std::fs::write(temp.path().join("broken"), "").unwrap();
    let error = engine.apply(at(v6, 2)).await.unwrap_err();
    assert!(error.to_string().contains("ready"), "{error:#}");
    assert_eq!(engine.revision().await, 1);
    assert_ne!(process(), before, "failed before the engine restarted");
    both_pass(
        &mut inside,
        &engine_udp,
        (tcp_port, udp_port),
        "engine failed",
    )
    .await;
    // The new configuration cannot be saved: once its engine is starting,
    // another connection holds the database's write lock past the store's
    // busy timeout.
    let before = process();
    std::fs::write(temp.path().join("slow"), "").unwrap();
    let moving = tokio::spawn({
        let (engine, cfg) = (engine.clone(), at(v6, 2));
        async move { engine.apply(cfg).await }
    });
    while !temp.path().join("slowed").exists() {
        if moving.is_finished() {
            panic!(
                "the move ended before its engine started: {:?}",
                moving.await.unwrap().map(|_| ())
            );
        }
        sleep(Duration::from_millis(20)).await;
    }
    let lock = rusqlite::Connection::open(&database).unwrap();
    lock.execute_batch("BEGIN IMMEDIATE").unwrap();
    let error = moving.await.unwrap().unwrap_err();
    lock.execute_batch("ROLLBACK").unwrap();
    assert!(format!("{error:#}").contains("locked"), "{error:#}");
    assert_eq!(engine.revision().await, 1);
    assert_ne!(process(), before, "failed before the engine restarted");
    both_pass(
        &mut inside,
        &engine_udp,
        (tcp_port, udp_port),
        "save failed",
    )
    .await;
    // And the move itself still works.
    engine.apply(at(v6, 2)).await.unwrap();
    both_pass(&mut inside, &engine_udp, (tcp_port, udp_port), "moved").await;
    engine.shutdown().await.unwrap();
}

/// A forwarding rule's own `[::]` is IPv6 only: moving it there from
/// `0.0.0.0` while something else holds `[::]` on that port fails at once
/// and leaves its IPv4 listener and its UDP sessions as they were.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_rule_whose_move_to_ipv6_cannot_bind_keeps_its_ipv4_listener() {
    let temp = tempfile::tempdir().unwrap();
    let target = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let mut native = rule(target.local_addr().unwrap(), Protocol::Udp);
    let port = native.listen.port();
    native.listen = SocketAddr::from(([0, 0, 0, 0], port));
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    engine.apply(config(native.clone())).await.unwrap();
    let client = probe_socket("127.0.0.1").await;
    // Where the target sees the client's session from.
    let session = || async {
        client
            .send_to(b"session", ("127.0.0.1", port))
            .await
            .unwrap();
        let mut buffer = [0; 64];
        timeout(Duration::from_secs(2), target.recv_from(&mut buffer))
            .await
            .expect("not forwarded")
            .unwrap()
            .1
    };
    let from = session().await;
    // Another socket holds [::] on the port, IPv6 only.
    let holder = socket2::Socket::new(socket2::Domain::IPV6, socket2::Type::DGRAM, None).unwrap();
    holder.set_only_v6(true).unwrap();
    holder
        .bind(&SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port)).into())
        .unwrap();
    let mut moved = native.clone();
    moved.listen = SocketAddr::from((std::net::Ipv6Addr::UNSPECIFIED, port));
    let mut cfg = config(moved);
    cfg.revision = 2;
    engine.apply(cfg).await.unwrap_err();
    assert_eq!(engine.revision().await, 1);
    assert_eq!(session().await, from, "the session was dropped");
    engine.shutdown().await.unwrap();
}

/// In a process of its own: it closes listeners and binds their ports
/// again, which a process another test starts could hold for that while
/// (see [`an_engine_whose_ports_cannot_be_read_keeps_the_gateway_closed`]).
#[cfg(target_os = "linux")]
#[test]
fn a_rule_becomes_a_gateway_on_its_port_only_after_it_is_disabled() {
    in_own_process("a_rule_becomes_a_gateway_on_its_port_only_after_it_is_disabled_worker");
}
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run by a_rule_becomes_a_gateway_on_its_port_only_after_it_is_disabled in a process of its own"]
async fn a_rule_becomes_a_gateway_on_its_port_only_after_it_is_disabled_worker() {
    if !is_worker("a_rule_becomes_a_gateway_on_its_port_only_after_it_is_disabled_worker") {
        return;
    }
    let certs = tls::Certificates::new();
    let temp = tempfile::tempdir().unwrap();
    let (target, _, echo) = counting_echo().await;
    let mut native = rule(target, Protocol::Tcp);
    native.id = "same".into();
    let mut gateway = gateway(vless());
    gateway.id = "same".into();
    gateway.protocol_gateway.as_mut().unwrap().listen = native.listen;
    let (engine_tcp, mut inside) = engine_port().await;
    let executable = fake_engine(temp.path(), &[(&gateway, engine_tcp)]);
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine =
        Engine::with_tls_directory(db, Some(certs.root.clone())).with_protocol_engine(executable);
    let with = |rule: &Rule, enabled: bool, revision: u64| {
        let mut rule = rule.clone();
        rule.enabled = enabled;
        let mut cfg = config(rule);
        cfg.revision = revision;
        cfg
    };
    engine.apply(config(native.clone())).await.unwrap();
    let error = engine.apply(with(&gateway, true, 2)).await.unwrap_err();
    assert!(error.to_string().contains("protocol gateway"), "{error:#}");
    assert_eq!(engine.revision().await, 1);
    let mut client = TcpStream::connect(native.listen).await.unwrap();
    echo_once(&mut client, b"still forwarding").await.unwrap();
    // Disabled and applied first, it becomes one.
    engine.apply(with(&native, false, 2)).await.unwrap();
    engine.apply(with(&gateway, true, 3)).await.unwrap();
    let _client = TcpStream::connect(native.listen).await.unwrap();
    assert!(taken(&mut inside).await.is_some(), "not a gateway");
    // And back the same way only.
    let error = engine.apply(with(&native, true, 4)).await.unwrap_err();
    assert!(error.to_string().contains("protocol gateway"), "{error:#}");
    assert_eq!(engine.revision().await, 3);
    let _client = TcpStream::connect(native.listen).await.unwrap();
    assert!(taken(&mut inside).await.is_some(), "the gateway closed");
    engine.apply(with(&gateway, false, 4)).await.unwrap();
    engine.apply(with(&native, true, 5)).await.unwrap();
    let mut client = TcpStream::connect(native.listen).await.unwrap();
    echo_once(&mut client, b"forwarding again").await.unwrap();
    engine.shutdown().await.unwrap();
    echo.abort();
}

/// Sets this process's soft descriptor limit to `descriptors`.
#[cfg(target_os = "linux")]
fn set_descriptor_limit(descriptors: u64) {
    use nix::libc;
    let mut limit = libc::rlimit {
        rlim_cur: 0,
        rlim_max: 0,
    };
    // SAFETY: `limit` is a valid rlimit that both calls only read or fill
    // for their duration.
    unsafe {
        assert_eq!(libc::getrlimit(libc::RLIMIT_NOFILE, &mut limit), 0);
        limit.rlim_cur = descriptors.min(limit.rlim_max);
        assert_eq!(libc::setrlimit(libc::RLIMIT_NOFILE, &limit), 0);
    }
}

/// The public listeners of every gateway keep within half of the process's
/// descriptor limit however many clients come, so the rest of the Agent
/// still opens what it needs. In a process of its own, since it lowers the
/// limit.
#[cfg(target_os = "linux")]
#[test]
fn gateway_clients_leave_the_agent_its_descriptors() {
    in_own_process("gateway_descriptor_worker");
}

#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "run by gateway_clients_leave_the_agent_its_descriptors in a process of its own"]
async fn gateway_descriptor_worker() {
    if !is_worker("gateway_descriptor_worker") {
        return;
    }
    const LIMIT: u64 = 1024;
    let budget = LIMIT as usize / 2;
    let detail = format!("the Agent's {budget} descriptors for gateway clients are in use");
    set_descriptor_limit(LIMIT);
    let certs = tls::Certificates::new();
    let temp = tempfile::tempdir().unwrap();
    let mut tcp = gateway(vless());
    tcp.id = "tcp-gw".into();
    tcp.idle_timeout_secs = 1;
    let mut udp = gateway(WireProtocol::Hysteria2 {
        password: "test-udp-password-1234".into(),
        obfs: None,
        masquerade: None,
    });
    udp.id = "udp-gw".into();
    let (tcp_port, udp_port) = (
        tcp.protocol_gateway.as_ref().unwrap().listen.port(),
        udp.protocol_gateway.as_ref().unwrap().listen.port(),
    );
    // An engine port that never accepts: the kernel completes connections
    // to it without a descriptor in this process.
    let socket = tokio::net::TcpSocket::new_v4().unwrap();
    socket.bind("127.0.0.1:0".parse().unwrap()).unwrap();
    let engine_tcp = socket.listen(1024).unwrap();
    let engine_udp = UdpSocket::bind("127.0.0.1:0").await.unwrap();
    let executable = fake_engine(
        temp.path(),
        &[
            (&tcp, engine_tcp.local_addr().unwrap()),
            (&udp, engine_udp.local_addr().unwrap()),
        ],
    );
    let (target, _, echo) = counting_echo().await;
    let mut native = rule(target, Protocol::Tcp);
    native.id = "native".into();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine =
        Engine::with_tls_directory(db, Some(certs.root.clone())).with_protocol_engine(executable);
    let mut cfg = config(tcp.clone());
    cfg.rules.push(udp.clone());
    cfg.rules.push(native.clone());
    engine.apply(cfg).await.unwrap();
    let source = |n: usize, net: u8| format!("127.{net}.{}.{}", n >> 8, n & 0xff);
    let budget_refusals = |rule: &str| {
        blocks(&engine)
            .iter()
            .filter(|b| b.rule_id == rule && b.detail == detail)
            .count()
    };
    // The rest of the Agent works: a forwarding rule carries a connection.
    let still_works = || async {
        std::fs::File::open("/dev/null").expect("the process is out of descriptors");
        let mut client = TcpStream::connect(native.listen).await.unwrap();
        echo_once(&mut client, b"forwarded").await.unwrap();
    };
    // TCP clients, two descriptors each, from addresses of their own.
    let extra = 40;
    let mut held = vec![];
    for n in 0..budget / 2 + extra {
        let client = connect_from(&source(n, 4), tcp_port).await;
        // A refused one may be reset before its connect returns.
        if n < budget / 2 {
            held.push(client.unwrap_or_else(|error| panic!("client {n}: {error}")));
        }
    }
    sleep(Duration::from_millis(500)).await;
    assert_eq!(budget_refusals("tcp-gw"), extra, "{:?}", blocks(&engine));
    still_works().await;
    // Clients that end free their places once the engine side is quiet
    // past the idle timeout.
    drop(held);
    sleep(Duration::from_secs(3)).await;
    let mut back = connect_from(&source(0, 5), tcp_port).await.unwrap();
    assert!(
        timeout(Duration::from_millis(500), back.read(&mut [0; 16]))
            .await
            .is_err(),
        "refused after the others ended"
    );
    drop(back);
    sleep(Duration::from_secs(2)).await;
    // UDP associations, one descriptor each, the engine never answers.
    let mut buffer = [0; 64];
    for n in 0..budget {
        probe_socket(&source(n, 6))
            .await
            .send_to(b"flood", ("127.0.0.1", udp_port))
            .await
            .unwrap();
        timeout(Duration::from_secs(2), engine_udp.recv_from(&mut buffer))
            .await
            .unwrap_or_else(|_| panic!("association {n} was refused"))
            .unwrap();
    }
    for n in budget..budget + extra {
        probe_socket(&source(n, 6))
            .await
            .send_to(b"flood", ("127.0.0.1", udp_port))
            .await
            .unwrap();
    }
    sleep(Duration::from_millis(500)).await;
    assert!(
        timeout(
            Duration::from_millis(200),
            engine_udp.recv_from(&mut buffer)
        )
        .await
        .is_err(),
        "passed on over the budget"
    );
    assert_eq!(budget_refusals("udp-gw"), extra, "{:?}", blocks(&engine));
    still_works().await;
    // Unanswered, they end soon and the places come back.
    sleep(Duration::from_secs(6)).await;
    probe_socket("127.0.0.1")
        .await
        .send_to(b"after", ("127.0.0.1", udp_port))
        .await
        .unwrap();
    let (n, _) = timeout(Duration::from_secs(2), engine_udp.recv_from(&mut buffer))
        .await
        .expect("the unanswered associations kept their places")
        .unwrap();
    assert_eq!(&buffer[..n], b"after");
    // The budget follows the limit as it is when a client comes: lowered,
    // fewer associations pass, the one above holding its descriptor.
    set_descriptor_limit(LIMIT / 2);
    let lower = format!(
        "the Agent's {} descriptors for gateway clients are in use",
        LIMIT / 4
    );
    for n in 0..LIMIT as usize / 4 - 1 {
        probe_socket(&source(n, 7))
            .await
            .send_to(b"lowered", ("127.0.0.1", udp_port))
            .await
            .unwrap();
        timeout(Duration::from_secs(2), engine_udp.recv_from(&mut buffer))
            .await
            .unwrap_or_else(|_| panic!("association {n} under the lowered limit was refused"))
            .unwrap();
    }
    probe_socket(&source(LIMIT as usize / 4, 7))
        .await
        .send_to(b"lowered", ("127.0.0.1", udp_port))
        .await
        .unwrap();
    sleep(Duration::from_millis(500)).await;
    assert_eq!(
        blocks(&engine)
            .iter()
            .filter(|b| b.rule_id == "udp-gw" && b.detail == lower)
            .count(),
        1,
        "{:?}",
        blocks(&engine)
    );
    engine.shutdown().await.unwrap();
    echo.abort();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the pinned engine; set RELAY_TEST_PROTOCOL_ENGINE and run explicitly"]
async fn max_connections_counts_each_client_connection_once() {
    let executable = PathBuf::from(std::env::var_os("RELAY_TEST_PROTOCOL_ENGINE").unwrap());
    let certs = tls::Certificates::new();
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::with_tls_directory(db, Some(certs.root.clone()))
        .with_protocol_engine(executable.clone());
    let mut r = gateway(vless());
    r.max_connections = 2;
    engine.apply(config(r.clone())).await.unwrap();
    let (target, _, echo) = counting_echo().await;
    let (mut process, local) = client(&executable, &certs.root, &r, false).await;
    // Each held connection passes the public listener and the bridge; only
    // the bridge counts it.
    let first = hold(local, target).await.unwrap();
    let second = hold(local, target).await.unwrap();
    assert!(hold(local, target).await.is_err(), "a third connection");
    assert!(
        blocks(&engine)
            .iter()
            .any(|b| b.reason == "connection_limit" && b.detail == "limit 2 connections"),
        "{:?}",
        blocks(&engine)
    );
    drop(first);
    let until = std::time::Instant::now() + Duration::from_secs(5);
    while hold(local, target).await.is_err() {
        assert!(
            std::time::Instant::now() < until,
            "the freed place stayed taken"
        );
    }
    drop(second);
    process.kill().await.unwrap();
    engine.shutdown().await.unwrap();
    echo.abort();
}

/// The real engine answers a QUIC Initial anyone can make, before any
/// authentication. Sent from addresses that do not hear the answer (here,
/// sockets that never use it), Initials hold their places for a few
/// seconds only, however often they are sent again; a sender that
/// addresses the connection the engine chose keeps its place.
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the pinned engine; set RELAY_TEST_PROTOCOL_ENGINE and run explicitly"]
async fn quic_initials_hold_a_place_only_once_their_sender_shows_it_hears_the_engine() {
    const PER_SOURCE: usize = 64;
    let executable = PathBuf::from(std::env::var_os("RELAY_TEST_PROTOCOL_ENGINE").unwrap());
    let certs = tls::Certificates::new();
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine =
        Engine::with_tls_directory(db, Some(certs.root.clone())).with_protocol_engine(executable);
    let r = gateway(WireProtocol::Hysteria2 {
        password: "test-udp-password-1234".into(),
        obfs: None,
        masquerade: None,
    });
    engine.apply(config(r.clone())).await.unwrap();
    let gateway = SocketAddr::from((
        [127, 0, 0, 1],
        r.protocol_gateway.as_ref().unwrap().listen.port(),
    ));
    let source = "127.0.0.9";
    /// A socket at `source` that sent Initial number `n`, the Initial and
    /// the engine's answer, if one came within a second.
    async fn initial(
        source: &str,
        gateway: SocketAddr,
        n: u8,
    ) -> (UdpSocket, Vec<u8>, Option<Vec<u8>>) {
        let socket = probe_socket(source).await;
        let packet = quic_initial(&[n, 0x51, 2, 3, 4, 5, 6, 7], &[n, 0xc1, 9, 9]);
        socket.send_to(&packet, gateway).await.unwrap();
        let mut buffer = vec![0; 2048];
        let answer = timeout(Duration::from_secs(1), socket.recv(&mut buffer))
            .await
            .ok()
            .and_then(Result::ok)
            .map(|size| buffer[..size].to_vec());
        (socket, packet, answer)
    }
    let mut senders = vec![];
    let started = std::time::Instant::now();
    for n in 0..PER_SOURCE as u8 {
        let (socket, packet, answer) = initial(source, gateway, n).await;
        let answer = answer.unwrap_or_else(|| panic!("Initial {n} was not answered"));
        // A long-header packet that chose the server's connection ID.
        let id = quic_source_id(&answer).unwrap_or_else(|| {
            panic!(
                "answer {n} is not a QUIC long header: {:02x?}",
                &answer[..8]
            )
        });
        assert!(!id.is_empty());
        senders.push((socket, packet, id));
    }
    let opened = std::time::Instant::now();
    // The first shows it heard the answer; the others only send their
    // Initial again, as a sender that does not hear the answer does.
    senders[0]
        .0
        .send_to(&quic_to(&senders[0].2), gateway)
        .await
        .unwrap();
    let (_, _, answer) = initial(source, gateway, 200).await;
    assert_eq!(
        answer, None,
        "an Initial over the address's bound was answered"
    );
    assert!(
        blocks(&engine)
            .iter()
            .any(|b| b.source.to_string() == source
                && b.reason == "udp_session_limit"
                && b.detail == format!("limit {PER_SOURCE} client associations from one address")),
        "{:?}",
        blocks(&engine)
    );
    // Until just before the first of them has lived its few seconds.
    while started.elapsed() < Duration::from_secs(4) {
        for (socket, packet, _) in &senders[1..] {
            socket.send_to(packet, gateway).await.unwrap();
        }
        sleep(Duration::from_millis(500)).await;
    }
    sleep(Duration::from_millis(5500).saturating_sub(opened.elapsed())).await;
    // Their places came back; the one that showed itself keeps its own.
    for n in 0..PER_SOURCE as u8 - 1 {
        let (_, _, answer) = initial(source, gateway, 100 + n).await;
        assert!(
            answer.is_some(),
            "a place of the address did not come back ({n})"
        );
    }
    let (_, _, answer) = initial(source, gateway, 250).await;
    assert_eq!(answer, None, "the association that showed itself ended");
    engine.shutdown().await.unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "requires the pinned engine; set RELAY_TEST_PROTOCOL_ENGINE and run explicitly"]
async fn quic_clients_are_not_the_rules_udp_sessions() {
    let executable = PathBuf::from(std::env::var_os("RELAY_TEST_PROTOCOL_ENGINE").unwrap());
    let certs = tls::Certificates::new();
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::with_tls_directory(db, Some(certs.root.clone()))
        .with_protocol_engine(executable.clone());
    let mut r = gateway(WireProtocol::Hysteria2 {
        password: "test-udp-password-1234".into(),
        obfs: None,
        masquerade: None,
    });
    // As in 0.150.0, the limit counts the UDP sessions clients open through
    // the gateway, not their own QUIC connections.
    r.udp_max_sessions = 1;
    engine.apply(config(r.clone())).await.unwrap();
    let (target, _, echo) = counting_echo().await;
    let mut processes = vec![];
    let mut held = vec![];
    // Three clients, each with its own QUIC connection, all open at once.
    for n in 0..3 {
        let (process, local) = client(&executable, &certs.root, &r, false).await;
        processes.push(process);
        held.push(
            hold(local, target)
                .await
                .unwrap_or_else(|error| panic!("client {n}: {error:#}")),
        );
    }
    for (n, stream) in held.iter_mut().enumerate() {
        echo_once(stream, format!("client {n}").as_bytes())
            .await
            .unwrap();
    }
    assert!(
        !blocks(&engine)
            .iter()
            .any(|b| b.reason == "udp_session_limit"),
        "{:?}",
        blocks(&engine)
    );
    drop(held);
    for mut process in processes {
        process.kill().await.unwrap();
    }
    engine.shutdown().await.unwrap();
    echo.abort();
}

/// How fast bulk data crosses a Hysteria2 gateway each way, and the CPU the
/// Agent (this process) and the engine spent. Uses only helpers 0.150.0's
/// copy of this file has, so the same function compares both:
/// `RELAY_TEST_PROTOCOL_ENGINE=… RELAY_TEST_BULK_MIB=256 cargo test --release
/// --test managed_gateways hysteria2_bulk_transfer -- --ignored --nocapture`
#[cfg(target_os = "linux")]
#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
#[ignore = "measurement; requires the pinned engine, run explicitly with --nocapture"]
async fn hysteria2_bulk_transfer_rate_and_cpu() {
    fn cpu_seconds(pid: u32) -> f64 {
        let stat = std::fs::read_to_string(format!("/proc/{pid}/stat")).unwrap_or_default();
        let fields: Vec<&str> = stat
            .rsplit_once(')')
            .map(|(_, rest)| rest.split_whitespace().collect())
            .unwrap_or_default();
        let ticks = |i: usize| {
            fields
                .get(i)
                .and_then(|f| f.parse::<f64>().ok())
                .unwrap_or(0.0)
        };
        // utime and stime, fields 14 and 15, at 100 ticks per second.
        (ticks(11) + ticks(12)) / 100.0
    }
    let executable = PathBuf::from(std::env::var_os("RELAY_TEST_PROTOCOL_ENGINE").unwrap());
    let mib: usize = std::env::var("RELAY_TEST_BULK_MIB")
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(64);
    let certs = tls::Certificates::new();
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::with_tls_directory(db, Some(certs.root.clone()))
        .with_protocol_engine(executable.clone());
    let r = gateway(WireProtocol::Hysteria2 {
        password: "test-udp-password-1234".into(),
        obfs: None,
        masquerade: None,
    });
    engine.apply(config(r.clone())).await.unwrap();
    // A sink that reads everything and answers with as many bytes.
    let sink = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let target = sink.local_addr().unwrap();
    let total = mib * 1024 * 1024;
    tokio::spawn(async move {
        while let Ok((mut stream, _)) = sink.accept().await {
            tokio::spawn(async move {
                let mut buffer = vec![0; 256 * 1024];
                let mut read = 0;
                while read < total {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(n) => read += n,
                    }
                }
                let chunk = vec![0x5a; 256 * 1024];
                let mut written = 0;
                while written < total {
                    let n = chunk.len().min(total - written);
                    if stream.write_all(&chunk[..n]).await.is_err() {
                        return;
                    }
                    written += n;
                }
            });
        }
    });
    let (mut process, local) = client(&executable, &certs.root, &r, false).await;
    let server_pid = engine.stats().protocol_gateway.unwrap().process_id.unwrap();
    let client_pid = process.id().unwrap();
    let mut stream = TcpStream::connect(local).await.unwrap();
    stream.write_all(&[5, 1, 0]).await.unwrap();
    let mut selected = [0; 2];
    stream.read_exact(&mut selected).await.unwrap();
    let std::net::IpAddr::V4(ip) = target.ip() else {
        unreachable!()
    };
    let mut request = vec![5, 1, 0, 1];
    request.extend(ip.octets());
    request.extend(target.port().to_be_bytes());
    stream.write_all(&request).await.unwrap();
    let mut reply = [0; 10];
    stream.read_exact(&mut reply).await.unwrap();
    assert_eq!(reply[1], 0);
    let cpu = || {
        (
            cpu_seconds(std::process::id()),
            cpu_seconds(server_pid),
            cpu_seconds(client_pid),
        )
    };
    let chunk = vec![0xa5; 256 * 1024];
    let (before, started) = (cpu(), std::time::Instant::now());
    let mut sent = 0;
    while sent < total {
        let n = chunk.len().min(total - sent);
        stream.write_all(&chunk[..n]).await.unwrap();
        sent += n;
    }
    let mut buffer = vec![0; 256 * 1024];
    let mut first_byte = None;
    let mut received = 0;
    while received < total {
        let n = stream.read(&mut buffer).await.unwrap();
        assert!(n > 0, "the sink ended early");
        first_byte.get_or_insert_with(std::time::Instant::now);
        received += n;
    }
    let (after, ended) = (cpu(), std::time::Instant::now());
    let upload = first_byte.unwrap() - started;
    let download = ended - first_byte.unwrap();
    let rate = |d: Duration| mib as f64 / d.as_secs_f64();
    println!(
        "hysteria2 {mib} MiB: upload {:.1} MiB/s, download {:.1} MiB/s; CPU s: agent {:.2}, engine {:.2}, client {:.2}",
        rate(upload),
        rate(download),
        after.0 - before.0,
        after.1 - before.1,
        after.2 - before.2
    );
    process.kill().await.unwrap();
    engine.shutdown().await.unwrap();
}
