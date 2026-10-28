mod common;
use common::*;
use relay_platform::{
    engine::Engine,
    model::*,
    mptcp::{Config, Mode},
    store::Store,
};
use std::time::Duration;
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::TcpStream,
    time::timeout,
};

fn configured(revision: u64, rule: Rule) -> NodeConfig {
    let mut value = config(rule);
    value.revision = revision;
    value
}

async fn exchange(stream: &mut TcpStream) {
    stream.write_all(b"mptcp-integrated-meter").await.unwrap();
    let mut out = [0u8; 22];
    timeout(Duration::from_secs(3), stream.read_exact(&mut out))
        .await
        .unwrap()
        .unwrap();
    assert_eq!(&out, b"mptcp-integrated-meter");
}

#[test]
fn validates_policy_and_preserves_it_in_serialization() {
    let mut r = rule("127.0.0.1:9".parse().unwrap(), Protocol::Tcp);
    r.mptcp = Some(Config {
        inbound: Mode::Require,
        outbound: Mode::Prefer,
    });
    r.validate().unwrap();
    assert_eq!(
        serde_json::from_value::<Rule>(serde_json::to_value(&r).unwrap()).unwrap(),
        r
    );
    r.protocol = Protocol::Udp;
    assert!(r.validate().is_err());
    r.protocol = Protocol::Both;
    r.validate().unwrap();
    r.mptcp = Some(Config::default());
    assert!(r.validate().is_err());
}

#[tokio::test]
async fn preferred_mode_allows_plain_tcp_and_releases_observers_on_disable() {
    let echo = tcp_echo().await;
    let target = echo.address;
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("agent.db")).unwrap();
    let engine = Engine::new(store.clone());
    let mut r = rule(target, Protocol::Tcp);
    r.mptcp = Some(Config {
        inbound: Mode::Prefer,
        outbound: Mode::Prefer,
    });
    engine.apply(configured(1, r.clone())).await.unwrap();
    let mut client = TcpStream::connect(r.listen).await.unwrap();
    exchange(&mut client).await;
    let stats = engine.stats().mptcp.unwrap();
    assert_eq!(stats.active_sockets, 2);
    assert!(stats.fallback_total >= 1);
    assert_eq!(stats.connections.len(), 2);
    assert!(
        stats
            .connections
            .iter()
            .any(|c| c.direction == "inbound" && c.info.negotiated == Some(false))
    );
    r.enabled = false;
    engine.apply(configured(2, r)).await.unwrap();
    timeout(Duration::from_secs(3), async {
        while engine.stats().mptcp.as_ref().unwrap().active_sockets != 0 {
            tokio::time::sleep(Duration::from_millis(10)).await;
        }
    })
    .await
    .unwrap();
    assert!(engine.stats().mptcp.unwrap().connections.is_empty());
    engine.shutdown().await.unwrap();
    drop(echo);
}

#[tokio::test]
async fn changing_live_listener_transport_rejects_revision_and_keeps_old_forwarding() {
    let echo = tcp_echo().await;
    let target = echo.address;
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule(target, Protocol::Tcp);
    engine.apply(configured(1, r.clone())).await.unwrap();
    r.mptcp = Some(Config {
        inbound: Mode::Prefer,
        outbound: Mode::Off,
    });
    assert!(engine.apply(configured(2, r.clone())).await.is_err());
    assert_eq!(engine.revision().await, 1);
    exchange(&mut TcpStream::connect(r.listen).await.unwrap()).await;
    engine.shutdown().await.unwrap();
    drop(echo);
}

#[cfg(not(target_os = "linux"))]
#[tokio::test]
async fn strict_policy_fails_preflight_on_unsupported_platform() {
    let temp = tempfile::tempdir().unwrap();
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    let mut r = rule("127.0.0.1:9".parse().unwrap(), Protocol::Tcp);
    r.mptcp = Some(Config {
        inbound: Mode::Require,
        outbound: Mode::Off,
    });
    assert!(engine.apply(configured(1, r)).await.is_err());
    assert_eq!(engine.revision().await, 0);
    engine.shutdown().await.unwrap();
}

#[cfg(target_os = "linux")]
mod linux {
    use super::*;
    use socket2::{Domain, Protocol as SocketProtocol, Socket, Type};
    use tokio::net::{TcpListener, TcpSocket};

    fn raw() -> Socket {
        let socket = Socket::new(Domain::IPV4, Type::STREAM, Some(SocketProtocol::MPTCP)).unwrap();
        socket.set_nonblocking(true).unwrap();
        socket
    }
    async fn client(address: std::net::SocketAddr) -> TcpStream {
        TcpSocket::from_std_stream(raw().into())
            .connect(address)
            .await
            .unwrap()
    }
    #[tokio::test]
    #[ignore = "requires Linux with enabled MPTCP; run explicitly during Linux acceptance"]
    async fn required_mptcp_forwards_and_reports_live_negotiation() {
        let socket = raw();
        socket
            .bind(
                &"127.0.0.1:0"
                    .parse::<std::net::SocketAddr>()
                    .unwrap()
                    .into(),
            )
            .unwrap();
        socket.listen(8).unwrap();
        let listener = TcpListener::from_std(socket.into()).unwrap();
        let target = listener.local_addr().unwrap();
        let echo = tokio::spawn(async move {
            let (mut stream, _) = listener.accept().await.unwrap();
            assert_eq!(
                relay_platform::mptcp::inspect(&stream).negotiated,
                Some(true)
            );
            let (mut reader, mut writer) = stream.split();
            tokio::io::copy(&mut reader, &mut writer).await.unwrap();
        });
        let temp = tempfile::tempdir().unwrap();
        let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
        let mut r = rule(target, Protocol::Tcp);
        r.mptcp = Some(Config {
            inbound: Mode::Require,
            outbound: Mode::Require,
        });
        engine.apply(configured(1, r.clone())).await.unwrap();
        let mut stream = client(r.listen).await;
        exchange(&mut stream).await;
        let observed = engine.stats().mptcp.unwrap();
        assert_eq!(observed.negotiated_total, 2);
        assert_eq!(observed.fallback_total, 0);
        assert!(
            observed
                .connections
                .iter()
                .all(|c| c.info.negotiated == Some(true))
        );
        assert_eq!(engine.stats().forwarded_upload_bytes, 22);
        assert_eq!(engine.stats().forwarded_download_bytes, 22);
        drop(stream);
        engine.shutdown().await.unwrap();
        echo.await.unwrap();
    }
    #[tokio::test]
    #[ignore = "requires Linux with enabled MPTCP; run explicitly during Linux acceptance"]
    async fn required_modes_reject_plain_tcp_peers() {
        let echo = tcp_echo().await;
        let target = echo.address;
        for (incoming, outgoing) in [(Mode::Require, Mode::Off), (Mode::Off, Mode::Require)] {
            let temp = tempfile::tempdir().unwrap();
            let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
            let mut r = rule(target, Protocol::Tcp);
            r.mptcp = Some(Config {
                inbound: incoming,
                outbound: outgoing,
            });
            engine.apply(configured(1, r.clone())).await.unwrap();
            let mut stream = TcpStream::connect(r.listen).await.unwrap();
            let _ = stream.write_all(b"must-not-relay").await;
            let mut byte = [0];
            assert!(!matches!(
                timeout(Duration::from_secs(3), stream.read(&mut byte)).await,
                Ok(Ok(1))
            ));
            assert_eq!(engine.stats().mptcp.unwrap().required_rejections, 1);
            assert_eq!(engine.stats().forwarded_upload_bytes, 0);
            engine.shutdown().await.unwrap();
        }
        drop(echo);
    }
}
