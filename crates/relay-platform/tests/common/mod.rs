#![allow(dead_code)]
use relay_platform::model::*;
use std::{net::SocketAddr, time::Duration};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    task::JoinHandle,
};
use tokio_util::sync::CancellationToken;

pub const PASSWORD: &str = "test-password-only-29x!";
pub fn free_address() -> SocketAddr {
    use rand::Rng;
    loop {
        // Keep test listeners outside the usual ephemeral client-port range.
        // A concurrent outbound connect could otherwise claim a just-released port.
        let port = rand::thread_rng().gen_range(12_000..30_000);
        let Ok(listener) = std::net::TcpListener::bind((std::net::Ipv4Addr::LOCALHOST, port))
        else {
            continue;
        };
        let address = listener.local_addr().unwrap();
        if let Ok(_udp) = std::net::UdpSocket::bind(address) {
            return address;
        }
    }
}
pub fn rule(target: SocketAddr, protocol: Protocol) -> Rule {
    Rule {
        inbound_multipath: None,
        outbound_multipath: None,
        health_check: None,
        budget_ids: vec![],
        id: "rule-one".into(),
        tenant_id: "default".into(),
        owner_id: "admin".into(),
        name: "Test rule".into(),
        listen: free_address(),
        listen_end_port: None,
        port_mapping: PortMapping::Fixed,
        outbound_bind: None,
        dns_cache: None,
        protocol,
        inbound_tls: None,
        inbound_proxy: None,
        inbound_websocket: None,
        advertise: None,
        targets: vec![Target {
            priority: 0,
            max_sessions: None,
            address: target.to_string(),
            weight: 1,
            tls: None,
            proxy_protocol: None,
            websocket: None,
            via: None,
        }],
        balance: Balance::WeightedRoundRobin,
        enabled: true,
        connect_timeout_ms: 1000,
        idle_timeout_secs: 10,
        max_connections: 128,
        udp_max_sessions: 64,
        quota_bytes: None,
        expires_at_ms: None,
        rate_bytes_per_sec: None,
        meter_epoch: "epoch-one".into(),
        allow_sources: vec![],
        deny_sources: vec![],
    }
}
pub fn config(rule: Rule) -> NodeConfig {
    NodeConfig {
        api_version: API_VERSION,
        node_id: "node-one".into(),
        revision: 1,
        rules: vec![rule],
    }
}
pub struct Echo {
    pub address: SocketAddr,
    stop: CancellationToken,
    task: JoinHandle<()>,
}
impl Drop for Echo {
    fn drop(&mut self) {
        self.stop.cancel();
        self.task.abort();
    }
}
pub async fn tcp_echo() -> Echo {
    tcp_echo_at("127.0.0.1:0", None).await
}
pub async fn tcp_echo_at(bind: &str, marker: Option<u8>) -> Echo {
    let listener = TcpListener::bind(bind).await.unwrap();
    tcp_echo_from(listener, marker)
}
pub async fn tcp_udp_echo() -> (Echo, Echo) {
    tcp_udp_echo_at("127.0.0.1:0").await
}
pub async fn tcp_udp_echo_at(bind: &str) -> (Echo, Echo) {
    // Keep both reservations alive before starting either task. A TCP ephemeral
    // port can already be occupied by an unrelated UDP client in a parallel test.
    for _ in 0..100 {
        let listener = TcpListener::bind(bind).await.unwrap();
        match UdpSocket::bind(listener.local_addr().unwrap()).await {
            Ok(socket) => return (tcp_echo_from(listener, None), udp_echo_from(socket)),
            Err(error) if error.kind() == std::io::ErrorKind::AddrInUse => continue,
            Err(error) => panic!("cannot reserve UDP echo socket: {error}"),
        }
    }
    panic!("cannot reserve a shared TCP/UDP echo port after 100 attempts")
}
fn tcp_echo_from(listener: TcpListener, marker: Option<u8>) -> Echo {
    let address = listener.local_addr().unwrap();
    let stop = CancellationToken::new();
    let shutdown = stop.clone();
    let task = tokio::spawn(async move {
        loop {
            let pair = tokio::select! {_=shutdown.cancelled()=>break,pair=listener.accept()=>pair};
            let Ok((mut stream, _)) = pair else {
                break;
            };
            let cancel = shutdown.clone();
            tokio::spawn(async move {
                let echo = async {
                    if let Some(marker) = marker {
                        stream.write_all(&[marker]).await?;
                    }
                    let mut buf = [0u8; 64 * 1024];
                    loop {
                        let count = stream.read(&mut buf).await?;
                        if count == 0 {
                            stream.shutdown().await?;
                            break;
                        }
                        stream.write_all(&buf[..count]).await?;
                    }
                    Ok::<(), std::io::Error>(())
                };
                tokio::select! {_=cancel.cancelled()=>{},_=echo=>{}}
            });
        }
    });
    Echo {
        address,
        stop,
        task,
    }
}
pub async fn udp_echo() -> Echo {
    udp_echo_at("127.0.0.1:0").await
}
pub async fn udp_echo_at(bind: &str) -> Echo {
    let socket = UdpSocket::bind(bind).await.unwrap();
    udp_echo_from(socket)
}
fn udp_echo_from(socket: UdpSocket) -> Echo {
    let address = socket.local_addr().unwrap();
    let stop = CancellationToken::new();
    let shutdown = stop.clone();
    let task = tokio::spawn(async move {
        let mut buf = [0u8; 65536];
        loop {
            let packet = tokio::select! {_=shutdown.cancelled()=>break,packet=socket.recv_from(&mut buf)=>packet};
            let Ok((n, peer)) = packet else {
                break;
            };
            let _ = socket.send_to(&buf[..n], peer).await;
        }
    });
    Echo {
        address,
        stop,
        task,
    }
}
pub async fn exchange(address: SocketAddr, payload: &[u8]) -> Vec<u8> {
    tokio::time::timeout(Duration::from_secs(5), async {
        let mut stream = TcpStream::connect(address).await.unwrap();
        let (mut read, mut write) = stream.split();
        let send = async {
            write.write_all(payload).await.unwrap();
            write.shutdown().await.unwrap();
        };
        let receive = async {
            let mut bytes = vec![];
            read.read_to_end(&mut bytes).await.unwrap();
            bytes
        };
        tokio::join!(send, receive).1
    })
    .await
    .expect("TCP exchange timed out")
}
