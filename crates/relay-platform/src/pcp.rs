//! Minimal PCP (RFC 6887) MAP client for one UDP mapping. It is a management
//! client, not a PCP server or a NAT traversal data path.
use anyhow::{Context, Result, ensure};
use serde::Serialize;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::time::{Duration, timeout};
use uuid::Uuid;

const VERSION: u8 = 2;
const OPCODE_MAP: u8 = 1;
const PROTOCOL_UDP: u8 = 17;
const DEFAULT_PORT: u16 = 5351;

#[derive(Clone, Debug, Serialize)]
pub struct Mapping {
    pub gateway: SocketAddr,
    pub internal_port: u16,
    pub external_port: u16,
    pub external_ip: IpAddr,
    pub lifetime_secs: u32,
    pub epoch: u32,
}
pub fn gateway_from(value: &str) -> Result<SocketAddr> {
    let mut address = match value.parse::<SocketAddr>() {
        Ok(address) => address,
        Err(_) => {
            let ip: Ipv4Addr = value
                .parse()
                .with_context(|| format!("invalid PCP gateway {value}; use IP:PORT or IP"))?;
            SocketAddr::new(ip.into(), DEFAULT_PORT)
        }
    };
    if address.port() == 0 {
        address.set_port(DEFAULT_PORT);
    }
    Ok(address)
}
pub fn request(
    client: IpAddr,
    internal_port: u16,
    external_port: u16,
    lifetime_secs: u32,
    nonce: [u8; 12],
) -> [u8; 60] {
    let mut packet = [0u8; 60];
    packet[0] = VERSION;
    packet[1] = OPCODE_MAP;
    packet[4..8].copy_from_slice(&lifetime_secs.to_be_bytes());
    let client = match client {
        IpAddr::V4(ip) => ip.to_ipv6_mapped(),
        IpAddr::V6(ip) => ip,
    };
    packet[8..24].copy_from_slice(&client.octets());
    packet[24..36].copy_from_slice(&nonce);
    packet[36] = PROTOCOL_UDP;
    packet[40..42].copy_from_slice(&internal_port.to_be_bytes());
    packet[42..44].copy_from_slice(&external_port.to_be_bytes());
    packet
}
pub fn parse_response(packet: &[u8], gateway: SocketAddr, nonce: [u8; 12]) -> Result<Mapping> {
    ensure!(packet.len() >= 60, "PCP response is too short");
    ensure!(packet[0] == VERSION, "unsupported PCP version");
    ensure!(
        packet[1] == OPCODE_MAP | 0x80,
        "unexpected PCP response opcode"
    );
    ensure!(
        packet[3] == 0,
        "PCP gateway refused the mapping: {}",
        packet[3]
    );
    ensure!(packet[24..36] == nonce, "PCP response nonce mismatch");
    ensure!(packet[36] == PROTOCOL_UDP, "PCP response protocol mismatch");
    let mut external = [0u8; 16];
    external.copy_from_slice(&packet[44..60]);
    let external_ip = Ipv6Addr::from(external)
        .to_ipv4_mapped()
        .map(IpAddr::V4)
        .unwrap_or_else(|| IpAddr::V6(Ipv6Addr::from(external)));
    Ok(Mapping {
        gateway,
        internal_port: u16::from_be_bytes([packet[40], packet[41]]),
        external_port: u16::from_be_bytes([packet[42], packet[43]]),
        external_ip,
        lifetime_secs: u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]),
        epoch: u32::from_be_bytes([packet[8], packet[9], packet[10], packet[11]]),
    })
}
pub fn new_nonce() -> [u8; 12] {
    let mut nonce = [0u8; 12];
    nonce.copy_from_slice(&Uuid::new_v4().into_bytes()[..12]);
    nonce
}
pub async fn map(
    gateway: SocketAddr,
    internal_port: u16,
    external_port: u16,
    lifetime_secs: u32,
) -> Result<Mapping> {
    ensure!(internal_port != 0, "internal port is zero");
    ensure!(
        lifetime_secs <= 604_800,
        "PCP lifetime must be at most seven days"
    );
    let local = if gateway.is_ipv4() {
        SocketAddr::from((Ipv4Addr::UNSPECIFIED, 0))
    } else {
        SocketAddr::from((Ipv6Addr::UNSPECIFIED, 0))
    };
    let socket = UdpSocket::bind(local)
        .await
        .context("cannot bind PCP client socket")?;
    socket
        .connect(gateway)
        .await
        .context("cannot connect PCP client socket")?;
    let nonce = new_nonce();
    let local_ip = socket
        .local_addr()
        .context("cannot read PCP client address")?
        .ip();
    socket
        .send(&request(
            local_ip,
            internal_port,
            external_port,
            lifetime_secs,
            nonce,
        ))
        .await
        .context("cannot send PCP request")?;
    let mut buffer = [0u8; 128];
    let size = timeout(Duration::from_secs(3), socket.recv(&mut buffer))
        .await
        .context("PCP gateway did not answer within 3s")?
        .context("cannot receive PCP response")?;
    parse_response(&buffer[..size], gateway, nonce)
}
