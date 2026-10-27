//! Minimal NAT-PMP (RFC 6886) port-mapping client. This manages one UDP
//! mapping; it is not a NAT traversal server or a WireGuard implementation.
use anyhow::{Context, Result, bail, ensure};
use serde::Serialize;
use std::net::{Ipv4Addr, SocketAddr};
use tokio::net::UdpSocket;
use tokio::time::{Duration, sleep, timeout};
use tokio_util::sync::CancellationToken;

const OPCODE_MAP_UDP: u8 = 1;
const DEFAULT_PORT: u16 = 5351;

#[derive(Clone, Debug, Serialize)]
pub struct Mapping {
    pub gateway: SocketAddr,
    pub internal_port: u16,
    pub external_port: u16,
    pub lifetime_secs: u32,
    pub epoch: u32,
}
pub fn gateway_from(value: &str) -> Result<SocketAddr> {
    let mut address = match value.parse::<SocketAddr>() {
        Ok(address) => address,
        Err(_) => {
            let ip: Ipv4Addr = value
                .parse()
                .with_context(|| format!("invalid NAT-PMP gateway {value}; use IP:PORT or IP"))?;
            SocketAddr::new(ip.into(), DEFAULT_PORT)
        }
    };
    if address.port() == 0 {
        address.set_port(DEFAULT_PORT);
    }
    ensure!(
        address.is_ipv4(),
        "NAT-PMP currently supports IPv4 gateways"
    );
    Ok(address)
}
pub fn request(internal_port: u16, external_port: u16, lifetime_secs: u32) -> [u8; 12] {
    let mut packet = [0u8; 12];
    packet[1] = OPCODE_MAP_UDP;
    packet[4..6].copy_from_slice(&internal_port.to_be_bytes());
    packet[6..8].copy_from_slice(&external_port.to_be_bytes());
    packet[8..12].copy_from_slice(&lifetime_secs.to_be_bytes());
    packet
}
pub fn parse_response(packet: &[u8], gateway: SocketAddr) -> Result<Mapping> {
    ensure!(packet.len() >= 16, "NAT-PMP response is too short");
    ensure!(packet[0] == 0, "unsupported NAT-PMP version");
    ensure!(
        packet[1] == OPCODE_MAP_UDP + 128,
        "unexpected NAT-PMP response opcode"
    );
    let result = u16::from_be_bytes([packet[2], packet[3]]);
    ensure!(result == 0, "NAT-PMP gateway refused the mapping: {result}");
    Ok(Mapping {
        gateway,
        epoch: u32::from_be_bytes([packet[4], packet[5], packet[6], packet[7]]),
        internal_port: u16::from_be_bytes([packet[8], packet[9]]),
        external_port: u16::from_be_bytes([packet[10], packet[11]]),
        lifetime_secs: u32::from_be_bytes([packet[12], packet[13], packet[14], packet[15]]),
    })
}
/// Request or delete (lifetime 0) one UDP mapping through a NAT-PMP gateway.
pub async fn map(
    gateway: SocketAddr,
    internal_port: u16,
    external_port: u16,
    lifetime_secs: u32,
) -> Result<Mapping> {
    ensure!(
        gateway.is_ipv4(),
        "NAT-PMP currently supports IPv4 gateways"
    );
    ensure!(internal_port != 0, "internal port is zero");
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0))
        .await
        .context("cannot bind NAT-PMP client socket")?;
    socket
        .connect(gateway)
        .await
        .context("cannot connect NAT-PMP client socket")?;
    socket
        .send(&request(internal_port, external_port, lifetime_secs))
        .await
        .context("cannot send NAT-PMP request")?;
    let mut buffer = [0u8; 32];
    let size = timeout(Duration::from_secs(3), socket.recv(&mut buffer))
        .await
        .context("NAT-PMP gateway did not answer within 3s")?
        .context("cannot receive NAT-PMP response")?;
    parse_response(&buffer[..size], gateway)
}
pub fn validate_lifetime(lifetime_secs: u32) -> Result<()> {
    ensure!(
        lifetime_secs <= 604_800,
        "NAT-PMP lifetime must be at most seven days"
    );
    Ok(())
}
pub fn validate_ports(internal: u16, _external: u16) -> Result<()> {
    if internal == 0 {
        bail!("internal port is zero");
    }
    Ok(())
}

/// Keep one NAT-PMP mapping alive until cancellation. `renew_after` is the
/// delay between successful requests; callers normally choose half the lease.
pub async fn maintain<F>(
    gateway: SocketAddr,
    internal_port: u16,
    external_port: u16,
    lifetime_secs: u32,
    renew_after: Duration,
    cancel: CancellationToken,
    mut on_mapping: F,
) -> Result<()>
where
    F: FnMut(&Mapping),
{
    ensure!(!renew_after.is_zero(), "renew interval is zero");
    ensure!(
        renew_after < Duration::from_secs(u64::from(lifetime_secs.max(1))),
        "renew interval must be shorter than the lease"
    );
    loop {
        let mapping = map(gateway, internal_port, external_port, lifetime_secs).await?;
        on_mapping(&mapping);
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = sleep(renew_after) => {}
        }
    }
    Ok(())
}
