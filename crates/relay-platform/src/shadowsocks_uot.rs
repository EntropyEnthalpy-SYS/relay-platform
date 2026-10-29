//! SagerNet UDP-over-TCP v1/v2 framing inside an authenticated SS stream.
//! This is an optional extension, not ordinary Shadowsocks UDP. Wire format:
//! https://sing-box.sagernet.org/configuration/shared/udp-over-tcp/
use crate::shadowsocks::Destination;
use anyhow::{Result, bail, ensure};
use std::net::{Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

pub const MAX_DATAGRAM: usize = 65_507;

pub fn version(destination: &Destination) -> Option<u8> {
    match destination {
        Destination::Domain(name, 0) if name == "sp.udp-over-tcp.arpa" => Some(1),
        Destination::Domain(name, 0) if name == "sp.v2.udp-over-tcp.arpa" => Some(2),
        _ => None,
    }
}

async fn address<R: AsyncRead + Unpin>(reader: &mut R, kind: u8, uot: bool) -> Result<Destination> {
    let kind = if uot {
        match kind {
            0 => 1,
            1 => 4,
            2 => 3,
            _ => bail!("invalid UoT address type"),
        }
    } else {
        kind
    };
    let host = match kind {
        1 => {
            let mut ip = [0; 4];
            reader.read_exact(&mut ip).await?;
            Some(Ipv4Addr::from(ip).into())
        }
        4 => {
            let mut ip = [0; 16];
            reader.read_exact(&mut ip).await?;
            Some(Ipv6Addr::from(ip).into())
        }
        3 => None,
        _ => bail!("invalid UoT request address type"),
    };
    if let Some(ip) = host {
        return Ok(Destination::Ip(SocketAddr::new(
            ip,
            reader.read_u16().await?,
        )));
    }
    let length = usize::from(reader.read_u8().await?);
    ensure!(length > 0, "empty UoT destination name");
    let mut name = vec![0; length];
    reader.read_exact(&mut name).await?;
    ensure!(
        name.iter()
            .all(|c| c.is_ascii_alphanumeric() || b"-._".contains(c)),
        "invalid UoT destination name"
    );
    Ok(Destination::Domain(
        String::from_utf8(name)?.to_ascii_lowercase(),
        reader.read_u16().await?,
    ))
}

fn valid_port(destination: &Destination) -> bool {
    match destination {
        Destination::Ip(a) => a.port() != 0,
        Destination::Domain(_, p) => *p != 0,
    }
}

/// None is an association (destination in each frame); Some is a connected flow.
pub async fn request<R: AsyncRead + Unpin>(
    reader: &mut R,
    version: u8,
) -> Result<Option<Destination>> {
    if version == 1 {
        return Ok(None);
    }
    ensure!(version == 2, "unsupported UoT version");
    let connect = reader.read_u8().await?;
    ensure!(connect <= 1, "invalid UoT connect flag");
    let kind = reader.read_u8().await?;
    let destination = address(reader, kind, false).await?;
    if connect == 0 {
        return Ok(None);
    } // Association header may be 0.0.0.0:0.
    ensure!(valid_port(&destination), "UoT destination port 0");
    Ok(Some(destination))
}

pub struct Packet {
    pub destination: Destination,
    pub payload: Vec<u8>,
}

/// Keep this future alive across reads of UDP replies: read_exact is not
/// cancellation safe when a TCP frame arrives in several writes.
pub async fn read_packet<R: AsyncRead + Unpin>(
    reader: &mut R,
    connected: Option<&Destination>,
) -> Result<Option<Packet>> {
    let mut first = [0];
    if reader.read(&mut first).await? == 0 {
        return Ok(None);
    }
    let (destination, size) = if let Some(destination) = connected {
        (
            destination.clone(),
            u16::from_be_bytes([first[0], reader.read_u8().await?]),
        )
    } else {
        let destination = address(reader, first[0], true).await?;
        ensure!(valid_port(&destination), "UoT destination port 0");
        (destination, reader.read_u16().await?)
    };
    let size = usize::from(size);
    ensure!(size <= MAX_DATAGRAM, "UoT datagram too large");
    let mut payload = vec![0; size];
    reader.read_exact(&mut payload).await?;
    Ok(Some(Packet {
        destination,
        payload,
    }))
}

pub async fn write_packet<W: AsyncWrite + Unpin>(
    writer: &mut W,
    connected: bool,
    source: SocketAddr,
    data: &[u8],
) -> Result<()> {
    ensure!(data.len() <= MAX_DATAGRAM, "UoT reply too large");
    let mut head = Vec::with_capacity(21);
    if !connected {
        match crate::model::canonical_address(source) {
            SocketAddr::V4(a) => {
                head.push(0);
                head.extend_from_slice(&a.ip().octets());
            }
            SocketAddr::V6(a) => {
                head.push(1);
                head.extend_from_slice(&a.ip().octets());
            }
        }
        head.extend_from_slice(&source.port().to_be_bytes());
    }
    head.extend_from_slice(&(data.len() as u16).to_be_bytes());
    writer.write_all(&head).await?;
    writer.write_all(data).await?;
    writer.flush().await?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    #[tokio::test]
    async fn association_and_connect_accept_empty_and_large_packets_without_boundary_loss() {
        for connected in [false, true] {
            let source: SocketAddr = "[::1]:5353".parse().unwrap();
            let destination = Destination::Ip(source);
            let mut wire = Vec::new();
            for size in [0, 1, 4096, MAX_DATAGRAM] {
                write_packet(&mut wire, connected, source, &vec![42; size])
                    .await
                    .unwrap();
            }
            let mut reader = wire.as_slice();
            for size in [0, 1, 4096, MAX_DATAGRAM] {
                let packet = read_packet(&mut reader, connected.then_some(&destination))
                    .await
                    .unwrap()
                    .unwrap();
                assert_eq!(packet.destination, destination);
                assert_eq!(packet.payload, vec![42; size]);
            }
            assert!(
                read_packet(&mut reader, connected.then_some(&destination))
                    .await
                    .unwrap()
                    .is_none()
            );
        }
    }
    #[tokio::test]
    async fn malformed_truncated_and_oversized_frames_are_rejected() {
        let destination = Destination::Ip("127.0.0.1:53".parse().unwrap());
        for bytes in [&[0][..], &[0, 2, 1], &[255, 255]] {
            assert!(
                read_packet(&mut &bytes[..], Some(&destination))
                    .await
                    .is_err()
            );
        }
        assert!(request(&mut &[2u8][..], 2).await.is_err());
        assert!(read_packet(&mut &[3u8][..], None).await.is_err());
        assert!(
            request(&mut &[1, 1, 127, 0, 0, 1, 0, 0][..], 2)
                .await
                .is_err()
        );
        assert_eq!(
            request(&mut &[0, 1, 0, 0, 0, 0, 0, 0][..], 2)
                .await
                .unwrap(),
            None
        );
    }
}
