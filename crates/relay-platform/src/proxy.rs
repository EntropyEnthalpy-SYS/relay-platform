//! Explicitly enabled PROXY protocol. Header claims are never authentication.
use crate::model::{ProxyAccept, ProxyInbound, ProxyOutbound, ProxyVersion};
use anyhow::{Context, Result, bail, ensure};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt};

const SIGNATURE: &[u8; 12] = b"\r\n\r\n\0\r\nQUIT\n";
const V1_MAX: usize = 107;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct ConnectionInfo {
    pub source: SocketAddr,
    pub destination: SocketAddr,
}

fn port(text: &str) -> Result<u16> {
    ensure!(
        !text.is_empty()
            && text.bytes().all(|b| b.is_ascii_digit())
            && (text.len() == 1 || !text.starts_with('0')),
        "invalid PROXY v1 port"
    );
    Ok(text.parse()?)
}

fn parse_v1(header: &[u8], original: ConnectionInfo) -> Result<ConnectionInfo> {
    ensure!(header.len() <= V1_MAX, "PROXY v1 header too long");
    let line = header
        .strip_suffix(b"\r\n")
        .context("PROXY v1 requires CRLF")?;
    if line == b"PROXY UNKNOWN" || line.starts_with(b"PROXY UNKNOWN ") {
        return Ok(original);
    }
    let text = std::str::from_utf8(line).context("non-ASCII PROXY v1 header")?;
    let parts: Vec<_> = text.split(' ').collect();
    ensure!(
        parts.len() == 6 && parts[0] == "PROXY",
        "invalid PROXY v1 fields"
    );
    let source: IpAddr = parts[2].parse()?;
    let destination: IpAddr = parts[3].parse()?;
    ensure!(
        matches!(parts[1], "TCP4" | "TCP6")
            && source.is_ipv4() == (parts[1] == "TCP4")
            && source.is_ipv4() == destination.is_ipv4(),
        "PROXY v1 address family mismatch"
    );
    Ok(ConnectionInfo {
        source: SocketAddr::new(source, port(parts[4])?),
        destination: SocketAddr::new(destination, port(parts[5])?),
    })
}

fn verify_tlvs(header: &[u8], mut offset: usize) -> Result<()> {
    let mut checksum = None;
    while offset < header.len() {
        ensure!(header.len() - offset >= 3, "truncated PROXY TLV");
        let kind = header[offset];
        let size = u16::from_be_bytes([header[offset + 1], header[offset + 2]]) as usize;
        offset += 3;
        ensure!(size <= header.len() - offset, "PROXY TLV exceeds header");
        if kind == 0x03 {
            ensure!(
                size == 4 && checksum.is_none(),
                "invalid or duplicate PROXY CRC32C"
            );
            checksum = Some(offset);
        }
        offset += size;
    }
    if let Some(offset) = checksum {
        let expected = u32::from_be_bytes(header[offset..offset + 4].try_into().unwrap());
        let mut bytes = header.to_vec();
        bytes[offset..offset + 4].fill(0);
        ensure!(crc32c::crc32c(&bytes) == expected, "PROXY CRC32C mismatch");
    }
    Ok(())
}

/// Decode one bounded v2 header. Bytes after `consumed` are application payload.
pub fn decode_v2(
    bytes: &[u8],
    tcp: bool,
    max_header_bytes: u32,
    original: ConnectionInfo,
) -> Result<(ConnectionInfo, usize)> {
    ensure!(
        bytes.len() >= 16 && bytes[..12] == *SIGNATURE,
        "invalid PROXY v2 signature"
    );
    ensure!(
        bytes[12] >> 4 == 2 && bytes[12] & 15 <= 1,
        "invalid PROXY v2 version/command"
    );
    let total = 16 + usize::from(u16::from_be_bytes([bytes[14], bytes[15]]));
    ensure!(
        total <= max_header_bytes as usize && bytes.len() >= total,
        "PROXY v2 length exceeds limit or input"
    );
    // LOCAL explicitly ignores the entire protocol block, including family/TLVs.
    if bytes[12] & 15 == 0 {
        return Ok((original, total));
    }
    let family = bytes[13] >> 4;
    let transport = bytes[13] & 15;
    ensure!(
        family <= 3 && transport <= 2,
        "invalid PROXY v2 address family/transport"
    );
    if family == 0 || transport == 0 {
        return Ok((original, total));
    }
    ensure!(
        transport == if tcp { 1 } else { 2 },
        "PROXY transport does not match this listener"
    );
    let body = &bytes[16..total];
    let address_len = match family {
        1 => 12,
        2 => 36,
        3 => 216,
        _ => unreachable!(),
    };
    ensure!(body.len() >= address_len, "truncated PROXY address block");
    verify_tlvs(&bytes[..total], 16 + address_len)?;
    let info = match family {
        1 => ConnectionInfo {
            source: SocketAddr::new(
                Ipv4Addr::from(<[u8; 4]>::try_from(&body[..4]).unwrap()).into(),
                u16::from_be_bytes([body[8], body[9]]),
            ),
            destination: SocketAddr::new(
                Ipv4Addr::from(<[u8; 4]>::try_from(&body[4..8]).unwrap()).into(),
                u16::from_be_bytes([body[10], body[11]]),
            ),
        },
        2 => ConnectionInfo {
            source: SocketAddr::new(
                Ipv6Addr::from(<[u8; 16]>::try_from(&body[..16]).unwrap()).into(),
                u16::from_be_bytes([body[32], body[33]]),
            ),
            destination: SocketAddr::new(
                Ipv6Addr::from(<[u8; 16]>::try_from(&body[16..32]).unwrap()).into(),
                u16::from_be_bytes([body[34], body[35]]),
            ),
        },
        // Valid but unsupported Unix addresses use the transport's real IP endpoints.
        _ => original,
    };
    Ok((info, total))
}

pub async fn read_tcp<R: AsyncRead + Unpin + ?Sized>(
    stream: &mut R,
    policy: &ProxyInbound,
    original: ConnectionInfo,
) -> Result<ConnectionInfo> {
    let first = stream.read_u8().await?;
    if first == b'P' && policy.version != ProxyAccept::V2 {
        let limit = V1_MAX.min(policy.max_header_bytes as usize);
        let mut header = vec![first];
        while header.len() < limit {
            header.push(stream.read_u8().await?);
            if header.ends_with(b"\r\n") {
                return parse_v1(&header, original);
            }
            ensure!(!header.ends_with(b"\n"), "PROXY v1 requires CRLF");
        }
        bail!("PROXY v1 header exceeds limit");
    }
    ensure!(
        first == b'\r' && policy.version != ProxyAccept::V1,
        "required PROXY header missing or wrong version"
    );
    let mut fixed = [0; 16];
    fixed[0] = first;
    stream.read_exact(&mut fixed[1..]).await?;
    ensure!(
        fixed[..12] == *SIGNATURE && fixed[12] >> 4 == 2 && fixed[12] & 15 <= 1,
        "invalid PROXY v2 prefix"
    );
    let total = 16 + usize::from(u16::from_be_bytes([fixed[14], fixed[15]]));
    ensure!(
        total <= policy.max_header_bytes as usize,
        "PROXY v2 header exceeds limit"
    );
    let mut bytes = vec![0; total];
    bytes[..16].copy_from_slice(&fixed);
    stream.read_exact(&mut bytes[16..]).await?;
    Ok(decode_v2(&bytes, true, policy.max_header_bytes, original)?.0)
}

pub fn encode(policy: &ProxyOutbound, tcp: bool, info: ConnectionInfo) -> Result<Vec<u8>> {
    ensure!(
        info.source.is_ipv4() == info.destination.is_ipv4(),
        "PROXY endpoint address families differ"
    );
    if policy.version == ProxyVersion::V1 {
        ensure!(tcp && !policy.checksum, "v1 requires TCP without CRC32C");
        return Ok(format!(
            "PROXY {} {} {} {} {}\r\n",
            if info.source.is_ipv4() {
                "TCP4"
            } else {
                "TCP6"
            },
            info.source.ip(),
            info.destination.ip(),
            info.source.port(),
            info.destination.port()
        )
        .into_bytes());
    }
    let mut bytes = SIGNATURE.to_vec();
    bytes.push(0x21);
    bytes.push((if info.source.is_ipv4() { 0x10 } else { 0x20 }) | if tcp { 1 } else { 2 });
    bytes.extend_from_slice(&[0, 0]);
    for ip in [info.source.ip(), info.destination.ip()] {
        match ip {
            IpAddr::V4(ip) => bytes.extend_from_slice(&ip.octets()),
            IpAddr::V6(ip) => bytes.extend_from_slice(&ip.octets()),
        }
    }
    bytes.extend_from_slice(&info.source.port().to_be_bytes());
    bytes.extend_from_slice(&info.destination.port().to_be_bytes());
    if policy.checksum {
        bytes.extend_from_slice(&[3, 0, 4, 0, 0, 0, 0]);
    }
    let body_len = (bytes.len() - 16) as u16;
    bytes[14..16].copy_from_slice(&body_len.to_be_bytes());
    if policy.checksum {
        let crc = crc32c::crc32c(&bytes);
        let offset = bytes.len() - 4;
        bytes[offset..].copy_from_slice(&crc.to_be_bytes());
    }
    Ok(bytes)
}
