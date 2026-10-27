//! SOCKS5 inbound (RFC 1928/1929) with optional username/password, TCP
//! CONNECT and UDP ASSOCIATE.
use crate::shadowsocks::Destination;
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::Instant;
use tokio::time::timeout_at;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ServerConfig {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
    #[serde(default)]
    pub allow_private_destinations: bool,
}
pub fn validate(config: &ServerConfig) -> Result<()> {
    match (&config.username, &config.password) {
        (None, None) => {}
        (Some(username), Some(password)) => {
            for (value, what) in [(username, "SOCKS5 username"), (password, "SOCKS5 password")] {
                if value.is_empty() || value.len() > 255 || value.chars().any(char::is_control) {
                    bail!("{what} must contain 1..255 bytes without control characters");
                }
            }
        }
        _ => bail!("SOCKS5 username and password must be configured together"),
    }
    Ok(())
}
pub struct Server {
    config: ServerConfig,
}
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Request {
    Connect(Destination),
    Bind(Destination),
    UdpAssociate,
}
#[derive(Clone, Debug)]
pub struct UdpDatagram {
    pub destination: Destination,
    pub payload: Vec<u8>,
}
impl Server {
    pub fn new(config: &ServerConfig) -> Result<Self> {
        validate(config)?;
        Ok(Self {
            config: config.clone(),
        })
    }
    pub fn permits(&self, ip: IpAddr) -> bool {
        self.config.allow_private_destinations || crate::shadowsocks::public(ip)
    }
    /// Performs the greeting, optional authentication and CONNECT/BIND/
    /// UDP ASSOCIATE request. On malformed/unsupported input this method sends
    /// a failure reply where the protocol still permits one.
    pub async fn accept<S>(&self, stream: &mut S, deadline: Instant) -> Result<Request>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut greeting = [0u8; 2];
        exact(stream, &mut greeting, deadline).await?;
        ensure!(greeting[0] == 5, "unsupported SOCKS version");
        let count = usize::from(greeting[1]);
        ensure!(count > 0, "SOCKS5 client offered no authentication methods");
        let mut methods = vec![0u8; count];
        exact(stream, &mut methods, deadline).await?;
        let method = if self.config.username.is_some() {
            methods.contains(&2).then_some(2)
        } else {
            methods.contains(&0).then_some(0)
        };
        let Some(method) = method else {
            write_all(stream, &[5, 0xFF]).await?;
            bail!("SOCKS5 client did not offer the required authentication method");
        };
        write_all(stream, &[5, method]).await?;
        if method == 2 {
            self.authenticate(stream, deadline).await?;
        }

        let mut header = [0u8; 4];
        exact(stream, &mut header, deadline).await?;
        ensure!(header[0] == 5 && header[2] == 0, "malformed SOCKS5 request");
        let allow_zero_port = matches!(header[1], 2 | 3);
        let destination = match header[3] {
            1 => {
                let mut bytes = [0u8; 4];
                exact(stream, &mut bytes, deadline).await?;
                let port = port(stream, deadline, allow_zero_port).await?;
                Destination::Ip(SocketAddr::new(Ipv4Addr::from(bytes).into(), port))
            }
            4 => {
                let mut bytes = [0u8; 16];
                exact(stream, &mut bytes, deadline).await?;
                let port = port(stream, deadline, allow_zero_port).await?;
                Destination::Ip(SocketAddr::new(Ipv6Addr::from(bytes).into(), port))
            }
            3 => {
                let mut length = [0u8; 1];
                exact(stream, &mut length, deadline).await?;
                ensure!(length[0] > 0, "empty SOCKS5 destination name");
                let mut name = vec![0u8; usize::from(length[0])];
                exact(stream, &mut name, deadline).await?;
                let name = String::from_utf8(name).context("SOCKS5 destination is not UTF-8")?;
                let port = port(stream, deadline, allow_zero_port).await?;
                Destination::Domain(name, port)
            }
            _ => {
                let _ = reply(stream, 8).await;
                bail!("unsupported SOCKS5 address type");
            }
        };
        match header[1] {
            1 => {
                ensure!(
                    destination_port(&destination) != 0,
                    "SOCKS5 CONNECT port is zero"
                );
                Ok(Request::Connect(destination))
            }
            2 => Ok(Request::Bind(destination)),
            3 => Ok(Request::UdpAssociate),
            command => {
                let _ = reply(stream, 7).await;
                bail!("SOCKS5 command {command} is not supported");
            }
        }
    }
    async fn authenticate<S>(&self, stream: &mut S, deadline: Instant) -> Result<()>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut head = [0u8; 2];
        exact(stream, &mut head, deadline).await?;
        ensure!(
            head[0] == 1 && head[1] > 0,
            "malformed SOCKS5 authentication"
        );
        let mut username = vec![0u8; usize::from(head[1])];
        exact(stream, &mut username, deadline).await?;
        let mut length = [0u8; 1];
        exact(stream, &mut length, deadline).await?;
        let mut password = vec![0u8; usize::from(length[0])];
        exact(stream, &mut password, deadline).await?;
        let ok = self.config.username.as_deref().is_some_and(|expected| {
            expected.as_bytes() == username.as_slice()
                && self
                    .config
                    .password
                    .as_deref()
                    .is_some_and(|expected| expected.as_bytes() == password.as_slice())
        });
        write_all(stream, &[1, if ok { 0 } else { 1 }]).await?;
        ensure!(ok, "SOCKS5 authentication failed");
        Ok(())
    }
}

async fn exact<S>(stream: &mut S, buffer: &mut [u8], deadline: Instant) -> Result<()>
where
    S: AsyncRead + Unpin,
{
    timeout_at(deadline, stream.read_exact(buffer))
        .await
        .context("SOCKS5 handshake timed out")??;
    Ok(())
}
async fn port<S>(stream: &mut S, deadline: Instant, allow_zero: bool) -> Result<u16>
where
    S: AsyncRead + Unpin,
{
    let mut bytes = [0u8; 2];
    exact(stream, &mut bytes, deadline).await?;
    let port = u16::from_be_bytes(bytes);
    ensure!(allow_zero || port != 0, "SOCKS5 destination port is zero");
    Ok(port)
}
fn destination_port(destination: &Destination) -> u16 {
    match destination {
        Destination::Ip(address) => address.port(),
        Destination::Domain(_, port) => *port,
    }
}
/// Encodes a successful BIND/UDP ASSOCIATE reply with the bound endpoint.
pub async fn udp_bind_reply<S>(stream: &mut S, address: SocketAddr) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    let mut packet = vec![5, 0, 0];
    match address {
        SocketAddr::V4(address) => {
            packet.push(1);
            packet.extend_from_slice(&address.ip().octets());
        }
        SocketAddr::V6(address) => {
            packet.push(4);
            packet.extend_from_slice(&address.ip().octets());
        }
    }
    packet.extend_from_slice(&address.port().to_be_bytes());
    write_all(stream, &packet).await
}
pub async fn bind_reply<S>(stream: &mut S, address: SocketAddr) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    udp_bind_reply(stream, address).await
}
/// Parses a SOCKS5 UDP request datagram (RSV, FRAG, destination, payload).
pub fn parse_udp_datagram(packet: &[u8]) -> Result<UdpDatagram> {
    ensure!(packet.len() >= 4, "SOCKS5 UDP datagram is too short");
    ensure!(
        packet[0] == 0 && packet[1] == 0,
        "SOCKS5 UDP reserved bytes"
    );
    ensure!(packet[2] == 0, "SOCKS5 UDP fragmentation is not supported");
    let (destination, payload_start) = parse_udp_address(&packet[3..])?;
    Ok(UdpDatagram {
        destination,
        payload: packet[3 + payload_start..].to_vec(),
    })
}
fn parse_udp_address(data: &[u8]) -> Result<(Destination, usize)> {
    ensure!(!data.is_empty(), "SOCKS5 UDP address is missing");
    let (destination, port_start) = match data[0] {
        1 => {
            ensure!(data.len() >= 7, "SOCKS5 UDP IPv4 address is truncated");
            (
                Destination::Ip(SocketAddr::from(([data[1], data[2], data[3], data[4]], 0))),
                5,
            )
        }
        4 => {
            ensure!(data.len() >= 19, "SOCKS5 UDP IPv6 address is truncated");
            let mut bytes = [0u8; 16];
            bytes.copy_from_slice(&data[1..17]);
            (
                Destination::Ip(SocketAddr::from((Ipv6Addr::from(bytes), 0))),
                17,
            )
        }
        3 => {
            ensure!(data.len() >= 2, "SOCKS5 UDP domain length is missing");
            let length = usize::from(data[1]);
            ensure!(
                length > 0 && data.len() >= 2 + length + 2,
                "SOCKS5 UDP domain is truncated"
            );
            let name = std::str::from_utf8(&data[2..2 + length])?.to_owned();
            (Destination::Domain(name, 0), 2 + length)
        }
        _ => bail!("unknown SOCKS5 UDP address type"),
    };
    let port = u16::from_be_bytes([data[port_start], data[port_start + 1]]);
    ensure!(port != 0, "SOCKS5 UDP destination port is zero");
    let destination = match destination {
        Destination::Ip(address) => Destination::Ip(SocketAddr::new(address.ip(), port)),
        Destination::Domain(name, _) => Destination::Domain(name, port),
    };
    Ok((destination, port_start + 2))
}

/// Wraps a UDP reply with the source address and payload.
pub fn encode_udp_datagram(destination: &Destination, payload: &[u8]) -> Vec<u8> {
    let mut packet = vec![0, 0, 0];
    match destination {
        Destination::Ip(address) => {
            match address.ip() {
                IpAddr::V4(ip) => {
                    packet.push(1);
                    packet.extend_from_slice(&ip.octets());
                }
                IpAddr::V6(ip) => {
                    packet.push(4);
                    packet.extend_from_slice(&ip.octets());
                }
            }
            packet.extend_from_slice(&address.port().to_be_bytes());
        }
        Destination::Domain(name, port) => {
            packet.push(3);
            packet.push(name.len() as u8);
            packet.extend_from_slice(name.as_bytes());
            packet.extend_from_slice(&port.to_be_bytes());
        }
    }
    packet.extend_from_slice(payload);
    packet
}
async fn write_all<S>(stream: &mut S, bytes: &[u8]) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(bytes).await?;
    stream.flush().await?;
    Ok(())
}
/// Sends a SOCKS5 CONNECT reply with an IPv4 zero bound address.
pub async fn reply<S>(stream: &mut S, status: u8) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    write_all(stream, &[5, status, 0, 1, 0, 0, 0, 0, 0, 0]).await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn no_auth_and_domain_connect_are_parsed() {
        let server = Server::new(&ServerConfig {
            username: None,
            password: None,
            allow_private_destinations: false,
        })
        .unwrap();
        let (mut client, mut peer) = duplex(256);
        let task = tokio::spawn(async move {
            server
                .accept(
                    &mut peer,
                    Instant::now() + std::time::Duration::from_secs(1),
                )
                .await
        });
        client.write_all(&[5, 1, 0]).await.unwrap();
        let mut selected = [0u8; 2];
        client.read_exact(&mut selected).await.unwrap();
        assert_eq!(selected, [5, 0]);
        // CONNECT example.com:443
        let mut request = vec![5, 1, 0, 3, 11];
        request.extend_from_slice(b"example.com");
        request.extend_from_slice(&443u16.to_be_bytes());
        client.write_all(&request).await.unwrap();
        let request = task.await.unwrap().unwrap();
        match request {
            Request::Connect(destination) => assert_eq!(destination.to_string(), "example.com:443"),
            Request::Bind(_) | Request::UdpAssociate => panic!("expected CONNECT"),
        }
    }

    #[tokio::test]
    async fn success_reply_is_well_formed() {
        let (mut writer, mut reader) = duplex(32);
        reply(&mut writer, 0).await.unwrap();
        let mut response = [0u8; 10];
        reader.read_exact(&mut response).await.unwrap();
        assert_eq!(response, [5, 0, 0, 1, 0, 0, 0, 0, 0, 0]);
    }

    #[tokio::test]
    async fn authentication_and_udp_associate_are_parsed() {
        let server = Server::new(&ServerConfig {
            username: Some("user".into()),
            password: Some("pass".into()),
            allow_private_destinations: true,
        })
        .unwrap();
        let (mut client, mut peer) = duplex(256);
        let task = tokio::spawn(async move {
            server
                .accept(
                    &mut peer,
                    Instant::now() + std::time::Duration::from_secs(1),
                )
                .await
        });
        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut selected = [0u8; 2];
        client.read_exact(&mut selected).await.unwrap();
        assert_eq!(selected, [5, 2]);
        let mut auth = vec![1, 4];
        auth.extend_from_slice(b"user");
        auth.push(4);
        auth.extend_from_slice(b"pass");
        client.write_all(&auth).await.unwrap();
        let mut ok = [0u8; 2];
        client.read_exact(&mut ok).await.unwrap();
        assert_eq!(ok, [1, 0]);
        // UDP ASSOCIATE (3): request is parsed enough to reject with code 7.
        client
            .write_all(&[5, 3, 0, 1, 127, 0, 0, 1, 0, 53])
            .await
            .unwrap();
        let request = task.await.unwrap().unwrap();
        assert!(matches!(request, Request::UdpAssociate));
    }

    #[tokio::test]
    async fn wrong_password_is_rejected() {
        let server = Server::new(&ServerConfig {
            username: Some("user".into()),
            password: Some("pass".into()),
            allow_private_destinations: false,
        })
        .unwrap();
        let (mut client, mut peer) = duplex(256);
        let task = tokio::spawn(async move {
            server
                .accept(
                    &mut peer,
                    Instant::now() + std::time::Duration::from_secs(1),
                )
                .await
        });
        client.write_all(&[5, 1, 2]).await.unwrap();
        let mut selected = [0u8; 2];
        client.read_exact(&mut selected).await.unwrap();
        assert_eq!(selected, [5, 2]);
        let mut auth = vec![1, 4];
        auth.extend_from_slice(b"user");
        auth.push(4);
        auth.extend_from_slice(b"bad!");
        client.write_all(&auth).await.unwrap();
        let mut reply_bytes = [0u8; 2];
        client.read_exact(&mut reply_bytes).await.unwrap();
        assert_eq!(reply_bytes, [1, 1]);
        assert!(task.await.unwrap().is_err());
    }
}
