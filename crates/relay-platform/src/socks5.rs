//! SOCKS5 inbound (RFC 1928/1929) with optional username/password and TCP
//! CONNECT. UDP ASSOCIATE is deliberately rejected until it has its own
//! datagram, metering and ACL path.
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
    /// Performs the greeting, optional authentication and CONNECT request.
    /// On success the caller must connect to the returned destination and then
    /// call [`reply`] with a status. On malformed/unsupported input this method
    /// sends a failure reply where the protocol still permits one.
    pub async fn accept<S>(&self, stream: &mut S, deadline: Instant) -> Result<Destination>
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
        let destination = match header[3] {
            1 => {
                let mut bytes = [0u8; 4];
                exact(stream, &mut bytes, deadline).await?;
                let port = port(stream, deadline).await?;
                Destination::Ip(SocketAddr::new(Ipv4Addr::from(bytes).into(), port))
            }
            4 => {
                let mut bytes = [0u8; 16];
                exact(stream, &mut bytes, deadline).await?;
                let port = port(stream, deadline).await?;
                Destination::Ip(SocketAddr::new(Ipv6Addr::from(bytes).into(), port))
            }
            3 => {
                let mut length = [0u8; 1];
                exact(stream, &mut length, deadline).await?;
                ensure!(length[0] > 0, "empty SOCKS5 destination name");
                let mut name = vec![0u8; usize::from(length[0])];
                exact(stream, &mut name, deadline).await?;
                let name = String::from_utf8(name).context("SOCKS5 destination is not UTF-8")?;
                let port = port(stream, deadline).await?;
                Destination::Domain(name, port)
            }
            _ => {
                let _ = reply(stream, 8).await;
                bail!("unsupported SOCKS5 address type");
            }
        };
        if header[1] != 1 {
            // UDP ASSOCIATE (3) and BIND (2) need separate data paths.
            let _ = reply(stream, 7).await;
            bail!("SOCKS5 command {} is not supported", header[1]);
        }
        Ok(destination)
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
async fn port<S>(stream: &mut S, deadline: Instant) -> Result<u16>
where
    S: AsyncRead + Unpin,
{
    let mut bytes = [0u8; 2];
    exact(stream, &mut bytes, deadline).await?;
    let port = u16::from_be_bytes(bytes);
    ensure!(port != 0, "SOCKS5 destination port is zero");
    Ok(port)
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
        let destination = task.await.unwrap().unwrap();
        assert_eq!(destination.to_string(), "example.com:443");
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
    async fn authentication_and_unsupported_udp_are_rejected() {
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
        let error = task.await.unwrap().unwrap_err();
        assert!(error.to_string().contains("not supported"), "{error}");
        let mut response = [0u8; 10];
        client.read_exact(&mut response).await.unwrap();
        assert_eq!(response[1], 7);
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
