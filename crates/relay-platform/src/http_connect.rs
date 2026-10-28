//! HTTP CONNECT proxy inbound (RFC 9110 §9.3.6). TCP only; optional Basic
//! authentication; the request authority selects the destination.
use crate::shadowsocks::Destination;
use anyhow::{Context, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::time::{Instant, timeout_at};

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
            for (value, what) in [
                (username, "HTTP CONNECT username"),
                (password, "HTTP CONNECT password"),
            ] {
                if value.is_empty() || value.len() > 255 || value.chars().any(char::is_control) {
                    bail!("{what} must contain 1..255 bytes without control characters");
                }
            }
        }
        _ => bail!("HTTP CONNECT username and password must be configured together"),
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
    /// Reads a complete CONNECT request. Authentication and malformed requests
    /// receive a final HTTP error here; a valid request returns the authority
    /// and the caller must connect before sending [`ok`].
    pub async fn accept<S>(&self, stream: &mut S, deadline: Instant) -> Result<Destination>
    where
        S: AsyncRead + AsyncWrite + Unpin,
    {
        let mut request = Vec::with_capacity(1024);
        let mut byte = [0u8; 1];
        loop {
            timeout_at(deadline, stream.read_exact(&mut byte))
                .await
                .context("HTTP CONNECT request timed out")??;
            request.push(byte[0]);
            if request.len() > 16 * 1024 {
                break;
            }
            if request.ends_with(b"\r\n\r\n") {
                break;
            }
        }
        ensure!(
            request.ends_with(b"\r\n\r\n"),
            "HTTP CONNECT request is too large"
        );
        let text = std::str::from_utf8(&request).context("HTTP CONNECT request is not UTF-8")?;
        let mut lines = text.split("\r\n");
        let line = lines.next().unwrap_or_default();
        let mut parts = line.split_whitespace();
        let method = parts.next().unwrap_or_default();
        let authority = parts.next().unwrap_or_default();
        let version = parts.next().unwrap_or_default();
        if method != "CONNECT" || !version.starts_with("HTTP/1.") {
            let _ = reply(stream, 405, "Method Not Allowed").await;
            bail!("unsupported HTTP proxy method");
        }
        let headers: Vec<(&str, &str)> = lines
            .filter_map(|line| line.split_once(':'))
            .map(|(name, value)| (name.trim(), value.trim()))
            .collect();
        if self.config.username.is_some() {
            let authorized = headers
                .iter()
                .find(|(name, _)| name.eq_ignore_ascii_case("proxy-authorization"))
                .and_then(|(_, value)| value.strip_prefix("Basic "))
                .and_then(|encoded| STANDARD.decode(encoded).ok())
                .and_then(|decoded| String::from_utf8(decoded).ok())
                .is_some_and(|credentials| {
                    let expected = format!(
                        "{}:{}",
                        self.config.username.as_deref().unwrap_or_default(),
                        self.config.password.as_deref().unwrap_or_default()
                    );
                    credentials == expected
                });
            if !authorized {
                let _ = write_all(
                    stream,
                    b"HTTP/1.1 407 Proxy Authentication Required\r\nProxy-Authenticate: Basic realm=\"relay\"\r\nContent-Length: 0\r\n\r\n",
                )
                .await;
                bail!("HTTP CONNECT authentication failed");
            }
        }
        parse_authority(authority)
    }
}
pub(crate) fn parse_authority(authority: &str) -> Result<Destination> {
    ensure!(
        !authority.contains(char::is_whitespace),
        "invalid HTTP CONNECT authority"
    );
    let (host, port) = if let Some(rest) = authority.strip_prefix('[') {
        let (host, port) = rest.rsplit_once("]:").context("invalid IPv6 authority")?;
        (host, port)
    } else {
        authority
            .rsplit_once(':')
            .context("missing HTTP CONNECT port")?
    };
    let port: u16 = port.parse().context("invalid HTTP CONNECT port")?;
    ensure!(
        port != 0 && !host.is_empty(),
        "invalid HTTP CONNECT endpoint"
    );
    if let Ok(ip) = host.parse::<Ipv4Addr>() {
        return Ok(Destination::Ip(SocketAddr::new(ip.into(), port)));
    }
    if let Ok(ip) = host.parse::<Ipv6Addr>() {
        return Ok(Destination::Ip(SocketAddr::new(ip.into(), port)));
    }
    ensure!(!host.contains(':'), "invalid HTTP CONNECT host");
    Ok(Destination::Domain(host.into(), port))
}
async fn write_all<S>(stream: &mut S, bytes: &[u8]) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    stream.write_all(bytes).await?;
    stream.flush().await?;
    Ok(())
}
pub async fn reply<S>(stream: &mut S, status: u16, reason: &str) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    write_all(
        stream,
        format!("HTTP/1.1 {status} {reason}\r\nContent-Length: 0\r\n\r\n").as_bytes(),
    )
    .await
}
pub async fn ok<S>(stream: &mut S) -> Result<()>
where
    S: AsyncWrite + Unpin,
{
    reply(stream, 200, "Connection Established").await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::duplex;

    #[tokio::test]
    async fn connect_authority_and_domain_are_parsed() {
        let server = Server::new(&ServerConfig {
            username: None,
            password: None,
            allow_private_destinations: true,
        })
        .unwrap();
        let (mut client, mut peer) = duplex(1024);
        let task = tokio::spawn(async move {
            server
                .accept(
                    &mut peer,
                    Instant::now() + std::time::Duration::from_secs(1),
                )
                .await
        });
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n")
            .await
            .unwrap();
        assert_eq!(task.await.unwrap().unwrap().to_string(), "example.com:443");
    }

    #[tokio::test]
    async fn success_reply_is_well_formed() {
        let (mut writer, mut reader) = duplex(64);
        ok(&mut writer).await.unwrap();
        let mut response = [0u8; 39];
        reader.read_exact(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 200"));
    }

    #[tokio::test]
    async fn basic_authentication_and_bad_method_are_rejected() {
        let server = Server::new(&ServerConfig {
            username: Some("user".into()),
            password: Some("pass".into()),
            allow_private_destinations: false,
        })
        .unwrap();
        let (mut client, mut peer) = duplex(1024);
        let task = tokio::spawn(async move {
            server
                .accept(
                    &mut peer,
                    Instant::now() + std::time::Duration::from_secs(1),
                )
                .await
        });
        client
            .write_all(b"CONNECT example.com:443 HTTP/1.1\r\n\r\n")
            .await
            .unwrap();
        let mut response = [0u8; 12];
        client.read_exact(&mut response).await.unwrap();
        assert!(response.starts_with(b"HTTP/1.1 407"));
        assert!(task.await.unwrap().is_err());

        let encoded = STANDARD.encode("user:pass");
        let (mut client, mut peer) = duplex(1024);
        let server = Server::new(&ServerConfig {
            username: Some("user".into()),
            password: Some("pass".into()),
            allow_private_destinations: false,
        })
        .unwrap();
        let task = tokio::spawn(async move {
            server
                .accept(
                    &mut peer,
                    Instant::now() + std::time::Duration::from_secs(1),
                )
                .await
        });
        client
            .write_all(
                format!(
                    "CONNECT 127.0.0.1:80 HTTP/1.1\r\nProxy-Authorization: Basic {encoded}\r\n\r\n"
                )
                .as_bytes(),
            )
            .await
            .unwrap();
        let destination = task.await.unwrap().unwrap();
        assert_eq!(destination.to_string(), "127.0.0.1:80");
    }
}
