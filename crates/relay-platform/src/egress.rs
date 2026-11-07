//! Egress proxies. On a rule whose clients name their destinations (SOCKS5,
//! HTTP CONNECT, HTTP/2 CONNECT and Shadowsocks inbounds), the node can
//! reach those destinations through an upstream SOCKS5 proxy (RFC 1928, with
//! RFC 1929 username/password) instead of connecting to them itself. The
//! destination still comes from the client; the upstream is only the way
//! out. Several upstream servers share one protocol and one set of
//! credentials and are tried in order. Only TCP is carried: a rule with an
//! egress proxy accepts no UDP, so no datagram leaves the node directly.
//!
//! The password is a rule secret like the Shadowsocks key and the SOCKS5
//! inbound password: it is kept in the rule, and no message here, no
//! `Debug` output and no report names it.
use crate::{
    model::{Protocol, Rule, validate_target},
    shadowsocks::Destination,
};
use anyhow::{Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::net::{IpAddr, SocketAddr};
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};

/// Most upstream servers of one egress proxy.
pub const MAX_SERVERS: usize = 8;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Kind {
    Socks5,
}

/// A rule's upstream proxy.
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub kind: Kind,
    /// `host:port`, `IPv4:port` or `[IPv6]:port`, tried in this order.
    pub servers: Vec<String>,
    /// RFC 1929 credentials of the upstream, set together or not at all.
    /// They are not the rule's inbound credentials.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub password: Option<String>,
}
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Config")
            .field("kind", &self.kind)
            .field("servers", &self.servers)
            .field("authenticated", &self.username.is_some())
            .finish_non_exhaustive()
    }
}
impl Config {
    fn credentials(&self) -> Option<(&str, &str)> {
        self.username.as_deref().zip(self.password.as_deref())
    }
}

/// Sent by agents to a controller that takes it; that it is sent tells the
/// controller this agent sends rules' destinations through egress proxies.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Report {}

/// Whether `rule` lets each client choose its destination.
pub fn dynamic_destination(rule: &Rule) -> bool {
    rule.inbound_socks5.is_some()
        || rule.inbound_http_connect.is_some()
        || rule.inbound_http2_connect.is_some()
        || rule.inbound_shadowsocks.is_some()
}

/// Checks `rule`'s egress proxy. Messages name servers but never the
/// credentials.
pub fn validate_rule(rule: &Rule) -> Result<()> {
    let Some(config) = &rule.egress_proxy else {
        return Ok(());
    };
    ensure!(
        dynamic_destination(rule),
        "an egress proxy applies only to rules whose clients choose the destination: a SOCKS5, HTTP CONNECT, HTTP/2 CONNECT or Shadowsocks inbound"
    );
    validate(config)?;
    ensure!(
        rule.protocol == Protocol::Tcp,
        "an egress proxy carries TCP only; set the rule's protocol to TCP (UDP is never sent around the egress proxy)"
    );
    ensure!(
        rule.inbound_shadowsocks
            .as_ref()
            .is_none_or(|s| !s.udp_over_tcp),
        "an egress proxy carries TCP only; turn off Shadowsocks UDP over TCP"
    );
    Ok(())
}

/// Checks the proxy on its own: 1..=8 distinct servers, and credentials of
/// 1..255 bytes each, both or neither, without control characters.
pub fn validate(config: &Config) -> Result<()> {
    ensure!(
        (1..=MAX_SERVERS).contains(&config.servers.len()),
        "an egress proxy needs 1..{MAX_SERVERS} servers"
    );
    for (index, server) in config.servers.iter().enumerate() {
        if validate_target(server).is_err() {
            if server.len() <= 300 && !server.chars().any(char::is_control) {
                bail!("egress proxy server {server:?} is not host:port, IPv4:port or [IPv6]:port");
            }
            bail!("egress proxy server {} is not host:port", index + 1);
        }
        ensure!(
            !config.servers[..index]
                .iter()
                .any(|other| other.eq_ignore_ascii_case(server)),
            "egress proxy server {server} is listed twice"
        );
    }
    match (&config.username, &config.password) {
        (None, None) => {}
        (Some(username), Some(password)) => {
            for (value, what) in [(username, "username"), (password, "password")] {
                ensure!(
                    !value.is_empty() && value.len() <= 255 && !value.chars().any(char::is_control),
                    "the egress proxy {what} must contain 1..255 bytes without control characters"
                );
            }
        }
        _ => bail!("the egress proxy username and password must be set together"),
    }
    Ok(())
}

/// The upstream refused for a reason the next server would share: wrong
/// credentials, no common authentication method, not a SOCKS5 server, or
/// an error reply about the destination. Other failures (cannot connect,
/// connection closed) move on to the next server.
#[derive(Debug)]
pub struct Refusal(pub String);
impl std::fmt::Display for Refusal {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for Refusal {}

fn refusal(message: String) -> anyhow::Error {
    Refusal(message).into()
}

/// Method selection and, when the upstream asks for it, username/password
/// authentication. With credentials both "no authentication" and
/// username/password are offered, without them only the first.
pub async fn greet<S>(stream: &mut S, config: &Config, server: &str) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let credentials = config.credentials();
    let offer: &[u8] = if credentials.is_some() {
        &[5, 2, 0, 2]
    } else {
        &[5, 1, 0]
    };
    stream.write_all(offer).await?;
    let mut choice = [0u8; 2];
    stream.read_exact(&mut choice).await?;
    if choice[0] != 5 {
        return Err(refusal(format!(
            "egress proxy {server} is not a SOCKS5 server"
        )));
    }
    match (choice[1], credentials) {
        (0, _) => Ok(()),
        (2, Some((username, password))) => {
            let mut request = Vec::with_capacity(3 + username.len() + password.len());
            request.extend([1, username.len() as u8]);
            request.extend_from_slice(username.as_bytes());
            request.push(password.len() as u8);
            request.extend_from_slice(password.as_bytes());
            stream.write_all(&request).await?;
            let mut status = [0u8; 2];
            stream.read_exact(&mut status).await?;
            if status[1] != 0 {
                return Err(refusal(format!(
                    "egress proxy {server} rejected the username and password"
                )));
            }
            Ok(())
        }
        (2 | 0xff, None) => Err(refusal(format!(
            "egress proxy {server} requires a username and password"
        ))),
        (0xff, Some(_)) => Err(refusal(format!(
            "egress proxy {server} accepts neither username/password nor no authentication"
        ))),
        (method, _) => Err(refusal(format!(
            "egress proxy {server} chose unsupported authentication method {method}"
        ))),
    }
}

/// Asks the upstream to connect to `destination`: a name is sent as a name
/// (ATYP 3), so the upstream resolves it. Reads the whole reply.
pub async fn connect<S>(stream: &mut S, server: &str, destination: &Destination) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Unpin,
{
    let mut request = vec![5, 1, 0];
    match destination {
        Destination::Ip(address) => encode_ip(&mut request, *address),
        Destination::Domain(name, port) => {
            let Ok(length) = u8::try_from(name.len()) else {
                bail!("destination name {name:.64} is longer than SOCKS5 allows");
            };
            ensure!(length > 0, "empty destination name");
            request.extend([3, length]);
            request.extend_from_slice(name.as_bytes());
            request.extend(port.to_be_bytes());
        }
    }
    stream.write_all(&request).await?;
    let mut head = [0u8; 4];
    stream.read_exact(&mut head).await?;
    if head[0] != 5 || head[2] != 0 {
        return Err(refusal(format!(
            "egress proxy {server} sent a malformed SOCKS5 reply"
        )));
    }
    if head[1] != 0 {
        return Err(refusal(format!(
            "egress proxy {server} could not connect to {destination}: {} (SOCKS5 reply {})",
            reply_meaning(head[1]),
            head[1]
        )));
    }
    let length = match head[3] {
        1 => 4,
        4 => 16,
        3 => {
            let mut length = [0u8; 1];
            stream.read_exact(&mut length).await?;
            usize::from(length[0])
        }
        _ => {
            return Err(refusal(format!(
                "egress proxy {server} sent a malformed SOCKS5 reply"
            )));
        }
    };
    let mut bound = vec![0u8; length + 2];
    stream.read_exact(&mut bound).await?;
    Ok(())
}

fn encode_ip(request: &mut Vec<u8>, address: SocketAddr) {
    match crate::model::canonical_ip(address.ip()) {
        IpAddr::V4(ip) => {
            request.push(1);
            request.extend_from_slice(&ip.octets());
        }
        IpAddr::V6(ip) => {
            request.push(4);
            request.extend_from_slice(&ip.octets());
        }
    }
    request.extend(address.port().to_be_bytes());
}

fn reply_meaning(code: u8) -> &'static str {
    match code {
        1 => "general SOCKS server failure",
        2 => "connection not allowed by its rules",
        3 => "network unreachable",
        4 => "host unreachable",
        5 => "connection refused",
        6 => "TTL expired",
        7 => "command not supported",
        8 => "address type not supported",
        _ => "unassigned error",
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::socks5::{Request, Server, ServerConfig};
    use tokio::time::{Duration, Instant};

    fn proxy(servers: &[&str]) -> Config {
        Config {
            kind: Kind::Socks5,
            servers: servers.iter().map(|s| (*s).to_owned()).collect(),
            username: Some("relay".into()),
            password: Some("upstream-secret".into()),
        }
    }

    #[test]
    fn servers_and_credentials_are_checked() {
        let good = proxy(&[
            "proxy.example.com:1080",
            "203.0.113.7:1080",
            "[2001:db8::1]:1080",
        ]);
        validate(&good).unwrap();
        let mut anonymous = good.clone();
        (anonymous.username, anonymous.password) = (None, None);
        validate(&anonymous).unwrap();
        let eight: Vec<String> = (0..8).map(|i| format!("p{i}.example.com:1080")).collect();
        validate(&Config {
            servers: eight.clone(),
            ..good.clone()
        })
        .unwrap();
        let cases: Vec<(Config, &str)> = vec![
            (
                Config {
                    servers: vec![],
                    ..good.clone()
                },
                "an egress proxy needs 1..8 servers",
            ),
            (
                Config {
                    servers: [eight, vec!["p8.example.com:1080".into()]].concat(),
                    ..good.clone()
                },
                "an egress proxy needs 1..8 servers",
            ),
            (
                proxy(&["2001:db8::1:1080"]),
                "egress proxy server \"2001:db8::1:1080\" is not host:port, IPv4:port or [IPv6]:port",
            ),
            (
                proxy(&["proxy.example.com"]),
                "egress proxy server \"proxy.example.com\" is not host:port, IPv4:port or [IPv6]:port",
            ),
            (
                proxy(&["proxy.example.com:0"]),
                "egress proxy server \"proxy.example.com:0\" is not host:port, IPv4:port or [IPv6]:port",
            ),
            (
                proxy(&["user@proxy.example.com:1080"]),
                "egress proxy server \"user@proxy.example.com:1080\" is not host:port, IPv4:port or [IPv6]:port",
            ),
            (
                proxy(&["a.example.com:1080", "A.example.com:1080"]),
                "egress proxy server A.example.com:1080 is listed twice",
            ),
            (
                Config {
                    password: None,
                    ..good.clone()
                },
                "the egress proxy username and password must be set together",
            ),
            (
                Config {
                    username: Some(String::new()),
                    ..good.clone()
                },
                "the egress proxy username must contain 1..255 bytes without control characters",
            ),
            (
                Config {
                    password: Some("x".repeat(256)),
                    ..good.clone()
                },
                "the egress proxy password must contain 1..255 bytes without control characters",
            ),
            (
                Config {
                    password: Some("line\nbreak".into()),
                    ..good.clone()
                },
                "the egress proxy password must contain 1..255 bytes without control characters",
            ),
        ];
        for (config, expected) in cases {
            let error = validate(&config).unwrap_err().to_string();
            assert_eq!(error, expected);
            assert!(!error.contains("upstream-secret"));
        }
        // 255 bytes of a multi-byte character fit; one more byte does not.
        validate(&Config {
            password: Some("é".repeat(127) + "x"),
            ..good.clone()
        })
        .unwrap();
        assert!(
            validate(&Config {
                password: Some("é".repeat(128)),
                ..good
            })
            .is_err()
        );
    }

    #[test]
    fn the_field_reads_and_writes_like_other_optional_rule_fields() {
        let text = r#"{"kind":"socks5","servers":["127.0.0.1:1080"]}"#;
        let config: Config = serde_json::from_str(text).unwrap();
        assert_eq!(serde_json::to_string(&config).unwrap(), text);
        assert!(
            serde_json::from_str::<Config>(
                r#"{"kind":"socks5","servers":["127.0.0.1:1080"],"extra":1}"#
            )
            .is_err()
        );
        assert!(
            serde_json::from_str::<Config>(r#"{"kind":"hysteria2","servers":["127.0.0.1:1080"]}"#)
                .is_err()
        );
        let shown = format!("{:?}", proxy(&["127.0.0.1:1080"]));
        assert!(
            !shown.contains("upstream-secret") && !shown.contains("relay\""),
            "{shown}"
        );
    }

    /// Relay's own SOCKS5 inbound as the upstream: what it was asked for
    /// and what the client heard.
    async fn exchange(
        upstream: ServerConfig,
        client: Config,
        destination: Destination,
    ) -> (Result<Request>, Result<()>) {
        let (mut near, mut far) = tokio::io::duplex(4096);
        let server = Server::new(&upstream).unwrap();
        let deadline = Instant::now() + Duration::from_secs(5);
        let serve = async {
            let request = server.accept(&mut far, deadline).await;
            if request.is_ok() {
                crate::socks5::reply(&mut far, 0).await.unwrap();
            }
            drop(far);
            request
        };
        let dial = async {
            greet(&mut near, &client, "upstream:1080").await?;
            connect(&mut near, "upstream:1080", &destination).await
        };
        tokio::join!(serve, dial)
    }

    #[tokio::test]
    async fn names_reach_the_upstream_as_names_after_authentication() {
        let upstream = ServerConfig {
            username: Some("relay".into()),
            password: Some("upstream-secret".into()),
            allow_private_destinations: false,
        };
        let name = Destination::Domain("www.example.com".into(), 443);
        let (asked, dialed) = exchange(upstream.clone(), proxy(&["u:1"]), name.clone()).await;
        dialed.unwrap();
        assert_eq!(asked.unwrap(), Request::Connect(name.clone()));
        let ip = Destination::Ip("[2001:db8::7]:8443".parse().unwrap());
        let (asked, dialed) = exchange(upstream.clone(), proxy(&["u:1"]), ip.clone()).await;
        dialed.unwrap();
        assert_eq!(asked.unwrap(), Request::Connect(ip));

        // A wrong password is refused by name, without the password.
        let mut wrong = proxy(&["u:1"]);
        wrong.password = Some("not-the-secret".into());
        let (asked, dialed) = exchange(upstream.clone(), wrong, name.clone()).await;
        assert!(asked.is_err());
        let error = dialed.unwrap_err();
        assert!(error.is::<Refusal>());
        assert_eq!(
            error.to_string(),
            "egress proxy upstream:1080 rejected the username and password"
        );
        // So is a missing one.
        let mut anonymous = proxy(&["u:1"]);
        (anonymous.username, anonymous.password) = (None, None);
        let (_, dialed) = exchange(upstream, anonymous.clone(), name.clone()).await;
        assert_eq!(
            dialed.unwrap_err().to_string(),
            "egress proxy upstream:1080 requires a username and password"
        );
        // Credentials are offered but not needed by an open upstream.
        let open = ServerConfig {
            username: None,
            password: None,
            allow_private_destinations: false,
        };
        let (asked, dialed) = exchange(open, proxy(&["u:1"]), name.clone()).await;
        dialed.unwrap();
        assert_eq!(asked.unwrap(), Request::Connect(name));
    }

    #[tokio::test]
    async fn error_replies_and_other_servers_are_refusals() {
        let (mut near, mut far) = tokio::io::duplex(1024);
        let upstream = async {
            let mut buffer = [0u8; 64];
            far.read_exact(&mut buffer[..3]).await.unwrap();
            far.write_all(&[5, 0]).await.unwrap();
            let read = far.read(&mut buffer).await.unwrap();
            assert_eq!(&buffer[..read], &[5, 1, 0, 1, 192, 0, 2, 1, 0, 80]);
            far.write_all(&[5, 4, 0, 1, 0, 0, 0, 0, 0, 0])
                .await
                .unwrap();
        };
        let mut anonymous = proxy(&["u:1"]);
        (anonymous.username, anonymous.password) = (None, None);
        let dial = async {
            greet(&mut near, &anonymous, "u:1").await?;
            connect(
                &mut near,
                "u:1",
                &Destination::Ip("192.0.2.1:80".parse().unwrap()),
            )
            .await
        };
        let ((), dialed) = tokio::join!(upstream, dial);
        let error = dialed.unwrap_err();
        assert!(error.is::<Refusal>());
        assert_eq!(
            error.to_string(),
            "egress proxy u:1 could not connect to 192.0.2.1:80: host unreachable (SOCKS5 reply 4)"
        );

        // An HTTP server is not a SOCKS5 server.
        let (mut near, mut far) = tokio::io::duplex(1024);
        let http = async {
            let mut buffer = [0u8; 4];
            far.read_exact(&mut buffer).await.unwrap();
            far.write_all(b"HTTP/1.1 400 Bad Request\r\n\r\n")
                .await
                .unwrap();
        };
        let client = proxy(&["u:1"]);
        let ((), greeted) = tokio::join!(http, greet(&mut near, &client, "u:1"));
        assert!(greeted.unwrap_err().is::<Refusal>());

        // A connection closed during the greeting is not a refusal: the next
        // server is tried.
        let (mut near, far) = tokio::io::duplex(1024);
        drop(far);
        let error = greet(&mut near, &proxy(&["u:1"]), "u:1").await.unwrap_err();
        assert!(!error.is::<Refusal>());
    }
}
