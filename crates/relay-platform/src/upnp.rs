//! Minimal UPnP IGD WANIPConnection/WANPPPConnection AddPortMapping client and
//! IPv4 SSDP discovery. The caller can use a discovered LOCATION as the
//! description URL. This is a mapping management tool, not a NAT server.
use anyhow::{Context, Result, bail, ensure};
use axum::{Router, extract::State, http::HeaderMap, routing::post};
use reqwest::Url;
use serde::{Deserialize, Serialize};
use std::net::{Ipv4Addr, SocketAddr};
use std::time::Duration;
use tokio::net::{TcpListener, UdpSocket};
use tokio::sync::mpsc::{UnboundedSender, unbounded_channel};
use tokio::time::{Instant, interval, sleep, timeout_at};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug, Serialize)]
pub struct Discovery {
    pub location: String,
    pub server: Option<String>,
    pub service_type: Option<String>,
    pub usn: Option<String>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Mapping {
    pub description_url: String,
    pub control_url: String,
    pub service: String,
    pub internal_client: String,
    pub internal_port: u16,
    pub external_port: u16,
    pub protocol: String,
    pub lifetime_secs: u32,
}
#[derive(Clone, Debug)]
pub struct Service {
    pub kind: String,
    pub control_url: String,
    pub event_url: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Subscription {
    pub event_url: String,
    pub sid: String,
    pub timeout_secs: u32,
}
#[derive(Clone, Debug, Serialize)]
pub struct Event {
    pub sid: String,
    pub sequence: Option<String>,
    pub body: String,
    pub properties: std::collections::BTreeMap<String, String>,
}
/// Extract the first WANIPConnection/WANPPPConnection service and its
/// control URL from an IGD description document. This deliberately avoids a
/// general XML parser: only the two known service names and controlURL tags
/// are accepted.
pub fn parse_description(xml: &str) -> Result<Service> {
    let (offset, kind) = if let Some(index) = xml.find("WANIPConnection") {
        (index, "WANIPConnection")
    } else if let Some(index) = xml.find("WANPPPConnection") {
        (index, "WANPPPConnection")
    } else {
        bail!("IGD description has no WANIPConnection/WANPPPConnection service");
    };
    let tail = &xml[offset..];
    let start = tail
        .find("<controlURL>")
        .context("IGD service has no controlURL")?
        + "<controlURL>".len();
    let end = tail[start..]
        .find("</controlURL>")
        .context("IGD controlURL is not closed")?
        + start;
    let control_url = tail[start..end].trim().to_owned();
    ensure!(!control_url.is_empty(), "IGD controlURL is empty");
    let event_url = tail
        .find("<eventSubURL>")
        .and_then(|start| {
            let start = start + "<eventSubURL>".len();
            tail[start..]
                .find("</eventSubURL>")
                .map(|end| tail[start..start + end].trim().to_owned())
        })
        .filter(|value| !value.is_empty());
    Ok(Service {
        kind: format!("urn:schemas-upnp-org:service:{kind}:1"),
        control_url,
        event_url,
    })
}
fn event_method(name: &str) -> Result<reqwest::Method> {
    reqwest::Method::from_bytes(name.as_bytes()).context("invalid UPnP event method")
}

/// Subscribe to the IGD event URL. The callback must be an absolute HTTP(S)
/// URL reachable by the gateway; this function does not run an event server.
pub async fn subscribe(
    description_url: &str,
    callback: &str,
    timeout_secs: u32,
) -> Result<Subscription> {
    ensure!(
        (1..=86_400).contains(&timeout_secs),
        "UPnP subscription timeout must be 1..86400 seconds"
    );
    let callback = Url::parse(callback).context("invalid UPnP callback URL")?;
    ensure!(
        matches!(callback.scheme(), "http" | "https"),
        "UPnP callback must be HTTP(S)"
    );
    let base = Url::parse(description_url).context("invalid IGD description URL")?;
    let event_url = event_target(description_url)
        .await?
        .ok_or_else(|| anyhow::anyhow!("IGD service has no eventSubURL"))?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let response = client
        .request(event_method("SUBSCRIBE")?, event_url.clone())
        .header("CALLBACK", format!("<{callback}>"))
        .header("NT", "upnp:event")
        .header("TIMEOUT", format!("Second-{timeout_secs}"))
        .send()
        .await
        .context("UPnP SUBSCRIBE failed")?;
    ensure!(
        response.status().is_success(),
        "UPnP SUBSCRIBE returned {}",
        response.status()
    );
    let sid = response
        .headers()
        .get("SID")
        .and_then(|value| value.to_str().ok())
        .context("UPnP SUBSCRIBE has no SID")?
        .to_owned();
    let timeout_secs = response
        .headers()
        .get("TIMEOUT")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Second-"))
        .and_then(|value| value.parse().ok())
        .unwrap_or(timeout_secs);
    let _ = base;
    Ok(Subscription {
        event_url: event_url.to_string(),
        sid,
        timeout_secs,
    })
}

pub async fn renew(event_url: &str, sid: &str, timeout_secs: u32) -> Result<u32> {
    ensure!(
        (1..=86_400).contains(&timeout_secs),
        "UPnP renewal timeout must be 1..86400 seconds"
    );
    ensure!(
        !sid.is_empty() && !sid.chars().any(char::is_control),
        "invalid UPnP SID"
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let response = client
        .request(event_method("SUBSCRIBE")?, Url::parse(event_url)?)
        .header("SID", sid)
        .header("TIMEOUT", format!("Second-{timeout_secs}"))
        .send()
        .await
        .context("UPnP subscription renewal failed")?;
    ensure!(
        response.status().is_success(),
        "UPnP renewal returned {}",
        response.status()
    );
    Ok(response
        .headers()
        .get("TIMEOUT")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Second-"))
        .and_then(|value| value.parse().ok())
        .unwrap_or(timeout_secs))
}

pub async fn unsubscribe(event_url: &str, sid: &str) -> Result<()> {
    ensure!(
        !sid.is_empty() && !sid.chars().any(char::is_control),
        "invalid UPnP SID"
    );
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()?;
    let response = client
        .request(event_method("UNSUBSCRIBE")?, Url::parse(event_url)?)
        .header("SID", sid)
        .send()
        .await
        .context("UPnP UNSUBSCRIBE failed")?;
    ensure!(
        response.status().is_success(),
        "UPnP UNSUBSCRIBE returned {}",
        response.status()
    );
    Ok(())
}

async fn event_target(description_url: &str) -> Result<Option<Url>> {
    let base = Url::parse(description_url).context("invalid IGD description URL")?;
    let xml = reqwest::get(description_url).await?;
    let xml = xml.text().await?;
    let service = parse_description(&xml)?;
    Ok(service.event_url.map(|path| base.join(&path)).transpose()?)
}

fn soap(service: &str, delete: bool, mapping: &Mapping) -> String {
    let action = if delete {
        "DeletePortMapping"
    } else {
        "AddPortMapping"
    };
    let body = if delete {
        format!(
            "<NewRemoteHost></NewRemoteHost><NewExternalPort>{}</NewExternalPort><NewProtocol>UDP</NewProtocol>",
            mapping.external_port
        )
    } else {
        format!(
            "<NewRemoteHost></NewRemoteHost><NewExternalPort>{}</NewExternalPort><NewProtocol>UDP</NewProtocol><NewInternalPort>{}</NewInternalPort><NewInternalClient>{}</NewInternalClient><NewEnabled>1</NewEnabled><NewPortMappingDescription>relay-platform</NewPortMappingDescription><NewLeaseDuration>{}</NewLeaseDuration>",
            mapping.external_port,
            mapping.internal_port,
            mapping.internal_client,
            mapping.lifetime_secs
        )
    };
    format!(
        "<?xml version=\"1.0\"?><s:Envelope xmlns:s=\"http://schemas.xmlsoap.org/soap/envelope/\" s:encodingStyle=\"http://schemas.xmlsoap.org/soap/encoding/\"><s:Body><u:{action} xmlns:u=\"{service}\">{body}</u:{action}></s:Body></s:Envelope>"
    )
}
async fn call(
    client: &reqwest::Client,
    control_url: &Url,
    service: &str,
    mapping: &Mapping,
    delete: bool,
) -> Result<()> {
    let action = if delete {
        "DeletePortMapping"
    } else {
        "AddPortMapping"
    };
    let response = client
        .post(control_url.clone())
        .header("SOAPAction", format!("\"{service}#{action}\""))
        .header("Content-Type", "text/xml; charset=utf-8")
        .body(soap(service, delete, mapping))
        .timeout(Duration::from_secs(5))
        .send()
        .await
        .context("UPnP SOAP request failed")?;
    let status = response.status();
    let body = response.text().await.context("UPnP SOAP body unreadable")?;
    if !status.is_success() {
        let code = body
            .split("<errorCode>")
            .nth(1)
            .and_then(|value| value.split("</errorCode>").next())
            .unwrap_or("unknown");
        bail!("UPnP gateway returned {status} (errorCode {code})");
    }
    ensure!(
        !body.contains("<errorCode>"),
        "UPnP gateway returned an error response"
    );
    Ok(())
}
pub async fn map(
    description_url: &str,
    internal_client: &str,
    internal_port: u16,
    external_port: u16,
    lifetime_secs: u32,
    delete: bool,
) -> Result<Mapping> {
    ensure!(internal_port != 0, "internal port is zero");
    ensure!(external_port != 0, "external port is zero");
    ensure!(
        lifetime_secs <= 604_800,
        "UPnP lifetime must be at most seven days"
    );
    let base = Url::parse(description_url).context("invalid IGD description URL")?;
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(5))
        .build()
        .context("cannot build UPnP HTTP client")?;
    let xml = client
        .get(base.clone())
        .send()
        .await
        .context("IGD description fetch failed")?
        .error_for_status()
        .context("IGD description HTTP error")?
        .text()
        .await
        .context("IGD description body unreadable")?;
    let service = parse_description(&xml)?;
    let control_url = base
        .join(&service.control_url)
        .context("invalid IGD control URL")?;
    let mapping = Mapping {
        description_url: description_url.into(),
        control_url: control_url.to_string(),
        service: service.kind,
        internal_client: internal_client.into(),
        internal_port,
        external_port,
        protocol: "UDP".into(),
        lifetime_secs: if delete { 0 } else { lifetime_secs },
    };
    call(&client, &control_url, &mapping.service, &mapping, delete).await?;
    Ok(mapping)
}

/// Send an SSDP M-SEARCH to the standard IPv4 multicast endpoint and collect
/// IGD responses until `timeout`. Duplicate LOCATION values are returned once.
pub async fn discover(timeout: Duration) -> Result<Vec<Discovery>> {
    discover_at(SocketAddr::from(([239, 255, 255, 250], 1900)), timeout).await
}

/// Discovery variant with an explicit target, useful for a controlled network
/// or tests. The target still speaks the normal SSDP request/response format.
pub async fn discover_at(target: SocketAddr, timeout: Duration) -> Result<Vec<Discovery>> {
    ensure!(!timeout.is_zero(), "discovery timeout is zero");
    ensure!(target.is_ipv4(), "SSDP discovery currently supports IPv4");
    let socket = UdpSocket::bind((Ipv4Addr::UNSPECIFIED, 0)).await?;
    let request = concat!(
        "M-SEARCH * HTTP/1.1\r\n",
        "HOST: 239.255.255.250:1900\r\n",
        "MAN: \"ssdp:discover\"\r\n",
        "MX: 2\r\n",
        "ST: urn:schemas-upnp-org:device:InternetGatewayDevice:1\r\n",
        "\r\n"
    );
    socket.send_to(request.as_bytes(), target).await?;
    let deadline = Instant::now() + timeout;
    let mut found = Vec::new();
    let mut seen = std::collections::HashSet::new();
    let mut buffer = vec![0u8; 8192];
    loop {
        let received = match timeout_at(deadline, socket.recv_from(&mut buffer)).await {
            Ok(received) => received,
            Err(_) => break,
        };
        let (size, _) = received?;
        let text = String::from_utf8_lossy(&buffer[..size]);
        if let Some(item) = parse_discovery(&text)
            && seen.insert(item.location.clone())
        {
            found.push(item);
        }
    }
    Ok(found)
}

fn parse_discovery(response: &str) -> Option<Discovery> {
    let mut location = None;
    let mut server = None;
    let mut service_type = None;
    let mut usn = None;
    for line in response.lines().skip(1) {
        let Some((key, value)) = line.split_once(':') else {
            continue;
        };
        let value = value.trim();
        match key.trim().to_ascii_lowercase().as_str() {
            "location" if !value.is_empty() => location = Some(value.to_string()),
            "server" => server = Some(value.to_string()),
            "st" => service_type = Some(value.to_string()),
            "usn" => usn = Some(value.to_string()),
            _ => {}
        }
    }
    Some(Discovery {
        location: location?,
        server,
        service_type,
        usn,
    })
}

/// Renew a UPnP IGD mapping until cancelled. The control URL is looked up on
/// every renewal so a changed description/control endpoint is picked up.
#[allow(clippy::too_many_arguments)]
pub async fn maintain<F>(
    description_url: &str,
    internal_client: &str,
    internal_port: u16,
    external_port: u16,
    lifetime_secs: u32,
    renew_after: Duration,
    retry_after: Option<Duration>,
    cancel: CancellationToken,
    mut on_mapping: F,
) -> Result<()>
where
    F: FnMut(&Mapping),
{
    ensure!(!renew_after.is_zero(), "renew interval is zero");
    ensure!(
        retry_after.is_none_or(|delay| !delay.is_zero()),
        "retry interval is zero"
    );
    ensure!(
        renew_after < Duration::from_secs(u64::from(lifetime_secs.max(1))),
        "renew interval must be shorter than the lease"
    );
    loop {
        let mapping = match map(
            description_url,
            internal_client,
            internal_port,
            external_port,
            lifetime_secs,
            false,
        )
        .await
        {
            Ok(mapping) => mapping,
            Err(error) if retry_after.is_some() => {
                tokio::select! {
                    biased;
                    _ = cancel.cancelled() => break,
                    _ = sleep(retry_after.unwrap()) => {}
                }
                let _ = error;
                continue;
            }
            Err(error) => return Err(error),
        };
        on_mapping(&mapping);
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            _ = sleep(renew_after) => {}
        }
    }
    Ok(())
}

/// Extract simple leaf property elements from a UPnP event document. This is
/// intentionally bounded and does not execute XML, resolve entities, or
/// interpret nested property sets.
pub fn parse_event_properties(body: &str) -> std::collections::BTreeMap<String, String> {
    let mut properties = std::collections::BTreeMap::new();
    let mut rest = body;
    while let Some(start) = rest.find('<') {
        rest = &rest[start..];
        if rest.starts_with("</") || rest.starts_with("<?") || rest.starts_with("<!") {
            let Some(end) = rest.find('>') else {
                break;
            };
            rest = &rest[end + 1..];
            continue;
        }
        let Some(tag_end) = rest.find('>') else {
            break;
        };
        let tag = rest[1..tag_end]
            .split_whitespace()
            .next()
            .unwrap_or_default();
        let name = tag.rsplit(':').next().unwrap_or(tag);
        let after = &rest[tag_end + 1..];
        if name.is_empty() || name == "propertyset" || name == "property" {
            rest = after;
            continue;
        }
        let close = format!("</{tag}>");
        let Some(value_end) = after.find(&close) else {
            rest = after;
            continue;
        };
        let value = after[..value_end].trim();
        if !value.is_empty() && value.len() <= 4096 && properties.len() < 64 {
            properties.insert(name.to_owned(), value.to_owned());
        }
        rest = &after[value_end + close.len()..];
    }
    properties
}

/// Run a callback HTTP server, subscribe the IGD to it, print events through
/// `on_event`, and renew the subscription at half its timeout until cancelled.
/// The callback URL must include a concrete loopback or local IP and port.
#[allow(clippy::too_many_arguments)]
pub async fn run_events<F>(
    description_url: &str,
    callback: &str,
    timeout_secs: u32,
    cancel: CancellationToken,
    mut on_event: F,
) -> Result<Subscription>
where
    F: FnMut(&Event),
{
    ensure!(
        (1..=86_400).contains(&timeout_secs),
        "UPnP event timeout must be 1..86400 seconds"
    );
    let callback_url = Url::parse(callback).context("invalid UPnP callback URL")?;
    ensure!(
        callback_url.scheme() == "http",
        "event callback must be plain HTTP"
    );
    let host = callback_url.host_str().context("callback has no host")?;
    let ip: Ipv4Addr = host
        .parse()
        .or(match host {
            "localhost" => Ok(Ipv4Addr::LOCALHOST),
            _ => Err(()),
        })
        .map_err(|_| anyhow::anyhow!("event callback host must be an IPv4 literal or localhost"))?;
    let port = callback_url.port().context("event callback has no port")?;
    let path = if callback_url.path().is_empty() {
        "/".to_owned()
    } else {
        callback_url.path().to_owned()
    };
    let listener = TcpListener::bind(SocketAddr::from((ip, port))).await?;
    let (tx, mut rx) = unbounded_channel::<Event>();
    async fn receive(
        State(tx): State<UnboundedSender<Event>>,
        headers: HeaderMap,
        body: String,
    ) -> axum::http::StatusCode {
        let sid = headers
            .get("SID")
            .and_then(|value| value.to_str().ok())
            .unwrap_or_default()
            .to_owned();
        let sequence = headers
            .get("SEQ")
            .and_then(|value| value.to_str().ok())
            .map(str::to_owned);
        let properties = parse_event_properties(&body);
        let _ = tx.send(Event {
            sid,
            sequence,
            body,
            properties,
        });
        axum::http::StatusCode::OK
    }
    let app = Router::new().route(&path, post(receive)).with_state(tx);
    let server_cancel = cancel.clone();
    let server = tokio::spawn(async move {
        let _ = axum::serve(listener, app)
            .with_graceful_shutdown(server_cancel.cancelled_owned())
            .await;
    });
    let subscription = subscribe(description_url, callback, timeout_secs).await?;
    let period = Duration::from_secs(u64::from((timeout_secs / 2).max(1)));
    let mut ticker = interval(period);
    ticker.tick().await;
    loop {
        tokio::select! {
            biased;
            _ = cancel.cancelled() => break,
            Some(event) = rx.recv() => on_event(&event),
            _ = ticker.tick() => {
                match renew(&subscription.event_url, &subscription.sid, timeout_secs).await {
                    Ok(timeout) => {
                        // Keep the subscription alive; the effective timeout is
                        // reported by the gateway but we renew on the requested
                        // cadence to avoid a one-off extension changing behavior.
                        let _ = timeout;
                    }
                    Err(error) => {
                        tracing::warn!(%error, "UPnP event renewal failed");
                        break;
                    }
                }
            }
        }
    }
    server.abort();
    let _ = unsubscribe(&subscription.event_url, &subscription.sid).await;
    Ok(subscription)
}
