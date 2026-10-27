//! Minimal UPnP IGD WANIPConnection/WANPPPConnection AddPortMapping client.
//! Discovery is intentionally out of scope; the caller supplies the IGD
//! description URL. This is a mapping management tool, not a NAT server.
use anyhow::{Context, Result, bail, ensure};
use reqwest::Url;
use serde::Serialize;
use std::time::Duration;

#[derive(Clone, Debug, Serialize)]
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
    Ok(Service {
        kind: format!("urn:schemas-upnp-org:service:{kind}:1"),
        control_url,
    })
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
