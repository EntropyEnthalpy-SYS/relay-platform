//! SMTP notifications with mandatory encryption except an explicit local relay.
use anyhow::{Context, Result, ensure};
use lettre::{
    AsyncSmtpTransport, AsyncTransport, Message, Tokio1Executor,
    message::{Mailbox, header::ContentType},
    transport::smtp::{
        authentication::Credentials,
        client::{Certificate, Tls, TlsParameters},
    },
};
use serde::{Deserialize, Serialize};
use std::{net::IpAddr, time::Duration};

#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Security {
    #[default]
    Starttls,
    ImplicitTls,
    LocalRelay,
}
#[derive(Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Config {
    pub host: String,
    pub port: u16,
    #[serde(default)]
    pub security: Security,
    pub from: String,
    pub to: Vec<String>,
    #[serde(default)]
    pub username: String,
    #[serde(default)]
    pub password: String,
    #[serde(default)]
    pub ca_pem: String,
}
impl std::fmt::Debug for Config {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SmtpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("security", &self.security)
            .field("password", &"[REDACTED]")
            .finish_non_exhaustive()
    }
}
impl Config {
    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.host.is_empty()
                && self.host.len() <= 253
                && self
                    .host
                    .bytes()
                    .all(|b| b.is_ascii_alphanumeric() || b".-:".contains(&b)),
            "invalid SMTP host"
        );
        ensure!(self.port != 0, "SMTP port cannot be zero");
        ensure!(
            !self.to.is_empty() && self.to.len() <= 20,
            "SMTP requires 1..20 recipients"
        );
        for address in std::iter::once(&self.from).chain(&self.to) {
            ensure!(
                address.len() <= 320 && !address.chars().any(char::is_control),
                "invalid email address"
            );
            address
                .parse::<Mailbox>()
                .context("invalid email address")?;
        }
        ensure!(
            self.username.is_empty() == self.password.is_empty(),
            "SMTP username and password must be supplied together"
        );
        ensure!(
            self.username.len() <= 256 && self.password.len() <= 1024,
            "SMTP credentials exceed their limits"
        );
        ensure!(
            self.ca_pem.len() <= 16384,
            "SMTP CA certificate exceeds 16 KiB"
        );
        if !self.ca_pem.is_empty() {
            Certificate::from_pem(self.ca_pem.as_bytes()).context("invalid SMTP CA certificate")?;
        }
        if self.security == Security::LocalRelay {
            ensure!(
                self.host.parse::<IpAddr>().is_ok_and(|ip| ip.is_loopback()),
                "unencrypted SMTP requires a literal loopback IP"
            );
            ensure!(
                self.username.is_empty() && self.password.is_empty() && self.ca_pem.is_empty(),
                "local SMTP relay does not accept credentials or TLS settings"
            );
        }
        Ok(())
    }
    pub fn public(&self) -> Self {
        Self {
            password: String::new(),
            ..self.clone()
        }
    }
}

pub async fn send(config: &Config, subject: &str, text: &str) -> Result<()> {
    config.validate()?;
    ensure!(text.len() <= 128 * 1024, "email exceeds 128 KiB");
    ensure!(
        subject.len() <= 256 && !subject.chars().any(char::is_control),
        "invalid email subject"
    );
    let mut message = Message::builder()
        .from(config.from.parse()?)
        .subject(subject)
        .header(ContentType::TEXT_PLAIN);
    for address in &config.to {
        message = message.to(address.parse()?);
    }
    let message = message.body(text.to_owned())?;
    let tls = if config.security == Security::LocalRelay {
        Tls::None
    } else {
        let mut parameters = TlsParameters::builder(config.host.clone());
        if !config.ca_pem.is_empty() {
            parameters =
                parameters.add_root_certificate(Certificate::from_pem(config.ca_pem.as_bytes())?);
        }
        let parameters = parameters.build()?;
        match config.security {
            Security::ImplicitTls => Tls::Wrapper(parameters),
            _ => Tls::Required(parameters),
        }
    };
    let mut transport = AsyncSmtpTransport::<Tokio1Executor>::builder_dangerous(&config.host)
        .port(config.port)
        .tls(tls)
        .timeout(Some(Duration::from_secs(10)));
    if !config.username.is_empty() {
        transport = transport.credentials(Credentials::new(
            config.username.clone(),
            config.password.clone(),
        ));
    }
    let mailer = transport.build();
    // A whole-delivery limit also bounds slow peers that dribble SMTP replies.
    tokio::time::timeout(Duration::from_secs(20), mailer.send(message)).await
        .context("SMTP delivery deadline exceeded")?
        .map_err(|_| anyhow::anyhow!("SMTP delivery failed: check connection, TLS, authentication and recipient acceptance"))?;
    Ok(())
}
