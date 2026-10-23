use crate::{
    api::{Enrollment, EnrollmentResponse},
    engine::Engine,
    model::*,
    store::{Store, secret},
};
use anyhow::{Context, Result, bail, ensure};
use reqwest::{Client, Url};
use serde::{Deserialize, Serialize, de::DeserializeOwned};
use std::{path::PathBuf, sync::Arc, time::Duration};
use tokio_util::sync::CancellationToken;

pub struct AgentOptions {
    pub controller: String,
    pub node_id: String,
    pub enrollment_token_file: Option<PathBuf>,
    pub ca_certificate: Option<PathBuf>,
    pub poll_interval: Duration,
}
#[derive(Serialize, Deserialize)]
struct Credential {
    controller: String,
    node_id: String,
    token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_enrollment_token: Option<String>,
}

pub fn controller_url(input: &str) -> Result<Url> {
    let mut url = Url::parse(input)?;
    ensure!(
        url.username().is_empty()
            && url.password().is_none()
            && url.query().is_none()
            && url.fragment().is_none()
            && url.path() == "/",
        "controller URL must be an origin without credentials, path, query or fragment"
    );
    let local = url.host_str().is_some_and(|host| {
        host == "localhost"
            || host
                .trim_matches(['[', ']'])
                .parse::<std::net::IpAddr>()
                .is_ok_and(|ip| ip.is_loopback())
    });
    ensure!(
        url.scheme() == "https" || (url.scheme() == "http" && local),
        "remote controller requires HTTPS; plain HTTP is only allowed on loopback"
    );
    url.set_path("/");
    Ok(url)
}

async fn bounded_json<T: DeserializeOwned>(mut response: reqwest::Response) -> Result<T> {
    let mut bytes = Vec::new();
    while let Some(chunk) = response.chunk().await? {
        ensure!(
            bytes.len() + chunk.len() <= 4 * 1024 * 1024,
            "controller response too large"
        );
        bytes.extend_from_slice(&chunk);
    }
    serde_json::from_slice(&bytes).context("invalid controller JSON")
}

pub async fn run(store: Store, options: AgentOptions, stop: CancellationToken) -> Result<()> {
    store.set_kind("agent")?;
    let base = controller_url(&options.controller)?;
    let mut builder = Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(5))
        .timeout(Duration::from_secs(15));
    if let Some(path) = options.ca_certificate {
        builder = builder.add_root_certificate(reqwest::Certificate::from_pem(
            &tokio::fs::read(path).await?,
        )?);
    }
    let client = builder.build()?;
    let mut credential: Credential = if let Some(saved) = store.metadata("agent_credential")? {
        let credential: Credential = serde_json::from_str(&saved)?;
        ensure!(
            credential.controller == base.as_str() && credential.node_id == options.node_id,
            "stored identity belongs to another controller or node"
        );
        credential
    } else {
        let path = options
            .enrollment_token_file
            .context("first start requires --enrollment-token-file")?;
        let token = tokio::fs::read_to_string(path).await?;
        let token = token.trim();
        ensure!(token.len() == 64, "invalid enrollment token length");
        let credential = Credential {
            controller: base.to_string(),
            node_id: options.node_id,
            token: secret(),
            pending_enrollment_token: Some(token.into()),
        };
        // Persist the proposed secret before sending a single-use enrollment request.
        store.set_metadata("agent_credential", &serde_json::to_string(&credential)?)?;
        credential
    };
    if let Some(token) = &credential.pending_enrollment_token {
        let response = client
            .post(base.join("api/v1/agent/enroll")?)
            .json(&Enrollment {
                node_id: credential.node_id.clone(),
                enrollment_token: token.into(),
                credential: credential.token.clone(),
            })
            .send()
            .await?;
        ensure!(
            response.status().is_success(),
            "node enrollment failed with HTTP {}",
            response.status()
        );
        let enrolled: EnrollmentResponse = bounded_json(response).await?;
        ensure!(enrolled.enrolled, "controller did not confirm enrollment");
        credential.pending_enrollment_token = None;
        store.set_metadata("agent_credential", &serde_json::to_string(&credential)?)?;
    }
    let engine = Arc::new(Engine::new(store.clone()));
    let mut active = false;
    let mut apply_error = None;
    let mut connection_failed = false;
    let result: Result<()> = async {
        loop {
            let db = store.clone();
            let usage = tokio::task::spawn_blocking(move || db.agent_usage(true)).await??;
            let request = SyncRequest {
                need_config: !active,
                applied_revision: engine.revision().await,
                apply_error: apply_error.clone(),
                usage,
                stats: engine.stats(),
            };
            let response = tokio::select! {
                biased;
                _ = stop.cancelled() => break,
                response = client.post(base.join("api/v1/agent/sync")?)
                    .bearer_auth(&credential.token).json(&request).send() => response,
            };
            match response {
                Ok(response) if (response.status().is_client_error()
                    && response.status() != reqwest::StatusCode::TOO_MANY_REQUESTS)
                    || response.status().is_redirection() => {
                    bail!("controller rejected agent with HTTP {}; forwarding stopped to protect identity and ledger consistency", response.status());
                }
                Ok(response) if response.status().is_success() => {
                    match bounded_json::<SyncResponse>(response).await {
                        Ok(synced) => {
                            let db = store.clone();
                            tokio::task::spawn_blocking(move || db.acknowledge(&synced.acknowledgements)).await??;
                            if let Some(config) = synced.config {
                                ensure!(config.node_id == credential.node_id, "controller sent a different node identity");
                                if let Some(cached) = store.agent_config()? {
                                    ensure!(config.revision >= cached.revision, "controller is behind the local durable configuration; reconcile restored state");
                                }
                                match engine.apply(config).await {
                                    Ok(()) => { active = true; apply_error = None; }
                                    Err(error) => {
                                        let message = error.to_string();
                                        tracing::warn!(%message, "configuration rejected; retaining previous revision");
                                        apply_error = Some(message.chars().take(2048).collect());
                                    }
                                }
                            }
                            if connection_failed { tracing::info!("controller connection recovered"); }
                            connection_failed = false;
                        }
                        Err(error) => {
                            if !connection_failed {
                                tracing::warn!(%error, "incomplete or invalid controller response; retaining local configuration");
                            }
                            connection_failed = true;
                        }
                    }
                }
                response => {
                    if !connection_failed {
                        match response {
                            Ok(response) => tracing::warn!(status=%response.status(), "controller unavailable; retaining local configuration"),
                            Err(error) => tracing::warn!(%error, "controller unavailable; retaining local configuration"),
                        }
                    }
                    connection_failed = true;
                }
            }
            if !active && let Some(cached) = store.agent_config()? {
                ensure!(cached.node_id == credential.node_id, "cached configuration belongs to another node");
                engine.apply(cached).await.context("cannot restore last successful configuration")?;
                active = true;
                tracing::info!("restored last successful local configuration");
            }
            tokio::select! {
                biased;
                _ = stop.cancelled() => break,
                _ = tokio::time::sleep(options.poll_interval) => {},
            }
        }
        Ok(())
    }.await;
    engine.shutdown().await?;
    result
}
