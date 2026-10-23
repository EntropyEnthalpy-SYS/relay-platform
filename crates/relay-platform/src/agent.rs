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
    pub tls_directory: Option<PathBuf>,
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
    let _instance = store.lock_instance()?;
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
    let budget_run = store.start_budget_run()?;
    let engine = Arc::new(Engine::with_tls_directory(
        store.clone(),
        options.tls_directory,
    ));
    let mut active = false;
    let mut apply_error = None;
    let mut connection_failed = false;
    let mut reconciled = false;
    let mut controller_instance: Option<String> = None;
    let result: Result<()> = async {
        loop {
            if !reconciled {
                let result = tokio::select! {
                    biased;
                    _ = stop.cancelled() => break,
                    result = reconcile(&client, &base, &credential, &store, active) => result,
                };
                match result {
                    Ok(config) => {
                        reconciled = true;
                        match engine.apply(config).await {
                            Ok(()) => {
                                store.finish_reconcile()?;
                                active = true;
                                apply_error = None;
                                tracing::info!("controller ledger reconciled before configuration activation");
                            }
                            Err(error) => {
                                tracing::warn!(%error, "reconciled configuration cannot be activated; recovery remains pending");
                                apply_error = Some(error.to_string().chars().take(512).collect());
                            }
                        }
                    }
                    Err(error) if error.is::<ReconcileRetry>() => {
                        if !connection_failed {
                            tracing::warn!(%error, "reconciliation pending; only ordinary restarts may use cached configuration");
                        }
                        connection_failed = true;
                    }
                    Err(error) => return Err(error.context("ledger reconciliation failed; forwarding stopped")),
                }
                if !reconciled {
                    if !active && !store.recovery_required()? && let Some(cached) = store.agent_config()? {
                        ensure!(cached.node_id == credential.node_id, "cached configuration belongs to another node");
                        engine.apply(cached).await.context("cannot restore last successful configuration")?;
                        active = true;
                        tracing::info!("ordinary offline restart restored local durable configuration");
                    }
                    tokio::select! {
                        biased;
                        _ = stop.cancelled() => break,
                        _ = tokio::time::sleep(options.poll_interval) => {},
                    }
                    continue;
                }
            }
            let db = store.clone();
            let run=budget_run.clone();
            let stats=engine.stats();let idle=stats.active_tcp==0&&stats.active_udp==0;
            let (usage,budget)=tokio::task::spawn_blocking(move || {
                if idle {db.seal_budget_run(&run)?;}
                Ok::<_,anyhow::Error>((db.agent_usage(true)?,db.budget_outbox(&run,!idle)?))
            }).await??;
            let requested_budget = !budget.requests.is_empty();
            let mut granted_budget = false;
            let request = SyncRequest {
                budget: Some(budget),
                ledger_id: store.metadata("ledger_id")?.context("missing reconciled ledger identity")?,
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
                            ensure!(identifier(&synced.controller_instance), "invalid controller instance identity");
                            if controller_instance.as_ref().is_some_and(|previous|previous != &synced.controller_instance) {
                                reconciled = false;
                            }
                            controller_instance = Some(synced.controller_instance);
                            granted_budget = synced.budget.as_ref().is_some_and(|reply| !reply.grants.is_empty());
                            let db = store.clone();
                            let run=budget_run.clone();
                            tokio::task::spawn_blocking(move || {db.acknowledge(&synced.acknowledgements)?;if let Some(reply)=synced.budget {db.accept_budget_reply(&run,reply)?;}Ok::<_,anyhow::Error>(())}).await??;
                            if let Some(config) = synced.config {
                                ensure!(config.node_id == credential.node_id, "controller sent a different node identity");
                                if let Some(cached) = store.agent_config()? {
                                    ensure!(config.revision >= cached.revision, "controller is behind the local durable configuration; reconcile restored state");
                                }
                                match engine.apply(config).await {
                                    Ok(()) => { store.finish_reconcile()?; active = true; apply_error = None; }
                                    Err(error) => {
                                        let message = error.to_string();
                                        tracing::warn!(%message, "configuration rejected; retaining previous revision");
                                        apply_error = Some(message.chars().take(512).collect());
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
            if !active && !store.recovery_required()? && let Some(cached) = store.agent_config()? {
                ensure!(cached.node_id == credential.node_id, "cached configuration belongs to another node");
                engine.apply(cached).await.context("cannot restore last successful configuration")?;
                active = true;
                tracing::info!("restored last successful local configuration");
            }
            let interval=if store.agent_config()?.is_some_and(|c|c.rules.iter().any(|r|!r.budget_ids.is_empty())) {options.poll_interval.min(Duration::from_millis(500))}else{options.poll_interval};
            // Coalesce successful refills briefly. Exhaustion and outages must
            // back off instead of turning each waiting payload into an HTTP poll.
            let refill_delay = Duration::from_millis(if connection_failed {500} else if requested_budget && !granted_budget {100} else {2});
            tokio::select! {
                biased;
                _ = stop.cancelled() => break,
                _ = tokio::time::sleep(interval) => {},
                _ = async {store.budget_refill_needed().await;tokio::time::sleep(refill_delay).await;} => {},
            }
        }
        Ok(())
    }.await;
    engine.shutdown().await?;
    store.seal_budget_run(&budget_run)?;
    let budget = store.budget_outbox(&budget_run, false)?;
    let usage = store.agent_usage(true)?;
    if !budget.reports.is_empty() || !usage.is_empty() {
        let cleanup = async {
            let request = SyncRequest {
                budget: Some(budget),
                ledger_id: store.metadata("ledger_id")?.context("missing ledger")?,
                need_config: false,
                applied_revision: engine.revision().await,
                apply_error: None,
                usage,
                stats: engine.stats(),
            };
            let response = client
                .post(base.join("api/v1/agent/sync")?)
                .bearer_auth(&credential.token)
                .json(&request)
                .send()
                .await?
                .error_for_status()?;
            let reply: SyncResponse = bounded_json(response).await?;
            store.acknowledge(&reply.acknowledgements)?;
            if let Some(reply) = reply.budget {
                store.accept_budget_reply(&budget_run, reply)?;
            }
            Ok::<_, anyhow::Error>(())
        };
        if !matches!(
            tokio::time::timeout(Duration::from_secs(2), cleanup).await,
            Ok(Ok(()))
        ) {
            tracing::warn!(
                "final usage or unused reservation return is pending; durable state remains for retry"
            );
        }
    }
    result
}

#[derive(Debug)]
struct ReconcileRetry(String);
impl std::fmt::Display for ReconcileRetry {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}
impl std::error::Error for ReconcileRetry {}

async fn reconcile(
    client: &Client,
    base: &Url,
    credential: &Credential,
    store: &Store,
    active: bool,
) -> Result<NodeConfig> {
    let db = store.clone();
    tokio::task::spawn_blocking(move || db.begin_reconcile()).await??;
    let mut ledger_id = store.metadata("ledger_id")?;
    let mut after: Option<UsageCursor> = None;
    let mut revision = None;
    // Bound a faulty controller's pagination while retaining up to a million periods.
    for _ in 0..4096 {
        let response = client
            .post(base.join("api/v1/agent/reconcile")?)
            .bearer_auth(&credential.token)
            .json(&ReconcileRequest {
                ledger_id: ledger_id.clone(),
                after: after.clone(),
                expected_revision: revision,
            })
            .send()
            .await
            .map_err(|error| ReconcileRetry(format!("checkpoint request failed: {error}")))?;
        let status = response.status();
        if status.is_server_error()
            || status == reqwest::StatusCode::TOO_MANY_REQUESTS
            || status == reqwest::StatusCode::PRECONDITION_FAILED
        {
            return Err(ReconcileRetry(format!(
                "checkpoint temporarily unavailable: HTTP {status}"
            ))
            .into());
        }
        ensure!(
            status.is_success(),
            "controller rejected reconciliation with HTTP {status}"
        );
        let page: ReconcileResponse = bounded_json(response)
            .await
            .map_err(|error| ReconcileRetry(format!("incomplete checkpoint response: {error}")))?;
        ensure!(
            page.node_id == credential.node_id,
            "checkpoint belongs to another node"
        );
        ensure!(
            ledger_id.as_ref().is_none_or(|id| id == &page.ledger_id),
            "checkpoint ledger identity changed"
        );
        ensure!(
            revision.is_none_or(|r| r == page.revision),
            "checkpoint configuration revision changed"
        );
        if let Some(cached) = store.agent_config()? {
            ensure!(
                page.revision >= cached.revision,
                "controller is behind the local durable configuration; explicit recovery is required"
            );
        }
        let first = page.usage.first().map(|u| UsageCursor {
            rule_id: u.rule_id.clone(),
            meter_epoch: u.meter_epoch.clone(),
        });
        ensure!(
            after
                .as_ref()
                .is_none_or(|previous| first.as_ref().is_none_or(|key| key > previous)),
            "checkpoint pagination did not advance"
        );
        if let Some(next) = &page.next {
            let last = page
                .usage
                .last()
                .context("non-final checkpoint page is empty")?;
            ensure!(
                next.rule_id == last.rule_id
                    && next.meter_epoch == last.meter_epoch
                    && page.config.is_none(),
                "invalid checkpoint continuation"
            );
        } else {
            let config = page
                .config
                .as_ref()
                .context("final checkpoint lacks configuration")?;
            ensure!(
                config.node_id == credential.node_id && config.revision == page.revision,
                "checkpoint configuration does not match its revision"
            );
        }
        if !active {
            // Once a checkpoint starts merging, an interrupted walk must not reopen
            // cached listeners before all remotely confirmed counters are known.
            store.set_metadata("recovery_required", "true")?;
        }
        let db = store.clone();
        let checkpoint = page.clone();
        tokio::task::spawn_blocking(move || db.merge_checkpoint(&checkpoint, !active)).await??;
        ledger_id = Some(page.ledger_id);
        revision = Some(page.revision);
        after = page.next;
        if after.is_none() {
            return page.config.context("final checkpoint lacks configuration");
        }
    }
    bail!("controller checkpoint exceeds the supported period limit")
}
