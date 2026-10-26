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
mod budget_recovery;
mod credentials;
mod lease_client;
use credentials::SharedCredential;

/// Agent metadata key of the user shares in force, restored after a restart.
const USER_SHARES: &str = "agent_user_shares";

pub struct AgentOptions {
    pub controller: String,
    pub node_id: String,
    pub enrollment_token_file: Option<PathBuf>,
    pub ca_certificate: Option<PathBuf>,
    pub tls_directory: Option<PathBuf>,
    pub poll_interval: Duration,
}
#[derive(Clone, Serialize, Deserialize)]
struct Credential {
    controller: String,
    node_id: String,
    token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_enrollment_token: Option<String>,
    #[serde(default = "credentials::initial_revision")]
    revision: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pending_rotation: Option<credentials::PendingRotation>,
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
            revision: 1,
            pending_rotation: None,
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
                identity_revision_supported: true,
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
        ensure!(
            (1..=i64::MAX as u64).contains(&enrolled.credential_revision),
            "invalid enrolled credential revision"
        );
        credential.revision = enrolled.credential_revision;
        credential.pending_enrollment_token = None;
        store.set_metadata("agent_credential", &serde_json::to_string(&credential)?)?;
    }
    let credential = SharedCredential::new(credential)?;
    let resume = store.budget_resume_candidate()?;
    let proposed_run = resume
        .as_ref()
        .map(|r| r.0.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    let Some(lease) = lease_client::AgentLease::acquire(
        &client,
        &base,
        &credential,
        &store,
        &proposed_run,
        resume.map(|r| r.1),
        &stop,
    )
    .await?
    else {
        return Ok(());
    };
    lease.ensure_live()?;
    let budget_run = lease
        .proof
        .as_ref()
        .map(|p| p.run_id.clone())
        .unwrap_or_else(|| uuid::Uuid::new_v4().to_string());
    if lease.resuming_budget {
        store.resume_budget_run(&budget_run, lease.proof.as_ref().unwrap().generation)?;
    } else {
        store.begin_budget_run_mode(&budget_run, lease.proof.as_ref().map(|p| p.generation))?;
    }
    let mut resume_pending = lease.resuming_budget;
    let mut budget_recovery = None;
    let mut sampler = crate::system::Sampler::default();
    let engine = Arc::new(Engine::with_tls_directory(
        store.clone(),
        options.tls_directory,
    ));
    let mut saved_shares = store.metadata(USER_SHARES)?.unwrap_or_default();
    if let Ok(shares) = serde_json::from_str::<Vec<UserShare>>(&saved_shares) {
        engine.restore_user_shares(&shares);
    }
    let mut active = false;
    let mut apply_error = None;
    let mut connection_failed = false;
    let mut reconciled = false;
    let mut controller_instance: Option<String> = None;
    // Long-polls the controller so a published revision wakes the sync loop
    // at once; the poll interval remains the fallback for older controllers.
    let published = tokio::sync::Notify::new();
    let watcher = async {
        let mut seen = 0;
        loop {
            let after = engine.revision().await.max(seen);
            let watched = async {
                let mut url = base.join("api/v1/agent/watch")?;
                url.query_pairs_mut()
                    .append_pair("after", &after.to_string());
                let response = credential
                    .send(client.get(url).timeout(Duration::from_secs(35)))
                    .await?;
                ensure!(response.status().is_success(), "HTTP {}", response.status());
                let body: serde_json::Value = bounded_json(response).await?;
                Ok::<_, anyhow::Error>(body["desired_revision"].as_u64().unwrap_or(0))
            };
            match watched.await {
                Ok(revision) if revision > after => {
                    seen = revision;
                    published.notify_one();
                }
                Ok(_) => {}
                Err(error) => {
                    tracing::debug!(%error, "configuration watch unavailable; polling");
                    tokio::time::sleep(options.poll_interval).await;
                }
            }
        }
    };
    let forwarding = async {
        // Report a new apply result at once instead of after the poll interval.
        let mut receipt_due = false;
        // Shares expire on time even while the controller is unreachable, and
        // an agent holding one syncs every second so shares can move.
        let user_poll = || {
            if engine.expire_user_shares() {
                options.poll_interval.min(Duration::from_secs(1))
            } else {
                options.poll_interval
            }
        };
        loop {
            lease.ensure_live()?;
            if !reconciled {
                let result = tokio::select! {
                    biased;
                    _ = stop.cancelled() => break,
                    result = reconcile(&client, &base, &credential, &store, active, lease.proof.as_ref()) => result,
                };
                match result {
                    Ok(config) => {
                        if resume_pending {
                            budget_recovery = Some(
                                budget_recovery::recover(
                                    &client,
                                    &base,
                                    &credential,
                                    &store,
                                    &lease,
                                )
                                .await?,
                            );
                            resume_pending = false;
                        }
                        reconciled = true;
                        lease.ensure_live()?;
                        match engine.apply(config).await {
                            Ok(()) => {
                                store.finish_reconcile()?;
                                active = true;
                                apply_error = None;
                                tracing::info!(
                                    "controller ledger reconciled before configuration activation"
                                );
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
                    Err(error) => {
                        return Err(
                            error.context("ledger reconciliation failed; forwarding stopped")
                        );
                    }
                }
                if !reconciled {
                    if !active
                        && !resume_pending
                        && !store.recovery_required()?
                        && let Some(cached) = store.agent_config()?
                    {
                        ensure!(
                            cached.node_id == credential.node_id,
                            "cached configuration belongs to another node"
                        );
                        lease.ensure_live()?;
                        engine
                            .apply(cached)
                            .await
                            .context("cannot restore last successful configuration")?;
                        active = true;
                        tracing::info!(
                            "ordinary offline restart restored local durable configuration"
                        );
                    }
                    tokio::select! {
                        biased;
                        _ = stop.cancelled() => break,
                        _ = tokio::time::sleep(user_poll()) => {},
                    }
                    continue;
                }
            }
            let db = store.clone();
            let run = budget_run.clone();
            let stats = engine.stats();
            let idle = stats.business_idle();
            let (usage, budget) = tokio::task::spawn_blocking(move || {
                if idle {
                    db.seal_budget_run(&run)?;
                }
                Ok::<_, anyhow::Error>((db.agent_usage(true)?, db.budget_outbox(&run, !idle)?))
            })
            .await??;
            let requested_budget = !budget.requests.is_empty();
            let mut granted_budget = false;
            let request = SyncRequest {
                lease: lease.proof.clone(),
                budget: Some(budget),
                ledger_id: store
                    .metadata("ledger_id")?
                    .context("missing reconciled ledger identity")?,
                need_config: !active,
                applied_revision: engine.revision().await,
                apply_error: apply_error.clone(),
                usage,
                stats: {
                    let mut stats = engine.stats();
                    stats.budget_recovery = budget_recovery.clone();
                    stats.system = Some(sampler.sample());
                    stats
                },
            };
            let sent = tokio::time::Instant::now();
            let response = tokio::select! {
                biased;
                _ = stop.cancelled() => break,
                response = credential.send(client.post(base.join("api/v1/agent/sync")?).json(&request)) => response,
            };
            match response {
                Ok(response)
                    if (response.status().is_client_error()
                        && response.status() != reqwest::StatusCode::TOO_MANY_REQUESTS)
                        || response.status().is_redirection() =>
                {
                    bail!(
                        "controller rejected agent with HTTP {}; forwarding stopped to protect identity and ledger consistency",
                        response.status()
                    );
                }
                Ok(response) if response.status().is_success() => {
                    match bounded_json::<SyncResponse>(response).await {
                        Ok(synced) => {
                            let rotation = synced.credential_rotation;
                            lease.ensure_live()?;
                            ensure!(
                                identifier(&synced.controller_instance),
                                "invalid controller instance identity"
                            );
                            if controller_instance
                                .as_ref()
                                .is_some_and(|previous| previous != &synced.controller_instance)
                            {
                                reconciled = false;
                            }
                            controller_instance = Some(synced.controller_instance);
                            granted_budget = synced
                                .budget
                                .as_ref()
                                .is_some_and(|reply| !reply.grants.is_empty());
                            let db = store.clone();
                            let run = budget_run.clone();
                            tokio::task::spawn_blocking(move || {
                                db.accept_sync_reply(&run, &synced.acknowledgements, synced.budget)
                            })
                            .await??;
                            if let Some(config) = synced.config {
                                ensure!(
                                    config.node_id == credential.node_id,
                                    "controller sent a different node identity"
                                );
                                if let Some(cached) = store.agent_config()? {
                                    ensure!(
                                        config.revision >= cached.revision,
                                        "controller is behind the local durable configuration; reconcile restored state"
                                    );
                                }
                                lease.ensure_live()?;
                                match engine.apply(config).await {
                                    Ok(()) => {
                                        store.finish_reconcile()?;
                                        active = true;
                                        apply_error = None;
                                        receipt_due = true;
                                    }
                                    Err(error) => {
                                        let message = error.to_string();
                                        tracing::warn!(%message, "configuration rejected; retaining previous revision");
                                        let message: String = message.chars().take(512).collect();
                                        receipt_due = apply_error.as_ref() != Some(&message);
                                        apply_error = Some(message);
                                    }
                                }
                            }
                            engine.set_user_shares(&synced.user_rates.unwrap_or_default(), sent);
                            // Saved as they would be restored, so the steady
                            // movement of shares above the fallback writes nothing.
                            let restored: Vec<UserShare> = engine
                                .user_shares()
                                .into_iter()
                                .map(|share| {
                                    let rate =
                                        share.rate_bytes_per_sec.min(share.fallback_bytes_per_sec);
                                    UserShare {
                                        rate_bytes_per_sec: rate,
                                        fallback_bytes_per_sec: rate,
                                        ..share
                                    }
                                })
                                .collect();
                            let shares = serde_json::to_string(&restored)?;
                            if shares != saved_shares {
                                store.set_metadata(USER_SHARES, &shares)?;
                                saved_shares = shares;
                            }
                            if let Err(error) = credential
                                .rotate_if_requested(
                                    &client,
                                    &base,
                                    &store,
                                    rotation,
                                    lease.proof.as_ref(),
                                )
                                .await
                            {
                                tracing::warn!(%error,"node credential rotation will retry; durable transition retained");
                            }
                            if connection_failed {
                                tracing::info!("controller connection recovered");
                            }
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
                            Ok(response) => {
                                tracing::warn!(status=%response.status(), "controller unavailable; retaining local configuration")
                            }
                            Err(error) => {
                                tracing::warn!(%error, "controller unavailable; retaining local configuration")
                            }
                        }
                    }
                    connection_failed = true;
                }
            }
            if !active
                && !resume_pending
                && !store.recovery_required()?
                && let Some(cached) = store.agent_config()?
            {
                ensure!(
                    cached.node_id == credential.node_id,
                    "cached configuration belongs to another node"
                );
                lease.ensure_live()?;
                engine
                    .apply(cached)
                    .await
                    .context("cannot restore last successful configuration")?;
                active = true;
                tracing::info!("restored last successful local configuration");
            }
            let poll_interval = user_poll();
            let interval = if store
                .agent_config()?
                .is_some_and(|c| c.rules.iter().any(|r| !r.budget_ids.is_empty()))
            {
                poll_interval.min(Duration::from_millis(500))
            } else {
                poll_interval
            };
            // Coalesce successful refills briefly. Exhaustion and outages must
            // back off instead of turning each waiting payload into an HTTP poll.
            let refill_delay = Duration::from_millis(if connection_failed {
                500
            } else if requested_budget && !granted_budget {
                100
            } else {
                2
            });
            if std::mem::take(&mut receipt_due) {
                continue;
            }
            tokio::select! {
                biased;
                _ = stop.cancelled() => break,
                _ = tokio::time::sleep(interval) => {},
                _ = published.notified() => {},
                _ = async {store.budget_refill_needed().await;tokio::time::sleep(refill_delay).await;} => {},
            }
        }
        Ok(())
    };
    let result: Result<()> = tokio::select! {biased;
        _=stop.cancelled()=>Ok(()),
        _=lease.lost.cancelled()=>Err(anyhow::anyhow!("node execution lease lost; forwarding stopped")),
        result=forwarding=>result,
        _=watcher=>unreachable!("configuration watch never returns"),
    };
    engine.shutdown().await?;
    if resume_pending {
        tracing::warn!(
            "budget recovery did not complete; retained reservations preserved without settlement or release"
        );
        return result;
    }
    store.seal_budget_run(&budget_run)?;
    let mut stopped_stats = engine.stats();
    stopped_stats.budget_recovery = budget_recovery;
    let cleanup = async {
        let mut reported_stopped = false;
        loop {
            // Recover replies lost in flight without issuing new reservations.
            // Seal each recovered grant before returning its unused balance.
            store.seal_budget_run(&budget_run)?;
            let budget = store.budget_outbox(&budget_run, false)?;
            let usage = store.agent_usage(true)?;
            if reported_stopped
                && budget.reports.is_empty()
                && budget.requests.is_empty()
                && usage.is_empty()
            {
                return Ok::<_, anyhow::Error>(());
            }
            let request = SyncRequest {
                lease: lease.proof.clone(),
                budget: Some(budget),
                ledger_id: store.metadata("ledger_id")?.context("missing ledger")?,
                need_config: false,
                applied_revision: engine.revision().await,
                apply_error: apply_error.clone(),
                usage,
                stats: stopped_stats.clone(),
            };
            let response = credential
                .send(client.post(base.join("api/v1/agent/sync")?).json(&request))
                .await?
                .error_for_status()?;
            let reply: SyncResponse = bounded_json(response).await?;
            store.accept_sync_reply(&budget_run, &reply.acknowledgements, reply.budget)?;
            reported_stopped = true;
        }
    };
    if matches!(
        tokio::time::timeout(Duration::from_secs(2), cleanup).await,
        Ok(Ok(()))
    ) {
        if !matches!(
            tokio::time::timeout(
                Duration::from_secs(2),
                lease.release(&client, &base, &credential, stopped_stats)
            )
            .await,
            Ok(Ok(()))
        ) {
            tracing::warn!("node lease release not confirmed; controller expiry remains in force");
        }
    } else {
        tracing::warn!(
            "final usage or unused reservation return is pending; durable state remains for retry"
        );
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
    credential: &SharedCredential,
    store: &Store,
    active: bool,
    lease: Option<&crate::lease::LeaseProof>,
) -> Result<NodeConfig> {
    let db = store.clone();
    tokio::task::spawn_blocking(move || db.begin_reconcile()).await??;
    let mut ledger_id = store.metadata("ledger_id")?;
    let mut after: Option<UsageCursor> = None;
    let mut revision = None;
    // Bound a faulty controller's pagination while retaining up to a million periods.
    for _ in 0..4096 {
        let response = credential
            .send(
                client
                    .post(base.join("api/v1/agent/reconcile")?)
                    .json(&ReconcileRequest {
                        lease: lease.cloned(),
                        ledger_id: ledger_id.clone(),
                        after: after.clone(),
                        expected_revision: revision,
                    }),
            )
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
