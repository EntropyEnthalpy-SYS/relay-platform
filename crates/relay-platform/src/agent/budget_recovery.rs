use super::*;
use crate::budget::{BudgetRecoveryRequest, BudgetRecoveryStats, BudgetReply};
use std::collections::HashSet;

pub(super) async fn recover(
    client: &Client,
    base: &Url,
    credential: &SharedCredential,
    store: &Store,
    lease: &lease_client::AgentLease,
) -> Result<BudgetRecoveryStats> {
    let proof = lease
        .proof
        .as_ref()
        .context("budget recovery lacks execution lease")?;
    let db = store.clone();
    let run = proof.run_id.clone();
    let batches = tokio::task::spawn_blocking(move || db.budget_recovery_batches(&run)).await??;
    let ledger_id = store
        .metadata("ledger_id")?
        .context("budget recovery lacks reconciled ledger")?;
    let mut stats = BudgetRecoveryStats {
        run_id: proof.run_id.clone(),
        ..Default::default()
    };
    for batch in batches {
        let input = BudgetRecoveryRequest {
            lease: proof.clone(),
            ledger_id: ledger_id.clone(),
            run_id: proof.run_id.clone(),
            claims: batch.claims,
            requests: batch.requests,
        };
        let reply = loop {
            lease.ensure_live()?;
            let attempt = async {
                let response = credential
                    .send(
                        client
                            .post(base.join("api/v1/agent/budgets/recover")?)
                            .json(&input),
                    )
                    .await?;
                let status = response.status();
                if status.is_server_error() || status == reqwest::StatusCode::TOO_MANY_REQUESTS {
                    return Err(ReconcileRetry(format!(
                        "budget recovery unavailable: HTTP {status}"
                    ))
                    .into());
                }
                ensure!(
                    status.is_success(),
                    "controller rejected budget recovery with HTTP {status}; listeners remain stopped"
                );
                bounded_json::<BudgetReply>(response).await
            };
            match attempt.await {
                Ok(reply) => break reply,
                Err(error)
                    if error.is::<ReconcileRetry>()
                        || error.downcast_ref::<reqwest::Error>().is_some() =>
                {
                    tracing::warn!(%error,"budget recovery pending before listener activation");
                    tokio::time::sleep(Duration::from_millis(500)).await;
                }
                Err(error) => return Err(error),
            }
        };
        lease.ensure_live()?;
        ensure!(
            !reply.allocation_paused,
            "controller allocation state is isolated"
        );
        let expected: HashSet<_> = input
            .claims
            .iter()
            .map(|c| c.grant.grant_id.as_str())
            .collect();
        let actual: HashSet<_> = reply
            .acknowledgements
            .iter()
            .map(|a| a.grant_id.as_str())
            .collect();
        ensure!(
            expected == actual && actual.len() == reply.acknowledgements.len(),
            "budget recovery omitted or duplicated a claim acknowledgement"
        );
        for ack in &reply.acknowledgements {
            let claim = input
                .claims
                .iter()
                .find(|c| c.grant.grant_id == ack.grant_id)
                .unwrap();
            ensure!(
                ack.consumed_bytes == claim.consumed_bytes && ack.surrender == claim.sealed,
                "budget recovery acknowledgement changed a retained boundary"
            );
        }
        let expected: HashSet<_> = input
            .requests
            .iter()
            .map(|r| r.request_id.as_str())
            .collect();
        let actual: HashSet<_> = reply
            .grants
            .iter()
            .map(|g| g.request_id.as_str())
            .chain(reply.cancelled_requests.iter().map(String::as_str))
            .collect();
        ensure!(
            expected == actual
                && actual.len() == reply.grants.len() + reply.cancelled_requests.len(),
            "budget recovery omitted or duplicated a pending request"
        );
        stats.validated_grants += input.claims.len() as u64;
        stats.recovered_pending_grants += reply.grants.len() as u64;
        stats.cancelled_requests += reply.cancelled_requests.len() as u64;
        let db = store.clone();
        let run = proof.run_id.clone();
        tokio::task::spawn_blocking(move || db.accept_budget_reply(&run, reply)).await??;
    }
    stats.open_grants = store.budget_open_grants_in_run(&proof.run_id)?;
    stats.at_ms = now_ms();
    store.set_metadata(
        "agent_budget_last_recovery",
        &serde_json::to_string(&stats)?,
    )?;
    tracing::info!(
        grants = stats.validated_grants,
        recovered_requests = stats.recovered_pending_grants,
        "durable budget run verified before listener activation"
    );
    Ok(stats)
}
