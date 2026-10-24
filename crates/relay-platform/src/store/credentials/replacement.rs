use super::*;
use crate::credential::{
    QuotaHold, ReplaceCredential, ReplacementStatus, RevocationReceipt, RevokeCredential,
};

pub(super) fn retired_enrollment_key(hash: &str) -> String {
    format!("retired_node_enrollment:{hash}")
}
fn meter_key(node: &str, rule: &str, epoch: &str) -> String {
    format!("revoked_meter:{node}:{rule}:{epoch}")
}
fn operation_key(node: &str, id: &str) -> String {
    format!("node_identity_operation:{node}:{id}")
}
fn valid_operation(id: &str, revision: u64) -> Result<()> {
    if !identifier(id) || revision >= i64::MAX as u64 {
        return reject(400, "invalid identity operation or revision");
    }
    Ok(())
}
fn operation_digest(actor: &Actor, kind: &str, input: &impl Serialize) -> Result<String> {
    Ok(token_hash(&serde_json::to_string(&(
        actor.id.as_str(),
        kind,
        input,
    ))?))
}
fn repeated(conn: &Connection, node: &str, id: &str, digest: &str) -> Result<bool> {
    let prior: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            [operation_key(node, id)],
            |row| row.get(0),
        )
        .optional()?;
    match prior {
        Some(prior) if prior == digest => Ok(true),
        Some(_) => reject(
            409,
            "identity operation ID was already used with different parameters or actor",
        ),
        None => Ok(false),
    }
}
fn remember(tx: &Transaction<'_>, node: &str, id: &str, digest: &str) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2)",
        params![operation_key(node, id), digest],
    )?;
    Ok(())
}
fn retire_enrollment(tx: &Transaction<'_>, node: &str) -> Result<()> {
    tx.execute("INSERT OR IGNORE INTO metadata(key,value) SELECT 'retired_node_enrollment:'||enrollment_hash,id FROM nodes WHERE id=?1 AND enrollment_hash IS NOT NULL", [node])?;
    Ok(())
}
pub(in crate::store) fn require_meter_period(
    conn: &Connection,
    node: &str,
    rule: &Rule,
) -> Result<()> {
    if !rule.enabled || rule.quota_bytes.is_none() {
        return Ok(());
    }
    let held: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM metadata WHERE key=?1)",
        [meter_key(node, &rule.id, &rule.meter_epoch)],
        |row| row.get(0),
    )?;
    if held {
        return reject(
            409,
            "quota period was fenced by identity revocation; explicitly select a new meter period before enabling it",
        );
    }
    Ok(())
}
pub(in crate::store) fn blocked_quotas(conn: &Connection, node: &str) -> Result<Vec<QuotaHold>> {
    // Ordinary nodes pay one indexed metadata lookup, not a config parse per poll.
    if read(conn, node)?.revocation.is_none() {
        return Ok(vec![]);
    }
    let config: String = conn.query_row("SELECT c.config_json FROM config_history c JOIN nodes n ON n.id=c.node_id AND n.desired_revision=c.revision WHERE n.id=?1", [node], |row|row.get(0))?;
    let config: NodeConfig = serde_json::from_str(&config)?;
    let mut held = vec![];
    for rule in config.rules {
        match require_meter_period(conn, node, &rule) {
            Err(error)
                if error
                    .downcast_ref::<Rejection>()
                    .is_some_and(|e| e.status == 409) =>
            {
                held.push(QuotaHold {
                    rule_id: rule.id,
                    meter_epoch: rule.meter_epoch,
                })
            }
            Err(error) => return Err(error),
            Ok(()) => {}
        }
    }
    Ok(held)
}
pub(in crate::store) fn enrollment_ready(
    tx: &Transaction<'_>,
    node: &str,
    now: i64,
    identity_revision_supported: bool,
) -> Result<()> {
    let state = read(tx, node)?;
    match state.phase {
        CredentialPhase::NotEnrolled => Ok(()),
        CredentialPhase::ReplacementPending => {
            if !identity_revision_supported {
                return reject(
                    426,
                    "replacement enrollment requires an Agent that supports credential revisions",
                );
            }
            let replacement = state
                .replacement
                .context("replacement state is missing its ticket")?;
            if now >= replacement.expires_at_ms {
                return reject(
                    410,
                    "replacement enrollment ticket expired; issue a fresh ticket",
                );
            }
            Ok(())
        }
        _ => reject(409, "node identity is not accepting enrollment"),
    }?;
    retire_enrollment(tx, node)
}
pub(in crate::store) fn finish_enrollment(
    tx: &Transaction<'_>,
    node: &str,
    now: i64,
) -> Result<u64> {
    let mut state = read(tx, node)?;
    if state.phase == CredentialPhase::ReplacementPending {
        state
            .replacement
            .as_mut()
            .context("missing replacement ticket")?
            .enrolled_at_ms = Some(now);
    }
    state.phase = CredentialPhase::Active;
    state.revision = state.revision.max(1);
    write(tx, node, &state)?;
    Ok(state.revision)
}

impl Store {
    pub fn revoke_node_credential(
        &self,
        actor: &Actor,
        node: &str,
        input: RevokeCredential,
    ) -> Result<CredentialStatus> {
        valid_operation(&input.operation_id, input.expected_revision)?;
        if input.reason.trim().is_empty()
            || input.reason.len() > 512
            || input.reason.chars().any(char::is_control)
        {
            return reject(
                400,
                "revocation requires a nonempty reason of at most 512 bytes",
            );
        }
        let digest = operation_digest(actor, "revoke", &input)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        require_node(&tx, actor, node, true)?;
        let mut state = read(&tx, node)?;
        if repeated(&tx, node, &input.operation_id, &digest)? {
            state.blocked_quota_periods = blocked_quotas(&tx, node)?;
            return Ok(state);
        }
        if state.revision != input.expected_revision {
            return reject(409, "credential revision changed; reload before revoking");
        }
        let mut clocks = self.3.lock().unwrap();
        let strict = leases::status(&tx, &mut clocks, node)?.policy.is_some();
        let fence = leases::invalidate(&tx, &mut clocks, node)?;
        tx.execute("INSERT OR IGNORE INTO metadata(key,value) SELECT 'retired_node_credential:'||token_hash,id FROM nodes WHERE id=?1 AND token_hash IS NOT NULL",[node])?;
        retire_enrollment(&tx, node)?;
        tx.execute("UPDATE nodes SET token_hash=NULL,enrollment_hash=NULL,applied_revision=0,apply_error='node identity revoked; awaiting replacement' WHERE id=?1",[node])?;
        // Never manufacture metered usage or free old grants. All pre-revocation
        // periods are fenced against future quota reuse, including historical ones.
        tx.execute("INSERT OR IGNORE INTO metadata(key,value) SELECT 'revoked_meter:'||b.node_id||':'||e.rule_id||':'||e.meter_epoch,?2 FROM rule_epochs e JOIN rule_bindings b ON b.rule_id=e.rule_id WHERE b.node_id=?1",params![node,input.operation_id])?;
        state.revision += 1;
        state.phase = CredentialPhase::Revoked;
        state.pending = None;
        state.replacement = None;
        state.revocation = Some(RevocationReceipt {
            id: input.operation_id.clone(),
            revision: state.revision,
            at_ms: clocks.policy_now_ms(),
            actor_id: actor.id.clone(),
            reason: input.reason,
            strict_execution: strict,
        });
        write(&tx, node, &state)?;
        remember(&tx, node, &input.operation_id, &digest)?;
        audit(
            &tx,
            &actor.id,
            "node.identity.revoke",
            node,
            &serde_json::to_string(&state.revocation)?,
        )?;
        state.blocked_quota_periods = blocked_quotas(&tx, node)?;
        tx.commit()?;
        fence.install(&mut clocks);
        Ok(state)
    }
    pub fn replace_node_credential(
        &self,
        actor: &Actor,
        node: &str,
        input: ReplaceCredential,
    ) -> Result<CredentialStatus> {
        valid_operation(&input.operation_id, input.expected_revision)?;
        if input.enrollment_token.len() != 64
            || !input
                .enrollment_token
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
            || !(1..=86400).contains(&input.valid_for_seconds)
        {
            return reject(
                400,
                "replacement requires a fresh 256-bit enrollment token and 1..86400 seconds validity",
            );
        }
        let digest = operation_digest(actor, "replace", &input)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        require_node(&tx, actor, node, true)?;
        let mut state = read(&tx, node)?;
        if repeated(&tx, node, &input.operation_id, &digest)? {
            state.blocked_quota_periods = blocked_quotas(&tx, node)?;
            return Ok(state);
        }
        if state.revision != input.expected_revision
            || !matches!(
                state.phase,
                CredentialPhase::Revoked | CredentialPhase::ReplacementPending
            )
        {
            return reject(
                409,
                "revoke the identity first and use its current revision",
            );
        }
        let hash = token_hash(&input.enrollment_token);
        require_fresh(&tx, &hash)?;
        let fence =
            leases::replacement_policy(&tx, node, input.lease_policy, input.offline_stop_attested)?;
        retire_enrollment(&tx, node)?;
        tx.execute(
            "UPDATE nodes SET enrollment_hash=?1 WHERE id=?2 AND token_hash IS NULL",
            params![hash, node],
        )?;
        let mut clocks = self.3.lock().unwrap();
        let now = clocks.policy_now_ms();
        state.revision += 1;
        state.phase = CredentialPhase::ReplacementPending;
        let offline_stop_attested = input.offline_stop_attested
            || state
                .replacement
                .as_ref()
                .is_some_and(|r| r.offline_stop_attested);
        state.replacement = Some(ReplacementStatus {
            id: input.operation_id.clone(),
            revision: state.revision,
            issued_at_ms: now,
            expires_at_ms: now + input.valid_for_seconds as i64 * 1000,
            enrolled_at_ms: None,
            offline_stop_attested,
        });
        write(&tx, node, &state)?;
        remember(&tx, node, &input.operation_id, &digest)?;
        audit(
            &tx,
            &actor.id,
            "node.identity.replacement",
            node,
            &serde_json::to_string(&state.replacement)?,
        )?;
        state.blocked_quota_periods = blocked_quotas(&tx, node)?;
        tx.commit()?;
        if let Some(fence) = fence {
            fence.install(&mut clocks);
        }
        Ok(state)
    }
}

#[cfg(test)]
#[path = "replacement_tests.rs"]
mod tests;
