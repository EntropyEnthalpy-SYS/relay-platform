use super::*;
use crate::credential::{
    CredentialPhase, CredentialStatus, RotateCredential, RotationReceipt, RotationRequest,
};

mod replacement;
pub(super) use replacement::{
    blocked_quotas, enrollment_ready, finish_enrollment, require_meter_period,
};

fn key(node: &str) -> String {
    format!("node_credential:{node}")
}
fn retired_key(hash: &str) -> String {
    format!("retired_node_credential:{hash}")
}
pub(super) fn read(conn: &Connection, node: &str) -> Result<CredentialStatus> {
    let saved: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            [key(node)],
            |row| row.get(0),
        )
        .optional()?;
    if let Some(saved) = saved {
        return Ok(serde_json::from_str(&saved)?);
    }
    let enrolled: bool = conn.query_row(
        "SELECT token_hash IS NOT NULL FROM nodes WHERE id=?1",
        [node],
        |row| row.get(0),
    )?;
    Ok(CredentialStatus {
        phase: if enrolled {
            CredentialPhase::Active
        } else {
            CredentialPhase::NotEnrolled
        },
        revision: u64::from(enrolled),
        ..Default::default()
    })
}
fn write(tx: &Transaction<'_>, node: &str, value: &CredentialStatus) -> Result<()> {
    tx.execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key(node), serde_json::to_string(value)?])?;
    Ok(())
}
pub(super) fn require_fresh(conn: &Connection, hash: &str) -> Result<()> {
    let used: bool = conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM metadata WHERE key IN (?1,?3)) OR EXISTS(SELECT 1 FROM nodes WHERE token_hash=?2 OR enrollment_hash=?2)",
        params![retired_key(hash), hash, replacement::retired_enrollment_key(hash)], |row| row.get(0),
    )?;
    if used {
        return reject(
            409,
            "node credential was already used; generate a new secret",
        );
    }
    Ok(())
}
impl Store {
    pub fn node_credential_status(&self, actor: &Actor, node: &str) -> Result<CredentialStatus> {
        let conn = self.0.lock().unwrap();
        require_node(&conn, actor, node, false)?;
        let mut state = read(&conn, node)?;
        state.blocked_quota_periods = blocked_quotas(&conn, node)?;
        Ok(state)
    }
    pub fn request_credential_rotation(
        &self,
        actor: &Actor,
        node: &str,
        expected_revision: u64,
    ) -> Result<CredentialStatus> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        require_node(&tx, actor, node, true)?;
        let mut state = read(&tx, node)?;
        if state.revision == 0 || state.phase != CredentialPhase::Active {
            return reject(409, "enroll the node before rotating its credential");
        }
        if state.revision != expected_revision || state.pending.is_some() {
            return reject(
                409,
                "credential revision changed or rotation is already pending",
            );
        }
        if state.revision >= i64::MAX as u64 {
            return reject(409, "credential revision exhausted");
        }
        state.pending = Some(RotationRequest {
            id: Uuid::new_v4().to_string(),
            expected_revision,
            requested_at_ms: now_ms(),
            requested_by: actor.id.clone(),
        });
        write(&tx, node, &state)?;
        audit(
            &tx,
            &actor.id,
            "node.credential.request",
            node,
            &serde_json::to_string(&state)?,
        )?;
        tx.commit()?;
        Ok(state)
    }
    pub fn rotate_node_credential(
        &self,
        credential: &str,
        input: RotateCredential,
    ) -> Result<RotationReceipt> {
        if !identifier(&input.request_id)
            || input.expected_revision == 0
            || input.expected_revision >= i64::MAX as u64
            || input.credential.len() != 64
            || !input.credential.bytes().all(|b| b.is_ascii_hexdigit())
        {
            return reject(400, "invalid node credential rotation");
        }
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let node = leases::authenticated(&tx, credential)?;
        let mut state = read(&tx, &node)?;
        let next_hash = token_hash(&input.credential);
        // A lost reply can only be recovered using the currently accepted new
        // credential and the exact completed request. Retired secrets never auth.
        if let Some(receipt) = &state.last_rotation
            && receipt.id == input.request_id
            && receipt.revision == input.expected_revision + 1
            && state.revision == receipt.revision
            && token_hash(credential) == next_hash
        {
            return Ok(receipt.clone());
        }
        if state.revision != input.expected_revision
            || state.pending.as_ref().is_none_or(|p| {
                p.id != input.request_id || p.expected_revision != input.expected_revision
            })
        {
            return reject(409, "rotation request is stale or was not authorized");
        }
        leases::validate(
            &tx,
            &mut self.3.lock().unwrap(),
            &node,
            input.lease.as_ref(),
            None,
        )?;
        require_fresh(&tx, &next_hash)?;
        let old_hash = token_hash(credential);
        tx.execute(
            "INSERT INTO metadata(key,value) VALUES(?1,?2)",
            params![retired_key(&old_hash), node],
        )?;
        tx.execute(
            "UPDATE nodes SET token_hash=?1 WHERE id=?2",
            params![next_hash, node],
        )?;
        let receipt = RotationReceipt {
            id: input.request_id,
            revision: state.revision + 1,
            completed_at_ms: now_ms(),
        };
        state.revision = receipt.revision;
        state.pending = None;
        state.last_rotation = Some(receipt.clone());
        write(&tx, &node, &state)?;
        audit(
            &tx,
            &node,
            "node.credential.rotate",
            &node,
            &serde_json::to_string(&receipt)?,
        )?;
        tx.commit()?;
        Ok(receipt)
    }
}

#[cfg(test)]
#[path = "credentials_tests.rs"]
mod tests;
