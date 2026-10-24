use super::*;
use crate::lease::{LeasePolicy, LeaseProof, LeaseRelease, LeaseReply, LeaseRequest, LeaseStatus};
use std::{collections::HashMap, time::Instant};

#[derive(Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct Holder {
    run_id: String,
    token_hash: String,
}
#[derive(Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
struct State {
    policy: Option<LeasePolicy>,
    generation: u64,
    holder: Option<Holder>,
}
struct Deadline {
    generation: u64,
    holder_hash: Option<String>,
    expires: Instant,
    recovery_until: Instant,
}
pub(super) struct LeaseClocks {
    started: Instant,
    nodes: HashMap<String, Deadline>,
}
impl Default for LeaseClocks {
    fn default() -> Self {
        Self {
            started: Instant::now(),
            nodes: HashMap::new(),
        }
    }
}
fn key(node: &str) -> String {
    format!("node_lease:{node}")
}
fn read(conn: &Connection, node: &str) -> Result<State> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            [key(node)],
            |r| r.get(0),
        )
        .optional()?;
    let state: State = value
        .map(|value| serde_json::from_str(&value).map_err(Into::into))
        .unwrap_or_else(|| Ok::<_, anyhow::Error>(State::default()))?;
    if let Some(policy) = &state.policy {
        policy.validate()?;
    }
    ensure!(
        state.generation <= i64::MAX as u64,
        "invalid stored lease generation"
    );
    if let Some(holder) = &state.holder {
        ensure!(
            state.policy.is_some()
                && state.generation > 0
                && identifier(&holder.run_id)
                && secret_valid(&holder.token_hash),
            "invalid stored lease holder"
        );
    }
    Ok(state)
}
fn write(tx: &Transaction<'_>, node: &str, state: &State) -> Result<()> {
    tx.execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![key(node),serde_json::to_string(state)?])?;
    Ok(())
}
fn owner_hash(state: &State) -> Option<String> {
    state.holder.as_ref().map(|h| h.token_hash.clone())
}
fn deadline<'a>(clocks: &'a mut LeaseClocks, node: &str, state: &State) -> &'a mut Deadline {
    let until = clocks.started + Duration::from_millis(state.policy.as_ref().unwrap().ttl_ms);
    let known = clocks.nodes.entry(node.into()).or_insert_with(|| Deadline {
        generation: state.generation,
        holder_hash: owner_hash(state),
        expires: until,
        recovery_until: until,
    });
    // Normal changes update the cache only after commit. An unexpected persisted
    // owner change must never inherit another owner's usable deadline.
    if known.generation != state.generation || known.holder_hash != owner_hash(state) {
        let until = Instant::now() + Duration::from_millis(state.policy.as_ref().unwrap().ttl_ms);
        *known = Deadline {
            generation: state.generation,
            holder_hash: owner_hash(state),
            expires: until,
            recovery_until: until,
        };
    }
    known
}
fn secret_valid(token: &str) -> bool {
    token.len() == 64 && token.bytes().all(|b| b.is_ascii_hexdigit())
}
fn matches(state: &State, proof: &LeaseProof) -> bool {
    state.generation == proof.generation
        && state
            .holder
            .as_ref()
            .is_some_and(|h| h.run_id == proof.run_id && h.token_hash == token_hash(&proof.token))
}
fn authenticated(tx: &Transaction<'_>, credential: &str) -> Result<String> {
    tx.query_row(
        "SELECT id FROM nodes WHERE token_hash=?1",
        [token_hash(credential)],
        |r| r.get(0),
    )
    .optional()?
    .map(Ok)
    .unwrap_or_else(|| reject(401, "node credential invalid"))
}

pub(super) fn initialize(
    tx: &Transaction<'_>,
    node: &str,
    policy: Option<LeasePolicy>,
) -> Result<()> {
    if let Some(policy) = &policy {
        policy.validate()?;
    }
    write(
        tx,
        node,
        &State {
            policy,
            ..Default::default()
        },
    )
}
pub(super) fn created(clocks: &mut LeaseClocks, node: &str) {
    let now = Instant::now();
    clocks.nodes.insert(
        node.into(),
        Deadline {
            generation: 0,
            holder_hash: None,
            expires: now,
            recovery_until: now,
        },
    );
}
pub(super) fn validate(
    conn: &Connection,
    clocks: &mut LeaseClocks,
    node: &str,
    proof: Option<&LeaseProof>,
    budget_run: Option<&str>,
) -> Result<()> {
    let state = read(conn, node)?;
    if state.policy.is_none() {
        return Ok(());
    }
    let Some(proof) = proof else {
        return reject(423, "this node requires an execution lease");
    };
    if !identifier(&proof.run_id) || !secret_valid(&proof.token) {
        return reject(400, "invalid node lease proof");
    }
    let clock = deadline(clocks, node, &state);
    if !matches(&state, proof) || Instant::now() >= clock.expires {
        return reject(409, "node execution lease is stale or expired");
    }
    if budget_run.is_some_and(|run| run != proof.run_id) {
        return reject(409, "budget run differs from execution lease");
    }
    Ok(())
}
pub(super) fn status(
    conn: &Connection,
    clocks: &mut LeaseClocks,
    node: &str,
) -> Result<LeaseStatus> {
    let state = read(conn, node)?;
    let Some(policy) = state.policy.clone() else {
        return Ok(LeaseStatus::default());
    };
    let now = Instant::now();
    let clock = deadline(clocks, node, &state);
    let remaining = clock.expires.saturating_duration_since(now).as_millis() as u64;
    Ok(LeaseStatus {
        policy: Some(policy),
        generation: state.generation,
        active: state.holder.is_some() && remaining > 0,
        holder_run_id: state.holder.map(|h| h.run_id),
        remaining_ms: if clock.holder_hash.is_some() {
            remaining
        } else {
            0
        },
        recovery_wait_ms: clock
            .recovery_until
            .saturating_duration_since(now)
            .as_millis() as u64,
    })
}

impl Store {
    pub fn exchange_lease(&self, credential: &str, input: LeaseRequest) -> Result<LeaseReply> {
        if !identifier(&input.run_id) || !secret_valid(&input.token) {
            return reject(400, "invalid node lease request");
        }
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let node = authenticated(&tx, credential)?;
        let mut state = read(&tx, &node)?;
        let Some(policy) = state.policy.clone() else {
            return Ok(LeaseReply {
                required: false,
                generation: None,
                valid_for_ms: 0,
                ttl_ms: 0,
            });
        };
        policy.validate()?;
        let mut clocks = self.3.lock().unwrap();
        let clock = deadline(&mut clocks, &node, &state);
        let now = Instant::now();
        let same = state
            .holder
            .as_ref()
            .is_some_and(|h| h.run_id == input.run_id && h.token_hash == token_hash(&input.token));
        let live = state.holder.is_some() && now < clock.expires;
        let expires;
        if let Some(generation) = input.generation {
            if !live || !same || generation != state.generation {
                return reject(409, "cannot renew a stale node lease");
            }
            expires = now + Duration::from_millis(policy.ttl_ms);
        } else if live {
            if !same {
                return reject(423, "another process holds this node execution lease");
            }
            // Idempotent recovery of a lost reply does not renew the lease.
            expires = clock.expires;
        } else {
            if now < clock.recovery_until {
                return reject(423, "node lease recovery quarantine is still active");
            }
            state.generation = state
                .generation
                .checked_add(1)
                .filter(|n| *n <= i64::MAX as u64)
                .context("node lease generation exhausted")?;
            state.holder = Some(Holder {
                run_id: input.run_id,
                token_hash: token_hash(&input.token),
            });
            write(&tx, &node, &state)?;
            // A new owner's lease is not evidence that its listeners or
            // configuration are active. Await a report from this generation.
            tx.execute("UPDATE nodes SET applied_revision=0,last_seen_ms=NULL,apply_error=NULL,stats_json='{}' WHERE id=?1",[&node])?;
            audit(
                &tx,
                &node,
                "node.lease.acquire",
                &node,
                &serde_json::json!({"generation":state.generation}).to_string(),
            )?;
            expires = now + Duration::from_millis(policy.ttl_ms);
        }
        tx.commit()?;
        *clock = Deadline {
            generation: state.generation,
            holder_hash: owner_hash(&state),
            expires,
            recovery_until: now,
        };
        Ok(LeaseReply {
            required: true,
            generation: Some(state.generation),
            valid_for_ms: expires
                .saturating_duration_since(Instant::now())
                .as_millis() as u64,
            ttl_ms: policy.ttl_ms,
        })
    }
    pub fn release_lease(&self, credential: &str, input: LeaseRelease) -> Result<()> {
        if !input.stats.business_idle() || input.stats.active_probes != 0 {
            return reject(
                409,
                "stop business sessions and probes before releasing the node lease",
            );
        }
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let node = authenticated(&tx, credential)?;
        let mut clocks = self.3.lock().unwrap();
        let mut state = read(&tx, &node)?;
        if state.policy.is_none() {
            return reject(409, "this node does not use execution leases");
        }
        validate(&tx, &mut clocks, &node, Some(&input.proof), None)?;
        state.holder = None;
        write(&tx, &node, &state)?;
        audit(
            &tx,
            &node,
            "node.lease.release",
            &node,
            &serde_json::json!({"generation":state.generation}).to_string(),
        )?;
        tx.commit()?;
        let now = Instant::now();
        clocks.nodes.insert(
            node,
            Deadline {
                generation: state.generation,
                holder_hash: None,
                expires: now,
                recovery_until: now,
            },
        );
        Ok(())
    }
}

#[cfg(test)]
#[path = "leases_tests.rs"]
mod tests;
