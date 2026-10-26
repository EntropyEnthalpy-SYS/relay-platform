//! Per-user speed limits across nodes. The limit lives in `metadata`, so the
//! schema, backups and the recovery journal stay at schema v4; how it is split
//! between nodes lives only in memory (see [`crate::user_rate`]).
use super::*;
use crate::user_rate::{Allocator, SeatView};
use std::collections::HashMap;

pub const MIN_USER_RATE: u64 = 1024;
pub const MAX_USER_RATE: u64 = 1 << 40;

fn rate_key(user: &str) -> String {
    format!("user_rate:{user}")
}

/// Which active nodes carry whose rules, rebuilt when a desired configuration
/// or node profile changes, and once a minute for node expiry.
#[derive(Default)]
pub struct UserRates {
    allocator: Allocator,
    signature: Option<(u64, u64, u64, u64, i64)>,
    /// Owner id to (tenant id, node ids).
    nodes: HashMap<String, (String, Vec<String>)>,
}
impl UserRates {
    fn refresh(&mut self, tx: &Transaction<'_>) -> Result<()> {
        let now = now_ms();
        let signature = tx.query_row(
            "SELECT COUNT(*),(SELECT COALESCE(MAX(rowid),0) FROM config_history),COALESCE(SUM(applied_revision),0),(SELECT COALESCE(SUM(json_extract(value,'$.revision')),0) FROM metadata WHERE key GLOB 'node_profile:*') FROM nodes",
            [],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, now / 60_000)),
        )?;
        if self.signature == Some(signature) {
            return Ok(());
        }
        let mut q =
            tx.prepare("SELECT id,desired_revision,applied_revision FROM nodes ORDER BY id")?;
        let rows: Vec<(String, u64, u64)> = q
            .query_map([], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
            .collect::<rusqlite::Result<_>>()?;
        self.nodes.clear();
        for (node, desired, applied) in rows {
            // A paused or expired node forwards nothing, so it holds no share.
            if super::node_profiles::read(tx, &node)?
                .settings
                .lifecycle(now)
                != crate::node::NodeLifecycle::Active
            {
                continue;
            }
            // The desired revision has not necessarily been activated. Keep
            // every still-running revision too, so a rejected update cannot
            // retire a limit that the old listener is still enforcing. An
            // agent confirms removal by reporting the new applied revision.
            let mut revisions = vec![desired];
            if applied != 0 && applied != desired {
                revisions.push(applied);
            }
            for revision in revisions {
                let Some(json) = tx
                    .query_row(
                        "SELECT config_json FROM config_history WHERE node_id=?1 AND revision=?2",
                        params![node, revision],
                        |r| r.get::<_, String>(0),
                    )
                    .optional()?
                else {
                    continue;
                };
                let config: NodeConfig = serde_json::from_str(&json)?;
                // Advertised listeners are counted too. An advertised address
                // can be reached directly, and the rule cannot prove an
                // already metered upstream, so excluding it would lift the
                // owner's limit.
                for rule in config.rules.iter().filter(|r| r.enabled) {
                    let (_, nodes) = self
                        .nodes
                        .entry(rule.owner_id.clone())
                        .or_insert_with(|| (rule.tenant_id.clone(), vec![]));
                    if !nodes.contains(&node) {
                        nodes.push(node.clone());
                    }
                }
            }
        }
        self.signature = Some(signature);
        Ok(())
    }
}

/// The share of every limited user with rules on `node`, from its sync.
pub(super) fn shares(
    tx: &Transaction<'_>,
    rates: &mut UserRates,
    node: &str,
    reports: &[UserRateReport],
) -> Result<Vec<UserShare>> {
    rates.refresh(tx)?;
    let mut q =
        tx.prepare("SELECT substr(key,11),value FROM metadata WHERE key GLOB 'user_rate:*'")?;
    let limits: Vec<(String, String)> = q
        .query_map([], |r| Ok((r.get(0)?, r.get(1)?)))?
        .collect::<rusqlite::Result<_>>()?;
    let now = std::time::Instant::now();
    let mut shares = vec![];
    for (owner, total) in &limits {
        let Some((tenant, nodes)) = rates.nodes.get(owner) else {
            continue;
        };
        if !nodes.iter().any(|n| n == node) {
            continue;
        }
        let total: u64 = total.parse()?;
        let report = reports
            .iter()
            .find(|r| r.owner_id == *owner && r.tenant_id == *tenant);
        let (rate, fallback) = rates
            .allocator
            .share(owner, total, nodes, node, report, now);
        shares.push(UserShare {
            tenant_id: tenant.clone(),
            owner_id: owner.clone(),
            rate_bytes_per_sec: rate,
            fallback_bytes_per_sec: fallback,
        });
    }
    let limited: Vec<&str> = shares.iter().map(|s| s.owner_id.as_str()).collect();
    rates.allocator.retain_node(node, &limited);
    Ok(shares)
}

#[derive(Serialize)]
pub struct UserRateView {
    pub user_id: String,
    pub rate_bytes_per_sec: Option<u64>,
    pub nodes: Vec<SeatView>,
}

impl Store {
    /// Only system administrators set limits, so a tenant cannot lift its own.
    pub fn set_user_rate(&self, actor: &Actor, user_id: &str, rate: Option<u64>) -> Result<()> {
        if actor.role != Role::SystemAdmin {
            return reject(403, "system administrator required");
        }
        if rate.is_some_and(|r| !(MIN_USER_RATE..=MAX_USER_RATE).contains(&r)) {
            return reject(
                400,
                format!("user rate must be {MIN_USER_RATE}..={MAX_USER_RATE} bytes/second"),
            );
        }
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        super::accounts::require_user_manager(&tx, actor, user_id)?;
        match rate {
            Some(rate) => tx.execute("INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value", params![rate_key(user_id), rate.to_string()])?,
            None => tx.execute("DELETE FROM metadata WHERE key=?1", [rate_key(user_id)])?,
        };
        audit(
            &tx,
            &actor.id,
            "user.rate",
            user_id,
            &serde_json::json!({ "rate_bytes_per_sec": rate }).to_string(),
        )?;
        tx.commit()?;
        Ok(())
    }
    pub fn user_rate(&self, actor: &Actor, user_id: &str) -> Result<UserRateView> {
        let rate = {
            let conn = self.0.lock().unwrap();
            let tenant: Option<String> = conn
                .query_row("SELECT tenant_id FROM users WHERE id=?1", [user_id], |r| {
                    r.get(0)
                })
                .optional()?;
            if !tenant.is_some_and(|t| actor.permits_tenant(&t)) {
                return reject(404, "user not found");
            }
            conn.query_row(
                "SELECT value FROM metadata WHERE key=?1",
                [rate_key(user_id)],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .map(|v| v.parse())
            .transpose()?
        };
        let nodes = match rate {
            Some(total) => {
                let rates = self.6.lock().unwrap();
                let participants = rates.nodes.get(user_id).map_or(&[][..], |(_, n)| n);
                rates
                    .allocator
                    .view(user_id, total, participants, std::time::Instant::now())
            }
            None => vec![],
        };
        Ok(UserRateView {
            user_id: user_id.into(),
            rate_bytes_per_sec: rate,
            nodes,
        })
    }
}
