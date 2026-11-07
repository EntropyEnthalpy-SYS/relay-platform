//! Per-user speed limits across nodes: combined, upload and download. The
//! limits live in `metadata` (`user_rate:`, `user_rate_upload:` and
//! `user_rate_download:` with the user id), so the schema, backups and the
//! recovery journal stay at schema v4; how each is split between nodes lives
//! only in memory (see [`crate::user_rate`]).
use super::*;
use crate::user_rate::{Allocator, SeatView};
use std::collections::{BTreeMap, HashMap};

pub const MIN_USER_RATE: u64 = 1024;
pub const MAX_USER_RATE: u64 = 1 << 40;

pub(super) fn rate_key(user: &str) -> String {
    format!("user_rate:{user}")
}
pub(super) fn upload_key(user: &str) -> String {
    format!("user_rate_upload:{user}")
}
pub(super) fn download_key(user: &str) -> String {
    format!("user_rate_download:{user}")
}
const DIRECTIONS: [RateDirection; 3] = [
    RateDirection::Combined,
    RateDirection::Upload,
    RateDirection::Download,
];
fn key(direction: RateDirection, user: &str) -> String {
    match direction {
        RateDirection::Combined => rate_key(user),
        RateDirection::Upload => upload_key(user),
        RateDirection::Download => download_key(user),
    }
}
/// Every user's combined, upload and download limits.
fn all_limits(conn: &Connection) -> Result<BTreeMap<String, [Option<u64>; 3]>> {
    let mut limits = BTreeMap::<String, [Option<u64>; 3]>::new();
    for (index, prefix) in ["user_rate:", "user_rate_upload:", "user_rate_download:"]
        .into_iter()
        .enumerate()
    {
        let mut q = conn.prepare("SELECT substr(key,?1),value FROM metadata WHERE key GLOB ?2")?;
        let rows: Vec<(String, String)> = q
            .query_map(params![prefix.len() + 1, format!("{prefix}*")], |r| {
                Ok((r.get(0)?, r.get(1)?))
            })?
            .collect::<rusqlite::Result<_>>()?;
        for (user, value) in rows {
            limits.entry(user).or_default()[index] = Some(value.parse()?);
        }
    }
    Ok(limits)
}
fn user_limits(conn: &Connection, user: &str) -> Result<[Option<u64>; 3]> {
    let mut limits = [None; 3];
    for (slot, direction) in limits.iter_mut().zip(DIRECTIONS) {
        *slot = conn
            .query_row(
                "SELECT value FROM metadata WHERE key=?1",
                [key(direction, user)],
                |r| r.get::<_, String>(0),
            )
            .optional()?
            .map(|v| v.parse())
            .transpose()?;
    }
    Ok(limits)
}
/// Sets or clears one of `user`'s limits.
pub(super) fn write_limit(
    tx: &Transaction<'_>,
    direction: RateDirection,
    user: &str,
    rate: Option<u64>,
) -> Result<()> {
    match rate {
        Some(rate) => tx.execute(
            "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key(direction, user), rate.to_string()],
        )?,
        None => tx.execute("DELETE FROM metadata WHERE key=?1", [key(direction, user)])?,
    };
    Ok(())
}
pub(super) fn valid(rate: Option<u64>) -> bool {
    rate.is_none_or(|r| (MIN_USER_RATE..=MAX_USER_RATE).contains(&r))
}

/// Which active nodes carry whose rules, rebuilt when a desired configuration
/// or node profile changes, and once a minute for node expiry.
#[derive(Default)]
pub struct UserRates {
    /// Combined, upload and download.
    allocators: [Allocator; 3],
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
/// Upload and download shares go only to a node whose agent enforces them
/// (`directional`); an older agent rejects them.
pub(super) fn shares(
    tx: &Transaction<'_>,
    rates: &mut UserRates,
    node: &str,
    reports: &[UserRateReport],
    directional: bool,
) -> Result<Vec<UserShare>> {
    rates.refresh(tx)?;
    let limits = all_limits(tx)?;
    let now = std::time::Instant::now();
    let mut shares = vec![];
    let mut limited: [Vec<&str>; 3] = Default::default();
    for (owner, totals) in &limits {
        let Some((tenant, nodes)) = rates.nodes.get(owner) else {
            continue;
        };
        if !nodes.iter().any(|n| n == node) {
            continue;
        }
        let report = reports
            .iter()
            .find(|r| r.owner_id == *owner && r.tenant_id == *tenant);
        let mut share = UserShare {
            tenant_id: tenant.clone(),
            owner_id: owner.clone(),
            ..Default::default()
        };
        for (index, direction) in DIRECTIONS.into_iter().enumerate() {
            let Some(total) = totals[index] else {
                continue;
            };
            if direction != RateDirection::Combined && !directional {
                continue;
            }
            let lane = report.and_then(|r| r.lane(direction));
            let (rate, fallback) =
                rates.allocators[index].share(owner, total, nodes, node, lane.as_ref(), now);
            share.set_part(
                direction,
                Some(SharePart {
                    rate_bytes_per_sec: rate,
                    fallback_bytes_per_sec: fallback,
                }),
            );
            limited[index].push(owner.as_str());
        }
        if DIRECTIONS.iter().any(|d| share.part(*d).is_some()) {
            shares.push(share);
        }
    }
    for (allocator, limited) in rates.allocators.iter_mut().zip(&limited) {
        allocator.retain_node(node, limited);
    }
    Ok(shares)
}

#[derive(Serialize)]
pub struct UserRateView {
    pub user_id: String,
    pub rate_bytes_per_sec: Option<u64>,
    pub nodes: Vec<SeatView>,
    pub upload_bytes_per_sec: Option<u64>,
    pub upload_nodes: Vec<SeatView>,
    pub download_bytes_per_sec: Option<u64>,
    pub download_nodes: Vec<SeatView>,
}

/// A change of a user's limits: the combined limit is replaced (`None`
/// clears it, as before); upload and download are kept when `None`,
/// cleared by `Some(None)`.
#[derive(Clone, Copy, Debug, Default)]
pub struct UserRateChange {
    pub rate_bytes_per_sec: Option<u64>,
    pub upload_bytes_per_sec: Option<Option<u64>>,
    pub download_bytes_per_sec: Option<Option<u64>>,
}

impl Store {
    /// Only system administrators set limits, so a tenant cannot lift its own.
    pub fn set_user_rate(&self, actor: &Actor, user_id: &str, rate: Option<u64>) -> Result<()> {
        self.set_user_rates(
            actor,
            user_id,
            UserRateChange {
                rate_bytes_per_sec: rate,
                ..Default::default()
            },
        )
    }
    /// Sets a user's limits. Upload and download limits need every server
    /// carrying the user's enabled rules to enforce them (409 otherwise).
    pub fn set_user_rates(
        &self,
        actor: &Actor,
        user_id: &str,
        change: UserRateChange,
    ) -> Result<()> {
        if actor.role != Role::SystemAdmin {
            return reject(403, "system administrator required");
        }
        for rate in [
            Some(change.rate_bytes_per_sec),
            change.upload_bytes_per_sec,
            change.download_bytes_per_sec,
        ]
        .into_iter()
        .flatten()
        {
            if !valid(rate) {
                return reject(
                    400,
                    format!("user rate must be {MIN_USER_RATE}..={MAX_USER_RATE} bytes/second"),
                );
            }
        }
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        super::accounts::require_user_manager(&tx, actor, user_id)?;
        let before = user_limits(&tx, user_id)?;
        let adds = [
            (change.upload_bytes_per_sec, before[1]),
            (change.download_bytes_per_sec, before[2]),
        ]
        .into_iter()
        .any(|(next, now)| next.flatten().is_some() && now.is_none());
        if adds {
            super::rate_limits::require_for_user(&tx, user_id)?;
        }
        write_limit(
            &tx,
            RateDirection::Combined,
            user_id,
            change.rate_bytes_per_sec,
        )?;
        let mut detail = serde_json::json!({ "rate_bytes_per_sec": change.rate_bytes_per_sec });
        for (direction, name, rate) in [
            (
                RateDirection::Upload,
                "upload_bytes_per_sec",
                change.upload_bytes_per_sec,
            ),
            (
                RateDirection::Download,
                "download_bytes_per_sec",
                change.download_bytes_per_sec,
            ),
        ] {
            if let Some(rate) = rate {
                write_limit(&tx, direction, user_id, rate)?;
                detail[name] = serde_json::json!(rate);
            }
        }
        audit(&tx, &actor.id, "user.rate", user_id, &detail.to_string())?;
        tx.commit()?;
        Ok(())
    }
    pub fn user_rate(&self, actor: &Actor, user_id: &str) -> Result<UserRateView> {
        let limits = {
            let conn = self.0.lock().unwrap();
            let tenant: Option<String> = conn
                .query_row("SELECT tenant_id FROM users WHERE id=?1", [user_id], |r| {
                    r.get(0)
                })
                .optional()?;
            if !tenant.is_some_and(|t| actor.permits_tenant(&t)) {
                return reject(404, "user not found");
            }
            user_limits(&conn, user_id)?
        };
        let rates = self.6.lock().unwrap();
        let participants = rates.nodes.get(user_id).map_or(&[][..], |(_, n)| n);
        let now = std::time::Instant::now();
        let [nodes, upload_nodes, download_nodes] =
            std::array::from_fn(|index| match limits[index] {
                Some(total) => rates.allocators[index].view(user_id, total, participants, now),
                None => vec![],
            });
        Ok(UserRateView {
            user_id: user_id.into(),
            rate_bytes_per_sec: limits[0],
            nodes,
            upload_bytes_per_sec: limits[1],
            upload_nodes,
            download_bytes_per_sec: limits[2],
            download_nodes,
        })
    }
}
