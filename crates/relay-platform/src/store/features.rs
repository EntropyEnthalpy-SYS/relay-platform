//! Optional features. Each stays off until a system administrator switches it
//! on. A feature that something already uses counts as on until it is
//! switched explicitly, so upgrading never turns off working configuration,
//! and a feature cannot be switched off while anything still uses it.
use super::*;

/// Every switchable feature, in the order the panel lists them.
pub const FEATURES: &[&str] = &[
    "mptcp",
    "dns-health",
    "plan-entitlements",
    "budget-recovery",
    "mptcp-paths",
    "dns-authoritative",
];

#[derive(Clone, Debug, Serialize)]
pub struct FeatureState {
    pub id: &'static str,
    pub enabled: bool,
    /// How many settings still use the feature; it cannot be switched off until this is 0.
    pub in_use: usize,
}

fn key(id: &str) -> String {
    format!("feature:{id}")
}

fn usage(conn: &Connection, id: &str) -> Result<usize> {
    Ok(match id {
        "mptcp" => topology::all_configs(conn)?
            .values()
            .flat_map(|config| &config.rules)
            .filter(|rule| rule.mptcp.is_some_and(|m| m != Default::default()))
            .count(),
        "dns-health" => conn.query_row(
            "SELECT COUNT(*) FROM metadata WHERE key GLOB 'dns_record:*' AND json_extract(value,'$.health') IS NOT NULL",
            [],
            |r| r.get(0),
        )?,
        "plan-entitlements" => commerce::live_count(conn)?,
        "mptcp-paths" => node_profiles::with_mptcp_paths(conn)?,
        "dns-authoritative" => dns_authoritative::zone_count(conn)?,
        _ => 0,
    })
}

/// What `usage` counts, for the refusal to switch a feature off.
fn users(id: &str) -> &'static str {
    match id {
        "mptcp" => "forwarding rule(s) use MPTCP",
        "dns-health" => "DNS record(s) use health gating",
        "plan-entitlements" => "plan(s) are active or waiting for a budget",
        "mptcp-paths" => "node(s) have MPTCP paths",
        "dns-authoritative" => "zone(s) are in the authoritative DNS pool",
        _ => "setting(s) use this feature",
    }
}

pub(super) fn enabled(conn: &Connection, id: &str) -> Result<bool> {
    debug_assert!(FEATURES.contains(&id), "unknown feature {id}");
    match conn
        .query_row("SELECT value FROM metadata WHERE key=?1", [key(id)], |r| {
            r.get::<_, String>(0)
        })
        .optional()?
    {
        Some(value) => Ok(value == "on"),
        None => Ok(usage(conn, id)? > 0),
    }
}

/// Rejects a change that needs `id` while it is switched off.
pub(super) fn require(conn: &Connection, id: &str, what: &str) -> Result<()> {
    if enabled(conn, id)? {
        return Ok(());
    }
    reject(
        409,
        format!(
            "{what} is switched off; a system administrator can turn it on in Optional features"
        ),
    )
}

fn state(conn: &Connection, id: &'static str) -> Result<FeatureState> {
    Ok(FeatureState {
        id,
        enabled: enabled(conn, id)?,
        in_use: usage(conn, id)?,
    })
}

impl Store {
    /// Every signed-in role may read the switches: the panel hides switched-off pages.
    pub fn features(&self, _actor: &Actor) -> Result<Vec<FeatureState>> {
        let conn = self.0.lock().unwrap();
        FEATURES.iter().map(|id| state(&conn, id)).collect()
    }
    pub fn feature_enabled(&self, id: &str) -> Result<bool> {
        enabled(&self.0.lock().unwrap(), id)
    }
    pub fn set_feature(&self, actor: &Actor, id: &str, on: bool) -> Result<FeatureState> {
        if actor.role != Role::SystemAdmin {
            return reject(403, "optional features require system administrator access");
        }
        let Some(id) = FEATURES.iter().copied().find(|known| *known == id) else {
            return reject(404, "unknown optional feature");
        };
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let used = usage(&tx, id)?;
        if !on && used > 0 {
            return reject(
                409,
                format!(
                    "{used} {}; remove them first, then switch the feature off",
                    users(id)
                ),
            );
        }
        tx.execute(
            "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key(id), if on { "on" } else { "off" }],
        )?;
        audit(
            &tx,
            &actor.id,
            if on {
                "feature.enable"
            } else {
                "feature.disable"
            },
            id,
            "{}",
        )?;
        let result = state(&tx, id)?;
        tx.commit()?;
        Ok(result)
    }
}
