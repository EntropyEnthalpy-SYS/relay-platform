//! Upload, download and burst speed limits on the controller. Agents older
//! than these limits reject a configuration or share that carries them, so
//! the controller sends them only to an agent that reported it enforces
//! them, kept in `rate_limit_node:<node id>` and written once, like reverse
//! tunnels' abilities. A change that would need them on another server is
//! refused with 409 and the reason, so no limit is silently dropped.
use super::*;
use std::collections::HashSet;

fn node_key(node: &str) -> String {
    format!("rate_limit_node:{node}")
}

/// Whether `node`'s agent reported that it enforces these limits.
pub(super) fn supported(conn: &Connection, node: &str) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM metadata WHERE key=?1)",
        [node_key(node)],
        |r| r.get(0),
    )?)
}

/// Keeps that `node`'s agent reported support. Agents report only to a
/// controller that asked, and the record is written once.
pub(super) fn observe(
    tx: &Transaction<'_>,
    node: &str,
    report: Option<&RateLimitReport>,
) -> Result<()> {
    if report.is_some() && !supported(tx, node)? {
        tx.execute(
            "INSERT INTO metadata(key,value) VALUES(?1,'1')",
            [node_key(node)],
        )?;
    }
    Ok(())
}

/// Why `node` cannot take these limits, if it cannot. A server that never
/// connected cannot be told from one too old.
pub(super) fn unsupported(conn: &Connection, node: &str) -> Result<Option<String>> {
    if supported(conn, node)? {
        return Ok(None);
    }
    let (name, seen): (String, Option<i64>) = conn.query_row(
        "SELECT name,last_seen_ms FROM nodes WHERE id=?1",
        [node],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    Ok(Some(match seen {
        None => format!(
            "server {name} has not connected to the panel yet; separate upload/download or burst speed limits need its agent to report in first"
        ),
        Some(_) => format!(
            "the agent on server {name} is too old for separate upload/download or burst speed limits; upgrade it first"
        ),
    }))
}

/// Users with an upload or download limit of their own.
fn directional_users(conn: &Connection) -> Result<HashSet<String>> {
    let mut q = conn.prepare(
        "SELECT substr(key,18) FROM metadata WHERE key GLOB 'user_rate_upload:*' UNION SELECT substr(key,20) FROM metadata WHERE key GLOB 'user_rate_download:*'",
    )?;
    let users = q
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    Ok(users)
}

/// Refuses (409) a configuration of a server whose agent has not reported
/// support when it carries upload, download or burst limits (its own or a
/// rule's) or an enabled rule of a user with upload or download limits.
pub(super) fn require(conn: &Connection, config: &NodeConfig) -> Result<()> {
    let Some(reason) = unsupported(conn, &config.node_id)? else {
        return Ok(());
    };
    if config.rate_limits.is_some() || config.rules.iter().any(|r| r.rate_limits.is_some()) {
        return reject(409, reason);
    }
    let users = directional_users(conn)?;
    if let Some(rule) = config
        .rules
        .iter()
        .find(|r| r.enabled && users.contains(&r.owner_id))
    {
        let name: String = conn
            .query_row(
                "SELECT username FROM users WHERE id=?1",
                [&rule.owner_id],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or_else(|| rule.owner_id.clone());
        return reject(
            409,
            format!("user {name} has separate upload/download speed limits: {reason}"),
        );
    }
    Ok(())
}

/// Refuses (409) upload or download limits for `user` while one of the
/// servers carrying the user's enabled rules cannot enforce them.
pub(super) fn require_for_user(conn: &Connection, user: &str) -> Result<()> {
    for (node, config) in topology::all_configs(conn)? {
        if config.rules.iter().any(|r| r.enabled && r.owner_id == user)
            && let Some(reason) = unsupported(conn, &node)?
        {
            return reject(409, reason);
        }
    }
    Ok(())
}
