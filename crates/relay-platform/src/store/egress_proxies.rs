//! Egress proxies on the controller. Agents older than egress proxies
//! reject a configuration that carries one (rule fields deny unknown
//! names), so the controller sends rules with an egress proxy only to an
//! agent that reported it sends destinations through them, kept in
//! `egress_proxy_node:<node id>` and written once, as for rate limits. Every
//! publish path (single and batch, rollback, templates, shared rules,
//! chains, shares and reverse tunnels' public ends) goes through
//! [`require`], which refuses such a configuration for any other server
//! with 409 and the reason, so no rule silently loses its upstream.
use super::*;

fn node_key(node: &str) -> String {
    format!("egress_proxy_node:{node}")
}

/// Whether `node`'s agent reported that it supports egress proxies.
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
    report: Option<&crate::egress::Report>,
) -> Result<()> {
    if report.is_some() && !supported(tx, node)? {
        tx.execute(
            "INSERT INTO metadata(key,value) VALUES(?1,'1')",
            [node_key(node)],
        )?;
    }
    Ok(())
}

/// Refuses (409) a configuration with an egress proxy for a server whose
/// agent has not reported support. A server that never connected cannot be
/// told from one too old.
pub(super) fn require(conn: &Connection, config: &NodeConfig) -> Result<()> {
    if config.rules.iter().all(|r| r.egress_proxy.is_none()) || supported(conn, &config.node_id)? {
        return Ok(());
    }
    let (name, seen): (String, Option<i64>) = conn.query_row(
        "SELECT name,last_seen_ms FROM nodes WHERE id=?1",
        [&config.node_id],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    reject(
        409,
        match seen {
            None => format!(
                "server {name} has not connected to the panel yet; egress proxies need its agent to report in first"
            ),
            Some(_) => format!(
                "the agent on server {name} is too old for egress proxies; upgrade it first"
            ),
        },
    )
}
