//! Reverse tunnels in metadata (`reverse_tunnel:<id>`), so the schema and
//! recovery log stay unchanged. The token is stored apart
//! (`reverse_tunnel_token:<id>`), like WireGuard preshared keys, and goes
//! only to the tunnel's two agents. What each agent reported it can do is
//! kept in `reverse_tunnel_node:<node id>`, written only when it changes.
//!
//! The public end is an ordinary rule that [`merge`] renders on every
//! publish of the public server, once both agents can run tunnels and the
//! public one has reported its key; before that neither agent gets
//! anything, because older agents reject the rule's `reverse_tunnel` field.
use super::*;
use crate::node::ForwardingDefaults;
use crate::reverse_tunnel::{
    Admitted, Desired, Dial, Listener, Report, ReverseTunnel, Role as TunnelRole, State,
    TunnelInput, TunnelView, owned, render,
};
use crate::topology::{ConfigBatch, ConfigUpdate};
use std::collections::HashSet;
use std::net::{IpAddr, Ipv4Addr, SocketAddr};

const ONLINE_MS: i64 = 90_000;

fn key(id: &str) -> String {
    format!("reverse_tunnel:{id}")
}
fn token_key(id: &str) -> String {
    format!("reverse_tunnel_token:{id}")
}
fn node_key(node: &str) -> String {
    format!("reverse_tunnel_node:{node}")
}
pub(super) fn all(conn: &Connection) -> Result<Vec<ReverseTunnel>> {
    let mut q = conn.prepare("SELECT value FROM metadata WHERE key GLOB 'reverse_tunnel:*'")?;
    let rows: Vec<String> = q
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    let mut tunnels: Vec<ReverseTunnel> = rows
        .into_iter()
        .map(|value| serde_json::from_str(&value).context("invalid stored reverse tunnel"))
        .collect::<Result<_>>()?;
    tunnels.sort_by(|a, b| (&a.name, &a.id).cmp(&(&b.name, &b.id)));
    Ok(tunnels)
}
fn set(tx: &Transaction<'_>, key: &str, value: &str) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, value],
    )?;
    Ok(())
}
fn get(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row("SELECT value FROM metadata WHERE key=?1", [key], |r| {
            r.get(0)
        })
        .optional()?)
}
fn visible(conn: &Connection, actor: &Actor, id: &str) -> Result<ReverseTunnel> {
    match get(conn, &key(id))? {
        Some(value) => {
            let tunnel: ReverseTunnel = serde_json::from_str(&value)?;
            if actor.permits_tenant(&tunnel.tenant_id) {
                Ok(tunnel)
            } else {
                reject(404, "reverse tunnel not found")
            }
        }
        None => reject(404, "reverse tunnel not found"),
    }
}
fn writer(actor: &Actor) -> Result<()> {
    if !actor.may_write() {
        return reject(403, "read-only role cannot change reverse tunnels");
    }
    Ok(())
}

/// What a node's agent reported it can do: it runs managed tunnels, and
/// the fingerprint of its tunnel key once it made one.
#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
struct NodeAbility {
    #[serde(default)]
    fingerprint: Option<String>,
}
fn ability(conn: &Connection, node: &str) -> Result<Option<NodeAbility>> {
    Ok(get(conn, &node_key(node))?
        .map(|value| serde_json::from_str(&value))
        .transpose()?)
}

enum Readiness {
    PublicTooOld,
    PrivateTooOld,
    WaitingForKey,
    Ready(String),
}
fn readiness(conn: &Connection, tunnel: &ReverseTunnel) -> Result<Readiness> {
    let Some(public) = ability(conn, &tunnel.public_node_id)? else {
        return Ok(Readiness::PublicTooOld);
    };
    if ability(conn, &tunnel.private_node_id)?.is_none() {
        return Ok(Readiness::PrivateTooOld);
    }
    Ok(match public.fingerprint {
        Some(fingerprint) => Readiness::Ready(fingerprint),
        None => Readiness::WaitingForKey,
    })
}

pub(super) fn forwarding(conn: &Connection, node: &str) -> Result<Option<ForwardingDefaults>> {
    Ok(node_profiles::read(conn, node)?.settings.forwarding)
}
/// The listen IP of the public port when the tunnel names none, and of the
/// tunnel listener: as endpoint allocation and shared rules choose it.
fn default_ip(conn: &Connection, node: &str) -> Result<IpAddr> {
    Ok(forwarding(conn, node)?.map_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED), |f| f.bind_ip()))
}
/// `host:port` others use for `port` of `node`: the forwarding host, with
/// the public NAT mapping when the port lies in the forwarding range.
pub(super) fn reachable(
    defaults: Option<&ForwardingDefaults>,
    ip: Option<IpAddr>,
    port: u16,
) -> Option<String> {
    if let Some(defaults) = defaults {
        let public = if (defaults.port_start..=defaults.port_end).contains(&port) {
            defaults.public_port(port)
        } else {
            port
        };
        return Some(defaults.endpoint(public));
    }
    ip.filter(|ip| !ip.is_unspecified())
        .map(|ip| SocketAddr::new(ip, port).to_string())
}

pub(super) fn current_config(conn: &Connection, node: &str) -> Result<Option<NodeConfig>> {
    let json: Option<String> = conn
        .query_row(
            "SELECT c.config_json FROM config_history c JOIN nodes n ON n.id=c.node_id AND n.desired_revision=c.revision WHERE n.id=?1",
            [node],
            |r| r.get(0),
        )
        .optional()?;
    Ok(json.map(|json| serde_json::from_str(&json)).transpose()?)
}

fn holds(rule: &Rule, port: u16) -> bool {
    (rule.listen.port()..=rule.listen_end_port.unwrap_or(rule.listen.port())).contains(&port)
        || rule
            .protocol_gateway
            .as_ref()
            .is_some_and(|gateway| gateway.listen.port() == port)
}

/// Ports tunnels hold on `node` (public and tunnel ports), as ranges for
/// the shared-rule port check.
pub(super) fn reserved_ports(conn: &Connection, node: &str) -> Result<Vec<(u16, u16)>> {
    Ok(all(conn)?
        .into_iter()
        .filter(|t| t.public_node_id == node)
        .flat_map(|t| {
            [
                (t.public_port, t.public_port),
                (t.tunnel_port, t.tunnel_port),
            ]
        })
        .collect())
}

/// Runs inside every publish of `node`: renders the public end of each
/// tunnel ready on it, keeping the editable fields of the rule the publish
/// carries (or of the current rule); drops public ends of tunnels that are
/// gone or not ready; refuses an edit of what the tunnel decides, and any
/// other rule on a port a tunnel holds.
pub(super) fn merge(conn: &Connection, node: &str, rules: &mut Vec<Rule>) -> Result<()> {
    let tunnels: Vec<ReverseTunnel> = all(conn)?
        .into_iter()
        .filter(|t| t.public_node_id == node)
        .collect();
    let mut ready = HashSet::new();
    for tunnel in &tunnels {
        if matches!(readiness(conn, tunnel)?, Readiness::Ready(_)) {
            ready.insert(tunnel.id.as_str());
        }
    }
    rules.retain(|rule| {
        rule.reverse_tunnel
            .as_deref()
            .is_none_or(|id| ready.contains(id))
    });
    if tunnels.is_empty() {
        return Ok(());
    }
    let current = current_config(conn, node)?;
    let default_ip = default_ip(conn, node)?;
    for tunnel in tunnels.iter().filter(|t| ready.contains(t.id.as_str())) {
        let mine: Vec<usize> = rules
            .iter()
            .enumerate()
            .filter(|(_, r)| r.reverse_tunnel.as_deref() == Some(tunnel.id.as_str()))
            .map(|(index, _)| index)
            .collect();
        match mine.as_slice() {
            [] => {
                let base = current.as_ref().and_then(|c| {
                    c.rules
                        .iter()
                        .find(|r| r.reverse_tunnel.as_deref() == Some(tunnel.id.as_str()))
                });
                rules.push(render(tunnel, base, default_ip));
            }
            [index] => {
                let rendered = render(tunnel, Some(&rules[*index]), default_ip);
                if owned(&rendered) != owned(&rules[*index]) {
                    return reject(
                        400,
                        format!(
                            "rule {} is the public end of reverse tunnel {}; change its name, port, protocol, target or switch on the Reverse tunnels page",
                            rules[*index].name, tunnel.name
                        ),
                    );
                }
                rules[*index] = rendered;
            }
            _ => return reject(400, "a reverse tunnel has one public end"),
        }
    }
    for rule in rules.iter() {
        for tunnel in &tunnels {
            for port in [tunnel.public_port, tunnel.tunnel_port] {
                let own = rule.reverse_tunnel.as_deref() == Some(tunnel.id.as_str())
                    && port == tunnel.public_port;
                if !own && holds(rule, port) {
                    return reject(
                        409,
                        format!(
                            "port {port} on this server is held by reverse tunnel {}; choose another port",
                            tunnel.name
                        ),
                    );
                }
            }
        }
    }
    Ok(())
}

fn system_actor(conn: &Connection, node: &str) -> Result<Actor> {
    let tenant: String =
        conn.query_row("SELECT tenant_id FROM nodes WHERE id=?1", [node], |r| {
            r.get(0)
        })?;
    Ok(Actor {
        id: "reverse-tunnel".into(),
        tenant_id: tenant,
        username: "reverse-tunnel".into(),
        role: Role::SystemAdmin,
    })
}

/// Publishes `node` when its public ends change: `replace` swaps in this
/// rendering of `tunnel`'s public end (an edit of the tunnel), otherwise the
/// current rules are rendered again. Returns whether a revision was made.
fn publish_public(
    tx: &Transaction<'_>,
    clocks: &mut leases::LeaseClocks,
    actor: &Actor,
    node: &str,
    replace: Option<(&str, Rule)>,
) -> Result<bool> {
    let Some(current) = current_config(tx, node)? else {
        return Ok(false);
    };
    let mut rules = current.rules.clone();
    if let Some((tunnel, rule)) = replace {
        rules.retain(|r| r.reverse_tunnel.as_deref() != Some(tunnel));
        rules.push(rule);
    }
    let mut merged = rules.clone();
    merge(tx, node, &mut merged)?;
    if merged == current.rules {
        return Ok(false);
    }
    topology::publish_in(
        tx,
        clocks,
        actor,
        ConfigBatch {
            updates: vec![ConfigUpdate {
                node_id: node.into(),
                expected_revision: current.revision,
                rules,
                rate_bytes_per_sec: None,
                rate_limits: None,
            }],
        },
    )?;
    Ok(true)
}

/// Keeps what a node's agent reports it can do. When that changes, both
/// ends of its tunnels are woken and their public servers published again,
/// so a tunnel goes out as soon as it is ready. A failed publish leaves the
/// tunnel waiting and the sync unaffected. Returns whether anything was
/// published or woken.
pub(super) fn observe(
    tx: &Transaction<'_>,
    clocks: &mut leases::LeaseClocks,
    wake: &Mutex<HashSet<String>>,
    node: &str,
    report: Option<&Report>,
) -> Result<bool> {
    let Some(report) = report.filter(|r| r.managed) else {
        return Ok(false);
    };
    let ability = NodeAbility {
        fingerprint: report
            .fingerprint
            .clone()
            .filter(|f| crate::reverse_mux::managed::parse_fingerprint(f).is_some()),
    };
    if self::ability(tx, node)?.as_ref() == Some(&ability) {
        return Ok(false);
    }
    set(tx, &node_key(node), &serde_json::to_string(&ability)?)?;
    let tunnels: Vec<ReverseTunnel> = all(tx)?
        .into_iter()
        .filter(|t| t.public_node_id == node || t.private_node_id == node)
        .collect();
    let mut publics = vec![];
    {
        let mut woken = wake.lock().unwrap();
        for tunnel in &tunnels {
            woken.insert(tunnel.public_node_id.clone());
            woken.insert(tunnel.private_node_id.clone());
            if !publics.contains(&tunnel.public_node_id) {
                publics.push(tunnel.public_node_id.clone());
            }
        }
    }
    for public in publics {
        tx.execute_batch("SAVEPOINT reverse_tunnel_publish")?;
        let result = system_actor(tx, &public)
            .and_then(|actor| publish_public(tx, clocks, &actor, &public, None));
        if let Err(error) = result {
            tracing::warn!(node = %public, %error, "reverse tunnel public end not published");
            tx.execute_batch("ROLLBACK TO reverse_tunnel_publish")?;
        }
        tx.execute_batch("RELEASE reverse_tunnel_publish")?;
    }
    Ok(!tunnels.is_empty())
}

/// What `node` runs: tunnel listeners for the tunnels it is the public end
/// of, dials for those it is the private end of. Only enabled tunnels that
/// are ready, with a token and a reachable tunnel address, are included.
pub(super) fn desired(conn: &Connection, node: &str) -> Result<Desired> {
    let tunnels = all(conn)?;
    let mut desired = Desired {
        key: tunnels.iter().any(|t| t.public_node_id == node),
        ..Default::default()
    };
    for tunnel in tunnels
        .iter()
        .filter(|t| t.enabled && (t.public_node_id == node || t.private_node_id == node))
    {
        let Readiness::Ready(fingerprint) = readiness(conn, tunnel)? else {
            continue;
        };
        let Some(token) = get(conn, &token_key(&tunnel.id))? else {
            continue;
        };
        if tunnel.public_node_id == node {
            let listen = SocketAddr::new(default_ip(conn, node)?, tunnel.tunnel_port);
            let admitted = Admitted {
                id: tunnel.id.clone(),
                token,
            };
            match desired.listeners.iter_mut().find(|l| l.listen == listen) {
                Some(listener) => listener.tunnels.push(admitted),
                None => desired.listeners.push(Listener {
                    listen,
                    tunnels: vec![admitted],
                }),
            }
        } else if let Some(server) = reachable(
            forwarding(conn, &tunnel.public_node_id)?.as_ref(),
            None,
            tunnel.tunnel_port,
        ) {
            desired.dials.push(Dial {
                id: tunnel.id.clone(),
                server,
                fingerprint,
                token,
                target: tunnel.target.clone(),
                protocol: tunnel.protocol,
            });
        }
    }
    Ok(desired)
}

/// Whether `node`'s watch should answer at once because one of its
/// tunnels changed; answers yes once.
pub(super) fn take_wake(wake: &Mutex<HashSet<String>>, node: &str) -> bool {
    wake.lock().unwrap().remove(node)
}

struct Seen {
    name: String,
    last_seen: Option<i64>,
    report: Option<Report>,
}
fn seen(
    conn: &Connection,
    telemetry: &crate::telemetry::Telemetry,
    node: &str,
) -> Result<Option<Seen>> {
    let row: Option<(String, Option<i64>, String)> = conn
        .query_row(
            "SELECT name,last_seen_ms,COALESCE(stats_json,'{}') FROM nodes WHERE id=?1",
            [node],
            |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
        )
        .optional()?;
    Ok(row.map(|(name, last_seen, stats)| {
        let (last_seen, stats) = telemetry.current(node, last_seen, stats);
        Seen {
            name,
            last_seen,
            report: serde_json::from_str::<EngineStats>(&stats)
                .ok()
                .and_then(|s| s.reverse_tunnel),
        }
    }))
}

fn view(
    conn: &Connection,
    telemetry: &crate::telemetry::Telemetry,
    tunnel: &ReverseTunnel,
) -> Result<TunnelView> {
    let public = seen(conn, telemetry, &tunnel.public_node_id)?;
    let private = seen(conn, telemetry, &tunnel.private_node_id)?;
    let defaults = forwarding(conn, &tunnel.public_node_id)?;
    let rule = current_config(conn, &tunnel.public_node_id)?.and_then(|c| {
        c.rules
            .into_iter()
            .find(|r| r.reverse_tunnel.as_deref() == Some(tunnel.id.as_str()))
    });
    let (upload, download): (u64, u64) = match &rule {
        Some(rule) => conn
            .query_row(
                "SELECT upload_bytes,download_bytes FROM usage WHERE node_id=?1 AND rule_id=?2 AND meter_epoch=?3",
                params![tunnel.public_node_id, rule.id, rule.meter_epoch],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .optional()?
            .unwrap_or((0, 0)),
        None => (0, 0),
    };
    let now = now_ms();
    let online = |s: &Seen| {
        s.last_seen
            .is_some_and(|seen| now.saturating_sub(seen) <= ONLINE_MS)
    };
    let report = |s: &Option<Seen>, role: TunnelRole| {
        s.as_ref()
            .filter(|s| online(s))
            .and_then(|s| s.report.as_ref())
            .and_then(|r| {
                r.tunnels
                    .iter()
                    .find(|t| t.id == tunnel.id && t.role == role)
                    .cloned()
            })
    };
    let mut connected = None;
    let (state, reason): (State, Option<String>) = if !tunnel.enabled {
        (State::Disabled, None)
    } else if public.is_none() {
        (State::Error, Some("the public server was deleted".into()))
    } else if private.is_none() {
        (State::Error, Some("the private server was deleted".into()))
    } else {
        // A server that never reported cannot be told from one too old.
        let never = |s: &Option<Seen>| s.as_ref().is_some_and(|s| s.last_seen.is_none());
        match readiness(conn, tunnel)? {
            Readiness::PublicTooOld if never(&public) => (
                State::Waiting,
                Some("the public server has not connected to the panel yet".into()),
            ),
            Readiness::PublicTooOld => (
                State::Waiting,
                Some("the public server's agent is too old for reverse tunnels; upgrade it".into()),
            ),
            Readiness::PrivateTooOld if never(&private) => (
                State::Waiting,
                Some("the private server has not connected to the panel yet".into()),
            ),
            Readiness::PrivateTooOld => (
                State::Waiting,
                Some(
                    "the private server's agent is too old for reverse tunnels; upgrade it".into(),
                ),
            ),
            Readiness::WaitingForKey => (
                State::Waiting,
                Some("waiting for the public server's key".into()),
            ),
            Readiness::Ready(_) => {
                let public_report = report(&public, TunnelRole::Public);
                let private_report = report(&private, TunnelRole::Private);
                if let Some(secs) = public_report.as_ref().and_then(|r| r.connected_secs) {
                    let at = public.as_ref().and_then(|s| s.last_seen).unwrap_or(now);
                    connected = Some((
                        at - secs as i64 * 1000,
                        secs + (now - at).max(0) as u64 / 1000,
                    ));
                    (State::Connected, None)
                } else if reachable(defaults.as_ref(), None, tunnel.tunnel_port).is_none() {
                    (
                        State::Error,
                        Some("the public server has no forwarding host, so the private server cannot reach the tunnel port; set it in the public server's forwarding settings".into()),
                    )
                } else if let Some(error) = public_report
                    .and_then(|r| r.error)
                    .or_else(|| private_report.and_then(|r| r.error))
                {
                    (State::Error, Some(error))
                } else if !public.as_ref().is_some_and(online) {
                    (State::Waiting, Some("the public server is offline".into()))
                } else if !private.as_ref().is_some_and(online) {
                    (State::Waiting, Some("the private server is offline".into()))
                } else if rule.is_none() {
                    (
                        State::Waiting,
                        Some("waiting for the public server's configuration".into()),
                    )
                } else {
                    (
                        State::Waiting,
                        Some("waiting for the private server to connect".into()),
                    )
                }
            }
        }
    };
    Ok(TunnelView {
        id: tunnel.id.clone(),
        tenant_id: tunnel.tenant_id.clone(),
        name: tunnel.name.clone(),
        public_node_id: tunnel.public_node_id.clone(),
        private_node_id: tunnel.private_node_id.clone(),
        public_port: tunnel.public_port,
        listen_ip: tunnel.listen_ip,
        protocol: tunnel.protocol,
        target: tunnel.target.clone(),
        tunnel_port: tunnel.tunnel_port,
        enabled: tunnel.enabled,
        created_at_ms: tunnel.created_at_ms,
        updated_at_ms: tunnel.updated_at_ms,
        public_node_name: public.as_ref().map(|s| s.name.clone()),
        private_node_name: private.as_ref().map(|s| s.name.clone()),
        public_missing: public.is_none(),
        private_missing: private.is_none(),
        state,
        reason,
        connected_since_ms: connected.map(|c| c.0),
        connected_for_secs: connected.map(|c| c.1),
        entry: reachable(
            defaults.as_ref(),
            Some(
                tunnel
                    .listen_ip
                    .unwrap_or(default_ip(conn, &tunnel.public_node_id)?),
            ),
            tunnel.public_port,
        ),
        rule_id: rule.map(|r| r.id),
        upload_bytes: upload,
        download_bytes: download,
    })
}

/// Checks both servers: visible, writable, the same tenant and able to run
/// tunnels. Returns their tenant.
fn servers(conn: &Connection, actor: &Actor, input: &TunnelInput) -> Result<String> {
    let public = require_node(conn, actor, &input.public_node_id, true)?;
    let private = require_node(conn, actor, &input.private_node_id, true)?;
    if public != private {
        return reject(400, "both servers must belong to the same tenant");
    }
    for (node, role) in [
        (&input.public_node_id, "public"),
        (&input.private_node_id, "private"),
    ] {
        let lifecycle = node_profiles::read(conn, node)?
            .settings
            .lifecycle(now_ms());
        if lifecycle != crate::node::NodeLifecycle::Active {
            return reject(
                409,
                format!("the {role} server is paused or expired and cannot run tunnels"),
            );
        }
    }
    Ok(public)
}

/// The public and tunnel ports must be free on the public server: no rule
/// or gateway on them, no cross-panel share, and no other tunnel, except
/// that tunnels share one tunnel port.
fn check_ports(
    conn: &Connection,
    node: &str,
    public_port: u16,
    tunnel_port: u16,
    except: Option<&str>,
) -> Result<()> {
    let config = current_config(conn, node)?.context("node configuration missing")?;
    let shares = federation::reserved_ports(conn, node)?;
    let others: Vec<ReverseTunnel> = all(conn)?
        .into_iter()
        .filter(|t| t.public_node_id == node && Some(t.id.as_str()) != except)
        .collect();
    for (port, what) in [(public_port, "public"), (tunnel_port, "tunnel")] {
        let rule = config.rules.iter().find(|rule| {
            holds(rule, port) && (except.is_none() || rule.reverse_tunnel.as_deref() != except)
        });
        let shared = shares.iter().any(|(s, e)| (*s..=*e).contains(&port));
        let tunnel = others
            .iter()
            .find(|t| t.public_port == port || (what == "public" && t.tunnel_port == port));
        let holder = match (rule, shared, tunnel) {
            (Some(rule), _, _) => format!("rule {}", rule.name),
            (_, true, _) => "a cross-panel share".into(),
            (_, _, Some(tunnel)) => format!("reverse tunnel {}", tunnel.name),
            _ => continue,
        };
        return reject(
            409,
            format!("the {what} port {port} is already used on the public server by {holder}"),
        );
    }
    Ok(())
}

/// The owner of a new tunnel's rule: the caller when it belongs to the
/// tenant, otherwise the tenant's first administrator.
fn pick_owner(conn: &Connection, actor: &Actor, tenant: &str) -> Result<String> {
    if actor.tenant_id == tenant {
        return Ok(actor.id.clone());
    }
    let owner: Option<String> = conn
        .query_row(
            "SELECT id FROM users WHERE tenant_id=?1 AND disabled=0 ORDER BY role<>'tenant_admin',rowid LIMIT 1",
            [tenant],
            |r| r.get(0),
        )
        .optional()?;
    match owner {
        Some(owner) => Ok(owner),
        None => reject(400, "the servers' tenant has no account to own the tunnel"),
    }
}

fn detail(tunnel: &ReverseTunnel) -> String {
    serde_json::json!({
        "name": tunnel.name,
        "public_node_id": tunnel.public_node_id,
        "private_node_id": tunnel.private_node_id,
        "public_port": tunnel.public_port,
        "listen_ip": tunnel.listen_ip,
        "protocol": tunnel.protocol,
        "target": tunnel.target,
        "tunnel_port": tunnel.tunnel_port,
        "enabled": tunnel.enabled,
    })
    .to_string()
}

impl Store {
    fn wake_tunnel(&self, tunnel: &ReverseTunnel) {
        let mut woken = self.10.lock().unwrap();
        woken.insert(tunnel.public_node_id.clone());
        woken.insert(tunnel.private_node_id.clone());
    }
    pub fn reverse_tunnels(&self, actor: &Actor) -> Result<Vec<TunnelView>> {
        let conn = self.0.lock().unwrap();
        all(&conn)?
            .iter()
            .filter(|t| actor.permits_tenant(&t.tenant_id))
            .map(|t| view(&conn, &self.4, t))
            .collect()
    }
    pub fn create_reverse_tunnel(&self, actor: &Actor, input: TunnelInput) -> Result<TunnelView> {
        writer(actor)?;
        input.validate()?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let tenant = servers(&tx, actor, &input)?;
        let tunnel_port = input
            .tunnel_port
            .unwrap_or(crate::reverse_tunnel::DEFAULT_TUNNEL_PORT);
        check_ports(
            &tx,
            &input.public_node_id,
            input.public_port,
            tunnel_port,
            None,
        )?;
        let now = now_ms();
        let tunnel = ReverseTunnel {
            id: Uuid::new_v4().to_string(),
            owner_id: pick_owner(&tx, actor, &tenant)?,
            tenant_id: tenant,
            name: input.name.trim().to_owned(),
            public_node_id: input.public_node_id,
            private_node_id: input.private_node_id,
            public_port: input.public_port,
            listen_ip: input.listen_ip,
            protocol: input.protocol,
            target: input.target,
            tunnel_port,
            enabled: input.enabled.unwrap_or(true),
            created_at_ms: now,
            updated_at_ms: now,
        };
        set(&tx, &key(&tunnel.id), &serde_json::to_string(&tunnel)?)?;
        set(&tx, &token_key(&tunnel.id), &secret())?;
        let published = publish_public(
            &tx,
            &mut self.3.lock().unwrap(),
            actor,
            &tunnel.public_node_id,
            None,
        )?;
        audit(
            &tx,
            &actor.id,
            "reverse_tunnel.create",
            &tunnel.id,
            &detail(&tunnel),
        )?;
        tx.commit()?;
        if published {
            self.2.config.notify_waiters();
        }
        self.wake_tunnel(&tunnel);
        self.2.config.notify_waiters();
        view(&conn, &self.4, &tunnel)
    }
    pub fn update_reverse_tunnel(
        &self,
        actor: &Actor,
        id: &str,
        input: TunnelInput,
    ) -> Result<TunnelView> {
        writer(actor)?;
        input.validate()?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let old = visible(&tx, actor, id)?;
        // Both servers of the tunnel as it was must be writable too.
        for node in [&old.public_node_id, &old.private_node_id] {
            match require_node(&tx, actor, node, true) {
                Err(error)
                    if error
                        .downcast_ref::<Rejection>()
                        .is_some_and(|r| r.status == 404) => {}
                result => {
                    result?;
                }
            }
        }
        let tenant = servers(&tx, actor, &input)?;
        if tenant != old.tenant_id {
            return reject(400, "a tunnel stays in its tenant");
        }
        let tunnel_port = input
            .tunnel_port
            .unwrap_or(crate::reverse_tunnel::DEFAULT_TUNNEL_PORT);
        check_ports(
            &tx,
            &input.public_node_id,
            input.public_port,
            tunnel_port,
            Some(id),
        )?;
        let tunnel = ReverseTunnel {
            name: input.name.trim().to_owned(),
            public_node_id: input.public_node_id,
            private_node_id: input.private_node_id,
            public_port: input.public_port,
            listen_ip: input.listen_ip,
            protocol: input.protocol,
            target: input.target,
            tunnel_port,
            enabled: input.enabled.unwrap_or(old.enabled),
            updated_at_ms: now_ms(),
            ..old.clone()
        };
        set(&tx, &key(id), &serde_json::to_string(&tunnel)?)?;
        // Another server at either end must not keep a working token.
        if tunnel.public_node_id != old.public_node_id
            || tunnel.private_node_id != old.private_node_id
        {
            set(&tx, &token_key(id), &secret())?;
        }
        let previous = current_config(&tx, &old.public_node_id)?.and_then(|c| {
            c.rules
                .into_iter()
                .find(|r| r.reverse_tunnel.as_deref() == Some(id))
        });
        let mut clocks = self.3.lock().unwrap();
        let mut published = false;
        if tunnel.public_node_id != old.public_node_id {
            published |= publish_public(&tx, &mut clocks, actor, &old.public_node_id, None)?;
        }
        let ip = default_ip(&tx, &tunnel.public_node_id)?;
        let rendered = previous.map(|mut base| {
            if tunnel.public_node_id != old.public_node_id {
                // The rule moves: a new identity and period, the same limits.
                base.id = format!("{}{}", crate::reverse_tunnel::RULE_PREFIX, Uuid::new_v4());
                base.meter_epoch = Uuid::new_v4().to_string();
            }
            render(&tunnel, Some(&base), ip)
        });
        published |= publish_public(
            &tx,
            &mut clocks,
            actor,
            &tunnel.public_node_id,
            rendered.map(|rule| (id, rule)),
        )?;
        drop(clocks);
        audit(
            &tx,
            &actor.id,
            "reverse_tunnel.update",
            id,
            &detail(&tunnel),
        )?;
        tx.commit()?;
        if published {
            self.2.config.notify_waiters();
        }
        self.wake_tunnel(&old);
        self.wake_tunnel(&tunnel);
        self.2.config.notify_waiters();
        view(&conn, &self.4, &tunnel)
    }
    pub fn delete_reverse_tunnel(&self, actor: &Actor, id: &str) -> Result<()> {
        writer(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let tunnel = visible(&tx, actor, id)?;
        // A deleted server no longer limits who may remove the tunnel.
        for node in [&tunnel.public_node_id, &tunnel.private_node_id] {
            match require_node(&tx, actor, node, true) {
                Err(error)
                    if error
                        .downcast_ref::<Rejection>()
                        .is_some_and(|r| r.status == 404) => {}
                result => {
                    result?;
                }
            }
        }
        tx.execute(
            "DELETE FROM metadata WHERE key IN (?1,?2)",
            params![key(id), token_key(id)],
        )?;
        let published = publish_public(
            &tx,
            &mut self.3.lock().unwrap(),
            actor,
            &tunnel.public_node_id,
            None,
        )?;
        audit(
            &tx,
            &actor.id,
            "reverse_tunnel.delete",
            id,
            &detail(&tunnel),
        )?;
        tx.commit()?;
        if published {
            self.2.config.notify_waiters();
        }
        self.wake_tunnel(&tunnel);
        self.2.config.notify_waiters();
        Ok(())
    }
}

/// After `node` was deleted: its tunnels' public ends go from the public
/// servers that remain, as the tunnels can no longer run.
pub(super) fn node_deleted(
    tx: &Transaction<'_>,
    clocks: &mut leases::LeaseClocks,
    node: &str,
) -> Result<bool> {
    let mut published = false;
    let publics: HashSet<String> = all(tx)?
        .into_iter()
        .filter(|t| t.private_node_id == node && t.public_node_id != node)
        .map(|t| t.public_node_id)
        .collect();
    for public in publics {
        tx.execute_batch("SAVEPOINT reverse_tunnel_publish")?;
        let result = system_actor(tx, &public)
            .and_then(|actor| publish_public(tx, clocks, &actor, &public, None));
        match result {
            Ok(changed) => published |= changed,
            Err(error) => {
                tracing::warn!(node = %public, %error, "reverse tunnel public end not removed");
                tx.execute_batch("ROLLBACK TO reverse_tunnel_publish")?;
            }
        }
        tx.execute_batch("RELEASE reverse_tunnel_publish")?;
    }
    Ok(published)
}
