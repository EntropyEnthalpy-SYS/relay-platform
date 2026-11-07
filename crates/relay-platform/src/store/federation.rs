//! Cross-panel sharing in the database: the shares this panel gives
//! (`federation_grant:<id>`) and the ones it received from other panels
//! (`federation_remote:<id>`), both in metadata, so the schema and recovery
//! log stay unchanged. A share's rules are ordinary rules on its node that
//! [`merge`] renders on every publish, so no other publish can change them.
use super::*;
use crate::{
    budget::{BudgetScope, NewBudget},
    federation::{
        self as fed, Grant, GrantInput, GrantView, Invite, Issued, Link, PeerError, RedeemRequest,
        Redeemed, Refusal, Remote, RulesRequest, Shared, State, Statement, View,
    },
    topology::{ConfigBatch, ConfigUpdate},
};
use std::{collections::HashSet, net::IpAddr};
use subtle::ConstantTimeEq;

const FEATURE: &str = "federation";
const WHAT: &str = "Cross-panel sharing";
const PANEL_KEY: &str = "federation_panel_id";
/// Bookkeeping that only shows freshness is written at most this often, so
/// polling does not grow the recovery log.
const REFRESH_MS: i64 = 5 * 60 * 1000;

fn key(kind: &str, id: &str) -> String {
    format!("federation_{kind}:{id}")
}
fn read<T: serde::de::DeserializeOwned>(
    conn: &Connection,
    kind: &str,
    id: &str,
) -> Result<Option<T>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            [key(kind, id)],
            |r| r.get(0),
        )
        .optional()?;
    Ok(raw.map(|value| serde_json::from_str(&value)).transpose()?)
}
fn write<T: Serialize>(tx: &Transaction<'_>, kind: &str, id: &str, value: &T) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key(kind, id), serde_json::to_string(value)?],
    )?;
    Ok(())
}
fn all<T: serde::de::DeserializeOwned>(conn: &Connection, kind: &str) -> Result<Vec<T>> {
    let mut q = conn.prepare("SELECT value FROM metadata WHERE key GLOB ?1 ORDER BY key")?;
    let rows: Vec<String> = q
        .query_map([format!("federation_{kind}:*")], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    rows.into_iter()
        .map(|value| serde_json::from_str(&value).context("invalid stored sharing data"))
        .collect()
}
fn grant(conn: &Connection, id: &str) -> Result<Grant> {
    match read(conn, "grant", id)? {
        Some(grant) => Ok(grant),
        None => reject(404, "share not found"),
    }
}
fn remote(conn: &Connection, id: &str) -> Result<Remote> {
    match read(conn, "remote", id)? {
        Some(remote) => Ok(remote),
        None => reject(404, "received share not found"),
    }
}
/// This panel's id, made once; receivers name the panel they redeemed from.
fn panel_id(tx: &Transaction<'_>) -> Result<String> {
    tx.execute(
        "INSERT OR IGNORE INTO metadata(key,value) VALUES(?1,?2)",
        params![PANEL_KEY, Uuid::new_v4().to_string()],
    )?;
    Ok(tx.query_row(
        "SELECT value FROM metadata WHERE key=?1",
        [PANEL_KEY],
        |r| r.get(0),
    )?)
}
/// Shares not revoked and received shares; the feature cannot be switched
/// off while any exist.
pub(super) fn active_count(conn: &Connection) -> Result<usize> {
    Ok(conn.query_row(
        "SELECT COUNT(*) FROM metadata WHERE (key GLOB 'federation_grant:*' AND json_extract(value,'$.state')<>'revoked') OR key GLOB 'federation_remote:*'",
        [],
        |r| r.get(0),
    )?)
}

/// Port ranges that shares not yet revoked hold on `node`.
pub(super) fn reserved_ports(conn: &Connection, node: &str) -> Result<Vec<(u16, u16)>> {
    Ok(all::<Grant>(conn, "grant")?
        .into_iter()
        .filter(|grant| grant.node_id == node && grant.state != State::Revoked)
        .map(|grant| (grant.port_start, grant.port_end))
        .collect())
}
fn overlaps(ip: IpAddr, start: u16, end: u16, rule: &Rule) -> bool {
    let last = rule.listen_end_port.unwrap_or(rule.listen.port());
    (ip == rule.listen.ip() || ip.is_unspecified() || rule.listen.ip().is_unspecified())
        && rule.listen.port() <= end
        && start <= last
}

/// Replaces the shared rules a publish of `node` carries with the canonical
/// rendering of every share on the node that is not revoked, and refuses
/// other rules inside a share's ports. Runs inside every publish.
pub(super) fn merge(
    conn: &Connection,
    node: &str,
    tenant: &str,
    rules: &mut Vec<Rule>,
) -> Result<()> {
    let grants = all::<Grant>(conn, "grant")?;
    if grants.is_empty() {
        return Ok(());
    }
    let accounts: HashSet<&str> = grants.iter().map(|g| g.user_id.as_str()).collect();
    if let Some(rule) = rules
        .iter()
        .find(|r| accounts.contains(r.owner_id.as_str()) && !r.id.starts_with(fed::RULE_PREFIX))
    {
        return reject(
            400,
            format!(
                "rule {} is owned by a share's account; those accounts own only their share's rules",
                rule.name
            ),
        );
    }
    rules.retain(|r| {
        !(r.id.starts_with(fed::RULE_PREFIX) && accounts.contains(r.owner_id.as_str()))
    });
    let live: Vec<&Grant> = grants
        .iter()
        .filter(|g| g.node_id == node && g.state != State::Revoked)
        .collect();
    for grant in &live {
        if let Some(rule) = rules
            .iter()
            .find(|r| overlaps(grant.listen_ip, grant.port_start, grant.port_end, r))
        {
            return reject(
                400,
                format!(
                    "rule {} uses ports {}–{}, which are shared as {}; choose other ports",
                    rule.name, grant.port_start, grant.port_end, grant.name
                ),
            );
        }
    }
    for grant in live {
        rules.extend(
            grant
                .rules
                .iter()
                .map(|rule| fed::render(grant, rule, tenant)),
        );
    }
    Ok(())
}

/// A new revision of `node` with its current rules, so it carries the newest
/// rendering of its shares.
fn republish(tx: &Transaction<'_>, clocks: &mut leases::LeaseClocks, node: &str) -> Result<u64> {
    let (tenant, json): (String, String) = tx.query_row(
        "SELECT n.tenant_id,c.config_json FROM nodes n JOIN config_history c ON c.node_id=n.id AND c.revision=n.desired_revision WHERE n.id=?1",
        [node],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let current: NodeConfig = serde_json::from_str(&json)?;
    let actor = Actor {
        id: "federation".into(),
        tenant_id: tenant,
        username: "federation".into(),
        role: Role::SystemAdmin,
    };
    let batch = ConfigBatch {
        updates: vec![ConfigUpdate {
            node_id: node.into(),
            expected_revision: current.revision,
            rules: current.rules,
            rate_bytes_per_sec: None,
        }],
    };
    Ok(topology::publish_in(tx, clocks, &actor, batch)?.configs[0].revision)
}

/// Traffic of the share's rules from the node's durable counters; `as_of_ms`
/// is the newest report, so an idle share reads the same every time.
fn statement(conn: &Connection, user: &str) -> Result<Statement> {
    let (as_of, upload, download): (Option<i64>, i64, i64) = conn.query_row(
        "SELECT MAX(u.reported_at_ms),COALESCE(SUM(u.upload_bytes),0),COALESCE(SUM(u.download_bytes),0) FROM usage u JOIN rule_bindings b ON b.rule_id=u.rule_id WHERE b.owner_id=?1",
        [user],
        |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)),
    )?;
    Ok(Statement {
        as_of_ms: as_of.unwrap_or(0),
        upload_bytes: upload as u64,
        download_bytes: download as u64,
    })
}
/// The node runs the share's newest rules, or none once revoked.
fn applied(conn: &Connection, grant: &Grant) -> Result<bool> {
    let wanted = match grant.state {
        State::Revoked => grant.revoked_revision,
        _ => grant.published_revision,
    };
    let Some(wanted) = wanted else {
        return Ok(true);
    };
    let applied: Option<u64> = conn
        .query_row(
            "SELECT applied_revision FROM nodes WHERE id=?1",
            [&grant.node_id],
            |r| r.get(0),
        )
        .optional()?;
    Ok(applied.is_some_and(|a| a >= wanted))
}
fn quota_used(conn: &Connection, grant: &Grant) -> Result<Option<u64>> {
    Ok(match &grant.budget_id {
        Some(id) => budgets::budget(conn, id)?.map(|b| b.consumed_bytes),
        None => None,
    })
}
fn shared(conn: &Connection, grant: &Grant, panel: &str) -> Result<Shared> {
    Ok(Shared {
        grant_id: grant.id.clone(),
        owner_panel_id: panel.into(),
        name: grant.name.clone(),
        public_host: grant.public_host.clone(),
        port_start: grant.port_start,
        port_end: grant.port_end,
        max_rules: grant.max_rules,
        kinds: grant.kinds.clone(),
        rate_bytes_per_sec: grant.rate_bytes_per_sec,
        quota_bytes: grant.quota_bytes,
        quota_used_bytes: quota_used(conn, grant)?,
        expires_at_ms: grant.expires_at_ms,
        allow_sources: grant.allow_sources.clone(),
        state: grant.state,
        revision: grant.revision,
        rules: grant.rules.clone(),
        applied: applied(conn, grant)?,
        statement: statement(conn, &grant.user_id)?,
    })
}

fn require_admin(actor: &Actor) -> Result<()> {
    if actor.role != Role::SystemAdmin {
        return reject(403, "cross-panel sharing requires a system administrator");
    }
    Ok(())
}
fn invalid<T>(error: anyhow::Error) -> Result<T> {
    reject(400, format!("{error:#}"))
}
fn listen_ip(input: &GrantInput) -> Result<IpAddr> {
    match input
        .listen_ip
        .as_deref()
        .map(str::trim)
        .filter(|ip| !ip.is_empty())
    {
        Some(text) => text
            .trim_matches(['[', ']'])
            .parse()
            .or_else(|_| reject(400, "the listening address must be an IP address")),
        None => Ok(IpAddr::from([0, 0, 0, 0])),
    }
}
/// The ports must be free on the node: no other rule and no other share.
fn free_ports(
    conn: &Connection,
    node: &str,
    ip: IpAddr,
    start: u16,
    end: u16,
    except: &str,
) -> Result<()> {
    let grants = all::<Grant>(conn, "grant")?;
    let accounts: HashSet<&str> = grants.iter().map(|g| g.user_id.as_str()).collect();
    let json: String = conn.query_row(
        "SELECT c.config_json FROM nodes n JOIN config_history c ON c.node_id=n.id AND c.revision=n.desired_revision WHERE n.id=?1",
        [node],
        |r| r.get(0),
    )?;
    let config: NodeConfig = serde_json::from_str(&json)?;
    if let Some(rule) = config
        .rules
        .iter()
        .filter(|r| !accounts.contains(r.owner_id.as_str()))
        .find(|r| overlaps(ip, start, end, r))
    {
        return reject(
            409,
            format!(
                "rule {} already uses ports in {start}–{end} on this node",
                rule.name
            ),
        );
    }
    for other in grants
        .iter()
        .filter(|g| g.node_id == node && g.id != except && g.state != State::Revoked)
    {
        let same_ip =
            other.listen_ip == ip || other.listen_ip.is_unspecified() || ip.is_unspecified();
        if same_ip && other.port_start <= end && start <= other.port_end {
            return reject(
                409,
                format!(
                    "the share {} already uses ports {}–{} on this node",
                    other.name, other.port_start, other.port_end
                ),
            );
        }
    }
    if let Some((port, _)) = reverse_tunnels::reserved_ports(conn, node)?
        .into_iter()
        .find(|(port, _)| (start..=end).contains(port))
    {
        return reject(
            409,
            format!("port {port} on this node is held by a reverse tunnel"),
        );
    }
    Ok(())
}
fn set_rate(tx: &Transaction<'_>, user: &str, rate: Option<u64>) -> Result<()> {
    let key = user_rates::rate_key(user);
    match rate {
        Some(rate) => tx.execute(
            "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, rate.to_string()],
        )?,
        None => tx.execute("DELETE FROM metadata WHERE key=?1", [key])?,
    };
    Ok(())
}
fn matches(stored: &str, secret: &str) -> bool {
    !stored.is_empty() && bool::from(stored.as_bytes().ct_eq(token_hash(secret).as_bytes()))
}
/// The share a receiver's secret belongs to.
fn by_secret(conn: &Connection, secret: &str) -> Result<Grant> {
    for grant in all::<Grant>(conn, "grant")? {
        if grant.state != State::Revoked
            && grant
                .link
                .as_ref()
                .is_some_and(|link| matches(&link.secret_sha256, secret))
        {
            return Ok(grant);
        }
    }
    reject(401, "this share was revoked or does not exist")
}
/// What a view may show: no secret hashes.
fn redacted(mut grant: Grant) -> Grant {
    if let Some(invite) = &mut grant.invite {
        invite.secret_sha256.clear();
    }
    if let Some(link) = &mut grant.link {
        link.secret_sha256.clear();
    }
    grant
}

impl Store {
    pub fn federation(&self, actor: &Actor) -> Result<View> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let panel = panel_id(&tx)?;
        let mut grants = vec![];
        for grant in all::<Grant>(&tx, "grant")? {
            let node_name = tx
                .query_row(
                    "SELECT name FROM nodes WHERE id=?1",
                    [&grant.node_id],
                    |r| r.get(0),
                )
                .optional()?
                .unwrap_or_else(|| grant.node_id.clone());
            let statement = statement(&tx, &grant.user_id)?;
            let ack_mismatch = grant
                .link
                .as_ref()
                .and_then(|l| l.ack.as_ref())
                .is_some_and(|ack| ack.total() > statement.total());
            grants.push(GrantView {
                node_name,
                quota_used_bytes: quota_used(&tx, &grant)?,
                applied: applied(&tx, &grant)?,
                statement,
                ack_mismatch,
                grant: redacted(grant),
            });
        }
        grants.sort_by(|a, b| {
            (a.grant.state == State::Revoked, &a.grant.name)
                .cmp(&(b.grant.state == State::Revoked, &b.grant.name))
        });
        let mut remotes = all::<Remote>(&tx, "remote")?;
        for remote in &mut remotes {
            remote.secret.clear();
        }
        remotes.sort_by(|a, b| a.label.cmp(&b.label));
        let view = View {
            enabled: features::enabled(&tx, FEATURE)?,
            panel_id: panel,
            grants,
            remotes,
        };
        tx.commit()?;
        Ok(view)
    }

    pub fn create_federation_grant(&self, actor: &Actor, input: GrantInput) -> Result<Grant> {
        require_admin(actor)?;
        fed::check_input(&input).or_else(invalid)?;
        let public_host = fed::public_host(&input.public_host).or_else(invalid)?;
        let ip = listen_ip(&input)?;
        let Some(node) = input.node_id.clone().filter(|n| !n.is_empty()) else {
            return reject(400, "choose the node to share");
        };
        // Nobody signs in as a share's account; hashing happens before the lock.
        let hash = password_hash(&secret())?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        features::require(&tx, FEATURE, WHAT)?;
        let tenant = require_node(&tx, actor, &node, true)?;
        if all::<Grant>(&tx, "grant")?.len() >= fed::MAX_GRANTS {
            return reject(
                409,
                format!(
                    "at most {} shares; delete revoked ones first",
                    fed::MAX_GRANTS
                ),
            );
        }
        let id = Uuid::new_v4().to_string();
        free_ports(&tx, &node, ip, input.port_start, input.port_end, &id)?;
        let user = Uuid::new_v4().to_string();
        tx.execute(
            "INSERT INTO users(id,tenant_id,username,password_hash,role,disabled) VALUES(?1,?2,?3,?4,'viewer',1)",
            params![user, tenant, format!("share-{}", &id[..8]), hash],
        )?;
        set_rate(&tx, &user, input.rate_bytes_per_sec)?;
        let budget_id = match input.quota_bytes {
            Some(quota) => Some(
                budgets::insert_budget(
                    &tx,
                    &tenant,
                    &NewBudget {
                        scope: BudgetScope::User,
                        scope_id: user.clone(),
                        name: format!("Share {}", input.name.trim()),
                        limit_bytes: quota,
                        quantum_bytes: quota.min(16 << 20),
                    },
                    &actor.id,
                )?
                .id,
            ),
            None => None,
        };
        let now = now_ms();
        let grant = Grant {
            id,
            name: input.name.trim().into(),
            node_id: node,
            public_host,
            listen_ip: ip,
            port_start: input.port_start,
            port_end: input.port_end,
            max_rules: input.max_rules,
            kinds: input.kinds.clone(),
            rate_bytes_per_sec: input.rate_bytes_per_sec,
            quota_bytes: input.quota_bytes,
            expires_at_ms: input.expires_at_ms,
            allow_sources: fed::sources(&input),
            allow_destinations: input.allow_destinations.clone(),
            deny_destinations: input.deny_destinations.clone(),
            allow_private_destinations: input.allow_private_destinations,
            state: State::Active,
            user_id: user,
            budget_id,
            revision: 1,
            next_rule: 0,
            rules: vec![],
            invite: None,
            link: None,
            published_revision: None,
            revoked_revision: None,
            created_at_ms: now,
            updated_at_ms: now,
        };
        write(&tx, "grant", &grant.id, &grant)?;
        audit(
            &tx,
            &actor.id,
            "federation.grant.create",
            &grant.id,
            &serde_json::json!({"name": grant.name, "node_id": grant.node_id, "ports": [grant.port_start, grant.port_end]}).to_string(),
        )?;
        tx.commit()?;
        Ok(grant)
    }

    pub fn update_federation_grant(
        &self,
        actor: &Actor,
        id: &str,
        input: GrantInput,
    ) -> Result<Grant> {
        require_admin(actor)?;
        fed::check_input(&input).or_else(invalid)?;
        let public_host = fed::public_host(&input.public_host).or_else(invalid)?;
        let ip = listen_ip(&input)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        features::require(&tx, FEATURE, WHAT)?;
        let mut grant = grant(&tx, id)?;
        if grant.state == State::Revoked {
            return reject(409, "a revoked share cannot change");
        }
        if input
            .node_id
            .as_ref()
            .is_some_and(|n| !n.is_empty() && *n != grant.node_id)
        {
            return reject(400, "a share's node cannot change; create a new share");
        }
        free_ports(
            &tx,
            &grant.node_id,
            ip,
            input.port_start,
            input.port_end,
            &grant.id,
        )?;
        if grant.rules.len() > usize::from(input.max_rules)
            || grant.rules.iter().any(|r| {
                !(input.port_start..=input.port_end).contains(&r.port)
                    || !input.kinds.contains(&r.kind)
            })
        {
            return reject(
                409,
                "the receiver's current rules would no longer fit; ask them to remove rules first, or pause the share",
            );
        }
        match (&grant.budget_id, input.quota_bytes) {
            (Some(budget), Some(quota)) => {
                if tx.execute(
                    "UPDATE budgets SET limit_bytes=?1,quantum_bytes=?2,revision=revision+1 WHERE id=?3 AND committed_bytes<=?1",
                    params![quota, quota.min(16 << 20), budget],
                )? != 1
                {
                    return reject(
                        409,
                        "the traffic limit cannot be below the traffic already used or reserved",
                    );
                }
            }
            (None, None) => {}
            _ => {
                return reject(
                    409,
                    "a share's traffic limit can change but cannot be added or removed; create a new share instead",
                );
            }
        }
        set_rate(&tx, &grant.user_id, input.rate_bytes_per_sec)?;
        grant.name = input.name.trim().into();
        grant.public_host = public_host;
        grant.listen_ip = ip;
        grant.port_start = input.port_start;
        grant.port_end = input.port_end;
        grant.max_rules = input.max_rules;
        grant.kinds = input.kinds.clone();
        grant.rate_bytes_per_sec = input.rate_bytes_per_sec;
        grant.quota_bytes = input.quota_bytes;
        grant.expires_at_ms = input.expires_at_ms;
        grant.allow_sources = fed::sources(&input);
        grant.allow_destinations = input.allow_destinations.clone();
        grant.deny_destinations = input.deny_destinations.clone();
        grant.allow_private_destinations = input.allow_private_destinations;
        grant.revision += 1;
        grant.updated_at_ms = now_ms();
        write(&tx, "grant", &grant.id, &grant)?;
        let republished = !grant.rules.is_empty();
        if republished {
            grant.published_revision =
                Some(republish(&tx, &mut self.3.lock().unwrap(), &grant.node_id)?);
            write(&tx, "grant", &grant.id, &grant)?;
        }
        audit(
            &tx,
            &actor.id,
            "federation.grant.update",
            &grant.id,
            &serde_json::json!({"name": grant.name, "ports": [grant.port_start, grant.port_end]})
                .to_string(),
        )?;
        tx.commit()?;
        if republished {
            self.2.config.notify_waiters();
        }
        Ok(redacted(grant))
    }

    /// A one-time code for the receiving panel; a new code replaces an unused one.
    pub fn invite_federation_grant(
        &self,
        actor: &Actor,
        id: &str,
        owner_url: &str,
    ) -> Result<Issued> {
        require_admin(actor)?;
        let owner = crate::agent::controller_url(owner_url).or_else(|e| {
            reject(
                400,
                format!("this panel's address does not work for other panels: {e:#}"),
            )
        })?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        features::require(&tx, FEATURE, WHAT)?;
        let mut grant = grant(&tx, id)?;
        if grant.state == State::Revoked {
            return reject(409, "the share is revoked");
        }
        if grant.link.is_some() {
            return reject(
                409,
                "another panel already redeemed this share; revoke it and create a new share to change who receives it",
            );
        }
        let secret = secret();
        let invite = Invite {
            id: Uuid::new_v4().to_string(),
            secret_sha256: token_hash(&secret),
            expires_at_ms: now_ms() + fed::INVITE_TTL_MS,
        };
        let issued = Issued {
            code: fed::invite_code(owner.as_str(), &invite.id, &secret),
            expires_at_ms: invite.expires_at_ms,
        };
        grant.invite = Some(invite);
        grant.updated_at_ms = now_ms();
        write(&tx, "grant", &grant.id, &grant)?;
        audit(&tx, &actor.id, "federation.grant.invite", &grant.id, "{}")?;
        tx.commit()?;
        Ok(issued)
    }

    /// Pauses, resumes or revokes a share. Revoking removes its rules from
    /// the node and stops the receiver's secret from working.
    pub fn set_federation_grant_state(
        &self,
        actor: &Actor,
        id: &str,
        state: State,
    ) -> Result<Grant> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        if state != State::Revoked {
            features::require(&tx, FEATURE, WHAT)?;
        }
        let mut grant = grant(&tx, id)?;
        if grant.state == State::Revoked {
            return reject(409, "the share is already revoked");
        }
        if grant.state == state {
            return Ok(redacted(grant));
        }
        grant.state = state;
        grant.revision += 1;
        grant.updated_at_ms = now_ms();
        if state == State::Revoked {
            grant.invite = None;
            if let Some(link) = &mut grant.link {
                link.secret_sha256.clear();
            }
            for rule in &mut grant.rules {
                rule.password = None;
            }
            set_rate(&tx, &grant.user_id, None)?;
        }
        write(&tx, "grant", &grant.id, &grant)?;
        let republished = grant.published_revision.is_some();
        if republished {
            let revision = republish(&tx, &mut self.3.lock().unwrap(), &grant.node_id)?;
            match state {
                State::Revoked => grant.revoked_revision = Some(revision),
                _ => grant.published_revision = Some(revision),
            }
            write(&tx, "grant", &grant.id, &grant)?;
        }
        let action = match state {
            State::Active => "federation.grant.resume",
            State::Paused => "federation.grant.pause",
            State::Revoked => "federation.grant.revoke",
        };
        audit(&tx, &actor.id, action, &grant.id, "{}")?;
        tx.commit()?;
        if republished {
            self.2.config.notify_waiters();
        }
        Ok(redacted(grant))
    }

    /// Only revoked shares; their account and traffic history stay.
    pub fn delete_federation_grant(&self, actor: &Actor, id: &str) -> Result<()> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let grant = grant(&tx, id)?;
        if grant.state != State::Revoked {
            return reject(409, "revoke the share before deleting it");
        }
        tx.execute("DELETE FROM metadata WHERE key=?1", [key("grant", id)])?;
        audit(&tx, &actor.id, "federation.grant.delete", id, "{}")?;
        tx.commit()?;
        Ok(())
    }

    /// The receiving panel trades the invite for its own secret.
    pub fn redeem_federation_invite(&self, request: RedeemRequest) -> Result<Redeemed> {
        if !identifier(&request.invite_id) || !identifier(&request.panel_id) {
            return reject(400, "malformed invite");
        }
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        features::require(&tx, FEATURE, WHAT)?;
        let found = all::<Grant>(&tx, "grant")?.into_iter().find(|g| {
            g.state != State::Revoked
                && g.invite.as_ref().is_some_and(|i| i.id == request.invite_id)
        });
        let Some(mut grant) = found else {
            return reject(401, "this invite is not valid; ask the owner for a new one");
        };
        let invite = grant.invite.clone().expect("found by its invite");
        if !matches(&invite.secret_sha256, &request.invite_secret) {
            return reject(401, "this invite is not valid; ask the owner for a new one");
        }
        if grant.link.is_some() {
            return reject(409, "this invite was already used");
        }
        if invite.expires_at_ms <= now_ms() {
            return reject(401, "this invite expired; ask the owner for a new one");
        }
        let secret = secret();
        grant.link = Some(Link {
            secret_sha256: token_hash(&secret),
            panel_id: request.panel_id.clone(),
            redeemed_at_ms: now_ms(),
            last_seen_ms: Some(now_ms()),
            ack: None,
        });
        write(&tx, "grant", &grant.id, &grant)?;
        audit(
            &tx,
            "federation",
            "federation.grant.redeem",
            &grant.id,
            &serde_json::json!({"panel_id": request.panel_id}).to_string(),
        )?;
        let panel = panel_id(&tx)?;
        let shared = shared(&tx, &grant, &panel)?;
        tx.commit()?;
        Ok(Redeemed { secret, shared })
    }

    pub fn peer_federation_grant(&self, secret: &str) -> Result<Shared> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut grant = by_secret(&tx, secret)?;
        features::require(&tx, FEATURE, WHAT)?;
        let now = now_ms();
        if let Some(link) = &mut grant.link
            && link
                .last_seen_ms
                .is_none_or(|seen| now - seen >= REFRESH_MS)
        {
            link.last_seen_ms = Some(now);
            write(&tx, "grant", &grant.id, &grant)?;
        }
        let panel = panel_id(&tx)?;
        let shared = shared(&tx, &grant, &panel)?;
        tx.commit()?;
        Ok(shared)
    }

    /// The receiver's rules, checked against the share and rendered by the owner.
    pub fn peer_federation_rules(&self, secret: &str, request: RulesRequest) -> Result<Shared> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut grant = by_secret(&tx, secret)?;
        features::require(&tx, FEATURE, WHAT)?;
        if grant.state == State::Paused {
            return reject(409, "the owner paused this share");
        }
        if grant.expires_at_ms.is_some_and(|at| at <= now_ms()) {
            return reject(409, "this share has expired");
        }
        if request.expected_revision != grant.revision {
            return reject(409, "the share changed; reload it and try again");
        }
        grant.rules = match fed::requested_rules(&mut grant, request.rules, fed::shadowsocks_key) {
            Ok(rules) => rules,
            Err(Refusal::Wider(message)) => return reject(403, message),
            Err(Refusal::Invalid(message)) => return reject(400, message),
        };
        grant.revision += 1;
        grant.updated_at_ms = now_ms();
        if let Some(link) = &mut grant.link {
            link.last_seen_ms = Some(now_ms());
        }
        write(&tx, "grant", &grant.id, &grant)?;
        grant.published_revision =
            Some(republish(&tx, &mut self.3.lock().unwrap(), &grant.node_id)?);
        write(&tx, "grant", &grant.id, &grant)?;
        audit(
            &tx,
            "federation",
            "federation.grant.rules",
            &grant.id,
            &serde_json::json!({"rules": grant.rules.len()}).to_string(),
        )?;
        let panel = panel_id(&tx)?;
        let shared = shared(&tx, &grant, &panel)?;
        tx.commit()?;
        self.2.config.notify_waiters();
        Ok(shared)
    }

    /// The receiver confirms the statement it saw, so a restore of the
    /// owner's data that loses traffic shows up on the owner's side too.
    pub fn peer_federation_ack(&self, secret: &str, statement: Statement) -> Result<()> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut grant = by_secret(&tx, secret)?;
        let Some(link) = &mut grant.link else {
            return reject(401, "this share was revoked or does not exist");
        };
        let changed = link.ack.as_ref().is_none_or(|ack| {
            ack.total() != statement.total() || statement.as_of_ms - ack.as_of_ms >= REFRESH_MS
        });
        if changed {
            link.ack = Some(statement);
            write(&tx, "grant", &grant.id, &grant)?;
        }
        tx.commit()?;
        Ok(())
    }

    /// Checks a received share can be added before redeeming its invite, and
    /// returns this panel's id for the owner.
    pub fn prepare_federation_remote(&self, actor: &Actor, label: &str) -> Result<String> {
        require_admin(actor)?;
        if label.trim().chars().count() > 64 {
            return reject(400, "the label has at most 64 characters");
        }
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        features::require(&tx, FEATURE, WHAT)?;
        let panel = panel_id(&tx)?;
        tx.commit()?;
        Ok(panel)
    }
    pub fn add_federation_remote(
        &self,
        actor: &Actor,
        owner_url: &str,
        label: &str,
        redeemed: Redeemed,
    ) -> Result<Remote> {
        require_admin(actor)?;
        let label = match label.trim() {
            "" => redeemed.shared.name.clone(),
            label => label.to_string(),
        };
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let remote = Remote {
            id: Uuid::new_v4().to_string(),
            owner_url: owner_url.into(),
            owner_panel_id: redeemed.shared.owner_panel_id.clone(),
            grant_id: redeemed.shared.grant_id.clone(),
            secret: redeemed.secret,
            label,
            high: redeemed.shared.statement.clone(),
            shared: Some(redeemed.shared),
            rollback: false,
            revoked: false,
            last_synced_ms: Some(now_ms()),
            last_error: None,
            added_at_ms: now_ms(),
        };
        write(&tx, "remote", &remote.id, &remote)?;
        audit(
            &tx,
            &actor.id,
            "federation.remote.add",
            &remote.id,
            &serde_json::json!({"owner_url": remote.owner_url, "grant_id": remote.grant_id})
                .to_string(),
        )?;
        tx.commit()?;
        let mut view = remote;
        view.secret.clear();
        Ok(view)
    }
    /// A received share with its secret, for talking to its owner.
    pub fn federation_remote(&self, actor: &Actor, id: &str) -> Result<Remote> {
        require_admin(actor)?;
        let conn = self.0.lock().unwrap();
        features::require(&conn, FEATURE, WHAT)?;
        remote(&conn, id)
    }
    pub fn federation_remote_access(&self, id: &str) -> Result<Remote> {
        remote(&self.0.lock().unwrap(), id)
    }
    /// Received shares the owner still accepts.
    pub fn federation_remote_ids(&self) -> Result<Vec<String>> {
        let conn = self.0.lock().unwrap();
        Ok(all::<Remote>(&conn, "remote")?
            .into_iter()
            .filter(|r| !r.revoked)
            .map(|r| r.id)
            .collect())
    }
    /// Keeps what the owner answered. Owner counters never go down, so a
    /// lower statement means the owner restored older data; that stays
    /// flagged.
    pub fn record_federation_remote(
        &self,
        id: &str,
        outcome: std::result::Result<Shared, PeerError>,
    ) -> Result<Remote> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut remote = remote(&tx, id)?;
        let before = serde_json::to_value(&remote)?;
        let now = now_ms();
        match outcome {
            Ok(shared) => {
                if shared.statement.total() < remote.high.total() {
                    remote.rollback = true;
                } else {
                    remote.high = shared.statement.clone();
                }
                remote.shared = Some(shared);
                remote.revoked = false;
                remote.last_error = None;
            }
            Err(error) => {
                remote.revoked |= error.revoked;
                remote.last_error = Some(error.message);
            }
        }
        let changed = serde_json::to_value(&remote)? != before;
        if changed
            || remote
                .last_synced_ms
                .is_none_or(|at| now - at >= REFRESH_MS)
        {
            remote.last_synced_ms = Some(now);
            write(&tx, "remote", &remote.id, &remote)?;
        }
        tx.commit()?;
        remote.secret.clear();
        Ok(remote)
    }
    pub fn delete_federation_remote(&self, actor: &Actor, id: &str) -> Result<()> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        remote(&tx, id)?;
        tx.execute("DELETE FROM metadata WHERE key=?1", [key("remote", id)])?;
        audit(&tx, &actor.id, "federation.remote.delete", id, "{}")?;
        tx.commit()?;
        Ok(())
    }
}
