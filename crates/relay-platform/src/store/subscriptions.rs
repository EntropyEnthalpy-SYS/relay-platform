//! Client subscriptions persisted in `metadata`, so schema v5 and the recovery
//! journal remain unchanged. Token hashes are indexed separately from records.
use super::*;
use crate::node::NodeLifecycle;
use crate::subscription::{
    self, Candidate, Format, MAX_SUBSCRIPTIONS, Rendered, Subscription, SubscriptionView, Template,
};

fn record_key(id: &str) -> String {
    format!("subscription:{id}")
}
fn index_key(hash: &str) -> String {
    format!("subscription_token:{hash}")
}
fn validate_name(name: &str) -> Result<()> {
    if name.is_empty()
        || name.len() > 120
        || name.trim() != name
        || name.chars().any(char::is_control)
    {
        return reject(
            400,
            "subscription name must contain 1..120 bytes without surrounding whitespace or control characters",
        );
    }
    Ok(())
}
fn read_record(conn: &Connection, id: &str) -> Result<Option<Subscription>> {
    let value: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            [record_key(id)],
            |r| r.get(0),
        )
        .optional()?;
    Ok(value.map(|s| serde_json::from_str(&s)).transpose()?)
}
fn write_record(tx: &Transaction<'_>, record: &Subscription) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![record_key(&record.id), serde_json::to_string(record)?],
    )?;
    Ok(())
}
fn owner_is_system_admin(conn: &Connection, record: &Subscription) -> Result<bool> {
    Ok(conn
        .query_row(
            "SELECT role='system_admin' FROM users WHERE id=?1 AND tenant_id=?2",
            params![record.owner_id, record.tenant_id],
            |r| r.get(0),
        )
        .optional()?
        .unwrap_or(false))
}
fn visible(conn: &Connection, actor: &Actor, record: &Subscription) -> Result<bool> {
    if actor.role == Role::SystemAdmin {
        return Ok(true);
    }
    if !actor.permits_tenant(&record.tenant_id) {
        return Ok(false);
    }
    if actor.id == record.owner_id {
        return Ok(true);
    }
    Ok(actor.role == Role::TenantAdmin && !owner_is_system_admin(conn, record)?)
}
fn manager(conn: &Connection, actor: &Actor, record: &Subscription) -> Result<()> {
    if !actor.may_write() {
        return reject(403, "read-only users cannot manage subscriptions");
    }
    if !visible(conn, actor, record)? {
        return reject(403, "subscription belongs to another user or tenant");
    }
    Ok(())
}
fn owner_actor(conn: &Connection, actor: &Actor, owner: Option<&str>) -> Result<Actor> {
    let Some(owner) = owner else {
        if !actor.may_write() {
            return reject(403, "read-only users cannot create subscriptions");
        }
        return Ok(actor.clone());
    };
    super::accounts::require_user_manager(conn, actor, owner)
}
impl Store {
    pub fn create_subscription(
        &self,
        actor: &Actor,
        owner: Option<&str>,
        name: &str,
        format: Format,
        template: Template,
        expires_in_days: u32,
    ) -> Result<(SubscriptionView, String)> {
        validate_name(name)?;
        template.validate()?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let owner = owner_actor(&tx, actor, owner)?;
        let existing: u64 = tx.query_row(
            "SELECT COUNT(*) FROM metadata WHERE key GLOB 'subscription:*' AND key NOT GLOB 'subscription_token:*' AND json_extract(value,'$.owner_id')=?1",
            [&owner.id],
            |r| r.get(0),
        )?;
        if existing >= MAX_SUBSCRIPTIONS as u64 {
            return reject(
                409,
                format!("a user may keep at most {MAX_SUBSCRIPTIONS} subscriptions"),
            );
        }
        let value = subscription::token();
        let record = Subscription {
            id: Uuid::new_v4().to_string(),
            tenant_id: owner.tenant_id.clone(),
            owner_id: owner.id.clone(),
            name: name.into(),
            format,
            template,
            token_hash: subscription::token_hash(&value),
            created_at_ms: now_ms(),
            expires_at_ms: Some(subscription::expiry(now_ms(), expires_in_days)?),
            last_used_ms: None,
            uses: 0,
        };
        write_record(&tx, &record)?;
        tx.execute(
            "INSERT INTO metadata(key,value) VALUES(?1,?2)",
            params![index_key(&record.token_hash), record.id],
        )?;
        audit(
            &tx,
            &actor.id,
            "subscription.create",
            &record.id,
            &serde_json::json!({"owner_id":record.owner_id,"format":record.format,"name":record.name}).to_string(),
        )?;
        tx.commit()?;
        Ok((SubscriptionView::from(&record), value))
    }

    pub fn subscriptions(&self, actor: &Actor) -> Result<Vec<SubscriptionView>> {
        let conn = self.0.lock().unwrap();
        let mut q = conn.prepare(
            "SELECT value FROM metadata WHERE key GLOB 'subscription:*' AND key NOT GLOB 'subscription_token:*' ORDER BY key",
        )?;
        let records: Vec<Subscription> = q
            .query_map([], |r| r.get::<_, String>(0))?
            .collect::<rusqlite::Result<Vec<_>>>()?
            .into_iter()
            .map(|value| serde_json::from_str(&value).context("invalid stored subscription"))
            .collect::<Result<Vec<_>>>()?;
        let mut views = vec![];
        for record in records {
            if visible(&conn, actor, &record)? {
                views.push(SubscriptionView::from(&record));
            }
        }
        Ok(views)
    }

    pub fn subscription(&self, actor: &Actor, id: &str) -> Result<SubscriptionView> {
        let conn = self.0.lock().unwrap();
        let record = read_record(&conn, id)?.context("subscription not found")?;
        if !visible(&conn, actor, &record)? {
            return reject(403, "subscription belongs to another user or tenant");
        }
        Ok(SubscriptionView::from(&record))
    }

    pub fn rotate_subscription(
        &self,
        actor: &Actor,
        id: &str,
    ) -> Result<(SubscriptionView, String)> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut record = read_record(&tx, id)?.context("subscription not found")?;
        manager(&tx, actor, &record)?;
        let old = record.token_hash.clone();
        let value = subscription::token();
        record.token_hash = subscription::token_hash(&value);
        record.last_used_ms = None;
        record.uses = 0;
        write_record(&tx, &record)?;
        tx.execute("DELETE FROM metadata WHERE key=?1", [index_key(&old)])?;
        tx.execute(
            "INSERT INTO metadata(key,value) VALUES(?1,?2)",
            params![index_key(&record.token_hash), record.id],
        )?;
        audit(
            &tx,
            &actor.id,
            "subscription.rotate",
            &record.id,
            &serde_json::json!({"owner_id":record.owner_id}).to_string(),
        )?;
        tx.commit()?;
        Ok((SubscriptionView::from(&record), value))
    }

    pub fn delete_subscription(&self, actor: &Actor, id: &str) -> Result<()> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let record = read_record(&tx, id)?.context("subscription not found")?;
        manager(&tx, actor, &record)?;
        tx.execute("DELETE FROM metadata WHERE key=?1", [record_key(id)])?;
        tx.execute(
            "DELETE FROM metadata WHERE key=?1",
            [index_key(&record.token_hash)],
        )?;
        audit(
            &tx,
            &actor.id,
            "subscription.delete",
            id,
            &serde_json::json!({"owner_id":record.owner_id}).to_string(),
        )?;
        tx.commit()?;
        Ok(())
    }

    /// Renders a managed subscription after checking visibility.
    pub fn render_subscription(&self, actor: &Actor, id: &str) -> Result<Rendered> {
        let conn = self.0.lock().unwrap();
        let record = read_record(&conn, id)?.context("subscription not found")?;
        if !visible(&conn, actor, &record)? {
            return reject(403, "subscription belongs to another user or tenant");
        }
        let candidates = candidates(&conn, &record)?;
        subscription::render(record.format, &record.template, &candidates)
    }

    /// Public rendering by opaque token. The token is independent of a login
    /// session and can be rotated or deleted without touching the account.
    pub fn render_public_subscription(&self, token: &str) -> Result<Rendered> {
        if !token.starts_with(subscription::TOKEN_PREFIX)
            || token.len() != subscription::TOKEN_PREFIX.len() + 64
            || !token[subscription::TOKEN_PREFIX.len()..]
                .bytes()
                .all(|b| b.is_ascii_hexdigit())
        {
            return reject(401, "subscription token invalid or expired");
        }
        let hash = subscription::token_hash(token);
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let id: Option<String> = tx
            .query_row(
                "SELECT value FROM metadata WHERE key=?1",
                [index_key(&hash)],
                |r| r.get(0),
            )
            .optional()?;
        let Some(record) = id
            .as_deref()
            .map(|id| read_record(&tx, id))
            .transpose()?
            .flatten()
            .filter(|record| record.token_hash == hash)
        else {
            return reject(401, "subscription token invalid or expired");
        };
        if record
            .expires_at_ms
            .is_some_and(|expiry| expiry <= now_ms())
        {
            return reject(401, "subscription token invalid or expired");
        }
        let enabled: bool = tx
            .query_row(
                "SELECT disabled=0 FROM users WHERE id=?1 AND tenant_id=?2",
                params![record.owner_id, record.tenant_id],
                |r| r.get(0),
            )
            .optional()?
            .unwrap_or(false);
        if !enabled {
            return reject(401, "subscription token invalid or expired");
        }
        let candidates = candidates(&tx, &record)?;
        let rendered = subscription::render(record.format, &record.template, &candidates)?;
        if rendered.entries.is_empty() {
            return reject(
                409,
                "subscription has no compatible enabled Shadowsocks entries; see the preview for skipped rules",
            );
        }
        if record
            .last_used_ms
            .is_none_or(|last| now_ms().saturating_sub(last) >= 60_000)
        {
            let mut updated = record.clone();
            updated.last_used_ms = Some(now_ms());
            updated.uses = updated.uses.saturating_add(1);
            write_record(&tx, &updated)?;
        }
        tx.commit()?;
        Ok(rendered)
    }
}

fn candidates(conn: &Connection, record: &Subscription) -> Result<Vec<Candidate>> {
    let mut q = conn.prepare(
        "SELECT n.id,n.name,c.config_json FROM nodes n JOIN config_history c ON c.node_id=n.id AND c.revision=n.desired_revision WHERE n.tenant_id=?1 ORDER BY n.name,n.id",
    )?;
    let nodes: Vec<(String, String, String)> = q
        .query_map([&record.tenant_id], |r| {
            Ok((r.get(0)?, r.get(1)?, r.get(2)?))
        })?
        .collect::<rusqlite::Result<_>>()?;
    drop(q);
    let mut candidates = vec![];
    for (node_id, node_name, config_json) in nodes {
        let profile = super::node_profiles::read(conn, &node_id)?;
        if profile.settings.lifecycle(now_ms()) != NodeLifecycle::Active {
            continue;
        }
        let config: NodeConfig = serde_json::from_str(&config_json)?;
        for rule in config.rules {
            if rule.owner_id != record.owner_id || rule.tenant_id != record.tenant_id {
                continue;
            }
            candidates.push(Candidate {
                node_name: node_name.clone(),
                node_tags: profile.settings.tags.clone(),
                rule,
            });
        }
    }
    Ok(candidates)
}
