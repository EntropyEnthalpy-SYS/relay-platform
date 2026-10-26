//! Announcement persistence in metadata, with global/tenant visibility.
use super::*;
use crate::announcement::{Announcement, AnnouncementDraft, Severity, active};

fn key(id: &str) -> String {
    format!("announcement:{id}")
}
fn read(conn: &Connection, id: &str) -> Result<Option<Announcement>> {
    let raw: Option<String> = conn
        .query_row("SELECT value FROM metadata WHERE key=?1", [key(id)], |r| {
            r.get(0)
        })
        .optional()?;
    Ok(raw.map(|value| serde_json::from_str(&value)).transpose()?)
}
fn write(tx: &Transaction<'_>, value: &Announcement) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key(&value.id), serde_json::to_string(value)?],
    )?;
    Ok(())
}
impl Store {
    /// Active announcements visible to this actor, newest/highest severity first.
    pub fn announcements(&self, actor: &Actor) -> Result<Vec<Announcement>> {
        let conn = self.0.lock().unwrap();
        let mut values: Vec<Announcement> = all(&conn)?;
        values.retain(|value| active(value, &actor.tenant_id, now_ms()));
        values.sort_by_key(|value| {
            (
                std::cmp::Reverse(severity_rank(value.severity)),
                std::cmp::Reverse(value.starts_at_ms),
            )
        });
        Ok(values)
    }
    /// Management view. System administrators see all; tenant administrators
    /// see their tenant and global announcements (global ones read-only).
    pub fn manage_announcements(&self, actor: &Actor) -> Result<Vec<Announcement>> {
        if !matches!(actor.role, Role::SystemAdmin | Role::TenantAdmin) {
            return reject(403, "announcement management requires an administrator");
        }
        let conn = self.0.lock().unwrap();
        let mut values = all(&conn)?;
        if actor.role == Role::TenantAdmin {
            values.retain(|value| {
                value.tenant_id.is_none() || value.tenant_id.as_deref() == Some(&actor.tenant_id)
            });
        }
        values.sort_by_key(|value| std::cmp::Reverse(value.created_at_ms));
        Ok(values)
    }
    pub fn create_announcement(
        &self,
        actor: &Actor,
        draft: AnnouncementDraft,
    ) -> Result<Announcement> {
        if !matches!(actor.role, Role::SystemAdmin | Role::TenantAdmin) {
            return reject(403, "announcement management requires an administrator");
        }
        if let Some(tenant) = draft.tenant_id.as_deref() {
            if !actor.permits_tenant(tenant)
                || actor.role == Role::TenantAdmin && tenant != actor.tenant_id
            {
                return reject(403, "cannot publish outside your tenant");
            }
        } else if actor.role != Role::SystemAdmin {
            return reject(
                403,
                "only a system administrator can publish a global announcement",
            );
        }
        crate::announcement::validate(
            &draft.title,
            &draft.body,
            draft.starts_at_ms,
            draft.ends_at_ms,
        )?;
        if let Some(tenant) = draft.tenant_id.as_deref() {
            let mut conn = self.0.lock().unwrap();
            let tx = conn.transaction()?;
            ensure_tenant(&tx, tenant)?;
            let value = Announcement {
                id: Uuid::new_v4().to_string(),
                tenant_id: Some(tenant.into()),
                title: draft.title,
                body: draft.body,
                severity: draft.severity,
                starts_at_ms: draft.starts_at_ms,
                ends_at_ms: draft.ends_at_ms,
                enabled: draft.enabled,
                created_by: actor.id.clone(),
                created_at_ms: now_ms(),
            };
            write(&tx, &value)?;
            audit(&tx, &actor.id, "announcement.create", &value.id, "{}")?;
            tx.commit()?;
            return Ok(value);
        }
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let value = Announcement {
            id: Uuid::new_v4().to_string(),
            tenant_id: None,
            title: draft.title,
            body: draft.body,
            severity: draft.severity,
            starts_at_ms: draft.starts_at_ms,
            ends_at_ms: draft.ends_at_ms,
            enabled: draft.enabled,
            created_by: actor.id.clone(),
            created_at_ms: now_ms(),
        };
        write(&tx, &value)?;
        audit(&tx, &actor.id, "announcement.create", &value.id, "{}")?;
        tx.commit()?;
        Ok(value)
    }
    pub fn update_announcement(
        &self,
        actor: &Actor,
        id: &str,
        draft: AnnouncementDraft,
    ) -> Result<Announcement> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut value = read(&tx, id)?.context("announcement not found")?;
        if actor.role == Role::TenantAdmin
            && (value.tenant_id.is_none() || value.tenant_id.as_deref() != Some(&actor.tenant_id))
        {
            return reject(403, "cannot edit this announcement");
        }
        if actor.role != Role::SystemAdmin && actor.role != Role::TenantAdmin {
            return reject(403, "announcement management requires an administrator");
        }
        crate::announcement::validate(
            &draft.title,
            &draft.body,
            draft.starts_at_ms,
            draft.ends_at_ms,
        )?;
        value.title = draft.title;
        value.body = draft.body;
        value.severity = draft.severity;
        value.starts_at_ms = draft.starts_at_ms;
        value.ends_at_ms = draft.ends_at_ms;
        value.enabled = draft.enabled;
        write(&tx, &value)?;
        audit(&tx, &actor.id, "announcement.update", &value.id, "{}")?;
        tx.commit()?;
        Ok(value)
    }
    pub fn delete_announcement(&self, actor: &Actor, id: &str) -> Result<()> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let value = read(&tx, id)?.context("announcement not found")?;
        if actor.role != Role::SystemAdmin
            && (actor.role != Role::TenantAdmin
                || value.tenant_id.as_deref() != Some(&actor.tenant_id))
        {
            return reject(403, "cannot delete this announcement");
        }
        tx.execute("DELETE FROM metadata WHERE key=?1", [key(id)])?;
        audit(&tx, &actor.id, "announcement.delete", id, "{}")?;
        tx.commit()?;
        Ok(())
    }
}

fn severity_rank(value: Severity) -> u8 {
    match value {
        Severity::Critical => 2,
        Severity::Warning => 1,
        Severity::Info => 0,
    }
}
fn all(conn: &Connection) -> Result<Vec<Announcement>> {
    let mut q =
        conn.prepare("SELECT value FROM metadata WHERE key GLOB 'announcement:*' ORDER BY key")?;
    let rows: Vec<String> = q
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    rows.into_iter()
        .map(|value| serde_json::from_str(&value).context("invalid stored announcement"))
        .collect()
}
fn ensure_tenant(conn: &Connection, tenant: &str) -> Result<()> {
    if !conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM tenants WHERE id=?1)",
        [tenant],
        |r| r.get::<_, bool>(0),
    )? {
        return reject(404, "tenant not found");
    }
    Ok(())
}
