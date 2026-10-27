//! Rule-template persistence in metadata and application into a node config.
use super::*;
use crate::template::{RuleTemplate, TemplateInput, validate};

fn key(id: &str) -> String {
    format!("template:{id}")
}
fn read(conn: &Connection, id: &str) -> Result<Option<RuleTemplate>> {
    let raw: Option<String> = conn
        .query_row("SELECT value FROM metadata WHERE key=?1", [key(id)], |r| {
            r.get(0)
        })
        .optional()?;
    Ok(raw.map(|value| serde_json::from_str(&value)).transpose()?)
}
fn all(conn: &Connection) -> Result<Vec<RuleTemplate>> {
    let mut q =
        conn.prepare("SELECT value FROM metadata WHERE key GLOB 'template:*' ORDER BY key")?;
    let rows: Vec<String> = q
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    rows.into_iter()
        .map(|value| serde_json::from_str(&value).context("invalid stored template"))
        .collect()
}
fn visible(actor: &Actor, template: &RuleTemplate) -> bool {
    template.tenant_id.is_none()
        || template.tenant_id.as_deref() == Some(&actor.tenant_id)
        || actor.role == Role::SystemAdmin
}
fn require_writer(actor: &Actor) -> Result<()> {
    if !matches!(actor.role, Role::SystemAdmin | Role::TenantAdmin) {
        return reject(403, "template management requires an administrator");
    }
    Ok(())
}
fn write(tx: &Transaction<'_>, value: &RuleTemplate) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key(&value.id), serde_json::to_string(value)?],
    )?;
    Ok(())
}
fn node_tenant(conn: &Connection, node: &str) -> Result<String> {
    conn.query_row("SELECT tenant_id FROM nodes WHERE id=?1", [node], |r| {
        r.get(0)
    })
    .optional()?
    .context("node not found")
}

impl Store {
    pub fn templates(&self, actor: &Actor) -> Result<Vec<RuleTemplate>> {
        let conn = self.0.lock().unwrap();
        let mut templates = all(&conn)?;
        templates.retain(|template| visible(actor, template));
        templates.sort_by_key(|template| std::cmp::Reverse(template.created_at_ms));
        Ok(templates)
    }
    pub fn create_template(&self, actor: &Actor, input: TemplateInput) -> Result<RuleTemplate> {
        require_writer(actor)?;
        validate(&input)?;
        if let Some(tenant) = input.tenant_id.as_deref() {
            if actor.role != Role::SystemAdmin && tenant != actor.tenant_id {
                return reject(403, "cannot create a template outside your tenant");
            }
        } else if actor.role != Role::SystemAdmin {
            return reject(
                403,
                "only a system administrator can create a global template",
            );
        }
        let template = RuleTemplate {
            id: Uuid::new_v4().to_string(),
            tenant_id: input.tenant_id,
            name: input.name,
            description: input.description,
            rule: input.rule,
            created_by: actor.id.clone(),
            created_at_ms: now_ms(),
        };
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        write(&tx, &template)?;
        audit(&tx, &actor.id, "template.create", &template.id, "{}")?;
        tx.commit()?;
        Ok(template)
    }
    pub fn update_template(
        &self,
        actor: &Actor,
        id: &str,
        input: TemplateInput,
    ) -> Result<RuleTemplate> {
        require_writer(actor)?;
        validate(&input)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut template = read(&tx, id)?.context("template not found")?;
        if actor.role != Role::SystemAdmin
            && (template.tenant_id.is_none()
                || template.tenant_id.as_deref() != Some(&actor.tenant_id))
        {
            return reject(403, "cannot edit this template");
        }
        if let Some(tenant) = input.tenant_id.as_deref() {
            if actor.role != Role::SystemAdmin && tenant != actor.tenant_id {
                return reject(403, "cannot move a template outside your tenant");
            }
        } else if actor.role != Role::SystemAdmin {
            return reject(
                403,
                "only a system administrator can create a global template",
            );
        }
        template.tenant_id = input.tenant_id;
        template.name = input.name;
        template.description = input.description;
        template.rule = input.rule;
        write(&tx, &template)?;
        audit(&tx, &actor.id, "template.update", &template.id, "{}")?;
        tx.commit()?;
        Ok(template)
    }
    pub fn delete_template(&self, actor: &Actor, id: &str) -> Result<()> {
        require_writer(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let template = read(&tx, id)?.context("template not found")?;
        if actor.role != Role::SystemAdmin
            && (template.tenant_id.is_none()
                || template.tenant_id.as_deref() != Some(&actor.tenant_id))
        {
            return reject(403, "cannot delete this template");
        }
        tx.execute("DELETE FROM metadata WHERE key=?1", [key(id)])?;
        audit(&tx, &actor.id, "template.delete", id, "{}")?;
        tx.commit()?;
        Ok(())
    }
    /// Validate a proposed application without writing a revision. The
    /// returned rule has the same fresh identity fields as `apply_template`.
    pub fn preview_template(
        &self,
        actor: &Actor,
        node: &str,
        template_id: &str,
        name: &str,
        listen: std::net::SocketAddr,
    ) -> Result<crate::template::TemplatePreview> {
        require_writer(actor)?;
        let (mut config, tenant, template) = {
            let conn = self.0.lock().unwrap();
            let template = read(&conn, template_id)?.context("template not found")?;
            if !visible(actor, &template) {
                return reject(403, "template belongs to another tenant");
            }
            require_node(&conn, actor, node, false)?;
            let json = conn
                .query_row(
                    "SELECT c.config_json FROM config_history c JOIN nodes n ON n.id=c.node_id AND n.desired_revision=c.revision WHERE n.id=?1",
                    [node],
                    |r| r.get::<_, String>(0),
                )
                .optional()?
                .context("configuration revision not found")?;
            (
                serde_json::from_str::<NodeConfig>(&json)?,
                node_tenant(&conn, node)?,
                template,
            )
        };
        let current_revision = config.revision;
        let mut rule = template.rule;
        rule.id = Uuid::new_v4().to_string();
        rule.tenant_id = tenant;
        rule.owner_id = actor.id.clone();
        rule.name = name.into();
        rule.listen = listen;
        rule.listen_end_port = None;
        rule.meter_epoch = Uuid::new_v4().to_string();
        rule.enabled = true;
        config.rules.push(rule.clone());
        let error = config.validate().err().map(|error| error.to_string());
        Ok(crate::template::TemplatePreview {
            node_id: node.into(),
            current_revision,
            template_id: template_id.into(),
            rule,
            valid: error.is_none(),
            error,
        })
    }
    /// Apply a template to ordered node batches. A failure in a batch stops
    /// later batches; successful nodes in that batch remain applied and are
    /// reported individually. Each node's expected revision still guards it.
    pub fn rollout_template(
        &self,
        actor: &Actor,
        template_id: &str,
        targets: &[crate::template::RolloutTarget],
        batch_size: usize,
    ) -> Result<crate::template::RolloutReport> {
        require_writer(actor)?;
        ensure!(!targets.is_empty(), "rollout requires at least one node");
        ensure!(targets.len() <= 100, "rollout supports at most 100 nodes");
        ensure!((1..=50).contains(&batch_size), "batch size must be 1..=50");
        let mut seen = std::collections::HashSet::new();
        for target in targets {
            ensure!(
                seen.insert(target.node_id.as_str()),
                "duplicate rollout node"
            );
        }
        let mut results = Vec::new();
        let mut applied = 0usize;
        let mut aborted = false;
        let mut batches = 0usize;
        for (index, batch) in targets.chunks(batch_size).enumerate() {
            batches = index + 1;
            let mut failed = false;
            for target in batch {
                match self.apply_template(
                    actor,
                    &target.node_id,
                    template_id,
                    target.expected_revision,
                    &target.name,
                    target.listen,
                ) {
                    Ok(config) => {
                        applied += 1;
                        let rule = config.rules.last();
                        results.push(crate::template::RolloutResult {
                            node_id: target.node_id.clone(),
                            batch: index + 1,
                            applied: true,
                            revision: Some(config.revision),
                            rule_id: rule.map(|rule| rule.id.clone()),
                            error: None,
                        });
                    }
                    Err(error) => {
                        failed = true;
                        results.push(crate::template::RolloutResult {
                            node_id: target.node_id.clone(),
                            batch: index + 1,
                            applied: false,
                            revision: None,
                            rule_id: None,
                            error: Some(error.to_string()),
                        });
                    }
                }
            }
            if failed {
                aborted = true;
                for target in targets.iter().skip((index + 1) * batch_size) {
                    results.push(crate::template::RolloutResult {
                        node_id: target.node_id.clone(),
                        batch: index + 2,
                        applied: false,
                        revision: None,
                        rule_id: None,
                        error: Some("not attempted after canary failure".into()),
                    });
                }
                break;
            }
        }
        Ok(crate::template::RolloutReport {
            template_id: template_id.into(),
            batch_size,
            batches,
            applied,
            aborted,
            results,
        })
    }

    /// Clone the template into a node revision. The expected revision keeps
    /// concurrent edits safe; the normal config validator rechecks listeners
    /// and references.
    pub fn apply_template(
        &self,
        actor: &Actor,
        node: &str,
        template_id: &str,
        expected_revision: u64,
        name: &str,
        listen: std::net::SocketAddr,
    ) -> Result<NodeConfig> {
        require_writer(actor)?;
        let (mut config, tenant) = {
            let conn = self.0.lock().unwrap();
            let template = read(&conn, template_id)?.context("template not found")?;
            if !visible(actor, &template) {
                return reject(403, "template belongs to another tenant");
            }
            require_node(&conn, actor, node, false)?;
            let json = conn
                .query_row(
                    "SELECT c.config_json FROM config_history c JOIN nodes n ON n.id=c.node_id AND n.desired_revision=c.revision WHERE n.id=?1",
                    [node],
                    |r| r.get::<_, String>(0),
                )
                .optional()?
                .context("configuration revision not found")?;
            (
                serde_json::from_str::<NodeConfig>(&json)?,
                node_tenant(&conn, node)?,
            )
        };
        let mut rule = {
            let conn = self.0.lock().unwrap();
            read(&conn, template_id)?
                .context("template not found")?
                .rule
        };
        rule.id = Uuid::new_v4().to_string();
        rule.tenant_id = tenant;
        rule.owner_id = actor.id.clone();
        rule.name = name.into();
        rule.listen = listen;
        rule.listen_end_port = None;
        rule.meter_epoch = Uuid::new_v4().to_string();
        rule.enabled = true;
        config.rules.push(rule);
        self.set_config_with_rate(actor, node, expected_revision, config.rules, None)
    }
}
