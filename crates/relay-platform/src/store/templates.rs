//! Rule-template persistence in metadata and application into a node config.
use super::*;
use crate::template::{RuleTemplate, TemplateInput, render_rule, validate, validate_variables};
use anyhow::bail;

fn key(id: &str) -> String {
    format!("template:{id}")
}
fn assign_template_listener(
    rule: &mut Rule,
    config: &NodeConfig,
    listen: std::net::SocketAddr,
) -> Result<()> {
    if let Some(gateway) = &mut rule.protocol_gateway {
        // The template API's listen argument always names the client endpoint.
        // Allocate a separate bridge against the current optimistic revision.
        gateway.listen = listen;
        let port = (20000..60000)
            .find(|port| {
                *port != listen.port()
                    && !config.rules.iter().any(|r| {
                        (r.listen.port()..=r.listen_end_port.unwrap_or(r.listen.port()))
                            .contains(port)
                            || r.protocol_gateway
                                .as_ref()
                                .is_some_and(|g| g.listen.port() == *port)
                    })
            })
            .context("no private gateway bridge port available")?;
        rule.listen = std::net::SocketAddr::from(([127, 0, 0, 1], port));
    } else {
        rule.listen = listen;
    }
    rule.listen_end_port = None;
    Ok(())
}
fn version_key(id: &str, version: u64) -> String {
    format!("template-version:{id}:{version}")
}
fn read_version(conn: &Connection, id: &str, version: u64) -> Result<Option<RuleTemplate>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            [version_key(id, version)],
            |row| row.get(0),
        )
        .optional()?;
    Ok(raw.map(|value| serde_json::from_str(&value)).transpose()?)
}
fn write_version(tx: &Transaction<'_>, value: &RuleTemplate) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![version_key(&value.id, value.version), serde_json::to_string(value)?],
    )?;
    Ok(())
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
fn rollout_key(id: &str) -> String {
    format!("rollout:{id}")
}
fn read_rollout(conn: &Connection, id: &str) -> Result<Option<crate::template::RolloutRecord>> {
    let raw: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            [rollout_key(id)],
            |r| r.get(0),
        )
        .optional()?;
    Ok(raw.map(|value| serde_json::from_str(&value)).transpose()?)
}
fn write_rollout(tx: &Transaction<'_>, record: &crate::template::RolloutRecord) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![rollout_key(&record.report.id), serde_json::to_string(record)?],
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
            version: 1,
            tenant_id: input.tenant_id,
            name: input.name,
            description: input.description,
            rule: input.rule,
            variables: input.variables,
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
        write_version(&tx, &template)?;
        template.version = template.version.saturating_add(1);
        template.tenant_id = input.tenant_id;
        template.name = input.name;
        template.description = input.description;
        template.rule = input.rule;
        template.variables = input.variables;
        write(&tx, &template)?;
        audit(&tx, &actor.id, "template.update", &template.id, "{}")?;
        tx.commit()?;
        Ok(template)
    }
    pub fn template_versions(&self, actor: &Actor, id: &str) -> Result<Vec<RuleTemplate>> {
        require_writer(actor)?;
        let conn = self.0.lock().unwrap();
        let current = read(&conn, id)?.context("template not found")?;
        if !visible(actor, &current) {
            return reject(403, "template belongs to another tenant");
        }
        let mut versions = vec![current];
        let mut statement =
            conn.prepare("SELECT value FROM metadata WHERE key GLOB ?1 ORDER BY key")?;
        let pattern = format!("template-version:{id}:*");
        let rows: Vec<String> = statement
            .query_map([pattern], |row| row.get(0))?
            .collect::<rusqlite::Result<_>>()?;
        for row in rows {
            versions.push(serde_json::from_str(&row).context("invalid stored template version")?);
        }
        versions.sort_by_key(|a| std::cmp::Reverse(a.version));
        versions.dedup_by_key(|template| template.version);
        Ok(versions)
    }

    pub fn template_diff(
        &self,
        actor: &Actor,
        id: &str,
        from: u64,
        to: u64,
    ) -> Result<crate::template::TemplateDiff> {
        require_writer(actor)?;
        let conn = self.0.lock().unwrap();
        let current = read(&conn, id)?.context("template not found")?;
        if !visible(actor, &current) {
            return reject(403, "template belongs to another tenant");
        }
        let resolve = |version: u64| -> Result<RuleTemplate> {
            if version == current.version {
                return Ok(current.clone());
            }
            ensure!(
                version > 0 && version < current.version,
                "template version is not available"
            );
            read_version(&conn, id, version)?.context("template version not found")
        };
        let left = resolve(from)?;
        let right = resolve(to)?;
        let mut changes = Vec::new();
        let left_value = serde_json::json!({
            "name": left.name,
            "description": left.description,
            "rule": left.rule,
            "variables": left.variables,
        });
        let right_value = serde_json::json!({
            "name": right.name,
            "description": right.description,
            "rule": right.rule,
            "variables": right.variables,
        });
        diff_values("", &left_value, &right_value, &mut changes)?;
        Ok(crate::template::TemplateDiff {
            template_id: id.into(),
            from,
            to,
            changes,
        })
    }

    pub fn rollback_template(&self, actor: &Actor, id: &str, version: u64) -> Result<RuleTemplate> {
        require_writer(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut current = read(&tx, id)?.context("template not found")?;
        if !visible(actor, &current) {
            return reject(403, "template belongs to another tenant");
        }
        if actor.role != Role::SystemAdmin
            && (current.tenant_id.is_none()
                || current.tenant_id.as_deref() != Some(&actor.tenant_id))
        {
            return reject(403, "cannot roll back this template");
        }
        if version >= current.version {
            return reject(409, "template version is not older than current");
        }
        let raw: String = tx
            .query_row(
                "SELECT value FROM metadata WHERE key=?1",
                [version_key(id, version)],
                |row| row.get(0),
            )
            .optional()?
            .context("template version not found")?;
        let snapshot: RuleTemplate =
            serde_json::from_str(&raw).context("invalid stored template version")?;
        if actor.role != Role::SystemAdmin
            && snapshot.tenant_id.as_deref() != Some(&actor.tenant_id)
        {
            return reject(403, "cannot restore this template version");
        }
        write_version(&tx, &current)?;
        current.version = current.version.saturating_add(1);
        current.tenant_id = snapshot.tenant_id;
        current.name = snapshot.name;
        current.description = snapshot.description;
        current.rule = snapshot.rule;
        current.variables = snapshot.variables;
        write(&tx, &current)?;
        audit(
            &tx,
            &actor.id,
            "template.rollback",
            id,
            &serde_json::json!({"from": current.version - 1, "to": version}).to_string(),
        )?;
        tx.commit()?;
        Ok(current)
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
        assign_template_listener(&mut rule, &config, listen)?;
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
    fn remove_rule(
        &self,
        actor: &Actor,
        node: &str,
        expected_revision: u64,
        rule_id: &str,
    ) -> Result<NodeConfig> {
        let mut config = self.config(actor, node, None)?;
        let before = config.rules.len();
        config.rules.retain(|rule| rule.id != rule_id);
        ensure!(config.rules.len() < before, "rollout rule no longer exists");
        self.set_config_with_rate(actor, node, expected_revision, config.rules, None)
    }

    /// Publish ordered batches and qualify each batch before advancing.
    #[allow(clippy::too_many_arguments)]
    pub fn rollout_template(
        &self,
        actor: &Actor,
        template_id: &str,
        targets: &[crate::template::RolloutTarget],
        batch_size: usize,
        rollback_on_failure: bool,
        canary_percent: Option<u8>,
        require_healthy: bool,
        require_target_health: bool,
        wait_for_apply_ms: Option<u64>,
    ) -> Result<crate::template::RolloutReport> {
        self.run_template_rollout(
            actor,
            template_id,
            targets,
            batch_size,
            rollback_on_failure,
            canary_percent,
            require_healthy,
            require_target_health,
            wait_for_apply_ms,
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    fn run_template_rollout(
        &self,
        actor: &Actor,
        template_id: &str,
        targets: &[crate::template::RolloutTarget],
        batch_size: usize,
        rollback_on_failure: bool,
        canary_percent: Option<u8>,
        require_healthy: bool,
        require_target_health: bool,
        wait_for_apply_ms: Option<u64>,
        previous: Option<&crate::template::RolloutRecord>,
    ) -> Result<crate::template::RolloutReport> {
        require_writer(actor)?;
        ensure!(!targets.is_empty(), "rollout requires at least one node");
        ensure!(targets.len() <= 100, "rollout supports at most 100 nodes");
        ensure!((1..=50).contains(&batch_size), "batch size must be 1..=50");
        ensure!(
            canary_percent.is_none_or(|p| (1..=100).contains(&p)),
            "canary percent must be 1..=100"
        );
        ensure!(
            wait_for_apply_ms.is_none_or(|ms| (1..=60_000).contains(&ms)),
            "wait_for_apply_ms must be 1..=60000"
        );
        let template = {
            let conn = self.0.lock().unwrap();
            let template = read(&conn, template_id)?.context("template not found")?;
            if !visible(actor, &template) {
                return reject(403, "template belongs to another tenant");
            }
            template
        };
        // Pin a release's template content so edits cannot change later batches.
        // An old unpinned record is only unambiguous while the template is v1.
        if previous.is_some()
            && template.version > 1
            && targets
                .iter()
                .any(|target| target.template_version.is_none())
        {
            return reject(
                409,
                "legacy rollout has no pinned template version; reconcile its rules before starting a new rollout",
            );
        }
        let targets: Vec<_> = targets
            .iter()
            .cloned()
            .map(|mut target| {
                target.template_version.get_or_insert(template.version);
                target
            })
            .collect();
        let mut seen = std::collections::HashSet::new();
        for target in &targets {
            ensure!(
                seen.insert(target.node_id.as_str()),
                "duplicate rollout node"
            );
            // Validate the complete cohort before any write or history replay.
            self.config(actor, &target.node_id, None)?;
        }
        let prior = |id: &str| {
            previous.and_then(|record| {
                record
                    .report
                    .results
                    .iter()
                    .find(|result| result.node_id == id)
            })
        };
        let mut results = Vec::<crate::template::RolloutResult>::new();
        let mut successes = Vec::<usize>::new();
        let mut aborted = false;
        let mut gate_error = None;
        let mut batches = 0usize;
        let first_batch = canary_percent
            .map(|percent| {
                (targets.len() * usize::from(percent))
                    .div_ceil(100)
                    .max(1)
                    .min(batch_size)
            })
            .unwrap_or(batch_size);
        let mut offset = 0;
        while offset < targets.len() {
            let size = if batches == 0 {
                first_batch
            } else {
                batch_size
            };
            let batch = &targets[offset..targets.len().min(offset + size)];
            offset += batch.len();
            batches += 1;
            let mut failed = false;
            for target in batch {
                let existing = prior(&target.node_id).filter(|r| r.applied && !r.rolled_back);
                let mut result = existing.cloned().unwrap_or_default();
                result.node_id = target.node_id.clone();
                result.batch = batches;
                result.reused = existing.is_some();
                result.acknowledged = false;
                result.healthy = false;
                result.completed = false;
                result.error = None;
                result.rollback_error = None;
                let publication = (|| -> Result<NodeConfig> {
                    let config = self.config(actor, &target.node_id, None)?;
                    if require_healthy {
                        let node = self
                            .nodes(actor)?
                            .into_iter()
                            .find(|n| n.id == target.node_id)
                            .context("node not found for health preflight")?;
                        ensure!(node.apply_error.is_none(), "node has an apply error");
                        ensure!(
                            node.last_seen_ms.is_some_and(
                                |seen| (0..=90_000).contains(&now_ms().saturating_sub(seen))
                            ),
                            "node has not synced within 90s"
                        );
                    }
                    if let Some(existing) = existing {
                        ensure!(
                            Some(config.revision) == existing.revision
                                && config
                                    .rules
                                    .iter()
                                    .any(|r| Some(&r.id) == existing.rule_id.as_ref()),
                            "rollout revision was superseded; reconcile the existing rule before retrying"
                        );
                        // Resume the gate on the original rule; never append a clone.
                        return Ok(config);
                    }
                    let expected = if previous.is_some() {
                        config.revision
                    } else {
                        target.expected_revision
                    };
                    self.apply_template_with_variables(
                        actor,
                        &target.node_id,
                        template_id,
                        expected,
                        &target.name,
                        target.listen,
                        &target.variables,
                        target.template_version,
                    )
                })();
                match publication {
                    Ok(config) => {
                        if !result.reused {
                            result.revision = Some(config.revision);
                            result.rule_id = config.rules.last().map(|r| r.id.clone());
                        }
                        result.applied = true;
                        result.rolled_back = false;
                        successes.push(results.len());
                    }
                    Err(error) => {
                        result.error = Some(error.to_string());
                        failed = true;
                    }
                }
                results.push(result);
            }
            if !failed {
                let expected: Vec<_> = results
                    .iter()
                    .filter(|r| r.batch == batches)
                    .map(|r| {
                        Ok((
                            r.node_id.clone(),
                            r.rule_id.clone().context("rollout rule missing")?,
                            r.revision.context("rollout revision missing")?,
                        ))
                    })
                    .collect::<Result<_>>()?;
                let gate = if require_target_health {
                    self.wait_for_target_health(
                        actor,
                        &expected,
                        wait_for_apply_ms.unwrap_or(5_000),
                    )
                } else if let Some(ms) = wait_for_apply_ms {
                    self.wait_for_applied(
                        actor,
                        &expected
                            .iter()
                            .map(|(id, _, rev)| (id.clone(), *rev))
                            .collect::<Vec<_>>(),
                        ms,
                    )
                } else {
                    Ok(())
                };
                if let Err(error) = gate {
                    failed = true;
                    gate_error = Some(error.to_string());
                }
                let nodes = self.nodes(actor)?;
                let now = now_ms();
                for result in results.iter_mut().filter(|r| r.batch == batches) {
                    if let Some(node) = nodes.iter().find(|n| n.id == result.node_id) {
                        result.acknowledged = result.revision.is_some_and(|revision| {
                            node.desired_revision == revision
                                && node.applied_revision == revision
                                && node.apply_error.is_none()
                        });
                        result.healthy = result.acknowledged
                            && result
                                .rule_id
                                .as_ref()
                                .is_some_and(|id| fresh_rule_health(node, id, now));
                    }
                }
                if !failed
                    && results.iter().filter(|r| r.batch == batches).any(|result| {
                        (require_target_health && !result.healthy)
                            || (wait_for_apply_ms.is_some() && !result.acknowledged)
                    })
                {
                    failed = true;
                    gate_error =
                        Some("rollout qualification changed before batch completion".into());
                }
                for result in results.iter_mut().filter(|r| r.batch == batches) {
                    result.completed = !failed;
                    if failed {
                        result.error = gate_error.clone();
                    }
                }
            }
            if failed {
                aborted = true;
                if rollback_on_failure {
                    for index in successes.iter().rev().copied() {
                        let result = &mut results[index];
                        let rollback = match (result.revision, &result.rule_id) {
                            (Some(revision), Some(rule)) => {
                                self.remove_rule(actor, &result.node_id, revision, rule)
                            }
                            _ => bail!("rollout result has no rule identity"),
                        };
                        result.completed = false;
                        match rollback {
                            Ok(_) => result.rolled_back = true,
                            Err(error) => result.rollback_error = Some(error.to_string()),
                        }
                    }
                }
                for target in targets.iter().skip(offset) {
                    // Keep any previous publication identity even when this retry
                    // stops before visiting it, so a further retry cannot clone it.
                    let mut result = prior(&target.node_id).cloned().unwrap_or_default();
                    result.node_id = target.node_id.clone();
                    result.batch = batches + 1;
                    result.completed = false;
                    result.error = Some("not attempted after canary failure".into());
                    results.push(result);
                }
                break;
            }
        }
        let report = crate::template::RolloutReport {
            id: Uuid::new_v4().to_string(),
            template_id: template_id.into(),
            batch_size,
            canary_percent,
            require_healthy,
            require_target_health,
            wait_for_apply_ms,
            gate_error,
            batches,
            applied: results.iter().filter(|r| r.applied).count(),
            rolled_back: results.iter().filter(|r| r.rolled_back).count(),
            rollback_failed: results
                .iter()
                .filter(|r| r.rollback_error.is_some())
                .count(),
            aborted,
            results,
        };
        let record = crate::template::RolloutRecord {
            root_id: previous
                .map(|r| {
                    if r.root_id.is_empty() {
                        r.report.id.clone()
                    } else {
                        r.root_id.clone()
                    }
                })
                .unwrap_or_else(|| report.id.clone()),
            retry_id: None,
            targets,
            rollback_on_failure,
            canary_percent,
            require_healthy,
            require_target_health,
            wait_for_apply_ms,
            report: report.clone(),
        };
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        write_rollout(&tx, &record)?;
        if let Some(previous) = previous {
            let mut parent = previous.clone();
            parent.retry_id = Some(report.id.clone());
            write_rollout(&tx, &parent)?;
        }
        tx.commit()?;
        Ok(report)
    }

    /// Qualify exactly the published revision. A later revision is a different
    /// operation even when it happens to retain the same rule ID.
    pub fn wait_for_target_health(
        &self,
        actor: &Actor,
        expected: &[(String, String, u64)],
        timeout_ms: u64,
    ) -> Result<()> {
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        loop {
            let nodes = self.nodes(actor)?;
            let now = now_ms();
            let mut ready = true;
            for (id, rule_id, revision) in expected {
                let node = nodes
                    .iter()
                    .find(|n| &n.id == id)
                    .context("rollout node not found")?;
                ensure!(
                    node.desired_revision == *revision && node.applied_revision <= *revision,
                    "rollout revision was superseded for node {id}"
                );
                ready &= node.applied_revision == *revision
                    && node.apply_error.is_none()
                    && fresh_rule_health(node, rule_id, now);
            }
            if ready {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                bail!(
                    "target health did not become eligible for the intended rules within {timeout_ms}ms"
                );
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    pub fn retry_rollout(
        &self,
        actor: &Actor,
        template_id: &str,
        rollout_id: &str,
    ) -> Result<crate::template::RolloutReport> {
        require_writer(actor)?;
        let first =
            read_rollout(&self.0.lock().unwrap(), rollout_id)?.context("rollout not found")?;
        ensure!(
            first.report.template_id == template_id,
            "rollout template mismatch"
        );
        {
            let conn = self.0.lock().unwrap();
            let template = read(&conn, template_id)?.context("template not found")?;
            if !visible(actor, &template) {
                return reject(403, "template belongs to another tenant");
            }
        }
        let root = if first.root_id.is_empty() {
            first.report.id.clone()
        } else {
            first.root_id.clone()
        };
        let _guard = RetryGuard::acquire(&self.7, &root)?;
        let mut record =
            read_rollout(&self.0.lock().unwrap(), &root)?.context("rollout root missing")?;
        let mut seen = std::collections::HashSet::new();
        while let Some(next) = record.retry_id.as_ref() {
            ensure!(seen.insert(record.report.id.clone()), "rollout retry cycle");
            record =
                read_rollout(&self.0.lock().unwrap(), next)?.context("rollout retry missing")?;
            ensure!(
                record.report.template_id == template_id,
                "rollout template mismatch"
            );
        }
        for target in &record.targets {
            self.config(actor, &target.node_id, None)?;
        }
        if !record.report.aborted {
            return Ok(record.report);
        }
        self.run_template_rollout(
            actor,
            template_id,
            &record.targets,
            record.report.batch_size,
            record.rollback_on_failure,
            record.canary_percent,
            record.require_healthy,
            record.require_target_health,
            record.wait_for_apply_ms,
            Some(&record),
        )
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
        self.apply_template_with_variables(
            actor,
            node,
            template_id,
            expected_revision,
            name,
            listen,
            &std::collections::BTreeMap::new(),
            None,
        )
    }

    #[allow(clippy::too_many_arguments)]
    pub fn apply_template_with_variables(
        &self,
        actor: &Actor,
        node: &str,
        template_id: &str,
        expected_revision: u64,
        name: &str,
        listen: std::net::SocketAddr,
        overrides: &std::collections::BTreeMap<String, String>,
        template_version: Option<u64>,
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
        let (raw_rule, mut variables) = {
            let conn = self.0.lock().unwrap();
            let current = read(&conn, template_id)?.context("template not found")?;
            let template = match template_version {
                None => current,
                Some(version) if version == current.version => current,
                Some(version) => {
                    ensure!(
                        version > 0 && version < current.version,
                        "template version is not available"
                    );
                    read_version(&conn, template_id, version)?
                        .context("template version not found")?
                }
            };
            (template.rule, template.variables)
        };
        validate_variables(overrides)?;
        variables.extend(overrides.clone());
        let mut rule = render_rule(&raw_rule, &variables)?;
        rule.id = Uuid::new_v4().to_string();
        rule.tenant_id = tenant;
        rule.owner_id = actor.id.clone();
        rule.name = name.into();
        assign_template_listener(&mut rule, &config, listen)?;
        rule.meter_epoch = Uuid::new_v4().to_string();
        rule.enabled = true;
        config.rules.push(rule);
        self.set_config_with_rate(actor, node, expected_revision, config.rules, None)
    }

    fn wait_for_applied(
        &self,
        actor: &Actor,
        expected: &[(String, u64)],
        timeout_ms: u64,
    ) -> Result<()> {
        ensure!(timeout_ms > 0, "wait_for_apply_ms must be positive");
        let deadline = std::time::Instant::now() + std::time::Duration::from_millis(timeout_ms);
        loop {
            let nodes = self.nodes(actor)?;
            let mut pending = 0usize;
            for (node_id, revision) in expected {
                let node = nodes.iter().find(|node| &node.id == node_id);
                if let Some(node) = node {
                    ensure!(
                        node.desired_revision == *revision && node.applied_revision <= *revision,
                        "rollout revision was superseded for node {node_id}"
                    );
                }
                if node.is_none_or(|node| {
                    node.applied_revision != *revision || node.apply_error.is_some()
                }) {
                    pending += 1;
                }
            }
            if pending == 0 {
                return Ok(());
            }
            if std::time::Instant::now() >= deadline {
                bail!("{pending} node(s) did not apply revision within {timeout_ms} ms");
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }
}

fn fresh_rule_health(node: &Node, rule_id: &str, now: i64) -> bool {
    let reports: Vec<_> = node
        .stats
        .target_health
        .iter()
        .filter(|r| r.rule_id == rule_id)
        .collect();
    !reports.is_empty()
        && reports.iter().all(|target| {
            target.eligible
                && target
                    .checked_at_ms
                    .and_then(|checked| now.checked_sub(checked))
                    .and_then(|age| u64::try_from(age).ok())
                    .is_some_and(|age| age <= target.max_age_ms)
                && target
                    .sample_age_ms
                    .is_some_and(|age| age <= target.max_age_ms)
        })
}

struct RetryGuard<'a> {
    active: &'a Mutex<std::collections::HashSet<String>>,
    id: String,
}
impl<'a> RetryGuard<'a> {
    fn acquire(active: &'a Mutex<std::collections::HashSet<String>>, id: &str) -> Result<Self> {
        if !active.lock().unwrap().insert(id.into()) {
            return reject(409, "rollout retry already in progress");
        }
        Ok(Self {
            active,
            id: id.into(),
        })
    }
}
impl Drop for RetryGuard<'_> {
    fn drop(&mut self) {
        self.active.lock().unwrap().remove(&self.id);
    }
}

fn diff_values(
    path: &str,
    left: &serde_json::Value,
    right: &serde_json::Value,
    changes: &mut Vec<crate::template::DiffChange>,
) -> Result<()> {
    if left == right {
        return Ok(());
    }
    ensure!(changes.len() < 512, "template diff is too large");
    match (left, right) {
        (serde_json::Value::Object(left), serde_json::Value::Object(right)) => {
            let mut keys: Vec<_> = left.keys().chain(right.keys()).cloned().collect();
            keys.sort();
            keys.dedup();
            for key in keys {
                let child = format!("{path}/{}", key.replace('~', "~0").replace('/', "~1"));
                match (left.get(&key), right.get(&key)) {
                    (Some(a), Some(b)) => diff_values(&child, a, b, changes)?,
                    (Some(a), None) => changes.push(crate::template::DiffChange {
                        path: child,
                        from: Some(a.clone()),
                        to: None,
                    }),
                    (None, Some(b)) => changes.push(crate::template::DiffChange {
                        path: child,
                        from: None,
                        to: Some(b.clone()),
                    }),
                    (None, None) => {}
                }
            }
        }
        (serde_json::Value::Array(left), serde_json::Value::Array(right)) => {
            for index in 0..left.len().max(right.len()) {
                let child = format!("{path}/{index}");
                match (left.get(index), right.get(index)) {
                    (Some(a), Some(b)) => diff_values(&child, a, b, changes)?,
                    (Some(a), None) => changes.push(crate::template::DiffChange {
                        path: child,
                        from: Some(a.clone()),
                        to: None,
                    }),
                    (None, Some(b)) => changes.push(crate::template::DiffChange {
                        path: child,
                        from: None,
                        to: Some(b.clone()),
                    }),
                    (None, None) => {}
                }
            }
        }
        _ => changes.push(crate::template::DiffChange {
            path: if path.is_empty() {
                "/".into()
            } else {
                path.into()
            },
            from: Some(left.clone()),
            to: Some(right.clone()),
        }),
    }
    Ok(())
}

fn now_ms() -> i64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|elapsed| elapsed.as_millis() as i64)
        .unwrap_or_default()
}

#[cfg(test)]
mod retry_tests {
    use super::*;
    #[test]
    fn concurrent_retry_guard_is_scoped_to_the_root_and_released_on_drop() {
        let active = std::sync::Mutex::new(std::collections::HashSet::new());
        let first = RetryGuard::acquire(&active, "root-a").unwrap();
        assert!(RetryGuard::acquire(&active, "root-a").is_err());
        let independent = RetryGuard::acquire(&active, "root-b").unwrap();
        drop(first);
        assert!(RetryGuard::acquire(&active, "root-a").is_ok());
        drop(independent);
        assert!(active.lock().unwrap().is_empty());
    }
}
