//! Rule-template persistence in metadata and application into a node config.
use super::*;
use crate::template::{RuleTemplate, TemplateInput, render_rule, validate, validate_variables};

fn key(id: &str) -> String {
    format!("template:{id}")
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

    /// Apply a template to ordered node batches. A failure in a batch stops
    /// later batches; successful nodes in that batch remain applied and are
    /// reported individually. Each node's expected revision still guards it.
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
    ) -> Result<crate::template::RolloutReport> {
        require_writer(actor)?;
        ensure!(!targets.is_empty(), "rollout requires at least one node");
        ensure!(targets.len() <= 100, "rollout supports at most 100 nodes");
        ensure!((1..=50).contains(&batch_size), "batch size must be 1..=50");
        ensure!(
            canary_percent.is_none_or(|percent| (1..=100).contains(&percent)),
            "canary percent must be 1..=100"
        );
        let mut seen = std::collections::HashSet::new();
        for target in targets {
            ensure!(
                seen.insert(target.node_id.as_str()),
                "duplicate rollout node"
            );
        }
        let health = if require_healthy {
            Some(
                self.nodes(actor)?
                    .into_iter()
                    .map(|node| (node.id.clone(), node))
                    .collect::<std::collections::HashMap<_, _>>(),
            )
        } else {
            None
        };
        let mut results = Vec::new();
        let mut applied = 0usize;
        let mut rolled_back = 0usize;
        let mut rollback_failed = 0usize;
        let mut successes = Vec::<usize>::new();
        let mut aborted = false;
        let mut batches = 0usize;
        let first_batch = canary_percent
            .map(|percent| {
                (targets.len() * usize::from(percent))
                    .div_ceil(100)
                    .max(1)
                    .min(batch_size)
            })
            .unwrap_or(batch_size);
        let mut offset = 0usize;
        let mut index = 0usize;
        while offset < targets.len() {
            let size = if index == 0 { first_batch } else { batch_size };
            let batch = &targets[offset..targets.len().min(offset + size)];
            offset += batch.len();
            index += 1;
            batches = index;
            let mut failed = false;
            for target in batch {
                if let Some(nodes) = &health {
                    let Some(node) = nodes.get(&target.node_id) else {
                        failed = true;
                        results.push(crate::template::RolloutResult {
                            node_id: target.node_id.clone(),
                            batch: index,
                            applied: false,
                            revision: None,
                            rule_id: None,
                            error: Some("node not found for health preflight".into()),
                            rolled_back: false,
                            rollback_error: None,
                        });
                        continue;
                    };
                    let healthy = node.apply_error.is_none()
                        && node
                            .last_seen_ms
                            .is_some_and(|seen| now_ms() - seen <= 90_000);
                    if !healthy {
                        failed = true;
                        results.push(crate::template::RolloutResult {
                            node_id: target.node_id.clone(),
                            batch: index,
                            applied: false,
                            revision: None,
                            rule_id: None,
                            error: Some(if node.apply_error.is_some() {
                                "node has an apply error".into()
                            } else {
                                "node has not synced within 90s".into()
                            }),
                            rolled_back: false,
                            rollback_error: None,
                        });
                        continue;
                    }
                }
                match self.apply_template_with_variables(
                    actor,
                    &target.node_id,
                    template_id,
                    target.expected_revision,
                    &target.name,
                    target.listen,
                    &target.variables,
                    target.template_version,
                ) {
                    Ok(config) => {
                        applied += 1;
                        let rule = config.rules.last();
                        results.push(crate::template::RolloutResult {
                            node_id: target.node_id.clone(),
                            batch: index,
                            applied: true,
                            revision: Some(config.revision),
                            rule_id: rule.map(|rule| rule.id.clone()),
                            error: None,
                            rolled_back: false,
                            rollback_error: None,
                        });
                        successes.push(results.len() - 1);
                    }
                    Err(error) => {
                        failed = true;
                        results.push(crate::template::RolloutResult {
                            node_id: target.node_id.clone(),
                            batch: index,
                            applied: false,
                            revision: None,
                            rule_id: None,
                            error: Some(error.to_string()),
                            rolled_back: false,
                            rollback_error: None,
                        });
                    }
                }
            }
            if failed {
                aborted = true;
                if rollback_on_failure {
                    for result_index in successes.iter().rev().copied() {
                        let (node_id, revision, rule_id) = {
                            let result = &results[result_index];
                            (
                                result.node_id.clone(),
                                result.revision,
                                result.rule_id.clone(),
                            )
                        };
                        let outcome = match (revision, rule_id) {
                            (Some(revision), Some(rule_id)) => {
                                self.remove_rule(actor, &node_id, revision, &rule_id)
                            }
                            _ => Err(anyhow::anyhow!("rollout result has no rule identity")),
                        };
                        match outcome {
                            Ok(_) => {
                                rolled_back += 1;
                                results[result_index].rolled_back = true;
                            }
                            Err(error) => {
                                rollback_failed += 1;
                                results[result_index].rollback_error = Some(error.to_string());
                            }
                        }
                    }
                }
                for target in targets.iter().skip(offset) {
                    results.push(crate::template::RolloutResult {
                        node_id: target.node_id.clone(),
                        batch: index + 1,
                        applied: false,
                        revision: None,
                        rule_id: None,
                        error: Some("not attempted after canary failure".into()),
                        rolled_back: false,
                        rollback_error: None,
                    });
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
            batches,
            applied,
            rolled_back,
            rollback_failed,
            aborted,
            results,
        };
        let record = crate::template::RolloutRecord {
            targets: targets.to_vec(),
            rollback_on_failure,
            canary_percent,
            require_healthy,
            report: report.clone(),
        };
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        write_rollout(&tx, &record)?;
        tx.commit()?;
        Ok(report)
    }

    pub fn retry_rollout(
        &self,
        actor: &Actor,
        template_id: &str,
        rollout_id: &str,
    ) -> Result<crate::template::RolloutReport> {
        require_writer(actor)?;
        let record = {
            let conn = self.0.lock().unwrap();
            read_rollout(&conn, rollout_id)?.context("rollout not found")?
        };
        ensure!(
            record.report.template_id == template_id,
            "rollout template mismatch"
        );
        let mut retry = Vec::new();
        for result in record
            .report
            .results
            .iter()
            .filter(|result| !result.applied)
        {
            let target = record
                .targets
                .iter()
                .find(|target| target.node_id == result.node_id)
                .context("rollout target missing")?;
            let revision = self.config(actor, &target.node_id, None)?.revision;
            retry.push(crate::template::RolloutTarget {
                expected_revision: revision,
                ..target.clone()
            });
        }
        ensure!(!retry.is_empty(), "rollout has no failed targets to retry");
        self.rollout_template(
            actor,
            template_id,
            &retry,
            record.report.batch_size,
            record.rollback_on_failure,
            record.canary_percent,
            record.require_healthy,
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
        rule.listen = listen;
        rule.listen_end_port = None;
        rule.meter_epoch = Uuid::new_v4().to_string();
        rule.enabled = true;
        config.rules.push(rule);
        self.set_config_with_rate(actor, node, expected_revision, config.rules, None)
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
