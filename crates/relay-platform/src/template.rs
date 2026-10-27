//! Reusable rule templates. A template stores a validated rule body; applying
//! it clones the body into a node configuration with a fresh identity, name,
//! listen address and meter epoch.
use crate::model::{Rule, now_ms};
use anyhow::{Context, Result, bail, ensure};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

fn default_version() -> u64 {
    1
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleTemplate {
    pub id: String,
    #[serde(default = "default_version")]
    pub version: u64,
    /// `None` is global; `Some` is visible only inside that tenant.
    pub tenant_id: Option<String>,
    pub name: String,
    pub description: String,
    pub rule: Rule,
    #[serde(default)]
    pub variables: BTreeMap<String, String>,
    pub created_by: String,
    pub created_at_ms: i64,
}
#[derive(Clone, Debug, Serialize)]
pub struct TemplatePreview {
    pub node_id: String,
    pub current_revision: u64,
    pub template_id: String,
    pub rule: Rule,
    pub valid: bool,
    pub error: Option<String>,
}
#[derive(Clone, Debug, Deserialize)]
pub struct RolloutTargetInput {
    pub node_id: String,
    pub expected_revision: u64,
    pub name: String,
    pub listen: String,
    #[serde(default)]
    pub variables: BTreeMap<String, String>,
    #[serde(default)]
    pub template_version: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RolloutTarget {
    pub node_id: String,
    pub expected_revision: u64,
    pub name: String,
    pub listen: std::net::SocketAddr,
    #[serde(default)]
    pub variables: BTreeMap<String, String>,
    #[serde(default)]
    pub template_version: Option<u64>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RolloutResult {
    pub node_id: String,
    pub batch: usize,
    pub applied: bool,
    pub revision: Option<u64>,
    pub rule_id: Option<String>,
    pub error: Option<String>,
    #[serde(default)]
    pub rolled_back: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rollback_error: Option<String>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RolloutReport {
    pub id: String,
    pub template_id: String,
    pub batch_size: usize,
    pub batches: usize,
    pub applied: usize,
    pub rolled_back: usize,
    pub rollback_failed: usize,
    pub aborted: bool,
    pub results: Vec<RolloutResult>,
}
#[derive(Clone, Debug, Serialize)]
pub struct TemplateDiff {
    pub template_id: String,
    pub from: u64,
    pub to: u64,
    pub changes: Vec<DiffChange>,
}
#[derive(Clone, Debug, Serialize)]
pub struct DiffChange {
    pub path: String,
    pub from: Option<serde_json::Value>,
    pub to: Option<serde_json::Value>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RolloutRecord {
    pub targets: Vec<RolloutTarget>,
    pub rollback_on_failure: bool,
    pub report: RolloutReport,
}
#[derive(Clone, Debug, Deserialize)]
pub struct TemplateInput {
    #[serde(default)]
    pub tenant_id: Option<String>,
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub rule: Rule,
    #[serde(default)]
    pub variables: BTreeMap<String, String>,
}
pub fn validate(input: &TemplateInput) -> Result<()> {
    ensure!(
        !input.name.trim().is_empty()
            && input.name.len() <= 120
            && !input.name.chars().any(char::is_control),
        "template name must contain 1..120 bytes without control characters"
    );
    ensure!(
        input.description.len() <= 2_000 && !input.description.contains('\0'),
        "template description must be at most 2000 bytes"
    );
    validate_variables(&input.variables)?;
    render_rule(&input.rule, &input.variables)?.validate()?;
    Ok(())
}

pub fn validate_variables(variables: &BTreeMap<String, String>) -> Result<()> {
    ensure!(
        variables.len() <= 64,
        "template variables must be at most 64"
    );
    for (name, value) in variables {
        ensure!(
            !name.is_empty()
                && name.len() <= 64
                && name
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'_'),
            "template variable names must be 1..64 ASCII alphanumeric/underscore"
        );
        ensure!(
            value.len() <= 1024 && !value.chars().any(char::is_control),
            "template variable values must be at most 1024 bytes without control characters"
        );
    }
    Ok(())
}

/// Substitute `{{name}}` in every string field of the rule. Missing values are
/// errors, so a typo cannot silently become a literal target.
pub fn render_rule(rule: &Rule, variables: &BTreeMap<String, String>) -> Result<Rule> {
    validate_variables(variables)?;
    let mut value = serde_json::to_value(rule)?;
    render_value(&mut value, variables)?;
    serde_json::from_value(value).context("rendered template rule is invalid")
}

fn render_value(value: &mut serde_json::Value, variables: &BTreeMap<String, String>) -> Result<()> {
    match value {
        serde_json::Value::String(text) => *text = render_string(text, variables)?,
        serde_json::Value::Array(items) => {
            for item in items {
                render_value(item, variables)?;
            }
        }
        serde_json::Value::Object(map) => {
            for item in map.values_mut() {
                render_value(item, variables)?;
            }
        }
        _ => {}
    }
    Ok(())
}

fn render_string(text: &str, variables: &BTreeMap<String, String>) -> Result<String> {
    let mut output = String::with_capacity(text.len());
    let mut rest = text;
    while let Some(start) = rest.find("{{") {
        output.push_str(&rest[..start]);
        let after = &rest[start + 2..];
        let Some(end) = after.find("}}") else {
            bail!("unterminated template placeholder");
        };
        let name = after[..end].trim();
        let value = variables
            .get(name)
            .with_context(|| format!("template variable {name} has no value"))?;
        output.push_str(value);
        rest = &after[end + 2..];
    }
    output.push_str(rest);
    Ok(output)
}
pub fn now() -> i64 {
    now_ms()
}
