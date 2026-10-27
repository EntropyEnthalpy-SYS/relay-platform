//! Reusable rule templates. A template stores a validated rule body; applying
//! it clones the body into a node configuration with a fresh identity, name,
//! listen address and meter epoch.
use crate::model::{Rule, now_ms};
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RuleTemplate {
    pub id: String,
    /// `None` is global; `Some` is visible only inside that tenant.
    pub tenant_id: Option<String>,
    pub name: String,
    pub description: String,
    pub rule: Rule,
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
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RolloutTarget {
    pub node_id: String,
    pub expected_revision: u64,
    pub name: String,
    pub listen: std::net::SocketAddr,
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
    input.rule.validate()?;
    Ok(())
}
pub fn now() -> i64 {
    now_ms()
}
