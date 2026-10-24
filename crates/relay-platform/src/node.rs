//! Operator-owned node inventory and lifecycle settings, separate from routing.
use crate::store::reject;
use anyhow::Result;
use serde::{Deserialize, Serialize};
use std::collections::HashSet;

#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeKind {
    Ingress,
    Relay,
    Egress,
    Ix,
    Nat,
}
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CostPeriod {
    Monthly,
    Yearly,
    OneTime,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NodeCost {
    pub currency: String,
    /// Millionths of the named currency unit; never a binary floating amount.
    pub amount_micros: u64,
    pub period: CostPeriod,
}
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct NodeSettings {
    pub kinds: Vec<NodeKind>,
    pub group: Option<String>,
    pub tags: Vec<String>,
    pub notes: String,
    pub cost: Option<NodeCost>,
    pub enabled: bool,
    pub expires_at_ms: Option<i64>,
}
impl Default for NodeSettings {
    fn default() -> Self {
        Self {
            kinds: vec![],
            group: None,
            tags: vec![],
            notes: String::new(),
            cost: None,
            enabled: true,
            expires_at_ms: None,
        }
    }
}
fn label(value: &str, maximum: usize) -> bool {
    !value.trim().is_empty()
        && value == value.trim()
        && value.len() <= maximum
        && !value.chars().any(char::is_control)
}
pub fn validate_name(name: &str) -> Result<()> {
    if !label(name, 120) {
        return reject(
            400,
            "node name must contain 1..120 bytes without surrounding whitespace or control characters",
        );
    }
    Ok(())
}
impl NodeSettings {
    pub fn validate(&self) -> Result<()> {
        if self.kinds.len() > 5
            || self
                .kinds
                .iter()
                .enumerate()
                .any(|(i, kind)| self.kinds[..i].contains(kind))
            || self.group.as_ref().is_some_and(|group| !label(group, 64))
            || self.tags.len() > 32
            || self.tags.iter().any(|tag| !label(tag, 64))
            || self.tags.iter().collect::<HashSet<_>>().len() != self.tags.len()
            || self.notes.len() > 4096
            || self
                .notes
                .chars()
                .any(|c| c.is_control() && !matches!(c, '\n' | '\r' | '\t'))
        {
            return reject(400, "invalid node kinds, group, tags or notes");
        }
        if self.cost.as_ref().is_some_and(|cost| {
            cost.currency.len() != 3
                || !cost.currency.bytes().all(|b| b.is_ascii_uppercase())
                || cost.amount_micros > 9_000_000_000_000_000
        }) {
            return reject(
                400,
                "cost requires a three-uppercase-letter currency and at most 9000000000000000 millionths",
            );
        }
        if self
            .expires_at_ms
            .is_some_and(|time| !(1..=253_402_300_799_999).contains(&time))
        {
            return reject(400, "node expiry timestamp must be within years 1970..9999");
        }
        Ok(())
    }
    pub fn lifecycle(&self, now_ms: i64) -> NodeLifecycle {
        if !self.enabled {
            NodeLifecycle::Disabled
        } else if self.expires_at_ms.is_some_and(|expiry| expiry <= now_ms) {
            NodeLifecycle::Expired
        } else {
            NodeLifecycle::Active
        }
    }
}
#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct NodeProfile {
    pub revision: u64,
    pub updated_at_ms: Option<i64>,
    pub settings: NodeSettings,
}
#[derive(Clone, Copy, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum NodeLifecycle {
    #[default]
    Active,
    Disabled,
    Expired,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeUpdate {
    pub expected_revision: u64,
    pub name: String,
    pub settings: NodeSettings,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeBatchEntry {
    pub node_id: String,
    pub update: NodeUpdate,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NodeUpdateResult {
    pub node_id: String,
    pub name: String,
    pub profile: NodeProfile,
    pub lifecycle: NodeLifecycle,
}
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NodeFilter {
    pub q: Option<String>,
    pub kind: Option<NodeKind>,
    pub group: Option<String>,
    pub tag: Option<String>,
    pub lifecycle: Option<NodeLifecycle>,
}
impl NodeFilter {
    pub fn validate(&self) -> Result<()> {
        if self.q.as_ref().is_some_and(|q| !label(q, 120))
            || self.group.as_ref().is_some_and(|group| !label(group, 64))
            || self.tag.as_ref().is_some_and(|tag| !label(tag, 64))
        {
            return reject(400, "invalid node filter");
        }
        Ok(())
    }
    pub fn matches(&self, node: &crate::store::Node) -> bool {
        let settings = &node.profile.settings;
        self.kind.is_none_or(|kind| settings.kinds.contains(&kind))
            && self
                .group
                .as_ref()
                .is_none_or(|group| settings.group.as_ref() == Some(group))
            && self
                .tag
                .as_ref()
                .is_none_or(|tag| settings.tags.contains(tag))
            && self.lifecycle.is_none_or(|state| node.lifecycle == state)
            && self.q.as_ref().is_none_or(|q| {
                let q = q.to_lowercase();
                [&node.id, &node.name, &settings.notes]
                    .into_iter()
                    .chain(settings.tags.iter())
                    .chain(settings.group.iter())
                    .any(|text| text.to_lowercase().contains(&q))
            })
    }
}
