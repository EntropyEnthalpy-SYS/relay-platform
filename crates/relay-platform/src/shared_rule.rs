//! Shared rules: one forwarding rule kept on several entry servers ("lines")
//! with the same listen port. Each member stays an ordinary rule on its node;
//! the controller only keeps the membership record, so agents and the rule
//! format are unchanged.
use crate::model::Rule;
use crate::store::{Rejection, reject};
use anyhow::Result;
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{collections::BTreeSet, fmt};

/// Most lines one shared rule can have.
pub const MAX_LINES: usize = 32;

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Member {
    pub node_id: String,
    pub rule_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SharedRule {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub listen_port: u16,
    pub members: Vec<Member>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}
/// Create and edit input. `rule` carries the common fields; its identity,
/// listen host and `advertise` are ignored. An empty `owner_id` means the
/// caller owns new lines.
#[derive(Clone, Debug)]
pub struct SharedRuleInput {
    pub name: String,
    pub node_ids: Vec<String>,
    pub listen_port: u16,
    pub rule: Rule,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct FromRuleInput {
    pub node_id: String,
    pub rule_id: String,
    pub add_node_ids: Vec<String>,
}
/// `id` names the shared rule being edited, so its own member rules do not
/// count as taking the port.
#[derive(Clone, Debug)]
pub struct PrecheckInput {
    pub id: Option<String>,
    pub node_ids: Vec<String>,
    pub listen_port: Option<u16>,
    pub rule: Rule,
}
#[derive(Clone, Debug, Serialize)]
pub struct PrecheckLine {
    pub node_id: String,
    pub node_name: String,
    /// Heartbeat within the last 90 seconds.
    pub online: bool,
    /// The port lies inside the node's forwarding port range. Advice only:
    /// a port outside the range can still be saved.
    pub in_range: bool,
    pub port_start: u16,
    pub port_end: u16,
    pub port_free: bool,
    pub valid: bool,
    pub error: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct Precheck {
    /// The checked port, or the automatic pick; `null` when none fits.
    pub listen_port: Option<u16>,
    /// Every line has the port free and passes validation.
    pub ok: bool,
    /// A problem of the whole set of lines rather than of one line.
    pub error: Option<String>,
    pub lines: Vec<PrecheckLine>,
}
#[derive(Clone, Debug, Serialize)]
pub struct MemberView {
    pub node_id: String,
    pub rule_id: String,
    pub node_name: Option<String>,
    /// The node or its rule no longer exists.
    pub missing: bool,
    pub rule: Option<Rule>,
    /// Address clients connect to, when it is known.
    pub entry: Option<String>,
    /// Common fields where this line differs from the first present line.
    pub drift: Vec<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct SharedRuleView {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub listen_port: u16,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
    pub members: Vec<MemberView>,
    /// Every common field where some line differs from the first present line.
    pub drift: Vec<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct LineError {
    pub node_id: String,
    pub error: String,
}
/// Per-line causes attached to a rejected change; the API adds them to the
/// error body as `lines`.
#[derive(Clone, Debug)]
pub struct LineErrors(pub Vec<LineError>);
impl fmt::Display for LineErrors {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        let lines: Vec<String> = self
            .0
            .iter()
            .map(|line| format!("{}: {}", line.node_id, line.error))
            .collect();
        f.write_str(&lines.join("; "))
    }
}

/// Reads the rule of a request. Identity fields a client leaves out get
/// placeholders, because the controller assigns them per line.
pub fn rule_from_json(mut value: Value) -> Result<Rule> {
    let Some(object) = value.as_object_mut() else {
        return reject(400, "rule must be a JSON object");
    };
    for (key, placeholder) in [
        ("id", "shared"),
        ("tenant_id", "shared"),
        ("owner_id", ""),
        ("meter_epoch", "shared"),
        ("name", "Shared rule"),
        ("listen", "0.0.0.0:1"),
    ] {
        if object.get(key).is_none_or(Value::is_null) {
            object.insert(key.into(), Value::from(placeholder));
        }
    }
    serde_json::from_value(value).map_err(|error| {
        Rejection {
            status: 400,
            message: format!("invalid rule: {error}"),
        }
        .into()
    })
}

/// The fields every line shares, as JSON: per-line identity (id, meter
/// epoch, owner, tenant), the listen host, the advertised address and the
/// controller-assigned budgets are left out; the listen port stays.
pub fn common_fields(rule: &Rule) -> Value {
    let mut value = serde_json::to_value(rule).unwrap_or_default();
    if let Some(object) = value.as_object_mut() {
        for key in [
            "id",
            "meter_epoch",
            "owner_id",
            "tenant_id",
            "advertise",
            "budget_ids",
            "listen",
        ] {
            object.remove(key);
        }
        object.insert("listen_port".into(), rule.listen.port().into());
    }
    value
}
fn diff(path: &str, a: &Value, b: &Value, out: &mut BTreeSet<String>) {
    if a == b {
        return;
    }
    match (a, b) {
        (Value::Object(x), Value::Object(y)) => {
            for key in x.keys().chain(y.keys()) {
                let next = if path.is_empty() {
                    key.clone()
                } else {
                    format!("{path}.{key}")
                };
                diff(
                    &next,
                    x.get(key).unwrap_or(&Value::Null),
                    y.get(key).unwrap_or(&Value::Null),
                    out,
                );
            }
        }
        (Value::Array(x), Value::Array(y)) if x.len() == y.len() => {
            for (index, (a, b)) in x.iter().zip(y).enumerate() {
                diff(&format!("{path}[{index}]"), a, b, out);
            }
        }
        _ => {
            out.insert(path.to_owned());
        }
    }
}
/// Paths of the common fields where `member` differs from `reference`, such
/// as `targets[0].address` or `listen_port`.
pub fn drift(reference: &Rule, member: &Rule) -> Vec<String> {
    let mut out = BTreeSet::new();
    diff(
        "",
        &common_fields(reference),
        &common_fields(member),
        &mut out,
    );
    out.into_iter().collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn base() -> Value {
        serde_json::json!({
            "name": "web", "protocol": "tcp", "listen": "10.0.0.1:25000",
            "targets": [{"address": "192.0.2.1:443", "weight": 1}],
            "quota_bytes": null, "expires_at_ms": null, "rate_bytes_per_sec": null,
        })
    }

    #[test]
    fn identity_and_listen_host_are_not_drift() {
        let a = rule_from_json(base()).unwrap();
        let mut b = a.clone();
        b.id = "other".into();
        b.meter_epoch = "other".into();
        b.owner_id = "other".into();
        b.tenant_id = "other".into();
        b.advertise = Some("203.0.113.9:25000".into());
        b.budget_ids = vec!["budget".into()];
        b.listen = "0.0.0.0:25000".parse().unwrap();
        assert!(drift(&a, &b).is_empty());
        b.listen = "0.0.0.0:25001".parse().unwrap();
        b.targets[0].address = "192.0.2.2:443".into();
        b.rate_bytes_per_sec = Some(1000);
        assert_eq!(
            drift(&a, &b),
            ["listen_port", "rate_bytes_per_sec", "targets[0].address"]
        );
        b.targets.push(b.targets[0].clone());
        assert!(drift(&a, &b).contains(&"targets".to_owned()));
    }

    #[test]
    fn requests_may_leave_out_identity_but_not_add_fields() {
        let rule = rule_from_json(base()).unwrap();
        assert_eq!(rule.owner_id, "");
        assert!(rule.enabled);
        let mut extra = base();
        extra["surprise"] = true.into();
        let error = rule_from_json(extra).unwrap_err();
        assert_eq!(error.downcast_ref::<Rejection>().unwrap().status, 400);
        assert!(rule_from_json(Value::Null).is_err());
    }
}
