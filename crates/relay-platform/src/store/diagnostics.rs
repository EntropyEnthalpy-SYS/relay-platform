//! System administrators' troubleshooting views: the live log reader and the
//! diagnostic report, which puts the current state of every node, rule and
//! hop, the problems found in it and the recent logs into one document. The
//! report lists rule settings by name only, so it never carries passwords,
//! keys, tokens or other credentials.
use super::*;
use crate::{
    history::{BUCKET_MS, HopKey},
    logs::{CONTROLLER, KEEP, Kept, Level},
    telemetry::{OFFLINE_AFTER_MS, Severity},
};
use serde::Serialize;
use serde_json::{Value, json};
use std::collections::{BTreeMap, HashMap, HashSet};

/// Lines returned by one live log read, and per source in a report.
const READ_LINES: usize = 500;
const REPORT_LINES: usize = 300;
const HOUR_MS: i64 = 3_600_000;
/// A hop needs this many connections in the last hour to be judged.
const HOP_MIN_ATTEMPTS: u64 = 5;

fn require_admin(actor: &Actor) -> Result<()> {
    if actor.role != Role::SystemAdmin {
        return reject(
            403,
            "logs and diagnostics require system administrator access",
        );
    }
    Ok(())
}

#[derive(Debug, Serialize)]
pub struct Finding {
    pub severity: Severity,
    pub kind: &'static str,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub node: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rule: Option<String>,
    pub facts: Value,
    pub message: String,
}

impl Finding {
    fn node(
        severity: Severity,
        kind: &'static str,
        node: &Node,
        facts: Value,
        message: String,
    ) -> Self {
        Self {
            severity,
            kind,
            node_id: Some(node.id.clone()),
            node: Some(node.name.clone()),
            rule_id: None,
            rule: None,
            facts,
            message,
        }
    }
}

/// The main cause among a hop's failures, as a key and in Chinese.
fn main_cause(c: &ConnectionCounts) -> (&'static str, &'static str, u64) {
    [
        ("refused", "连接被拒绝", c.refused),
        ("timeout", "连接超时", c.timeout),
        ("dns", "域名解析失败", c.dns),
        ("closed", "连接被对方关闭", c.closed),
        ("other", "其他错误", c.other),
    ]
    .into_iter()
    .max_by_key(|cause| cause.2)
    .unwrap()
}

/// Where a hop starts and ends, by node name or target address.
fn hop_ends(
    hop: &HopKey,
    node: &str,
    rule: &Rule,
    names: &HashMap<String, String>,
) -> (String, String) {
    match hop.target_index {
        None => ("客户端".into(), node.into()),
        Some(index) => {
            let via = rule.targets.get(index).and_then(|t| t.via.as_ref());
            let to = via
                .and_then(|v| names.get(&v.node_id).cloned())
                .unwrap_or_else(|| hop.target_address.clone());
            (node.into(), to)
        }
    }
}

/// Problems in the current state, most severe first. Data of offline nodes
/// is stale, so only their silence is reported.
pub fn findings(
    now: i64,
    nodes: &[Node],
    configs: &HashMap<String, NodeConfig>,
    hops: &BTreeMap<HopKey, ConnectionCounts>,
    logs: &[(String, String, Vec<Kept>)],
) -> Vec<Finding> {
    let names: HashMap<String, String> = nodes
        .iter()
        .map(|n| (n.id.clone(), n.name.clone()))
        .collect();
    let mut found = vec![];
    let mut failing = HashSet::new();
    for node in nodes {
        let name = &node.name;
        if !node.enrolled {
            found.push(Finding::node(
                Severity::Info,
                "node_not_enrolled",
                node,
                json!({}),
                format!("节点 {name} 尚未接入"),
            ));
            continue;
        }
        let Some(seen) = node.last_seen_ms else {
            found.push(Finding::node(
                Severity::Critical,
                "node_never_reported",
                node,
                json!({}),
                format!("节点 {name} 已接入但从未回报"),
            ));
            continue;
        };
        if now - seen > OFFLINE_AFTER_MS {
            let seconds = (now - seen) / 1000;
            found.push(Finding::node(
                Severity::Critical,
                "node_offline",
                node,
                json!({"seconds": seconds}),
                format!("节点 {name} 已 {seconds} 秒无回报"),
            ));
            continue;
        }
        let (applied, desired) = (node.applied_revision, node.desired_revision);
        if let Some(error) = &node.apply_error {
            found.push(Finding::node(
                Severity::Critical,
                "config_rejected",
                node,
                json!({"applied": applied, "desired": desired, "error": error}),
                format!("节点 {name} 拒绝了修订 {desired}，仍在运行修订 {applied}：{error}"),
            ));
        } else if applied < desired {
            found.push(Finding::node(
                Severity::Info,
                "config_pending",
                node,
                json!({"applied": applied, "desired": desired}),
                format!("节点 {name} 尚未应用修订 {desired}（当前 {applied}）"),
            ));
        }
        let rules: HashMap<&str, &Rule> = configs
            .get(&node.id)
            .map(|c| c.rules.iter().map(|r| (r.id.as_str(), r)).collect())
            .unwrap_or_default();
        for (hop, counts) in hops.range(
            HopKey {
                node_id: node.id.clone(),
                rule_id: String::new(),
                target_index: None,
                target_address: String::new(),
            }..,
        ) {
            if hop.node_id != node.id {
                break;
            }
            let Some(rule) = rules.get(hop.rule_id.as_str()) else {
                continue;
            };
            if counts.attempts < HOP_MIN_ATTEMPTS || counts.connected * 10 >= counts.attempts * 9 {
                continue;
            }
            let percent = counts.connected * 100 / counts.attempts;
            let (cause, cause_zh, cause_count) = main_cause(counts);
            let (from, to) = hop_ends(hop, name, rule, &names);
            failing.insert((hop.node_id.clone(), hop.rule_id.clone(), hop.target_index));
            found.push(Finding {
                severity: if percent < 50 { Severity::Critical } else { Severity::Warning },
                kind: "hop_failing",
                node_id: Some(node.id.clone()),
                node: Some(name.clone()),
                rule_id: Some(rule.id.clone()),
                rule: Some(rule.name.clone()),
                facts: json!({"from": from, "to": to, "target_index": hop.target_index, "target_address": hop.target_address, "attempts": counts.attempts, "connected": counts.connected, "success_percent": percent, "cause": cause, "cause_count": cause_count, "counts": counts}),
                message: format!("{}：{from} → {to} 最近 1 小时 {} 次连接成功 {percent}%，主要原因：{cause_zh}（{cause_count} 次）", rule.name, counts.attempts),
            });
        }
        // One finding per target, naming each protocol whose probe fails.
        let mut unhealthy: BTreeMap<(&str, usize), Vec<&crate::health::TargetHealthReport>> =
            BTreeMap::new();
        for report in &node.stats.target_health {
            if report.status == crate::health::Status::Unhealthy
                && rules
                    .get(report.rule_id.as_str())
                    .is_some_and(|r| r.enabled)
                && !failing.contains(&(
                    node.id.clone(),
                    report.rule_id.clone(),
                    Some(report.target_index),
                ))
            {
                unhealthy
                    .entry((&report.rule_id, report.target_index))
                    .or_default()
                    .push(report);
            }
        }
        for ((rule_id, index), reports) in unhealthy {
            let rule = rules[rule_id];
            let address = &reports[0].target_address;
            let probes: Vec<Value> = reports
                .iter()
                .map(|r| json!({"protocol": r.protocol, "error": r.last_error}))
                .collect();
            let causes: Vec<String> = probes
                .iter()
                .map(|p| {
                    format!(
                        "{}: {}",
                        p["protocol"].as_str().unwrap_or("?"),
                        p["error"].as_str().unwrap_or("unknown")
                    )
                })
                .collect();
            found.push(Finding {
                severity: Severity::Warning,
                kind: "target_unhealthy",
                node_id: Some(node.id.clone()),
                node: Some(name.clone()),
                rule_id: Some(rule.id.clone()),
                rule: Some(rule.name.clone()),
                facts: json!({"target_index": index, "target_address": address, "probes": probes}),
                message: format!(
                    "{}：节点 {name} 的目标 {address} 探测失败（{}）",
                    rule.name,
                    causes.join("，")
                ),
            });
        }
        if let Some(system) = &node.stats.system {
            if let Some(cpu) = system.cpu_percent.filter(|cpu| *cpu >= 90.0) {
                let percent = cpu.round() as u32;
                found.push(Finding::node(
                    Severity::Warning,
                    "high_cpu",
                    node,
                    json!({"cpu_percent": percent}),
                    format!("节点 {name} CPU 使用率 {percent}%"),
                ));
            }
            if let (Some(total), Some(available)) =
                (system.memory_total_bytes, system.memory_available_bytes)
                && total > 0
                && available * 10 < total
            {
                let percent = available * 100 / total;
                found.push(Finding::node(
                    Severity::Warning,
                    "low_memory",
                    node,
                    json!({"available_percent": percent}),
                    format!("节点 {name} 可用内存仅剩 {percent}%"),
                ));
            }
        }
    }
    for (source, name, lines) in logs {
        let recent = || lines.iter().filter(|l| now - l.at_ms <= HOUR_MS);
        for (level, kind, severity, min, word) in [
            (Level::Error, "log_errors", Severity::Warning, 1, "错误"),
            (Level::Warn, "log_warnings", Severity::Info, 10, "警告"),
        ] {
            let count = recent().filter(|l| l.level == level).count();
            if count < min {
                continue;
            }
            let latest = recent()
                .rfind(|l| l.level == level)
                .map(|l| l.text.clone())
                .unwrap_or_default();
            found.push(Finding {
                severity,
                kind,
                node_id: (source != CONTROLLER).then(|| source.clone()),
                node: Some(name.clone()),
                rule_id: None,
                rule: None,
                facts: json!({"source": source, "count": count, "latest": latest}),
                message: format!("{name} 最近 1 小时记录了 {count} 条{word}，最新：{latest}"),
            });
            break;
        }
    }
    found.sort_by_key(|f| std::cmp::Reverse(f.severity));
    found
}

/// A rule without its secrets: plain settings, target addresses and the
/// names of the features it uses.
fn rule_summary(rule: &Rule, names: &HashMap<String, String>) -> Value {
    const PLAIN: [&str; 14] = [
        "id",
        "name",
        "enabled",
        "protocol",
        "listen",
        "listen_end_port",
        "advertise",
        "balance",
        "connect_timeout_ms",
        "idle_timeout_secs",
        "max_connections",
        "udp_max_sessions",
        "quota_bytes",
        "rate_bytes_per_sec",
    ];
    const OMIT: [&str; 6] = [
        "tenant_id",
        "owner_id",
        "meter_epoch",
        "budget_ids",
        "targets",
        "expires_at_ms",
    ];
    let full = serde_json::to_value(rule).unwrap_or_default();
    let mut summary = serde_json::Map::new();
    let mut features = vec![];
    for (key, value) in full.as_object().into_iter().flatten() {
        let unset =
            value.is_null() || value == &json!(false) || value == &json!([]) || value == &json!({});
        if PLAIN.contains(&key.as_str()) {
            summary.insert(key.clone(), value.clone());
        } else if !OMIT.contains(&key.as_str()) && !unset {
            features.push(key.clone());
        }
    }
    summary.insert("features".into(), features.into());
    let targets: Vec<Value> = rule
        .targets
        .iter()
        .map(|t| {
            json!({
                "address": t.address,
                "via": t.via.as_ref().map(|v| json!({"node": names.get(&v.node_id), "node_id": v.node_id, "rule_id": v.rule_id})),
                "weight": t.weight,
                "priority": t.priority,
                "draining": t.draining,
                "prewarm": t.prewarm,
                "tls": t.tls.is_some(),
                "proxy_protocol": t.proxy_protocol.is_some(),
                "websocket": t.websocket.is_some(),
            })
        })
        .collect();
    summary.insert("targets".into(), targets.into());
    Value::Object(summary)
}

impl Store {
    /// Log lines newer than `after` from one source (a node id or
    /// `controller`) or from all, oldest first, with every source's name.
    pub fn logs(&self, actor: &Actor, source: Option<&str>, after: u64) -> Result<Value> {
        require_admin(actor)?;
        let nodes = self.nodes(actor)?;
        let (lines, truncated, latest_id) = self.4.logs(source, after, READ_LINES);
        let mut sources = vec![json!({"id": CONTROLLER, "name": CONTROLLER})];
        sources.extend(
            nodes
                .iter()
                .map(|n| json!({"id": n.id, "name": n.name, "enrolled": n.enrolled})),
        );
        Ok(
            json!({"lines": lines, "truncated": truncated, "latest_id": latest_id, "sources": sources}),
        )
    }

    pub fn diagnostic_report(&self, actor: &Actor) -> Result<Value> {
        require_admin(actor)?;
        let now = now_ms();
        let nodes = self.nodes(actor)?;
        let names: HashMap<String, String> = nodes
            .iter()
            .map(|n| (n.id.clone(), n.name.clone()))
            .collect();
        let configs: HashMap<String, NodeConfig> = nodes
            .iter()
            .filter_map(|n| Some((n.id.clone(), self.config(actor, &n.id, None).ok()?)))
            .collect();
        let ids: Vec<String> = nodes.iter().map(|n| n.id.clone()).collect();
        let mut hops: BTreeMap<HopKey, ConnectionCounts> = BTreeMap::new();
        let since = crate::history::bucket(now) + BUCKET_MS - HOUR_MS;
        for ((hop, _), counts) in self
            .4
            .history(&ids, since)?
            .map(|b| b.hops)
            .unwrap_or_default()
        {
            hops.entry(hop).or_default().add(&counts);
        }
        let logs: Vec<(String, String, Vec<Kept>)> =
            std::iter::once((CONTROLLER.to_owned(), CONTROLLER.to_owned()))
                .chain(nodes.iter().map(|n| (n.id.clone(), n.name.clone())))
                .map(|(id, name)| {
                    let lines = self.4.logs(Some(&id), 0, KEEP).0;
                    (id, name, lines)
                })
                .collect();
        let findings = findings(now, &nodes, &configs, &hops, &logs);
        let count = |severity| findings.iter().filter(|f| f.severity == severity).count();
        let summary = json!({
            "nodes": nodes.len(),
            "enrolled": nodes.iter().filter(|n| n.enrolled).count(),
            "online": nodes.iter().filter(|n| n.last_seen_ms.is_some_and(|seen| now - seen <= OFFLINE_AFTER_MS)).count(),
            "rules": configs.values().map(|c| c.rules.len()).sum::<usize>(),
            "critical": count(Severity::Critical),
            "warning": count(Severity::Warning),
            "info": count(Severity::Info),
        });
        let node_states: Vec<Value> = nodes
            .iter()
            .map(|n| {
                let s = &n.stats;
                json!({
                    "id": n.id, "name": n.name, "enrolled": n.enrolled,
                    "online": n.last_seen_ms.is_some_and(|seen| now - seen <= OFFLINE_AFTER_MS),
                    "last_seen_ms": n.last_seen_ms,
                    "desired_revision": n.desired_revision, "applied_revision": n.applied_revision,
                    "apply_error": n.apply_error,
                    "system": s.system,
                    "active_tcp": s.active_tcp, "active_udp": s.active_udp, "accepted_tcp": s.accepted_tcp,
                    "rejected_connections": s.rejected_connections, "failed_connections": s.failed_connections,
                    "dropped_datagrams": s.dropped_datagrams,
                    "forwarded_upload_bytes": s.forwarded_upload_bytes, "forwarded_download_bytes": s.forwarded_download_bytes,
                    "target_health": s.target_health,
                })
            })
            .collect();
        let rules: Vec<Value> = configs
            .iter()
            .flat_map(|(node, config)| {
                config.rules.iter().map(|rule| {
                    let mut summary = rule_summary(rule, &names);
                    summary["node_id"] = node.clone().into();
                    summary["node"] = names.get(node).cloned().into();
                    summary
                })
            })
            .collect();
        let connections: Vec<Value> = hops
            .iter()
            .filter_map(|(hop, counts)| {
                let rule = configs.get(&hop.node_id)?.rules.iter().find(|r| r.id == hop.rule_id)?;
                let (from, to) = hop_ends(hop, names.get(&hop.node_id)?, rule, &names);
                Some(json!({"node_id": hop.node_id, "rule_id": rule.id, "rule": rule.name, "from": from, "to": to, "target_index": hop.target_index, "target_address": hop.target_address, "counts": counts}))
            })
            .collect();
        let mut events = self.4.snapshot(&ids).1;
        events.drain(..events.len().saturating_sub(200));
        let logs: Vec<Value> = logs
            .into_iter()
            .map(|(id, name, mut lines)| {
                lines.drain(..lines.len().saturating_sub(REPORT_LINES));
                json!({"source": id, "name": name, "lines": lines})
            })
            .collect();
        Ok(json!({
            "format": "relay-diagnostics/1",
            "generated_at_ms": now,
            "controller_version": env!("CARGO_PKG_VERSION"),
            "summary": summary,
            "findings": findings,
            "nodes": node_states,
            "rules": rules,
            "connections_last_hour": connections,
            "events": events,
            "logs": logs,
        }))
    }
}
