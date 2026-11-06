//! Incident notifications. Channels and settings persist in `metadata`; open
//! incidents and the delivery log live in memory, so a restarted controller
//! re-detects current problems after a grace period instead of replaying old
//! notices.
use crate::{
    model::now_ms,
    store::Store,
    telemetry::{OFFLINE_AFTER_MS, Severity},
};
use anyhow::{Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use serde::{Deserialize, Serialize};
use std::{
    collections::{HashMap, VecDeque},
    sync::Mutex,
    time::Duration,
};
use tokio_util::sync::CancellationToken;

pub const MAX_CHANNELS: usize = 20;
/// A problem that clears and returns within this time is one incident; its
/// next notice waits until this long after the previous one.
pub const HOLD_MS: i64 = 5 * 60 * 1000;
/// New problems wait this long so failures that arrive together share one message.
pub const GROUP_WAIT_MS: i64 = 5_000;
/// Problems listed in one grouped message; the rest are counted.
const LIST_LIMIT: usize = 10;
/// After a controller start, nodes get this long to report before they count as offline.
pub const STARTUP_GRACE_MS: i64 = 2 * OFFLINE_AFTER_MS;
const TEST_MESSAGE: &str = "【测试】Relay 告警通道配置正确，可以收到通知。";
const KEEP_RESOLVED: usize = 200;
const KEEP_DELIVERIES: usize = 200;
const RETRY_DELAYS: [Duration; 3] = [
    Duration::from_secs(10),
    Duration::from_secs(60),
    Duration::from_secs(300),
];

#[derive(Clone, Debug, Default, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Settings {
    /// Notices are held until this time; incidents still open afterwards are sent then.
    #[serde(default)]
    pub maintenance_until_ms: Option<i64>,
    /// The resource, expiry, budget and DNS alerts. Absent means the
    /// defaults, and a save without it keeps the saved rules. Omitted while
    /// unset, so settings without rules stay readable by older controllers.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rules: Option<Rules>,
}
impl Settings {
    pub fn in_maintenance(&self, now: i64) -> bool {
        self.maintenance_until_ms.is_some_and(|until| until > now)
    }
}

/// Checks a problem must be found in a row before it opens, at most.
pub const MAX_CHECKS: u32 = 100;
const DAY_MS: i64 = 86_400_000;
/// The summary of an incident closed because its rule was switched off.
const RULE_DISABLED: &str = "此项告警已停用";

/// When one kind of problem opens an incident.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    pub enabled: bool,
    /// Percent for CPU, memory and budget use, days for an approaching node
    /// expiry; absent for problems without a level.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub threshold: Option<u32>,
    /// Consecutive checks that must find the problem before it opens. CPU
    /// and memory are checked once per node report, the others on every
    /// pass of the alert worker.
    pub checks: u32,
}

/// Every rule is off by default, so an upgrade sends no new kinds of notice.
#[derive(Clone, Copy, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(default, deny_unknown_fields)]
pub struct Rules {
    /// Host CPU use at or above `threshold` percent.
    pub node_cpu: Rule,
    /// Host memory use (total minus available) at or above `threshold` percent.
    pub node_memory: Rule,
    /// The node profile's expiry is at most `threshold` days away, or passed.
    pub node_expiring: Rule,
    /// The node profile's expiry has passed.
    pub node_expired: Rule,
    /// A shared budget's committed bytes reach `threshold` percent of its limit.
    pub budget_near: Rule,
    /// A shared budget has nothing left to allocate.
    pub budget_exhausted: Rule,
    /// A managed DNS record's last provider sync failed.
    pub dns_sync_failed: Rule,
}
impl Default for Rules {
    fn default() -> Self {
        let off = |threshold, checks| Rule {
            enabled: false,
            threshold,
            checks,
        };
        Self {
            node_cpu: off(Some(90), 5),
            node_memory: off(Some(90), 5),
            node_expiring: off(Some(7), 1),
            node_expired: off(None, 1),
            budget_near: off(Some(90), 1),
            budget_exhausted: off(None, 1),
            dns_sync_failed: off(None, 1),
        }
    }
}
impl Rules {
    pub fn validate(&self) -> Result<()> {
        for (name, rule, range) in [
            ("node_cpu", self.node_cpu, Some(1..=100)),
            ("node_memory", self.node_memory, Some(1..=100)),
            ("node_expiring", self.node_expiring, Some(1..=365)),
            ("node_expired", self.node_expired, None),
            ("budget_near", self.budget_near, Some(1..=100)),
            ("budget_exhausted", self.budget_exhausted, None),
            ("dns_sync_failed", self.dns_sync_failed, None),
        ] {
            ensure!(
                (1..=MAX_CHECKS).contains(&rule.checks),
                "{name}: consecutive checks must be 1..{MAX_CHECKS}"
            );
            match (range, rule.threshold) {
                (Some(range), Some(threshold)) => ensure!(
                    range.contains(&threshold),
                    "{name}: threshold must be {}..{}",
                    range.start(),
                    range.end()
                ),
                (Some(_), None) => anyhow::bail!("{name} needs a threshold"),
                (None, Some(_)) => anyhow::bail!("{name} has no threshold"),
                (None, None) => {}
            }
        }
        Ok(())
    }
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum Target {
    Smtp {
        config: crate::email::Config,
    },
    /// JSON POST; with a secret, `X-Relay-Signature: sha256=<hex HMAC of the body>`.
    Webhook {
        url: String,
        #[serde(default)]
        secret: String,
    },
    Telegram {
        bot_token: String,
        chat_id: String,
    },
    Wecom {
        url: String,
    },
    Feishu {
        url: String,
        #[serde(default)]
        secret: String,
    },
    Dingtalk {
        url: String,
        #[serde(default)]
        secret: String,
    },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Channel {
    /// None routes incidents from all tenants. Only a system administrator may set this.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub tenant_id: Option<String>,
    #[serde(default)]
    pub id: String,
    pub name: String,
    pub enabled: bool,
    /// `warning` sends every incident; `critical` only configuration
    /// rejections, offline and expired nodes and exhausted budgets.
    pub min_severity: Severity,
    pub target: Target,
}

/// What the API shows: destinations without tokens, URLs or secrets.
#[derive(Serialize)]
pub struct ChannelView {
    pub tenant_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub smtp: Option<crate::email::Config>,
    pub id: String,
    pub name: String,
    pub enabled: bool,
    pub min_severity: Severity,
    pub kind: &'static str,
    pub destination: String,
    pub secret_set: bool,
}
impl Channel {
    pub fn view(&self) -> ChannelView {
        let host = |url: &str| {
            reqwest::Url::parse(url)
                .ok()
                .and_then(|u| u.host_str().map(|h| format!("{}://{h}/…", u.scheme())))
                .unwrap_or_else(|| "…".into())
        };
        let (kind, destination, secret_set) = match &self.target {
            Target::Smtp { config } => (
                "smtp",
                format!("{}:{} → {}", config.host, config.port, config.to.join(", ")),
                !config.password.is_empty(),
            ),
            Target::Webhook { url, secret } => ("webhook", host(url), !secret.is_empty()),
            Target::Telegram { chat_id, .. } => ("telegram", format!("chat {chat_id}"), true),
            Target::Wecom { url } => ("wecom", host(url), false),
            Target::Feishu { url, secret } => ("feishu", host(url), !secret.is_empty()),
            Target::Dingtalk { url, secret } => ("dingtalk", host(url), !secret.is_empty()),
        };
        ChannelView {
            tenant_id: self.tenant_id.clone(),
            smtp: match &self.target {
                Target::Smtp { config } => Some(config.public()),
                _ => None,
            },
            id: self.id.clone(),
            name: self.name.clone(),
            enabled: self.enabled,
            min_severity: self.min_severity,
            kind,
            destination,
            secret_set,
        }
    }

    pub fn validate(&self) -> Result<()> {
        ensure!(
            !self.name.trim().is_empty() && self.name.len() <= 80,
            "channel name must contain 1..80 bytes"
        );
        ensure!(
            matches!(self.min_severity, Severity::Warning | Severity::Critical),
            "minimum severity must be warning or critical"
        );
        let url = |url: &str| -> Result<()> {
            let parsed = reqwest::Url::parse(url).map_err(|_| anyhow::anyhow!("invalid URL"))?;
            ensure!(
                matches!(parsed.scheme(), "https" | "http") && parsed.host().is_some(),
                "notification URLs must be http or https"
            );
            ensure!(url.len() <= 2048, "notification URL is too long");
            Ok(())
        };
        match &self.target {
            Target::Smtp { config } => config.validate()?,
            Target::Webhook { url: u, secret }
            | Target::Feishu { url: u, secret }
            | Target::Dingtalk { url: u, secret } => {
                url(u)?;
                ensure!(secret.len() <= 256, "secret is too long");
            }
            Target::Wecom { url: u } => url(u)?,
            Target::Telegram { bot_token, chat_id } => {
                ensure!(
                    !bot_token.is_empty()
                        && bot_token.len() <= 128
                        && bot_token.bytes().all(|b| b.is_ascii_alphanumeric()
                            || b == b':'
                            || b == b'_'
                            || b == b'-'),
                    "invalid Telegram bot token"
                );
                ensure!(
                    !chat_id.is_empty()
                        && chat_id.len() <= 64
                        && chat_id.bytes().all(|b| b.is_ascii_alphanumeric()
                            || b == b'-'
                            || b == b'_'
                            || b == b'@'),
                    "invalid Telegram chat ID"
                );
            }
        }
        Ok(())
    }

    /// Keeps saved URLs, tokens and secrets that an edit left blank.
    pub fn keep_secrets_from(&mut self, saved: &Channel) {
        let keep = |new: &mut String, old: &String| {
            if new.is_empty() {
                new.clone_from(old)
            }
        };
        match (&mut self.target, &saved.target) {
            (Target::Smtp { config }, Target::Smtp { config: old }) => {
                if config.host == old.host
                    && config.port == old.port
                    && config.username == old.username
                    && config.security == old.security
                {
                    keep(&mut config.password, &old.password);
                }
            }
            (Target::Webhook { url, secret }, Target::Webhook { url: u, secret: s })
            | (Target::Feishu { url, secret }, Target::Feishu { url: u, secret: s })
            | (Target::Dingtalk { url, secret }, Target::Dingtalk { url: u, secret: s }) => {
                keep(url, u);
                keep(secret, s);
            }
            (Target::Wecom { url }, Target::Wecom { url: u }) => keep(url, u),
            (
                Target::Telegram { bot_token, chat_id },
                Target::Telegram {
                    bot_token: t,
                    chat_id: c,
                },
            ) => {
                keep(bot_token, t);
                keep(chat_id, c);
            }
            _ => {}
        }
    }
}

#[derive(Clone, Debug, Serialize)]
pub struct Incident {
    /// Empty for DNS records, which belong to no tenant.
    pub tenant_id: String,
    pub key: String,
    /// What the incident is about: a node id, or `budget:<id>` or
    /// `dns_record:<id>`. Ownership is checked against it.
    pub node_id: String,
    /// The node's, budget's or DNS record's name.
    pub node_name: String,
    pub severity: Severity,
    pub summary: String,
    pub opened_at_ms: i64,
    pub resolved_at_ms: Option<i64>,
    /// Times the problem returned after clearing while this incident was held.
    pub repeats: u32,
    /// An opening notice went out and its recovery notice has not.
    pub notified: bool,
    pub last_notice_ms: Option<i64>,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize)]
#[serde(rename_all = "snake_case")]
pub enum Notice {
    Opened,
    Resolved,
    Test,
}

#[derive(Clone, Debug, Serialize)]
pub struct Delivery {
    pub tenant_id: Option<String>,
    pub id: u64,
    pub channel_id: String,
    pub channel_name: String,
    pub incident_key: String,
    /// Incidents covered by the message; a grouped message covers several.
    pub incidents: usize,
    pub notice: Notice,
    pub created_at_ms: i64,
    pub attempts: u32,
    pub status: &'static str,
    pub error: Option<String>,
}

#[derive(Default)]
struct State {
    open: HashMap<String, Incident>,
    resolved: VecDeque<Incident>,
    deliveries: VecDeque<Delivery>,
    last_event: u64,
    next_delivery: u64,
    /// By incident key: checks in a row that found the problem, and the
    /// observation the last one counted.
    streaks: HashMap<String, (u32, i64)>,
}

#[derive(Default)]
pub struct Alerts(Mutex<State>);

#[derive(Serialize)]
pub struct Snapshot {
    pub open: Vec<Incident>,
    pub resolved: Vec<Incident>,
    pub deliveries: Vec<Delivery>,
}

/// A change in an incident that may produce a notice.
enum Change {
    Open {
        key: String,
        node_id: String,
        severity: Severity,
        summary: String,
    },
    Resolve {
        key: String,
        summary: String,
    },
}

/// One rule's condition for one node, budget or DNS record.
#[derive(Debug)]
struct Check {
    key: String,
    /// The owner key in the worker's name map.
    owner: String,
    rule: Rule,
    severity: Severity,
    /// Changes when there is new data; a check whose observation equals the
    /// one counted last is not counted again.
    observation: i64,
    /// The problem is present.
    holds: bool,
    /// The incident text while it holds, otherwise the recovery text.
    summary: String,
}

impl Alerts {
    pub fn snapshot(&self) -> Snapshot {
        let state = self.0.lock().unwrap();
        let mut open: Vec<_> = state.open.values().cloned().collect();
        open.sort_by_key(|i| std::cmp::Reverse(i.opened_at_ms));
        Snapshot {
            open,
            resolved: state.resolved.iter().rev().cloned().collect(),
            deliveries: state.deliveries.iter().rev().cloned().collect(),
        }
    }

    /// Remove stale ownership before ingesting new events or exposing a snapshot.
    fn retain_owned(&self, owners: &HashMap<String, (String, String)>) {
        let mut state = self.0.lock().unwrap();
        let permitted = |i: &Incident| {
            owners
                .get(&i.node_id)
                .is_some_and(|(_, tenant)| tenant == &i.tenant_id)
        };
        state.open.retain(|_, i| permitted(i));
        state.resolved.retain(permitted);
    }

    fn apply(&self, change: Change, names: &HashMap<String, (String, String)>, now: i64) {
        let mut state = self.0.lock().unwrap();
        match change {
            Change::Open {
                key,
                node_id,
                severity,
                summary,
            } => {
                let Some((name, tenant)) = names.get(&node_id) else {
                    return;
                };
                if let Some(incident) = state.open.get_mut(&key) {
                    incident.summary = summary;
                    return;
                }
                let held = state
                    .resolved
                    .iter()
                    .rposition(|i| i.key == key && now - i.resolved_at_ms.unwrap_or(0) < HOLD_MS);
                let incident = match held {
                    Some(position) => {
                        let mut incident = state.resolved.remove(position).expect("found");
                        incident.resolved_at_ms = None;
                        incident.repeats += 1;
                        incident.summary = summary;
                        incident
                    }
                    None => Incident {
                        node_name: name.clone(),
                        tenant_id: tenant.clone(),
                        key: key.clone(),
                        node_id,
                        severity,
                        summary,
                        opened_at_ms: now,
                        resolved_at_ms: None,
                        repeats: 0,
                        notified: false,
                        last_notice_ms: None,
                    },
                };
                state.open.insert(key, incident);
            }
            Change::Resolve { key, summary } => {
                if let Some(mut incident) = state.open.remove(&key) {
                    incident.resolved_at_ms = Some(now);
                    incident.summary = summary;
                    state.resolved.push_back(incident);
                    while state.resolved.len() > KEEP_RESOLVED {
                        state.resolved.pop_front();
                    }
                }
            }
        }
    }

    /// Counts a rule's check and opens its incident once the problem was
    /// found on `rule.checks` checks in a row; one check without it resolves.
    /// A switched-off rule closes its incident.
    fn check(&self, check: Check, names: &HashMap<String, (String, String)>, now: i64) {
        let change = if !check.rule.enabled {
            self.0.lock().unwrap().streaks.remove(&check.key);
            Change::Resolve {
                key: check.key,
                summary: RULE_DISABLED.into(),
            }
        } else {
            let mut state = self.0.lock().unwrap();
            let streak = state
                .streaks
                .entry(check.key.clone())
                .or_insert((0, check.observation.wrapping_sub(1)));
            if streak.1 == check.observation {
                return;
            }
            *streak = (
                if check.holds {
                    streak.0.saturating_add(1)
                } else {
                    0
                },
                check.observation,
            );
            let found = streak.0;
            drop(state);
            match check.holds {
                false => Change::Resolve {
                    key: check.key,
                    summary: check.summary,
                },
                true if found >= check.rule.checks => Change::Open {
                    key: check.key,
                    node_id: check.owner,
                    severity: check.severity,
                    summary: check.summary,
                },
                true => return,
            }
        };
        self.apply(change, names, now);
    }

    /// Forgets the counts of conditions that were not checked in this pass:
    /// deleted objects and switched-off rules.
    fn keep_streaks(&self, checked: &std::collections::HashSet<String>) {
        self.0
            .lock()
            .unwrap()
            .streaks
            .retain(|key, _| checked.contains(key));
    }

    /// Notices due now: openings not yet announced (after the group wait,
    /// outside maintenance and the hold after the previous notice) and
    /// recoveries of announced ones.
    fn due(&self, maintenance: bool, now: i64) -> Vec<(Notice, Incident)> {
        let mut state = self.0.lock().unwrap();
        let mut due = vec![];
        for incident in state.open.values_mut() {
            if !incident.notified
                && !maintenance
                && now - incident.opened_at_ms >= GROUP_WAIT_MS
                && incident.last_notice_ms.is_none_or(|at| now - at >= HOLD_MS)
            {
                incident.notified = true;
                incident.last_notice_ms = Some(now);
                due.push((Notice::Opened, incident.clone()));
            }
        }
        for incident in state.resolved.iter_mut() {
            if incident.notified {
                incident.notified = false;
                incident.last_notice_ms = Some(now);
                due.push((Notice::Resolved, incident.clone()));
            }
        }
        due
    }

    fn record(
        &self,
        channel: &Channel,
        incident_key: &str,
        incidents: usize,
        notice: Notice,
    ) -> u64 {
        let mut state = self.0.lock().unwrap();
        state.next_delivery += 1;
        let id = state.next_delivery;
        state.deliveries.push_back(Delivery {
            tenant_id: channel.tenant_id.clone(),
            id,
            channel_id: channel.id.clone(),
            channel_name: channel.name.clone(),
            incident_key: incident_key.into(),
            incidents,
            notice,
            created_at_ms: now_ms(),
            attempts: 0,
            status: "pending",
            error: None,
        });
        while state.deliveries.len() > KEEP_DELIVERIES {
            state.deliveries.pop_front();
        }
        id
    }

    fn update(&self, id: u64, attempts: u32, status: &'static str, error: Option<String>) {
        let mut state = self.0.lock().unwrap();
        if let Some(delivery) = state.deliveries.iter_mut().find(|d| d.id == id) {
            delivery.attempts = attempts;
            delivery.status = status;
            delivery.error = error;
        }
    }
}

/// Reads new telemetry events and node silence into incidents, then sends due
/// notices. Runs until `stop`; `tick` is the polling interval.
pub async fn run(store: Store, tick: Duration, stop: CancellationToken) {
    let started = now_ms();
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()
        .expect("notification HTTP client");
    let mut interval = tokio::time::interval(tick);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    let mut pass = 0;
    loop {
        tokio::select! {
            biased;
            _ = stop.cancelled() => return,
            _ = interval.tick() => {}
        }
        let db = store.clone();
        let loaded = tokio::task::spawn_blocking(move || {
            Ok::<_, anyhow::Error>((
                db.alert_config()?,
                db.alert_nodes()?,
                db.alert_budgets()?,
                db.alert_dns_records()?,
            ))
        })
        .await;
        let ((settings, channels), nodes, budgets, records) = match loaded {
            Ok(Ok(loaded)) => loaded,
            Ok(Err(error)) => {
                tracing::warn!(%error, "alert state unavailable");
                continue;
            }
            Err(_) => return,
        };
        let now = now_ms();
        pass += 1;
        let alerts = store.alerts();
        // Owner key to name and tenant. DNS records belong to no tenant, so
        // only channels for all tenants receive them.
        let names: HashMap<_, _> = nodes
            .iter()
            .map(|n| (n.id.clone(), (n.name.clone(), n.tenant_id.clone())))
            .chain(budgets.iter().map(|b| {
                (
                    format!("budget:{}", b.id),
                    (b.name.clone(), b.tenant_id.clone()),
                )
            }))
            .chain(records.iter().map(|r| {
                (
                    format!("dns_record:{}", r.id),
                    (r.name.clone(), String::new()),
                )
            }))
            .collect();
        alerts.retain_owned(&names);
        let after = alerts.0.lock().unwrap().last_event;
        for event in store.telemetry_events_after(after) {
            alerts.0.lock().unwrap().last_event = event.id;
            if let Some(change) = change_for(&event) {
                alerts.apply(change, &names, event.at_ms);
            }
        }
        for node in &nodes {
            let key = format!("node:{}", node.id);
            let silent = node.last_seen_ms.map(|seen| now - seen);
            if node.watched && silent.is_some_and(|s| s > OFFLINE_AFTER_MS) {
                if now - started >= STARTUP_GRACE_MS {
                    alerts.apply(
                        Change::Open {
                            key,
                            node_id: node.id.clone(),
                            severity: Severity::Critical,
                            summary: format!(
                                "节点 {} 已 {} 秒无回报",
                                node.name,
                                silent.unwrap_or(0) / 1000
                            ),
                        },
                        &names,
                        now,
                    );
                }
            } else {
                alerts.apply(
                    Change::Resolve {
                        key,
                        summary: format!("节点 {} 恢复回报", node.name),
                    },
                    &names,
                    now,
                );
            }
        }
        let rules = settings.rules.unwrap_or_default();
        let mut checked = std::collections::HashSet::new();
        for check in conditions(&rules, &nodes, &budgets, &records, now, pass) {
            checked.insert(check.key.clone());
            alerts.check(check, &names, now);
        }
        alerts.keep_streaks(&checked);
        let due = alerts.due(settings.in_maintenance(now), now);
        for channel in channels.iter().filter(|c| c.enabled) {
            let batch: Vec<_> = due
                .iter()
                .filter(|(_, incident)| {
                    incident.severity >= channel.min_severity
                        && channel
                            .tenant_id
                            .as_ref()
                            .is_none_or(|t| t == &incident.tenant_id)
                })
                .cloned()
                .collect();
            let Some((_, first)) = batch.first() else {
                continue;
            };
            let notice = if batch.iter().any(|(n, _)| *n == Notice::Opened) {
                Notice::Opened
            } else {
                Notice::Resolved
            };
            let id = alerts.record(channel, &first.key, batch.len(), notice);
            let message = grouped(&batch);
            let ownership: Vec<_> = batch
                .iter()
                .map(|(_, i)| (i.node_id.clone(), i.tenant_id.clone()))
                .collect();
            let (client, channel, store) = (client.clone(), channel.clone(), store.clone());
            tokio::spawn(async move {
                deliver(&client, &channel, &message, &store, &ownership, id).await
            });
        }
    }
}

fn change_for(event: &crate::telemetry::Event) -> Option<Change> {
    let node = &event.node_id;
    Some(match event.kind {
        "target_down" => Change::Open {
            key: format!("target:{node}:{}", event.subject),
            node_id: node.clone(),
            severity: Severity::Warning,
            summary: event.message.clone(),
        },
        "target_recovered" | "target_removed" => Change::Resolve {
            key: format!("target:{node}:{}", event.subject),
            summary: event.message.clone(),
        },
        "config_rejected" => Change::Open {
            key: format!("config:{node}"),
            node_id: node.clone(),
            severity: Severity::Critical,
            summary: event.message.clone(),
        },
        "config_recovered" => Change::Resolve {
            key: format!("config:{node}"),
            summary: event.message.clone(),
        },
        _ => return None,
    })
}

/// Every rule's condition on the current state. CPU and memory count one
/// check per node report, so a report seen on several passes counts once;
/// a node without a new report keeps its count and its incident. The other
/// conditions count once per pass (`pass` increases with each).
fn conditions(
    rules: &Rules,
    nodes: &[crate::store::AlertNode],
    budgets: &[crate::store::AlertBudget],
    records: &[crate::store::AlertDnsRecord],
    now: i64,
    pass: i64,
) -> Vec<Check> {
    let mut checks = vec![];
    let mut add = |key: String, owner: &str, rule: Rule, severity, observation, holds, summary| {
        checks.push(Check {
            key,
            owner: owner.to_string(),
            rule,
            severity,
            observation,
            holds,
            summary,
        })
    };
    for node in nodes {
        let (id, name) = (&node.id, &node.name);
        if let Some(sample) = &node.usage {
            if let Some(cpu) = sample.cpu_percent {
                let rule = rules.node_cpu;
                let limit = rule.threshold.unwrap_or(100);
                let holds = f64::from(cpu) >= f64::from(limit);
                let percent = cpu.floor() as u32;
                add(
                    format!("cpu:{id}"),
                    id,
                    rule,
                    Severity::Warning,
                    sample.at_ms,
                    holds,
                    if holds {
                        format!(
                            "节点 {name} CPU 使用率 {percent}%，连续 {} 次回报不低于 {limit}%",
                            rule.checks
                        )
                    } else {
                        format!("节点 {name} CPU 使用率回落到 {percent}%")
                    },
                );
            }
            if let (Some(total), Some(available)) =
                (sample.memory_total_bytes, sample.memory_available_bytes)
                && total > 0
            {
                let rule = rules.node_memory;
                let limit = rule.threshold.unwrap_or(100);
                let used = u128::from(total.saturating_sub(available));
                let holds = used * 100 >= u128::from(limit) * u128::from(total);
                let percent = used * 100 / u128::from(total);
                add(
                    format!("memory:{id}"),
                    id,
                    rule,
                    Severity::Warning,
                    sample.at_ms,
                    holds,
                    if holds {
                        format!(
                            "节点 {name} 内存使用率 {percent}%，连续 {} 次回报不低于 {limit}%",
                            rule.checks
                        )
                    } else {
                        format!("节点 {name} 内存使用率回落到 {percent}%")
                    },
                );
            }
        }
        let expires = node.expires_at_ms;
        let days = i64::from(rules.node_expiring.threshold.unwrap_or(0));
        let passed = |at: i64| at <= now;
        let summary = |at: i64| match passed(at) {
            true => format!("节点 {name} 已于 {} 到期", utc(at)),
            false => format!("节点 {name} 将于 {} 到期", utc(at)),
        };
        let extended = format!("节点 {name} 的到期时间已延后或取消");
        let soon = expires.filter(|at| at.saturating_sub(now) <= days * DAY_MS);
        add(
            format!("expiring:{id}"),
            id,
            rules.node_expiring,
            Severity::Warning,
            pass,
            soon.is_some(),
            soon.map_or_else(|| extended.clone(), summary),
        );
        let over = expires.filter(|at| passed(*at));
        add(
            format!("expired:{id}"),
            id,
            rules.node_expired,
            Severity::Critical,
            pass,
            over.is_some(),
            over.map_or(extended, summary),
        );
    }
    for budget in budgets {
        let owner = format!("budget:{}", budget.id);
        let name = &budget.name;
        // A zero limit is an operator's stop for new allocations, not a surprise.
        let (limit, committed) = (
            u128::from(budget.limit_bytes),
            u128::from(budget.committed_bytes),
        );
        let percent = (committed * 100).checked_div(limit).unwrap_or(0);
        let rule = rules.budget_near;
        let threshold = u128::from(rule.threshold.unwrap_or(100));
        let near = limit > 0 && committed * 100 >= threshold * limit;
        add(
            format!("budget_near:{}", budget.id),
            &owner,
            rule,
            Severity::Warning,
            pass,
            near,
            if near {
                format!("共享额度 {name} 已占用 {percent}%，阈值 {threshold}%")
            } else {
                format!("共享额度 {name} 占用回落到 {percent}%")
            },
        );
        let exhausted = limit > 0 && committed >= limit;
        add(
            format!("budget_exhausted:{}", budget.id),
            &owner,
            rules.budget_exhausted,
            Severity::Critical,
            pass,
            exhausted,
            if exhausted {
                format!("共享额度 {name} 已用尽，无法再分配流量")
            } else {
                format!("共享额度 {name} 恢复可分配")
            },
        );
    }
    for record in records {
        let error = record.error.as_deref();
        add(
            format!("dns:{}", record.id),
            &format!("dns_record:{}", record.id),
            rules.dns_sync_failed,
            Severity::Warning,
            pass,
            error.is_some(),
            match error {
                Some(error) => format!(
                    "DNS 记录 {} 同步失败：{}",
                    record.name,
                    error.chars().take(300).collect::<String>()
                ),
                None => format!("DNS 记录 {} 同步恢复", record.name),
            },
        );
    }
    checks
}

pub fn message(notice: Notice, incident: &Incident) -> String {
    let level = match incident.severity {
        Severity::Critical => "严重",
        _ => "警告",
    };
    let repeats = if incident.repeats > 0 {
        format!("\n期间反复出现 {} 次", incident.repeats)
    } else {
        String::new()
    };
    match notice {
        Notice::Opened => format!(
            "【告警·{level}】{}\n{}\n开始于 {}{repeats}",
            incident.node_name,
            incident.summary,
            utc(incident.opened_at_ms)
        ),
        Notice::Resolved => format!(
            "【已恢复】{}\n{}\n持续 {}{repeats}",
            incident.node_name,
            incident.summary,
            duration(
                incident.resolved_at_ms.unwrap_or(incident.opened_at_ms) - incident.opened_at_ms
            )
        ),
        Notice::Test => TEST_MESSAGE.into(),
    }
}

/// One message for every notice due on a channel at once.
pub fn grouped(batch: &[(Notice, Incident)]) -> String {
    if let [(notice, incident)] = batch {
        return message(*notice, incident);
    }
    let opened = batch.iter().filter(|(n, _)| *n == Notice::Opened).count();
    let critical = batch
        .iter()
        .any(|(n, i)| *n == Notice::Opened && i.severity == Severity::Critical);
    let mut text = match (opened, batch.len() - opened) {
        (0, resolved) => format!("【已恢复】{resolved} 个问题已恢复"),
        (opened, 0) => format!(
            "【告警·{}】{opened} 个新问题",
            if critical { "严重" } else { "警告" }
        ),
        (opened, resolved) => format!(
            "【告警·{}】{opened} 个新问题，{resolved} 个已恢复",
            if critical { "严重" } else { "警告" }
        ),
    };
    // New problems first, the most severe at the top.
    let mut order: Vec<_> = batch.iter().collect();
    order.sort_by_key(|(n, i)| (*n != Notice::Opened, std::cmp::Reverse(i.severity)));
    for (notice, incident) in order.iter().take(LIST_LIMIT) {
        let tag = match (notice, incident.severity) {
            (Notice::Resolved, _) => "恢复",
            (_, Severity::Critical) => "严重",
            _ => "警告",
        };
        text += &format!("\n• [{tag}] {}：{}", incident.node_name, incident.summary);
    }
    if batch.len() > LIST_LIMIT {
        text += &format!(
            "\n…另有 {} 条，详见控制台“告警通知”",
            batch.len() - LIST_LIMIT
        );
    }
    text
}

/// Sends with retries, recording each outcome in the delivery log.
pub async fn deliver(
    client: &reqwest::Client,
    channel: &Channel,
    message: &str,
    store: &Store,
    ownership: &[(String, String)],
    id: u64,
) -> Result<()> {
    let alerts = store.alerts();
    let mut attempts = 0;
    loop {
        let (db, saved, nodes) = (store.clone(), channel.clone(), ownership.to_vec());
        let permitted =
            tokio::task::spawn_blocking(move || db.alert_delivery_permitted(&saved, &nodes))
                .await??;
        if !permitted {
            alerts.update(
                id,
                attempts,
                "cancelled",
                Some("channel or node ownership changed".into()),
            );
            return Ok(());
        }
        attempts += 1;
        let error = match send(client, channel, message).await {
            Ok(()) => {
                alerts.update(id, attempts, "sent", None);
                return Ok(());
            }
            Err(error) => format!("{error:#}"),
        };
        let Some(delay) = RETRY_DELAYS.get(attempts as usize - 1) else {
            alerts.update(id, attempts, "failed", Some(error.clone()));
            anyhow::bail!(error);
        };
        alerts.update(id, attempts, "retrying", Some(error));
        tokio::time::sleep(*delay).await;
    }
}

/// One attempt at a test message, recorded in the delivery log.
pub async fn test(channel: &Channel, alerts: &Alerts) -> Result<()> {
    let client = reqwest::Client::builder()
        .timeout(Duration::from_secs(10))
        .build()?;
    let id = alerts.record(channel, "test", 0, Notice::Test);
    let result = send(&client, channel, TEST_MESSAGE).await;
    match &result {
        Ok(()) => alerts.update(id, 1, "sent", None),
        Err(error) => alerts.update(id, 1, "failed", Some(format!("{error:#}"))),
    }
    result
}

async fn send(client: &reqwest::Client, channel: &Channel, message: &str) -> Result<()> {
    if let Target::Smtp { config } = &channel.target {
        return crate::email::send(config, "Relay platform alert", message).await;
    }
    let (url, body, headers) = request(&channel.target, message, now_ms())?;
    let mut builder = client.post(url).header("content-type", "application/json");
    for (name, value) in headers {
        builder = builder.header(name, value);
    }
    let response = builder.body(body).send().await?;
    let status = response.status();
    let text = response.text().await.unwrap_or_default();
    ensure!(
        status.is_success(),
        "HTTP {status}: {}",
        text.chars().take(200).collect::<String>()
    );
    // These services report some failures with HTTP 200 and an error code.
    if let Ok(reply) = serde_json::from_str::<serde_json::Value>(&text) {
        let failed = match &channel.target {
            Target::Telegram { .. } => reply["ok"] == false,
            Target::Wecom { .. } | Target::Dingtalk { .. } => {
                reply["errcode"].as_i64().is_some_and(|code| code != 0)
            }
            Target::Feishu { .. } => reply["code"].as_i64().is_some_and(|code| code != 0),
            Target::Webhook { .. } | Target::Smtp { .. } => false,
        };
        ensure!(
            !failed,
            "provider rejected the message: {}",
            text.chars().take(200).collect::<String>()
        );
    }
    Ok(())
}

/// URL, JSON body and extra headers for one message.
pub type Request = (String, String, Vec<(&'static str, String)>);

pub fn request(target: &Target, message: &str, now: i64) -> Result<Request> {
    let sign = |key: &[u8], data: &[u8]| {
        ring::hmac::sign(&ring::hmac::Key::new(ring::hmac::HMAC_SHA256, key), data)
    };
    Ok(match target {
        Target::Smtp { .. } => anyhow::bail!("SMTP channels do not use HTTP requests"),
        Target::Webhook { url, secret } => {
            let body = serde_json::json!({"text": message, "sent_at_ms": now}).to_string();
            let headers = if secret.is_empty() {
                vec![]
            } else {
                let tag = sign(secret.as_bytes(), body.as_bytes());
                let hex: String = tag.as_ref().iter().map(|b| format!("{b:02x}")).collect();
                vec![("x-relay-signature", format!("sha256={hex}"))]
            };
            (url.clone(), body, headers)
        }
        Target::Telegram { bot_token, chat_id } => (
            format!("https://api.telegram.org/bot{bot_token}/sendMessage"),
            serde_json::json!({"chat_id": chat_id, "text": message, "disable_web_page_preview": true})
                .to_string(),
            vec![],
        ),
        Target::Wecom { url } => (
            url.clone(),
            serde_json::json!({"msgtype": "text", "text": {"content": message}}).to_string(),
            vec![],
        ),
        Target::Feishu { url, secret } => {
            let mut body = serde_json::json!({"msg_type": "text", "content": {"text": message}});
            if !secret.is_empty() {
                // Feishu signs "timestamp\nsecret" as the HMAC key over an empty message.
                let seconds = now / 1000;
                let tag = sign(format!("{seconds}\n{secret}").as_bytes(), b"");
                body["timestamp"] = seconds.to_string().into();
                body["sign"] = STANDARD.encode(tag.as_ref()).into();
            }
            (url.clone(), body.to_string(), vec![])
        }
        Target::Dingtalk { url, secret } => {
            let mut url = reqwest::Url::parse(url)?;
            if !secret.is_empty() {
                // DingTalk signs "timestamp\nsecret" with the secret as key.
                let tag = sign(secret.as_bytes(), format!("{now}\n{secret}").as_bytes());
                url.query_pairs_mut()
                    .append_pair("timestamp", &now.to_string())
                    .append_pair("sign", &STANDARD.encode(tag.as_ref()));
            }
            (
                url.to_string(),
                serde_json::json!({"msgtype": "text", "text": {"content": message}}).to_string(),
                vec![],
            )
        }
    })
}

fn duration(ms: i64) -> String {
    let s = ms.max(0) / 1000;
    match s {
        0..60 => format!("{s} 秒"),
        60..3600 => format!("{} 分 {} 秒", s / 60, s % 60),
        _ => format!("{} 小时 {} 分", s / 3600, s % 3600 / 60),
    }
}

/// "YYYY-MM-DD HH:MM:SS UTC" from Unix milliseconds.
pub fn utc(ms: i64) -> String {
    let seconds = ms.div_euclid(1000);
    let (days, rest) = (seconds.div_euclid(86_400), seconds.rem_euclid(86_400));
    // Civil date from days since 1970-01-01 (Howard Hinnant's algorithm).
    let z = days + 719_468;
    let era = z.div_euclid(146_097);
    let doe = z - era * 146_097;
    let yoe = (doe - doe / 1460 + doe / 36_524 - doe / 146_096) / 365;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let day = doy - (153 * mp + 2) / 5 + 1;
    let month = if mp < 10 { mp + 3 } else { mp - 9 };
    let year = yoe + era * 400 + i64::from(month <= 2);
    format!(
        "{year:04}-{month:02}-{day:02} {:02}:{:02}:{:02} UTC",
        rest / 3600,
        rest % 3600 / 60,
        rest % 60
    )
}

#[cfg(test)]
mod tests {
    use super::*;

    const NOW: i64 = 1_700_000_000_123;

    #[test]
    fn signatures_match_each_provider_specification() {
        let secret = "s3cret".to_string();
        // Expected values computed separately with Python's hmac module.
        let (_, body, headers) = request(
            &Target::Webhook {
                url: "https://hooks.example/a".into(),
                secret: secret.clone(),
            },
            "hi",
            NOW,
        )
        .unwrap();
        assert_eq!(body, r#"{"sent_at_ms":1700000000123,"text":"hi"}"#);
        assert_eq!(
            headers,
            [(
                "x-relay-signature",
                "sha256=33db80e02eea4ee29fecac15d32631ed465d2182c87aa4d3d5d033e856dc4c2e"
                    .to_string()
            )]
        );

        let (_, body, _) = request(
            &Target::Feishu {
                url: "https://open.feishu.cn/hook/x".into(),
                secret: secret.clone(),
            },
            "hi",
            NOW,
        )
        .unwrap();
        let body: serde_json::Value = serde_json::from_str(&body).unwrap();
        assert_eq!(body["timestamp"], "1700000000");
        assert_eq!(body["sign"], "IX3eHI0/v/Td7jqJ0ynSEK3Dq5JY3HUZeoeMgVZeZGo=");

        let (url, _, _) = request(
            &Target::Dingtalk {
                url: "https://oapi.dingtalk.com/robot/send?access_token=t".into(),
                secret,
            },
            "hi",
            NOW,
        )
        .unwrap();
        assert_eq!(
            url,
            "https://oapi.dingtalk.com/robot/send?access_token=t&timestamp=1700000000123\
             &sign=Q%2FGu1K6gif%2F%2FXkCNhmmMXCz3dFOshDi118WieTgZpto%3D"
        );

        // Without a secret nothing is signed.
        let (_, _, headers) = request(
            &Target::Webhook {
                url: "https://hooks.example/a".into(),
                secret: String::new(),
            },
            "hi",
            NOW,
        )
        .unwrap();
        assert!(headers.is_empty());
    }

    #[test]
    fn utc_formats_leap_days_and_times_before_1970() {
        assert_eq!(utc(0), "1970-01-01 00:00:00 UTC");
        assert_eq!(utc(951_786_123_000), "2000-02-29 01:02:03 UTC");
        assert_eq!(utc(-1), "1969-12-31 23:59:59 UTC");
        assert_eq!(utc(4_102_444_799_000), "2099-12-31 23:59:59 UTC");
    }

    fn open(alerts: &Alerts, at: i64) {
        alerts.apply(
            Change::Open {
                key: "target:n:r".into(),
                node_id: "n".into(),
                severity: Severity::Warning,
                summary: "down".into(),
            },
            &HashMap::from([("n".into(), ("edge-01".into(), "default".into()))]),
            at,
        );
    }
    fn resolve(alerts: &Alerts, at: i64) {
        alerts.apply(
            Change::Resolve {
                key: "target:n:r".into(),
                summary: "up".into(),
            },
            &HashMap::new(),
            at,
        );
    }
    fn notices(alerts: &Alerts, maintenance: bool, at: i64) -> Vec<Notice> {
        alerts
            .due(maintenance, at)
            .into_iter()
            .map(|(n, _)| n)
            .collect()
    }

    #[test]
    fn a_flapping_problem_is_one_incident_with_held_notices() {
        let alerts = Alerts::default();
        open(&alerts, NOW);
        assert_eq!(notices(&alerts, false, NOW + GROUP_WAIT_MS - 1), []);
        assert_eq!(
            notices(&alerts, false, NOW + GROUP_WAIT_MS),
            [Notice::Opened]
        );
        assert_eq!(notices(&alerts, false, NOW + GROUP_WAIT_MS + 1), []);
        let at = NOW + GROUP_WAIT_MS;
        resolve(&alerts, at + 2_000);
        assert_eq!(notices(&alerts, false, at + 2_000), [Notice::Resolved]);

        // It returns and clears twice inside the hold: no notices at all.
        open(&alerts, at + 3_000);
        assert_eq!(notices(&alerts, false, at + 3_000 + GROUP_WAIT_MS), []);
        resolve(&alerts, at + 4_000);
        open(&alerts, at + 5_000);
        assert_eq!(notices(&alerts, false, at + 5_000 + GROUP_WAIT_MS), []);
        let snapshot = alerts.snapshot();
        assert_eq!((snapshot.open.len(), snapshot.resolved.len()), (1, 0));
        assert_eq!(snapshot.open[0].repeats, 2);
        assert_eq!(snapshot.open[0].opened_at_ms, NOW);
        assert_eq!(snapshot.open[0].node_name, "edge-01");

        // Still open when the hold after the last notice ends: announce it again.
        assert_eq!(notices(&alerts, false, at + 2_000 + HOLD_MS - 1), []);
        let due = alerts.due(false, at + 2_000 + HOLD_MS);
        assert_eq!(due.len(), 1);
        assert!(grouped(&due).contains("反复出现 2 次"));
        resolve(&alerts, at + 2_000 + HOLD_MS + 1);
        assert_eq!(
            notices(&alerts, false, at + 2_000 + HOLD_MS + 1),
            [Notice::Resolved]
        );

        // A return after the hold since it cleared is a new incident.
        open(&alerts, NOW + 3 * HOLD_MS);
        let snapshot = alerts.snapshot();
        assert_eq!((snapshot.open[0].repeats, snapshot.resolved.len()), (0, 1));
        assert_eq!(
            notices(&alerts, false, NOW + 3 * HOLD_MS + GROUP_WAIT_MS),
            [Notice::Opened]
        );
    }

    #[test]
    fn maintenance_holds_openings_and_unannounced_recoveries_stay_silent() {
        let alerts = Alerts::default();
        open(&alerts, NOW);
        assert_eq!(notices(&alerts, true, NOW + GROUP_WAIT_MS), []);
        // Still open after maintenance: sent then.
        assert_eq!(notices(&alerts, false, NOW + 60_000), [Notice::Opened]);

        let quiet = Alerts::default();
        open(&quiet, NOW);
        assert_eq!(notices(&quiet, true, NOW + GROUP_WAIT_MS), []);
        resolve(&quiet, NOW + 1_000);
        assert_eq!(notices(&quiet, false, NOW + 2_000), []);
    }

    #[test]
    fn grouped_messages_list_new_and_critical_problems_first() {
        let incident = |node: &str, severity| Incident {
            tenant_id: "default".into(),
            key: node.into(),
            node_id: node.into(),
            node_name: node.into(),
            severity,
            summary: format!("{node} problem"),
            opened_at_ms: NOW,
            resolved_at_ms: Some(NOW + 1_000),
            repeats: 0,
            notified: false,
            last_notice_ms: None,
        };
        let mut batch = vec![(Notice::Resolved, incident("r", Severity::Critical))];
        batch.extend((0..11).map(|i| {
            (
                Notice::Opened,
                incident(&format!("w{i}"), Severity::Warning),
            )
        }));
        batch.push((Notice::Opened, incident("c", Severity::Critical)));
        let text = grouped(&batch);
        let lines: Vec<_> = text.lines().collect();
        assert_eq!(lines[0], "【告警·严重】12 个新问题，1 个已恢复");
        assert_eq!(lines[1], "• [严重] c：c problem");
        assert_eq!(lines[2], "• [警告] w0：w0 problem");
        // Ten listed; the recovery sorts last and is counted with the rest.
        assert_eq!(lines.len(), 12);
        assert_eq!(lines[11], "…另有 3 条，详见控制台“告警通知”");
        assert!(!text.contains("r problem"));
        assert_eq!(grouped(&batch[..1]), message(Notice::Resolved, &batch[0].1));
        assert!(grouped(&batch[..2]).starts_with("【告警·警告】1 个新问题，1 个已恢复"));
    }

    fn node(cpu: Option<f32>, at: i64, expires_at_ms: Option<i64>) -> crate::store::AlertNode {
        crate::store::AlertNode {
            tenant_id: "default".into(),
            id: "n".into(),
            name: "edge-01".into(),
            last_seen_ms: Some(at),
            watched: true,
            expires_at_ms,
            usage: Some(crate::telemetry::Sample {
                at_ms: at,
                forwarded_bytes: 0,
                active_sessions: 0,
                failed_connections: 0,
                cpu_percent: cpu,
                process_cpu_percent: None,
                rss_bytes: None,
                memory_total_bytes: Some(1000),
                memory_available_bytes: Some(900),
                probe_latency_us: None,
                healthy_targets: 0,
                probed_targets: 0,
            }),
        }
    }
    fn on(threshold: Option<u32>, checks: u32) -> Rule {
        Rule {
            enabled: true,
            threshold,
            checks,
        }
    }

    #[test]
    fn a_rule_opens_after_its_consecutive_checks_and_resolves_when_cleared() {
        let alerts = Alerts::default();
        let names = HashMap::from([("n".into(), ("edge-01".into(), "default".into()))]);
        let mut rules = Rules {
            node_cpu: on(Some(80), 3),
            ..Rules::default()
        };
        let mut pass = 0;
        let mut report = |rules: &Rules, cpu: f32, at: i64| {
            pass += 1;
            for check in conditions(rules, &[node(Some(cpu), at, None)], &[], &[], NOW, pass) {
                alerts.check(check, &names, NOW + at);
            }
            let snapshot = alerts.snapshot();
            let open: Vec<_> = snapshot.open.iter().map(|i| i.key.clone()).collect();
            (open, snapshot.resolved)
        };
        // Two reports above the threshold; the second seen on three passes
        // still counts once.
        report(&rules, 95.0, 1);
        report(&rules, 95.0, 2);
        report(&rules, 95.0, 2);
        assert!(report(&rules, 95.0, 2).0.is_empty());
        // One report below starts the count again.
        report(&rules, 79.9, 3);
        report(&rules, 95.0, 4);
        assert!(report(&rules, 95.0, 5).0.is_empty());
        let (open, _) = report(&rules, 80.0, 6);
        assert_eq!(open, ["cpu:n"]);
        let incident = &alerts.snapshot().open[0];
        assert_eq!(
            (incident.severity, incident.node_name.as_str()),
            (Severity::Warning, "edge-01")
        );
        assert_eq!(
            incident.summary,
            "节点 edge-01 CPU 使用率 80%，连续 3 次回报不低于 80%"
        );
        let (open, resolved) = report(&rules, 50.4, 7);
        assert!(open.is_empty());
        assert_eq!(resolved[0].summary, "节点 edge-01 CPU 使用率回落到 50%");

        // Switched off while the problem lasts: the incident closes and
        // stays closed however long it lasts.
        for at in 8..11 {
            report(&rules, 99.0, at);
        }
        assert_eq!(alerts.snapshot().open.len(), 1);
        rules.node_cpu.enabled = false;
        for at in 11..20 {
            let (open, resolved) = report(&rules, 99.0, at);
            assert!(open.is_empty());
            assert_eq!(resolved.last().unwrap().summary, RULE_DISABLED);
        }
        // Switched on again, it counts from zero.
        rules.node_cpu.enabled = true;
        report(&rules, 99.0, 20);
        assert!(report(&rules, 99.0, 21).0.is_empty());
        assert_eq!(report(&rules, 99.0, 22).0, ["cpu:n"]);
    }

    #[test]
    fn conditions_follow_each_threshold() {
        let rules = Rules {
            node_cpu: on(Some(90), 1),
            node_memory: on(Some(90), 1),
            node_expiring: on(Some(7), 1),
            node_expired: on(None, 1),
            budget_near: on(Some(90), 1),
            budget_exhausted: on(None, 1),
            dns_sync_failed: on(None, 1),
        };
        let budget = |id: &str, limit_bytes, committed_bytes| crate::store::AlertBudget {
            tenant_id: "default".into(),
            id: id.into(),
            name: id.into(),
            limit_bytes,
            committed_bytes,
        };
        let record = |id: &str, error: Option<&str>| crate::store::AlertDnsRecord {
            id: id.into(),
            name: format!("{id}.example.com A"),
            error: error.map(Into::into),
        };
        let mut nodes = vec![];
        for (id, available, expires) in [
            ("full", 100, Some(NOW + 7 * DAY_MS)),
            ("roomy", 101, Some(NOW + 7 * DAY_MS + 1)),
            ("over", 900, Some(NOW)),
            ("open", 900, None),
        ] {
            let mut n = node(Some(10.0), NOW, expires);
            n.id = id.into();
            n.name = id.into();
            n.usage.as_mut().unwrap().memory_available_bytes = Some(available);
            nodes.push(n);
        }
        let checks = conditions(
            &rules,
            &nodes,
            &[
                budget("near", 1000, 900),
                budget("below", 1000, 899),
                budget("empty", 1000, 1000),
                budget("stopped", 0, 0),
            ],
            &[record("bad", Some("HTTP 403")), record("good", None)],
            NOW,
            1,
        );
        let found: Vec<(&str, Severity)> = checks
            .iter()
            .filter(|c| c.holds)
            .map(|c| (c.key.as_str(), c.severity))
            .collect();
        assert_eq!(
            found,
            [
                ("memory:full", Severity::Warning),
                ("expiring:full", Severity::Warning),
                ("expiring:over", Severity::Warning),
                ("expired:over", Severity::Critical),
                ("budget_near:near", Severity::Warning),
                ("budget_near:empty", Severity::Warning),
                ("budget_exhausted:empty", Severity::Critical),
                ("dns:bad", Severity::Warning),
            ]
        );
        let summary = |key: &str| &checks.iter().find(|c| c.key == key).unwrap().summary;
        assert_eq!(
            summary("memory:full"),
            "节点 full 内存使用率 90%，连续 1 次回报不低于 90%"
        );
        assert_eq!(
            summary("expiring:full"),
            "节点 full 将于 2023-11-21 22:13:20 UTC 到期"
        );
        assert_eq!(
            summary("expired:over"),
            "节点 over 已于 2023-11-14 22:13:20 UTC 到期"
        );
        assert_eq!(
            summary("budget_near:near"),
            "共享额度 near 已占用 90%，阈值 90%"
        );
        assert_eq!(
            summary("budget_exhausted:below"),
            "共享额度 below 恢复可分配"
        );
        assert_eq!(
            summary("dns:bad"),
            "DNS 记录 bad.example.com A 同步失败：HTTP 403"
        );
        // Budgets and DNS records are owned through prefixed keys.
        let owner = |key: &str| &checks.iter().find(|c| c.key == key).unwrap().owner;
        assert_eq!(owner("budget_near:near"), "budget:near");
        assert_eq!(owner("dns:bad"), "dns_record:bad");
        assert_eq!(owner("expired:over"), "over");
    }

    #[test]
    fn settings_load_without_rules_and_rules_are_validated() {
        let old: Settings = serde_json::from_str(r#"{"maintenance_until_ms":5}"#).unwrap();
        assert_eq!(old.rules, None);
        assert_eq!(
            serde_json::to_string(&Settings::default()).unwrap(),
            r#"{"maintenance_until_ms":null}"#,
            "settings without rules are written as before"
        );
        let partial: Settings = serde_json::from_str(
            r#"{"rules":{"node_cpu":{"enabled":true,"threshold":70,"checks":2}}}"#,
        )
        .unwrap();
        let rules = partial.rules.unwrap();
        assert_eq!(rules.node_cpu, on(Some(70), 2));
        assert_eq!(rules.dns_sync_failed, Rules::default().dns_sync_failed);
        assert!(
            Rules::default().validate().is_ok()
                && [
                    Rules::default().node_cpu,
                    Rules::default().budget_exhausted,
                    Rules::default().node_expired,
                ]
                .iter()
                .all(|r| !r.enabled)
        );
        assert!(serde_json::from_str::<Settings>(r#"{"rules":{"cpu":{}}}"#).is_err());
        for broken in [
            Rules {
                node_cpu: on(Some(0), 1),
                ..Rules::default()
            },
            Rules {
                budget_near: on(Some(101), 1),
                ..Rules::default()
            },
            Rules {
                node_expiring: on(Some(366), 1),
                ..Rules::default()
            },
            Rules {
                node_memory: on(None, 1),
                ..Rules::default()
            },
            Rules {
                node_expired: on(Some(1), 1),
                ..Rules::default()
            },
            Rules {
                dns_sync_failed: on(None, 0),
                ..Rules::default()
            },
            Rules {
                dns_sync_failed: on(None, MAX_CHECKS + 1),
                ..Rules::default()
            },
        ] {
            assert!(broken.validate().is_err(), "{broken:?}");
        }
    }

    #[test]
    fn edits_keep_saved_secrets_left_blank() {
        let saved = Channel {
            tenant_id: None,
            id: "c".into(),
            name: "ops".into(),
            enabled: true,
            min_severity: Severity::Warning,
            target: Target::Dingtalk {
                url: "https://oapi.dingtalk.com/x".into(),
                secret: "old".into(),
            },
        };
        let mut edit = saved.clone();
        edit.target = Target::Dingtalk {
            url: String::new(),
            secret: String::new(),
        };
        edit.keep_secrets_from(&saved);
        assert_eq!(edit.target, saved.target);
        // A different kind replaces everything.
        edit.target = Target::Wecom { url: String::new() };
        edit.keep_secrets_from(&saved);
        assert!(edit.validate().is_err());
        let view = saved.view();
        assert_eq!(view.destination, "https://oapi.dingtalk.com/…");
        assert!(view.secret_set);
    }
}
