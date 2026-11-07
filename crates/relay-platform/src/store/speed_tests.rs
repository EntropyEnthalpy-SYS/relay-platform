//! Speed tests on the controller. A test is a job in metadata
//! (`speed_test:<id>`), so the schema and recovery log stay unchanged; the
//! last [`KEEP`] ended jobs are kept. Running jobs are listed in
//! `speed_tests_running`, so a sync reads only those. The per-segment
//! tokens are kept apart (`speed_test_token:<id>`), go only to the two
//! agents of their segment and are deleted when the job ends.
//!
//! Segments run one after another. The controller sends each agent its
//! part of the running segment in `SyncResponse::speed_test_tasks` and
//! wakes its watch; the dialing (or Cloudflare) agent reports the results,
//! which move the job on. Agents that never reported support
//! (`speed_test_node:<node id>`, written once, as for rate limits) get
//! nothing, and a test that would need one is refused with 409.
use super::*;
use crate::node::ForwardingDefaults;
use crate::speed_test::{
    Job, JobState, JobView, Kind, LimitKind, Mode, Params, PathLimit, PathPlan, PathRule,
    PathTestInput, PlanHop, PlanSegment, PlanTarget, Progress, Report, Segment, ServerTestInput,
    StepState, TargetProbe, Task, TaskReport, TaskRole, TaskState,
};
use std::collections::{HashMap, HashSet};
use std::net::SocketAddr;

/// Ended jobs kept for the history.
pub const KEEP: usize = 50;
const ONLINE_MS: i64 = 90_000;
/// Between two tests started by the same account that is not a system
/// administrator.
const COOLDOWN_MS: i64 = 60_000;
const MAX_HOPS: usize = 16;
const RUNNING: &str = "speed_tests_running";
/// How long the controller waits for a target probe's result.
const PROBE_DEADLINE_MS: i64 = 45_000;

/// Watch wakes and the running segments' latest progress; neither needs
/// to survive a restart.
#[derive(Default)]
pub(super) struct Live {
    wake: HashSet<String>,
    progress: HashMap<String, TaskReport>,
}

fn key(id: &str) -> String {
    format!("speed_test:{id}")
}
fn token_key(id: &str) -> String {
    format!("speed_test_token:{id}")
}
fn node_key(node: &str) -> String {
    format!("speed_test_node:{node}")
}
/// One agent's part of one step; the role keeps a server's two parts of
/// one step apart.
fn task_id(job: &str, step: usize, role: TaskRole) -> String {
    let role = match role {
        TaskRole::Listen => "l",
        TaskRole::Dial => "d",
        TaskRole::Cloudflare => "c",
        TaskRole::Connect => "t",
    };
    format!("{job}-{step}-{role}")
}

fn get(conn: &Connection, key: &str) -> Result<Option<String>> {
    Ok(conn
        .query_row("SELECT value FROM metadata WHERE key=?1", [key], |r| {
            r.get(0)
        })
        .optional()?)
}
fn set(tx: &Transaction<'_>, key: &str, value: &str) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, value],
    )?;
    Ok(())
}
fn load(conn: &Connection, id: &str) -> Result<Option<Job>> {
    get(conn, &key(id))?
        .map(|value| serde_json::from_str(&value).context("invalid stored speed test"))
        .transpose()
}
fn save(tx: &Transaction<'_>, job: &Job) -> Result<()> {
    set(tx, &key(&job.id), &serde_json::to_string(job)?)
}
fn all(conn: &Connection) -> Result<Vec<Job>> {
    let mut q = conn.prepare("SELECT value FROM metadata WHERE key GLOB 'speed_test:*'")?;
    let rows: Vec<String> = q
        .query_map([], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    rows.into_iter()
        .map(|value| serde_json::from_str(&value).context("invalid stored speed test"))
        .collect()
}
fn running_ids(conn: &Connection) -> Result<Vec<String>> {
    Ok(get(conn, RUNNING)?
        .map(|value| serde_json::from_str(&value))
        .transpose()?
        .unwrap_or_default())
}
fn set_running(tx: &Transaction<'_>, ids: &[String]) -> Result<()> {
    if ids.is_empty() {
        tx.execute("DELETE FROM metadata WHERE key=?1", [RUNNING])?;
        Ok(())
    } else {
        set(tx, RUNNING, &serde_json::to_string(ids)?)
    }
}
fn running(conn: &Connection) -> Result<Vec<Job>> {
    let mut jobs = vec![];
    for id in running_ids(conn)? {
        if let Some(job) = load(conn, &id)?
            && job.state == JobState::Running
        {
            jobs.push(job);
        }
    }
    Ok(jobs)
}
fn tokens(conn: &Connection, id: &str) -> Result<Vec<String>> {
    Ok(get(conn, &token_key(id))?
        .map(|value| serde_json::from_str(&value))
        .transpose()?
        .unwrap_or_default())
}

/// Whether `node`'s agent reported that it runs speed tests.
pub(super) fn supported(conn: &Connection, node: &str) -> Result<bool> {
    Ok(conn.query_row(
        "SELECT EXISTS(SELECT 1 FROM metadata WHERE key=?1)",
        [node_key(node)],
        |r| r.get(0),
    )?)
}

fn node_name(conn: &Connection, node: &str) -> Result<String> {
    Ok(conn
        .query_row("SELECT name FROM nodes WHERE id=?1", [node], |r| r.get(0))
        .optional()?
        .unwrap_or_else(|| node.to_owned()))
}

/// Why `node` cannot take part in a test now: an agent too old or never
/// connected, or a server that is offline.
fn not_ready(
    conn: &Connection,
    telemetry: &crate::telemetry::Telemetry,
    node: &str,
) -> Result<Option<String>> {
    let (name, seen): (String, Option<i64>) = conn.query_row(
        "SELECT name,last_seen_ms FROM nodes WHERE id=?1",
        [node],
        |r| Ok((r.get(0)?, r.get(1)?)),
    )?;
    let (seen, _) = telemetry.current(node, seen, String::new());
    if !supported(conn, node)? {
        return Ok(Some(match seen {
            None => format!(
                "server {name} has not connected to the panel yet; speed tests need its agent to report in first"
            ),
            Some(_) => {
                format!("the agent on server {name} is too old for speed tests; upgrade it first")
            }
        }));
    }
    if seen.is_none_or(|seen| now_ms().saturating_sub(seen) > ONLINE_MS) {
        return Ok(Some(format!("server {name} is offline")));
    }
    Ok(None)
}

/// A server of `nodes` that a running test already uses.
fn busy(conn: &Connection, nodes: &[String]) -> Result<Option<String>> {
    for job in running(conn)? {
        if let Some(node) = nodes.iter().find(|n| job.node_ids.contains(n)) {
            return Ok(Some(format!(
                "server {} is already running a speed test",
                node_name(conn, node)?
            )));
        }
    }
    Ok(None)
}

/// The highest port of `start..=end` outside every range in `used`.
pub(crate) fn pick_port(start: u16, end: u16, used: &[(u16, u16)]) -> Option<u16> {
    (start..=end)
        .rev()
        .find(|port| !used.iter().any(|(a, b)| (*a..=*b).contains(port)))
}

/// Ports on `node` that rules (shared rules' lines included), gateways,
/// reverse tunnels and cross-panel shares hold.
fn used_ports(conn: &Connection, node: &str) -> Result<Vec<(u16, u16)>> {
    let mut used: Vec<(u16, u16)> = reverse_tunnels::current_config(conn, node)?
        .map(|config| {
            config
                .rules
                .iter()
                .flat_map(|rule| {
                    let mut ports = vec![(
                        rule.listen.port(),
                        rule.listen_end_port.unwrap_or(rule.listen.port()),
                    )];
                    if let Some(gateway) = &rule.protocol_gateway {
                        ports.push((gateway.listen.port(), gateway.listen.port()));
                    }
                    ports
                })
                .collect()
        })
        .unwrap_or_default();
    used.extend(reverse_tunnels::reserved_ports(conn, node)?);
    used.extend(federation::reserved_ports(conn, node)?);
    Ok(used)
}

/// The receiving server's forwarding settings, or why there are none.
fn receiving(
    conn: &Connection,
    node: &str,
) -> Result<std::result::Result<ForwardingDefaults, String>> {
    Ok(match reverse_tunnels::forwarding(conn, node)? {
        Some(defaults) => Ok(defaults),
        None => Err(format!(
            "server {} has no forwarding host; set the forwarding address and port range in its settings first",
            node_name(conn, node)?
        )),
    })
}

/// The test port on the receiving server: the one asked for, or the
/// highest free port of its forwarding range.
fn choose_port(
    conn: &Connection,
    node: &str,
    defaults: &ForwardingDefaults,
    wanted: Option<u16>,
) -> Result<u16> {
    let used = used_ports(conn, node)?;
    match wanted {
        Some(port) => {
            if port < 1024 {
                return reject(400, "the test port must be 1024 to 65535");
            }
            if used.iter().any(|(a, b)| (*a..=*b).contains(&port)) {
                return reject(
                    409,
                    format!(
                        "port {port} on server {} is used by a rule, reverse tunnel or share; choose another port",
                        node_name(conn, node)?
                    ),
                );
            }
            Ok(port)
        }
        None => match pick_port(defaults.port_start, defaults.port_end, &used) {
            Some(port) => Ok(port),
            None => reject(
                409,
                format!(
                    "server {} has no free port in its forwarding port range for a speed test",
                    node_name(conn, node)?
                ),
            ),
        },
    }
}

fn host_port(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

fn visible(conn: &Connection, actor: &Actor, id: &str) -> Result<Job> {
    match load(conn, id)? {
        Some(job)
            if actor.role == Role::SystemAdmin
                || (job.kind == Kind::Path && actor.permits_tenant(&job.tenant_id)) =>
        {
            Ok(job)
        }
        _ => reject(404, "speed test not found"),
    }
}

fn view(job: Job, live: &Live) -> JobView {
    let progress = if job.state == JobState::Running && job.step < job.segments.len() {
        let role = match job.mode {
            Mode::Cloudflare => TaskRole::Cloudflare,
            Mode::Server => TaskRole::Dial,
        };
        live.progress
            .get(&task_id(&job.id, job.step, role))
            .map(|report| Progress {
                segment: job.step,
                direction: report.phase,
                elapsed_ms: report.elapsed_ms,
                bytes: report.bytes,
                current_bps: report.current_bps,
            })
    } else {
        None
    };
    let slowest_segment = if job.kind == Kind::Path {
        job.segments
            .iter()
            .enumerate()
            .filter_map(|(index, s)| s.slowest_bps().map(|bps| (bps, index)))
            .min()
            .map(|(_, index)| index)
    } else {
        None
    };
    JobView {
        job,
        progress,
        slowest_segment,
        metered: false,
    }
}

fn steps(job: &Job) -> usize {
    job.segments.len() + usize::from(job.target.is_some())
}
fn step_state(job: &Job, step: usize) -> StepState {
    match job.segments.get(step) {
        Some(segment) => segment.state,
        None => job.target.as_ref().map_or(StepState::Finished, |t| t.state),
    }
}
fn set_step(job: &mut Job, step: usize, state: StepState, error: Option<String>, now: i64) {
    match job.segments.get_mut(step) {
        Some(segment) => {
            segment.state = state;
            if state == StepState::Running {
                segment.started_at_ms = Some(now);
            } else if state.ended() {
                segment.finished_at_ms = Some(now);
            }
            if error.is_some() {
                segment.error = error;
            }
        }
        None => {
            if let Some(target) = &mut job.target {
                target.state = state;
                if error.is_some() {
                    target.error = error;
                }
            }
        }
    }
}
/// The servers of `step`, which its agents must wake for.
fn step_nodes(job: &Job, step: usize) -> Vec<String> {
    match job.segments.get(step) {
        Some(segment) => std::iter::once(segment.from_node_id.clone())
            .chain(segment.to_node_id.clone())
            .collect(),
        None => job.target.iter().map(|t| t.node_id.clone()).collect(),
    }
}
fn step_deadline_ms(job: &Job, step: usize) -> i64 {
    if step < job.segments.len() {
        job.params.hard_limit().as_millis() as i64 + 30_000
    } else {
        PROBE_DEADLINE_MS
    }
}

/// Takes `node`'s report of the job's running step.
fn apply_report(job: &mut Job, node: &str, report: &Report, live: &mut Live, now: i64) -> bool {
    let step = job.step;
    if step >= steps(job) || step_state(job, step) != StepState::Running {
        return false;
    }
    let job_id = job.id.clone();
    let find = |role| {
        let id = task_id(&job_id, step, role);
        report.tasks.iter().find(|t| t.id == id).cloned()
    };
    let mut changed = false;
    if let Some(segment) = job.segments.get(step).cloned() {
        let measuring = match job.mode {
            Mode::Cloudflare => TaskRole::Cloudflare,
            Mode::Server => TaskRole::Dial,
        };
        if segment.to_node_id.as_deref() == Some(node)
            && let Some(task) = find(TaskRole::Listen)
        {
            let target = &mut job.segments[step];
            if task.rejected > target.rejected_connections {
                target.rejected_connections = task.rejected;
                changed = true;
            }
            if task.state == TaskState::Failed {
                let error = format!(
                    "{}: {}",
                    segment.to_name.clone().unwrap_or_default(),
                    task.error.unwrap_or_default()
                );
                set_step(job, step, StepState::Failed, Some(error), now);
                return true;
            }
        }
        if segment.from_node_id == node
            && let Some(task) = find(measuring)
        {
            let id = task.id.clone();
            match task.state {
                TaskState::Running => {
                    live.progress.insert(id, task);
                }
                TaskState::Finished | TaskState::Failed => {
                    live.progress.remove(&id);
                    job.segments[step].results = task.results;
                    let (state, error) = if task.state == TaskState::Finished {
                        (StepState::Finished, None)
                    } else {
                        (
                            StepState::Failed,
                            Some(format!(
                                "{}: {}",
                                segment.from_name,
                                task.error.unwrap_or_default()
                            )),
                        )
                    };
                    set_step(job, step, state, error, now);
                    changed = true;
                }
            }
        }
    } else if let Some(target) = &mut job.target
        && target.node_id == node
        && let Some(task) = find(TaskRole::Connect)
    {
        match task.state {
            TaskState::Running => {}
            TaskState::Finished => {
                target.connect_us = task.connect_us;
                target.state = StepState::Finished;
                changed = true;
            }
            TaskState::Failed => {
                target.error = task.error;
                target.state = StepState::Failed;
                changed = true;
            }
        }
    }
    changed
}

/// Moves a running job past ended or overdue steps, and ends it after the
/// last. Returns whether its agents must be woken.
fn advance(tx: &Transaction<'_>, job: &mut Job, live: &mut Live, now: i64) -> Result<bool> {
    let mut woke = false;
    while job.state == JobState::Running {
        if job.step >= steps(job) {
            let measured = job.segments.iter().any(|s| s.state == StepState::Finished)
                || job
                    .target
                    .as_ref()
                    .is_some_and(|t| t.state == StepState::Finished);
            job.state = if measured {
                JobState::Finished
            } else {
                JobState::Failed
            };
            job.finished_at_ms = Some(now);
            end(tx, job, &job.started_by.clone(), "speed_test.finish")?;
            woke = true;
            break;
        }
        match step_state(job, job.step) {
            StepState::Pending => {
                set_step(job, job.step, StepState::Running, None, now);
                job.step_started_ms = now;
                woke = true;
                break;
            }
            StepState::Running => {
                if now.saturating_sub(job.step_started_ms) <= step_deadline_ms(job, job.step) {
                    break;
                }
                let names: Vec<String> = step_nodes(job, job.step)
                    .iter()
                    .map(|n| node_name(tx, n))
                    .collect::<Result<_>>()?;
                set_step(
                    job,
                    job.step,
                    StepState::Failed,
                    Some(format!(
                        "no result from server {} in time",
                        names.join(" / ")
                    )),
                    now,
                );
            }
            _ => {
                for role in [
                    TaskRole::Dial,
                    TaskRole::Cloudflare,
                    TaskRole::Listen,
                    TaskRole::Connect,
                ] {
                    live.progress.remove(&task_id(&job.id, job.step, role));
                }
                job.step += 1;
                woke = true;
            }
        }
    }
    if woke {
        live.wake.extend(job.node_ids.iter().cloned());
    }
    Ok(woke)
}

/// Ends `job` (already marked): out of the running list, tokens deleted,
/// audited without them, and old results pruned.
fn end(tx: &Transaction<'_>, job: &Job, actor: &str, action: &str) -> Result<()> {
    let ids: Vec<String> = running_ids(tx)?
        .into_iter()
        .filter(|id| id != &job.id)
        .collect();
    set_running(tx, &ids)?;
    tx.execute("DELETE FROM metadata WHERE key=?1", [token_key(&job.id)])?;
    let segments: Vec<serde_json::Value> = job
        .segments
        .iter()
        .map(|s| {
            serde_json::json!({
                "from": s.from_node_id,
                "to": s.to_node_id,
                "state": s.state,
                "average_bps": s.results.iter().map(|r| (r.direction, r.average_bps)).collect::<Vec<_>>(),
            })
        })
        .collect();
    audit(
        tx,
        actor,
        action,
        &job.id,
        &serde_json::json!({"state": job.state, "segments": segments}).to_string(),
    )?;
    save(tx, job)?;
    let mut ended: Vec<Job> = all(tx)?
        .into_iter()
        .filter(|j| j.state != JobState::Running)
        .collect();
    ended.sort_by_key(|j| {
        std::cmp::Reverse((j.finished_at_ms.unwrap_or(j.created_at_ms), j.created_at_ms))
    });
    for old in ended.iter().skip(KEEP) {
        tx.execute(
            "DELETE FROM metadata WHERE key IN (?1,?2)",
            params![key(&old.id), token_key(&old.id)],
        )?;
    }
    Ok(())
}

/// Keeps that `node`'s agent runs speed tests and takes its report of the
/// running tests; moves running jobs on. Returns whether a watch must wake.
pub(super) fn observe(
    tx: &Transaction<'_>,
    live: &Mutex<Live>,
    node: &str,
    report: Option<&Report>,
) -> Result<bool> {
    if report.is_some() && !supported(tx, node)? {
        tx.execute(
            "INSERT INTO metadata(key,value) VALUES(?1,'1')",
            [node_key(node)],
        )?;
    }
    tick(tx, live, Some((node, report)))
}

/// Moves every running job on, with `node`'s report when one came.
fn tick(
    tx: &Transaction<'_>,
    live: &Mutex<Live>,
    report: Option<(&str, Option<&Report>)>,
) -> Result<bool> {
    let ids = running_ids(tx)?;
    if ids.is_empty() {
        return Ok(false);
    }
    let now = now_ms();
    let mut live = live.lock().unwrap();
    let mut woke = false;
    for id in ids {
        let Some(mut job) = load(tx, &id)? else {
            let rest: Vec<String> = running_ids(tx)?.into_iter().filter(|i| i != &id).collect();
            set_running(tx, &rest)?;
            continue;
        };
        let before = job.clone();
        if let Some((node, Some(report))) = report
            && job.node_ids.iter().any(|n| n == node)
        {
            apply_report(&mut job, node, report, &mut live, now);
        }
        woke |= advance(tx, &mut job, &mut live, now)?;
        if job != before && job.state == JobState::Running {
            save(tx, &job)?;
        }
    }
    Ok(woke)
}

/// The tasks `node` runs now; none for an agent that never reported support.
pub(super) fn desired(conn: &Connection, node: &str) -> Result<Vec<Task>> {
    if !supported(conn, node)? {
        return Ok(vec![]);
    }
    let mut tasks = vec![];
    for job in running(conn)? {
        let step = job.step;
        if step >= steps(&job) || step_state(&job, step) != StepState::Running {
            continue;
        }
        let task = |role, listen, address: Option<String>, token: Option<String>| Task {
            id: task_id(&job.id, step, role),
            role,
            params: job.params.clone(),
            listen,
            address,
            token,
        };
        if let Some(segment) = job.segments.get(step) {
            match job.mode {
                Mode::Cloudflare if segment.from_node_id == node => {
                    tasks.push(task(TaskRole::Cloudflare, None, None, None));
                }
                Mode::Cloudflare => {}
                Mode::Server => {
                    let token = tokens(conn, &job.id)?.get(step).cloned();
                    if token.is_none() {
                        continue;
                    }
                    if segment.to_node_id.as_deref() == Some(node) {
                        tasks.push(task(TaskRole::Listen, segment.listen, None, token.clone()));
                    }
                    if segment.from_node_id == node {
                        tasks.push(task(
                            TaskRole::Dial,
                            None,
                            Some(segment.address.clone()),
                            token,
                        ));
                    }
                }
            }
        } else if let Some(target) = &job.target
            && target.node_id == node
        {
            tasks.push(task(
                TaskRole::Connect,
                None,
                Some(target.address.clone()),
                None,
            ));
        }
    }
    tasks.truncate(crate::speed_test::MAX_TASKS);
    Ok(tasks)
}

/// Whether `node`'s watch should answer at once; answers yes once.
pub(super) fn take_wake(live: &Mutex<Live>, node: &str) -> bool {
    live.lock().unwrap().wake.remove(node)
}

/// The preferred target of a rule: the first of the best priority that is
/// not paused (the first of all when every one is).
fn primary(rule: &Rule) -> Option<&Target> {
    let now = now_ms();
    let usable: Vec<&Target> = rule.targets.iter().filter(|t| !t.paused_at(now)).collect();
    let pool = if usable.is_empty() {
        rule.targets.iter().collect()
    } else {
        usable
    };
    let best = pool.iter().map(|t| t.priority).min()?;
    pool.into_iter().find(|t| t.priority == best)
}

/// The servers and rules of a path, from the entry.
type Hops = Vec<(String, Rule)>;

/// Follows a rule's preferred targets through its next hops: the plan,
/// with why the test cannot run now if it cannot, and the hops.
fn plan(
    conn: &Connection,
    telemetry: &crate::telemetry::Telemetry,
    actor: &Actor,
    node: &str,
    rule_id: &str,
) -> Result<(PathPlan, Hops)> {
    require_node(conn, actor, node, false)?;
    let mut configs: HashMap<String, Option<NodeConfig>> = HashMap::new();
    let mut rule_of =
        |conn: &Connection, node: &str, rule: &str| -> Result<Option<(NodeConfig, Rule)>> {
            let config = match configs.get(node) {
                Some(config) => config.clone(),
                None => {
                    let config = reverse_tunnels::current_config(conn, node)?;
                    configs.insert(node.to_owned(), config.clone());
                    config
                }
            };
            Ok(config.and_then(|c| {
                let rule = c.rules.iter().find(|r| r.id == rule)?.clone();
                Some((c, rule))
            }))
        };
    let Some((_, entry)) = rule_of(conn, node, rule_id)? else {
        return reject(404, "rule not found");
    };
    let mut reason = None;
    if entry.id.starts_with(crate::federation::RULE_PREFIX) {
        reason = Some("this rule is shared from another panel (cross-panel sharing); its path cannot be tested here".to_owned());
    } else if entry.reverse_tunnel.is_some() {
        reason = Some("this rule is the public end of a reverse tunnel and reaches its target through the tunnel; test the two servers with a server speed test instead".to_owned());
    } else if entry.protocol_gateway.is_some() || entry.targets.is_empty() {
        reason = Some("this rule is a proxy service or protocol gateway with no fixed target; there is no path to test".to_owned());
    }
    let mut hops: Hops = vec![(node.to_owned(), entry.clone())];
    let mut targets: Vec<Target> = vec![];
    let mut last_target: Option<Target> = None;
    let mut seen = HashSet::from([(node.to_owned(), entry.id.clone())]);
    while reason.is_none() {
        let (current_node, current) = hops.last().unwrap().clone();
        // A proxy service at the last hop: no fixed target to time.
        let Some(target) = primary(&current).cloned() else {
            break;
        };
        let Some(next) = target.via.clone() else {
            last_target = Some(target);
            break;
        };
        if hops.len() > MAX_HOPS || !seen.insert((next.node_id.clone(), next.rule_id.clone())) {
            reason = Some("the path is too long or loops".into());
            break;
        }
        match rule_of(conn, &next.node_id, &next.rule_id)? {
            Some((_, rule)) => {
                require_node(conn, actor, &next.node_id, false)?;
                targets.push(target);
                hops.push((next.node_id.clone(), rule));
            }
            None => {
                reason = Some(format!(
                    "the next hop of rule {} on server {} no longer exists",
                    current.name,
                    node_name(conn, &current_node)?
                ));
                break;
            }
        }
    }
    let mut names = HashMap::new();
    for (node, _) in &hops {
        if !names.contains_key(node) {
            names.insert(node.clone(), node_name(conn, node)?);
        }
    }
    let segments: Vec<PlanSegment> = targets
        .iter()
        .enumerate()
        .map(|(index, target)| PlanSegment {
            from_node_id: hops[index].0.clone(),
            from_name: names[&hops[index].0].clone(),
            to_node_id: hops[index + 1].0.clone(),
            to_name: names[&hops[index + 1].0].clone(),
            rule_id: hops[index].1.id.clone(),
            target_address: target.address.clone(),
        })
        .collect();
    let (last_node, last_rule) = hops.last().unwrap().clone();
    let target = last_target
        .filter(|_| last_rule.protocol.tcp())
        .map(|target| PlanTarget {
            node_id: last_node.clone(),
            node_name: names[&last_node].clone(),
            rule_id: last_rule.id.clone(),
            address: target.address,
        });
    if reason.is_none() && segments.is_empty() && target.is_none() {
        reason = Some("this rule runs on one server and has no TCP target whose connect time could be measured".into());
    }
    let mut limits = vec![];
    for (node, rule) in &hops {
        limits.push(PathLimit {
            kind: LimitKind::Rule,
            node_id: node.clone(),
            node_name: names[node].clone(),
            rule_id: Some(rule.id.clone()),
            rule_name: Some(rule.name.clone()),
            rate_bytes_per_sec: rule.rate_bytes_per_sec,
            rate_limits: rule.rate_limits,
            quota_bytes: rule.quota_bytes,
        });
    }
    let mut listed = HashSet::new();
    for (node, _) in &hops {
        if listed.insert(node.clone())
            && let Some(config) = configs.get(node).cloned().flatten()
        {
            limits.push(PathLimit {
                kind: LimitKind::Server,
                node_id: node.clone(),
                node_name: names[node].clone(),
                rule_id: None,
                rule_name: None,
                rate_bytes_per_sec: config.rate_bytes_per_sec,
                rate_limits: config.rate_limits,
                quota_bytes: None,
            });
        }
    }
    // What would stop it now: the receiving servers' settings and ports,
    // then every server's agent, and tests already running.
    let mut blocked = None;
    if reason.is_none() {
        let mut nodes: Vec<String> = vec![];
        for (node, _) in &hops {
            if !nodes.contains(node) {
                nodes.push(node.clone());
            }
        }
        for node in &nodes {
            if let Some(why) = not_ready(conn, telemetry, node)? {
                blocked = Some(why);
                break;
            }
        }
        for segment in &segments {
            if blocked.is_some() {
                break;
            }
            match receiving(conn, &segment.to_node_id)? {
                Ok(defaults) => {
                    if pick_port(
                        defaults.port_start,
                        defaults.port_end,
                        &used_ports(conn, &segment.to_node_id)?,
                    )
                    .is_none()
                    {
                        blocked = Some(format!(
                            "server {} has no free port in its forwarding port range for a speed test",
                            segment.to_name
                        ));
                    }
                }
                Err(why) => blocked = Some(why),
            }
        }
        if blocked.is_none() {
            blocked = busy(conn, &nodes)?;
        }
    }
    let plan = PathPlan {
        node_id: node.to_owned(),
        rule_id: entry.id.clone(),
        rule_name: entry.name.clone(),
        hops: hops
            .iter()
            .map(|(node, rule)| PlanHop {
                node_id: node.clone(),
                node_name: names[node].clone(),
                rule_id: rule.id.clone(),
                rule_name: rule.name.clone(),
            })
            .collect(),
        segments,
        target,
        limits,
        reason: reason.or(blocked),
        metered: false,
    };
    Ok((plan, hops))
}

fn params_of(
    direction: crate::speed_test::Directions,
    duration_secs: Option<u32>,
    bytes: Option<u64>,
    streams: u8,
) -> Result<Params> {
    let params = Params {
        direction,
        duration_secs,
        bytes,
        streams,
    }
    .normalized();
    params.validate()?;
    Ok(params)
}

fn start_detail(job: &Job) -> String {
    serde_json::json!({
        "kind": job.kind,
        "mode": job.mode,
        "node_ids": job.node_ids,
        "rule": job.rule.as_ref().map(|r| (&r.node_id, &r.rule_id)),
        "port": job.port,
        "direction": job.params.direction,
        "duration_secs": job.params.duration_secs,
        "bytes": job.params.bytes,
        "streams": job.params.streams,
    })
    .to_string()
}

impl Store {
    fn wake_speed_test(&self, job: &Job) {
        self.11
            .lock()
            .unwrap()
            .wake
            .extend(job.node_ids.iter().cloned());
        self.2.config.notify_waiters();
    }

    /// Ends overdue steps before reading, so a test whose agents went
    /// silent does not look busy forever.
    fn tick_speed_tests(&self) -> Result<()> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let woke = tick(&tx, &self.11, None)?;
        tx.commit()?;
        if woke {
            self.2.config.notify_waiters();
        }
        Ok(())
    }

    pub fn speed_tests(&self, actor: &Actor) -> Result<Vec<JobView>> {
        self.tick_speed_tests()?;
        let conn = self.0.lock().unwrap();
        let mut jobs: Vec<Job> = all(&conn)?
            .into_iter()
            .filter(|job| {
                actor.role == Role::SystemAdmin
                    || (job.kind == Kind::Path && actor.permits_tenant(&job.tenant_id))
            })
            .collect();
        jobs.sort_by_key(|j| std::cmp::Reverse((j.state == JobState::Running, j.created_at_ms)));
        let live = self.11.lock().unwrap();
        Ok(jobs.into_iter().map(|job| view(job, &live)).collect())
    }

    pub fn speed_test(&self, actor: &Actor, id: &str) -> Result<JobView> {
        self.tick_speed_tests()?;
        let conn = self.0.lock().unwrap();
        let job = visible(&conn, actor, id)?;
        Ok(view(job, &self.11.lock().unwrap()))
    }

    /// Checks shared by both kinds of test, then stores and starts `job`.
    fn begin_speed_test(
        &self,
        tx: crate::journal::LoggedTransaction<'_>,
        actor: &Actor,
        mut job: Job,
        tokens: Vec<String>,
    ) -> Result<JobView> {
        if let Some(why) = busy(&tx, &job.node_ids)? {
            return reject(409, why);
        }
        for node in &job.node_ids {
            if let Some(why) = not_ready(&tx, &self.4, node)? {
                return reject(409, why);
            }
        }
        let now = now_ms();
        if actor.role != Role::SystemAdmin
            && let Some(last) = all(&tx)?
                .iter()
                .filter(|j| j.started_by == actor.id)
                .map(|j| j.created_at_ms)
                .max()
            && now.saturating_sub(last) < COOLDOWN_MS
        {
            let wait = (COOLDOWN_MS - now.saturating_sub(last) + 999) / 1000;
            return reject(
                429,
                format!("wait {wait} s before starting another speed test"),
            );
        }
        job.created_at_ms = now;
        job.step_started_ms = now;
        set_step(&mut job, 0, StepState::Running, None, now);
        save(&tx, &job)?;
        if !tokens.is_empty() {
            set(&tx, &token_key(&job.id), &serde_json::to_string(&tokens)?)?;
        }
        let mut ids = running_ids(&tx)?;
        ids.push(job.id.clone());
        set_running(&tx, &ids)?;
        audit(
            &tx,
            &actor.id,
            "speed_test.start",
            &job.id,
            &start_detail(&job),
        )?;
        tx.commit()?;
        self.wake_speed_test(&job);
        Ok(view(job, &self.11.lock().unwrap()))
    }

    /// A server ↔ Cloudflare or server ↔ server test; system administrators.
    pub fn start_speed_test(&self, actor: &Actor, input: ServerTestInput) -> Result<JobView> {
        if actor.role != Role::SystemAdmin {
            return reject(403, "server speed tests need system administrator access");
        }
        let params = params_of(
            input.direction,
            input.duration_secs,
            input.bytes,
            input.streams,
        )?;
        self.tick_speed_tests()?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let tenant = require_node(&tx, actor, &input.node_id, true)?;
        let from_name = node_name(&tx, &input.node_id)?;
        let id = Uuid::new_v4().to_string();
        let mut tokens = vec![];
        let segment = match input.mode {
            Mode::Cloudflare => {
                if input.peer_node_id.is_some() || input.port.is_some() {
                    return reject(400, "a Cloudflare test has no second server or port");
                }
                Segment {
                    from_node_id: input.node_id.clone(),
                    from_name,
                    to_node_id: None,
                    to_name: None,
                    rule_id: None,
                    listen: None,
                    address: "speed.cloudflare.com".into(),
                    state: StepState::Pending,
                    results: vec![],
                    rejected_connections: 0,
                    error: None,
                    started_at_ms: None,
                    finished_at_ms: None,
                }
            }
            Mode::Server => {
                let Some(peer) = input.peer_node_id.clone() else {
                    return reject(400, "a server-to-server test needs a second server");
                };
                if peer == input.node_id {
                    return reject(400, "choose two different servers");
                }
                require_node(&tx, actor, &peer, true)?;
                for node in [&input.node_id, &peer] {
                    if let Some(why) = not_ready(&tx, &self.4, node)? {
                        return reject(409, why);
                    }
                }
                for node in [&input.node_id, &peer] {
                    if let Err(why) = receiving(&tx, node)? {
                        return reject(409, why);
                    }
                }
                let defaults = receiving(&tx, &peer)?.unwrap();
                let port = choose_port(&tx, &peer, &defaults, input.port)?;
                tokens.push(secret());
                Segment {
                    from_node_id: input.node_id.clone(),
                    from_name,
                    to_node_id: Some(peer.clone()),
                    to_name: Some(node_name(&tx, &peer)?),
                    rule_id: None,
                    listen: Some(SocketAddr::new(defaults.bind_ip(), port)),
                    address: reverse_tunnels::reachable(Some(&defaults), None, port)
                        .context("the receiving server has no forwarding host")?,
                    state: StepState::Pending,
                    results: vec![],
                    rejected_connections: 0,
                    error: None,
                    started_at_ms: None,
                    finished_at_ms: None,
                }
            }
        };
        let port = segment.listen.map(|l| l.port());
        let node_ids: Vec<String> = std::iter::once(segment.from_node_id.clone())
            .chain(segment.to_node_id.clone())
            .collect();
        let job = Job {
            id,
            kind: Kind::Server,
            mode: input.mode,
            tenant_id: tenant,
            started_by: actor.id.clone(),
            started_by_name: actor.username.clone(),
            params,
            port,
            rule: None,
            node_ids,
            segments: vec![segment],
            target: None,
            limits: vec![],
            state: JobState::Running,
            step: 0,
            step_started_ms: 0,
            created_at_ms: 0,
            finished_at_ms: None,
            error: None,
        };
        self.begin_speed_test(tx, actor, job, tokens)
    }

    /// What a path test of the rule would measure, the limits along it,
    /// and why it cannot start now if it cannot.
    pub fn speed_test_path(&self, actor: &Actor, node: &str, rule: &str) -> Result<PathPlan> {
        self.tick_speed_tests()?;
        let conn = self.0.lock().unwrap();
        Ok(plan(&conn, &self.4, actor, node, rule)?.0)
    }

    /// Every segment of a rule's path; system administrators and users who
    /// may write every server of the path.
    pub fn start_path_speed_test(&self, actor: &Actor, input: PathTestInput) -> Result<JobView> {
        let params = params_of(
            input.direction,
            input.duration_secs,
            input.bytes,
            input.streams,
        )?;
        self.tick_speed_tests()?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let (plan, hops) = plan(&tx, &self.4, actor, &input.node_id, &input.rule_id)?;
        let nodes: Vec<String> = {
            let mut nodes = vec![];
            for (node, _) in &hops {
                if !nodes.contains(node) {
                    nodes.push(node.clone());
                }
            }
            nodes
        };
        for node in &nodes {
            match require_node(&tx, actor, node, true) {
                Err(error)
                    if error
                        .downcast_ref::<Rejection>()
                        .is_some_and(|r| r.status == 403) =>
                {
                    return reject(403, "read-only role cannot run speed tests");
                }
                result => {
                    result?;
                }
            }
        }
        if let Some(reason) = &plan.reason {
            return reject(409, reason.clone());
        }
        let mut tokens = vec![];
        let mut segments = vec![];
        for planned in &plan.segments {
            let defaults = match receiving(&tx, &planned.to_node_id)? {
                Ok(defaults) => defaults,
                Err(why) => return reject(409, why),
            };
            let port = choose_port(&tx, &planned.to_node_id, &defaults, None)?;
            // The real route: the host this hop's target dials, on the test
            // port as the receiving server's NAT maps it.
            let (host, _) = crate::topology::endpoint(&planned.target_address)?;
            let public = if (defaults.port_start..=defaults.port_end).contains(&port) {
                defaults.public_port(port)
            } else {
                port
            };
            tokens.push(secret());
            segments.push(Segment {
                from_node_id: planned.from_node_id.clone(),
                from_name: planned.from_name.clone(),
                to_node_id: Some(planned.to_node_id.clone()),
                to_name: Some(planned.to_name.clone()),
                rule_id: Some(planned.rule_id.clone()),
                listen: Some(SocketAddr::new(defaults.bind_ip(), port)),
                address: host_port(&host, public),
                state: StepState::Pending,
                results: vec![],
                rejected_connections: 0,
                error: None,
                started_at_ms: None,
                finished_at_ms: None,
            });
        }
        let tenant = hops[0].1.tenant_id.clone();
        let job = Job {
            id: Uuid::new_v4().to_string(),
            kind: Kind::Path,
            mode: Mode::Server,
            tenant_id: tenant,
            started_by: actor.id.clone(),
            started_by_name: actor.username.clone(),
            params,
            port: None,
            rule: Some(PathRule {
                node_id: plan.node_id.clone(),
                rule_id: plan.rule_id.clone(),
                name: plan.rule_name.clone(),
            }),
            node_ids: nodes,
            segments,
            target: plan.target.as_ref().map(|t| TargetProbe {
                node_id: t.node_id.clone(),
                node_name: t.node_name.clone(),
                rule_id: t.rule_id.clone(),
                address: t.address.clone(),
                state: StepState::Pending,
                connect_us: None,
                error: None,
            }),
            limits: plan.limits.clone(),
            state: JobState::Running,
            step: 0,
            step_started_ms: 0,
            created_at_ms: 0,
            finished_at_ms: None,
            error: None,
        };
        self.begin_speed_test(tx, actor, job, tokens)
    }

    /// Stops a running test on every agent; the history keeps it.
    pub fn cancel_speed_test(&self, actor: &Actor, id: &str) -> Result<JobView> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut job = visible(&tx, actor, id)?;
        if actor.role != Role::SystemAdmin {
            if job.kind != Kind::Path {
                return reject(404, "speed test not found");
            }
            for node in &job.node_ids {
                match require_node(&tx, actor, node, true) {
                    Err(error)
                        if error
                            .downcast_ref::<Rejection>()
                            .is_some_and(|r| r.status == 403) =>
                    {
                        return reject(403, "read-only role cannot stop speed tests");
                    }
                    result => {
                        result?;
                    }
                }
            }
        }
        if job.state != JobState::Running {
            return reject(409, "this speed test has already ended");
        }
        let now = now_ms();
        for step in job.step..steps(&job) {
            set_step(&mut job, step, StepState::Cancelled, None, now);
        }
        job.state = JobState::Cancelled;
        job.finished_at_ms = Some(now);
        {
            let mut live = self.11.lock().unwrap();
            live.progress.retain(|task, _| !task.starts_with(&job.id));
        }
        end(&tx, &job, &actor.id, "speed_test.cancel")?;
        tx.commit()?;
        self.wake_speed_test(&job);
        Ok(view(job, &self.11.lock().unwrap()))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn the_test_port_avoids_every_used_port() {
        assert_eq!(pick_port(20000, 29999, &[]), Some(29999));
        assert_eq!(
            pick_port(20000, 29999, &[(29999, 29999), (29990, 29998)]),
            Some(29989)
        );
        // Ranges of rules and shares, and single ports of gateways.
        assert_eq!(
            pick_port(
                20000,
                20010,
                &[(20005, 20010), (20004, 20004), (20000, 20002)]
            ),
            Some(20003)
        );
        assert_eq!(pick_port(20000, 20002, &[(19000, 21000)]), None);
        assert_eq!(pick_port(30000, 30000, &[(29999, 29999)]), Some(30000));
    }

    #[test]
    fn task_ids_keep_a_servers_two_roles_apart() {
        assert_eq!(task_id("job", 2, TaskRole::Listen), "job-2-l");
        assert_ne!(
            task_id("job", 0, TaskRole::Listen),
            task_id("job", 0, TaskRole::Dial)
        );
        assert!(crate::model::identifier(&task_id(
            &Uuid::new_v4().to_string(),
            15,
            TaskRole::Connect
        )));
    }

    #[test]
    fn the_preferred_target_is_the_first_usable_one_of_the_best_priority() {
        let target = |address: &str, priority: u16, paused: bool| Target {
            address: address.into(),
            via: None,
            weight: 1,
            priority,
            max_sessions: None,
            tls: None,
            proxy_protocol: None,
            websocket: None,
            prewarm: None,
            draining: false,
            paused,
            paused_until_ms: None,
        };
        let mut rule: Rule = serde_json::from_value(serde_json::json!({
            "id": "r", "tenant_id": "t", "owner_id": "o", "name": "n",
            "listen": "0.0.0.0:20000", "protocol": "tcp", "targets": [{"address": "192.0.2.1:1"}],
            "enabled": true, "meter_epoch": "e", "quota_bytes": null, "expires_at_ms": null,
            "rate_bytes_per_sec": null
        }))
        .unwrap();
        rule.targets = vec![
            target("192.0.2.1:1", 1, false),
            target("192.0.2.2:1", 0, true),
            target("192.0.2.3:1", 0, false),
            target("192.0.2.4:1", 0, false),
        ];
        assert_eq!(primary(&rule).unwrap().address, "192.0.2.3:1");
        for t in &mut rule.targets {
            t.paused = true;
        }
        assert_eq!(primary(&rule).unwrap().address, "192.0.2.2:1");
        rule.targets.clear();
        assert!(primary(&rule).is_none());
    }
}
