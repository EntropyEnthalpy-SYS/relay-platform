//! Endpoint groups and saved forwarding chains. A group is one layer of
//! alternative servers; a chain is an ordered list of groups. Building a
//! forwarding from a chain creates ordinary rules, one per server, so agents
//! and the rule format are unchanged: every server of a layer targets every
//! server of the next layer through `via`, chosen by that layer's balance.
use crate::model::{Balance, Protocol, Rule, RuleRef, Target};
use crate::store::Store;
use crate::topology::{BatchResult, ConfigBatch, RuleChange};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::net::SocketAddr;
use std::time::Duration;

/// Most servers in one endpoint group.
pub const MAX_MEMBERS: usize = 32;
/// Most layers in one chain.
pub const MAX_LAYERS: usize = 6;
/// How long a refresh may take from its confirmation until its new routes
/// are published, by default and at least and at most. Past it the
/// forwarding is put back as it was.
pub const REFRESH_TIMEOUT_SECS: u64 = 600;
pub const MIN_REFRESH_TIMEOUT_SECS: u64 = 60;
pub const MAX_REFRESH_TIMEOUT_SECS: u64 = 86_400;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EndpointGroup {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub description: String,
    /// Node ids in the order the operator chose.
    pub members: Vec<String>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GroupInput {
    pub name: String,
    #[serde(default)]
    pub description: String,
    pub members: Vec<String>,
}
/// One layer: its servers are the candidates the previous hop chooses from
/// with `balance`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Layer {
    pub group_id: String,
    #[serde(default)]
    pub balance: Balance,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Chain {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub enabled: bool,
    pub layers: Vec<Layer>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}
fn enabled() -> bool {
    true
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ChainInput {
    pub name: String,
    #[serde(default = "enabled")]
    pub enabled: bool,
    pub layers: Vec<Layer>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Hop {
    pub node_id: String,
    pub rule_id: String,
}
/// What a forwarding built from a chain created, stored under
/// `chain_use:<entry rule id>`: the rules of each layer, in group order.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ChainUse {
    pub chain_id: String,
    pub entry_node_id: String,
    pub layers: Vec<Vec<Hop>>,
    /// Refresh the forwarding when its groups change; off unless an
    /// operator turned it on.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_sync: Option<AutoSync>,
    /// Why the controller turned automatic refresh off.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub auto_sync_stopped: Option<String>,
}
/// Automatic refresh of one forwarding. Each run interrupts it like a
/// confirmed refresh, and runs as the user who turned it on.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct AutoSync {
    pub enabled_by: String,
    pub enabled_at_ms: i64,
    pub timeout_secs: u64,
    /// Automatic refreshes in a row that failed or could not start.
    #[serde(default)]
    pub failures: u32,
    /// No automatic refresh starts before this time.
    #[serde(default)]
    pub next_attempt_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_result: Option<String>,
}
/// Plan and apply input. `owner_id` defaults to the caller. Apply refuses
/// with 409 when `expected_revisions` (from a plan) no longer matches a
/// server, so what is published is what was planned.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BuildInput {
    pub entry_node_id: String,
    pub name: String,
    pub protocol: Protocol,
    pub target: String,
    #[serde(default)]
    pub entry_port: Option<u16>,
    #[serde(default)]
    pub owner_id: Option<String>,
    #[serde(default)]
    pub expected_revisions: Option<BTreeMap<String, u64>>,
}

#[derive(Clone, Debug, Serialize)]
pub struct MemberView {
    pub node_id: String,
    pub node_name: Option<String>,
    /// The node no longer exists.
    pub missing: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct ChainRef {
    pub id: String,
    pub name: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct GroupView {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub description: String,
    pub members: Vec<MemberView>,
    /// Chains with a layer on this group; it cannot be deleted while any is.
    pub used_by: Vec<ChainRef>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}
#[derive(Clone, Debug, Serialize)]
pub struct LayerView {
    pub group_id: String,
    pub group_name: Option<String>,
    pub balance: Balance,
    pub members: Vec<MemberView>,
}
#[derive(Clone, Debug, Serialize)]
pub struct HopView {
    pub node_id: String,
    pub rule_id: String,
    pub node_name: Option<String>,
    /// The node or its rule no longer exists.
    pub missing: bool,
}
/// Members of a layer's group now compared with when the forwarding was
/// built; `layer` counts from 1.
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct LayerChange {
    pub layer: usize,
    pub added: Vec<String>,
    pub removed: Vec<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct UseView {
    pub entry_rule_id: String,
    pub entry_node_id: String,
    pub entry_node_name: Option<String>,
    /// The entry rule's name, while it exists.
    pub name: Option<String>,
    /// The entry rule or its node no longer exists.
    pub missing: bool,
    pub layers: Vec<Vec<HopView>>,
    /// Some layer's group gained or lost members since the forwarding was
    /// built or last refreshed. It changes only by a confirmed refresh, or
    /// an automatic one when `auto_sync` is on.
    pub out_of_date: bool,
    pub changes: Vec<LayerChange>,
    pub auto_sync: Option<AutoSync>,
    pub auto_sync_stopped: Option<String>,
    /// The current or last refresh.
    pub refresh: Option<RefreshView>,
}
#[derive(Clone, Debug, Serialize)]
pub struct ChainView {
    pub id: String,
    pub tenant_id: String,
    pub name: String,
    pub enabled: bool,
    pub layers: Vec<LayerView>,
    pub uses: Vec<UseView>,
    pub created_at_ms: i64,
    pub updated_at_ms: i64,
}
/// One planned rule: `layer` 0 is the entry, then the chain's layers from 1.
#[derive(Clone, Debug, Serialize)]
pub struct PlannedHop {
    pub layer: usize,
    pub node_id: String,
    pub node_name: String,
    pub rule_id: String,
    pub listen: SocketAddr,
    pub advertise: String,
}
#[derive(Clone, Debug, Serialize)]
pub struct ChainPlan {
    pub entry_rule_id: String,
    pub hops: Vec<PlannedHop>,
    /// The batch apply would publish; rule ids are generated again by apply.
    pub batch: ConfigBatch,
    pub preview: BatchResult,
}
#[derive(Clone, Debug, Serialize)]
pub struct ChainApplied {
    pub entry_rule_id: String,
    pub hops: Vec<PlannedHop>,
    pub published: BatchResult,
}

/// What a refresh of one forwarding does, from the preview to the last
/// cleanup. A refresh brings a forwarding built from a chain up to its
/// groups' current members without rebuilding it: rules of servers that
/// stay keep their identity, meter, limits and every manual edit, new
/// servers get rules copied from a server of their layer, and only the
/// next hops that change are rewired. Three sets of rules matter:
///
/// - `stopped` (P): the entry and every kept rule above the deepest changed
///   layer. An enabled rule may not route to a disabled one, so they are
///   paused, then stopped together, and the rewire enables them again; the
///   topology stop barrier applies unchanged: their servers (`quiet`) must
///   have no session of any rule. Rules of removed servers that route into
///   P stop with it and are not enabled again.
/// - `rewired` (R): the rules of P whose next hops change; only they get
///   new routes.
/// - rules added on new servers are enabled from the start with their final
///   routes, and nothing routes to them until the rewire.
///
/// 1. `preparing`: rules on new servers are added and confirmed; the
///    servers of P must be connected and in sync.
/// 2. `draining`: the targets of P are paused until the deadline, so the
///    entry refuses new connections; open sessions go on. A pause can end
///    before a long refresh does: new connections then fail on the stopped
///    rules instead.
/// 3. `stopping`: once every server of P is idle, P is disabled with its
///    routes unchanged, and its agents must confirm it while still idle.
/// 4. The rewire publishes the new routes of R, enables and resumes P and
///    disables the rules of removed servers. From here a refresh only goes
///    forward. `confirming`: every agent must apply it; `blocked`: one
///    rejected it or did not confirm it in time.
/// 5. `cleanup`: rules of removed servers are deleted once their server is
///    idle.
///
/// Before the rewire, cancellation, the deadline (checked on every step), a
/// refused step, an agent that cannot apply a step, a lost permission or a
/// change to one of these rules by anyone else all go to `restoring`: rules
/// the stop disabled are enabled again with the route they had before,
/// without waiting for idle servers; paused targets resume and added rules
/// are disabled, then deleted in `cleanup`. Only fields the refresh still
/// owns change, so edits by others are kept; when someone else rerouted,
/// re-listened or deleted a rule on the path, stopped rules stay stopped
/// for an operator (`unresolved`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshPhase {
    Preparing,
    Draining,
    Stopping,
    Confirming,
    Blocked,
    Restoring,
    Cleanup,
    Finished,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshOutcome {
    Succeeded,
    Failed,
    Cancelled,
}
/// One publish of a refresh, with the revision it gave each server.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RefreshStep {
    Add,
    Pause,
    Stop,
    Rewire,
    Restore,
    Cleanup,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct RefreshCommit {
    pub step: RefreshStep,
    pub at_ms: i64,
    pub revisions: BTreeMap<String, u64>,
}
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct NodeProblem {
    pub node_id: String,
    pub error: String,
}
/// An existing rule whose next hops change: its targets once refreshed.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Rewire {
    pub node_id: String,
    pub rule_id: String,
    pub targets: Vec<Target>,
}
/// A target this refresh paused, found again by its address and next hop.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct PausedTarget {
    pub node_id: String,
    pub rule_id: String,
    pub address: String,
    pub via: Option<RuleRef>,
}
/// A refresh, stored under `chain_refresh:<entry rule id>`: the current or
/// last one of that forwarding. Everything it does is planned when it is
/// confirmed; each step is one transaction that publishes and records it,
/// so a restarted controller continues from the step it stored.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Refresh {
    pub id: String,
    pub chain_id: String,
    pub tenant_id: String,
    pub entry_rule_id: String,
    pub entry_node_id: String,
    /// Steps that change the forwarding run as this user, checked again
    /// before each one.
    pub actor_id: String,
    pub automatic: bool,
    pub token: String,
    pub started_at_ms: i64,
    /// Past this the refresh gives up and restores the forwarding; it is
    /// counted from the confirmation, also across controller restarts.
    pub deadline_ms: i64,
    pub updated_at_ms: i64,
    pub phase: RefreshPhase,
    #[serde(default)]
    pub outcome: Option<RefreshOutcome>,
    #[serde(default)]
    pub cancel_requested: bool,
    /// Where it failed and why.
    #[serde(default)]
    pub failed_in: Option<RefreshPhase>,
    #[serde(default)]
    pub error: Option<String>,
    /// What keeps the cleanup from deleting a rule, while it waits.
    #[serde(default)]
    pub retry_error: Option<String>,
    #[serde(default)]
    pub problems: Vec<NodeProblem>,
    /// Rules left alone because someone else changed them, and similar.
    #[serde(default)]
    pub notes: Vec<String>,
    pub changes: Vec<LayerChange>,
    /// The forwarding's servers and rules once refreshed.
    pub layers: Vec<Vec<Hop>>,
    pub added: Vec<RuleRef>,
    pub rewired: Vec<Rewire>,
    /// The entry and the kept rules above the deepest changed layer (P),
    /// paused, disabled and enabled again together, and rules of removed
    /// servers that route into them.
    pub stopped: Vec<RuleRef>,
    /// The servers of the kept rules of `stopped`: each must report no
    /// sessions at all before they stop and before the rewire.
    pub quiet: Vec<String>,
    pub paused: Vec<PausedTarget>,
    /// Rules of servers that leave the forwarding.
    pub removed: Vec<RuleRef>,
    /// Rules still to disable and delete: those of removed servers once the
    /// refresh succeeded, or those it added once it failed.
    pub retire: Vec<RuleRef>,
    /// Every rule of the forwarding when the refresh was confirmed, by
    /// `<node id>/<rule id>`: what a restore puts back and the routes it
    /// checks the path against.
    #[serde(default)]
    pub before: BTreeMap<String, Rule>,
    /// Each rule this refresh touches as it last left it, by
    /// `<node id>/<rule id>`, to notice and keep changes made by anyone else.
    #[serde(default)]
    pub last_rules: BTreeMap<String, Rule>,
    /// Rules the refresh could not put back or finish by itself.
    #[serde(default)]
    pub unresolved: Vec<Unresolved>,
    /// When a restore had nothing left to publish; then its agents confirm.
    #[serde(default)]
    pub restored_at_ms: Option<i64>,
    /// The operator cancelled asking to keep the rules the stop disabled
    /// stopped.
    #[serde(default)]
    pub keep_stopped: bool,
    /// The configuration revision of each server of its rules as it last
    /// saw it: a pass reads configurations only when one moved.
    #[serde(default)]
    pub known: BTreeMap<String, u64>,
    /// Why each server's part of the restore is refused, while it retries.
    #[serde(default)]
    pub refused: Vec<NodeProblem>,
    /// What a refused restore's checks depend on when it was last tried,
    /// and when it is tried again anyway: it retries as soon as that
    /// changed, otherwise not before this time.
    #[serde(default)]
    pub retry_key: Option<String>,
    #[serde(default)]
    pub retry_at_ms: Option<i64>,
    /// The committed restore was rejected by an agent or not confirmed in
    /// time: shown as `restore_failed` or `restore_overdue` until confirmed.
    #[serde(default)]
    pub restore_late: bool,
    /// An operator ended the restore: it stops retrying and leaves what it
    /// did not put back to them.
    #[serde(default)]
    pub end_requested: bool,
    /// Removed servers seen to have applied its pause or stop: they carry
    /// the forwarding again once restored, even after their agent restarts
    /// under a new lease, which resets what it applied to 0.
    #[serde(default)]
    pub carried: Vec<String>,
    pub commits: Vec<RefreshCommit>,
}
/// A rule a refresh could not put back or finish by itself: why, and what an
/// operator should do with it.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct Unresolved {
    pub node_id: String,
    pub rule_id: String,
    pub error: String,
}
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshPlanInput {
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}
/// Confirms a preview: `token` and `expected_revisions` come from it, and a
/// refresh starts only while nothing they cover has changed.
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RefreshInput {
    pub token: String,
    pub expected_revisions: BTreeMap<String, u64>,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}
/// Cancels a refresh before its rewire; `keep_stopped` keeps the rules its
/// stop disabled stopped instead of enabling them again.
#[derive(Clone, Debug, Default, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct CancelInput {
    #[serde(default)]
    pub keep_stopped: bool,
}
#[derive(Clone, Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct AutoSyncInput {
    pub auto_sync: bool,
    #[serde(default)]
    pub timeout_secs: Option<u64>,
}
#[derive(Clone, Debug, Serialize)]
pub struct RefreshProblem {
    pub node_id: Option<String>,
    pub rule_id: Option<String>,
    pub message: String,
}
/// A server as a refresh sees it now. `idle` is the stop barrier's test:
/// connected, in sync, and no session or probe on any of its rules.
#[derive(Clone, Debug, Serialize)]
pub struct ServerState {
    pub node_id: String,
    pub node_name: Option<String>,
    pub enrolled: bool,
    pub online: bool,
    pub last_seen_ms: Option<i64>,
    pub desired_revision: u64,
    pub applied_revision: u64,
    pub apply_error: Option<String>,
    pub active_tcp: u64,
    pub active_udp: u64,
    pub active_probes: u64,
    pub idle: bool,
}
#[derive(Clone, Debug, Serialize)]
pub struct RefreshPlan {
    pub entry_rule_id: String,
    pub token: String,
    pub up_to_date: bool,
    pub changes: Vec<LayerChange>,
    /// Each blocks the refresh until it is resolved.
    pub conflicts: Vec<RefreshProblem>,
    pub warnings: Vec<RefreshProblem>,
    pub notes: Vec<String>,
    /// The refresh stops new connections on the whole forwarding from the
    /// pause until the rewire, at most `timeout_secs`.
    pub interrupts: bool,
    pub timeout_secs: u64,
    /// The servers that must be idle as a whole, every rule counted.
    pub idle_servers: Vec<ServerState>,
    /// New rules on new servers, with their endpoints.
    pub hops: Vec<PlannedHop>,
    pub expected_revisions: BTreeMap<String, u64>,
    /// Each server once refreshed and cleaned up, against now.
    pub result: Vec<ServerChange>,
    /// The checked first publish: rules on new servers, or else the pause.
    pub preview: Option<BatchResult>,
}
/// A server's rules once a refresh is done, against its `revision` now;
/// the refresh reaches them in several revisions.
#[derive(Clone, Debug, Serialize)]
pub struct ServerChange {
    pub node_id: String,
    pub node_name: Option<String>,
    pub revision: u64,
    pub added: Vec<String>,
    pub removed: Vec<String>,
    pub modified: Vec<String>,
    pub rule_changes: Vec<RuleChange>,
}
/// How far an agent is with the last step that changed its server.
#[derive(Clone, Debug, Serialize)]
pub struct AgentState {
    pub node_id: String,
    pub node_name: Option<String>,
    pub step: RefreshStep,
    pub revision: u64,
    /// `applied`, `pending`, `failed` or `not_enrolled`.
    pub state: &'static str,
    pub online: bool,
    pub error: Option<String>,
}
#[derive(Clone, Debug, Serialize)]
pub struct RefreshView {
    pub id: String,
    pub automatic: bool,
    pub actor_id: String,
    pub started_at_ms: i64,
    pub deadline_ms: i64,
    pub updated_at_ms: i64,
    pub phase: RefreshPhase,
    pub outcome: Option<RefreshOutcome>,
    pub cancel_requested: bool,
    pub failed_in: Option<RefreshPhase>,
    pub error: Option<String>,
    pub retry_error: Option<String>,
    pub problems: Vec<NodeProblem>,
    pub notes: Vec<String>,
    pub changes: Vec<LayerChange>,
    /// Where it is, for people: `updating` (preparing, draining, stopping),
    /// `confirming` (rewire committed, agents confirming), `blocked`,
    /// `restoring` (putting the forwarding back), `restore_blocked` (the
    /// controller refuses part of the restore; it retries),
    /// `restore_confirming` (restore committed, agents confirming),
    /// `restore_failed` (committed, an agent of the path rejected it),
    /// `restore_overdue` (committed, not confirmed in time), `cleanup` or
    /// `finished`. Until the restore is confirmed the forwarding is not back.
    pub stage: &'static str,
    /// The forwarding is not fully carrying traffic because of this refresh:
    /// a rule it stopped is still disabled, a target it paused still paused,
    /// or a rewire or restore is not confirmed by every agent yet.
    pub interrupted: bool,
    /// What the refresh waits for, while it waits.
    pub waiting: Vec<NodeProblem>,
    pub servers: Vec<ServerState>,
    pub agents: Vec<AgentState>,
    pub retire_pending: Vec<RuleRef>,
    /// Rules left to an operator, each with why and what to do.
    pub unresolved: Vec<Unresolved>,
    pub commits: Vec<RefreshCommit>,
}

/// Moves refreshes on and starts automatic ones, every `tick`, until
/// `stop`. A pass that fails or panics is logged and retried: after `n`
/// failed passes in a row it waits `n` more ticks, at most 30, so a stopped
/// forwarding is never left without anyone to move it on.
pub async fn run(store: Store, tick: Duration, stop: tokio_util::sync::CancellationToken) {
    drive(
        move || tokio::time::sleep(tick),
        stop,
        move || {
            let db = store.clone();
            tokio::task::spawn_blocking(move || db.advance_chain_refreshes())
        },
    )
    .await
}
/// The loop of [`run`], with its wait for a tick and its pass given.
async fn drive<W, P>(
    mut tick: impl FnMut() -> W,
    stop: tokio_util::sync::CancellationToken,
    mut pass: impl FnMut() -> P,
) where
    W: std::future::Future<Output = ()>,
    P: std::future::Future<Output = Result<anyhow::Result<()>, tokio::task::JoinError>>,
{
    let mut failures: u32 = 0;
    loop {
        for _ in 0..=failures.min(30) {
            tokio::select! {
                biased;
                _ = stop.cancelled() => return,
                _ = tick() => {}
            }
        }
        match pass().await {
            Ok(Ok(())) => failures = 0,
            Ok(Err(error)) => {
                failures += 1;
                tracing::error!(%error, failures, "saved chain refreshes could not advance; retrying");
            }
            Err(error) => {
                failures += 1;
                tracing::error!(%error, failures, "saved chain refresh pass panicked; retrying");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::{Arc, Mutex};

    /// Passes that fail, panic and succeed: the loop goes on after each,
    /// waits one more tick per failed pass in a row (at most 31 ticks), and
    /// one tick again after a pass succeeds.
    #[tokio::test]
    async fn the_refresh_loop_survives_failures_and_panics_and_backs_off() {
        enum Pass {
            Fail,
            Panic,
            Succeed,
        }
        let mut script: Vec<Pass> = vec![Pass::Fail, Pass::Panic, Pass::Fail, Pass::Succeed];
        script.extend((0..33).map(|_| Pass::Fail));
        script.push(Pass::Succeed);
        script.push(Pass::Succeed);
        let total = script.len();
        let script = Arc::new(Mutex::new(script.into_iter()));
        let ticks = Arc::new(Mutex::new(0u32));
        // The ticks each pass waited for.
        let waited = Arc::new(Mutex::new(vec![]));
        let stop = tokio_util::sync::CancellationToken::new();
        let counter = ticks.clone();
        let tick = move || {
            *counter.lock().unwrap() += 1;
            std::future::ready(())
        };
        let (log, end) = (waited.clone(), stop.clone());
        let pass = move || {
            log.lock()
                .unwrap()
                .push(std::mem::take(&mut *ticks.lock().unwrap()));
            let next = script.lock().unwrap().next();
            if next.is_none() {
                end.cancel();
            }
            tokio::task::spawn_blocking(move || match next {
                Some(Pass::Fail) => Err(anyhow::anyhow!("a broken record")),
                Some(Pass::Panic) => panic!("a pass panicked"),
                _ => Ok(()),
            })
        };
        tokio::time::timeout(Duration::from_secs(10), drive(tick, stop, pass))
            .await
            .expect("the loop ends only when stopped");
        let waited = waited.lock().unwrap().clone();
        assert_eq!(waited.len(), total + 1);
        // Fail, panic, fail and a success, which waited 4 ticks.
        assert_eq!(waited[..4], [1, 2, 3, 4]);
        // The success reset the count; 33 failures in a row: the wait grows
        // to 31 ticks and stays there.
        let growing: Vec<u32> = (1..=33).map(|n: u32| n.min(31)).collect();
        assert_eq!(waited[4..37], growing[..]);
        // The success after them, and the passes after that.
        assert_eq!(waited[37..], [31, 1, 1]);
    }
}
