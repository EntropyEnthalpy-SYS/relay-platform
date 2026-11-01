use serde::{Deserialize, Serialize};

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum BudgetScope {
    User,
    Tenant,
    Node,
}
impl BudgetScope {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::User => "user",
            Self::Tenant => "tenant",
            Self::Node => "node",
        }
    }
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct NewBudget {
    pub scope: BudgetScope,
    pub scope_id: String,
    pub name: String,
    pub limit_bytes: u64,
    pub quantum_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetUpdate {
    pub expected_revision: u64,
    pub limit_bytes: u64,
    pub quantum_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Budget {
    pub id: String,
    pub tenant_id: String,
    pub scope: BudgetScope,
    pub scope_id: String,
    pub name: String,
    pub limit_bytes: u64,
    pub quantum_bytes: u64,
    pub committed_bytes: u64,
    pub consumed_bytes: u64,
    pub revision: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BudgetOverview {
    pub allocation_paused: bool,
    pub budgets: Vec<Budget>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantRequest {
    #[serde(default)]
    pub minimum_bytes: u64,
    pub budget_id: String,
    pub request_id: String,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct GrantReport {
    pub grant_id: String,
    pub consumed_bytes: u64,
    pub surrender: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetExchange {
    #[serde(default)]
    pub settle_only: bool,
    pub run_id: String,
    pub requests: Vec<GrantRequest>,
    pub reports: Vec<GrantReport>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Grant {
    pub grant_id: String,
    pub budget_id: String,
    pub request_id: String,
    pub run_id: String,
    pub bytes: u64,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetReply {
    #[serde(default)]
    pub cancelled_requests: Vec<String>,
    pub grants: Vec<Grant>,
    pub acknowledgements: Vec<GrantReport>,
    pub allocation_paused: bool,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RecoveryClaim {
    pub grant: Grant,
    pub consumed_bytes: u64,
    pub sealed: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetRecoveryRequest {
    pub lease: crate::lease::LeaseProof,
    pub ledger_id: String,
    pub run_id: String,
    pub claims: Vec<RecoveryClaim>,
    pub requests: Vec<GrantRequest>,
}
#[derive(Clone, Debug, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct BudgetRecoveryStats {
    pub run_id: String,
    pub at_ms: i64,
    pub validated_grants: u64,
    pub recovered_pending_grants: u64,
    pub cancelled_requests: u64,
    pub open_grants: u64,
}

pub(crate) struct RecoveryBatch {
    pub claims: Vec<RecoveryClaim>,
    pub requests: Vec<GrantRequest>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReservationView {
    pub grant_id: String,
    pub node_id: String,
    pub node_name: String,
    pub run_id: String,
    pub allocated_bytes: u64,
    pub confirmed_consumed_bytes: u64,
    pub outstanding_bytes: u64,
    pub node_lease: crate::lease::LeaseStatus,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct ReservationPage {
    pub budget_id: String,
    pub reservations: Vec<ReservationView>,
    pub next: Option<String>,
}

/// Whether an open reservation run can still act on the controller.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum RunFence {
    /// The run holds the node's execution lease; it is in use.
    Current,
    /// Another run took over, but the old run's window has not closed yet.
    Waiting,
    /// The run can no longer report or resume on its own.
    Fenced,
    /// The node has no execution lease, so only the operator can confirm the run stopped.
    Unconfirmed,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct StuckRun {
    pub node_id: String,
    pub node_name: String,
    pub run_id: String,
    pub reservations: u64,
    pub outstanding_bytes: u64,
    pub fence: RunFence,
    pub wait_ms: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct QuarantineBudget {
    pub id: String,
    pub name: String,
    pub revision: u64,
    pub limit_bytes: u64,
    pub committed_bytes: u64,
    /// Unknown use assumed when the restore lock ends: limit minus committed.
    pub assumed_bytes: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct RecoveryReceipt {
    pub operation_id: String,
    /// `write_off` or `quarantine_exit`.
    pub kind: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub node_id: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub run_id: Option<String>,
    pub reservations: u64,
    pub bytes: u64,
    pub reason: String,
    pub actor_id: String,
    pub at_ms: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct BudgetRecoveryView {
    pub enabled: bool,
    pub allocation_paused: bool,
    pub budgets: Vec<QuarantineBudget>,
    pub runs: Vec<StuckRun>,
    pub receipts: Vec<RecoveryReceipt>,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct RunWriteOff {
    pub operation_id: String,
    pub run_id: String,
    pub reason: String,
    /// Required when the node has no execution lease.
    #[serde(default)]
    pub stopped_confirmed: bool,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ReviewedBudget {
    pub id: String,
    pub expected_revision: u64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct QuarantineExit {
    pub operation_id: String,
    pub reason: String,
    /// Every budget at the revision the operator reviewed.
    pub budgets: Vec<ReviewedBudget>,
}
