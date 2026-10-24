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
