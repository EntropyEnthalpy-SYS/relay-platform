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
    pub grants: Vec<Grant>,
    pub acknowledgements: Vec<GrantReport>,
    pub allocation_paused: bool,
}
