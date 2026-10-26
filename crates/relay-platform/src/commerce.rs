//! Minimal commerce core: plans, a single-currency wallet ledger, orders paid
//! from the wallet, and refunds. Payment-provider callbacks, coupons,
//! commissions, taxes and service-entitlement enforcement are not implemented.
use crate::model::now_ms;
use anyhow::{Result, ensure};
use serde::{Deserialize, Serialize};

pub const CURRENCY: &str = "CNY";
pub const MAX_AMOUNT_CENTS: i64 = 1_000_000_000_000;

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Plan {
    pub id: String,
    pub name: String,
    pub description: String,
    pub price_cents: i64,
    pub duration_days: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic_bytes: Option<u64>,
    pub enabled: bool,
    pub created_at_ms: i64,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Wallet {
    pub user_id: String,
    pub balance_cents: i64,
    pub currency: String,
    pub updated_at_ms: i64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum LedgerKind {
    Adjustment,
    Credit,
    Purchase,
    Refund,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct LedgerEntry {
    pub id: String,
    pub user_id: String,
    pub delta_cents: i64,
    pub currency: String,
    pub kind: LedgerKind,
    pub reference: String,
    pub description: String,
    pub created_at_ms: i64,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderStatus {
    Pending,
    Paid,
    Refunded,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Order {
    pub id: String,
    pub user_id: String,
    pub plan_id: String,
    pub plan_name: String,
    pub amount_cents: i64,
    pub currency: String,
    pub duration_days: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic_bytes: Option<u64>,
    pub status: OrderStatus,
    pub created_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub paid_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub refunded_at_ms: Option<i64>,
}
#[derive(Clone, Debug, Serialize)]
pub struct WalletView {
    pub wallet: Wallet,
    pub entries: Vec<LedgerEntry>,
}
#[derive(Clone, Debug)]
pub struct PlanInput {
    pub name: String,
    pub description: String,
    pub price_cents: i64,
    pub duration_days: u32,
    pub traffic_bytes: Option<u64>,
    pub enabled: bool,
}
pub fn validate_plan(input: &PlanInput) -> Result<()> {
    ensure!(
        !input.name.trim().is_empty()
            && input.name.len() <= 120
            && !input.name.chars().any(char::is_control),
        "plan name must contain 1..120 bytes without control characters"
    );
    ensure!(
        input.description.len() <= 5_000 && !input.description.contains('\0'),
        "plan description must be at most 5000 bytes"
    );
    ensure!(
        (0..=MAX_AMOUNT_CENTS).contains(&input.price_cents),
        "plan price is out of range"
    );
    ensure!(
        (1..=3650).contains(&input.duration_days),
        "plan duration must be 1..3650 days"
    );
    ensure!(
        input.traffic_bytes.is_none_or(|bytes| bytes > 0),
        "plan traffic must be positive when set"
    );
    Ok(())
}
pub fn validate_reference(reference: &str) -> Result<()> {
    ensure!(
        !reference.trim().is_empty()
            && reference.len() <= 120
            && reference.trim() == reference
            && !reference.chars().any(char::is_control),
        "ledger reference must contain 1..120 bytes without surrounding whitespace or control characters"
    );
    Ok(())
}
pub fn validate_adjustment(delta_cents: i64, reference: &str, description: &str) -> Result<()> {
    ensure!(
        delta_cents != 0 && delta_cents.unsigned_abs() <= MAX_AMOUNT_CENTS as u64,
        "wallet adjustment must be nonzero and within range"
    );
    validate_reference(reference)?;
    ensure!(
        description.len() <= 500 && !description.contains('\0'),
        "wallet adjustment description must be at most 500 bytes"
    );
    Ok(())
}
pub fn now() -> i64 {
    now_ms()
}
