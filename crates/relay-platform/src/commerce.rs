//! Minimal commerce core: plans, a single-currency wallet ledger, orders paid
//! from the wallet, and refunds. Payment-provider callbacks, coupons,
//! commissions, taxes and service-entitlement enforcement are not implemented.
use crate::model::now_ms;
use anyhow::{Context, Result, ensure};
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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum CouponKind {
    Percent,
    Fixed,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Coupon {
    pub id: String,
    pub code: String,
    pub kind: CouponKind,
    /// Percent 1..100, or fixed discount in cents.
    pub value: i64,
    #[serde(default)]
    pub min_amount_cents: i64,
    pub starts_at_ms: i64,
    pub ends_at_ms: Option<i64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_redemptions: Option<u32>,
    #[serde(default)]
    pub redeemed: u32,
    pub enabled: bool,
    pub created_at_ms: i64,
}
#[derive(Clone, Debug)]
pub struct CouponInput {
    pub code: String,
    pub kind: CouponKind,
    pub value: i64,
    pub min_amount_cents: i64,
    pub starts_at_ms: i64,
    pub ends_at_ms: Option<i64>,
    pub max_redemptions: Option<u32>,
    pub enabled: bool,
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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentChannel {
    #[default]
    Wallet,
    External,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum PaymentStatus {
    Pending,
    Paid,
    Failed,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Payment {
    pub id: String,
    pub order_id: String,
    pub user_id: String,
    pub amount_cents: i64,
    pub status: PaymentStatus,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub external_id: Option<String>,
    pub created_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub settled_at_ms: Option<i64>,
}
#[derive(Clone, Debug, Serialize)]
pub struct WebhookView {
    pub enabled: bool,
    pub secret_set: bool,
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
    /// Plan price before a coupon.
    #[serde(default)]
    pub subtotal_cents: i64,
    /// Coupon discount actually applied.
    #[serde(default)]
    pub discount_cents: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub coupon_code: Option<String>,
    /// Final amount charged (subtotal - discount).
    pub amount_cents: i64,
    pub currency: String,
    pub duration_days: u32,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic_bytes: Option<u64>,
    pub status: OrderStatus,
    #[serde(default)]
    pub channel: PaymentChannel,
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
pub fn validate_coupon(input: &CouponInput) -> Result<()> {
    let code = input.code.trim().to_ascii_uppercase();
    ensure!(
        code.len() >= 3
            && code.len() <= 32
            && code
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "coupon code must contain 3..32 ASCII letters, digits, '-' or '_'"
    );
    ensure!(
        (0..=MAX_AMOUNT_CENTS).contains(&input.min_amount_cents),
        "coupon minimum amount is out of range"
    );
    match input.kind {
        CouponKind::Percent => ensure!(
            (1..=100).contains(&input.value),
            "percent coupon must be 1..100"
        ),
        CouponKind::Fixed => ensure!(
            input.value > 0 && input.value <= MAX_AMOUNT_CENTS,
            "fixed coupon must be positive and within range"
        ),
    }
    ensure!(input.starts_at_ms >= 0, "coupon start must be nonnegative");
    ensure!(
        input.ends_at_ms.is_none_or(|end| end > input.starts_at_ms),
        "coupon end must be after its start"
    );
    ensure!(
        input.max_redemptions.is_none_or(|max| max > 0),
        "coupon max redemptions must be positive when set"
    );
    Ok(())
}
pub fn discount_for(coupon: &Coupon, subtotal: i64, now: i64) -> Result<i64> {
    ensure!(
        coupon.enabled
            && coupon.starts_at_ms <= now
            && coupon.ends_at_ms.is_none_or(|end| end > now),
        "coupon is not active"
    );
    ensure!(
        coupon
            .max_redemptions
            .is_none_or(|max| coupon.redeemed < max),
        "coupon redemption limit reached"
    );
    ensure!(
        subtotal >= coupon.min_amount_cents,
        "order is below the coupon minimum"
    );
    let discount = match coupon.kind {
        CouponKind::Percent => (subtotal / 100)
            .checked_mul(coupon.value)
            .context("coupon discount overflow")?,
        CouponKind::Fixed => coupon.value,
    };
    Ok(discount.clamp(0, subtotal))
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
