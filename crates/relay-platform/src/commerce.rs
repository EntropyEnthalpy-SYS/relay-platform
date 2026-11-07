//! Minimal commerce core: plans, a single-currency wallet ledger, orders paid
//! from the wallet, refunds, and (optional feature) plan entitlements that turn
//! a paid order into the buyer's traffic budget, with traffic reset cycles and
//! automatic top-ups. Commissions and taxes are not implemented.
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
    /// Stored plans from before cycles have none: one allowance for the whole plan.
    #[serde(default)]
    pub traffic_reset: TrafficReset,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_up: Option<TopUp>,
}
/// When a plan's traffic starts again (only with plan entitlements).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TrafficReset {
    /// One allowance for the whole plan; renewals add traffic.
    #[default]
    None,
    /// At each billing boundary: activation, then the end of every paid period.
    Billing,
    /// Every N days (1..=366) from the start of the first cycle.
    EveryDays(u16),
}
impl TrafficReset {
    pub fn resets(self) -> bool {
        self != Self::None
    }
}
/// Traffic bought from the wallet when a cycle runs out. It belongs to the
/// current cycle only and never extends the plan.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct TopUp {
    pub bytes: u64,
    pub price_cents: i64,
    pub max_per_cycle: u32,
}
pub const MAX_TOP_UPS_PER_CYCLE: u32 = 1_000;
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
pub struct GiftCode {
    pub id: String,
    pub code: String,
    pub amount_cents: i64,
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
pub struct GiftCodeInput {
    pub code: String,
    pub amount_cents: i64,
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
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum OrderKind {
    /// A plan bought or renewed by the user.
    #[default]
    Plan,
    /// Traffic bought automatically for the current cycle; paid on creation.
    TopUp,
}
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Order {
    /// Orders stored before top-ups are plan orders.
    #[serde(default)]
    pub kind: OrderKind,
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
    /// The plan's reset policy and top-up when the order was created.
    #[serde(default)]
    pub traffic_reset: TrafficReset,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_up: Option<TopUp>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EntitlementState {
    /// The plan's traffic and days apply to the buyer's user budget.
    Active,
    /// Paid, but the user budget cannot be created until the buyer's rules are paused.
    AwaitingBudget,
    /// Expired or fully refunded: the budget issues no new traffic.
    Lapsed,
}
/// One paid order's contribution to an entitlement, copied from the order.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct EntitlementGrant {
    pub order_id: String,
    pub plan_name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub traffic_bytes: Option<u64>,
    pub duration_days: u32,
    pub granted_at_ms: i64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub revoked_at_ms: Option<i64>,
    #[serde(default)]
    pub traffic_reset: TrafficReset,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub top_up: Option<TopUp>,
}
/// A user's plan window. Renewals stack: days extend the expiry; without a
/// reset policy traffic adds up, with one each cycle gets the latest plan's traffic.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Entitlement {
    pub user_id: String,
    pub state: EntitlementState,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget_id: Option<String>,
    /// Allowance outside the plans: an adopted budget's limit, or the bytes
    /// already committed when a lapsed plan is renewed. Unused by cycles.
    pub base_bytes: u64,
    pub expires_at_ms: i64,
    pub grants: Vec<EntitlementGrant>,
    /// "Top up automatically when used up", switched by the user.
    #[serde(default)]
    pub auto_top_up: bool,
    /// Cycles started so far, across windows; numbers top-up ledger references.
    #[serde(default)]
    pub cycles: u64,
    /// The current traffic cycle of a plan that resets; none otherwise.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cycle: Option<TrafficCycle>,
}
/// One reset period. The budget's ledger never goes back: a cycle's room is
/// `baseline_bytes + allowance + top-ups`, never below the committed bytes.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct TrafficCycle {
    pub policy: TrafficReset,
    /// `every_days` boundaries fall on `anchor_ms + k · N days`.
    pub anchor_ms: i64,
    pub started_at_ms: i64,
    /// The budget's consumed bytes when the cycle began. Reservations that
    /// servers held then count against this cycle.
    pub baseline_bytes: u64,
    /// The plan's traffic per cycle; none is unlimited.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowance_bytes: Option<u64>,
    pub top_ups: u32,
    pub top_up_bytes: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub last_failure: Option<TopUpFailure>,
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum TopUpFailureReason {
    /// The plan has no top-up.
    NotConfigured,
    /// The user has not switched on automatic top-up.
    SwitchedOff,
    /// This cycle already had `max_per_cycle` top-ups.
    CapReached,
    /// The wallet balance is below the top-up price.
    InsufficientBalance,
}
impl TopUpFailureReason {
    /// The Chinese text used in alert summaries.
    pub fn summary(self) -> &'static str {
        match self {
            Self::NotConfigured => "套餐未配置自动补流量",
            Self::SwitchedOff => "用户未开启自动补流量",
            Self::CapReached => "本周期补流量次数已达上限",
            Self::InsufficientBalance => "钱包余额不足",
        }
    }
}
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub struct TopUpFailure {
    pub reason: TopUpFailureReason,
    pub at_ms: i64,
}
/// The current cycle as the user sees it.
#[derive(Clone, Debug, Serialize)]
pub struct CycleView {
    pub policy: TrafficReset,
    pub started_at_ms: i64,
    /// The next reset, or the plan's expiry when that comes first.
    pub ends_at_ms: i64,
    /// None when the plan expires before another reset.
    pub next_reset_at_ms: Option<i64>,
    /// The plan's traffic per cycle plus this cycle's top-ups; none is unlimited.
    pub allowance_bytes: Option<u64>,
    pub top_up_bytes: u64,
    /// Reported use since the cycle began.
    pub used_bytes: u64,
    /// Reservations servers hold that they have not reported as used yet.
    pub reserved_bytes: u64,
    /// What the controller can still hand out this cycle; none is unlimited.
    pub remaining_bytes: Option<u64>,
    pub top_ups: u32,
    /// The plan's top-up, with `max_per_cycle` as the cap.
    pub top_up: Option<TopUp>,
    pub last_failure: Option<TopUpFailure>,
}
#[derive(Clone, Debug, Serialize)]
pub struct EntitlementView {
    #[serde(flatten)]
    pub entitlement: Entitlement,
    pub username: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub budget: Option<crate::budget::Budget>,
    /// Present while a plan that resets is active or waiting for its budget.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub current_cycle: Option<CycleView>,
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
    pub traffic_reset: TrafficReset,
    pub top_up: Option<TopUp>,
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
pub fn validate_gift_code(input: &GiftCodeInput) -> Result<()> {
    let code = input.code.trim().to_ascii_uppercase();
    ensure!(
        code.len() >= 6
            && code.len() <= 32
            && code
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || b == b'-' || b == b'_'),
        "gift code must contain 6..32 ASCII letters, digits, '-' or '_'"
    );
    ensure!(
        input.amount_cents > 0 && input.amount_cents <= MAX_AMOUNT_CENTS,
        "gift amount must be positive and within range"
    );
    ensure!(input.starts_at_ms >= 0, "gift start must be nonnegative");
    ensure!(
        input.ends_at_ms.is_none_or(|end| end > input.starts_at_ms),
        "gift end must be after its start"
    );
    ensure!(
        input.max_redemptions.is_none_or(|max| max > 0),
        "gift max redemptions must be positive when set"
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
    if let TrafficReset::EveryDays(days) = input.traffic_reset {
        ensure!(
            (1..=366).contains(&days),
            "traffic reset interval must be 1..366 days"
        );
    }
    if let Some(top_up) = input.top_up {
        ensure!(
            input.traffic_reset.resets() && input.traffic_bytes.is_some(),
            "a top-up needs a plan whose traffic is limited and resets"
        );
        ensure!(
            top_up.bytes > 0 && top_up.bytes <= crate::model::MAX_COUNTER,
            "top-up traffic must be positive"
        );
        ensure!(
            (0..=MAX_AMOUNT_CENTS).contains(&top_up.price_cents),
            "top-up price is out of range"
        );
        ensure!(
            (1..=MAX_TOP_UPS_PER_CYCLE).contains(&top_up.max_per_cycle),
            "top-ups per cycle must be 1..1000"
        );
    }
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

/// Expires plans whose days have run out, retries plans waiting for their
/// budget and starts due traffic cycles, once per `tick`.
pub async fn run_entitlements(
    store: crate::store::Store,
    tick: std::time::Duration,
    stop: tokio_util::sync::CancellationToken,
) {
    let mut interval = tokio::time::interval(tick);
    interval.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Delay);
    loop {
        tokio::select! {
            biased;
            _ = stop.cancelled() => return,
            _ = interval.tick() => {}
        }
        let db = store.clone();
        match tokio::task::spawn_blocking(move || db.sweep_entitlements()).await {
            Ok(Ok(_)) => {}
            Ok(Err(error)) => tracing::warn!(%error, "plan entitlement sweep failed"),
            Err(_) => return,
        }
    }
}
