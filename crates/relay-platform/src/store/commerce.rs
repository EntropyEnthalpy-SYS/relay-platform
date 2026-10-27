//! Commerce persistence in metadata. Money moves only inside a SQLite
//! transaction together with its ledger entry and order/wallet state.
use super::*;
use crate::commerce::{
    CURRENCY, Coupon, CouponInput, GiftCode, GiftCodeInput, LedgerEntry, LedgerKind, Order,
    OrderStatus, Payment, PaymentChannel, PaymentStatus, Plan, PlanInput, Wallet, WalletView,
    WebhookView, discount_for, validate_adjustment, validate_coupon, validate_gift_code,
    validate_plan,
};

fn plan_key(id: &str) -> String {
    format!("commerce_plan:{id}")
}
fn wallet_key(user: &str) -> String {
    format!("commerce_wallet:{user}")
}
fn ledger_key(id: &str) -> String {
    format!("commerce_ledger:{id}")
}
fn ledger_ref_key(reference: &str) -> String {
    format!("commerce_ledger_ref:{reference}")
}
fn order_key(id: &str) -> String {
    format!("commerce_order:{id}")
}
fn coupon_key(id: &str) -> String {
    format!("commerce_coupon:{id}")
}
fn coupon_code_key(code: &str) -> String {
    format!("commerce_coupon_code:{code}")
}
fn gift_key(id: &str) -> String {
    format!("commerce_gift:{id}")
}
fn gift_code_key(code: &str) -> String {
    format!("commerce_gift_code:{code}")
}
fn payment_key(id: &str) -> String {
    format!("commerce_payment:{id}")
}
const WEBHOOK_KEY: &str = "commerce_webhook";
#[derive(Serialize, Deserialize)]
pub(crate) struct WebhookRecord {
    pub(crate) secret: String,
    pub(crate) enabled: bool,
}
fn read_plan(conn: &Connection, id: &str) -> Result<Option<Plan>> {
    read_json(conn, &plan_key(id))
}
fn read_wallet(conn: &Connection, user: &str) -> Result<Wallet> {
    Ok(
        read_json::<Wallet>(conn, &wallet_key(user))?.unwrap_or(Wallet {
            user_id: user.into(),
            balance_cents: 0,
            currency: CURRENCY.into(),
            updated_at_ms: now_ms(),
        }),
    )
}
fn write_wallet(tx: &Transaction<'_>, wallet: &Wallet) -> Result<()> {
    write_json(tx, &wallet_key(&wallet.user_id), wallet)
}
fn read_order(conn: &Connection, id: &str) -> Result<Option<Order>> {
    let mut order: Option<Order> = read_json(conn, &order_key(id))?;
    if let Some(order) = &mut order
        && order.subtotal_cents == 0
        && order.discount_cents == 0
    {
        order.subtotal_cents = order.amount_cents;
    }
    Ok(order)
}
fn read_coupon(conn: &Connection, id: &str) -> Result<Option<Coupon>> {
    read_json(conn, &coupon_key(id))
}
fn read_coupon_code(conn: &Connection, code: &str) -> Result<Option<Coupon>> {
    let id: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            [coupon_code_key(code)],
            |r| r.get(0),
        )
        .optional()?;
    id.map(|id| read_coupon(conn, &id))
        .transpose()
        .map(Option::flatten)
}
fn read_gift(conn: &Connection, id: &str) -> Result<Option<GiftCode>> {
    read_json(conn, &gift_key(id))
}
fn read_gift_code(conn: &Connection, code: &str) -> Result<Option<GiftCode>> {
    let id: Option<String> = conn
        .query_row(
            "SELECT value FROM metadata WHERE key=?1",
            [gift_code_key(code)],
            |r| r.get(0),
        )
        .optional()?;
    id.map(|id| read_gift(conn, &id))
        .transpose()
        .map(Option::flatten)
}
fn write_gift(tx: &Transaction<'_>, gift: &GiftCode) -> Result<()> {
    write_json(tx, &gift_key(&gift.id), gift)?;
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![gift_code_key(&gift.code), gift.id],
    )?;
    Ok(())
}
fn write_coupon(tx: &Transaction<'_>, coupon: &Coupon) -> Result<()> {
    write_json(tx, &coupon_key(&coupon.id), coupon)?;
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![coupon_code_key(&coupon.code), coupon.id],
    )?;
    Ok(())
}
fn write_order(tx: &Transaction<'_>, order: &Order) -> Result<()> {
    write_json(tx, &order_key(&order.id), order)
}
fn read_ledger_ref(conn: &Connection, reference: &str) -> Result<Option<String>> {
    conn.query_row(
        "SELECT value FROM metadata WHERE key=?1",
        [ledger_ref_key(reference)],
        |r| r.get(0),
    )
    .optional()
    .map_err(Into::into)
}
fn post_ledger(
    tx: &Transaction<'_>,
    user_id: &str,
    delta_cents: i64,
    kind: LedgerKind,
    reference: &str,
    description: &str,
) -> Result<LedgerEntry> {
    if read_ledger_ref(tx, reference)?.is_some() {
        return reject(
            409,
            "ledger reference already used; refusing a duplicate money entry",
        );
    }
    let entry = LedgerEntry {
        id: Uuid::new_v4().to_string(),
        user_id: user_id.into(),
        delta_cents,
        currency: CURRENCY.into(),
        kind,
        reference: reference.into(),
        description: description.into(),
        created_at_ms: now_ms(),
    };
    write_json(tx, &ledger_key(&entry.id), &entry)?;
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2)",
        params![ledger_ref_key(reference), entry.id],
    )?;
    Ok(entry)
}

// Small JSON helpers local to this module.
fn read_json<T: serde::de::DeserializeOwned>(conn: &Connection, key: &str) -> Result<Option<T>> {
    let raw: Option<String> = conn
        .query_row("SELECT value FROM metadata WHERE key=?1", [key], |r| {
            r.get(0)
        })
        .optional()?;
    Ok(raw.map(|value| serde_json::from_str(&value)).transpose()?)
}
fn write_json<T: Serialize>(tx: &Transaction<'_>, key: &str, value: &T) -> Result<()> {
    tx.execute(
        "INSERT INTO metadata(key,value) VALUES(?1,?2) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, serde_json::to_string(value)?],
    )?;
    Ok(())
}
fn all<T: serde::de::DeserializeOwned>(conn: &Connection, prefix: &str) -> Result<Vec<T>> {
    let mut q = conn.prepare("SELECT value FROM metadata WHERE key GLOB ?1 ORDER BY key")?;
    let rows: Vec<String> = q
        .query_map([format!("{prefix}*")], |r| r.get(0))?
        .collect::<rusqlite::Result<_>>()?;
    rows.into_iter()
        .map(|value| serde_json::from_str(&value).context("invalid stored commerce record"))
        .collect()
}
fn require_admin(actor: &Actor) -> Result<()> {
    if actor.role != Role::SystemAdmin {
        return reject(
            403,
            "commerce plan/wallet operations require a system administrator",
        );
    }
    Ok(())
}
fn require_user(actor: &Actor, user: &str) -> Result<()> {
    if actor.id != user && actor.role != Role::SystemAdmin {
        return reject(403, "wallet belongs to another user");
    }
    Ok(())
}

impl Store {
    pub fn commerce_plans(&self, actor: &Actor) -> Result<Vec<Plan>> {
        let conn = self.0.lock().unwrap();
        let mut plans = all::<Plan>(&conn, "commerce_plan:")?;
        if actor.role != Role::SystemAdmin {
            plans.retain(|plan| plan.enabled);
        }
        plans.sort_by_key(|plan| plan.price_cents);
        Ok(plans)
    }
    pub fn create_commerce_plan(&self, actor: &Actor, input: PlanInput) -> Result<Plan> {
        require_admin(actor)?;
        validate_plan(&input)?;
        let plan = Plan {
            id: Uuid::new_v4().to_string(),
            name: input.name,
            description: input.description,
            price_cents: input.price_cents,
            duration_days: input.duration_days,
            traffic_bytes: input.traffic_bytes,
            enabled: input.enabled,
            created_at_ms: now_ms(),
        };
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        write_json(&tx, &plan_key(&plan.id), &plan)?;
        audit(&tx, &actor.id, "commerce.plan.create", &plan.id, "{}")?;
        tx.commit()?;
        Ok(plan)
    }
    pub fn update_commerce_plan(&self, actor: &Actor, id: &str, input: PlanInput) -> Result<Plan> {
        require_admin(actor)?;
        validate_plan(&input)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut plan = read_plan(&tx, id)?.context("plan not found")?;
        plan.name = input.name;
        plan.description = input.description;
        plan.price_cents = input.price_cents;
        plan.duration_days = input.duration_days;
        plan.traffic_bytes = input.traffic_bytes;
        plan.enabled = input.enabled;
        write_json(&tx, &plan_key(&plan.id), &plan)?;
        audit(&tx, &actor.id, "commerce.plan.update", &plan.id, "{}")?;
        tx.commit()?;
        Ok(plan)
    }
    pub fn delete_commerce_plan(&self, actor: &Actor, id: &str) -> Result<()> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let plan = read_plan(&tx, id)?.context("plan not found")?;
        let orders: i64 = tx.query_row(
            "SELECT COUNT(*) FROM metadata WHERE key GLOB 'commerce_order:*' AND json_extract(value,'$.plan_id')=?1",
            [&plan.id],
            |r| r.get(0),
        )?;
        if orders > 0 {
            return reject(409, "disable the plan; it already has orders");
        }
        tx.execute("DELETE FROM metadata WHERE key=?1", [plan_key(id)])?;
        audit(&tx, &actor.id, "commerce.plan.delete", id, "{}")?;
        tx.commit()?;
        Ok(())
    }
    pub fn wallet(&self, actor: &Actor, user: &str) -> Result<WalletView> {
        require_user(actor, user)?;
        let conn = self.0.lock().unwrap();
        let wallet = read_wallet(&conn, user)?;
        let mut entries = all::<LedgerEntry>(&conn, "commerce_ledger:")?;
        entries.retain(|entry| entry.user_id == user);
        entries.sort_by_key(|entry| std::cmp::Reverse(entry.created_at_ms));
        Ok(WalletView { wallet, entries })
    }
    pub fn adjust_wallet(
        &self,
        actor: &Actor,
        user: &str,
        delta_cents: i64,
        reference: &str,
        description: &str,
    ) -> Result<Wallet> {
        require_admin(actor)?;
        validate_adjustment(delta_cents, reference, description)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        // Ensure the target exists.
        if !tx.query_row(
            "SELECT EXISTS(SELECT 1 FROM users WHERE id=?1)",
            [user],
            |r| r.get::<_, bool>(0),
        )? {
            return reject(404, "user not found");
        }
        let mut wallet = read_wallet(&tx, user)?;
        let balance = wallet
            .balance_cents
            .checked_add(delta_cents)
            .context("wallet balance overflow")?;
        if balance < 0 {
            return reject(409, "wallet has insufficient funds");
        }
        wallet.balance_cents = balance;
        wallet.updated_at_ms = now_ms();
        write_wallet(&tx, &wallet)?;
        post_ledger(
            &tx,
            user,
            delta_cents,
            LedgerKind::Adjustment,
            reference,
            description,
        )?;
        audit(&tx, &actor.id, "commerce.wallet.adjust", user, "{}")?;
        tx.commit()?;
        Ok(wallet)
    }
    pub fn orders(&self, actor: &Actor) -> Result<Vec<Order>> {
        let conn = self.0.lock().unwrap();
        let mut orders = all::<Order>(&conn, "commerce_order:")?;
        if actor.role != Role::SystemAdmin {
            orders.retain(|order| order.user_id == actor.id);
        }
        orders.sort_by_key(|order| std::cmp::Reverse(order.created_at_ms));
        Ok(orders)
    }
    pub fn create_order(&self, actor: &Actor, plan_id: &str) -> Result<Order> {
        self.create_order_with_coupon(actor, plan_id, None)
    }
    pub fn create_order_with_coupon(
        &self,
        actor: &Actor,
        plan_id: &str,
        coupon_code: Option<&str>,
    ) -> Result<Order> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let plan = read_plan(&tx, plan_id)?.context("plan not found")?;
        if !plan.enabled {
            return reject(409, "plan is disabled");
        }
        let subtotal_cents = plan.price_cents;
        let mut discount_cents = 0;
        let mut applied_coupon = None;
        if let Some(code) = coupon_code.map(str::trim).filter(|code| !code.is_empty()) {
            let code = code.to_ascii_uppercase();
            let mut coupon = match read_coupon_code(&tx, &code)? {
                Some(coupon) => coupon,
                None => return reject(404, "coupon not found"),
            };
            discount_cents = match discount_for(&coupon, subtotal_cents, now_ms()) {
                Ok(discount) => discount,
                Err(error) => return reject(409, error.to_string()),
            };
            coupon.redeemed = coupon
                .redeemed
                .checked_add(1)
                .context("coupon redemption overflow")?;
            write_coupon(&tx, &coupon)?;
            applied_coupon = Some(code);
        }
        let order = Order {
            id: Uuid::new_v4().to_string(),
            user_id: actor.id.clone(),
            plan_id: plan.id.clone(),
            plan_name: plan.name.clone(),
            subtotal_cents,
            discount_cents,
            coupon_code: applied_coupon,
            amount_cents: subtotal_cents - discount_cents,
            currency: CURRENCY.into(),
            duration_days: plan.duration_days,
            traffic_bytes: plan.traffic_bytes,
            status: OrderStatus::Pending,
            channel: PaymentChannel::Wallet,
            created_at_ms: now_ms(),
            paid_at_ms: None,
            refunded_at_ms: None,
        };
        write_order(&tx, &order)?;
        audit(&tx, &actor.id, "commerce.order.create", &order.id, "{}")?;
        tx.commit()?;
        Ok(order)
    }
    pub fn pay_order(&self, actor: &Actor, id: &str) -> Result<Order> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut order = read_order(&tx, id)?.context("order not found")?;
        if order.user_id != actor.id && actor.role != Role::SystemAdmin {
            return reject(403, "order belongs to another user");
        }
        if order.status != OrderStatus::Pending {
            return reject(409, "order is not pending");
        }
        // A wallet payment supersedes any pending external intent; a later
        // callback sees a failed payment and cannot settle the order twice.
        for mut payment in all::<Payment>(&tx, "commerce_payment:")?
            .into_iter()
            .filter(|payment| {
                payment.order_id == order.id && payment.status == PaymentStatus::Pending
            })
        {
            payment.status = PaymentStatus::Failed;
            payment.settled_at_ms = Some(now_ms());
            write_json(&tx, &payment_key(&payment.id), &payment)?;
        }
        let mut wallet = read_wallet(&tx, &order.user_id)?;
        if wallet.balance_cents < order.amount_cents {
            return reject(409, "wallet has insufficient funds");
        }
        if order.amount_cents > 0 {
            wallet.balance_cents -= order.amount_cents;
            wallet.updated_at_ms = now_ms();
            write_wallet(&tx, &wallet)?;
            post_ledger(
                &tx,
                &order.user_id,
                -order.amount_cents,
                LedgerKind::Purchase,
                &format!("order:{}", order.id),
                &format!("purchase {}", order.plan_name),
            )?;
        }
        order.status = OrderStatus::Paid;
        order.paid_at_ms = Some(now_ms());
        write_order(&tx, &order)?;
        audit(&tx, &actor.id, "commerce.order.pay", &order.id, "{}")?;
        tx.commit()?;
        Ok(order)
    }
    pub fn refund_order(&self, actor: &Actor, id: &str) -> Result<Order> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut order = read_order(&tx, id)?.context("order not found")?;
        if order.status != OrderStatus::Paid {
            return reject(409, "only a paid order can be refunded");
        }
        if order.channel == PaymentChannel::External {
            return reject(
                409,
                "external payments must be refunded through the payment provider",
            );
        }
        if order.amount_cents > 0 {
            let mut wallet = read_wallet(&tx, &order.user_id)?;
            wallet.balance_cents = wallet
                .balance_cents
                .checked_add(order.amount_cents)
                .context("wallet balance overflow")?;
            wallet.updated_at_ms = now_ms();
            write_wallet(&tx, &wallet)?;
            post_ledger(
                &tx,
                &order.user_id,
                order.amount_cents,
                LedgerKind::Refund,
                &format!("refund:{}", order.id),
                &format!("refund {}", order.plan_name),
            )?;
        }
        order.status = OrderStatus::Refunded;
        order.refunded_at_ms = Some(now_ms());
        write_order(&tx, &order)?;
        audit(&tx, &actor.id, "commerce.order.refund", &order.id, "{}")?;
        tx.commit()?;
        Ok(order)
    }
    pub fn commerce_coupons(&self, actor: &Actor) -> Result<Vec<Coupon>> {
        require_admin(actor)?;
        let conn = self.0.lock().unwrap();
        let mut coupons = all::<Coupon>(&conn, "commerce_coupon:")?;
        coupons.sort_by_key(|coupon| std::cmp::Reverse(coupon.created_at_ms));
        Ok(coupons)
    }
    pub fn create_coupon(&self, actor: &Actor, input: CouponInput) -> Result<Coupon> {
        require_admin(actor)?;
        validate_coupon(&input)?;
        let code = input.code.trim().to_ascii_uppercase();
        let coupon = Coupon {
            id: Uuid::new_v4().to_string(),
            code,
            kind: input.kind,
            value: input.value,
            min_amount_cents: input.min_amount_cents,
            starts_at_ms: input.starts_at_ms,
            ends_at_ms: input.ends_at_ms,
            max_redemptions: input.max_redemptions,
            redeemed: 0,
            enabled: input.enabled,
            created_at_ms: now_ms(),
        };
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        if read_coupon_code(&tx, &coupon.code)?.is_some() {
            return reject(409, "coupon code already exists");
        }
        write_coupon(&tx, &coupon)?;
        audit(&tx, &actor.id, "commerce.coupon.create", &coupon.id, "{}")?;
        tx.commit()?;
        Ok(coupon)
    }
    pub fn update_coupon(&self, actor: &Actor, id: &str, input: CouponInput) -> Result<Coupon> {
        require_admin(actor)?;
        validate_coupon(&input)?;
        let code = input.code.trim().to_ascii_uppercase();
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut coupon = read_coupon(&tx, id)?.context("coupon not found")?;
        if let Some(existing) = read_coupon_code(&tx, &code)?
            && existing.id != coupon.id
        {
            return reject(409, "coupon code already exists");
        }
        tx.execute(
            "DELETE FROM metadata WHERE key=?1",
            [coupon_code_key(&coupon.code)],
        )?;
        coupon.code = code;
        coupon.kind = input.kind;
        coupon.value = input.value;
        coupon.min_amount_cents = input.min_amount_cents;
        coupon.starts_at_ms = input.starts_at_ms;
        coupon.ends_at_ms = input.ends_at_ms;
        coupon.max_redemptions = input.max_redemptions;
        coupon.enabled = input.enabled;
        write_coupon(&tx, &coupon)?;
        audit(&tx, &actor.id, "commerce.coupon.update", &coupon.id, "{}")?;
        tx.commit()?;
        Ok(coupon)
    }
    pub fn delete_coupon(&self, actor: &Actor, id: &str) -> Result<()> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let coupon = read_coupon(&tx, id)?.context("coupon not found")?;
        if coupon.redeemed > 0 {
            return reject(409, "disable the coupon; it already has redemptions");
        }
        tx.execute("DELETE FROM metadata WHERE key=?1", [coupon_key(id)])?;
        tx.execute(
            "DELETE FROM metadata WHERE key=?1",
            [coupon_code_key(&coupon.code)],
        )?;
        audit(&tx, &actor.id, "commerce.coupon.delete", id, "{}")?;
        tx.commit()?;
        Ok(())
    }
    pub fn commerce_gift_codes(&self, actor: &Actor) -> Result<Vec<GiftCode>> {
        require_admin(actor)?;
        let conn = self.0.lock().unwrap();
        let mut gifts = all::<GiftCode>(&conn, "commerce_gift:")?;
        gifts.sort_by_key(|gift| std::cmp::Reverse(gift.created_at_ms));
        Ok(gifts)
    }
    pub fn create_gift_code(&self, actor: &Actor, input: GiftCodeInput) -> Result<GiftCode> {
        require_admin(actor)?;
        validate_gift_code(&input)?;
        let code = input.code.trim().to_ascii_uppercase();
        let gift = GiftCode {
            id: Uuid::new_v4().to_string(),
            code,
            amount_cents: input.amount_cents,
            starts_at_ms: input.starts_at_ms,
            ends_at_ms: input.ends_at_ms,
            max_redemptions: input.max_redemptions,
            redeemed: 0,
            enabled: input.enabled,
            created_at_ms: now_ms(),
        };
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        if read_gift_code(&tx, &gift.code)?.is_some() {
            return reject(409, "gift code already exists");
        }
        write_gift(&tx, &gift)?;
        audit(&tx, &actor.id, "commerce.gift.create", &gift.id, "{}")?;
        tx.commit()?;
        Ok(gift)
    }
    pub fn update_gift_code(
        &self,
        actor: &Actor,
        id: &str,
        input: GiftCodeInput,
    ) -> Result<GiftCode> {
        require_admin(actor)?;
        validate_gift_code(&input)?;
        let code = input.code.trim().to_ascii_uppercase();
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut gift = read_gift(&tx, id)?.context("gift code not found")?;
        if let Some(existing) = read_gift_code(&tx, &code)?
            && existing.id != gift.id
        {
            return reject(409, "gift code already exists");
        }
        tx.execute(
            "DELETE FROM metadata WHERE key=?1",
            [gift_code_key(&gift.code)],
        )?;
        gift.code = code;
        gift.amount_cents = input.amount_cents;
        gift.starts_at_ms = input.starts_at_ms;
        gift.ends_at_ms = input.ends_at_ms;
        gift.max_redemptions = input.max_redemptions;
        gift.enabled = input.enabled;
        write_gift(&tx, &gift)?;
        audit(&tx, &actor.id, "commerce.gift.update", &gift.id, "{}")?;
        tx.commit()?;
        Ok(gift)
    }
    pub fn delete_gift_code(&self, actor: &Actor, id: &str) -> Result<()> {
        require_admin(actor)?;
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let gift = read_gift(&tx, id)?.context("gift code not found")?;
        if gift.redeemed > 0 {
            return reject(409, "disable the gift code; it already has redemptions");
        }
        tx.execute("DELETE FROM metadata WHERE key=?1", [gift_key(id)])?;
        tx.execute(
            "DELETE FROM metadata WHERE key=?1",
            [gift_code_key(&gift.code)],
        )?;
        audit(&tx, &actor.id, "commerce.gift.delete", id, "{}")?;
        tx.commit()?;
        Ok(())
    }
    pub fn redeem_gift_code(&self, actor: &Actor, code: &str) -> Result<Wallet> {
        let code = code.trim().to_ascii_uppercase();
        let now = now_ms();
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut gift = match read_gift_code(&tx, &code)? {
            Some(gift) => gift,
            None => return reject(404, "gift code not found"),
        };
        if !gift.enabled || gift.starts_at_ms > now || gift.ends_at_ms.is_some_and(|end| end <= now)
        {
            return reject(409, "gift code is not active");
        }
        if gift.max_redemptions.is_some_and(|max| gift.redeemed >= max) {
            return reject(409, "gift code redemption limit reached");
        }
        let reference = format!("gift:{}:{}", gift.code, actor.id);
        if read_ledger_ref(&tx, &reference)?.is_some() {
            return reject(409, "gift code already redeemed by this user");
        }
        let mut wallet = read_wallet(&tx, &actor.id)?;
        wallet.balance_cents = wallet
            .balance_cents
            .checked_add(gift.amount_cents)
            .context("wallet balance overflow")?;
        wallet.updated_at_ms = now;
        write_wallet(&tx, &wallet)?;
        gift.redeemed = gift
            .redeemed
            .checked_add(1)
            .context("gift redemption overflow")?;
        write_gift(&tx, &gift)?;
        post_ledger(
            &tx,
            &actor.id,
            gift.amount_cents,
            LedgerKind::Credit,
            &reference,
            &format!("gift {}", gift.code),
        )?;
        audit(&tx, &actor.id, "commerce.gift.redeem", &gift.id, "{}")?;
        tx.commit()?;
        Ok(wallet)
    }
    pub fn commerce_webhook(&self, actor: &Actor) -> Result<WebhookView> {
        require_admin(actor)?;
        let conn = self.0.lock().unwrap();
        let record: Option<WebhookRecord> = read_json(&conn, WEBHOOK_KEY)?;
        Ok(WebhookView {
            enabled: record.as_ref().is_some_and(|r| r.enabled),
            secret_set: record.as_ref().is_some_and(|r| !r.secret.is_empty()),
        })
    }
    pub fn set_commerce_webhook(
        &self,
        actor: &Actor,
        secret: &str,
        enabled: bool,
    ) -> Result<WebhookView> {
        require_admin(actor)?;
        if secret.len() < 16 || secret.len() > 512 || secret.chars().any(char::is_control) {
            return reject(
                400,
                "webhook secret must contain 16..512 bytes without control characters",
            );
        }
        let record = WebhookRecord {
            secret: secret.into(),
            enabled,
        };
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        write_json(&tx, WEBHOOK_KEY, &record)?;
        audit(&tx, &actor.id, "commerce.webhook.update", "commerce", "{}")?;
        tx.commit()?;
        Ok(WebhookView {
            enabled,
            secret_set: true,
        })
    }
    pub(crate) fn commerce_webhook_secret(&self) -> Result<Option<WebhookRecord>> {
        let conn = self.0.lock().unwrap();
        read_json(&conn, WEBHOOK_KEY)
    }
    pub fn create_payment(&self, actor: &Actor, order_id: &str) -> Result<Payment> {
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let order = read_order(&tx, order_id)?.context("order not found")?;
        if order.user_id != actor.id && actor.role != Role::SystemAdmin {
            return reject(403, "order belongs to another user");
        }
        if order.status != OrderStatus::Pending {
            return reject(409, "only a pending order can create a payment");
        }
        let existing: Option<Payment> = all::<Payment>(&tx, "commerce_payment:")?
            .into_iter()
            .find(|p| p.order_id == order.id && p.status == PaymentStatus::Pending);
        if let Some(payment) = existing {
            return Ok(payment);
        }
        let payment = Payment {
            id: Uuid::new_v4().to_string(),
            order_id: order.id,
            user_id: order.user_id,
            amount_cents: order.amount_cents,
            status: PaymentStatus::Pending,
            external_id: None,
            created_at_ms: now_ms(),
            settled_at_ms: None,
        };
        write_json(&tx, &payment_key(&payment.id), &payment)?;
        audit(&tx, &actor.id, "commerce.payment.create", &payment.id, "{}")?;
        tx.commit()?;
        Ok(payment)
    }
    /// Used only after the caller verified the webhook signature.
    pub fn settle_external_payment(
        &self,
        payment_id: &str,
        status: PaymentStatus,
        external_id: Option<&str>,
        amount_cents: i64,
    ) -> Result<(Payment, bool)> {
        if !matches!(status, PaymentStatus::Paid | PaymentStatus::Failed) {
            return reject(400, "webhook status must be paid or failed");
        }
        let mut conn = self.0.lock().unwrap();
        let tx = conn.transaction()?;
        let mut payment: Payment =
            read_json(&tx, &payment_key(payment_id))?.context("payment not found")?;
        if payment.amount_cents != amount_cents {
            return reject(409, "payment amount does not match the order");
        }
        if payment.status == status && payment.status != PaymentStatus::Pending {
            return Ok((payment, true));
        }
        if payment.status != PaymentStatus::Pending {
            return reject(409, "payment has already been settled differently");
        }
        let mut order = read_order(&tx, &payment.order_id)?.context("order not found")?;
        if order.status != OrderStatus::Pending {
            return reject(409, "order is not pending");
        }
        payment.status = status;
        payment.external_id = external_id.map(str::to_owned);
        payment.settled_at_ms = Some(now_ms());
        write_json(&tx, &payment_key(&payment.id), &payment)?;
        let paid = status == PaymentStatus::Paid;
        if paid {
            order.status = OrderStatus::Paid;
            order.channel = PaymentChannel::External;
            order.paid_at_ms = Some(now_ms());
            write_order(&tx, &order)?;
        }
        audit(
            &tx,
            "webhook",
            if paid {
                "commerce.payment.paid"
            } else {
                "commerce.payment.failed"
            },
            &payment.id,
            "{}",
        )?;
        tx.commit()?;
        Ok((payment, false))
    }
}
