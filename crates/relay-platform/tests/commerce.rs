mod common;
use common::*;
use relay_platform::{
    api::{self, AppState},
    commerce::{CouponInput, CouponKind, LedgerKind, OrderStatus, PaymentStatus, PlanInput},
    model::now_ms,
    store::{Rejection, Store},
};
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

fn rejection(error: anyhow::Error) -> u16 {
    error.downcast_ref::<Rejection>().unwrap().status
}
fn plan_input(price_cents: i64) -> PlanInput {
    PlanInput {
        name: "Monthly".into(),
        description: "30 days".into(),
        price_cents,
        duration_days: 30,
        traffic_bytes: Some(100 * 1024 * 1024 * 1024),
        enabled: true,
    }
}

#[test]
fn wallet_orders_and_refunds_are_idempotent_and_balanced() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let user = store
        .create_user(
            &admin,
            "default",
            "buyer",
            PASSWORD,
            relay_platform::store::Role::Viewer,
        )
        .unwrap();
    let (_, buyer) = store.login("buyer", PASSWORD).unwrap();
    let plan = store
        .create_commerce_plan(&admin, plan_input(5_000))
        .unwrap();
    assert_eq!(store.commerce_plans(&buyer).unwrap().len(), 1);
    let disabled = store
        .create_commerce_plan(
            &admin,
            PlanInput {
                enabled: false,
                name: "Hidden".into(),
                ..plan_input(1_000)
            },
        )
        .unwrap();
    assert!(
        !store
            .commerce_plans(&buyer)
            .unwrap()
            .iter()
            .any(|p| p.id == disabled.id)
    );
    assert_eq!(
        rejection(
            store
                .create_commerce_plan(&buyer, plan_input(1))
                .unwrap_err()
        ),
        403
    );

    let wallet = store
        .adjust_wallet(&admin, &user.id, 10_000, "topup-1", "bank transfer")
        .unwrap();
    assert_eq!(wallet.balance_cents, 10_000);
    assert_eq!(
        rejection(
            store
                .adjust_wallet(&admin, &user.id, 1, "topup-1", "duplicate")
                .unwrap_err()
        ),
        409
    );
    assert_eq!(
        rejection(
            store
                .adjust_wallet(&admin, &user.id, -20_000, "withdraw-1", "too much")
                .unwrap_err()
        ),
        409
    );

    let order = store.create_order(&buyer, &plan.id).unwrap();
    assert_eq!(order.status, OrderStatus::Pending);
    let paid = store.pay_order(&buyer, &order.id).unwrap();
    assert_eq!(paid.status, OrderStatus::Paid);
    assert_eq!(paid.amount_cents, 5_000);
    assert_eq!(
        store.wallet(&buyer, &user.id).unwrap().wallet.balance_cents,
        5_000
    );
    assert_eq!(
        rejection(store.pay_order(&buyer, &order.id).unwrap_err()),
        409
    );
    let view = store.wallet(&buyer, &user.id).unwrap();
    assert!(
        view.entries
            .iter()
            .any(|entry| entry.kind == LedgerKind::Purchase && entry.delta_cents == -5_000)
    );
    assert_eq!(
        rejection(store.refund_order(&buyer, &order.id).unwrap_err()),
        403
    );
    let refunded = store.refund_order(&admin, &order.id).unwrap();
    assert_eq!(refunded.status, OrderStatus::Refunded);
    assert_eq!(
        store.wallet(&admin, &user.id).unwrap().wallet.balance_cents,
        10_000
    );
    assert_eq!(
        rejection(store.refund_order(&admin, &order.id).unwrap_err()),
        409
    );
    let view = store.wallet(&buyer, &user.id).unwrap();
    assert_eq!(view.wallet.balance_cents, 10_000);
    assert!(
        view.entries
            .iter()
            .any(|entry| entry.kind == LedgerKind::Refund && entry.delta_cents == 5_000)
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn external_payment_webhook_is_signed_idempotent_and_not_wallet_refundable() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let user = store
        .create_user(
            &admin,
            "default",
            "buyer",
            PASSWORD,
            relay_platform::store::Role::Viewer,
        )
        .unwrap();
    let (_, buyer) = store.login("buyer", PASSWORD).unwrap();
    let secret = "test-webhook-secret-32-bytes-long";
    store.set_commerce_webhook(&admin, secret, true).unwrap();
    let plan = store
        .create_commerce_plan(&admin, plan_input(5_000))
        .unwrap();
    let order = store.create_order(&buyer, &plan.id).unwrap();
    let payment = store.create_payment(&buyer, &order.id).unwrap();
    assert_eq!(payment.status, PaymentStatus::Pending);
    let (address, stop) = serve(store.clone()).await;
    let origin = format!("http://{address}");
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let body = json!({
        "payment_id": payment.id,
        "status": "paid",
        "external_id": "gateway-123",
        "amount_cents": 5_000
    })
    .to_string();
    let sign = |body: &str| {
        let signature = ring::hmac::sign(
            &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes()),
            body.as_bytes(),
        );
        signature
            .as_ref()
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect::<String>()
    };
    let wrong = client
        .post(format!("{origin}/api/v1/commerce/payments/callback"))
        .header("x-relay-signature", "00".repeat(32))
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(wrong.status(), 401);
    let paid = client
        .post(format!("{origin}/api/v1/commerce/payments/callback"))
        .header("x-relay-signature", sign(&body))
        .body(body.clone())
        .send()
        .await
        .unwrap();
    assert_eq!(paid.status(), 200);
    let response: Value = paid.json().await.unwrap();
    assert_eq!(response["duplicate"], false);
    assert_eq!(response["payment"]["status"], "paid");
    let duplicate = client
        .post(format!("{origin}/api/v1/commerce/payments/callback"))
        .header("x-relay-signature", sign(&body))
        .body(body)
        .send()
        .await
        .unwrap();
    assert_eq!(duplicate.status(), 200);
    let response: Value = duplicate.json().await.unwrap();
    assert_eq!(response["duplicate"], true);
    let admin_session = login(&client, &origin, "admin").await;
    let orders: Value = client
        .get(format!("{origin}/api/v1/commerce/orders"))
        .bearer_auth(&admin_session)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(orders[0]["status"], "paid");
    assert_eq!(orders[0]["channel"], "external");
    assert_eq!(
        client
            .post(format!(
                "{origin}/api/v1/commerce/orders/{}/refund",
                order.id
            ))
            .bearer_auth(&admin_session)
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    let wallet = store.wallet(&buyer, &user.id).unwrap();
    assert_eq!(
        wallet.wallet.balance_cents, 0,
        "external payment must not credit the wallet"
    );
    assert_eq!(orders[0]["amount_cents"], 5_000);
    stop.cancel();
}

#[test]
fn coupons_discount_orders_and_enforce_limits() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let user = store
        .create_user(
            &admin,
            "default",
            "buyer",
            PASSWORD,
            relay_platform::store::Role::Viewer,
        )
        .unwrap();
    let (_, buyer) = store.login("buyer", PASSWORD).unwrap();
    let plan = store
        .create_commerce_plan(&admin, plan_input(5_000))
        .unwrap();
    let coupon = store
        .create_coupon(
            &admin,
            CouponInput {
                code: "save10".into(),
                kind: CouponKind::Percent,
                value: 10,
                min_amount_cents: 1_000,
                starts_at_ms: now_ms() - 1_000,
                ends_at_ms: None,
                max_redemptions: Some(1),
                enabled: true,
            },
        )
        .unwrap();
    assert_eq!(coupon.code, "SAVE10");
    assert_eq!(rejection(store.commerce_coupons(&buyer).unwrap_err()), 403);
    let order = store
        .create_order_with_coupon(&buyer, &plan.id, Some("save10"))
        .unwrap();
    assert_eq!(order.subtotal_cents, 5_000);
    assert_eq!(order.discount_cents, 500);
    assert_eq!(order.amount_cents, 4_500);
    assert_eq!(order.coupon_code.as_deref(), Some("SAVE10"));
    assert_eq!(store.commerce_coupons(&admin).unwrap()[0].redeemed, 1);
    assert_eq!(
        rejection(
            store
                .create_order_with_coupon(&buyer, &plan.id, Some("SAVE10"))
                .unwrap_err()
        ),
        409
    );
    store
        .update_coupon(
            &admin,
            &coupon.id,
            CouponInput {
                code: "SAVE10".into(),
                kind: CouponKind::Fixed,
                value: 1_000,
                min_amount_cents: 1_000,
                starts_at_ms: now_ms() - 1_000,
                ends_at_ms: None,
                max_redemptions: None,
                enabled: false,
            },
        )
        .unwrap();
    assert_eq!(
        rejection(
            store
                .create_order_with_coupon(&buyer, &plan.id, Some("SAVE10"))
                .unwrap_err()
        ),
        409
    );
    let wallet = store
        .adjust_wallet(&admin, &user.id, 4_500, "coupon-topup", "test")
        .unwrap();
    assert_eq!(wallet.balance_cents, 4_500);
    store.pay_order(&buyer, &order.id).unwrap();
    assert_eq!(
        store.wallet(&buyer, &user.id).unwrap().wallet.balance_cents,
        0
    );
    store.refund_order(&admin, &order.id).unwrap();
    assert_eq!(
        store.wallet(&buyer, &user.id).unwrap().wallet.balance_cents,
        4_500
    );
}

async fn serve(store: Store) -> (SocketAddr, CancellationToken) {
    let stop = CancellationToken::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let app = api::router(AppState::new(store).with_shutdown(stop.clone()));
    let shutdown = stop.clone();
    tokio::spawn(async move {
        axum::serve(
            listener,
            app.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await
        .unwrap();
    });
    (address, stop)
}
async fn login(client: &reqwest::Client, origin: &str, username: &str) -> String {
    let body: Value = client
        .post(format!("{origin}/api/v1/auth/login"))
        .json(&json!({"username": username, "password": PASSWORD}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    body["token"].as_str().unwrap().into()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn commerce_http_routes_move_money_and_block_non_admins() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    store
        .create_user(
            &admin,
            "default",
            "buyer",
            PASSWORD,
            relay_platform::store::Role::Viewer,
        )
        .unwrap();
    let (address, stop) = serve(store).await;
    let origin = format!("http://{address}");
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let admin_session = login(&client, &origin, "admin").await;
    let buyer_session = login(&client, &origin, "buyer").await;
    let plan: Value = client
        .post(format!("{origin}/api/v1/commerce/plans"))
        .bearer_auth(&admin_session)
        .json(&json!({"name":"Monthly","description":"30 days","price_cents":5000,"duration_days":30}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let plan_id = plan["id"].as_str().unwrap();
    assert_eq!(
        client
            .post(format!("{origin}/api/v1/commerce/coupons"))
            .bearer_auth(&admin_session)
            .json(&json!({"code":"HTTP10","kind":"percent","value":10,"max_redemptions":5}))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client
            .post(format!("{origin}/api/v1/commerce/coupons"))
            .bearer_auth(&buyer_session)
            .json(&json!({"code":"NO","kind":"fixed","value":1}))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .post(format!("{origin}/api/v1/commerce/plans"))
            .bearer_auth(&buyer_session)
            .json(&json!({"name":"No","price_cents":1,"duration_days":1}))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let buyer: Value = client
        .get(format!("{origin}/api/v1/users"))
        .bearer_auth(&admin_session)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let buyer_id = buyer
        .as_array()
        .unwrap()
        .iter()
        .find(|user| user["username"] == "buyer")
        .unwrap()["id"]
        .as_str()
        .unwrap();
    assert_eq!(
        client
            .post(format!(
                "{origin}/api/v1/commerce/wallets/{buyer_id}/adjust"
            ))
            .bearer_auth(&admin_session)
            .json(&json!({"delta_cents":10000,"reference":"bank-1","description":"deposit"}))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let order: Value = client
        .post(format!("{origin}/api/v1/commerce/orders"))
        .bearer_auth(&buyer_session)
        .json(&json!({"plan_id":plan_id,"coupon_code":"http10"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(order["subtotal_cents"], 5000);
    assert_eq!(order["discount_cents"], 500);
    assert_eq!(order["amount_cents"], 4500);
    let order_id = order["id"].as_str().unwrap();
    assert_eq!(
        client
            .post(format!("{origin}/api/v1/commerce/orders/{order_id}/pay"))
            .bearer_auth(&buyer_session)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let wallet: Value = client
        .get(format!("{origin}/api/v1/commerce/wallet"))
        .bearer_auth(&buyer_session)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(wallet["wallet"]["balance_cents"], 5500);
    assert_eq!(
        client
            .post(format!("{origin}/api/v1/commerce/orders/{order_id}/refund"))
            .bearer_auth(&admin_session)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let wallet: Value = client
        .get(format!("{origin}/api/v1/commerce/wallet"))
        .bearer_auth(&buyer_session)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(wallet["wallet"]["balance_cents"], 10000);
    stop.cancel();
    tokio::time::sleep(Duration::from_millis(50)).await;
}
