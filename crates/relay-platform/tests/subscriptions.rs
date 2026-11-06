mod common;
use common::*;
use relay_platform::{
    api::{self, AppState},
    model::*,
    shadowsocks,
    store::{Actor, Rejection, Role, Store},
    subscription,
};
use serde_json::{Value, json};
use std::{
    net::{IpAddr, SocketAddr},
    time::Duration,
};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

fn ss_rule() -> Rule {
    let mut rule = rule("127.0.0.1:9".parse().unwrap(), Protocol::Both);
    rule.id = "ss".into();
    rule.owner_id = "admin".into();
    rule.name = "Tokyo".into();
    rule.inbound_shadowsocks = Some(shadowsocks::ServerConfig {
        method: shadowsocks::Method::Blake3Aes256Gcm,
        password: "AAECAwQFBgcICQoLDA0ODxAREhMUFRYXGBkaGxwdHh8=".into(),
        allow_private_destinations: false,
        udp_over_tcp: false,
    });
    rule.targets.clear();
    rule.advertise = Some("edge.example.com:9000".into());
    rule
}
fn rejection(error: anyhow::Error) -> u16 {
    error.downcast_ref::<Rejection>().unwrap().status
}
/// A client address outside every test allowlist.
fn anywhere() -> IpAddr {
    "198.51.100.1".parse().unwrap()
}
fn settings(name: &str, format: subscription::Format) -> subscription::Settings {
    subscription::Settings::new(name, format, subscription::Template::default())
}

#[tokio::test]
async fn subscriptions_are_scoped_rotated_and_rendered_without_a_session() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let (node, enrollment) = store.create_node(&admin, "default", "edge").unwrap();
    store
        .enroll(&node.id, &enrollment, &relay_platform::store::secret())
        .unwrap();
    store
        .set_config(&admin, &node.id, 0, vec![ss_rule()])
        .unwrap();
    let other_tenant = store.create_tenant(&admin, "other").unwrap();
    let other = store
        .create_user(
            &admin,
            &other_tenant,
            "outsider",
            PASSWORD,
            relay_platform::store::Role::Viewer,
        )
        .unwrap();

    // A mistake in the template is the caller's to fix: a 400 that names it.
    let invalid: subscription::Template = serde_json::from_value(json!({"upstreams": [
        {"name": "Home", "type": "socks5", "server": "home.example.net", "port": 0}
    ]}))
    .unwrap();
    let error = store
        .create_subscription(
            &admin,
            None,
            subscription::Settings::new("phone", subscription::Format::Clash, invalid),
            30,
        )
        .unwrap_err();
    let error = error.downcast_ref::<Rejection>().unwrap();
    assert_eq!(error.status, 400);
    assert!(
        error.message.contains("Home") && error.message.contains("port"),
        "{}",
        error.message
    );

    let (view, token) = store
        .create_subscription(
            &admin,
            None,
            settings("phone", subscription::Format::V2ray),
            30,
        )
        .unwrap();
    assert!(token.starts_with(subscription::TOKEN_PREFIX));
    assert_eq!(store.subscriptions(&admin).unwrap().len(), 1);
    assert!(store.subscriptions(&other).unwrap().is_empty());
    assert_eq!(
        rejection(store.render_subscription(&other, &view.id).unwrap_err()),
        403
    );
    // A tenant administrator does not gain control over a system
    // administrator's private subscription.
    let tenant_admin = store
        .create_user(
            &admin,
            "default",
            "tenant-admin",
            PASSWORD,
            relay_platform::store::Role::TenantAdmin,
        )
        .unwrap();
    assert!(store.subscriptions(&tenant_admin).unwrap().is_empty());
    assert_eq!(
        rejection(
            store
                .render_subscription(&tenant_admin, &view.id)
                .unwrap_err()
        ),
        403
    );
    assert_eq!(
        rejection(
            store
                .rotate_subscription(&tenant_admin, &view.id, 0)
                .unwrap_err()
        ),
        403
    );

    let preview = store.render_subscription(&admin, &view.id).unwrap();
    assert_eq!(preview.entries.len(), 1);
    assert_eq!(preview.entries[0].host, "edge.example.com");
    assert_eq!(preview.entries[0].port, 9000);
    let public = store
        .render_public_subscription(&token, anywhere())
        .unwrap();
    let decoded = base64::Engine::decode(
        &base64::engine::general_purpose::STANDARD,
        public.content.as_bytes(),
    )
    .unwrap();
    let decoded = String::from_utf8(decoded).unwrap();
    assert!(
        decoded.starts_with("ss://2022-blake3-aes-256-gcm:"),
        "{decoded}"
    );
    assert!(decoded.contains("@edge.example.com:9000#edge%20%C2%B7%20Tokyo"));

    let (rotated, fresh) = store.rotate_subscription(&admin, &view.id, 0).unwrap();
    assert_ne!(fresh, token);
    assert_eq!(rotated.id, view.id);
    assert_eq!(rotated.previous_token_expires_at_ms, None);
    assert_eq!(
        rejection(
            store
                .render_public_subscription(&token, anywhere())
                .unwrap_err()
        ),
        401
    );
    assert!(store.render_public_subscription(&fresh, anywhere()).is_ok());
    store.delete_subscription(&admin, &view.id).unwrap();
    assert!(store.subscriptions(&admin).unwrap().is_empty());
    assert_eq!(
        rejection(
            store
                .render_public_subscription(&fresh, anywhere())
                .unwrap_err()
        ),
        401
    );
}

#[tokio::test]
async fn subscription_records_and_hashed_tokens_survive_a_reopen() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("controller.db");
    let token = {
        let store = Store::open(&path).unwrap();
        store.set_kind("controller").unwrap();
        let admin = store.bootstrap(PASSWORD).unwrap();
        let (node, enrollment) = store.create_node(&admin, "default", "edge").unwrap();
        store
            .enroll(&node.id, &enrollment, &relay_platform::store::secret())
            .unwrap();
        store
            .set_config(&admin, &node.id, 0, vec![ss_rule()])
            .unwrap();
        let (_, token) = store
            .create_subscription(
                &admin,
                None,
                settings("persisted", subscription::Format::Shadowrocket),
                7,
            )
            .unwrap();
        token
    };
    let store = Store::open(&path).unwrap();
    let (_, admin) = store.login("admin", PASSWORD).unwrap();
    assert_eq!(store.subscriptions(&admin).unwrap().len(), 1);
    assert!(
        store
            .render_public_subscription(&token, anywhere())
            .unwrap()
            .content
            .contains("ss://")
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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn public_subscription_http_rotation_and_rate_limit_are_real() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let (node, enrollment) = store.create_node(&admin, "default", "edge").unwrap();
    store
        .enroll(&node.id, &enrollment, &relay_platform::store::secret())
        .unwrap();
    store
        .set_config(&admin, &node.id, 0, vec![ss_rule()])
        .unwrap();
    let (address, stop) = serve(store).await;
    let origin = format!("http://{address}");
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let login: Value = client
        .post(format!("{origin}/api/v1/auth/login"))
        .json(&json!({"username": "admin", "password": PASSWORD}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let session = login["token"].as_str().unwrap().to_owned();
    let token_response: Value = client
        .post(format!("{origin}/api/v1/api-tokens"))
        .bearer_auth(&session)
        .json(&json!({"name": "sub-read", "scopes": ["read"], "expires_in_days": 1}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let read_token = token_response["token"].as_str().unwrap().to_owned();
    assert_eq!(
        client
            .get(format!("{origin}/api/v1/subscriptions"))
            .bearer_auth(&read_token)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client
            .post(format!("{origin}/api/v1/subscriptions"))
            .bearer_auth(&read_token)
            .json(&json!({"name": "nope", "format": "v2ray"}))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let created: Value = client
        .post(format!("{origin}/api/v1/subscriptions"))
        .bearer_auth(&session)
        .json(&json!({
            "name": "phone",
            "format": "clash",
            "template": {"name_prefix": "Relay "},
            "expires_in_days": 30
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = created["token"].as_str().unwrap().to_owned();
    let id = created["subscription"]["id"].as_str().unwrap().to_owned();
    let response = client
        .get(format!("{origin}/sub/{token}"))
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["content-type"],
        "text/yaml; charset=utf-8"
    );
    let body = response.text().await.unwrap();
    let yaml: serde_yaml::Value = serde_yaml::from_str(&body).unwrap();
    assert_eq!(yaml["proxies"][0]["server"], "edge.example.com");

    let preview: Value = client
        .get(format!("{origin}/api/v1/subscriptions/{id}/preview"))
        .bearer_auth(&session)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(preview["entries"][0]["name"], "Relay edge · Tokyo");

    // Surge updates a profile from the URL in its first line: the address the
    // client used, as the HTTPS reverse proxy forwards it.
    let surge: Value = client
        .post(format!("{origin}/api/v1/subscriptions"))
        .bearer_auth(&session)
        .json(&json!({"name": "mac", "format": "surge"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let surge_token = surge["token"].as_str().unwrap();
    let fetch = |host: &str, proto: Option<&str>| {
        let mut request = client
            .get(format!("{origin}/sub/{surge_token}"))
            .header("host", host);
        if let Some(proto) = proto {
            request = request.header("x-forwarded-proto", proto);
        }
        async move { request.send().await.unwrap().text().await.unwrap() }
    };
    let profile = fetch("panel.example.com", Some("https")).await;
    assert!(
        profile.starts_with(&format!(
            "#!MANAGED-CONFIG https://panel.example.com/sub/{surge_token} interval=86400 strict=false\n# Relay subscription\n[General]\n"
        )),
        "{profile}"
    );
    assert!(profile.ends_with("FINAL,Relay,dns-failed\n"), "{profile}");
    assert!(
        fetch(&address.to_string(), None)
            .await
            .starts_with(&format!(
                "#!MANAGED-CONFIG http://{address}/sub/{surge_token} "
            ))
    );
    assert!(
        fetch("panel.example.com\"x", Some("https"))
            .await
            .starts_with("# Relay subscription\n"),
        "a host that cannot be written into the line leaves the profile unmanaged"
    );

    let rotated: Value = client
        .post(format!("{origin}/api/v1/subscriptions/{id}/rotate"))
        .bearer_auth(&session)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let fresh = rotated["token"].as_str().unwrap().to_owned();
    assert_ne!(fresh, token);
    assert_eq!(
        client
            .get(format!("{origin}/sub/{token}"))
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    assert_eq!(
        client
            .get(format!("{origin}/sub/{fresh}"))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );

    // The per-token bucket allows 60 requests in a minute and then 429.
    let mut limited = false;
    for _ in 0..62 {
        let status = client
            .get(format!("{origin}/sub/{fresh}"))
            .send()
            .await
            .unwrap()
            .status();
        if status == 429 {
            limited = true;
            break;
        }
    }
    assert!(limited, "subscription polling was never rate limited");
    stop.cancel();
    tokio::time::sleep(Duration::from_millis(50)).await;
}

const GIB: u64 = 1 << 30;

fn controller() -> (tempfile::TempDir, Store, Actor) {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    (temp, store, admin)
}
fn publish(store: &Store, admin: &Actor, rules: Vec<Rule>) -> String {
    let (node, enrollment) = store.create_node(admin, "default", "edge").unwrap();
    store
        .enroll(&node.id, &enrollment, &relay_platform::store::secret())
        .unwrap();
    store.set_config(admin, &node.id, 0, rules).unwrap();
    node.id
}
fn refusal(error: anyhow::Error) -> (u16, String) {
    let rejection = error.downcast_ref::<Rejection>().unwrap();
    (rejection.status, rejection.message.clone())
}
fn v2ray_lines(content: &str) -> String {
    String::from_utf8(
        base64::Engine::decode(&base64::engine::general_purpose::STANDARD, content).unwrap(),
    )
    .unwrap()
}

#[test]
fn editing_keeps_the_token_and_changes_what_clients_receive() {
    use subscription::{Format, Settings, Template};
    let (_temp, store, admin) = controller();
    publish(&store, &admin, vec![ss_rule()]);
    let carol = store
        .create_user(&admin, "default", "carol", PASSWORD, Role::Viewer)
        .unwrap();
    let tenant_admin = store
        .create_user(
            &admin,
            "default",
            "tenant-admin",
            PASSWORD,
            Role::TenantAdmin,
        )
        .unwrap();
    let other_tenant = store.create_tenant(&admin, "other").unwrap();
    let outsider = store
        .create_user(
            &admin,
            &other_tenant,
            "outsider",
            PASSWORD,
            Role::TenantAdmin,
        )
        .unwrap();

    let (view, token) = store
        .create_subscription(&admin, None, settings("phone", Format::V2ray), 30)
        .unwrap();
    let before = store
        .render_public_subscription(&token, anywhere())
        .unwrap();
    assert!(v2ray_lines(&before.content).contains("#edge%20%C2%B7%20Tokyo"));

    let edited = store
        .update_subscription(
            &admin,
            &view.id,
            Settings::new(
                "phone (edited)",
                Format::Clash,
                Template {
                    name_prefix: "Edited ".into(),
                    ..Default::default()
                },
            ),
            None,
        )
        .unwrap();
    assert_eq!(edited.id, view.id);
    assert_eq!(edited.name, "phone (edited)");
    assert_eq!(edited.created_at_ms, view.created_at_ms);
    assert_eq!(
        edited.expires_at_ms, view.expires_at_ms,
        "None keeps the expiry"
    );
    // The same token now serves the edited settings.
    let after = store
        .render_public_subscription(&token, anywhere())
        .unwrap();
    assert_eq!(after.content_type, "text/yaml; charset=utf-8");
    let yaml: serde_yaml::Value = serde_yaml::from_str(&after.content).unwrap();
    assert_eq!(yaml["proxies"][0]["name"], "Edited edge · Tokyo");
    assert_eq!(store.subscriptions(&admin).unwrap().len(), 1);

    let renewed = store
        .update_subscription(&admin, &view.id, settings("phone", Format::Clash), Some(2))
        .unwrap();
    let expiry = renewed.expires_at_ms.unwrap();
    assert!(expiry > now_ms() + 2 * 86_400_000 - 60_000 && expiry <= now_ms() + 2 * 86_400_000);

    // Invalid settings are the caller's to fix, and change nothing.
    let invalid: subscription::Template = serde_json::from_value(json!({"upstreams": [
        {"name": "Home", "type": "socks5", "server": "home.example.net", "port": 0}
    ]}))
    .unwrap();
    let too_many = Settings {
        allow_sources: (0..=subscription::MAX_ALLOW_SOURCES)
            .map(|n| format!("10.0.{n}.0/24").parse().unwrap())
            .collect(),
        ..settings("x", Format::Clash)
    };
    for (bad, days) in [
        (settings(" padded", Format::Clash), None),
        (settings("x", Format::Clash), Some(0)),
        (Settings::new("x", Format::Clash, invalid), None),
        (too_many, None),
    ] {
        assert_eq!(
            rejection(
                store
                    .update_subscription(&admin, &view.id, bad, days)
                    .unwrap_err()
            ),
            400
        );
    }
    assert_eq!(store.subscription(&admin, &view.id).unwrap().name, "phone");

    // The rules that govern creating a link for its owner govern editing it.
    for actor in [&tenant_admin, &carol, &outsider] {
        assert_eq!(
            rejection(
                store
                    .update_subscription(actor, &view.id, settings("taken", Format::V2ray), None)
                    .unwrap_err()
            ),
            403
        );
    }
    let (carols, _) = store
        .create_subscription(
            &admin,
            Some(&carol.id),
            settings("carol", Format::V2ray),
            30,
        )
        .unwrap();
    assert_eq!(
        rejection(
            store
                .update_subscription(&carol, &carols.id, settings("mine", Format::V2ray), None)
                .unwrap_err()
        ),
        403,
        "read-only accounts cannot create links, so they cannot edit them"
    );
    let managed = store
        .update_subscription(
            &tenant_admin,
            &carols.id,
            settings("carol 2", Format::V2ray),
            None,
        )
        .unwrap();
    assert_eq!(managed.owner_id, carol.id);
    assert_eq!(store.subscription(&admin, &view.id).unwrap().name, "phone");
}

#[test]
fn fetches_from_other_sources_look_like_an_unknown_token() {
    use subscription::{Format, Settings};
    let (_temp, store, admin) = controller();
    publish(&store, &admin, vec![ss_rule()]);
    let (view, token) = store
        .create_subscription(
            &admin,
            None,
            Settings {
                allow_sources: vec![
                    "203.0.113.0/24".parse().unwrap(),
                    "2001:db8::/32".parse().unwrap(),
                ],
                ..settings("office", Format::V2ray)
            },
            30,
        )
        .unwrap();
    assert_eq!(view.allow_sources.len(), 2);
    let unknown = format!("{}{}", subscription::TOKEN_PREFIX, "0".repeat(64));
    let expected = refusal(
        store
            .render_public_subscription(&unknown, anywhere())
            .unwrap_err(),
    );
    assert_eq!(expected.0, 401);
    for source in [
        "198.51.100.1",
        "203.0.114.9",
        "2001:db9::1",
        "::ffff:198.51.100.1",
    ] {
        assert_eq!(
            refusal(
                store
                    .render_public_subscription(&token, source.parse().unwrap())
                    .unwrap_err()
            ),
            expected,
            "{source}"
        );
    }
    let used = store.subscription(&admin, &view.id).unwrap();
    assert_eq!(
        (used.uses, used.last_used_ms),
        (0, None),
        "a refused fetch is not a use"
    );
    for source in ["203.0.113.9", "::ffff:203.0.113.9", "2001:db8::7"] {
        assert!(
            store
                .render_public_subscription(&token, source.parse().unwrap())
                .is_ok(),
            "{source}"
        );
    }
    assert_eq!(store.subscription(&admin, &view.id).unwrap().uses, 1);
    // An edit without a list lets every source fetch again.
    store
        .update_subscription(&admin, &view.id, settings("office", Format::V2ray), None)
        .unwrap();
    assert!(store.render_public_subscription(&token, anywhere()).is_ok());
}

#[test]
fn rotation_grace_keeps_only_the_replaced_token_until_it_ends() {
    let (temp, store, admin) = controller();
    publish(&store, &admin, vec![ss_rule()]);
    let (view, first) = store
        .create_subscription(
            &admin,
            None,
            settings("phone", subscription::Format::V2ray),
            30,
        )
        .unwrap();
    let works = |token: &str| store.render_public_subscription(token, anywhere()).is_ok();
    assert_eq!(
        rejection(
            store
                .rotate_subscription(
                    &admin,
                    &view.id,
                    subscription::MAX_ROTATION_GRACE_MINUTES + 1
                )
                .unwrap_err()
        ),
        400
    );
    assert!(works(&first), "a refused rotation changes nothing");

    let before = now_ms();
    let (rotated, second) = store.rotate_subscription(&admin, &view.id, 30).unwrap();
    let until = rotated.previous_token_expires_at_ms.unwrap();
    assert!(until >= before + 30 * 60_000 && until <= now_ms() + 30 * 60_000);
    assert_eq!(
        store
            .subscription(&admin, &view.id)
            .unwrap()
            .previous_token_expires_at_ms,
        Some(until)
    );
    assert!(
        works(&first),
        "the replaced token works inside the grace period"
    );
    assert!(works(&second));

    // Only the token a rotation replaces is kept.
    let (_, third) = store.rotate_subscription(&admin, &view.id, 30).unwrap();
    assert!(!works(&first));
    assert!(works(&second) && works(&third));

    // After the grace period the replaced token is refused and forgotten.
    let raw = rusqlite::Connection::open(temp.path().join("controller.db")).unwrap();
    let key = format!("subscription:{}", view.id);
    raw.execute(
        "UPDATE metadata SET value=json_set(value,'$.previous_token_expires_at_ms',?1) WHERE key=?2",
        rusqlite::params![now_ms() - 1, key],
    )
    .unwrap();
    assert_eq!(
        refusal(
            store
                .render_public_subscription(&second, anywhere())
                .unwrap_err()
        ),
        refusal(
            store
                .render_public_subscription(
                    &format!("{}{}", subscription::TOKEN_PREFIX, "0".repeat(64)),
                    anywhere()
                )
                .unwrap_err()
        )
    );
    assert!(works(&third));
    let stored: String = raw
        .query_row("SELECT value FROM metadata WHERE key=?1", [&key], |r| {
            r.get(0)
        })
        .unwrap();
    assert!(!stored.contains("previous_token"), "{stored}");
    let index = |raw: &rusqlite::Connection| -> u64 {
        raw.query_row(
            "SELECT COUNT(*) FROM metadata WHERE key GLOB 'subscription_token:*'",
            [],
            |r| r.get(0),
        )
        .unwrap()
    };
    assert_eq!(index(&raw), 1);

    // Zero keeps the original behaviour: the old token stops at once.
    let (rotated, fourth) = store.rotate_subscription(&admin, &view.id, 0).unwrap();
    assert_eq!(rotated.previous_token_expires_at_ms, None);
    assert!(!works(&third) && works(&fourth));
    // Deleting removes a token in its grace period too; only hashes were stored.
    let (_, fifth) = store.rotate_subscription(&admin, &view.id, 60).unwrap();
    let dump: Vec<String> = raw
        .prepare("SELECT key || value FROM metadata")
        .unwrap()
        .query_map([], |r| r.get(0))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    for token in [&first, &second, &third, &fourth, &fifth] {
        assert!(!dump.iter().any(|row| row.contains(token.as_str())));
    }
    assert_eq!(index(&raw), 2);
    store.delete_subscription(&admin, &view.id).unwrap();
    assert!(!works(&fourth) && !works(&fifth));
    assert_eq!(index(&raw), 0);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn usage_header_reports_the_owners_budget_and_plan() {
    use relay_platform::budget::{BudgetScope, NewBudget};
    let (temp, store, admin) = controller();
    let carol = store
        .create_user(&admin, "default", "carol", PASSWORD, Role::Viewer)
        .unwrap();
    let dave = store
        .create_user(&admin, "default", "dave", PASSWORD, Role::Viewer)
        .unwrap();
    // The administrator has a paid plan: 100 GiB for 30 days.
    store
        .set_feature(&admin, "plan-entitlements", true)
        .unwrap();
    let plan = store
        .create_commerce_plan(
            &admin,
            relay_platform::commerce::PlanInput {
                name: "Monthly".into(),
                description: "30 days".into(),
                price_cents: 1_000,
                duration_days: 30,
                traffic_bytes: Some(100 * GIB),
                enabled: true,
            },
        )
        .unwrap();
    store
        .adjust_wallet(&admin, &admin.id, 10_000, "topup-admin", "test")
        .unwrap();
    let order = store.create_order(&admin, &plan.id).unwrap();
    store.pay_order(&admin, &order.id).unwrap();
    let entitlement = store.entitlement(&admin, &admin.id).unwrap().unwrap();
    let budget = entitlement.budget.unwrap();
    assert_eq!(budget.limit_bytes, 100 * GIB);
    // Carol has a user budget without a plan; Dave has neither.
    store
        .create_budget(
            &admin,
            NewBudget {
                scope: BudgetScope::User,
                scope_id: carol.id.clone(),
                name: "carol".into(),
                limit_bytes: 1 << 20,
                quantum_bytes: 4096,
            },
        )
        .unwrap();
    let owned = |owner: &str, id: &str, port: u16| {
        let mut rule = ss_rule();
        rule.id = id.into();
        rule.owner_id = owner.into();
        rule.advertise = Some(format!("edge.example.com:{port}"));
        rule
    };
    publish(
        &store,
        &admin,
        vec![
            ss_rule(),
            owned(&carol.id, "carol-ss", 9001),
            owned(&dave.id, "dave-ss", 9002),
        ],
    );
    // 5 GiB used, plus a 4 MiB reservation not used yet: only use counts.
    rusqlite::Connection::open(temp.path().join("controller.db"))
        .unwrap()
        .execute(
            "UPDATE budgets SET committed_bytes=?1,consumed_bytes=?2 WHERE id=?3",
            rusqlite::params![5 * GIB + (4 << 20), 5 * GIB, budget.id],
        )
        .unwrap();
    let link = |owner: Option<&str>| {
        // A 7-day link: its own expiry is not the plan's.
        store
            .create_subscription(
                &admin,
                owner,
                settings("link", subscription::Format::V2ray),
                7,
            )
            .unwrap()
            .1
    };
    let (mine, carols, daves) = (link(None), link(Some(&carol.id)), link(Some(&dave.id)));
    let header = |token: &str| {
        store
            .render_public_subscription(token, anywhere())
            .unwrap()
            .usage
            .header()
    };
    let expected = format!(
        "download={}; total={}; expire={}",
        5 * GIB,
        100 * GIB,
        entitlement.entitlement.expires_at_ms / 1000
    );
    assert_eq!(header(&mine).as_deref(), Some(expected.as_str()));
    assert_eq!(
        header(&carols).as_deref(),
        Some("download=0; total=1048576")
    );
    assert_eq!(header(&daves), None);

    let (address, stop) = serve(store.clone()).await;
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let fetch = |token: String| {
        let request = client.get(format!("http://{address}/sub/{token}"));
        async move { request.send().await.unwrap() }
    };
    let response = fetch(mine).await;
    assert_eq!(response.status(), 200);
    assert_eq!(
        response.headers()["subscription-userinfo"],
        expected.as_str()
    );
    let response = fetch(daves).await;
    assert_eq!(response.status(), 200);
    assert!(response.headers().get("subscription-userinfo").is_none());
    stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn edits_source_lists_and_rotation_grace_over_http() {
    let (_temp, store, admin) = controller();
    publish(&store, &admin, vec![ss_rule()]);
    drop(admin);
    let (address, stop) = serve(store).await;
    let origin = format!("http://{address}");
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let login: Value = client
        .post(format!("{origin}/api/v1/auth/login"))
        .json(&json!({"username": "admin", "password": PASSWORD}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let session = login["token"].as_str().unwrap().to_owned();
    let read_only: Value = client
        .post(format!("{origin}/api/v1/api-tokens"))
        .bearer_auth(&session)
        .json(&json!({"name": "sub-read", "scopes": ["read"], "expires_in_days": 1}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let read_only = read_only["token"].as_str().unwrap().to_owned();
    let created: Value = client
        .post(format!("{origin}/api/v1/subscriptions"))
        .bearer_auth(&session)
        .json(&json!({"name": "office", "format": "clash", "allow_sources": ["203.0.113.0/24"]}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["subscription"]["id"].as_str().unwrap().to_owned();
    assert_eq!(
        created["subscription"]["allow_sources"],
        json!(["203.0.113.0/24"])
    );
    let token = created["token"].as_str().unwrap().to_owned();
    let fetch = |token: &str, forwarded: Option<&str>| {
        let mut request = client.get(format!("{origin}/sub/{token}"));
        if let Some(forwarded) = forwarded {
            request = request.header("x-forwarded-for", forwarded);
        }
        async move {
            let response = request.send().await.unwrap();
            let status = response.status().as_u16();
            let content_type = response.headers()["content-type"].clone();
            (status, content_type, response.text().await.unwrap())
        }
    };
    // The proxy on this host appends the visitor last; earlier entries are claims.
    let unknown = format!("{}{}", subscription::TOKEN_PREFIX, "1".repeat(64));
    let refused = fetch(&unknown, Some("198.51.100.7")).await;
    assert_eq!(refused.0, 401);
    assert_eq!(fetch(&token, Some("198.51.100.7")).await, refused);
    assert_eq!(
        fetch(&token, Some("203.0.113.9, 198.51.100.7")).await,
        refused
    );
    assert_eq!(fetch(&token, None).await, refused, "loopback is not listed");
    assert_eq!(
        fetch(&token, Some("198.51.100.7, 203.0.113.9")).await.0,
        200
    );

    let edit = json!({"name": "laptop", "format": "v2ray", "template": {"name_prefix": "Edited "}});
    let status = |request: reqwest::RequestBuilder| async move {
        request.send().await.unwrap().status().as_u16()
    };
    assert_eq!(
        status(
            client
                .put(format!("{origin}/api/v1/subscriptions/{id}"))
                .bearer_auth(&read_only)
                .json(&edit)
        )
        .await,
        403
    );
    let edited: Value = client
        .put(format!("{origin}/api/v1/subscriptions/{id}"))
        .bearer_auth(&session)
        .json(&edit)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(edited["id"], id.as_str());
    assert_eq!(edited["name"], "laptop");
    assert_eq!(edited["allow_sources"], json!([]), "PUT replaces the list");
    let (code, _, body) = fetch(&token, None).await;
    assert_eq!(code, 200);
    assert!(v2ray_lines(&body).contains("#Edited%20edge"), "{body}");
    assert_eq!(
        status(
            client
                .put(format!("{origin}/api/v1/subscriptions/{id}"))
                .bearer_auth(&session)
                .json(&json!({"name": "laptop", "format": "v2ray", "token": "rsub_x"}))
        )
        .await,
        422,
        "the token is not a setting"
    );

    let rotate = |body: Option<Value>| {
        let mut request = client
            .post(format!("{origin}/api/v1/subscriptions/{id}/rotate"))
            .bearer_auth(&session);
        if let Some(body) = body {
            request = request.json(&body);
        }
        async move {
            let response = request.send().await.unwrap();
            (
                response.status().as_u16(),
                response.json::<Value>().await.unwrap(),
            )
        }
    };
    assert_eq!(rotate(Some(json!({"grace_minutes": 1441}))).await.0, 400);
    let (code, graced) = rotate(Some(json!({"grace_minutes": 5}))).await;
    assert_eq!(code, 200);
    assert!(
        graced["subscription"]["previous_token_expires_at_ms"]
            .as_i64()
            .unwrap()
            > now_ms()
    );
    let fresh = graced["token"].as_str().unwrap().to_owned();
    assert_eq!(fetch(&token, None).await.0, 200, "inside the grace period");
    assert_eq!(fetch(&fresh, None).await.0, 200);
    // Without a body a rotation ends the old links at once, as before.
    let (code, plain) = rotate(None).await;
    assert_eq!(code, 200);
    assert!(plain["subscription"]["previous_token_expires_at_ms"].is_null());
    let latest = plain["token"].as_str().unwrap();
    assert_eq!(fetch(&token, None).await.0, 401);
    assert_eq!(fetch(&fresh, None).await.0, 401);
    assert_eq!(fetch(latest, None).await.0, 200);
    stop.cancel();
    tokio::time::sleep(Duration::from_millis(50)).await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn gateway_rules_have_share_links_and_qr_codes() {
    use relay_platform::gateway::{Config, Obfuscation, Security, WireProtocol};
    let (_temp, store, admin) = controller();
    let gateway = |id: &str, protocol: WireProtocol| {
        let mut rule = rule("127.0.0.1:9".parse().unwrap(), Protocol::Tcp);
        rule.id = id.into();
        rule.name = format!("{id} rule");
        rule.targets.clear();
        rule.protocol_gateway = Some(Config {
            listen: free_address(),
            protocol,
            security: Security::Certificate {
                identity: "server".into(),
                server_name: Some("relay.example".into()),
            },
            allow_private_destinations: false,
        });
        rule
    };
    let hysteria = gateway(
        "hy2",
        WireProtocol::Hysteria2 {
            password: "client-password-12345".into(),
            obfs: Some(Obfuscation::Salamander {
                password: "obfuscation-password-1".into(),
            }),
            masquerade: None,
        },
    );
    let listen_port = hysteria.protocol_gateway.as_ref().unwrap().listen.port();
    let node = publish(
        &store,
        &admin,
        vec![
            hysteria,
            gateway(
                "anytls",
                WireProtocol::AnyTls {
                    password: "client-password-12345".into(),
                },
            ),
            ss_rule(),
        ],
    );
    let other_tenant = store.create_tenant(&admin, "other").unwrap();
    store
        .create_user(
            &admin,
            &other_tenant,
            "outsider",
            PASSWORD,
            Role::TenantAdmin,
        )
        .unwrap();
    drop(admin);
    let (address, stop) = serve(store).await;
    let origin = format!("http://{address}");
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let login = |username: &str| {
        let request = client
            .post(format!("{origin}/api/v1/auth/login"))
            .json(&json!({"username": username, "password": PASSWORD}));
        async move {
            let value: Value = request.send().await.unwrap().json().await.unwrap();
            value["token"].as_str().unwrap().to_owned()
        }
    };
    let session = login("admin").await;
    let share = |session: &str, rule: &str, query: &str| {
        let request = client
            .get(format!(
                "{origin}/api/v1/nodes/{node}/rules/{rule}/share?{query}"
            ))
            .bearer_auth(session);
        async move {
            let response = request.send().await.unwrap();
            (
                response.status().as_u16(),
                response.json::<Value>().await.unwrap(),
            )
        }
    };
    let (code, body) = share(&session, "hy2", "host=edge.example.com").await;
    assert_eq!(code, 200, "{body}");
    let uri = body["uri"].as_str().unwrap();
    assert!(
        uri.starts_with(&format!(
            "hysteria2://client-password-12345@edge.example.com:{listen_port}/?"
        )),
        "{uri}"
    );
    assert!(uri.contains("obfs=salamander&obfs-password=obfuscation-password-1"));
    assert!(uri.ends_with("#hy2%20rule"), "{uri}");
    assert!(body["qr_svg"].as_str().unwrap().contains("<svg"));
    let (code, body) = share(&session, "hy2", "host=2001:db8::1&port=443&name=Phone").await;
    assert_eq!(code, 200, "{body}");
    assert!(
        body["uri"]
            .as_str()
            .unwrap()
            .contains("@[2001:db8::1]:443/?")
    );
    assert!(body["uri"].as_str().unwrap().ends_with("#Phone"));

    assert_eq!(
        share(&session, "anytls", "host=edge.example.com").await.0,
        409
    );
    assert_eq!(share(&session, "ss", "host=edge.example.com").await.0, 409);
    assert_eq!(
        share(&session, "missing", "host=edge.example.com").await.0,
        404
    );
    assert_eq!(
        share(&session, "hy2", "host=https://edge.example.com")
            .await
            .0,
        400
    );
    // Another tenant cannot read the node's configuration, so not its links.
    let outsider = login("outsider").await;
    let (code, body) = share(&outsider, "hy2", "host=edge.example.com").await;
    assert_eq!(code, 404);
    assert!(body.get("uri").is_none());
    stop.cancel();
    tokio::time::sleep(Duration::from_millis(50)).await;
}
