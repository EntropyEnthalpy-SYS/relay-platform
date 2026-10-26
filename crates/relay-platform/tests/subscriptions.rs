mod common;
use common::*;
use relay_platform::{
    api::{self, AppState},
    model::*,
    shadowsocks,
    store::{Rejection, Store},
    subscription,
};
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
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
    });
    rule.targets.clear();
    rule.advertise = Some("edge.example.com:9000".into());
    rule
}
fn rejection(error: anyhow::Error) -> u16 {
    error.downcast_ref::<Rejection>().unwrap().status
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

    let (view, token) = store
        .create_subscription(
            &admin,
            None,
            "phone",
            subscription::Format::V2ray,
            subscription::Template::default(),
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
                .rotate_subscription(&tenant_admin, &view.id)
                .unwrap_err()
        ),
        403
    );

    let preview = store.render_subscription(&admin, &view.id).unwrap();
    assert_eq!(preview.entries.len(), 1);
    assert_eq!(preview.entries[0].host, "edge.example.com");
    assert_eq!(preview.entries[0].port, 9000);
    let public = store.render_public_subscription(&token).unwrap();
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

    let (rotated, fresh) = store.rotate_subscription(&admin, &view.id).unwrap();
    assert_ne!(fresh, token);
    assert_eq!(rotated.id, view.id);
    assert_eq!(
        rejection(store.render_public_subscription(&token).unwrap_err()),
        401
    );
    assert!(store.render_public_subscription(&fresh).is_ok());
    store.delete_subscription(&admin, &view.id).unwrap();
    assert!(store.subscriptions(&admin).unwrap().is_empty());
    assert_eq!(
        rejection(store.render_public_subscription(&fresh).unwrap_err()),
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
                "persisted",
                subscription::Format::Shadowrocket,
                subscription::Template::default(),
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
            .render_public_subscription(&token)
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
