mod common;
use common::*;
use relay_platform::{
    model::Protocol,
    store::{Rejection, Store},
    template::TemplateInput,
};
use serde_json::{Value, json};
use std::net::SocketAddr;

fn rejection(error: anyhow::Error) -> u16 {
    error.downcast_ref::<Rejection>().unwrap().status
}
fn input(tenant: Option<&str>, source: relay_platform::model::Rule) -> TemplateInput {
    TemplateInput {
        tenant_id: tenant.map(str::to_owned),
        name: "Web preset".into(),
        description: "HTTP ingress".into(),
        rule: source,
    }
}

#[test]
fn templates_are_scoped_and_apply_a_fresh_rule_identity() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let (node, _) = store.create_node(&admin, "default", "edge").unwrap();
    let initial = store.set_config(&admin, &node.id, 0, vec![]).unwrap();
    let source = rule("127.0.0.1:9000".parse().unwrap(), Protocol::Tcp);
    let template = store
        .create_template(&admin, input(None, source.clone()))
        .unwrap();
    assert_eq!(template.name, "Web preset");
    assert_eq!(store.templates(&admin).unwrap().len(), 1);
    let preview = store
        .preview_template(
            &admin,
            &node.id,
            &template.id,
            "Previewed",
            "127.0.0.1:19090".parse().unwrap(),
        )
        .unwrap();
    assert!(preview.valid, "{:?}", preview.error);
    assert_eq!(preview.current_revision, initial.revision);
    assert_ne!(preview.rule.id, template.rule.id);
    assert_eq!(
        store.config(&admin, &node.id, None).unwrap().revision,
        initial.revision
    );
    let applied = store
        .apply_template(
            &admin,
            &node.id,
            &template.id,
            initial.revision,
            "Cloned web",
            "127.0.0.1:19090".parse::<SocketAddr>().unwrap(),
        )
        .unwrap();
    assert_eq!(applied.rules.len(), 1);
    assert_eq!(applied.rules[0].name, "Cloned web");
    assert_eq!(applied.rules[0].listen.to_string(), "127.0.0.1:19090");
    assert_ne!(applied.rules[0].id, template.rule.id);
    assert_eq!(applied.rules[0].owner_id, admin.id);
    assert_eq!(applied.rules[0].tenant_id, "default");
    assert_eq!(template.rule.listen, source.listen);
    assert_eq!(
        rejection(
            store
                .apply_template(
                    &admin,
                    &node.id,
                    &template.id,
                    initial.revision,
                    "stale",
                    "127.0.0.1:19091".parse().unwrap(),
                )
                .unwrap_err()
        ),
        409
    );
    let viewer = store
        .create_user(
            &admin,
            "default",
            "viewer",
            PASSWORD,
            relay_platform::store::Role::Viewer,
        )
        .unwrap();
    assert_eq!(
        rejection(
            store
                .create_template(&viewer, input(Some("default"), source))
                .unwrap_err()
        ),
        403
    );
    let _ = viewer;
}

#[test]
fn rollout_stops_after_a_failed_canary_batch() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let (a, _) = store.create_node(&admin, "default", "a").unwrap();
    let (b, _) = store.create_node(&admin, "default", "b").unwrap();
    let (c, _) = store.create_node(&admin, "default", "c").unwrap();
    let ra = store.set_config(&admin, &a.id, 0, vec![]).unwrap();
    let rb = store.set_config(&admin, &b.id, 0, vec![]).unwrap();
    let rc = store.set_config(&admin, &c.id, 0, vec![]).unwrap();
    let source = rule("127.0.0.1:9000".parse().unwrap(), Protocol::Tcp);
    let template = store.create_template(&admin, input(None, source)).unwrap();
    let target = |node: &relay_platform::store::Node, expected: u64, port: u16| {
        relay_platform::template::RolloutTarget {
            node_id: node.id.clone(),
            expected_revision: expected,
            name: format!("rollout-{}", node.id),
            listen: format!("127.0.0.1:{port}").parse().unwrap(),
        }
    };
    let report = store
        .rollout_template(
            &admin,
            &template.id,
            &[
                target(&a, ra.revision, 19001),
                target(&b, rb.revision + 99, 19002),
                target(&c, rc.revision, 19003),
            ],
            1,
        )
        .unwrap();
    assert!(report.aborted);
    assert_eq!(report.applied, 1);
    assert_eq!(report.batches, 2);
    assert_eq!(report.results.len(), 3);
    assert!(report.results[0].applied);
    assert!(!report.results[1].applied);
    assert_eq!(
        report.results[2].error.as_deref(),
        Some("not attempted after canary failure")
    );
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn template_http_applies_and_rejects_viewers() {
    use relay_platform::api::{self, AppState};
    use tokio_util::sync::CancellationToken;
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let (node, _) = store.create_node(&admin, "default", "edge").unwrap();
    store.set_config(&admin, &node.id, 0, vec![]).unwrap();
    let viewer = store
        .create_user(
            &admin,
            "default",
            "viewer",
            PASSWORD,
            relay_platform::store::Role::Viewer,
        )
        .unwrap();
    let _ = viewer;
    let stop = CancellationToken::new();
    let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
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
    let origin = format!("http://{address}");
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let admin_session = login(&client, &origin, "admin").await;
    let viewer_session = login(&client, &origin, "viewer").await;
    let rule = rule("127.0.0.1:9000".parse().unwrap(), Protocol::Tcp);
    let template: Value = client
        .post(format!("{origin}/api/v1/templates"))
        .bearer_auth(&admin_session)
        .json(&json!({"name":"HTTP","description":"","rule": rule}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let template_id = template["id"].as_str().unwrap();
    assert_eq!(
        client
            .post(format!("{origin}/api/v1/templates"))
            .bearer_auth(&viewer_session)
            .json(&json!({"name":"No","rule":rule}))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let config: Value = client
        .get(format!("{origin}/api/v1/nodes/{}/config", node.id))
        .bearer_auth(&admin_session)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let revision = config["revision"].as_u64().unwrap();
    let applied: Value = client
        .post(format!(
            "{origin}/api/v1/nodes/{}/templates/{template_id}",
            node.id
        ))
        .bearer_auth(&admin_session)
        .json(&json!({"expected_revision":revision,"name":"HTTP rule","listen":"127.0.0.1:19090"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(applied["rules"][0]["name"], "HTTP rule");
    stop.cancel();
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
    body["token"].as_str().unwrap().to_string()
}
