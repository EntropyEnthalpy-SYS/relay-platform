mod common;
use common::*;
use relay_platform::{
    health::{ProbeKind, Status, TargetHealthReport},
    model::{EngineStats, Protocol},
    store::{Rejection, Role, Store},
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
        variables: Default::default(),
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
            variables: Default::default(),
            template_version: None,
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
            true,
            None,
            false,
            false,
            None,
        )
        .unwrap();
    assert!(report.aborted);
    assert_eq!(report.applied, 1);
    assert_eq!(report.rolled_back, 1);
    assert_eq!(report.rollback_failed, 0);
    assert!(report.results[0].rolled_back);
    assert!(store.config(&admin, &a.id, None).unwrap().rules.is_empty());
    assert_eq!(report.batches, 2);
    assert_eq!(report.results.len(), 3);
    assert!(report.results[0].applied);
    assert!(!report.results[1].applied);
    assert_eq!(
        report.results[2].error.as_deref(),
        Some("not attempted after canary failure")
    );
    let retry = store
        .retry_rollout(&admin, &template.id, &report.id)
        .unwrap();
    assert!(!retry.aborted);
    assert_eq!(retry.applied, 3);
    assert!(store.config(&admin, &a.id, None).unwrap().rules.len() == 1);
    assert!(store.config(&admin, &b.id, None).unwrap().rules.len() == 1);
    assert!(store.config(&admin, &c.id, None).unwrap().rules.len() == 1);
}

#[test]
fn template_variables_render_and_can_be_overridden() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let (node, _) = store.create_node(&admin, "default", "edge").unwrap();
    let initial = store.set_config(&admin, &node.id, 0, vec![]).unwrap();
    let mut source = rule("127.0.0.1:9000".parse().unwrap(), Protocol::Tcp);
    source.targets[0].address = "{{host}}:9000".into();
    let mut input = input(None, source);
    input.variables.insert("host".into(), "127.0.0.1".into());
    let template = store.create_template(&admin, input).unwrap();
    let defaults = store
        .apply_template(
            &admin,
            &node.id,
            &template.id,
            initial.revision,
            "default",
            "127.0.0.1:19001".parse().unwrap(),
        )
        .unwrap();
    assert_eq!(defaults.rules[0].targets[0].address, "127.0.0.1:9000");
    let overrides =
        std::collections::BTreeMap::from([("host".to_string(), "localhost".to_string())]);
    let changed = store
        .apply_template_with_variables(
            &admin,
            &node.id,
            &template.id,
            defaults.revision,
            "override",
            "127.0.0.1:19002".parse().unwrap(),
            &overrides,
            None,
        )
        .unwrap();
    assert_eq!(changed.rules[1].targets[0].address, "localhost:9000");
}

#[test]
fn rollout_reports_a_missing_post_apply_receipt() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let (node, _) = store.create_node(&admin, "default", "apply-gate").unwrap();
    let revision = store.set_config(&admin, &node.id, 0, vec![]).unwrap();
    let template = store
        .create_template(
            &admin,
            input(None, rule("127.0.0.1:9000".parse().unwrap(), Protocol::Tcp)),
        )
        .unwrap();
    let target = relay_platform::template::RolloutTarget {
        node_id: node.id,
        expected_revision: revision.revision,
        name: "apply-gate".into(),
        listen: "127.0.0.1:19105".parse().unwrap(),
        variables: Default::default(),
        template_version: None,
    };
    let report = store
        .rollout_template(
            &admin,
            &template.id,
            &[target],
            1,
            false,
            None,
            false,
            false,
            Some(100),
        )
        .unwrap();
    assert_eq!(report.applied, 1);
    assert!(report.aborted);
    assert!(
        report
            .gate_error
            .as_deref()
            .unwrap()
            .contains("did not apply")
    );
}

#[test]
fn rollout_can_require_a_recent_healthy_node() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let (node, _) = store.create_node(&admin, "default", "health-gate").unwrap();
    let revision = store.set_config(&admin, &node.id, 0, vec![]).unwrap();
    let template = store
        .create_template(
            &admin,
            input(None, rule("127.0.0.1:9000".parse().unwrap(), Protocol::Tcp)),
        )
        .unwrap();
    let target = relay_platform::template::RolloutTarget {
        node_id: node.id.clone(),
        expected_revision: revision.revision,
        name: "health-gate".into(),
        listen: "127.0.0.1:19104".parse().unwrap(),
        variables: Default::default(),
        template_version: None,
    };
    let rejected = store
        .rollout_template(
            &admin,
            &template.id,
            std::slice::from_ref(&target),
            1,
            false,
            None,
            true,
            false,
            None,
        )
        .unwrap();
    assert_eq!(rejected.applied, 0);
    assert!(
        rejected.results[0]
            .error
            .as_deref()
            .unwrap()
            .contains("synced")
    );
    let applied = store
        .rollout_template(
            &admin,
            &template.id,
            &[target],
            1,
            false,
            None,
            false,
            false,
            None,
        )
        .unwrap();
    assert_eq!(applied.applied, 1);
}

#[test]
fn stale_unrelated_target_health_blocks_rollout() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("controller.db");
    let store = Store::open(&db).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let (node, _) = store.create_node(&admin, "default", "target-gate").unwrap();
    let revision = store.set_config(&admin, &node.id, 0, vec![]).unwrap();
    let stats = EngineStats {
        target_health: vec![TargetHealthReport {
            probe_kind: ProbeKind::TcpConnect,
            rule_id: "rule-one".into(),
            target_index: 0,
            listen_port: 9000,
            protocol: Protocol::Tcp,
            target_address: "127.0.0.1:9".into(),
            status: Status::Healthy,
            eligible: true,
            selection_reason: "fixture".into(),
            sample_age_ms: Some(10),
            max_age_ms: 30_000,
            checked_at_ms: Some(1),
            latency_ewma_us: Some(1000),
            window_checks: 1,
            window_failures: 0,
            jitter_us: None,
            consecutive_successes: 1,
            consecutive_failures: 0,
            completed_checks: 1,
            successful_checks: 1,
            last_error: None,
            probe_sent_bytes: 1,
            probe_received_bytes: 1,
            priority: 0,
            active_sessions: 0,
            max_sessions: None,
        }],
        ..Default::default()
    };
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute(
            "UPDATE nodes SET stats_json=?1 WHERE id=?2",
            rusqlite::params![serde_json::to_string(&stats).unwrap(), node.id],
        )
        .unwrap();
    let template = store
        .create_template(
            &admin,
            input(None, rule("127.0.0.1:9000".parse().unwrap(), Protocol::Tcp)),
        )
        .unwrap();
    let target = relay_platform::template::RolloutTarget {
        node_id: node.id.clone(),
        expected_revision: revision.revision,
        name: "target-gate".into(),
        listen: "127.0.0.1:19105".parse().unwrap(),
        variables: Default::default(),
        template_version: None,
    };
    let report = store
        .rollout_template(
            &admin,
            &template.id,
            &[target],
            1,
            false,
            None,
            false,
            true,
            Some(200),
        )
        .unwrap();
    assert!(report.aborted);
    assert!(report.require_target_health);
    assert_eq!(report.applied, 1);
    assert_eq!(report.rolled_back, 0);
    assert!(
        report
            .gate_error
            .as_deref()
            .unwrap()
            .contains("intended rules")
    );
    let current = store.config(&admin, &node.id, None).unwrap();
    assert_eq!(current.revision, revision.revision + 1);
    assert!(
        store.nodes(&admin).unwrap()[0].applied_revision < current.revision,
        "the published revision must not be reported as applied"
    );
}

#[test]
fn fresh_health_for_the_intended_rule_is_accepted() {
    let temp = tempfile::tempdir().unwrap();
    let db = temp.path().join("controller.db");
    let store = Store::open(&db).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let (node, _) = store.create_node(&admin, "default", "target-gate").unwrap();
    let mut intended = rule("127.0.0.1:9000".parse().unwrap(), Protocol::Tcp);
    intended.id = "intended-rule".into();
    let published = store
        .set_config(&admin, &node.id, 0, vec![intended])
        .unwrap();
    let checked = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap()
        .as_millis() as i64;
    let stats = EngineStats {
        target_health: vec![TargetHealthReport {
            probe_kind: ProbeKind::TcpConnect,
            rule_id: "intended-rule".into(),
            target_index: 0,
            listen_port: 9000,
            protocol: Protocol::Tcp,
            target_address: "127.0.0.1:9".into(),
            status: Status::Healthy,
            eligible: true,
            selection_reason: "fixture".into(),
            sample_age_ms: Some(10),
            max_age_ms: 30_000,
            checked_at_ms: Some(checked),
            latency_ewma_us: Some(1000),
            window_checks: 1,
            window_failures: 0,
            jitter_us: None,
            consecutive_successes: 1,
            consecutive_failures: 0,
            completed_checks: 1,
            successful_checks: 1,
            last_error: None,
            probe_sent_bytes: 1,
            probe_received_bytes: 1,
            priority: 0,
            active_sessions: 0,
            max_sessions: None,
        }],
        ..Default::default()
    };
    rusqlite::Connection::open(&db)
        .unwrap()
        .execute(
            "UPDATE nodes SET applied_revision=?1, stats_json=?2 WHERE id=?3",
            rusqlite::params![
                published.revision,
                serde_json::to_string(&stats).unwrap(),
                node.id
            ],
        )
        .unwrap();
    store
        .wait_for_target_health(
            &admin,
            &[(node.id.clone(), "intended-rule".into(), published.revision)],
            200,
        )
        .unwrap();
}

#[test]
fn canary_percent_sizes_the_first_batch() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let source = rule("127.0.0.1:9000".parse().unwrap(), Protocol::Tcp);
    let template = store.create_template(&admin, input(None, source)).unwrap();
    let mut targets = Vec::new();
    for (index, port) in [19101u16, 19102, 19103].into_iter().enumerate() {
        let (node, _) = store
            .create_node(&admin, "default", &format!("canary-{index}"))
            .unwrap();
        let revision = store.set_config(&admin, &node.id, 0, vec![]).unwrap();
        targets.push(relay_platform::template::RolloutTarget {
            node_id: node.id,
            expected_revision: revision.revision,
            name: format!("canary-{index}"),
            listen: format!("127.0.0.1:{port}").parse().unwrap(),
            variables: Default::default(),
            template_version: None,
        });
    }
    let report = store
        .rollout_template(
            &admin,
            &template.id,
            &targets,
            2,
            false,
            Some(34),
            false,
            false,
            None,
        )
        .unwrap();
    assert_eq!(report.canary_percent, Some(34));
    assert_eq!(report.batches, 2);
    assert_eq!(report.applied, 3);
    assert_eq!(report.results[0].batch, 1);
    assert_eq!(report.results[1].batch, 1);
    assert_eq!(report.results[2].batch, 2);
}

#[test]
fn template_versions_can_be_listed_and_rolled_back() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let source = rule("127.0.0.1:9000".parse().unwrap(), Protocol::Tcp);
    let template = store.create_template(&admin, input(None, source)).unwrap();
    assert_eq!(template.version, 1);
    let mut changed = input(None, rule("127.0.0.1:9001".parse().unwrap(), Protocol::Tcp));
    changed.name = "Second version".into();
    let updated = store
        .update_template(&admin, &template.id, changed)
        .unwrap();
    assert_eq!(updated.version, 2);
    assert_eq!(
        store.template_versions(&admin, &template.id).unwrap().len(),
        2
    );
    let rolled = store.rollback_template(&admin, &template.id, 1).unwrap();
    assert_eq!(rolled.version, 3);
    assert_eq!(rolled.name, "Web preset");
    assert_eq!(rolled.rule.targets[0].address, "127.0.0.1:9000");
    assert_eq!(
        store.template_versions(&admin, &template.id).unwrap().len(),
        3
    );
}

#[test]
fn tenant_administrators_cannot_roll_back_global_templates() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let tenant = store.create_tenant(&admin, "acme").unwrap();
    let tenant_admin = store
        .create_user(&admin, &tenant, "tenant-admin", PASSWORD, Role::TenantAdmin)
        .unwrap();
    let source = rule("127.0.0.1:9000".parse().unwrap(), Protocol::Tcp);
    let template = store.create_template(&admin, input(None, source)).unwrap();
    let mut changed = input(None, rule("127.0.0.1:9001".parse().unwrap(), Protocol::Tcp));
    changed.name = "Global v2".into();
    store
        .update_template(&admin, &template.id, changed)
        .unwrap();
    let error = store
        .rollback_template(&tenant_admin, &template.id, 1)
        .unwrap_err();
    assert_eq!(rejection(error), 403);
    let current = store
        .template_versions(&admin, &template.id)
        .unwrap()
        .into_iter()
        .find(|template| template.version == 2)
        .unwrap();
    assert_eq!(current.name, "Global v2");
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
