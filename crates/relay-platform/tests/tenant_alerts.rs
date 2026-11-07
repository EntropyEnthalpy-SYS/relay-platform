mod common;
use axum::{Router, extract::State, routing::post};
use relay_platform::{
    alerts::{self, Channel, Target},
    model::*,
    store::{Role, Store},
    telemetry::Severity,
};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    net::TcpListener,
    sync::mpsc,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;

async fn receiver() -> (SocketAddr, mpsc::UnboundedReceiver<String>) {
    let (tx, rx) = mpsc::unbounded_channel();
    let router = Router::new()
        .route(
            "/",
            post(
                |State(tx): State<mpsc::UnboundedSender<String>>, body: String| async move {
                    let _ = tx.send(body);
                    "ok"
                },
            ),
        )
        .with_state(tx);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (address, rx)
}
fn channel(tenant: Option<String>, address: SocketAddr) -> Channel {
    Channel {
        tenant_id: tenant,
        id: String::new(),
        name: "fixture".into(),
        enabled: true,
        min_severity: Severity::Warning,
        target: Target::Webhook {
            url: format!("http://{address}/"),
            secret: String::new(),
        },
    }
}
fn report(db: &Store, id: &str, ledger: &str, error: Option<&str>) {
    db.sync(
        id,
        SyncRequest {
            logs: None,
            lease: None,
            budget: None,
            ledger_id: ledger.into(),
            need_config: false,
            applied_revision: 0,
            apply_error: error.map(Into::into),
            usage: vec![],
            stats: EngineStats::default(),
        },
    )
    .unwrap();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn mixed_tenant_incidents_are_routed_and_read_without_cross_tenant_data() {
    let temp = tempfile::tempdir().unwrap();
    let db = Store::open(&temp.path().join("controller.db")).unwrap();
    let admin = db.bootstrap(common::PASSWORD).unwrap();
    let other = db.create_tenant(&admin, "other").unwrap();
    let op = db
        .create_user(
            &admin,
            "default",
            "operator",
            common::PASSWORD,
            Role::TenantAdmin,
        )
        .unwrap();
    let viewer = db
        .create_user(&admin, "default", "viewer", common::PASSWORD, Role::Viewer)
        .unwrap();
    let (a, a_rx) = receiver().await;
    let (b, b_rx) = receiver().await;
    let (g, g_rx) = receiver().await;
    let ca = db
        .save_alert_channel(&admin, None, channel(Some("default".into()), a))
        .unwrap();
    db.save_alert_channel(&admin, None, channel(Some(other.clone()), b))
        .unwrap();
    db.save_alert_channel(&admin, None, channel(None, g))
        .unwrap();
    assert!(
        db.save_alert_channel(&op, None, channel(Some("default".into()), a))
            .is_err()
    );
    assert!(
        db.save_alert_channel(&admin, None, channel(Some("missing".into()), a))
            .is_err()
    );
    assert!(db.alert_overview(&viewer).is_err());
    let view = db.alert_overview(&op).unwrap();
    assert_eq!(view["can_manage"], false);
    assert_eq!(view["channels"].as_array().unwrap().len(), 1);
    assert_eq!(view["channels"][0]["id"], ca.id);
    for (tenant, name) in [
        ("default", "node-A-private"),
        (other.as_str(), "node-B-private"),
    ] {
        let (node, token) = db.create_node(&admin, tenant, name).unwrap();
        db.enroll(&node.id, &token, &relay_platform::store::secret())
            .unwrap();
        let ledger = db
            .reconcile(
                &node.id,
                ReconcileRequest {
                    lease: None,
                    ledger_id: None,
                    after: None,
                    expected_revision: None,
                },
            )
            .unwrap()
            .ledger_id;
        report(&db, &node.id, &ledger, Some(&format!("{name} rejected")));
    }
    // Hold delivery until both incidents are due. Their event timestamps differ,
    // so an arbitrary polling tick can otherwise send two separate global
    // messages instead of the mixed batch whose tenant routing this test checks.
    db.set_alert_settings(
        &admin,
        alerts::Settings {
            maintenance_until_ms: Some(now_ms() + 60_000),
            ..Default::default()
        },
    )
    .unwrap();
    let stop = CancellationToken::new();
    let worker = tokio::spawn(alerts::run(
        db.clone(),
        Duration::from_millis(20),
        stop.clone(),
    ));
    timeout(Duration::from_secs(10), async {
        loop {
            let open = db.alerts().snapshot().open;
            if open.len() == 2
                && open
                    .iter()
                    .all(|incident| now_ms() - incident.opened_at_ms >= alerts::GROUP_WAIT_MS)
            {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("both tenant incidents must be due before releasing the mixed batch");
    assert!(db.alerts().snapshot().deliveries.is_empty());
    db.set_alert_settings(&admin, alerts::Settings::default())
        .unwrap();
    let next = |rx: mpsc::UnboundedReceiver<String>| async move {
        let mut rx = rx;
        timeout(Duration::from_secs(10), rx.recv())
            .await
            .unwrap()
            .unwrap()
    };
    let (ma, mb, mg) = tokio::join!(next(a_rx), next(b_rx), next(g_rx));
    assert!(ma.contains("node-A-private") && !ma.contains("node-B-private"));
    assert!(mb.contains("node-B-private") && !mb.contains("node-A-private"));
    assert!(
        mg.contains("node-A-private") && mg.contains("node-B-private"),
        "{mg}"
    );
    let visible = db.alert_overview(&op).unwrap();
    assert_eq!(visible["incidents"]["open"].as_array().unwrap().len(), 1);
    assert!(!visible.to_string().contains("node-B-private"));
    assert_eq!(
        visible["incidents"]["deliveries"].as_array().unwrap().len(),
        1
    );
    stop.cancel();
    worker.await.unwrap();
}

#[tokio::test]
async fn a_revoked_or_reassigned_channel_cancels_queued_attempts() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("controller.db");
    let db = Store::open(&path).unwrap();
    let admin = db.bootstrap(common::PASSWORD).unwrap();
    let (address, mut received) = receiver().await;
    let view = db
        .save_alert_channel(&admin, None, channel(Some("default".into()), address))
        .unwrap();
    let saved = db.alert_channel(&admin, &view.id).unwrap();
    let (node, _) = db.create_node(&admin, "default", "edge").unwrap();
    let ownership = vec![(node.id.clone(), "default".into())];
    assert!(db.alert_delivery_permitted(&saved, &ownership).unwrap());
    assert!(
        !db.alert_delivery_permitted(&saved, &[(node.id.clone(), "other".into())])
            .unwrap()
    );
    let mut changed = saved.clone();
    changed.tenant_id = None;
    db.save_alert_channel(&admin, Some(&view.id), changed)
        .unwrap();
    alerts::deliver(
        &reqwest::Client::new(),
        &saved,
        "must not leak",
        &db,
        &ownership,
        0,
    )
    .await
    .unwrap();
    sleep(Duration::from_millis(50)).await;
    assert!(received.try_recv().is_err());
    let saved = db.alert_channel(&admin, &view.id).unwrap();
    db.delete_alert_channel(&admin, &view.id).unwrap();
    assert!(!db.alert_delivery_permitted(&saved, &ownership).unwrap());
    drop(db);
    let reopened = Store::open(&path).unwrap();
    assert!(
        reopened.alert_overview(&admin).unwrap()["channels"]
            .as_array()
            .unwrap()
            .is_empty()
    );
}

/// A budget belongs to its tenant, a node to its tenant, and a DNS record
/// to no tenant, so only channels for all tenants hear about it.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn budget_expiry_and_dns_incidents_follow_tenant_routing_and_clear() {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("controller.db");
    let db = Store::open(&path).unwrap();
    let admin = db.bootstrap(common::PASSWORD).unwrap();
    let other = db.create_tenant(&admin, "other").unwrap();
    let op = db
        .create_user(
            &admin,
            "default",
            "operator",
            common::PASSWORD,
            Role::TenantAdmin,
        )
        .unwrap();
    let (a, mut a_rx) = receiver().await;
    let (b, mut b_rx) = receiver().await;
    let (g, mut g_rx) = receiver().await;
    for (tenant, address) in [
        (Some("default".into()), a),
        (Some(other.clone()), b),
        (None, g),
    ] {
        db.save_alert_channel(&admin, None, channel(tenant, address))
            .unwrap();
    }
    let raw = rusqlite::Connection::open(&path).unwrap();
    // A default-tenant budget at 95 % of its limit.
    let budget = db
        .create_budget(
            &admin,
            relay_platform::budget::NewBudget {
                scope: relay_platform::budget::BudgetScope::Tenant,
                scope_id: "default".into(),
                name: "pool-A-private".into(),
                limit_bytes: 1000,
                quantum_bytes: 100,
            },
        )
        .unwrap();
    let commit = |bytes: u64| {
        raw.execute(
            "UPDATE budgets SET committed_bytes=?1 WHERE id=?2",
            rusqlite::params![bytes, budget.id],
        )
        .unwrap()
    };
    commit(950);
    // A node of the other tenant whose expiry passed.
    let (node, _) = db.create_node(&admin, &other, "node-B-private").unwrap();
    let expire = |at: Option<i64>| {
        raw.execute(
            "UPDATE metadata SET value=json_set(value,'$.settings.expires_at_ms',json(?2)) WHERE key=?1",
            rusqlite::params![format!("node_profile:{}", node.id), serde_json::json!(at).to_string()],
        )
        .unwrap()
    };
    expire(Some(now_ms() - 1_000));
    // A DNS record whose last provider sync failed.
    let provider = db
        .create_dns_provider(
            &admin,
            "fixture",
            relay_platform::dns::ProviderKind::Cloudflare,
            "http://127.0.0.1:9/client/v4",
            "fixture-token",
            0,
            Default::default(),
        )
        .unwrap();
    let zone = db
        .create_dns_zone(
            &admin,
            &provider.id,
            "example.com",
            relay_platform::dns::ZoneMode::Apply,
            0,
            0,
        )
        .unwrap();
    let record = db
        .create_dns_record(
            &admin,
            &zone.id,
            relay_platform::store::NewDnsRecord {
                name: "edge.example.com".into(),
                record_type: relay_platform::dns::RecordType::A,
                content: "203.0.113.10".into(),
                ttl: 300,
                proxied: false,
                health: None,
            },
        )
        .unwrap();
    db.dns_record_failed(&record.id, "provider said no")
        .unwrap();

    let on = |threshold| alerts::Rule {
        enabled: true,
        threshold,
        checks: 2,
    };
    db.set_alert_settings(
        &admin,
        alerts::Settings {
            maintenance_until_ms: Some(now_ms() + 60_000),
            rules: Some(alerts::Rules {
                budget_near: on(Some(90)),
                node_expired: on(None),
                dns_sync_failed: on(None),
                ..alerts::Rules::default()
            }),
        },
    )
    .unwrap();
    let stop = CancellationToken::new();
    let worker = tokio::spawn(alerts::run(
        db.clone(),
        Duration::from_millis(20),
        stop.clone(),
    ));
    let open = || {
        let mut keys: Vec<String> = db
            .alerts()
            .snapshot()
            .open
            .iter()
            .map(|i| i.key.split(':').next().unwrap().to_owned())
            .collect();
        keys.sort();
        keys
    };
    // Maintenance holds the notices until all three are due, so one
    // grouped message per channel shows the routing.
    timeout(Duration::from_secs(10), async {
        loop {
            let snapshot = db.alerts().snapshot();
            if snapshot.open.len() == 3
                && snapshot
                    .open
                    .iter()
                    .all(|i| now_ms() - i.opened_at_ms >= alerts::GROUP_WAIT_MS)
            {
                break;
            }
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("the budget, expiry and DNS incidents must open");
    assert_eq!(open(), ["budget_near", "dns", "expired"]);
    assert!(db.alerts().snapshot().deliveries.is_empty());
    let visible = db.alert_overview(&op).unwrap();
    assert_eq!(visible["incidents"]["open"].as_array().unwrap().len(), 1);
    let text = visible.to_string();
    assert!(text.contains("pool-A-private"));
    assert!(!text.contains("node-B-private") && !text.contains("edge.example.com"));

    // Ending maintenance without rules keeps the saved rules.
    db.set_alert_settings(&admin, alerts::Settings::default())
        .unwrap();
    assert_eq!(
        db.alert_config().unwrap().0.rules.unwrap().dns_sync_failed,
        on(None)
    );
    let (ma, mb, mg) = tokio::join!(next(&mut a_rx), next(&mut b_rx), next(&mut g_rx));
    assert!(ma.contains("共享额度 pool-A-private 已占用 95%"), "{ma}");
    assert!(!ma.contains("node-B-private") && !ma.contains("edge.example.com"));
    assert!(mb.contains("节点 node-B-private 已于"), "{mb}");
    assert!(!mb.contains("pool-A-private") && !mb.contains("edge.example.com"));
    assert!(mg.contains("【告警·严重】3 个新问题"), "{mg}");
    assert!(
        mg.contains("pool-A-private")
            && mg.contains("node-B-private")
            && mg.contains("DNS 记录 edge.example.com A 同步失败：provider said no"),
        "{mg}"
    );

    // Each clears on its own and the recoveries go the same ways.
    commit(100);
    expire(None);
    db.dns_record_synced(&record.id, None, None).unwrap();
    timeout(Duration::from_secs(10), async {
        while !open().is_empty() {
            sleep(Duration::from_millis(20)).await;
        }
    })
    .await
    .expect("every incident must resolve");
    let (ra, rb) = tokio::join!(next(&mut a_rx), next(&mut b_rx));
    assert!(
        ra.contains("【已恢复】") && ra.contains("占用回落到 10%"),
        "{ra}"
    );
    assert!(!ra.contains("edge.example.com"), "{ra}");
    assert!(
        rb.contains("节点 node-B-private 的到期时间已延后或取消"),
        "{rb}"
    );
    // The three may clear on different passes, so in up to three messages.
    let mut rg = String::new();
    while !(rg.contains("pool-A-private")
        && rg.contains("node-B-private")
        && rg.contains("DNS 记录 edge.example.com A 同步恢复"))
    {
        rg += &next(&mut g_rx).await;
    }
    assert!(!rg.contains("【告警"), "{rg}");
    stop.cancel();
    worker.await.unwrap();
}

async fn next(rx: &mut mpsc::UnboundedReceiver<String>) -> String {
    timeout(Duration::from_secs(10), rx.recv())
        .await
        .expect("no notice arrived")
        .unwrap()
}
