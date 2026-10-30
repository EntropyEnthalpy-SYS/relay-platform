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
