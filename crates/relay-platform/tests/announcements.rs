mod common;
use common::*;
use relay_platform::{
    announcement::{AnnouncementDraft, Severity},
    api::{self, AppState},
    model::now_ms,
    store::{Rejection, Store},
};
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

fn draft(
    tenant: Option<&str>,
    title: &str,
    body: &str,
    severity: Severity,
    starts_at_ms: i64,
    ends_at_ms: Option<i64>,
    enabled: bool,
) -> AnnouncementDraft {
    AnnouncementDraft {
        tenant_id: tenant.map(str::to_owned),
        title: title.into(),
        body: body.into(),
        severity,
        starts_at_ms,
        ends_at_ms,
        enabled,
    }
}
fn rejection(error: anyhow::Error) -> u16 {
    error.downcast_ref::<Rejection>().unwrap().status
}

#[test]
fn announcements_are_global_or_tenant_scoped_and_administrators_are_checked() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let other_tenant = store.create_tenant(&admin, "other").unwrap();
    let tenant_admin = store
        .create_user(
            &admin,
            "default",
            "tenant-admin",
            PASSWORD,
            relay_platform::store::Role::TenantAdmin,
        )
        .unwrap();
    let outsider = store
        .create_user(
            &admin,
            &other_tenant,
            "outsider",
            PASSWORD,
            relay_platform::store::Role::Viewer,
        )
        .unwrap();
    let now = now_ms();
    let global = store
        .create_announcement(
            &admin,
            draft(
                None,
                "Maintenance",
                "All tenants",
                Severity::Warning,
                now - 1000,
                None,
                true,
            ),
        )
        .unwrap();
    let local = store
        .create_announcement(
            &admin,
            draft(
                Some("default"),
                "Tenant notice",
                "Default only",
                Severity::Info,
                now - 1000,
                None,
                true,
            ),
        )
        .unwrap();
    let future = store
        .create_announcement(
            &admin,
            draft(
                None,
                "Future",
                "Not yet",
                Severity::Critical,
                now + 60_000,
                None,
                true,
            ),
        )
        .unwrap();
    assert_eq!(store.announcements(&admin).unwrap().len(), 2);
    assert_eq!(store.announcements(&outsider).unwrap().len(), 1);
    assert_eq!(store.announcements(&outsider).unwrap()[0].id, global.id);
    assert!(
        !store
            .announcements(&admin)
            .unwrap()
            .iter()
            .any(|a| a.id == future.id)
    );

    assert_eq!(
        rejection(
            store
                .create_announcement(
                    &tenant_admin,
                    draft(None, "Global", "nope", Severity::Info, now, None, true)
                )
                .unwrap_err()
        ),
        403
    );
    let own = store
        .create_announcement(
            &tenant_admin,
            draft(
                Some("default"),
                "Tenant admin",
                "ok",
                Severity::Info,
                now,
                None,
                true,
            ),
        )
        .unwrap();
    assert_eq!(
        rejection(
            store
                .update_announcement(
                    &tenant_admin,
                    &global.id,
                    draft(None, "x", "", Severity::Info, now, None, true)
                )
                .unwrap_err()
        ),
        403
    );
    store
        .update_announcement(
            &tenant_admin,
            &own.id,
            draft(None, "Updated", "ok", Severity::Warning, now, None, true),
        )
        .unwrap();
    let managed = store.manage_announcements(&tenant_admin).unwrap();
    assert!(
        managed.iter().any(|a| a.id == global.id),
        "global is visible read-only"
    );
    assert!(managed.iter().any(|a| a.id == own.id));
    assert_eq!(
        rejection(
            store
                .delete_announcement(&tenant_admin, &global.id)
                .unwrap_err()
        ),
        403
    );
    store.delete_announcement(&admin, &local.id).unwrap();
    assert!(
        store
            .announcements(&admin)
            .unwrap()
            .iter()
            .all(|a| a.id != local.id)
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
async fn announcement_http_routes_publish_and_hide_by_time_and_role() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    store
        .create_user(
            &admin,
            "default",
            "viewer",
            PASSWORD,
            relay_platform::store::Role::Viewer,
        )
        .unwrap();
    let (address, stop) = serve(store).await;
    let origin = format!("http://{address}");
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let admin_session = login(&client, &origin, "admin").await;
    let viewer_session = login(&client, &origin, "viewer").await;
    let created: Value = client
        .post(format!("{origin}/api/v1/announcements"))
        .bearer_auth(&admin_session)
        .json(&json!({
            "title": "Planned work",
            "body": "Tonight",
            "severity": "warning",
            "starts_at_ms": now_ms() - 1000,
            "ends_at_ms": now_ms() + 60_000,
            "enabled": true
        }))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(created["tenant_id"], Value::Null);
    let active: Value = client
        .get(format!("{origin}/api/v1/announcements"))
        .bearer_auth(&viewer_session)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(active.as_array().unwrap().len(), 1);
    assert_eq!(active[0]["title"], "Planned work");
    assert_eq!(
        client
            .post(format!("{origin}/api/v1/announcements"))
            .bearer_auth(&viewer_session)
            .json(&json!({"title":"no","body":"","severity":"info"}))
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .get(format!("{origin}/api/v1/announcements/manage"))
            .bearer_auth(&viewer_session)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    let id = created["id"].as_str().unwrap();
    assert_eq!(
        client
            .delete(format!("{origin}/api/v1/announcements/{id}"))
            .bearer_auth(&admin_session)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    stop.cancel();
    tokio::time::sleep(Duration::from_millis(50)).await;
}
