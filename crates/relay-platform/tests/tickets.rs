mod common;
use common::*;
use relay_platform::{
    api::{self, AppState},
    store::{Rejection, Store},
    ticket::{NewTicket, TicketPriority, TicketStatus},
};
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

fn rejection(error: anyhow::Error) -> u16 {
    error.downcast_ref::<Rejection>().unwrap().status
}
fn new_ticket() -> NewTicket {
    NewTicket {
        subject: "Cannot connect".into(),
        body: "The listener refuses connections".into(),
        priority: TicketPriority::High,
    }
}

#[test]
fn tickets_are_owner_tenant_and_admin_scoped() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let other_tenant = store.create_tenant(&admin, "other").unwrap();
    let tadmin = store
        .create_user(
            &admin,
            "default",
            "support",
            PASSWORD,
            relay_platform::store::Role::TenantAdmin,
        )
        .unwrap();
    let alice = store
        .create_user(
            &admin,
            "default",
            "alice",
            PASSWORD,
            relay_platform::store::Role::Viewer,
        )
        .unwrap();
    let bob = store
        .create_user(
            &admin,
            "default",
            "bob",
            PASSWORD,
            relay_platform::store::Role::Viewer,
        )
        .unwrap();
    let outsider = store
        .create_user(
            &admin,
            &other_tenant,
            "outsider",
            PASSWORD,
            relay_platform::store::Role::TenantAdmin,
        )
        .unwrap();
    let (_, alice_actor) = store.login("alice", PASSWORD).unwrap();
    let (_, bob_actor) = store.login("bob", PASSWORD).unwrap();
    let (_, tadmin_actor) = store.login("support", PASSWORD).unwrap();
    let (_, outsider_actor) = store.login("outsider", PASSWORD).unwrap();
    let created = store.create_ticket(&alice_actor, new_ticket()).unwrap();
    assert_eq!(created.ticket.status, TicketStatus::Open);
    assert_eq!(store.tickets(&alice_actor).unwrap().len(), 1);
    assert!(store.tickets(&bob_actor).unwrap().is_empty());
    assert_eq!(
        rejection(store.ticket(&bob_actor, &created.ticket.id).unwrap_err()),
        403
    );
    assert_eq!(
        rejection(
            store
                .ticket(&outsider_actor, &created.ticket.id)
                .unwrap_err()
        ),
        403
    );
    assert_eq!(
        store
            .ticket(&tadmin_actor, &created.ticket.id)
            .unwrap()
            .messages
            .len(),
        1
    );
    let internal = store
        .reply_ticket(&tadmin_actor, &created.ticket.id, "checking the node", true)
        .unwrap();
    assert_eq!(internal.messages.len(), 2);
    let owner_view = store.ticket(&alice_actor, &created.ticket.id).unwrap();
    assert_eq!(
        owner_view.messages.len(),
        1,
        "internal note leaked to owner"
    );
    assert_eq!(
        rejection(
            store
                .reply_ticket(&alice_actor, &created.ticket.id, "private", true)
                .unwrap_err()
        ),
        403
    );
    let reply = store
        .reply_ticket(&alice_actor, &created.ticket.id, "still broken", false)
        .unwrap();
    assert_eq!(reply.ticket.status, TicketStatus::Open);
    assert_eq!(
        rejection(
            store
                .set_ticket_status(&alice_actor, &created.ticket.id, TicketStatus::Pending)
                .unwrap_err()
        ),
        403
    );
    store
        .set_ticket_status(&alice_actor, &created.ticket.id, TicketStatus::Closed)
        .unwrap();
    assert_eq!(
        rejection(
            store
                .reply_ticket(&alice_actor, &created.ticket.id, "closed", false)
                .unwrap_err()
        ),
        409
    );
    let reopened = store
        .set_ticket_status(&tadmin_actor, &created.ticket.id, TicketStatus::Pending)
        .unwrap();
    assert_eq!(reopened.ticket.status, TicketStatus::Pending);
    assert_eq!(store.tickets(&admin).unwrap().len(), 1);
    assert_eq!(store.tickets(&outsider_actor).unwrap().len(), 0);
    let _ = (&alice, &bob, &tadmin, &outsider);
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
async fn ticket_http_thread_internal_notes_and_status() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    store
        .create_user(
            &admin,
            "default",
            "alice",
            PASSWORD,
            relay_platform::store::Role::Viewer,
        )
        .unwrap();
    store
        .create_user(
            &admin,
            "default",
            "bob",
            PASSWORD,
            relay_platform::store::Role::Viewer,
        )
        .unwrap();
    let (address, stop) = serve(store).await;
    let origin = format!("http://{address}");
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let alice = login(&client, &origin, "alice").await;
    let bob = login(&client, &origin, "bob").await;
    let admin_session = login(&client, &origin, "admin").await;
    let created: Value = client
        .post(format!("{origin}/api/v1/tickets"))
        .bearer_auth(&alice)
        .json(&json!({"subject":"Help","body":"No route","priority":"high"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let id = created["ticket"]["id"].as_str().unwrap();
    assert_eq!(
        client
            .get(format!("{origin}/api/v1/tickets/{id}"))
            .bearer_auth(&bob)
            .send()
            .await
            .unwrap()
            .status(),
        403
    );
    assert_eq!(
        client
            .post(format!("{origin}/api/v1/tickets/{id}/messages"))
            .bearer_auth(&admin_session)
            .json(&json!({"body":"internal","internal":true}))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    let owner: Value = client
        .get(format!("{origin}/api/v1/tickets/{id}"))
        .bearer_auth(&alice)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(owner["messages"].as_array().unwrap().len(), 1);
    assert_eq!(owner["ticket"]["status"], "open");
    assert_eq!(
        client
            .put(format!("{origin}/api/v1/tickets/{id}/status"))
            .bearer_auth(&alice)
            .json(&json!({"status":"closed"}))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client
            .post(format!("{origin}/api/v1/tickets/{id}/messages"))
            .bearer_auth(&alice)
            .json(&json!({"body":"after close"}))
            .send()
            .await
            .unwrap()
            .status(),
        409
    );
    stop.cancel();
    tokio::time::sleep(Duration::from_millis(50)).await;
}
