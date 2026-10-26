mod common;
use common::*;
use relay_platform::{
    api::{self, AppState},
    store::{Rejection, Store},
};
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

const NEW: &str = "new-password-29x!";

fn rejection(error: anyhow::Error) -> u16 {
    error.downcast_ref::<Rejection>().unwrap().status
}

#[test]
fn password_change_reset_disable_and_delete_revoke_the_right_credentials() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let alice = store
        .create_user(
            &admin,
            "default",
            "alice",
            PASSWORD,
            relay_platform::store::Role::Viewer,
        )
        .unwrap();
    let (current, actor) = store.login("alice", PASSWORD).unwrap();
    let (other, _) = store.login("alice", PASSWORD).unwrap();
    let api_token = store
        .create_api_token(&actor, "script", &[relay_platform::store::Scope::Read], 1)
        .unwrap()
        .0;
    assert_eq!(
        rejection(
            store
                .change_password(&actor, "wrong-password", NEW, &current)
                .unwrap_err()
        ),
        403
    );
    store
        .change_password(&actor, PASSWORD, NEW, &current)
        .unwrap();
    assert_eq!(rejection(store.login("alice", PASSWORD).unwrap_err()), 401);
    assert!(store.login("alice", NEW).is_ok());
    assert!(
        store.authenticate(&current).is_ok(),
        "the current session stays valid"
    );
    assert_eq!(rejection(store.authenticate(&other).unwrap_err()), 401);
    assert!(store.authenticate(&api_token).is_ok());

    let (second, _) = store.login("alice", NEW).unwrap();
    store.reset_password(&admin, &alice.id, NEW).unwrap();
    assert_eq!(rejection(store.authenticate(&second).unwrap_err()), 401);
    assert_eq!(rejection(store.authenticate(&api_token).unwrap_err()), 401);
    assert!(store.login("alice", NEW).is_ok());

    let (third, _) = store.login("alice", NEW).unwrap();
    assert!(store.set_user_disabled(&admin, &alice.id, true).unwrap());
    assert_eq!(rejection(store.login("alice", NEW).unwrap_err()), 401);
    assert_eq!(rejection(store.authenticate(&third).unwrap_err()), 401);
    assert!(!store.set_user_disabled(&admin, &alice.id, false).unwrap());
    assert!(store.login("alice", NEW).is_ok());

    assert_eq!(
        rejection(
            store
                .set_user_disabled(&admin, &admin.id, true)
                .unwrap_err()
        ),
        400
    );
    assert_eq!(
        rejection(store.delete_user(&admin, &admin.id).unwrap_err()),
        400
    );
    store.delete_user(&admin, &alice.id).unwrap();
    assert_eq!(rejection(store.login("alice", NEW).unwrap_err()), 401);
    assert!(
        store
            .users(&admin)
            .unwrap()
            .iter()
            .all(|user| user.user.id != alice.id)
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
async fn login(
    client: &reqwest::Client,
    origin: &str,
    username: &str,
    password: &str,
) -> (u16, Value) {
    let response = client
        .post(format!("{origin}/api/v1/auth/login"))
        .json(&json!({"username": username, "password": password}))
        .send()
        .await
        .unwrap();
    let status = response.status().as_u16();
    (status, response.json().await.unwrap())
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn user_lifecycle_http_routes_are_guarded_and_effective() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    store.bootstrap(PASSWORD).unwrap();
    let (address, stop) = serve(store).await;
    let origin = format!("http://{address}");
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let (_, admin) = login(&client, &origin, "admin", PASSWORD).await;
    let session = admin["token"].as_str().unwrap().to_owned();
    let user: Value = client
        .post(format!("{origin}/api/v1/users"))
        .bearer_auth(&session)
        .json(&json!({"username": "bob", "password": PASSWORD, "role": "viewer"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let user_id = user["id"].as_str().unwrap().to_owned();
    let (_, bob) = login(&client, &origin, "bob", PASSWORD).await;
    let bob_session = bob["token"].as_str().unwrap().to_owned();

    let changed = client
        .post(format!("{origin}/api/v1/account/password"))
        .bearer_auth(&bob_session)
        .json(&json!({"current_password": PASSWORD, "new_password": NEW}))
        .send()
        .await
        .unwrap();
    assert_eq!(changed.status(), 200);
    assert_eq!(login(&client, &origin, "bob", PASSWORD).await.0, 401);
    assert_eq!(login(&client, &origin, "bob", NEW).await.0, 200);
    assert_eq!(
        client
            .get(format!("{origin}/api/v1/users"))
            .bearer_auth(&bob_session)
            .send()
            .await
            .unwrap()
            .status(),
        200,
        "the current session remains usable"
    );

    let disabled = client
        .put(format!("{origin}/api/v1/users/{user_id}/disabled"))
        .bearer_auth(&session)
        .json(&json!({"disabled": true}))
        .send()
        .await
        .unwrap();
    assert_eq!(disabled.status(), 200);
    assert_eq!(login(&client, &origin, "bob", NEW).await.0, 401);
    assert_eq!(
        client
            .get(format!("{origin}/api/v1/users"))
            .bearer_auth(&bob_session)
            .send()
            .await
            .unwrap()
            .status(),
        401
    );
    let users: Value = client
        .get(format!("{origin}/api/v1/users"))
        .bearer_auth(&session)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(
        users
            .as_array()
            .unwrap()
            .iter()
            .any(|user| user["id"] == user_id && user["disabled"] == true)
    );

    assert_eq!(
        client
            .put(format!("{origin}/api/v1/users/{user_id}/disabled"))
            .bearer_auth(&session)
            .json(&json!({"disabled": false}))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(login(&client, &origin, "bob", NEW).await.0, 200);
    assert_eq!(
        client
            .post(format!("{origin}/api/v1/users/{user_id}/password"))
            .bearer_auth(&session)
            .json(&json!({"password": "another-password-29x!"}))
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(login(&client, &origin, "bob", NEW).await.0, 401);
    assert_eq!(
        client
            .delete(format!("{origin}/api/v1/users/{user_id}"))
            .bearer_auth(&session)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        login(&client, &origin, "bob", "another-password-29x!")
            .await
            .0,
        401
    );
    stop.cancel();
    tokio::time::sleep(Duration::from_millis(50)).await;
}
