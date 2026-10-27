mod common;
use common::{PASSWORD, rule};
use relay_platform::{
    api::{self, AppState},
    model::Protocol,
    store::Store,
};
use serde_json::{Value, json};
use std::net::SocketAddr;
use tokio::net::TcpListener;
use tokio_util::sync::CancellationToken;

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
async fn prometheus_metrics_expose_node_counters_to_a_viewer() {
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let (node, _) = store
        .create_node(&admin, "default", "metrics-node")
        .unwrap();
    let node_id = node.id.clone();
    let revision = store.set_config(&admin, &node.id, 0, vec![]).unwrap();
    store
        .set_config(
            &admin,
            &node.id,
            revision.revision,
            vec![rule("127.0.0.1:9".parse().unwrap(), Protocol::Tcp)],
        )
        .unwrap();
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
    let login: Value = client
        .post(format!("{origin}/api/v1/auth/login"))
        .json(&json!({"username": "viewer", "password": PASSWORD}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let token = login["token"].as_str().unwrap();
    let response = client
        .get(format!("{origin}/api/v1/metrics"))
        .bearer_auth(token)
        .send()
        .await
        .unwrap();
    assert_eq!(response.status(), reqwest::StatusCode::OK);
    assert!(
        response.headers()["content-type"]
            .to_str()
            .unwrap()
            .starts_with("text/plain")
    );
    let body = response.text().await.unwrap();
    assert!(body.contains("relay_build_info{version=\""));
    assert!(body.contains(&format!("relay_node_up{{node=\"{node_id}\"")));
    assert!(body.contains(&format!("relay_node_active_tcp{{node=\"{node_id}\"}} 0")));
    assert!(body.contains(&format!("relay_node_active_udp{{node=\"{node_id}\"}} 0")));
    assert!(body.contains(&format!(
        "relay_node_accepted_tcp_total{{node=\"{node_id}\"}} 0"
    )));
    stop.cancel();
}
