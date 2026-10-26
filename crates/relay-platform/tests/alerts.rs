mod common;
use axum::{Router, extract::State, http::HeaderMap, routing::post};
use common::*;
use relay_platform::{
    agent::{self, AgentOptions},
    alerts,
    api::{self, AppState},
    model::*,
    store::{Role, Scope, Store, write_secret},
};
use serde_json::{Value, json};
use std::{net::SocketAddr, time::Duration};
use tokio::{
    net::TcpListener,
    sync::mpsc,
    time::{sleep, timeout},
};
use tokio_util::sync::CancellationToken;

type Received = (Option<String>, String);

async fn receiver() -> (SocketAddr, mpsc::UnboundedReceiver<Received>) {
    let (sender, received) = mpsc::unbounded_channel();
    let router = Router::new()
        .route(
            "/hook",
            post(
                |State(sender): State<mpsc::UnboundedSender<Received>>,
                 headers: HeaderMap,
                 body: String| async move {
                    let signature = headers
                        .get("x-relay-signature")
                        .map(|v| v.to_str().unwrap().to_owned());
                    sender.send((signature, body)).unwrap();
                    "ok"
                },
            ),
        )
        .with_state(sender);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
    (address, received)
}

/// The text of the next notice, after checking its signature.
async fn next(received: &mut mpsc::UnboundedReceiver<Received>) -> String {
    let (signature, body) = timeout(Duration::from_secs(10), received.recv())
        .await
        .expect("no notice arrived")
        .unwrap();
    let tag = hex(ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, b"hook-secret"),
        body.as_bytes(),
    )
    .as_ref());
    assert_eq!(signature, Some(format!("sha256={tag}")));
    serde_json::from_str::<Value>(&body).unwrap()["text"]
        .as_str()
        .unwrap()
        .to_owned()
}
fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|b| format!("{b:02x}")).collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn target_outages_notify_once_per_incident_through_signed_webhooks() {
    let temp = tempfile::tempdir().unwrap();
    let control = Store::open(&temp.path().join("controller.db")).unwrap();
    control.set_kind("controller").unwrap();
    let admin = control.bootstrap(PASSWORD).unwrap();
    let operator = control
        .create_user(&admin, "default", "operator", PASSWORD, Role::TenantAdmin)
        .unwrap();
    let (session, _) = control.login("admin", PASSWORD).unwrap();
    let (operator_session, _) = control.login(&operator.username, PASSWORD).unwrap();
    let (api_token, _) = control
        .create_api_token(&admin, "automation", &[Scope::Read, Scope::NodesWrite], 1)
        .unwrap();

    let stop = CancellationToken::new();
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let origin = format!("http://{}", listener.local_addr().unwrap());
    let router = api::router(AppState::new(control.clone()).with_shutdown(stop.clone()));
    let shutdown = stop.clone();
    tokio::spawn(async move {
        axum::serve(
            listener,
            router.into_make_service_with_connect_info::<SocketAddr>(),
        )
        .with_graceful_shutdown(shutdown.cancelled_owned())
        .await
        .unwrap()
    });
    tokio::spawn(alerts::run(
        control.clone(),
        Duration::from_millis(100),
        stop.clone(),
    ));
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let api = |path: &str| format!("{origin}/api/v1/{path}");

    // Only system administrators, in an interactive session, manage alerts.
    let status = |r: reqwest::Response| r.status().as_u16();
    let hook = receiver().await;
    let (hook_address, mut received) = hook;
    let channel = json!({"name":"ops","enabled":true,"min_severity":"warning",
        "target":{"kind":"webhook","url":format!("http://{hook_address}/hook"),"secret":"hook-secret"}});
    let get = client.get(api("alerts"));
    assert_eq!(
        status(get.bearer_auth(&operator_session).send().await.unwrap()),
        403
    );
    let post = client.post(api("alerts/channels")).json(&channel);
    assert_eq!(
        status(post.bearer_auth(&api_token).send().await.unwrap()),
        403
    );
    let created: Value = client
        .post(api("alerts/channels"))
        .bearer_auth(&session)
        .json(&channel)
        .send()
        .await
        .unwrap()
        .error_for_status()
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(created["destination"], "http://127.0.0.1/…");
    assert_eq!(created["secret_set"], true);
    let id = created["id"].as_str().unwrap().to_owned();
    let overview = client
        .get(api("alerts"))
        .bearer_auth(&session)
        .send()
        .await
        .unwrap();
    assert!(!overview.text().await.unwrap().contains("hook-secret"));

    // An edit that leaves the secret blank keeps it; the test message proves it.
    let mut edited = channel.clone();
    edited["name"] = "ops-primary".into();
    edited["target"]["secret"] = "".into();
    let put = client
        .put(api(&format!("alerts/channels/{id}")))
        .json(&edited);
    assert_eq!(status(put.bearer_auth(&session).send().await.unwrap()), 200);
    let test = client.post(api(&format!("alerts/channels/{id}/test")));
    assert_eq!(
        status(test.bearer_auth(&session).send().await.unwrap()),
        200
    );
    assert!(next(&mut received).await.contains("【测试】"));

    // A real agent forwards to a backend that fails and recovers.
    let echo = tcp_echo().await;
    let backend = echo.address;
    let (node, enrollment) = control.create_node(&admin, "default", "edge-01").unwrap();
    let mut r = rule(backend, Protocol::Tcp);
    r.health_check = Some(
        serde_json::from_value(json!({
            "interval_ms":100, "timeout_ms":60, "healthy_threshold":2,
            "unhealthy_threshold":2, "recovery_delay_ms":250, "max_age_ms":1000,
            "tcp":{"kind":"exchange","request_base64":"UElORw==","expected_base64":"UElORw==","half_close":true}
        }))
        .unwrap(),
    );
    control.set_config(&admin, &node.id, 0, vec![r]).unwrap();
    let secret_path = temp.path().join("enroll.secret");
    write_secret(&secret_path, enrollment.as_bytes()).unwrap();
    let agent_db = Store::open(&temp.path().join("agent.db")).unwrap();
    tokio::spawn(agent::run(
        agent_db,
        AgentOptions {
            controller: origin.clone(),
            node_id: node.id.clone(),
            enrollment_token_file: Some(secret_path),
            ca_certificate: None,
            tls_directory: None,
            poll_interval: Duration::from_millis(50),
        },
        stop.clone(),
    ));
    let incidents = || async {
        client
            .get(api("alerts"))
            .bearer_auth(&session)
            .send()
            .await
            .unwrap()
            .json::<Value>()
            .await
            .unwrap()["incidents"]
            .clone()
    };
    let restart = |address: SocketAddr| async move {
        // The aborted echo task releases its port shortly after the drop.
        for _ in 0..100 {
            if let Ok(listener) = TcpListener::bind(address).await {
                drop(listener);
                return tcp_echo_at(&address.to_string(), None).await;
            }
            sleep(Duration::from_millis(20)).await;
        }
        panic!("backend port never came free");
    };
    sleep(Duration::from_millis(800)).await;
    drop(echo);
    let opened = next(&mut received).await;
    assert!(opened.starts_with("【告警·警告】edge-01"), "{opened}");
    assert!(opened.contains(&backend.to_string()), "{opened}");
    let echo = restart(backend).await;
    let resolved = next(&mut received).await;
    assert!(resolved.starts_with("【已恢复】edge-01"), "{resolved}");

    // The same failure again within the hold is one incident and stays quiet.
    drop(echo);
    timeout(Duration::from_secs(10), async {
        while incidents().await["open"][0]["repeats"] != 1 {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the repeated failure never reopened the incident");
    let _echo = restart(backend).await;
    timeout(Duration::from_secs(10), async {
        while incidents().await["open"] != json!([]) {
            sleep(Duration::from_millis(50)).await;
        }
    })
    .await
    .expect("the incident never resolved");
    sleep(Duration::from_millis(500)).await;
    assert!(received.try_recv().is_err(), "a held repeat was announced");

    let log = incidents().await["deliveries"].clone();
    let kinds: Vec<_> = log
        .as_array()
        .unwrap()
        .iter()
        .map(|d| (d["notice"].as_str().unwrap(), d["status"].as_str().unwrap()))
        .collect();
    assert_eq!(
        kinds,
        [("resolved", "sent"), ("opened", "sent"), ("test", "sent")]
    );

    // Maintenance settings round-trip; deleting the channel stops deliveries.
    let settings = json!({"maintenance_until_ms": 4_102_444_799_000_i64});
    let put = client.put(api("alerts/settings")).json(&settings);
    assert_eq!(status(put.bearer_auth(&session).send().await.unwrap()), 200);
    let overview = client
        .get(api("alerts"))
        .bearer_auth(&session)
        .send()
        .await
        .unwrap();
    assert_eq!(
        overview.json::<Value>().await.unwrap()["settings"],
        settings
    );
    let delete = client.delete(api(&format!("alerts/channels/{id}")));
    assert_eq!(
        status(delete.bearer_auth(&session).send().await.unwrap()),
        200
    );
    let test = client.post(api(&format!("alerts/channels/{id}/test")));
    assert_eq!(
        status(test.bearer_auth(&session).send().await.unwrap()),
        404
    );
    stop.cancel();
}
