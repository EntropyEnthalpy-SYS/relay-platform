//! Cross-panel sharing: two panels over HTTP, the owner node's engine running
//! the shared rule, and the statements both sides keep.
mod common;
use common::*;
use relay_platform::{
    api::{self, AppState},
    engine::Engine,
    federation::{self as fed, PeerError, RedeemRequest, Redeemed, RulesRequest, Statement},
    model::*,
    store::{Actor, Rejection, Store},
};
use reqwest::{Method, StatusCode};
use serde_json::{Value, json};
use std::net::SocketAddr;
use tokio::net::{TcpListener, TcpStream};
use tokio_util::sync::CancellationToken;

fn rejection<T: std::fmt::Debug>(result: anyhow::Result<T>) -> u16 {
    result
        .unwrap_err()
        .downcast_ref::<Rejection>()
        .unwrap()
        .status
}
fn input<T: serde::de::DeserializeOwned>(value: Value) -> T {
    serde_json::from_value(value).unwrap()
}
fn panel(path: &std::path::Path) -> (Store, Actor) {
    let store = Store::open(path).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    (store, admin)
}
async fn serve(store: Store) -> (String, CancellationToken) {
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
    (format!("http://{address}"), stop)
}
async fn call(
    client: &reqwest::Client,
    method: Method,
    url: &str,
    token: &str,
    body: Option<Value>,
) -> (StatusCode, Value) {
    let mut request = client.request(method, url).bearer_auth(token);
    if let Some(body) = body {
        request = request.json(&body);
    }
    let response = request.send().await.unwrap();
    let status = response.status();
    (status, response.json().await.unwrap_or(Value::Null))
}
async fn login(client: &reqwest::Client, origin: &str) -> String {
    let body: Value = client
        .post(format!("{origin}/api/v1/auth/login"))
        .json(&json!({"username": "admin", "password": PASSWORD}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    body["token"].as_str().unwrap().into()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn a_share_runs_on_the_owner_node_within_its_limits_until_revoked() {
    let echo = tcp_echo().await;
    let temp = tempfile::tempdir().unwrap();
    let (owner, admin) = panel(&temp.path().join("owner.db"));
    let (receiver, receiver_admin) = panel(&temp.path().join("receiver.db"));
    let (node, _) = owner.create_node(&admin, "default", "tokyo").unwrap();
    let (owner_origin, owner_stop) = serve(owner.clone()).await;
    let (receiver_origin, receiver_stop) = serve(receiver.clone()).await;
    let client = reqwest::Client::new();
    let owner_token = login(&client, &owner_origin).await;
    let receiver_token = login(&client, &receiver_origin).await;
    let at_owner = |path: &str| format!("{owner_origin}/api/v1/federation/{path}");
    let at_receiver = |path: &str| format!("{receiver_origin}/api/v1/federation/{path}");
    // `free_address` leaves the next three ports for the test.
    let port = free_address().port();
    let share = json!({
        "name": "Partner", "node_id": node.id, "public_host": "tyo.example.com",
        "listen_ip": "127.0.0.1", "port_start": port, "port_end": port + 2,
        "max_rules": 2, "kinds": ["forward"], "rate_bytes_per_sec": 1 << 20,
        "expires_at_ms": now_ms() + 86_400_000, "allow_sources": ["127.0.0.1"],
        "allow_private_destinations": true,
    });

    let (status, _) = call(
        &client,
        Method::POST,
        &at_owner("grants"),
        &owner_token,
        Some(share.clone()),
    )
    .await;
    assert_eq!(status, 409, "off until switched on");
    owner.set_feature(&admin, "federation", true).unwrap();
    receiver
        .set_feature(&receiver_admin, "federation", true)
        .unwrap();
    let (status, grant) = call(
        &client,
        Method::POST,
        &at_owner("grants"),
        &owner_token,
        Some(share.clone()),
    )
    .await;
    assert_eq!(status, 200, "{grant}");
    let grant_id = grant["id"].as_str().unwrap().to_string();

    // The shared ports stay free of other rules and shares.
    let mut squatter = rule(echo.address, Protocol::Tcp);
    squatter.listen = SocketAddr::from(([127, 0, 0, 1], port + 1));
    let revision = owner.config(&admin, &node.id, None).unwrap().revision;
    assert_eq!(
        rejection(owner.set_config(&admin, &node.id, revision, vec![squatter])),
        400
    );
    let mut overlapping = share.clone();
    overlapping["port_start"] = (port + 2).into();
    overlapping["port_end"] = (port + 2).into();
    overlapping["max_rules"] = 1.into();
    let (status, _) = call(
        &client,
        Method::POST,
        &at_owner("grants"),
        &owner_token,
        Some(overlapping),
    )
    .await;
    assert_eq!(status, 409);

    // A one-time invite gives the receiver its own secret.
    let invite = json!({"owner_url": format!("{owner_origin}/")});
    let (status, issued) = call(
        &client,
        Method::POST,
        &at_owner(&format!("grants/{grant_id}/invite")),
        &owner_token,
        Some(invite),
    )
    .await;
    assert_eq!(status, 200, "{issued}");
    let code = issued["code"].as_str().unwrap();
    let redeem = json!({"invite": code, "label": "Tokyo"});
    let (status, remote) = call(
        &client,
        Method::POST,
        &at_receiver("remotes"),
        &receiver_token,
        Some(redeem.clone()),
    )
    .await;
    assert_eq!(status, 200, "{remote}");
    assert!(
        remote.get("secret").is_none(),
        "views never show the secret"
    );
    let remote_id = remote["id"].as_str().unwrap().to_string();
    let (status, _) = call(
        &client,
        Method::POST,
        &at_receiver("remotes"),
        &receiver_token,
        Some(redeem),
    )
    .await;
    assert_eq!(status, 409, "an invite works once");

    // The receiver cannot widen the share.
    let rules_url = at_receiver(&format!("remotes/{remote_id}/rules"));
    let revision = remote["shared"]["revision"].as_u64().unwrap();
    let ask = |port: u16, kind: &str| {
        let targets = if kind == "forward" {
            json!([echo.address.to_string()])
        } else {
            json!([])
        };
        json!({"expected_revision": revision, "rules": [
            {"name": "web", "kind": kind, "protocol": "tcp", "port": port, "targets": targets}
        ]})
    };
    for (body, why) in [
        (ask(port + 3, "forward"), "outside the range"),
        (ask(port, "shadowsocks"), "a kind the share does not allow"),
    ] {
        let (status, _) = call(
            &client,
            Method::PUT,
            &rules_url,
            &receiver_token,
            Some(body),
        )
        .await;
        assert_eq!(status, 403, "{why}");
    }
    let (status, remote) = call(
        &client,
        Method::PUT,
        &rules_url,
        &receiver_token,
        Some(ask(port, "forward")),
    )
    .await;
    assert_eq!(status, 200, "{remote}");
    assert_eq!(remote["shared"]["rules"].as_array().unwrap().len(), 1);
    let (status, _) = call(
        &client,
        Method::PUT,
        &rules_url,
        &receiver_token,
        Some(ask(port, "forward")),
    )
    .await;
    assert_eq!(status, 409, "a stale revision is refused");

    // The owner's node carries the rule with every limit of the share.
    let config = owner.config(&admin, &node.id, None).unwrap();
    let [shared] = config.rules.as_slice() else {
        panic!("{:?}", config.rules)
    };
    assert!(shared.id.starts_with("fed-") && shared.enabled);
    assert_eq!(shared.owner_id, grant["user_id"].as_str().unwrap());
    assert_eq!(shared.listen, SocketAddr::from(([127, 0, 0, 1], port)));
    assert_eq!(shared.rate_bytes_per_sec, Some(1 << 20));
    assert_eq!(shared.expires_at_ms, share["expires_at_ms"].as_i64());
    assert_eq!(shared.allow_sources, vec!["127.0.0.1/32".parse().unwrap()]);

    // The owner's own publishes can neither change nor drop it.
    let mut edited = config.rules.clone();
    edited[0].listen = SocketAddr::from(([127, 0, 0, 1], port + 1));
    edited[0].allow_sources.clear();
    let after_edit = owner
        .set_config(&admin, &node.id, config.revision, edited)
        .unwrap();
    assert_eq!(after_edit.rules, config.rules);
    let after_drop = owner
        .set_config(&admin, &node.id, after_edit.revision, vec![])
        .unwrap();
    assert_eq!(after_drop.rules, config.rules);

    // The node's engine forwards it.
    let engine = Engine::new(Store::open(&temp.path().join("agent.db")).unwrap());
    engine.apply(after_drop).await.unwrap();
    let address = SocketAddr::from(([127, 0, 0, 1], port));
    assert_eq!(exchange(address, b"shared").await, b"shared");

    // Pausing disables the rule and freezes the receiver's rules.
    let (status, _) = call(
        &client,
        Method::POST,
        &at_owner(&format!("grants/{grant_id}/pause")),
        &owner_token,
        None,
    )
    .await;
    assert_eq!(status, 200);
    let paused = owner.config(&admin, &node.id, None).unwrap();
    assert!(!paused.rules[0].enabled);
    let (status, synced) = call(
        &client,
        Method::POST,
        &at_receiver(&format!("remotes/{remote_id}/sync")),
        &receiver_token,
        None,
    )
    .await;
    assert_eq!(
        (status, synced["shared"]["state"].as_str()),
        (StatusCode::OK, Some("paused"))
    );
    let mut body = ask(port + 1, "forward");
    body["expected_revision"] = synced["shared"]["revision"].clone();
    let (status, _) = call(
        &client,
        Method::PUT,
        &rules_url,
        &receiver_token,
        Some(body),
    )
    .await;
    assert_eq!(status, 409);
    let (status, _) = call(
        &client,
        Method::POST,
        &at_owner(&format!("grants/{grant_id}/resume")),
        &owner_token,
        None,
    )
    .await;
    assert_eq!(status, 200);
    assert!(owner.config(&admin, &node.id, None).unwrap().rules[0].enabled);

    // Revoking removes the rule, the listener closes and the secret stops working.
    let (status, _) = call(
        &client,
        Method::DELETE,
        &at_owner(&format!("grants/{grant_id}")),
        &owner_token,
        None,
    )
    .await;
    assert_eq!(status, 409, "only revoked shares are deleted");
    let (status, _) = call(
        &client,
        Method::POST,
        &at_owner(&format!("grants/{grant_id}/revoke")),
        &owner_token,
        None,
    )
    .await;
    assert_eq!(status, 200);
    let revoked = owner.config(&admin, &node.id, None).unwrap();
    assert!(revoked.rules.is_empty());
    engine.apply(revoked).await.unwrap();
    assert!(TcpStream::connect(address).await.is_err());
    let (status, synced) = call(
        &client,
        Method::POST,
        &at_receiver(&format!("remotes/{remote_id}/sync")),
        &receiver_token,
        None,
    )
    .await;
    assert_eq!((status, &synced["revoked"]), (StatusCode::OK, &json!(true)));
    let secret = receiver
        .federation_remote(&receiver_admin, &remote_id)
        .unwrap()
        .secret;
    let (status, _) = call(&client, Method::GET, &at_owner("peer/grant"), &secret, None).await;
    assert_eq!(status, 401);

    // The switch stays on while anything still uses it.
    assert_eq!(
        rejection(receiver.set_feature(&receiver_admin, "federation", false)),
        409
    );
    let (status, _) = call(
        &client,
        Method::DELETE,
        &at_owner(&format!("grants/{grant_id}")),
        &owner_token,
        None,
    )
    .await;
    assert_eq!(status, 200);
    owner.set_feature(&admin, "federation", false).unwrap();
    engine.shutdown().await.unwrap();
    owner_stop.cancel();
    receiver_stop.cancel();
}

#[test]
fn statements_follow_the_owner_counters_and_receivers_flag_lower_ones() {
    let temp = tempfile::tempdir().unwrap();
    let (owner, admin) = panel(&temp.path().join("owner.db"));
    let (receiver, receiver_admin) = panel(&temp.path().join("receiver.db"));
    let (node, _) = owner.create_node(&admin, "default", "tokyo").unwrap();
    let ledger = owner
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
    owner.set_feature(&admin, "federation", true).unwrap();
    receiver
        .set_feature(&receiver_admin, "federation", true)
        .unwrap();
    let grant = owner
        .create_federation_grant(
            &admin,
            input(json!({
                "name": "Proxy", "node_id": node.id, "public_host": "203.0.113.7",
                "port_start": 21000, "port_end": 21009, "max_rules": 1,
                "kinds": ["shadowsocks"], "quota_bytes": 64 << 20,
            })),
        )
        .unwrap();
    assert_eq!(
        rejection(owner.delete_user(&admin, &grant.user_id)),
        409,
        "a share's account stays with the share"
    );
    let budget = owner
        .budgets(&admin)
        .unwrap()
        .budgets
        .into_iter()
        .find(|b| b.scope_id == grant.user_id)
        .expect("the traffic limit is a budget of the share's account");
    assert_eq!(budget.limit_bytes, 64 << 20);
    let mut no_limit = json!({
        "name": "Proxy", "public_host": "203.0.113.7", "port_start": 21000,
        "port_end": 21009, "max_rules": 1, "kinds": ["shadowsocks"],
    });
    assert_eq!(
        rejection(owner.update_federation_grant(&admin, &grant.id, input(no_limit.clone()))),
        409,
        "a limit cannot be removed"
    );
    no_limit["quota_bytes"] = json!(128 << 20);
    owner
        .update_federation_grant(&admin, &grant.id, input(no_limit))
        .unwrap();

    let issued = owner
        .invite_federation_grant(&admin, &grant.id, "http://127.0.0.1:9/")
        .unwrap();
    let (_, invite_id, invite_secret) = fed::parse_invite(&issued.code).unwrap();
    let redeemed = owner
        .redeem_federation_invite(RedeemRequest {
            invite_id,
            invite_secret,
            panel_id: "receiver-panel".into(),
        })
        .unwrap();
    let secret = redeemed.secret.clone();
    let shared = owner
        .peer_federation_rules(
            &secret,
            RulesRequest {
                expected_revision: redeemed.shared.revision,
                rules: vec![input(json!({
                    "name": "phones", "kind": "shadowsocks", "protocol": "tcp", "port": 21003,
                }))],
            },
        )
        .unwrap();
    assert!(shared.rules[0].password.is_some() && !shared.applied);
    let config = owner.config(&admin, &node.id, None).unwrap();
    let rule = &config.rules[0];
    assert_eq!(rule.budget_ids, vec![budget.id.clone()]);
    assert!(rule.deny_destinations.contains(&"10.0.0.0/8".to_string()));
    assert!(
        !rule
            .inbound_shadowsocks
            .as_ref()
            .unwrap()
            .allow_private_destinations
    );

    // The node applies the share and reports its traffic.
    owner
        .sync(
            &node.id,
            SyncRequest {
                logs: None,
                lease: None,
                budget: None,
                ledger_id: ledger,
                need_config: false,
                applied_revision: config.revision,
                apply_error: None,
                usage: vec![Usage {
                    rule_id: rule.id.clone(),
                    meter_epoch: rule.meter_epoch.clone(),
                    sequence: 1,
                    upload_bytes: 1000,
                    download_bytes: 3000,
                }],
                stats: EngineStats::default(),
            },
        )
        .unwrap();
    let statement = owner.peer_federation_grant(&secret).unwrap();
    assert!(statement.applied);
    assert_eq!(
        (
            statement.statement.upload_bytes,
            statement.statement.download_bytes
        ),
        (1000, 3000)
    );

    // A receiver that confirmed more than the owner now shows is flagged on
    // the owner's side.
    owner
        .peer_federation_ack(
            &secret,
            Statement {
                as_of_ms: now_ms(),
                upload_bytes: 5000,
                download_bytes: 0,
            },
        )
        .unwrap();
    let view = owner.federation(&admin).unwrap();
    assert!(view.grants[0].ack_mismatch);
    assert!(
        view.grants[0]
            .grant
            .link
            .as_ref()
            .unwrap()
            .secret_sha256
            .is_empty(),
        "views carry no secret hashes"
    );

    // The receiver keeps the highest statement and flags a lower one.
    let remote = receiver
        .add_federation_remote(
            &receiver_admin,
            "http://127.0.0.1:9/",
            "",
            Redeemed {
                secret,
                shared: statement.clone(),
            },
        )
        .unwrap();
    assert_eq!(remote.label, "Proxy");
    let mut lower = statement.clone();
    lower.statement.download_bytes = 0;
    let after = receiver
        .record_federation_remote(&remote.id, Ok(lower))
        .unwrap();
    assert!(after.rollback && after.high.total() == 4000);
    let after = receiver
        .record_federation_remote(
            &remote.id,
            Err(PeerError {
                revoked: true,
                status: Some(401),
                message: "revoked".into(),
            }),
        )
        .unwrap();
    assert!(after.revoked && after.rollback);
    assert!(receiver.federation_remote_ids().unwrap().is_empty());
}
