mod common;
use common::*;
use relay_platform::{
    api::{self, AppState},
    dns::{self, HealthGate, ProviderKind, RecordType, ZoneMode},
    store::{Rejection, Store},
};
use serde_json::{Value, json};
use std::{net::SocketAddr, sync::Arc};
use tokio::{net::TcpListener, sync::Mutex};
use tokio_util::sync::CancellationToken;

#[derive(Clone, Debug)]
struct Remote {
    id: String,
    name: String,
    record_type: String,
    content: String,
    ttl: u32,
    proxied: bool,
    comment: Option<String>,
}
#[derive(Clone)]
struct Mock {
    records: Arc<Mutex<Vec<Remote>>>,
    next: Arc<Mutex<u64>>,
}
async fn mock_cloudflare(_zone: &str) -> (Mock, String, CancellationToken) {
    use axum::{
        Json, Router,
        extract::{Path, State},
        http::{HeaderMap, StatusCode},
        routing::get,
    };
    let mock = Mock {
        records: Arc::new(Mutex::new(vec![])),
        next: Arc::new(Mutex::new(1)),
    };
    let state = mock.clone();
    fn auth(headers: &HeaderMap) -> bool {
        headers.get("authorization").and_then(|v| v.to_str().ok()) == Some("Bearer test-token")
    }
    let list = |State(mock): State<Mock>, headers: HeaderMap| async move {
        if !auth(&headers) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(
                    json!({"success":false,"errors":[{"code":10000,"message":"auth"}],"result":null}),
                ),
            );
        }
        let records: Vec<Value> = mock
            .records
            .lock()
            .await
            .iter()
            .map(|record| {
                json!({
                    "id": record.id, "name": record.name, "type": record.record_type,
                    "content": record.content, "ttl": record.ttl, "proxied": record.proxied,
                    "comment": record.comment,
                })
            })
            .collect();
        (
            StatusCode::OK,
            Json(json!({"success":true,"errors":[],"result":records})),
        )
    };
    let create = |State(mock): State<Mock>, headers: HeaderMap, Json(body): Json<Value>| async move {
        if !auth(&headers) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(
                    json!({"success":false,"errors":[{"code":10000,"message":"auth"}],"result":null}),
                ),
            );
        }
        let mut next = mock.next.lock().await;
        let id = format!("remote-{}", *next);
        *next += 1;
        let record = Remote {
            id: id.clone(),
            name: body["name"].as_str().unwrap().into(),
            record_type: body["type"].as_str().unwrap().into(),
            content: body["content"].as_str().unwrap().into(),
            ttl: body["ttl"].as_u64().unwrap() as u32,
            proxied: body["proxied"].as_bool().unwrap_or(false),
            comment: body["comment"].as_str().map(str::to_owned),
        };
        mock.records.lock().await.push(record.clone());
        (
            StatusCode::OK,
            Json(json!({"success":true,"errors":[],"result":{
            "id": record.id, "name": record.name, "type": record.record_type,
            "content": record.content, "ttl": record.ttl, "proxied": record.proxied,
            "comment": record.comment}})),
        )
    };
    let update = |State(mock): State<Mock>,
                  Path((_zone, id)): Path<(String, String)>,
                  headers: HeaderMap,
                  Json(body): Json<Value>| async move {
        if !auth(&headers) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(
                    json!({"success":false,"errors":[{"code":10000,"message":"auth"}],"result":null}),
                ),
            );
        }
        let mut records = mock.records.lock().await;
        let Some(record) = records.iter_mut().find(|record| record.id == id) else {
            return (
                StatusCode::NOT_FOUND,
                Json(
                    json!({"success":false,"errors":[{"code":81044,"message":"not found"}],"result":null}),
                ),
            );
        };
        record.name = body["name"].as_str().unwrap().into();
        record.record_type = body["type"].as_str().unwrap().into();
        record.content = body["content"].as_str().unwrap().into();
        record.ttl = body["ttl"].as_u64().unwrap() as u32;
        record.proxied = body["proxied"].as_bool().unwrap_or(false);
        record.comment = body["comment"].as_str().map(str::to_owned);
        let result = record.clone();
        (
            StatusCode::OK,
            Json(json!({"success":true,"errors":[],"result":{
            "id": result.id, "name": result.name, "type": result.record_type,
            "content": result.content, "ttl": result.ttl, "proxied": result.proxied,
            "comment": result.comment}})),
        )
    };
    let delete = |State(mock): State<Mock>,
                  Path((_zone, id)): Path<(String, String)>,
                  headers: HeaderMap| async move {
        if !auth(&headers) {
            return (
                StatusCode::UNAUTHORIZED,
                Json(
                    json!({"success":false,"errors":[{"code":10000,"message":"auth"}],"result":null}),
                ),
            );
        }
        mock.records.lock().await.retain(|record| record.id != id);
        (
            StatusCode::OK,
            Json(json!({"success":true,"errors":[],"result":{"id":id}})),
        )
    };
    let app = Router::new()
        .route(
            "/client/v4/zones/{zone}/dns_records",
            get(list).post(create),
        )
        .route(
            "/client/v4/zones/{zone}/dns_records/{id}",
            axum::routing::put(update).delete(delete),
        )
        .with_state(state);
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    let stop = CancellationToken::new();
    let shutdown = stop.clone();
    tokio::spawn(async move {
        axum::serve(listener, app)
            .with_graceful_shutdown(shutdown.cancelled_owned())
            .await
            .unwrap();
    });
    (mock, format!("http://{address}/client/v4"), stop)
}
fn rejection(error: anyhow::Error) -> u16 {
    error.downcast_ref::<Rejection>().unwrap().status
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_apply_observe_min_keep_and_provider_isolation_are_real() {
    let (_mock, endpoint, stop) = mock_cloudflare("example.com").await;
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let tenant_admin = store
        .create_user(
            &admin,
            "default",
            "tenant-admin",
            PASSWORD,
            relay_platform::store::Role::TenantAdmin,
        )
        .unwrap();
    assert_eq!(
        rejection(store.dns_providers(&tenant_admin).unwrap_err()),
        403
    );
    let provider = store
        .create_dns_provider(
            &admin,
            "fixture",
            ProviderKind::Cloudflare,
            &endpoint,
            "test-token",
        )
        .unwrap();
    assert!(provider.token_set);
    assert!(
        !serde_json::to_string(&provider)
            .unwrap()
            .contains("test-token")
    );
    let zone = store
        .create_dns_zone(&admin, &provider.id, "example.com", ZoneMode::Apply, 1)
        .unwrap();
    let first = store
        .create_dns_record(
            &admin,
            &zone.id,
            relay_platform::store::NewDnsRecord {
                name: "edge.example.com".into(),
                record_type: RecordType::A,
                content: "203.0.113.10".into(),
                ttl: 300,
                proxied: false,
                health: None,
            },
        )
        .unwrap();
    let second = store
        .create_dns_record(
            &admin,
            &zone.id,
            relay_platform::store::NewDnsRecord {
                name: "edge2.example.com".into(),
                record_type: RecordType::A,
                content: "203.0.113.11".into(),
                ttl: 300,
                proxied: false,
                health: None,
            },
        )
        .unwrap();
    let http = reqwest::Client::new();
    let first_run = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!(first_run.created, 2, "{first_run:?}");
    assert_eq!(first_run.errors, 0);
    assert_eq!(_mock.records.lock().await.len(), 2);
    let synced = store.dns_record(&admin, &first.id).unwrap();
    assert!(synced.provider_record_id.is_some());
    let second_run = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!(second_run.unchanged, 2, "{second_run:?}");

    // A content change is applied only after a reconcile.
    store
        .update_dns_record(
            &admin,
            &first.id,
            relay_platform::store::DnsRecordPatch {
                content: Some("203.0.113.12".into()),
                ..Default::default()
            },
        )
        .unwrap();
    let changed = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!(changed.updated, 1, "{changed:?}");
    assert!(
        _mock
            .records
            .lock()
            .await
            .iter()
            .any(|record| record.content == "203.0.113.12")
    );

    // Observation mode reports without writing or assigning a provider ID.
    let observe = store
        .create_dns_zone(&admin, &provider.id, "example.com", ZoneMode::Observe, 1)
        .unwrap();
    let probe = store
        .create_dns_record(
            &admin,
            &observe.id,
            relay_platform::store::NewDnsRecord {
                name: "probe.example.com".into(),
                record_type: RecordType::A,
                content: "203.0.113.20".into(),
                ttl: 300,
                proxied: false,
                health: None,
            },
        )
        .unwrap();
    let observed = dns::reconcile(&store, &http, &observe.id).await.unwrap();
    assert_eq!(observed.created, 1);
    assert!(
        observed
            .actions
            .iter()
            .any(|action| action.action == "would-create")
    );
    assert!(
        _mock
            .records
            .lock()
            .await
            .iter()
            .all(|record| record.content != "203.0.113.20")
    );
    assert!(
        store
            .dns_record(&admin, &probe.id)
            .unwrap()
            .provider_record_id
            .is_none()
    );

    // Disabling a record with min_keep=2 keeps it; min_keep=1 removes it.
    store
        .update_dns_zone(&admin, &zone.id, None, None, Some(2))
        .unwrap();
    store
        .update_dns_record(
            &admin,
            &second.id,
            relay_platform::store::DnsRecordPatch {
                enabled: Some(false),
                ..Default::default()
            },
        )
        .unwrap();
    let kept = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!(kept.kept, 1, "{kept:?}");
    assert_eq!(_mock.records.lock().await.len(), 2);
    store
        .update_dns_zone(&admin, &zone.id, None, None, Some(1))
        .unwrap();
    let deleted = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!(deleted.deleted, 1, "{deleted:?}");
    assert_eq!(_mock.records.lock().await.len(), 1);
    stop.cancel();
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
    assert!(body["token"].is_string(), "{body}");
    body["token"].as_str().unwrap().into()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_health_gate_removes_an_entry_and_restores_it_after_recovery() {
    let (_mock, endpoint, stop) = mock_cloudflare("example.com").await;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("controller.db");
    let store = Store::open(&path).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let (node, _enrollment) = store.create_node(&admin, "default", "edge").unwrap();
    let provider = store
        .create_dns_provider(
            &admin,
            "fixture",
            ProviderKind::Cloudflare,
            &endpoint,
            "test-token",
        )
        .unwrap();
    let zone = store
        .create_dns_zone(&admin, &provider.id, "example.com", ZoneMode::Apply, 0)
        .unwrap();
    let record = store
        .create_dns_record(
            &admin,
            &zone.id,
            relay_platform::store::NewDnsRecord {
                name: "edge.example.com".into(),
                record_type: RecordType::A,
                content: "203.0.113.40".into(),
                ttl: 300,
                proxied: false,
                health: Some(HealthGate {
                    node_id: node.id.clone(),
                    rule_id: "entry".into(),
                }),
            },
        )
        .unwrap();
    let http = reqwest::Client::new();
    // No fresh observation: the gate fails closed and creates nothing.
    let cold = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!(cold.created, 0, "{cold:?}");
    assert!(_mock.records.lock().await.is_empty());

    let set_health = |status: &str, eligible: bool, seen: i64| {
        let stats = json!({
            "active_tcp": 0, "active_udp": 0, "accepted_tcp": 0,
            "rejected_connections": 0, "failed_connections": 0,
            "dropped_datagrams": 0, "forwarded_upload_bytes": 0,
            "forwarded_download_bytes": 0,
            "target_health": [{
                "probe_kind": "tcp_connect", "rule_id": "entry", "target_index": 0,
                "listen_port": 443, "protocol": "tcp", "target_address": "127.0.0.1:9",
                "status": status, "eligible": eligible, "selection_reason": if eligible { "eligible" } else { "unhealthy" },
                "sample_age_ms": 10, "max_age_ms": 5000, "checked_at_ms": relay_platform::model::now_ms(),
                "latency_ewma_us": 1000, "window_checks": 1, "window_failures": if eligible { 0 } else { 1 },
                "jitter_us": null, "consecutive_successes": if eligible { 1 } else { 0 },
                "consecutive_failures": if eligible { 0 } else { 1 }, "completed_checks": 1,
                "successful_checks": if eligible { 1 } else { 0 }, "last_error": null,
                "probe_sent_bytes": 0, "probe_received_bytes": 0, "priority": 0,
                "active_sessions": 0, "max_sessions": null
            }]
        });
        let connection = rusqlite::Connection::open(&path).unwrap();
        connection
            .execute(
                "UPDATE nodes SET last_seen_ms=?1,stats_json=?2 WHERE id=?3",
                rusqlite::params![seen, stats.to_string(), node.id],
            )
            .unwrap();
    };
    set_health("healthy", true, relay_platform::model::now_ms());
    let healthy = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!(healthy.created, 1, "{healthy:?}");
    assert_eq!(_mock.records.lock().await.len(), 1);

    set_health("unhealthy", false, relay_platform::model::now_ms());
    let removed = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!(removed.deleted, 1, "{removed:?}");
    assert!(
        removed
            .actions
            .iter()
            .any(|action| action.action == "health-remove")
    );
    assert!(_mock.records.lock().await.is_empty());
    assert!(store.dns_record(&admin, &record.id).unwrap().enabled);

    set_health("healthy", true, relay_platform::model::now_ms());
    let restored = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!(restored.created, 1, "{restored:?}");

    // A stale heartbeat fails closed even when the last report was healthy.
    set_health("healthy", true, relay_platform::model::now_ms() - 120_000);
    let stale = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!(stale.deleted, 1, "{stale:?}");
    assert!(_mock.records.lock().await.is_empty());

    set_health("healthy", true, relay_platform::model::now_ms());
    let recovered = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!(recovered.created, 1, "{recovered:?}");

    // Clearing the gate stops health-based removal.
    store
        .update_dns_record(
            &admin,
            &record.id,
            relay_platform::store::DnsRecordPatch {
                clear_health: true,
                ..Default::default()
            },
        )
        .unwrap();
    set_health(
        "unhealthy",
        false,
        relay_platform::model::now_ms() - 120_000,
    );
    let ungated = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!(ungated.deleted, 0, "{ungated:?}");
    assert_eq!(_mock.records.lock().await.len(), 1);
    stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_http_routes_are_admin_only_and_apply_through_a_public_client() {
    let (mock, endpoint, mock_stop) = mock_cloudflare("example.com").await;
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    let _tenant_admin = store
        .create_user(
            &admin,
            "default",
            "tenant-admin",
            PASSWORD,
            relay_platform::store::Role::TenantAdmin,
        )
        .unwrap();
    let (address, stop) = serve(store).await;
    let origin = format!("http://{address}");
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let session = login(&client, &origin, "admin").await;
    let tenant_session = login(&client, &origin, "tenant-admin").await;

    let denied = client
        .get(format!("{origin}/api/v1/dns/providers"))
        .bearer_auth(&tenant_session)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);
    let token_body: Value = client
        .post(format!("{origin}/api/v1/api-tokens"))
        .bearer_auth(&session)
        .json(&json!({"name": "dns-denied", "scopes": ["users:write"], "expires_in_days": 1}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let api_token = token_body["token"].as_str().unwrap();
    assert_eq!(
        client
            .get(format!("{origin}/api/v1/dns/providers"))
            .bearer_auth(api_token)
            .send()
            .await
            .unwrap()
            .status(),
        403,
        "DNS management must remain session-only"
    );

    let provider: Value = client
        .post(format!("{origin}/api/v1/dns/providers"))
        .bearer_auth(&session)
        .json(&json!({"name": "fixture", "kind": "cloudflare", "endpoint": endpoint, "token": "test-token"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert!(provider["token_set"].as_bool().unwrap());
    assert!(provider.get("token").is_none());
    let provider_id = provider["id"].as_str().unwrap();
    let zone: Value = client
        .post(format!("{origin}/api/v1/dns/zones"))
        .bearer_auth(&session)
        .json(&json!({"provider_id": provider_id, "name": "example.com", "mode": "apply", "min_keep": 1}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let zone_id = zone["id"].as_str().unwrap();
    let record: Value = client
        .post(format!("{origin}/api/v1/dns/zones/{zone_id}/records"))
        .bearer_auth(&session)
        .json(&json!({"name": "edge.example.com", "type": "A", "content": "203.0.113.30", "ttl": 300}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    let record_id = record["id"].as_str().unwrap();
    let reconciled: Value = client
        .post(format!("{origin}/api/v1/dns/zones/{zone_id}/reconcile"))
        .bearer_auth(&session)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(reconciled["created"], 1, "{reconciled}");
    assert_eq!(mock.records.lock().await.len(), 1);
    let ddns: Value = client
        .post(format!("{origin}/api/v1/dns/records/{record_id}/ddns"))
        .bearer_auth(&session)
        .json(&json!({"content": "203.0.113.31"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(ddns["updated"], 1, "{ddns}");
    assert!(
        mock.records
            .lock()
            .await
            .iter()
            .any(|record| record.content == "203.0.113.31")
    );
    let deleted = client
        .delete(format!("{origin}/api/v1/dns/records/{record_id}"))
        .bearer_auth(&session)
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), 200);
    assert!(mock.records.lock().await.is_empty());
    assert_eq!(
        client
            .delete(format!("{origin}/api/v1/dns/zones/{zone_id}"))
            .bearer_auth(&session)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    assert_eq!(
        client
            .delete(format!("{origin}/api/v1/dns/providers/{provider_id}"))
            .bearer_auth(&session)
            .send()
            .await
            .unwrap()
            .status(),
        200
    );
    stop.cancel();
    mock_stop.cancel();
}

#[test]
fn dns_inputs_are_bounded_and_endpoints_reject_plaintext_remote_hosts() {
    assert!(dns::validate_endpoint("http://127.0.0.1:9000/client/v4").is_ok());
    assert!(dns::validate_endpoint("http://example.com/client/v4").is_err());
    assert!(dns::validate_endpoint("https://user:pass@example.com").is_err());
    assert!(dns::validate_record(RecordType::A, "bad name", "203.0.113.1", 300).is_err());
    assert!(dns::validate_record(RecordType::A, "a.example.com", "2001:db8::1", 300).is_err());
    assert!(dns::validate_record(RecordType::Aaaa, "a.example.com", "2001:db8::1", 300).is_ok());
    assert!(dns::validate_comment(Some(&"x".repeat(101))).is_err());
}
