mod common;
use common::*;
use relay_platform::{
    api::{self, AppState},
    dns::{self, HealthGate, ProviderKind, RecordType, ZoneMode},
    store::{Rejection, Store},
};
use serde_json::{Value, json};
use std::{
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
    time::{Duration, Instant},
};
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
    /// Create, update and delete calls received.
    writes: Arc<AtomicU64>,
    /// Delay of every list response, to widen race windows.
    list_delay_ms: Arc<AtomicU64>,
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
        writes: Arc::new(AtomicU64::new(0)),
        list_delay_ms: Arc::new(AtomicU64::new(0)),
    };
    let state = mock.clone();
    fn auth(headers: &HeaderMap) -> bool {
        headers.get("authorization").and_then(|v| v.to_str().ok()) == Some("Bearer test-token")
    }
    // Like Cloudflare: proxied records always report TTL 1 ("automatic").
    fn stored_ttl(body: &Value) -> u32 {
        if body["proxied"].as_bool().unwrap_or(false) {
            1
        } else {
            body["ttl"].as_u64().unwrap() as u32
        }
    }
    // The zone list echoes a rejected token in its error, so the controller
    // must redact it.
    let zones = |headers: HeaderMap| async move {
        let presented = headers
            .get("authorization")
            .and_then(|v| v.to_str().ok())
            .and_then(|v| v.strip_prefix("Bearer "))
            .unwrap_or_default()
            .to_owned();
        if presented != "test-token" {
            return (
                StatusCode::FORBIDDEN,
                Json(
                    json!({"success":false,"errors":[{"code":9109,"message":format!("Invalid access token {presented}")}],"result":null}),
                ),
            );
        }
        (
            StatusCode::OK,
            Json(json!({"success":true,"errors":[],"result":[
                {"id":"023e105f4ecef8ad9ca31a8372d0c353","name":"example.com","status":"active"},
                {"id":"9a7806061c88ada191ed06f989cc3dac","name":"example.net","status":"active"}
            ],"result_info":{"page":1,"per_page":50,"total_pages":1}})),
        )
    };
    let list = |State(mock): State<Mock>, headers: HeaderMap| async move {
        tokio::time::sleep(Duration::from_millis(
            mock.list_delay_ms.load(Ordering::SeqCst),
        ))
        .await;
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
        mock.writes.fetch_add(1, Ordering::SeqCst);
        let mut next = mock.next.lock().await;
        let id = format!("remote-{}", *next);
        *next += 1;
        let record = Remote {
            id: id.clone(),
            name: body["name"].as_str().unwrap().into(),
            record_type: body["type"].as_str().unwrap().into(),
            content: body["content"].as_str().unwrap().into(),
            ttl: stored_ttl(&body),
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
        mock.writes.fetch_add(1, Ordering::SeqCst);
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
        record.ttl = stored_ttl(&body);
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
        mock.writes.fetch_add(1, Ordering::SeqCst);
        mock.records.lock().await.retain(|record| record.id != id);
        (
            StatusCode::OK,
            Json(json!({"success":true,"errors":[],"result":{"id":id}})),
        )
    };
    let app = Router::new()
        .route("/client/v4/zones", get(zones))
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
            0,
            Default::default(),
        )
        .unwrap();
    assert!(provider.token_set);
    assert!(
        !serde_json::to_string(&provider)
            .unwrap()
            .contains("test-token")
    );
    let zone = store
        .create_dns_zone(&admin, &provider.id, "example.com", ZoneMode::Apply, 1, 0)
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
        .create_dns_zone(&admin, &provider.id, "example.com", ZoneMode::Observe, 1, 0)
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
        .update_dns_zone(&admin, &zone.id, None, None, Some(2), None)
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
        .update_dns_zone(&admin, &zone.id, None, None, Some(1), None)
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
            0,
            Default::default(),
        )
        .unwrap();
    let zone = store
        .create_dns_zone(&admin, &provider.id, "example.com", ZoneMode::Apply, 0, 0)
        .unwrap();
    let gated = || relay_platform::store::NewDnsRecord {
        name: "edge.example.com".into(),
        record_type: RecordType::A,
        content: "203.0.113.40".into(),
        ttl: 300,
        proxied: false,
        health: Some(HealthGate {
            node_id: node.id.clone(),
            rule_id: "entry".into(),
        }),
    };
    // Health gating is an optional feature: refused until switched on.
    assert!(!store.feature_enabled("dns-health").unwrap());
    assert_eq!(
        rejection(
            store
                .create_dns_record(&admin, &zone.id, gated())
                .unwrap_err()
        ),
        409
    );
    store.set_feature(&admin, "dns-health", true).unwrap();
    let record = store.create_dns_record(&admin, &zone.id, gated()).unwrap();
    // A gated record keeps the feature on until it is removed.
    store.set_feature(&admin, "dns-health", false).unwrap_err();
    assert!(store.feature_enabled("dns-health").unwrap());
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

#[tokio::test]
async fn dns_list_follows_cloudflare_pagination() {
    async fn page(
        axum::extract::Query(params): axum::extract::Query<
            std::collections::HashMap<String, String>,
        >,
    ) -> axum::Json<Value> {
        let page: u64 = params
            .get("page")
            .and_then(|value| value.parse().ok())
            .unwrap_or(1);
        let result = if page == 1 {
            json!([{"id":"one","name":"a.example.com","type":"A","content":"192.0.2.1","ttl":120}])
        } else {
            json!([{"id":"two","name":"b.example.com","type":"A","content":"192.0.2.2","ttl":120}])
        };
        axum::Json(json!({"success":true,"errors":[],"result":result,
            "result_info":{"page":page,"per_page":100,"total_pages":2}}))
    }
    let app = axum::Router::new().route(
        "/client/v4/zones/{zone}/dns_records",
        axum::routing::get(page),
    );
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let address = listener.local_addr().unwrap();
    tokio::spawn(async move { axum::serve(listener, app).await.unwrap() });
    let provider = dns::Provider {
        id: "provider".into(),
        name: "fixture".into(),
        kind: ProviderKind::Cloudflare,
        endpoint: format!("http://{address}/client/v4"),
        token: "test-token".into(),
        min_ttl: None,
        zones: vec![],
        timeout_secs: None,
        created_at_ms: 0,
    };
    let client = dns::Cloudflare::new(reqwest::Client::new(), &provider).unwrap();
    let records = client.list("example.com").await.unwrap();
    assert_eq!(records.len(), 2);
    assert_eq!(records[0].id, "one");
    assert_eq!(records[1].id, "two");
}

/// Writes a fresh heartbeat for `node` with one health report per rule.
fn write_health(path: &std::path::Path, node: &str, rules: &[(&str, bool)]) {
    let now = relay_platform::model::now_ms();
    let reports: Vec<Value> = rules
        .iter()
        .map(|&(rule, healthy)| {
            let n = u64::from(healthy);
            json!({
                "probe_kind": "tcp_connect", "rule_id": rule, "target_index": 0,
                "listen_port": 443, "protocol": "tcp", "target_address": "127.0.0.1:9",
                "status": if healthy { "healthy" } else { "unhealthy" }, "eligible": healthy,
                "selection_reason": if healthy { "eligible" } else { "unhealthy" },
                "sample_age_ms": 10, "max_age_ms": 5000, "checked_at_ms": now,
                "latency_ewma_us": 1000, "window_checks": 1, "window_failures": 1 - n,
                "jitter_us": null, "consecutive_successes": n, "consecutive_failures": 1 - n,
                "completed_checks": 1, "successful_checks": n, "last_error": null,
                "probe_sent_bytes": 0, "probe_received_bytes": 0, "priority": 0,
                "active_sessions": 0, "max_sessions": null
            })
        })
        .collect();
    let stats = json!({
        "active_tcp": 0, "active_udp": 0, "accepted_tcp": 0,
        "rejected_connections": 0, "failed_connections": 0,
        "dropped_datagrams": 0, "forwarded_upload_bytes": 0,
        "forwarded_download_bytes": 0, "target_health": reports
    });
    rusqlite::Connection::open(path)
        .unwrap()
        .execute(
            "UPDATE nodes SET last_seen_ms=?1,stats_json=?2 WHERE id=?3",
            rusqlite::params![now, stats.to_string(), node],
        )
        .unwrap();
}
fn a_record(
    name: &str,
    content: &str,
    ttl: u32,
    health: Option<HealthGate>,
) -> relay_platform::store::NewDnsRecord {
    relay_platform::store::NewDnsRecord {
        name: name.into(),
        record_type: RecordType::A,
        content: content.into(),
        ttl,
        proxied: false,
        health,
    }
}
async fn published(mock: &Mock, content: &str) -> bool {
    mock.records
        .lock()
        .await
        .iter()
        .any(|record| record.content == content)
}
async fn wait_for<F, Fut>(what: &str, mut condition: F)
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = bool>,
{
    let deadline = Instant::now() + Duration::from_secs(20);
    while !condition().await {
        assert!(Instant::now() < deadline, "timed out waiting for {what}");
        tokio::time::sleep(Duration::from_millis(20)).await;
    }
}
/// A controller store with the health feature on, one node and a provider
/// pointing at the mock.
struct Fixture {
    _temp: tempfile::TempDir,
    path: std::path::PathBuf,
    store: Store,
    admin: relay_platform::store::Actor,
    node: String,
    provider: String,
}
fn fixture(endpoint: &str, min_ttl: u32) -> Fixture {
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("controller.db");
    let store = Store::open(&path).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    store.set_feature(&admin, "dns-health", true).unwrap();
    let (node, _enrollment) = store.create_node(&admin, "default", "edge").unwrap();
    let provider = store
        .create_dns_provider(
            &admin,
            "fixture",
            ProviderKind::Cloudflare,
            endpoint,
            "test-token",
            min_ttl,
            Default::default(),
        )
        .unwrap();
    Fixture {
        _temp: temp,
        path,
        store,
        admin,
        node: node.id,
        provider: provider.id,
    }
}
impl Fixture {
    fn gate(&self, rule: &str) -> Option<HealthGate> {
        Some(HealthGate {
            node_id: self.node.clone(),
            rule_id: rule.into(),
        })
    }
    fn status(&self, record: &str) -> Option<dns::RecordStatus> {
        self.store.dns_record(&self.admin, record).unwrap().status
    }
    fn state(&self, record: &str) -> Option<dns::RecordState> {
        self.status(record).map(|status| status.state)
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_background_sync_confirms_removal_and_restoration_over_the_window() {
    let (mock, endpoint, mock_stop) = mock_cloudflare("example.com").await;
    let f = fixture(&endpoint, 0);
    let window = Duration::from_secs(3);
    let zone = f
        .store
        .create_dns_zone(&f.admin, &f.provider, "example.com", ZoneMode::Apply, 0, 3)
        .unwrap();
    let observe = f
        .store
        .create_dns_zone(
            &f.admin,
            &f.provider,
            "example.com",
            ZoneMode::Observe,
            0,
            3,
        )
        .unwrap();
    let record = f
        .store
        .create_dns_record(
            &f.admin,
            &zone.id,
            a_record("edge.example.com", "203.0.113.40", 300, f.gate("entry")),
        )
        .unwrap();
    let probe = f
        .store
        .create_dns_record(
            &f.admin,
            &observe.id,
            a_record("probe.example.com", "203.0.113.41", 300, None),
        )
        .unwrap();
    write_health(&f.path, &f.node, &[("entry", true)]);
    let healthy_at = Instant::now();
    let stop = CancellationToken::new();
    tokio::spawn(dns::run(
        f.store.clone(),
        Duration::from_millis(100),
        Duration::ZERO,
        stop.clone(),
    ));

    // A healthy entry is published only after a full healthy window.
    wait_for("pending restore", || async {
        f.state(&record.id) == Some(dns::RecordState::PendingRestore)
    })
    .await;
    assert!(!published(&mock, "203.0.113.40").await);
    let status = f.status(&record.id).unwrap();
    assert_eq!(status.healthy, Some(true));
    assert!(status.due_at_ms.unwrap() >= status.since_ms.unwrap() + 3_000);
    wait_for("creation", || published(&mock, "203.0.113.40")).await;
    assert!(healthy_at.elapsed() >= window, "{:?}", healthy_at.elapsed());
    wait_for("published status", || async {
        f.state(&record.id) == Some(dns::RecordState::Published)
    })
    .await;

    // Unchanged records cause neither provider writes nor metadata rewrites.
    let writes = mock.writes.load(Ordering::SeqCst);
    let updated_at = f
        .store
        .dns_record(&f.admin, &record.id)
        .unwrap()
        .updated_at_ms;
    tokio::time::sleep(Duration::from_millis(600)).await;
    assert_eq!(mock.writes.load(Ordering::SeqCst), writes);
    assert_eq!(
        f.store
            .dns_record(&f.admin, &record.id)
            .unwrap()
            .updated_at_ms,
        updated_at
    );
    let zone_view = f
        .store
        .dns_runtime()
        .zone_view(f.store.dns_zone(&f.admin, &zone.id).unwrap());
    let automatic = zone_view.status.last_automatic_ms.unwrap();
    assert!(relay_platform::model::now_ms() - automatic < 2_000);
    assert_eq!(zone_view.status.last_trigger, Some(dns::Trigger::Automatic));
    assert!(zone_view.status.last_error.is_none());
    // The observe zone is evaluated too, but never written.
    assert_eq!(f.state(&probe.id), Some(dns::RecordState::WouldCreate));
    assert!(!published(&mock, "203.0.113.41").await);

    // A failure is held for the window; one healthy sample restarts it.
    write_health(&f.path, &f.node, &[("entry", false)]);
    wait_for("pending removal", || async {
        f.state(&record.id) == Some(dns::RecordState::PendingRemove)
    })
    .await;
    tokio::time::sleep(Duration::from_secs(1)).await;
    assert!(published(&mock, "203.0.113.40").await, "removed too early");
    write_health(&f.path, &f.node, &[("entry", true)]);
    wait_for("healthy sample", || async {
        f.status(&record.id).and_then(|status| status.healthy) == Some(true)
    })
    .await;
    write_health(&f.path, &f.node, &[("entry", false)]);
    let failing_again = Instant::now();
    tokio::time::sleep(Duration::from_millis(1_500)).await;
    assert!(
        published(&mock, "203.0.113.40").await,
        "the failing run must restart after a healthy sample"
    );
    wait_for("removal", || async {
        !published(&mock, "203.0.113.40").await
    })
    .await;
    assert!(failing_again.elapsed() >= window);
    wait_for("removed status", || async {
        f.state(&record.id) == Some(dns::RecordState::Removed)
    })
    .await;

    // Recovery waits for a full healthy window before the record returns.
    write_health(&f.path, &f.node, &[("entry", true)]);
    let healed = Instant::now();
    wait_for("pending restore after removal", || async {
        f.state(&record.id) == Some(dns::RecordState::PendingRestore)
    })
    .await;
    assert!(!published(&mock, "203.0.113.40").await);
    wait_for("restoration", || published(&mock, "203.0.113.40")).await;
    assert!(healed.elapsed() >= window);
    stop.cancel();
    mock_stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_manual_and_automatic_passes_of_a_zone_never_write_twice() {
    let (mock, endpoint, mock_stop) = mock_cloudflare("example.com").await;
    let f = fixture(&endpoint, 0);
    let zone = f
        .store
        .create_dns_zone(&f.admin, &f.provider, "example.com", ZoneMode::Apply, 0, 0)
        .unwrap();
    f.store
        .create_dns_record(
            &f.admin,
            &zone.id,
            a_record("edge.example.com", "203.0.113.50", 300, None),
        )
        .unwrap();
    // Every pass reads an empty zone unless it waits for the previous one.
    mock.list_delay_ms.store(150, Ordering::SeqCst);
    let passes: Vec<_> = (0..4)
        .map(|index| {
            let store = f.store.clone();
            let zone = zone.id.clone();
            tokio::spawn(async move {
                let http = reqwest::Client::new();
                if index % 2 == 0 {
                    dns::reconcile(&store, &http, &zone).await
                } else {
                    dns::reconcile_as(&store, &http, &zone, dns::Trigger::Automatic).await
                }
            })
        })
        .collect();
    let mut created = 0;
    for pass in passes {
        created += pass.await.unwrap().unwrap().created;
    }
    assert_eq!(created, 1);
    assert_eq!(mock.writes.load(Ordering::SeqCst), 1);
    assert_eq!(mock.records.lock().await.len(), 1);
    mock_stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_mass_failure_guard_pauses_removals_for_one_name() {
    let (mock, endpoint, mock_stop) = mock_cloudflare("example.com").await;
    let f = fixture(&endpoint, 0);
    let zone = f
        .store
        .create_dns_zone(&f.admin, &f.provider, "example.com", ZoneMode::Apply, 0, 0)
        .unwrap();
    let mut edge = vec![];
    for (rule, content) in [
        ("a", "203.0.113.1"),
        ("b", "203.0.113.2"),
        ("c", "203.0.113.3"),
        ("d", "203.0.113.4"),
    ] {
        edge.push(
            f.store
                .create_dns_record(
                    &f.admin,
                    &zone.id,
                    a_record("edge.example.com", content, 300, f.gate(rule)),
                )
                .unwrap(),
        );
    }
    let single = f
        .store
        .create_dns_record(
            &f.admin,
            &zone.id,
            a_record("other.example.com", "203.0.113.9", 300, f.gate("other")),
        )
        .unwrap();
    let http = reqwest::Client::new();
    let health = |failing: &[&str]| {
        let rules: Vec<(&str, bool)> = ["a", "b", "c", "d", "other"]
            .into_iter()
            .map(|rule| (rule, !failing.contains(&rule)))
            .collect();
        write_health(&f.path, &f.node, &rules);
    };
    health(&[]);
    let all = dns::reconcile(&f.store, &http, &zone.id).await.unwrap();
    assert_eq!(all.created, 5, "{all:?}");

    // Three of four edge values fail at once: probably not the entries.
    // The single-value name is not a "mass" and is removed as before.
    health(&["a", "b", "c", "other"]);
    let guarded = dns::reconcile(&f.store, &http, &zone.id).await.unwrap();
    assert_eq!(guarded.guarded, 3, "{guarded:?}");
    assert_eq!(guarded.deleted, 1, "{guarded:?}");
    assert!(
        guarded
            .actions
            .iter()
            .any(|action| action.action == "guard" && action.record_id == edge[0].id)
    );
    assert_eq!(mock.records.lock().await.len(), 4);
    assert!(!published(&mock, "203.0.113.9").await);
    assert_eq!(f.state(&edge[0].id), Some(dns::RecordState::HeldGuard));
    assert_eq!(f.state(&edge[3].id), Some(dns::RecordState::Published));
    assert_eq!(f.state(&single.id), Some(dns::RecordState::Removed));
    let status = f
        .store
        .dns_runtime()
        .zone_view(f.store.dns_zone(&f.admin, &zone.id).unwrap())
        .status;
    assert_eq!(status.guarded, ["A edge.example.com"]);

    // Exactly half failing is not "more than half": removals proceed.
    health(&["a", "b"]);
    let half = dns::reconcile(&f.store, &http, &zone.id).await.unwrap();
    assert_eq!(half.guarded, 0, "{half:?}");
    assert_eq!(half.deleted, 2, "{half:?}");
    assert!(!published(&mock, "203.0.113.1").await);
    assert!(!published(&mock, "203.0.113.2").await);
    assert!(published(&mock, "203.0.113.3").await);
    assert_eq!(f.state(&edge[0].id), Some(dns::RecordState::Removed));
    assert!(
        f.store
            .dns_runtime()
            .zone_view(f.store.dns_zone(&f.admin, &zone.id).unwrap())
            .status
            .guarded
            .is_empty()
    );
    mock_stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_provider_minimum_ttl_is_published_without_update_loops() {
    let (mock, endpoint, mock_stop) = mock_cloudflare("example.com").await;
    let f = fixture(&endpoint, 60);
    let zone = f
        .store
        .create_dns_zone(&f.admin, &f.provider, "example.com", ZoneMode::Apply, 0, 0)
        .unwrap();
    let low = f
        .store
        .create_dns_record(
            &f.admin,
            &zone.id,
            a_record("low.example.com", "203.0.113.61", 30, None),
        )
        .unwrap();
    f.store
        .create_dns_record(
            &f.admin,
            &zone.id,
            a_record("auto.example.com", "203.0.113.62", 1, None),
        )
        .unwrap();
    f.store
        .create_dns_record(
            &f.admin,
            &zone.id,
            a_record("high.example.com", "203.0.113.63", 120, None),
        )
        .unwrap();
    let mut proxied = a_record("cdn.example.com", "203.0.113.64", 300, None);
    proxied.proxied = true;
    f.store
        .create_dns_record(&f.admin, &zone.id, proxied)
        .unwrap();
    let http = reqwest::Client::new();
    let first = dns::reconcile(&f.store, &http, &zone.id).await.unwrap();
    assert_eq!(first.created, 4, "{first:?}");
    let ttl = |records: &[Remote], content: &str| {
        records
            .iter()
            .find(|record| record.content == content)
            .unwrap()
            .ttl
    };
    {
        let records = mock.records.lock().await;
        assert_eq!(ttl(&records, "203.0.113.61"), 60);
        assert_eq!(
            ttl(&records, "203.0.113.62"),
            1,
            "automatic stays automatic"
        );
        assert_eq!(ttl(&records, "203.0.113.63"), 120);
        assert_eq!(ttl(&records, "203.0.113.64"), 1, "proxied is automatic");
    }
    assert_eq!(f.status(&low.id).unwrap().published_ttl, 60);
    assert_eq!(f.store.dns_record(&f.admin, &low.id).unwrap().ttl, 30);
    // Raised and proxied TTLs are not differences on the next pass.
    let second = dns::reconcile(&f.store, &http, &zone.id).await.unwrap();
    assert_eq!(second.unchanged, 4, "{second:?}");
    assert_eq!(mock.writes.load(Ordering::SeqCst), 4);

    // Removing the minimum publishes the record's own TTL.
    let provider = f
        .store
        .update_dns_provider(
            &f.admin,
            &f.provider,
            None,
            None,
            None,
            Some(0),
            Default::default(),
        )
        .unwrap();
    assert_eq!(provider.min_ttl, None);
    let lowered = dns::reconcile(&f.store, &http, &zone.id).await.unwrap();
    assert_eq!(lowered.updated, 1, "{lowered:?}");
    assert_eq!(ttl(&mock.records.lock().await, "203.0.113.61"), 30);
    assert_eq!(
        rejection(
            f.store
                .update_dns_provider(
                    &f.admin,
                    &f.provider,
                    None,
                    None,
                    None,
                    Some(86_401),
                    Default::default(),
                )
                .unwrap_err()
        ),
        400
    );
    mock_stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_provider_test_lists_zones_for_admins_without_leaking_the_token() {
    let (_mock, endpoint, mock_stop) = mock_cloudflare("example.com").await;
    let temp = tempfile::tempdir().unwrap();
    let store = Store::open(&temp.path().join("controller.db")).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    store
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
    let provider: Value = client
        .post(format!("{origin}/api/v1/dns/providers"))
        .bearer_auth(&session)
        .json(&json!({"name": "fixture", "kind": "cloudflare", "endpoint": endpoint, "token": "test-token", "min_ttl": 60}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(provider["min_ttl"], 60, "{provider}");
    let provider_id = provider["id"].as_str().unwrap();
    let test_url = format!("{origin}/api/v1/dns/providers/{provider_id}/test");

    let tested = client
        .post(&test_url)
        .bearer_auth(&session)
        .send()
        .await
        .unwrap();
    assert_eq!(tested.status(), 200);
    let tested: Value = tested.json().await.unwrap();
    assert_eq!(tested["ok"], true);
    assert_eq!(tested["truncated"], false);
    assert_eq!(
        tested["zones"],
        json!([
            {"id": "023e105f4ecef8ad9ca31a8372d0c353", "name": "example.com"},
            {"id": "9a7806061c88ada191ed06f989cc3dac", "name": "example.net"}
        ])
    );
    let denied = client
        .post(&test_url)
        .bearer_auth(&tenant_session)
        .send()
        .await
        .unwrap();
    assert_eq!(denied.status(), 403);

    // Wrong credentials: a clear provider error, with the token redacted.
    let secret = "wrong-secret-token-7f3a";
    let updated = client
        .put(format!("{origin}/api/v1/dns/providers/{provider_id}"))
        .bearer_auth(&session)
        .json(&json!({"token": secret}))
        .send()
        .await
        .unwrap();
    assert_eq!(updated.status(), 200);
    let failed = client
        .post(&test_url)
        .bearer_auth(&session)
        .send()
        .await
        .unwrap();
    assert_eq!(failed.status(), 502);
    let body = failed.text().await.unwrap();
    assert!(body.contains("Invalid access token"), "{body}");
    assert!(body.contains("9109"), "{body}");
    assert!(!body.contains(secret), "{body}");

    // Zones default to a 60 s window and expose their evaluation status.
    let zone: Value = client
        .post(format!("{origin}/api/v1/dns/zones"))
        .bearer_auth(&session)
        .json(&json!({"provider_id": provider_id, "name": "example.com", "mode": "apply"}))
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(zone["failover_confirm_secs"], 60, "{zone}");
    let zones: Value = client
        .get(format!("{origin}/api/v1/dns/zones"))
        .bearer_auth(&session)
        .send()
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(zones[0]["failover_confirm_secs"], 60, "{zones}");
    assert!(zones[0]["status"]["last_automatic_ms"].is_null(), "{zones}");
    let too_long = client
        .put(format!(
            "{origin}/api/v1/dns/zones/{}",
            zone["id"].as_str().unwrap()
        ))
        .bearer_auth(&session)
        .json(&json!({"failover_confirm_secs": 1801}))
        .send()
        .await
        .unwrap();
    assert_eq!(too_long.status(), 400);
    stop.cancel();
    mock_stop.cancel();
}

// ---- DNS webhook provider ----

const WEBHOOK_SECRET: &str = "webhook-secret-for-tests-0123456789abcdef";

/// A local webhook receiver after the public description of the ZFC DNS
/// webhook protocol v1: it checks the HMAC signature and clock, keeps a
/// generation watermark per source and the last (generation, seq, body) per
/// set, and replaces whole value sets. Failures can be injected.
#[derive(Clone, Default)]
struct Receiver(Arc<std::sync::Mutex<ReceiverState>>);
/// (source, zone, name, type) → last accepted (generation, seq, raw body).
type Versions = std::collections::HashMap<(String, String, String, String), (u64, u64, Vec<u8>)>;
#[derive(Default)]
struct ReceiverState {
    zones: Vec<String>,
    watermarks: std::collections::HashMap<String, u64>,
    versions: Versions,
    /// (zone, name, type) → (ttl, values).
    sets: std::collections::BTreeMap<(String, String, String), (u64, Vec<String>)>,
    /// Bodies of accepted requests, in order.
    accepted: Vec<Value>,
    deliveries: Vec<String>,
    /// Every request to the receiver URL, accepted or not.
    requests: u64,
    fail: Option<(u16, Value)>,
    delay_ms: u64,
}
impl Receiver {
    fn state(&self) -> std::sync::MutexGuard<'_, ReceiverState> {
        self.0.lock().unwrap()
    }
    fn set(&self, name: &str, record_type: &str) -> Option<(u64, Vec<String>)> {
        self.state()
            .sets
            .get(&("example.com".into(), name.into(), record_type.into()))
            .cloned()
    }
    fn events(&self) -> Vec<String> {
        self.state()
            .accepted
            .iter()
            .map(|body| body["event"].as_str().unwrap().to_owned())
            .collect()
    }
    fn requests(&self) -> u64 {
        self.state().requests
    }
}
fn hmac_hex(secret: &str, timestamp: &str, body: &[u8]) -> String {
    let key = ring::hmac::Key::new(ring::hmac::HMAC_SHA256, secret.as_bytes());
    let tag = ring::hmac::sign(&key, &[timestamp.as_bytes(), b".", body].concat());
    let hex: String = tag.as_ref().iter().map(|b| format!("{b:02x}")).collect();
    format!("sha256={hex}")
}
/// `1..=i64::MAX` as a decimal string without leading zeros.
fn decimal(value: &Value) -> Option<u64> {
    let text = value.as_str()?;
    if text.is_empty() || text.starts_with('0') || !text.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    text.parse::<u64>()
        .ok()
        .filter(|value| *value <= i64::MAX as u64)
}
async fn mock_receiver(zones: &[&str]) -> (Receiver, String, CancellationToken) {
    use axum::{
        Router,
        body::Bytes,
        extract::State,
        http::{HeaderMap, StatusCode},
        response::{IntoResponse, Response},
        routing::post,
    };
    let receiver = Receiver::default();
    receiver.state().zones = zones.iter().map(|zone| zone.to_string()).collect();
    fn reply(status: u16, body: Value) -> Response {
        (StatusCode::from_u16(status).unwrap(), axum::Json(body)).into_response()
    }
    async fn receive(State(receiver): State<Receiver>, headers: HeaderMap, raw: Bytes) -> Response {
        let delay = {
            let mut state = receiver.state();
            state.requests += 1;
            state.delay_ms
        };
        tokio::time::sleep(Duration::from_millis(delay)).await;
        let header = |name: &str| {
            headers
                .get(name)
                .and_then(|value| value.to_str().ok())
                .unwrap_or_default()
                .to_owned()
        };
        let timestamp = header("x-zfc-timestamp");
        let now = relay_platform::model::now_ms() / 1000;
        if timestamp
            .parse::<i64>()
            .is_ok_and(|at| (now - at).abs() > 300)
            || hmac_hex(WEBHOOK_SECRET, &timestamp, &raw) != header("x-zfc-signature")
        {
            return reply(401, json!({"error": "invalid_signature"}));
        }
        let Ok(body) = serde_json::from_slice::<Value>(&raw) else {
            return reply(400, json!({"error": "invalid_json"}));
        };
        let event = body["event"].as_str().unwrap_or_default().to_owned();
        if body["version"] != 1
            || header("x-zfc-event") != event
            || header("content-type") != "application/json"
            || uuid::Uuid::parse_str(&header("x-zfc-delivery")).is_err()
        {
            return reply(400, json!({"error": "invalid_request"}));
        }
        let mut state = receiver.state();
        if let Some((status, body)) = state.fail.clone() {
            return reply(status, body);
        }
        let source = body["source"].as_str().unwrap_or_default().to_owned();
        let allowed = |zone: &Value, state: &ReceiverState| {
            zone.as_str()
                .is_some_and(|zone| state.zones.iter().any(|allowed| allowed == zone))
        };
        match event.as_str() {
            "ping" => {
                let zones = body["zones"].as_array().cloned().unwrap_or_default();
                if zones.is_empty() || !zones.iter().all(|zone| allowed(zone, &state)) {
                    return reply(400, json!({"error": "zone_not_allowed"}));
                }
            }
            "generation.start" => {
                let Some(generation) = decimal(&body["generation"]) else {
                    return reply(400, json!({"error": "invalid_generation"}));
                };
                let watermark = state.watermarks.get(&source).copied().unwrap_or(0);
                if generation < watermark {
                    return reply(
                        409,
                        json!({"error": "stale_generation", "watermark": watermark.to_string()}),
                    );
                }
                state.watermarks.insert(source.clone(), generation);
            }
            "record_set.put" => {
                let (Some(generation), Some(seq)) =
                    (decimal(&body["generation"]), decimal(&body["seq"]))
                else {
                    return reply(400, json!({"error": "invalid_version"}));
                };
                let watermark = state.watermarks.get(&source).copied().unwrap_or(0);
                if generation != watermark {
                    return reply(
                        409,
                        json!({"error": "stale_generation", "watermark": watermark.to_string()}),
                    );
                }
                if !allowed(&body["zone"], &state) {
                    return reply(400, json!({"error": "zone_not_allowed"}));
                }
                let values: Vec<String> = body["values"]
                    .as_array()
                    .unwrap()
                    .iter()
                    .map(|value| value.as_str().unwrap().to_owned())
                    .collect();
                // A complete set, deduplicated and in byte order.
                if values.windows(2).any(|pair| pair[0] >= pair[1]) {
                    return reply(400, json!({"error": "values_not_canonical"}));
                }
                let text = |field: &str| body[field].as_str().unwrap().to_owned();
                let key = (source.clone(), text("zone"), text("name"), text("type"));
                match state.versions.get(&key) {
                    Some((g, s, previous)) if (*g, *s) == (generation, seq) => {
                        if *previous != raw.to_vec() {
                            return reply(409, json!({"error": "version_conflict"}));
                        }
                    }
                    Some((g, s, _)) if (*g, *s) > (generation, seq) => {
                        return reply(409, json!({"error": "stale_version"}));
                    }
                    _ => {
                        let set = (text("zone"), text("name"), text("type"));
                        if values.is_empty() {
                            state.sets.remove(&set);
                        } else {
                            state
                                .sets
                                .insert(set, (body["ttl"].as_u64().unwrap(), values));
                        }
                        state.versions.insert(key, (generation, seq, raw.to_vec()));
                    }
                }
            }
            _ => return reply(400, json!({"error": "unknown_event"})),
        }
        state.accepted.push(body);
        state.deliveries.push(header("x-zfc-delivery"));
        StatusCode::NO_CONTENT.into_response()
    }
    // A redirect to the real receiver URL: following it would deliver.
    let redirect = || async {
        (
            StatusCode::TEMPORARY_REDIRECT,
            [(axum::http::header::LOCATION, "/dns")],
        )
            .into_response()
    };
    let app = Router::new()
        .route("/dns", post(receive))
        .route("/moved", post(redirect))
        .with_state(receiver.clone());
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
    (receiver, format!("http://{address}/dns"), stop)
}
fn webhook_store(path: &std::path::Path) -> (Store, relay_platform::store::Actor) {
    let store = Store::open(path).unwrap();
    store.set_kind("controller").unwrap();
    let admin = store.bootstrap(PASSWORD).unwrap();
    (store, admin)
}
fn webhook_provider(store: &Store, admin: &relay_platform::store::Actor, endpoint: &str) -> String {
    store
        .create_dns_provider(
            admin,
            "receiver",
            ProviderKind::Webhook,
            endpoint,
            WEBHOOK_SECRET,
            0,
            dns::WebhookSettings {
                zones: Some(vec!["example.com".into(), "example.net".into()]),
                timeout_secs: None,
            },
        )
        .unwrap()
        .id
}
fn record(
    name: &str,
    record_type: RecordType,
    content: &str,
    ttl: u32,
) -> relay_platform::store::NewDnsRecord {
    relay_platform::store::NewDnsRecord {
        name: name.into(),
        record_type,
        content: content.into(),
        ttl,
        proxied: false,
        health: None,
    }
}
fn patch(
    f: impl FnOnce(&mut relay_platform::store::DnsRecordPatch),
) -> relay_platform::store::DnsRecordPatch {
    let mut patch = relay_platform::store::DnsRecordPatch::default();
    f(&mut patch);
    patch
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_webhook_sends_signed_complete_sets_and_writes_only_differences() {
    let (receiver, endpoint, receiver_stop) = mock_receiver(&["example.com", "example.net"]).await;
    let temp = tempfile::tempdir().unwrap();
    let (store, admin) = webhook_store(&temp.path().join("controller.db"));
    let provider = webhook_provider(&store, &admin, &endpoint);
    let zone = store
        .create_dns_zone(&admin, &provider, "example.com", ZoneMode::Apply, 0, 0)
        .unwrap();
    let low = store
        .create_dns_record(
            &admin,
            &zone.id,
            record("edge.example.com", RecordType::A, "203.0.113.2", 120),
        )
        .unwrap();
    let high = store
        .create_dns_record(
            &admin,
            &zone.id,
            record("Edge.example.com.", RecordType::A, "203.0.113.1", 300),
        )
        .unwrap();
    let v6 = store
        .create_dns_record(
            &admin,
            &zone.id,
            record("edge.example.com", RecordType::Aaaa, "2001:DB8::1", 300),
        )
        .unwrap();
    store
        .create_dns_record(
            &admin,
            &zone.id,
            record(
                "www.example.com",
                RecordType::Cname,
                "Edge.Example.com.",
                300,
            ),
        )
        .unwrap();
    let http = reqwest::Client::new();
    let first = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!((first.created, first.errors), (4, 0), "{first:?}");
    // One generation, then one put per record; one name's values form one
    // set with the lowest TTL of its values.
    assert_eq!(
        receiver.events(),
        [
            "generation.start",
            "record_set.put",
            "record_set.put",
            "record_set.put",
            "record_set.put"
        ]
    );
    {
        let state = receiver.state();
        assert_eq!(state.accepted[0]["generation"], "1");
        assert_eq!(state.accepted[0]["source"], provider.as_str());
        let seqs: Vec<u64> = state.accepted[1..]
            .iter()
            .map(|body| decimal(&body["seq"]).unwrap())
            .collect();
        assert!(seqs.windows(2).all(|pair| pair[0] < pair[1]), "{seqs:?}");
        let deliveries: std::collections::HashSet<_> = state.deliveries.iter().collect();
        assert_eq!(
            deliveries.len(),
            state.deliveries.len(),
            "a new delivery ID per request"
        );
    }
    assert_eq!(
        receiver.set("edge.example.com", "A"),
        Some((120, vec!["203.0.113.1".into(), "203.0.113.2".into()]))
    );
    assert_eq!(
        receiver.set("edge.example.com", "AAAA"),
        Some((300, vec!["2001:db8::1".into()]))
    );
    assert_eq!(
        receiver.set("www.example.com", "CNAME"),
        Some((300, vec!["edge.example.com".into()]))
    );
    assert_eq!(
        store
            .dns_record(&admin, &low.id)
            .unwrap()
            .status
            .unwrap()
            .state,
        dns::RecordState::Published
    );

    // Nothing changed: no request at all.
    let requests = receiver.requests();
    let again = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!(
        (
            again.unchanged,
            again.created + again.updated + again.deleted
        ),
        (4, 0),
        "{again:?}"
    );
    assert_eq!(receiver.requests(), requests);

    // A changed value replaces the whole set.
    store
        .update_dns_record(
            &admin,
            &low.id,
            patch(|p| p.content = Some("203.0.113.3".into())),
        )
        .unwrap();
    let changed = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!(changed.updated, 1, "{changed:?}");
    assert_eq!(
        receiver.set("edge.example.com", "A"),
        Some((120, vec!["203.0.113.1".into(), "203.0.113.3".into()]))
    );
    // A disabled value leaves the set, and the set's TTL follows the rest.
    store
        .update_dns_record(&admin, &low.id, patch(|p| p.enabled = Some(false)))
        .unwrap();
    let disabled = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!(disabled.deleted, 1, "{disabled:?}");
    assert_eq!(
        receiver.set("edge.example.com", "A"),
        Some((300, vec!["203.0.113.1".into()]))
    );
    assert!(
        store
            .dns_record(&admin, &low.id)
            .unwrap()
            .provider_record_id
            .is_none()
    );
    // A renamed record leaves its old set (now empty: deleted) for the new one.
    store
        .update_dns_record(
            &admin,
            &v6.id,
            patch(|p| p.name = Some("api.example.com".into())),
        )
        .unwrap();
    let renamed = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!((renamed.updated, renamed.errors), (1, 0), "{renamed:?}");
    assert_eq!(receiver.set("edge.example.com", "AAAA"), None);
    assert_eq!(
        receiver.set("api.example.com", "AAAA"),
        Some((300, vec!["2001:db8::1".into()]))
    );
    // A second CNAME target for one name is refused before sending.
    store
        .create_dns_record(
            &admin,
            &zone.id,
            record(
                "www.example.com",
                RecordType::Cname,
                "other.example.net",
                300,
            ),
        )
        .unwrap();
    let requests = receiver.requests();
    let cname = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!(cname.errors, 1, "{cname:?}");
    assert!(
        cname
            .actions
            .iter()
            .any(|action| action.detail.contains("only one target")),
        "{cname:?}"
    );
    assert_eq!(receiver.requests(), requests);
    let _ = high;

    // Observe mode never contacts the receiver and reports against what it
    // acknowledged.
    let observe = store
        .create_dns_zone(&admin, &provider, "example.net", ZoneMode::Observe, 0, 0)
        .unwrap();
    store
        .create_dns_record(
            &admin,
            &observe.id,
            record("probe.example.net", RecordType::A, "203.0.113.20", 300),
        )
        .unwrap();
    let requests = receiver.requests();
    let observed = dns::reconcile(&store, &http, &observe.id).await.unwrap();
    assert_eq!(observed.created, 1, "{observed:?}");
    assert!(
        observed
            .actions
            .iter()
            .any(|action| action.action == "would-create")
    );
    assert_eq!(receiver.requests(), requests);
    receiver_stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_webhook_generations_survive_restarts_and_follow_the_receiver() {
    let (receiver, endpoint, receiver_stop) = mock_receiver(&["example.com"]).await;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("controller.db");
    let (store, admin) = webhook_store(&path);
    let provider = webhook_provider(&store, &admin, &endpoint);
    let zone = store
        .create_dns_zone(&admin, &provider, "example.com", ZoneMode::Apply, 0, 0)
        .unwrap();
    let edge = store
        .create_dns_record(
            &admin,
            &zone.id,
            record("edge.example.com", RecordType::A, "203.0.113.1", 300),
        )
        .unwrap();
    let http = reqwest::Client::new();
    assert_eq!(
        dns::reconcile(&store, &http, &zone.id)
            .await
            .unwrap()
            .created,
        1
    );
    let last_generation = |receiver: &Receiver| {
        receiver
            .state()
            .accepted
            .iter()
            .rev()
            .find(|body| body["event"] == "generation.start")
            .map(|body| body["generation"].as_str().unwrap().to_owned())
    };
    assert_eq!(last_generation(&receiver).as_deref(), Some("1"));

    // A restarted controller reads what was acknowledged: nothing to send.
    drop(store);
    let store = Store::open(&path).unwrap();
    let requests = receiver.requests();
    let restarted = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!(restarted.unchanged, 1, "{restarted:?}");
    assert_eq!(receiver.requests(), requests);
    // Its first write starts the next generation.
    let move_to = |content: &str| patch(|p| p.content = Some(content.into()));
    store
        .update_dns_record(&admin, &edge.id, move_to("203.0.113.2"))
        .unwrap();
    assert_eq!(
        dns::reconcile(&store, &http, &zone.id)
            .await
            .unwrap()
            .updated,
        1
    );
    assert_eq!(last_generation(&receiver).as_deref(), Some("2"));
    assert_eq!(receiver.state().accepted.last().unwrap()["generation"], "2");

    // A receiver ahead of the controller (a restored database): the
    // controller starts above the receiver's generation.
    receiver.state().watermarks.insert(provider.clone(), 7);
    drop(store);
    let store = Store::open(&path).unwrap();
    store
        .update_dns_record(&admin, &edge.id, move_to("203.0.113.3"))
        .unwrap();
    let ahead = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!((ahead.updated, ahead.errors), (1, 0), "{ahead:?}");
    assert_eq!(last_generation(&receiver).as_deref(), Some("8"));

    // The receiver moves on mid-session: that write fails and the next
    // pass starts a newer generation.
    receiver.state().watermarks.insert(provider.clone(), 20);
    store
        .update_dns_record(&admin, &edge.id, move_to("203.0.113.4"))
        .unwrap();
    let stale = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!(stale.errors, 1, "{stale:?}");
    let error = store
        .dns_record(&admin, &edge.id)
        .unwrap()
        .last_error
        .unwrap();
    assert!(
        error.contains("409") && error.contains("stale_generation"),
        "{error}"
    );
    let resumed = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!((resumed.updated, resumed.errors), (1, 0), "{resumed:?}");
    assert_eq!(last_generation(&receiver).as_deref(), Some("21"));
    assert_eq!(
        receiver.set("edge.example.com", "A"),
        Some((300, vec!["203.0.113.4".into()]))
    );
    assert!(
        store
            .dns_record(&admin, &edge.id)
            .unwrap()
            .last_error
            .is_none()
    );
    receiver_stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_webhook_failures_are_errors_and_never_reveal_the_secret() {
    let (receiver, endpoint, receiver_stop) = mock_receiver(&["example.com"]).await;
    let temp = tempfile::tempdir().unwrap();
    let (store, admin) = webhook_store(&temp.path().join("controller.db"));
    let provider = webhook_provider(&store, &admin, &endpoint);
    let zone = store
        .create_dns_zone(&admin, &provider, "example.com", ZoneMode::Apply, 0, 0)
        .unwrap();
    let edge = store
        .create_dns_record(
            &admin,
            &zone.id,
            record("edge.example.com", RecordType::A, "203.0.113.1", 300),
        )
        .unwrap();
    let http = reqwest::Client::new();
    let failed_with = |status: u16, body: Value| {
        receiver.state().fail = Some((status, body));
    };
    let error = |store: &Store| {
        store
            .dns_record(&admin, &edge.id)
            .unwrap()
            .last_error
            .unwrap_or_default()
    };

    // The receiver could not apply the change: an error, nothing kept.
    failed_with(
        503,
        json!({"error": "dns_not_applied", "message": "adapter exited 3"}),
    );
    let pass = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!((pass.created, pass.errors), (0, 1), "{pass:?}");
    let message = error(&store);
    assert!(
        message.contains("HTTP 503") && message.contains("dns_not_applied: adapter exited 3"),
        "{message}"
    );
    assert_eq!(
        store
            .dns_record(&admin, &edge.id)
            .unwrap()
            .status
            .unwrap()
            .state,
        dns::RecordState::Error
    );
    // A 202 is not an applied change.
    failed_with(202, json!({}));
    dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert!(
        error(&store).contains("accepted without applying"),
        "{}",
        error(&store)
    );
    // A receiver echoing the secret: redacted.
    failed_with(400, json!({"error": format!("bad key {WEBHOOK_SECRET}")}));
    dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert!(error(&store).contains("[redacted]"), "{}", error(&store));
    assert!(!error(&store).contains(WEBHOOK_SECRET));

    // A wrong secret is refused by the receiver's signature check.
    receiver.state().fail = None;
    store
        .update_dns_provider(
            &admin,
            &provider,
            None,
            None,
            Some("another-secret-of-at-least-32-bytes!"),
            None,
            Default::default(),
        )
        .unwrap();
    dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert!(error(&store).contains("HTTP 401"), "{}", error(&store));
    store
        .update_dns_provider(
            &admin,
            &provider,
            None,
            None,
            Some(WEBHOOK_SECRET),
            None,
            Default::default(),
        )
        .unwrap();

    // A slow receiver: the request gives up after the provider timeout.
    store
        .update_dns_provider(
            &admin,
            &provider,
            None,
            None,
            None,
            None,
            dns::WebhookSettings {
                zones: None,
                timeout_secs: Some(1),
            },
        )
        .unwrap();
    receiver.state().delay_ms = 2_500;
    let started = Instant::now();
    dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert!(
        started.elapsed() < Duration::from_millis(2_400),
        "{:?}",
        started.elapsed()
    );
    assert!(
        error(&store).contains("no answer within 1 s"),
        "{}",
        error(&store)
    );
    receiver.state().delay_ms = 0;

    // A redirect is never followed, even to the receiver itself.
    let moved = endpoint.replace("/dns", "/moved");
    store
        .update_dns_provider(
            &admin,
            &provider,
            None,
            Some(&moved),
            None,
            None,
            Default::default(),
        )
        .unwrap();
    let requests = receiver.requests();
    dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert!(
        error(&store).contains("HTTP 307") && error(&store).contains("redirects are not followed"),
        "{}",
        error(&store)
    );
    assert_eq!(
        receiver.requests(),
        requests,
        "the redirect must not be followed"
    );

    // Back to a working receiver: published, and the error clears.
    store
        .update_dns_provider(
            &admin,
            &provider,
            None,
            Some(&endpoint),
            None,
            None,
            Default::default(),
        )
        .unwrap();
    let healed = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!((healed.created, healed.errors), (1, 0), "{healed:?}");
    assert!(
        store
            .dns_record(&admin, &edge.id)
            .unwrap()
            .last_error
            .is_none()
    );
    assert_eq!(
        receiver.set("edge.example.com", "A"),
        Some((300, vec!["203.0.113.1".into()]))
    );
    let view = serde_json::to_string(&store.dns_provider(&admin, &provider).unwrap()).unwrap();
    assert!(!view.contains(WEBHOOK_SECRET), "{view}");
    receiver_stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_webhook_health_removals_keep_the_window_min_keep_and_guard() {
    let (receiver, endpoint, receiver_stop) = mock_receiver(&["example.com"]).await;
    let temp = tempfile::tempdir().unwrap();
    let path = temp.path().join("controller.db");
    let (store, admin) = webhook_store(&path);
    store.set_feature(&admin, "dns-health", true).unwrap();
    let (node, _enrollment) = store.create_node(&admin, "default", "edge").unwrap();
    let provider = webhook_provider(&store, &admin, &endpoint);
    let zone = store
        .create_dns_zone(&admin, &provider, "example.com", ZoneMode::Apply, 3, 1)
        .unwrap();
    let rules = ["a", "b", "c", "d"];
    for (rule, content) in
        rules
            .iter()
            .zip(["203.0.113.1", "203.0.113.2", "203.0.113.3", "203.0.113.4"])
    {
        let mut input = record("edge.example.com", RecordType::A, content, 300);
        input.health = Some(HealthGate {
            node_id: node.id.clone(),
            rule_id: (*rule).into(),
        });
        store.create_dns_record(&admin, &zone.id, input).unwrap();
    }
    let health = |failing: &[&str]| {
        let reports: Vec<(&str, bool)> = rules
            .iter()
            .map(|rule| (*rule, !failing.contains(rule)))
            .collect();
        write_health(&path, &node.id, &reports);
    };
    let values = || {
        receiver
            .set("edge.example.com", "A")
            .map(|(_, values)| values.len())
            .unwrap_or(0)
    };
    let http = reqwest::Client::new();
    health(&[]);
    // New gated records wait for a healthy window, then form one set.
    let waiting = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!((waiting.pending, waiting.created), (4, 0), "{waiting:?}");
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    health(&[]);
    assert_eq!(
        dns::reconcile(&store, &http, &zone.id)
            .await
            .unwrap()
            .created,
        4
    );
    assert_eq!(values(), 4);

    // Three of four fail at once: the guard holds them; nothing is sent.
    health(&["a", "b", "c"]);
    let requests = receiver.requests();
    dns::reconcile(&store, &http, &zone.id).await.unwrap();
    tokio::time::sleep(Duration::from_millis(1_100)).await;
    health(&["a", "b", "c"]);
    let guarded = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!(guarded.guarded, 3, "{guarded:?}");
    assert_eq!(receiver.requests(), requests);
    // Two of four fail after the window: min_keep 3 keeps both.
    health(&["a", "b"]);
    let kept = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!((kept.kept, kept.deleted), (2, 0), "{kept:?}");
    assert_eq!(values(), 4);
    // With min_keep 2 they leave the set.
    store
        .update_dns_zone(&admin, &zone.id, None, None, Some(2), None)
        .unwrap();
    let removed = dns::reconcile(&store, &http, &zone.id).await.unwrap();
    assert_eq!(removed.deleted, 2, "{removed:?}");
    assert_eq!(
        receiver.set("edge.example.com", "A"),
        Some((300, vec!["203.0.113.3".into(), "203.0.113.4".into()]))
    );
    receiver_stop.cancel();
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn dns_webhook_provider_api_validates_and_tests_with_a_signed_ping() {
    let (receiver, endpoint, receiver_stop) = mock_receiver(&["example.com"]).await;
    let temp = tempfile::tempdir().unwrap();
    let (store, _admin) = webhook_store(&temp.path().join("controller.db"));
    let (address, stop) = serve(store).await;
    let origin = format!("http://{address}");
    let client = reqwest::Client::builder().no_proxy().build().unwrap();
    let session = login(&client, &origin, "admin").await;
    let post = |path: &str, body: Value| {
        client
            .post(format!("{origin}/api/v1{path}"))
            .bearer_auth(&session)
            .json(&body)
            .send()
    };
    let provider = |overrides: Value| {
        let mut body = json!({"name": "receiver", "kind": "webhook", "endpoint": endpoint,
            "token": WEBHOOK_SECRET, "zones": ["Example.COM."]});
        for (key, value) in overrides.as_object().unwrap() {
            if value.is_null() {
                body.as_object_mut().unwrap().remove(key);
            } else {
                body[key] = value.clone();
            }
        }
        body
    };
    for (overrides, status) in [
        (json!({"token": "short-secret"}), 400),
        (json!({"endpoint": "http://example.com/dns"}), 400),
        (
            json!({"endpoint": "https://user:pass@example.com/dns"}),
            400,
        ),
        (json!({"endpoint": null}), 400),
        (json!({"zones": null}), 400),
        (json!({"zones": ["bad zone"]}), 400),
        (json!({"timeout_secs": 31}), 400),
        (json!({"timeout_secs": 0}), 400),
        (json!({"kind": "cloudflare"}), 400),
    ] {
        let response = post("/dns/providers", provider(overrides.clone()))
            .await
            .unwrap();
        assert_eq!(
            response.status(),
            status,
            "{overrides}: {}",
            response.text().await.unwrap()
        );
    }
    let created = post("/dns/providers", provider(json!({}))).await.unwrap();
    assert_eq!(created.status(), 200);
    let text = created.text().await.unwrap();
    assert!(!text.contains(WEBHOOK_SECRET), "{text}");
    let created: Value = serde_json::from_str(&text).unwrap();
    assert_eq!(created["token_set"], true);
    assert_eq!(created["zones"], json!(["example.com"]));
    assert_eq!(created["timeout_secs"], 15);
    let provider_id = created["id"].as_str().unwrap().to_owned();
    assert_eq!(
        post("/dns/providers", provider(json!({"name": "again"})))
            .await
            .unwrap()
            .status(),
        409
    );

    // The test sends a signed ping with the configured zones and a
    // throwaway source.
    let tested = post(&format!("/dns/providers/{provider_id}/test"), json!(null))
        .await
        .unwrap();
    assert_eq!(tested.status(), 200);
    let tested: Value = tested.json().await.unwrap();
    assert_eq!(
        tested["zones"],
        json!([{"id": "example.com", "name": "example.com"}])
    );
    {
        let state = receiver.state();
        let ping = state.accepted.last().unwrap();
        assert_eq!(ping["event"], "ping");
        assert_eq!(ping["zones"], json!(["example.com"]));
        assert_ne!(ping["source"], provider_id.as_str());
    }
    receiver.state().fail = Some((
        401,
        json!({"error": format!("signature mismatch for {WEBHOOK_SECRET}")}),
    ));
    let failed = post(&format!("/dns/providers/{provider_id}/test"), json!(null))
        .await
        .unwrap();
    assert_eq!(failed.status(), 502);
    let body = failed.text().await.unwrap();
    assert!(
        body.contains("HTTP 401") && !body.contains(WEBHOOK_SECRET),
        "{body}"
    );
    receiver.state().fail = None;

    // Zones come from the provider's list, once each.
    let zone = |name: &str| {
        post(
            "/dns/zones",
            json!({"provider_id": provider_id, "name": name, "mode": "apply", "min_keep": 0}),
        )
    };
    assert_eq!(zone("example.org").await.unwrap().status(), 400);
    let created_zone: Value = zone("example.com").await.unwrap().json().await.unwrap();
    let zone_id = created_zone["id"].as_str().unwrap().to_owned();
    assert_eq!(zone("EXAMPLE.com.").await.unwrap().status(), 409);
    // Records stay inside the zone and are never proxied.
    let records = format!("/dns/zones/{zone_id}/records");
    assert_eq!(
        post(&records, json!({"name": "edge.example.com", "type": "A", "content": "203.0.113.30", "proxied": true})).await.unwrap().status(),
        400
    );
    assert_eq!(
        post(
            &records,
            json!({"name": "edge.example.org", "type": "A", "content": "203.0.113.30"})
        )
        .await
        .unwrap()
        .status(),
        400
    );
    let record: Value = post(
        &records,
        json!({"name": "edge.example.com", "type": "A", "content": "203.0.113.30"}),
    )
    .await
    .unwrap()
    .json()
    .await
    .unwrap();
    let record_id = record["id"].as_str().unwrap();
    let reconciled: Value = post(&format!("/dns/zones/{zone_id}/reconcile"), json!(null))
        .await
        .unwrap()
        .json()
        .await
        .unwrap();
    assert_eq!(reconciled["created"], 1, "{reconciled}");
    assert_eq!(
        receiver.set("edge.example.com", "A"),
        Some((300, vec!["203.0.113.30".into()]))
    );
    // A published zone cannot be renamed away from its sets.
    let put = |path: String, body: Value| {
        client
            .put(format!("{origin}/api/v1{path}"))
            .bearer_auth(&session)
            .json(&body)
            .send()
    };
    let widened = put(
        format!("/dns/providers/{provider_id}"),
        json!({"zones": ["example.com", "example.net"]}),
    )
    .await
    .unwrap();
    assert_eq!(widened.status(), 200);
    let rename = |name: &'static str| put(format!("/dns/zones/{zone_id}"), json!({"name": name}));
    assert_eq!(rename("example.net").await.unwrap().status(), 409);
    assert_eq!(
        rename("example.com.").await.unwrap().status(),
        200,
        "the same zone in another spelling"
    );
    // Deleting the record empties its set at the receiver.
    let deleted = client
        .delete(format!("{origin}/api/v1/dns/records/{record_id}"))
        .bearer_auth(&session)
        .send()
        .await
        .unwrap();
    assert_eq!(deleted.status(), 200);
    assert_eq!(receiver.set("edge.example.com", "A"), None);
    let last = receiver.state().accepted.last().cloned().unwrap();
    assert_eq!(
        (last["event"].as_str(), last["values"].clone()),
        (Some("record_set.put"), json!([]))
    );
    stop.cancel();
    receiver_stop.cancel();
}
