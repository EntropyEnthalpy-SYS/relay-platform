use crate::{
    budget::{Budget, BudgetOverview, BudgetUpdate, NewBudget},
    model::*,
    store::{Actor, Rejection, Role, Scope, Store, reject},
    subscription::{Format, Template},
};
use axum::{
    Json, Router,
    body::Body,
    extract::{ConnectInfo, DefaultBodyLimit, Path, Query, Request, State},
    http::{HeaderMap, HeaderValue, Method, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{delete, get, post},
};
use serde::{Deserialize, Serialize};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{Arc, Mutex},
    time::{Duration, Instant},
};
use tokio::sync::Semaphore;

#[derive(Clone)]
pub struct AppState {
    pub store: Store,
    instance: String,
    login_attempts: Arc<Mutex<HashMap<String, (u32, Instant)>>>,
    second_factor_failures: Arc<Mutex<HashMap<String, (u32, Instant)>>>,
    login_slots: Arc<Semaphore>,
    subscription_hits: Arc<Mutex<HashMap<String, (u32, Instant)>>>,
    sync_queue: crate::sync_queue::SyncQueue,
    /// Ends agent watches so a graceful shutdown need not wait for them.
    stopping: tokio_util::sync::CancellationToken,
}
impl AppState {
    pub fn new(store: Store) -> Self {
        Self {
            sync_queue: crate::sync_queue::SyncQueue::new(store.clone(), 16).unwrap(),
            store,
            instance: uuid::Uuid::new_v4().to_string(),
            login_attempts: Arc::new(Mutex::new(HashMap::new())),
            second_factor_failures: Arc::new(Mutex::new(HashMap::new())),
            login_slots: Arc::new(Semaphore::new(4)),
            subscription_hits: Arc::new(Mutex::new(HashMap::new())),
            stopping: Default::default(),
        }
    }
    pub fn with_shutdown(mut self, stopping: tokio_util::sync::CancellationToken) -> Self {
        self.stopping = stopping;
        self
    }
    pub fn with_sync_batch_size(mut self, size: usize) -> anyhow::Result<Self> {
        self.sync_queue = crate::sync_queue::SyncQueue::new(self.store.clone(), size)?;
        Ok(self)
    }
    fn login_allowed(&self, source: String) -> bool {
        let now = Instant::now();
        let mut map = self.login_attempts.lock().unwrap();
        map.retain(|_, (_, until)| *until > now);
        if !map.contains_key(&source) && map.len() >= 4096 {
            return false;
        }
        let entry = map
            .entry(source)
            .or_insert((0, now + Duration::from_secs(300)));
        entry.0 += 1;
        entry.0 <= 30
    }
    /// Wrong second-factor codes are limited per account, independent of source address.
    /// Public subscription polling is capped per token. The map stores hashes,
    /// never the bearer value, and is bounded so random paths cannot grow it.
    fn subscription_allowed(&self, token: &str) -> bool {
        let key = crate::subscription::token_hash(token);
        let now = Instant::now();
        let mut map = self.subscription_hits.lock().unwrap();
        map.retain(|_, (_, until)| *until > now);
        if !map.contains_key(&key) && map.len() >= 4096 {
            return false;
        }
        let entry = map.entry(key).or_insert((0, now + Duration::from_secs(60)));
        entry.0 += 1;
        entry.0 <= 60
    }
    fn second_factor_locked(&self, username: &str, failed: bool) -> bool {
        let now = Instant::now();
        let mut map = self.second_factor_failures.lock().unwrap();
        map.retain(|_, (_, until)| *until > now);
        if failed && map.len() < 4096 {
            map.entry(username.to_owned())
                .or_insert((0, now + Duration::from_secs(300)))
                .0 += 1;
        }
        map.get(username).is_some_and(|(count, _)| *count >= 10)
    }
}

pub struct ApiError(anyhow::Error);
impl From<anyhow::Error> for ApiError {
    fn from(value: anyhow::Error) -> Self {
        Self(value)
    }
}
impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, message) = if let Some(error) = self.0.downcast_ref::<Rejection>() {
            (
                StatusCode::from_u16(error.status).unwrap_or(StatusCode::INTERNAL_SERVER_ERROR),
                error.message.clone(),
            )
        } else {
            tracing::error!(error=%self.0,"API operation failed");
            (
                StatusCode::INTERNAL_SERVER_ERROR,
                "internal operation failed".into(),
            )
        };
        (status, Json(serde_json::json!({"error":message}))).into_response()
    }
}
type ApiResult<T> = Result<Json<T>, ApiError>;

async fn database<T: Send + 'static>(
    store: Store,
    f: impl FnOnce(Store) -> anyhow::Result<T> + Send + 'static,
) -> Result<T, ApiError> {
    tokio::task::spawn_blocking(move || f(store))
        .await
        .map_err(|e| ApiError(e.into()))?
        .map_err(ApiError)
}
fn bearer(headers: &HeaderMap) -> anyhow::Result<String> {
    let Some(token) = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .and_then(|s| s.strip_prefix("Bearer "))
        .filter(|s| {
            let secret = s.strip_prefix(crate::store::API_TOKEN_PREFIX).unwrap_or(s);
            secret.len() == 64 && secret.bytes().all(|b| b.is_ascii_hexdigit())
        })
    else {
        return reject(401, "Bearer credential required");
    };
    Ok(token.to_owned())
}
async fn require_session(
    State(state): State<AppState>,
    mut request: Request,
    next: Next,
) -> Result<Response, ApiError> {
    let token = bearer(request.headers())?;
    let (actor, scopes) = database(state.store, move |db| db.authenticate(&token)).await?;
    if let Some(scopes) = scopes
        && !scope_permits(&scopes, request.method(), request.uri().path())
    {
        return Err(Rejection {
            status: 403,
            message: "API token scope does not permit this request".into(),
        }
        .into());
    }
    request.extensions_mut().insert(actor);
    Ok(next.run(request).await)
}
/// API tokens narrow the owner's role: reads need `read`, writes need the
/// scope of their resource. Account security and token management stay
/// limited to interactive sessions, so a token cannot extend itself.
fn scope_permits(scopes: &[Scope], method: &Method, path: &str) -> bool {
    let path = path.strip_prefix("/api/v1/").unwrap_or(path);
    if path.starts_with("account/")
        || path.starts_with("dns/")
        || path.starts_with("commerce/")
        || path.starts_with("tickets")
        || path == "templates"
        || path.starts_with("templates/")
        || path == "diagnostics/mptcp"
        || path.contains("/templates/")
        || path.starts_with("api-tokens")
        || path.ends_with("/mfa/reset")
        || path == "auth/logout"
    {
        return false;
    }
    if path.starts_with("subscriptions") {
        return if method == Method::GET || method == Method::HEAD {
            scopes.contains(&Scope::Read)
        } else {
            scopes.contains(&Scope::UsersWrite)
        };
    }
    if path.starts_with("announcements") {
        return if method == Method::GET || method == Method::HEAD {
            scopes.contains(&Scope::Read)
        } else {
            scopes.contains(&Scope::UsersWrite)
        };
    }
    let needed = if method == Method::GET || method == Method::HEAD {
        Scope::Read
    } else if path.starts_with("nodes") || path.starts_with("configurations/") {
        Scope::NodesWrite
    } else if path.starts_with("budgets") {
        Scope::BudgetsWrite
    } else if path.starts_with("users") || path == "tenants" {
        Scope::UsersWrite
    } else {
        return false;
    };
    scopes.contains(&needed)
}
async fn security_headers(request: Request, next: Next) -> Response {
    let mut response = next.run(request).await;
    for (name, value) in [
        ("cache-control", "no-store"),
        ("x-content-type-options", "nosniff"),
        ("x-frame-options", "DENY"),
        ("referrer-policy", "no-referrer"),
        (
            "content-security-policy",
            "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        ),
    ] {
        response
            .headers_mut()
            .insert(name, HeaderValue::from_static(value));
    }
    response
}

pub fn router(state: AppState) -> Router {
    let authenticated = Router::new()
        .route("/api/v1/session", get(session))
        .route("/api/v1/auth/logout", post(logout))
        .route("/api/v1/nodes", get(nodes).post(create_node))
        .route("/api/v1/nodes/profiles", post(update_node_profiles))
        .route(
            "/api/v1/nodes/{node}/profile",
            axum::routing::put(update_node_profile),
        )
        .route("/api/v1/nodes/{node}/config", get(config).put(publish))
        .route("/api/v1/nodes/{node}/history", get(history))
        .route("/api/v1/nodes/{node}/credential", get(node_credential))
        .route(
            "/api/v1/nodes/{node}/credential/revoke",
            post(revoke_credential),
        )
        .route(
            "/api/v1/nodes/{node}/credential/replace",
            post(replace_credential),
        )
        .route(
            "/api/v1/nodes/{node}/credential/rotate",
            post(request_rotation),
        )
        .route("/api/v1/nodes/{node}/health", get(node_health))
        .route("/api/v1/nodes/{node}/rollback", post(rollback))
        .route("/api/v1/nodes/{node}/drain", post(drain))
        .route("/api/v1/topology", get(topology))
        .route("/api/v1/telemetry", get(telemetry))
        .route("/api/v1/configurations/preview", post(preview_batch))
        .route("/api/v1/configurations/publish", post(publish_batch))
        .route("/api/v1/users", get(users).post(create_user))
        .route(
            "/api/v1/users/{user}/revoke-sessions",
            post(revoke_sessions),
        )
        .route("/api/v1/users/{user}/mfa/reset", post(reset_second_factor))
        .route("/api/v1/account/password", post(change_password))
        .route("/api/v1/users/{user}/password", post(reset_user_password))
        .route(
            "/api/v1/users/{user}/disabled",
            axum::routing::put(set_user_disabled),
        )
        .route("/api/v1/users/{user}", delete(delete_user))
        .route(
            "/api/v1/users/{user}/rate",
            get(user_rate).put(set_user_rate),
        )
        .route("/api/v1/account/mfa", get(second_factor_status))
        .route("/api/v1/account/mfa/setup", post(begin_second_factor))
        .route("/api/v1/account/mfa/enable", post(enable_second_factor))
        .route("/api/v1/account/mfa/disable", post(disable_second_factor))
        .route("/api/v1/api-tokens", get(api_tokens).post(create_api_token))
        .route("/api/v1/api-tokens/{id}", delete(revoke_api_token))
        .route(
            "/api/v1/subscriptions",
            get(subscriptions).post(create_subscription),
        )
        .route(
            "/api/v1/subscriptions/{id}",
            get(subscription).delete(delete_subscription),
        )
        .route(
            "/api/v1/subscriptions/{id}/rotate",
            post(rotate_subscription),
        )
        .route(
            "/api/v1/subscriptions/{id}/preview",
            get(preview_subscription),
        )
        .route("/api/v1/diagnostics/mptcp", get(mptcp_diagnostics))
        .route("/api/v1/tickets", get(tickets).post(create_ticket))
        .route("/api/v1/templates", get(templates).post(create_template))
        .route(
            "/api/v1/templates/{id}",
            axum::routing::put(update_template).delete(delete_template),
        )
        .route("/api/v1/nodes/{node}/templates/{id}", post(apply_template))
        .route(
            "/api/v1/nodes/{node}/templates/{id}/preview",
            post(preview_template),
        )
        .route("/api/v1/templates/{id}/rollout", post(rollout_template))
        .route(
            "/api/v1/templates/{id}/rollouts/{rollout_id}/retry",
            post(retry_rollout),
        )
        .route("/api/v1/tickets/{id}", get(ticket))
        .route("/api/v1/tickets/{id}/messages", post(reply_ticket))
        .route(
            "/api/v1/tickets/{id}/status",
            axum::routing::put(set_ticket_status),
        )
        .route(
            "/api/v1/commerce/gift-codes",
            get(commerce_gift_codes).post(create_gift_code),
        )
        .route(
            "/api/v1/commerce/gift-codes/{id}",
            axum::routing::put(update_gift_code).delete(delete_gift_code),
        )
        .route("/api/v1/commerce/gift-codes/redeem", post(redeem_gift_code))
        .route(
            "/api/v1/commerce/coupons",
            get(commerce_coupons).post(create_coupon),
        )
        .route(
            "/api/v1/commerce/coupons/{id}",
            axum::routing::put(update_coupon).delete(delete_coupon),
        )
        .route(
            "/api/v1/commerce/plans",
            get(commerce_plans).post(create_commerce_plan),
        )
        .route(
            "/api/v1/commerce/plans/{id}",
            axum::routing::put(update_commerce_plan).delete(delete_commerce_plan),
        )
        .route("/api/v1/commerce/wallet", get(commerce_wallet))
        .route(
            "/api/v1/commerce/wallets/{user}/adjust",
            post(adjust_wallet),
        )
        .route(
            "/api/v1/commerce/orders",
            get(commerce_orders).post(create_order),
        )
        .route("/api/v1/commerce/orders/{id}/pay", post(pay_order))
        .route("/api/v1/commerce/orders/{id}/refund", post(refund_order))
        .route("/api/v1/commerce/orders/{id}/payment", post(create_payment))
        .route(
            "/api/v1/commerce/webhook",
            get(commerce_webhook).put(set_commerce_webhook),
        )
        .route(
            "/api/v1/announcements",
            get(announcements).post(create_announcement),
        )
        .route("/api/v1/announcements/manage", get(manage_announcements))
        .route(
            "/api/v1/announcements/{id}",
            axum::routing::put(update_announcement).delete(delete_announcement),
        )
        .route(
            "/api/v1/dns/providers",
            get(dns_providers).post(create_dns_provider),
        )
        .route(
            "/api/v1/dns/providers/{id}",
            get(dns_provider)
                .put(update_dns_provider)
                .delete(delete_dns_provider),
        )
        .route("/api/v1/dns/zones", get(dns_zones).post(create_dns_zone))
        .route(
            "/api/v1/dns/zones/{id}",
            get(dns_zone).put(update_dns_zone).delete(delete_dns_zone),
        )
        .route(
            "/api/v1/dns/zones/{id}/records",
            get(dns_records).post(create_dns_record),
        )
        .route("/api/v1/dns/zones/{id}/reconcile", post(reconcile_dns_zone))
        .route(
            "/api/v1/dns/records/{id}",
            get(dns_record)
                .put(update_dns_record)
                .delete(delete_dns_record),
        )
        .route("/api/v1/dns/records/{id}/ddns", post(dns_ddns))
        .route("/api/v1/tenants", post(create_tenant))
        .route("/api/v1/usage", get(usage))
        .route("/api/v1/budgets", get(budgets).post(create_budget))
        .route("/api/v1/budgets/{id}", axum::routing::put(update_budget))
        .route(
            "/api/v1/budgets/{id}/reservations",
            get(budget_reservations),
        )
        .route("/api/v1/alerts", get(alerts))
        .route(
            "/api/v1/alerts/settings",
            axum::routing::put(set_alert_settings),
        )
        .route("/api/v1/alerts/channels", post(create_alert_channel))
        .route(
            "/api/v1/alerts/channels/{id}",
            axum::routing::put(update_alert_channel).delete(delete_alert_channel),
        )
        .route(
            "/api/v1/alerts/channels/{id}/test",
            post(test_alert_channel),
        )
        .route("/api/v1/audit", get(audit))
        .route("/api/v1/recovery", get(recovery_status))
        .route("/api/v1/control/metrics", get(control_metrics))
        .route("/api/v1/capabilities", get(capabilities))
        .route_layer(middleware::from_fn_with_state(
            state.clone(),
            require_session,
        ));
    Router::new()
        .merge(authenticated)
        .route(
            "/api/v1/commerce/payments/callback",
            post(commerce_payment_callback),
        )
        .route("/sub/{token}", get(public_subscription))
        .route("/healthz", get(health))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/agent/enroll", post(enroll))
        .route("/api/v1/agent/credential/rotate", post(rotate_credential))
        .route("/api/v1/agent/lease", post(exchange_lease))
        .route("/api/v1/agent/lease/release", post(release_lease))
        .route("/api/v1/agent/budgets/recover", post(recover_agent_budget))
        .route("/api/v1/agent/reconcile", post(reconcile))
        .route("/api/v1/agent/sync", post(sync))
        .route("/api/v1/agent/watch", get(watch_config))
        .route(
            "/",
            get(|| async { Html(include_str!("../../../web/index.html")) }),
        )
        .route(
            "/assets/app.js",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/javascript; charset=utf-8")],
                    include_str!("../../../web/app.js"),
                )
            }),
        )
        .route(
            "/assets/style.css",
            get(|| async {
                (
                    [(header::CONTENT_TYPE, "text/css; charset=utf-8")],
                    include_str!("../../../web/style.css"),
                )
            }),
        )
        .fallback(|| async {
            (
                StatusCode::NOT_FOUND,
                Json(serde_json::json!({"error":"route not found"})),
            )
        })
        .layer(DefaultBodyLimit::max(2 * 1024 * 1024))
        .layer(middleware::from_fn(security_headers))
        .with_state(state)
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Login {
    username: String,
    password: String,
    /// Six-digit authenticator code or a recovery code; required once two-factor login is on.
    #[serde(default)]
    second_factor: Option<String>,
}
#[derive(Serialize)]
struct LoginResponse {
    token: String,
    user: Actor,
    expires_in_seconds: u32,
}
async fn login(
    State(state): State<AppState>,
    ConnectInfo(peer): ConnectInfo<SocketAddr>,
    Json(input): Json<Login>,
) -> Result<Response, ApiError> {
    if input.username.len() > 80
        || input.password.len() > 1024
        || input.second_factor.as_ref().is_some_and(|c| c.len() > 32)
    {
        return Err(Rejection {
            status: 400,
            message: "credentials exceed limits".into(),
        }
        .into());
    }
    if !state.login_allowed(peer.ip().to_string()) {
        return Err(Rejection {
            status: 429,
            message: "too many login attempts; retry in five minutes".into(),
        }
        .into());
    }
    let _slot = state.login_slots.clone().try_acquire_owned().map_err(|_| {
        ApiError(
            Rejection {
                status: 429,
                message: "login service busy".into(),
            }
            .into(),
        )
    })?;
    if state.second_factor_locked(&input.username, false) {
        return Err(Rejection {
            status: 429,
            message: "too many invalid two-factor codes; retry in five minutes".into(),
        }
        .into());
    }
    let username = input.username.clone();
    let result = database(state.store.clone(), move |db| {
        db.login_with_second_factor(
            &input.username,
            &input.password,
            input.second_factor.as_deref(),
        )
    })
    .await;
    let message = match &result {
        Err(ApiError(e)) => e.downcast_ref::<Rejection>().map(|r| r.message.as_str()),
        Ok(_) => None,
    };
    if message == Some(crate::store::SECOND_FACTOR_INVALID) {
        state.second_factor_locked(&username, true);
    }
    if message == Some(crate::store::SECOND_FACTOR_REQUIRED) {
        let body = serde_json::json!({"error":crate::store::SECOND_FACTOR_REQUIRED,"second_factor_required":true});
        return Ok((StatusCode::UNAUTHORIZED, Json(body)).into_response());
    }
    let (token, user) = result?;
    Ok(Json(LoginResponse {
        token,
        user,
        expires_in_seconds: 8 * 60 * 60,
    })
    .into_response())
}
impl From<Rejection> for ApiError {
    fn from(value: Rejection) -> Self {
        Self(value.into())
    }
}
async fn session(axum::Extension(actor): axum::Extension<Actor>) -> Json<Actor> {
    Json(actor)
}
async fn logout(State(state): State<AppState>, headers: HeaderMap) -> ApiResult<serde_json::Value> {
    let token = bearer(&headers)?;
    database(state.store, move |db| db.logout(&token)).await?;
    Ok(Json(serde_json::json!({"ok":true})))
}
async fn nodes(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Query(filter): Query<crate::node::NodeFilter>,
) -> ApiResult<Vec<crate::store::Node>> {
    Ok(Json(
        database(state.store, move |db| db.nodes_filtered(&actor, filter)).await?,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewNode {
    name: String,
    tenant_id: Option<String>,
    /// Omitted or `null`: availability mode, which keeps forwarding while the
    /// controller is unreachable. `{}` or `{"ttl_ms":..}`: strict lease.
    #[serde(default)]
    lease_policy: Option<crate::lease::LeasePolicy>,
    #[serde(default)]
    settings: crate::node::NodeSettings,
}
async fn create_node(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(input): Json<NewNode>,
) -> ApiResult<serde_json::Value> {
    let tenant = input.tenant_id.unwrap_or_else(|| actor.tenant_id.clone());
    let (node, token) = database(state.store, move |db| {
        db.create_node_with_settings(
            &actor,
            &tenant,
            &input.name,
            input.lease_policy,
            input.settings,
        )
    })
    .await?;
    Ok(Json(
        serde_json::json!({"node":node,"enrollment_token":token}),
    ))
}
async fn update_node_profile(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(node): Path<String>,
    Json(input): Json<crate::node::NodeUpdate>,
) -> ApiResult<crate::node::NodeUpdateResult> {
    Ok(Json(
        database(state.store, move |db| db.update_node(&actor, &node, input)).await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NodeProfileBatch {
    updates: Vec<crate::node::NodeBatchEntry>,
}
async fn update_node_profiles(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(input): Json<NodeProfileBatch>,
) -> ApiResult<Vec<crate::node::NodeUpdateResult>> {
    Ok(Json(
        database(state.store, move |db| {
            db.update_nodes(&actor, input.updates)
        })
        .await?,
    ))
}
async fn config(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(node): Path<String>,
) -> ApiResult<NodeConfig> {
    Ok(Json(
        database(state.store, move |db| db.config(&actor, &node, None)).await?,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Publish {
    expected_revision: u64,
    rules: Vec<Rule>,
    #[serde(default, deserialize_with = "crate::model::explicit")]
    rate_bytes_per_sec: Option<Option<u64>>,
}
async fn publish(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(node): Path<String>,
    Json(input): Json<Publish>,
) -> ApiResult<NodeConfig> {
    Ok(Json(
        database(state.store, move |db| {
            db.set_config_with_rate(
                &actor,
                &node,
                input.expected_revision,
                input.rules,
                input.rate_bytes_per_sec,
            )
        })
        .await?,
    ))
}
async fn history(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(node): Path<String>,
) -> ApiResult<Vec<serde_json::Value>> {
    Ok(Json(
        database(state.store, move |db| db.history(&actor, &node)).await?,
    ))
}

async fn node_health(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(node): Path<String>,
) -> ApiResult<serde_json::Value> {
    Ok(Json(
        database(state.store, move |db| db.node_health(&actor, &node)).await?,
    ))
}

async fn topology(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<serde_json::Value> {
    Ok(Json(
        database(state.store, move |db| db.topology(&actor)).await?,
    ))
}
async fn telemetry(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<serde_json::Value> {
    Ok(Json(
        database(state.store, move |db| db.telemetry(&actor)).await?,
    ))
}
async fn preview_batch(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(batch): Json<crate::topology::ConfigBatch>,
) -> ApiResult<crate::topology::BatchResult> {
    Ok(Json(
        database(state.store, move |db| db.preview_configs(&actor, batch)).await?,
    ))
}
async fn publish_batch(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(batch): Json<crate::topology::ConfigBatch>,
) -> ApiResult<crate::topology::BatchResult> {
    Ok(Json(
        database(state.store, move |db| db.publish_configs(&actor, batch)).await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Drain {
    draining: bool,
}
async fn drain(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(node): Path<String>,
    Json(input): Json<Drain>,
) -> ApiResult<crate::topology::BatchResult> {
    Ok(Json(
        database(state.store, move |db| {
            db.drain_node(&actor, &node, input.draining)
        })
        .await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Rollback {
    revision: u64,
    expected_revision: u64,
}
async fn rollback(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(node): Path<String>,
    Json(input): Json<Rollback>,
) -> ApiResult<NodeConfig> {
    Ok(Json(
        database(state.store, move |db| {
            let previous = db.config(&actor, &node, Some(input.revision))?;
            db.set_config_with_rate(
                &actor,
                &node,
                input.expected_revision,
                previous.rules,
                Some(previous.rate_bytes_per_sec),
            )
        })
        .await?,
    ))
}
async fn users(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<Vec<crate::store::UserSummary>> {
    Ok(Json(
        database(state.store, move |db| db.users(&actor)).await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ChangePassword {
    current_password: String,
    new_password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AdminPassword {
    password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SetUserDisabled {
    disabled: bool,
}
async fn change_password(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    headers: HeaderMap,
    Json(input): Json<ChangePassword>,
) -> ApiResult<serde_json::Value> {
    let token = bearer(&headers)?;
    database(state.store, move |db| {
        db.change_password(&actor, &input.current_password, &input.new_password, &token)
    })
    .await?;
    Ok(Json(serde_json::json!({"ok": true})))
}
async fn reset_user_password(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(user): Path<String>,
    Json(input): Json<AdminPassword>,
) -> ApiResult<serde_json::Value> {
    database(state.store, move |db| {
        db.reset_password(&actor, &user, &input.password)
    })
    .await?;
    Ok(Json(serde_json::json!({"ok": true})))
}
async fn set_user_disabled(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(user): Path<String>,
    Json(input): Json<SetUserDisabled>,
) -> ApiResult<serde_json::Value> {
    let disabled = database(state.store, move |db| {
        db.set_user_disabled(&actor, &user, input.disabled)
    })
    .await?;
    Ok(Json(serde_json::json!({"disabled": disabled})))
}
async fn delete_user(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(user): Path<String>,
) -> ApiResult<serde_json::Value> {
    database(state.store, move |db| db.delete_user(&actor, &user)).await?;
    Ok(Json(serde_json::json!({"ok": true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewUser {
    username: String,
    password: String,
    role: Role,
    tenant_id: Option<String>,
}
async fn create_user(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(input): Json<NewUser>,
) -> ApiResult<Actor> {
    let tenant = input.tenant_id.unwrap_or_else(|| actor.tenant_id.clone());
    Ok(Json(
        database(state.store, move |db| {
            db.create_user(
                &actor,
                &tenant,
                &input.username,
                &input.password,
                input.role,
            )
        })
        .await?,
    ))
}
async fn revoke_sessions(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(user): Path<String>,
) -> ApiResult<serde_json::Value> {
    database(state.store, move |db| db.revoke_sessions(&actor, &user)).await?;
    Ok(Json(serde_json::json!({"ok":true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PasswordConfirmation {
    password: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct SecondFactorCode {
    code: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DisableSecondFactor {
    password: String,
    code: String,
}
async fn second_factor_status(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<crate::store::SecondFactorStatus> {
    Ok(Json(
        database(state.store, move |db| db.second_factor_status(&actor)).await?,
    ))
}
async fn begin_second_factor(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(input): Json<PasswordConfirmation>,
) -> ApiResult<serde_json::Value> {
    let setup = database(state.store, move |db| {
        db.begin_second_factor(&actor, &input.password)
    })
    .await?;
    let qr = qrcode::QrCode::new(setup.otpauth_uri.as_bytes())
        .map_err(|e| ApiError(anyhow::anyhow!("QR encoding failed: {e}")))?
        .render::<qrcode::render::svg::Color>()
        .min_dimensions(200, 200)
        .build();
    Ok(Json(
        serde_json::json!({"secret":setup.secret,"otpauth_uri":setup.otpauth_uri,"qr_svg":qr}),
    ))
}
async fn enable_second_factor(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(input): Json<SecondFactorCode>,
) -> ApiResult<serde_json::Value> {
    let codes = database(state.store, move |db| {
        db.enable_second_factor(&actor, &input.code)
    })
    .await?;
    Ok(Json(serde_json::json!({"recovery_codes":codes})))
}
async fn disable_second_factor(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(input): Json<DisableSecondFactor>,
) -> ApiResult<serde_json::Value> {
    database(state.store, move |db| {
        db.disable_second_factor(&actor, &input.password, &input.code)
    })
    .await?;
    Ok(Json(serde_json::json!({"ok":true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UserRate {
    rate_bytes_per_sec: Option<u64>,
}
async fn set_user_rate(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(user): Path<String>,
    Json(input): Json<UserRate>,
) -> ApiResult<crate::store::UserRateView> {
    Ok(Json(
        database(state.store, move |db| {
            db.set_user_rate(&actor, &user, input.rate_bytes_per_sec)?;
            db.user_rate(&actor, &user)
        })
        .await?,
    ))
}
async fn user_rate(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(user): Path<String>,
) -> ApiResult<crate::store::UserRateView> {
    Ok(Json(
        database(state.store, move |db| db.user_rate(&actor, &user)).await?,
    ))
}
async fn reset_second_factor(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(user): Path<String>,
) -> ApiResult<serde_json::Value> {
    database(state.store, move |db| db.reset_second_factor(&actor, &user)).await?;
    Ok(Json(serde_json::json!({"ok":true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewApiToken {
    name: String,
    scopes: Vec<Scope>,
    expires_in_days: u32,
}
async fn api_tokens(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<Vec<crate::store::ApiToken>> {
    Ok(Json(
        database(state.store, move |db| db.api_tokens(&actor)).await?,
    ))
}
async fn create_api_token(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(input): Json<NewApiToken>,
) -> ApiResult<serde_json::Value> {
    let (token, record) = database(state.store, move |db| {
        db.create_api_token(&actor, &input.name, &input.scopes, input.expires_in_days)
    })
    .await?;
    Ok(Json(serde_json::json!({"token":token,"api_token":record})))
}
async fn revoke_api_token(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    database(state.store, move |db| db.revoke_api_token(&actor, &id)).await?;
    Ok(Json(serde_json::json!({"ok":true})))
}
async fn alerts(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<serde_json::Value> {
    Ok(Json(
        database(state.store, move |db| db.alert_overview(&actor)).await?,
    ))
}
async fn set_alert_settings(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(settings): Json<crate::alerts::Settings>,
) -> ApiResult<serde_json::Value> {
    database(state.store, move |db| {
        db.set_alert_settings(&actor, settings)
    })
    .await?;
    Ok(Json(serde_json::json!({"ok":true})))
}
async fn create_alert_channel(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(channel): Json<crate::alerts::Channel>,
) -> ApiResult<crate::alerts::ChannelView> {
    Ok(Json(
        database(state.store, move |db| {
            db.save_alert_channel(&actor, None, channel)
        })
        .await?,
    ))
}
async fn update_alert_channel(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
    Json(channel): Json<crate::alerts::Channel>,
) -> ApiResult<crate::alerts::ChannelView> {
    Ok(Json(
        database(state.store, move |db| {
            db.save_alert_channel(&actor, Some(&id), channel)
        })
        .await?,
    ))
}
async fn delete_alert_channel(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    database(state.store, move |db| db.delete_alert_channel(&actor, &id)).await?;
    Ok(Json(serde_json::json!({"ok":true})))
}
async fn test_alert_channel(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.clone();
    let channel = database(state.store, move |db| db.alert_channel(&actor, &id)).await?;
    crate::alerts::test(&channel, &store.alerts())
        .await
        .or_else(|error| reject(502, format!("test message failed: {error:#}")))
        .map_err(ApiError)?;
    Ok(Json(serde_json::json!({"ok":true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewTenant {
    name: String,
}
async fn create_tenant(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(input): Json<NewTenant>,
) -> ApiResult<serde_json::Value> {
    let name = input.name.clone();
    let id = database(state.store, move |db| db.create_tenant(&actor, &input.name)).await?;
    Ok(Json(serde_json::json!({"id":id,"name":name})))
}
async fn usage(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<Vec<serde_json::Value>> {
    Ok(Json(
        database(state.store, move |db| db.reported_usage(&actor)).await?,
    ))
}
async fn audit(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<Vec<serde_json::Value>> {
    Ok(Json(
        database(state.store, move |db| db.audit_log(&actor)).await?,
    ))
}

#[derive(Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Enrollment {
    pub node_id: String,
    pub enrollment_token: String,
    pub credential: String,
    #[serde(default)]
    pub identity_revision_supported: bool,
}
#[derive(Serialize, Deserialize)]
pub struct EnrollmentResponse {
    pub enrolled: bool,
    #[serde(default = "initial_credential_revision")]
    pub credential_revision: u64,
}
fn initial_credential_revision() -> u64 {
    1
}
async fn enroll(
    State(state): State<AppState>,
    Json(input): Json<Enrollment>,
) -> ApiResult<EnrollmentResponse> {
    if !identifier(&input.node_id) || input.enrollment_token.len() != 64 {
        return Err(Rejection {
            status: 400,
            message: "invalid enrollment request".into(),
        }
        .into());
    }
    let credential_revision = database(state.store, move |db| {
        db.enroll_with_capability(
            &input.node_id,
            &input.enrollment_token,
            &input.credential,
            input.identity_revision_supported,
        )
    })
    .await?;
    Ok(Json(EnrollmentResponse {
        enrolled: true,
        credential_revision,
    }))
}
async fn reconcile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ReconcileRequest>,
) -> ApiResult<ReconcileResponse> {
    let token = bearer(&headers)?;
    Ok(Json(
        database(state.store, move |db| {
            db.reconcile_authenticated(&token, input)
        })
        .await?,
    ))
}
async fn node_credential(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(node): Path<String>,
) -> ApiResult<crate::credential::CredentialStatus> {
    Ok(Json(
        database(state.store, move |db| {
            db.node_credential_status(&actor, &node)
        })
        .await?,
    ))
}
async fn revoke_credential(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(node): Path<String>,
    Json(input): Json<crate::credential::RevokeCredential>,
) -> ApiResult<crate::credential::CredentialStatus> {
    Ok(Json(
        database(state.store, move |db| {
            db.revoke_node_credential(&actor, &node, input)
        })
        .await?,
    ))
}
async fn replace_credential(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(node): Path<String>,
    Json(input): Json<crate::credential::ReplaceCredential>,
) -> ApiResult<crate::credential::CredentialStatus> {
    Ok(Json(
        database(state.store, move |db| {
            db.replace_node_credential(&actor, &node, input)
        })
        .await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RequestRotation {
    expected_revision: u64,
}
async fn request_rotation(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(node): Path<String>,
    Json(input): Json<RequestRotation>,
) -> ApiResult<crate::credential::CredentialStatus> {
    Ok(Json(
        database(state.store, move |db| {
            db.request_credential_rotation(&actor, &node, input.expected_revision)
        })
        .await?,
    ))
}
async fn rotate_credential(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<crate::credential::RotateCredential>,
) -> ApiResult<crate::credential::RotationReceipt> {
    let token = bearer(&headers)?;
    Ok(Json(
        database(state.store, move |db| {
            db.rotate_node_credential(&token, input)
        })
        .await?,
    ))
}
async fn exchange_lease(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<crate::lease::LeaseRequest>,
) -> ApiResult<crate::lease::LeaseReply> {
    let token = bearer(&headers)?;
    Ok(Json(
        database(state.store, move |db| db.exchange_lease(&token, input)).await?,
    ))
}
async fn release_lease(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<crate::lease::LeaseRelease>,
) -> ApiResult<serde_json::Value> {
    let token = bearer(&headers)?;
    database(state.store, move |db| db.release_lease(&token, input)).await?;
    Ok(Json(serde_json::json!({"released":true})))
}
async fn recover_agent_budget(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<crate::budget::BudgetRecoveryRequest>,
) -> ApiResult<crate::budget::BudgetReply> {
    let token = bearer(&headers)?;
    Ok(Json(
        database(state.store, move |db| db.recover_budget_run(&token, input)).await?,
    ))
}
async fn sync(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<SyncRequest>,
) -> ApiResult<SyncResponse> {
    let token = bearer(&headers)?;
    let mut result = state.sync_queue.submit(token, input).await?;
    result.controller_instance = state.instance;
    Ok(Json(result))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WatchQuery {
    after: u64,
}
/// Long poll: answers once the node's desired revision exceeds `after`, or
/// after 25 s with the unchanged revision. Agents then sync immediately.
async fn watch_config(
    State(state): State<AppState>,
    headers: HeaderMap,
    Query(query): Query<WatchQuery>,
) -> ApiResult<serde_json::Value> {
    let token = bearer(&headers)?;
    let deadline = tokio::time::Instant::now() + std::time::Duration::from_secs(25);
    loop {
        let published = state.store.config_published();
        let credential = token.clone();
        let revision = database(state.store.clone(), move |db| {
            db.node_desired_revision(&credential)
        })
        .await?;
        let reply = Json(serde_json::json!({ "desired_revision": revision }));
        if revision > query.after {
            return Ok(reply);
        }
        tokio::select! {
            changed = tokio::time::timeout_at(deadline, published) => if changed.is_err() {
                return Ok(reply);
            },
            _ = state.stopping.cancelled() => return Ok(reply),
        }
    }
}
async fn control_metrics(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<crate::sync_queue::SyncQueueStats> {
    if actor.role != Role::SystemAdmin {
        return Err(Rejection {
            status: 403,
            message: "control metrics require system administrator access".into(),
        }
        .into());
    }
    Ok(Json(state.sync_queue.stats()))
}
async fn health(State(state): State<AppState>) -> (StatusCode, Json<serde_json::Value>) {
    let healthy = database(state.store, |db| db.recovery_log_status())
        .await
        .is_ok_and(|s| s.healthy);
    (
        if healthy {
            StatusCode::OK
        } else {
            StatusCode::SERVICE_UNAVAILABLE
        },
        Json(
            serde_json::json!({"status":if healthy {"ok"}else{"recovery_log_unavailable"},"version":env!("CARGO_PKG_VERSION")}),
        ),
    )
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewSubscription {
    name: String,
    format: Format,
    #[serde(default)]
    template: Template,
    #[serde(default = "default_subscription_days")]
    expires_in_days: u32,
    /// System administrators and tenant administrators may create a
    /// subscription for another user in their scope.
    #[serde(default)]
    user_id: Option<String>,
}
fn default_subscription_days() -> u32 {
    365
}
async fn subscriptions(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<Vec<crate::subscription::SubscriptionView>> {
    Ok(Json(
        database(state.store, move |db| db.subscriptions(&actor)).await?,
    ))
}
async fn create_subscription(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(input): Json<NewSubscription>,
) -> ApiResult<serde_json::Value> {
    let (subscription, token) = database(state.store, move |db| {
        db.create_subscription(
            &actor,
            input.user_id.as_deref(),
            &input.name,
            input.format,
            input.template,
            input.expires_in_days,
        )
    })
    .await?;
    Ok(Json(
        serde_json::json!({"subscription": subscription, "token": token}),
    ))
}
async fn subscription(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
) -> ApiResult<crate::subscription::SubscriptionView> {
    Ok(Json(
        database(state.store, move |db| db.subscription(&actor, &id)).await?,
    ))
}
async fn rotate_subscription(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let (subscription, token) =
        database(state.store, move |db| db.rotate_subscription(&actor, &id)).await?;
    Ok(Json(
        serde_json::json!({"subscription": subscription, "token": token}),
    ))
}
async fn delete_subscription(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    database(state.store, move |db| db.delete_subscription(&actor, &id)).await?;
    Ok(Json(serde_json::json!({"ok": true})))
}
async fn preview_subscription(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
) -> ApiResult<crate::subscription::Rendered> {
    Ok(Json(
        database(state.store, move |db| db.render_subscription(&actor, &id)).await?,
    ))
}
async fn public_subscription(
    State(state): State<AppState>,
    Path(token): Path<String>,
) -> Result<Response, ApiError> {
    if !state.subscription_allowed(&token) {
        return Err(Rejection {
            status: 429,
            message: "subscription token is rate limited; retry in one minute".into(),
        }
        .into());
    }
    let rendered = database(state.store, move |db| db.render_public_subscription(&token)).await?;
    let mut response = Response::new(Body::from(rendered.content));
    response.headers_mut().insert(
        header::CONTENT_TYPE,
        HeaderValue::from_static(rendered.content_type),
    );
    response
        .headers_mut()
        .insert(header::CACHE_CONTROL, HeaderValue::from_static("no-store"));
    response.headers_mut().insert(
        "x-content-type-options",
        HeaderValue::from_static("nosniff"),
    );
    Ok(response)
}

async fn mptcp_diagnostics(
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<crate::mptcp::Capability> {
    if actor.role != Role::SystemAdmin {
        return Err(ApiError(
            Rejection {
                status: 403,
                message: "system administrator required for MPTCP diagnostics".into(),
            }
            .into(),
        ));
    }
    Ok(Json(crate::mptcp::detect()))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RolloutInput {
    batch_size: usize,
    #[serde(default)]
    rollback_on_failure: bool,
    targets: Vec<crate::template::RolloutTargetInput>,
}
async fn retry_rollout(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path((template_id, rollout_id)): Path<(String, String)>,
) -> ApiResult<crate::template::RolloutReport> {
    Ok(Json(
        database(state.store, move |db| {
            db.retry_rollout(&actor, &template_id, &rollout_id)
        })
        .await?,
    ))
}
async fn rollout_template(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
    Json(input): Json<RolloutInput>,
) -> ApiResult<crate::template::RolloutReport> {
    let targets = input
        .targets
        .into_iter()
        .map(|target| {
            let listen = target.listen.parse().map_err(|_| {
                ApiError(
                    Rejection {
                        status: 400,
                        message: format!("invalid rollout listen for {}", target.node_id),
                    }
                    .into(),
                )
            })?;
            Ok(crate::template::RolloutTarget {
                node_id: target.node_id,
                expected_revision: target.expected_revision,
                name: target.name,
                listen,
                variables: target.variables,
            })
        })
        .collect::<std::result::Result<Vec<_>, ApiError>>()?;
    Ok(Json(
        database(state.store, move |db| {
            db.rollout_template(
                &actor,
                &id,
                &targets,
                input.batch_size,
                input.rollback_on_failure,
            )
        })
        .await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PreviewTemplate {
    name: String,
    listen: String,
}
async fn preview_template(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path((node, id)): Path<(String, String)>,
    Json(input): Json<PreviewTemplate>,
) -> ApiResult<crate::template::TemplatePreview> {
    let listen: std::net::SocketAddr = input.listen.parse().map_err(|_| {
        ApiError(
            Rejection {
                status: 400,
                message: "invalid listen address".into(),
            }
            .into(),
        )
    })?;
    Ok(Json(
        database(state.store, move |db| {
            db.preview_template(&actor, &node, &id, &input.name, listen)
        })
        .await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ApplyTemplate {
    expected_revision: u64,
    name: String,
    listen: String,
    #[serde(default)]
    variables: std::collections::BTreeMap<String, String>,
}
async fn templates(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<Vec<crate::template::RuleTemplate>> {
    Ok(Json(
        database(state.store, move |db| db.templates(&actor)).await?,
    ))
}
async fn create_template(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(input): Json<crate::template::TemplateInput>,
) -> ApiResult<crate::template::RuleTemplate> {
    Ok(Json(
        database(state.store, move |db| db.create_template(&actor, input)).await?,
    ))
}
async fn update_template(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
    Json(input): Json<crate::template::TemplateInput>,
) -> ApiResult<crate::template::RuleTemplate> {
    Ok(Json(
        database(state.store, move |db| {
            db.update_template(&actor, &id, input)
        })
        .await?,
    ))
}
async fn delete_template(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    database(state.store, move |db| db.delete_template(&actor, &id)).await?;
    Ok(Json(serde_json::json!({"ok": true})))
}
async fn apply_template(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path((node, id)): Path<(String, String)>,
    Json(input): Json<ApplyTemplate>,
) -> ApiResult<NodeConfig> {
    let listen: std::net::SocketAddr = input.listen.parse().map_err(|_| {
        ApiError(
            Rejection {
                status: 400,
                message: "invalid listen address".into(),
            }
            .into(),
        )
    })?;
    Ok(Json(
        database(state.store, move |db| {
            db.apply_template_with_variables(
                &actor,
                &node,
                &id,
                input.expected_revision,
                &input.name,
                listen,
                &input.variables,
            )
        })
        .await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewTicketInput {
    subject: String,
    body: String,
    #[serde(default = "ticket_normal")]
    priority: crate::ticket::TicketPriority,
}
fn ticket_normal() -> crate::ticket::TicketPriority {
    crate::ticket::TicketPriority::Normal
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TicketReplyInput {
    body: String,
    #[serde(default)]
    internal: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TicketStatusInput {
    status: crate::ticket::TicketStatus,
}
async fn tickets(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<Vec<crate::ticket::Ticket>> {
    Ok(Json(
        database(state.store, move |db| db.tickets(&actor)).await?,
    ))
}
async fn ticket(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
) -> ApiResult<crate::ticket::TicketView> {
    Ok(Json(
        database(state.store, move |db| db.ticket(&actor, &id)).await?,
    ))
}
async fn create_ticket(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(input): Json<NewTicketInput>,
) -> ApiResult<crate::ticket::TicketView> {
    Ok(Json(
        database(state.store, move |db| {
            db.create_ticket(
                &actor,
                crate::ticket::NewTicket {
                    subject: input.subject,
                    body: input.body,
                    priority: input.priority,
                },
            )
        })
        .await?,
    ))
}
async fn reply_ticket(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
    Json(input): Json<TicketReplyInput>,
) -> ApiResult<crate::ticket::TicketView> {
    Ok(Json(
        database(state.store, move |db| {
            db.reply_ticket(&actor, &id, &input.body, input.internal)
        })
        .await?,
    ))
}
async fn set_ticket_status(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
    Json(input): Json<TicketStatusInput>,
) -> ApiResult<crate::ticket::TicketView> {
    Ok(Json(
        database(state.store, move |db| {
            db.set_ticket_status(&actor, &id, input.status)
        })
        .await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommerceGiftCodeInput {
    code: String,
    amount_cents: i64,
    #[serde(default = "announcement_start")]
    starts_at_ms: i64,
    #[serde(default)]
    ends_at_ms: Option<i64>,
    #[serde(default)]
    max_redemptions: Option<u32>,
    #[serde(default = "commerce_enabled")]
    enabled: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct RedeemGiftCode {
    code: String,
}
impl From<CommerceGiftCodeInput> for crate::commerce::GiftCodeInput {
    fn from(value: CommerceGiftCodeInput) -> Self {
        Self {
            code: value.code,
            amount_cents: value.amount_cents,
            starts_at_ms: value.starts_at_ms,
            ends_at_ms: value.ends_at_ms,
            max_redemptions: value.max_redemptions,
            enabled: value.enabled,
        }
    }
}
async fn commerce_gift_codes(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<Vec<crate::commerce::GiftCode>> {
    Ok(Json(
        database(state.store, move |db| db.commerce_gift_codes(&actor)).await?,
    ))
}
async fn create_gift_code(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(input): Json<CommerceGiftCodeInput>,
) -> ApiResult<crate::commerce::GiftCode> {
    Ok(Json(
        database(state.store, move |db| {
            db.create_gift_code(&actor, input.into())
        })
        .await?,
    ))
}
async fn update_gift_code(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
    Json(input): Json<CommerceGiftCodeInput>,
) -> ApiResult<crate::commerce::GiftCode> {
    Ok(Json(
        database(state.store, move |db| {
            db.update_gift_code(&actor, &id, input.into())
        })
        .await?,
    ))
}
async fn delete_gift_code(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    database(state.store, move |db| db.delete_gift_code(&actor, &id)).await?;
    Ok(Json(serde_json::json!({"ok": true})))
}
async fn redeem_gift_code(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(input): Json<RedeemGiftCode>,
) -> ApiResult<crate::commerce::Wallet> {
    Ok(Json(
        database(state.store, move |db| {
            db.redeem_gift_code(&actor, &input.code)
        })
        .await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommerceCouponInput {
    code: String,
    kind: crate::commerce::CouponKind,
    value: i64,
    #[serde(default)]
    min_amount_cents: i64,
    #[serde(default = "announcement_start")]
    starts_at_ms: i64,
    #[serde(default)]
    ends_at_ms: Option<i64>,
    #[serde(default)]
    max_redemptions: Option<u32>,
    #[serde(default = "commerce_enabled")]
    enabled: bool,
}
impl From<CommerceCouponInput> for crate::commerce::CouponInput {
    fn from(value: CommerceCouponInput) -> Self {
        Self {
            code: value.code,
            kind: value.kind,
            value: value.value,
            min_amount_cents: value.min_amount_cents,
            starts_at_ms: value.starts_at_ms,
            ends_at_ms: value.ends_at_ms,
            max_redemptions: value.max_redemptions,
            enabled: value.enabled,
        }
    }
}
async fn commerce_coupons(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<Vec<crate::commerce::Coupon>> {
    Ok(Json(
        database(state.store, move |db| db.commerce_coupons(&actor)).await?,
    ))
}
async fn create_coupon(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(input): Json<CommerceCouponInput>,
) -> ApiResult<crate::commerce::Coupon> {
    Ok(Json(
        database(state.store, move |db| {
            db.create_coupon(&actor, input.into())
        })
        .await?,
    ))
}
async fn update_coupon(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
    Json(input): Json<CommerceCouponInput>,
) -> ApiResult<crate::commerce::Coupon> {
    Ok(Json(
        database(state.store, move |db| {
            db.update_coupon(&actor, &id, input.into())
        })
        .await?,
    ))
}
async fn delete_coupon(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    database(state.store, move |db| db.delete_coupon(&actor, &id)).await?;
    Ok(Json(serde_json::json!({"ok": true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CommercePlanInput {
    name: String,
    #[serde(default)]
    description: String,
    price_cents: i64,
    duration_days: u32,
    #[serde(default)]
    traffic_bytes: Option<u64>,
    #[serde(default = "commerce_enabled")]
    enabled: bool,
}
fn commerce_enabled() -> bool {
    true
}
impl From<CommercePlanInput> for crate::commerce::PlanInput {
    fn from(value: CommercePlanInput) -> Self {
        Self {
            name: value.name,
            description: value.description,
            price_cents: value.price_cents,
            duration_days: value.duration_days,
            traffic_bytes: value.traffic_bytes,
            enabled: value.enabled,
        }
    }
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WalletAdjustment {
    delta_cents: i64,
    reference: String,
    #[serde(default)]
    description: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewOrder {
    plan_id: String,
    #[serde(default)]
    coupon_code: Option<String>,
}
async fn commerce_plans(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<Vec<crate::commerce::Plan>> {
    Ok(Json(
        database(state.store, move |db| db.commerce_plans(&actor)).await?,
    ))
}
async fn create_commerce_plan(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(input): Json<CommercePlanInput>,
) -> ApiResult<crate::commerce::Plan> {
    Ok(Json(
        database(state.store, move |db| {
            db.create_commerce_plan(&actor, input.into())
        })
        .await?,
    ))
}
async fn update_commerce_plan(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
    Json(input): Json<CommercePlanInput>,
) -> ApiResult<crate::commerce::Plan> {
    Ok(Json(
        database(state.store, move |db| {
            db.update_commerce_plan(&actor, &id, input.into())
        })
        .await?,
    ))
}
async fn delete_commerce_plan(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    database(state.store, move |db| db.delete_commerce_plan(&actor, &id)).await?;
    Ok(Json(serde_json::json!({"ok": true})))
}
async fn commerce_wallet(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<crate::commerce::WalletView> {
    let user = actor.id.clone();
    Ok(Json(
        database(state.store, move |db| db.wallet(&actor, &user)).await?,
    ))
}
async fn adjust_wallet(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(user): Path<String>,
    Json(input): Json<WalletAdjustment>,
) -> ApiResult<crate::commerce::Wallet> {
    Ok(Json(
        database(state.store, move |db| {
            db.adjust_wallet(
                &actor,
                &user,
                input.delta_cents,
                &input.reference,
                &input.description,
            )
        })
        .await?,
    ))
}
async fn commerce_orders(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<Vec<crate::commerce::Order>> {
    Ok(Json(
        database(state.store, move |db| db.orders(&actor)).await?,
    ))
}
async fn create_order(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(input): Json<NewOrder>,
) -> ApiResult<crate::commerce::Order> {
    Ok(Json(
        database(state.store, move |db| {
            db.create_order_with_coupon(&actor, &input.plan_id, input.coupon_code.as_deref())
        })
        .await?,
    ))
}
async fn pay_order(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
) -> ApiResult<crate::commerce::Order> {
    Ok(Json(
        database(state.store, move |db| db.pay_order(&actor, &id)).await?,
    ))
}
async fn refund_order(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
) -> ApiResult<crate::commerce::Order> {
    Ok(Json(
        database(state.store, move |db| db.refund_order(&actor, &id)).await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct WebhookSet {
    secret: String,
    #[serde(default = "commerce_enabled")]
    enabled: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct PaymentCallback {
    payment_id: String,
    status: crate::commerce::PaymentStatus,
    #[serde(default)]
    external_id: Option<String>,
    amount_cents: i64,
}
async fn commerce_webhook(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<crate::commerce::WebhookView> {
    Ok(Json(
        database(state.store, move |db| db.commerce_webhook(&actor)).await?,
    ))
}
async fn set_commerce_webhook(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(input): Json<WebhookSet>,
) -> ApiResult<crate::commerce::WebhookView> {
    Ok(Json(
        database(state.store, move |db| {
            db.set_commerce_webhook(&actor, &input.secret, input.enabled)
        })
        .await?,
    ))
}
async fn create_payment(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
) -> ApiResult<crate::commerce::Payment> {
    Ok(Json(
        database(state.store, move |db| db.create_payment(&actor, &id)).await?,
    ))
}
/// Public gateway callback. Authentication is the HMAC over the exact raw body.
async fn commerce_payment_callback(
    State(state): State<AppState>,
    headers: HeaderMap,
    body: axum::body::Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    let webhook = database(state.store.clone(), move |db| db.commerce_webhook_secret())
        .await?
        .ok_or_else(|| {
            ApiError(
                Rejection {
                    status: 409,
                    message: "payment webhook is not configured".into(),
                }
                .into(),
            )
        })?;
    if !webhook.enabled {
        return Err(Rejection {
            status: 409,
            message: "payment webhook is disabled".into(),
        }
        .into());
    }
    let signature = headers
        .get("x-relay-signature")
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("sha256=").or(Some(value)))
        .and_then(hex_decode)
        .ok_or_else(|| {
            ApiError(
                Rejection {
                    status: 401,
                    message: "missing or invalid payment signature".into(),
                }
                .into(),
            )
        })?;
    let expected = ring::hmac::sign(
        &ring::hmac::Key::new(ring::hmac::HMAC_SHA256, webhook.secret.as_bytes()),
        &body,
    );
    let expected = expected.as_ref();
    let mismatch = signature.len() != expected.len()
        || signature
            .iter()
            .zip(expected)
            .fold(0u8, |diff, (left, right)| diff | (left ^ right))
            != 0;
    if mismatch {
        return Err(Rejection {
            status: 401,
            message: "payment signature rejected".into(),
        }
        .into());
    }
    let input: PaymentCallback = serde_json::from_slice(&body).map_err(|_| {
        ApiError(
            Rejection {
                status: 400,
                message: "invalid payment callback JSON".into(),
            }
            .into(),
        )
    })?;
    let (payment, duplicate) = database(state.store, move |db| {
        db.settle_external_payment(
            &input.payment_id,
            input.status,
            input.external_id.as_deref(),
            input.amount_cents,
        )
    })
    .await?;
    Ok(Json(
        serde_json::json!({"payment": payment, "duplicate": duplicate}),
    ))
}
fn hex_decode(value: &str) -> Option<Vec<u8>> {
    if !value.len().is_multiple_of(2) || !value.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    (0..value.len())
        .step_by(2)
        .map(|index| u8::from_str_radix(&value[index..index + 2], 16).ok())
        .collect()
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct AnnouncementInput {
    #[serde(default)]
    tenant_id: Option<String>,
    title: String,
    body: String,
    severity: crate::announcement::Severity,
    #[serde(default = "announcement_start")]
    starts_at_ms: i64,
    #[serde(default)]
    ends_at_ms: Option<i64>,
    #[serde(default = "announcement_enabled")]
    enabled: bool,
}
fn announcement_start() -> i64 {
    now_ms()
}
fn announcement_enabled() -> bool {
    true
}
async fn announcements(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<Vec<crate::announcement::Announcement>> {
    Ok(Json(
        database(state.store, move |db| db.announcements(&actor)).await?,
    ))
}
async fn manage_announcements(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<Vec<crate::announcement::Announcement>> {
    Ok(Json(
        database(state.store, move |db| db.manage_announcements(&actor)).await?,
    ))
}
async fn create_announcement(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(input): Json<AnnouncementInput>,
) -> ApiResult<crate::announcement::Announcement> {
    Ok(Json(
        database(state.store, move |db| {
            db.create_announcement(
                &actor,
                crate::announcement::AnnouncementDraft {
                    tenant_id: input.tenant_id,
                    title: input.title,
                    body: input.body,
                    severity: input.severity,
                    starts_at_ms: input.starts_at_ms,
                    ends_at_ms: input.ends_at_ms,
                    enabled: input.enabled,
                },
            )
        })
        .await?,
    ))
}
async fn update_announcement(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
    Json(input): Json<AnnouncementInput>,
) -> ApiResult<crate::announcement::Announcement> {
    Ok(Json(
        database(state.store, move |db| {
            db.update_announcement(
                &actor,
                &id,
                crate::announcement::AnnouncementDraft {
                    tenant_id: input.tenant_id,
                    title: input.title,
                    body: input.body,
                    severity: input.severity,
                    starts_at_ms: input.starts_at_ms,
                    ends_at_ms: input.ends_at_ms,
                    enabled: input.enabled,
                },
            )
        })
        .await?,
    ))
}
async fn delete_announcement(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    database(state.store, move |db| db.delete_announcement(&actor, &id)).await?;
    Ok(Json(serde_json::json!({"ok": true})))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewDnsProvider {
    name: String,
    kind: crate::dns::ProviderKind,
    #[serde(default)]
    endpoint: Option<String>,
    token: String,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateDnsProvider {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    endpoint: Option<String>,
    #[serde(default)]
    token: Option<String>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewDnsZone {
    provider_id: String,
    name: String,
    mode: crate::dns::ZoneMode,
    #[serde(default)]
    min_keep: u32,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateDnsZone {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    mode: Option<crate::dns::ZoneMode>,
    #[serde(default)]
    min_keep: Option<u32>,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewDnsRecord {
    name: String,
    #[serde(rename = "type")]
    record_type: crate::dns::RecordType,
    content: String,
    #[serde(default = "default_dns_ttl")]
    ttl: u32,
    #[serde(default)]
    proxied: bool,
    #[serde(default)]
    health: Option<crate::dns::HealthGate>,
}
fn default_dns_ttl() -> u32 {
    300
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UpdateDnsRecord {
    #[serde(default)]
    name: Option<String>,
    #[serde(default)]
    content: Option<String>,
    #[serde(default)]
    ttl: Option<u32>,
    #[serde(default)]
    proxied: Option<bool>,
    #[serde(default)]
    enabled: Option<bool>,
    #[serde(default)]
    health: Option<crate::dns::HealthGate>,
    #[serde(default)]
    clear_health: bool,
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct DdnsUpdate {
    content: String,
}
async fn dns_providers(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<Vec<crate::dns::ProviderView>> {
    Ok(Json(
        database(state.store, move |db| db.dns_providers(&actor)).await?,
    ))
}
async fn dns_provider(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
) -> ApiResult<crate::dns::ProviderView> {
    Ok(Json(
        database(state.store, move |db| db.dns_provider(&actor, &id)).await?,
    ))
}
async fn create_dns_provider(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(input): Json<NewDnsProvider>,
) -> ApiResult<crate::dns::ProviderView> {
    let endpoint = input
        .endpoint
        .unwrap_or_else(|| "https://api.cloudflare.com/client/v4".into());
    Ok(Json(
        database(state.store, move |db| {
            db.create_dns_provider(&actor, &input.name, input.kind, &endpoint, &input.token)
        })
        .await?,
    ))
}
async fn update_dns_provider(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
    Json(input): Json<UpdateDnsProvider>,
) -> ApiResult<crate::dns::ProviderView> {
    Ok(Json(
        database(state.store, move |db| {
            db.update_dns_provider(
                &actor,
                &id,
                input.name.as_deref(),
                input.endpoint.as_deref(),
                input.token.as_deref(),
            )
        })
        .await?,
    ))
}
async fn delete_dns_provider(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    database(state.store, move |db| db.delete_dns_provider(&actor, &id)).await?;
    Ok(Json(serde_json::json!({"ok": true})))
}
async fn dns_zones(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<Vec<crate::dns::Zone>> {
    Ok(Json(
        database(state.store, move |db| db.dns_zones(&actor)).await?,
    ))
}
async fn dns_zone(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
) -> ApiResult<crate::dns::Zone> {
    Ok(Json(
        database(state.store, move |db| db.dns_zone(&actor, &id)).await?,
    ))
}
async fn create_dns_zone(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(input): Json<NewDnsZone>,
) -> ApiResult<crate::dns::Zone> {
    Ok(Json(
        database(state.store, move |db| {
            db.create_dns_zone(
                &actor,
                &input.provider_id,
                &input.name,
                input.mode,
                input.min_keep,
            )
        })
        .await?,
    ))
}
async fn update_dns_zone(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
    Json(input): Json<UpdateDnsZone>,
) -> ApiResult<crate::dns::Zone> {
    Ok(Json(
        database(state.store, move |db| {
            db.update_dns_zone(
                &actor,
                &id,
                input.name.as_deref(),
                input.mode,
                input.min_keep,
            )
        })
        .await?,
    ))
}
async fn delete_dns_zone(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    database(state.store, move |db| db.delete_dns_zone(&actor, &id)).await?;
    Ok(Json(serde_json::json!({"ok": true})))
}
async fn dns_records(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(zone): Path<String>,
) -> ApiResult<Vec<crate::dns::RecordView>> {
    Ok(Json(
        database(state.store, move |db| db.dns_records(&actor, &zone)).await?,
    ))
}
async fn dns_record(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
) -> ApiResult<crate::dns::RecordView> {
    Ok(Json(
        database(state.store, move |db| db.dns_record(&actor, &id)).await?,
    ))
}
async fn create_dns_record(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(zone): Path<String>,
    Json(input): Json<NewDnsRecord>,
) -> ApiResult<crate::dns::RecordView> {
    let record = crate::store::NewDnsRecord {
        name: input.name,
        record_type: input.record_type,
        content: input.content,
        ttl: input.ttl,
        proxied: input.proxied,
        health: input.health,
    };
    Ok(Json(
        database(state.store, move |db| {
            db.create_dns_record(&actor, &zone, record)
        })
        .await?,
    ))
}
async fn update_dns_record(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
    Json(input): Json<UpdateDnsRecord>,
) -> ApiResult<crate::dns::RecordView> {
    let patch = crate::store::DnsRecordPatch {
        name: input.name,
        content: input.content,
        ttl: input.ttl,
        proxied: input.proxied,
        enabled: input.enabled,
        health: input.health,
        clear_health: input.clear_health,
    };
    Ok(Json(
        database(state.store, move |db| {
            db.update_dns_record(&actor, &id, patch)
        })
        .await?,
    ))
}
async fn delete_dns_record(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
) -> ApiResult<serde_json::Value> {
    let store = state.store.clone();
    let actor2 = actor.clone();
    let record_id = id.clone();
    let record = database(store.clone(), move |db| db.dns_record(&actor2, &record_id)).await?;
    let zone = database(store.clone(), {
        let actor = actor.clone();
        let zone_id = record.zone_id.clone();
        move |db| db.dns_zone(&actor, &zone_id)
    })
    .await?;
    if zone.mode == crate::dns::ZoneMode::Apply
        && let Some(remote_id) = record.provider_record_id.as_deref()
    {
        let provider = database(store.clone(), {
            let provider_id = zone.provider_id.clone();
            move |db| db.dns_provider_raw(&provider_id)
        })
        .await?;
        let client =
            crate::dns::Cloudflare::new(reqwest::Client::new(), &provider).map_err(ApiError)?;
        client
            .delete(&zone.name, remote_id)
            .await
            .map_err(ApiError)?;
    }
    database(store, move |db| db.delete_dns_record(&actor, &id)).await?;
    Ok(Json(serde_json::json!({"ok": true})))
}
async fn reconcile_dns_zone(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
) -> ApiResult<crate::dns::ReconcileResult> {
    // Check the system-administrator scope before touching provider secrets.
    database(state.store.clone(), {
        let actor = actor.clone();
        let id = id.clone();
        move |db| db.dns_zone(&actor, &id)
    })
    .await?;
    let result = crate::dns::reconcile(&state.store, &reqwest::Client::new(), &id)
        .await
        .map_err(ApiError)?;
    Ok(Json(result))
}
async fn dns_ddns(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
    Json(input): Json<DdnsUpdate>,
) -> ApiResult<crate::dns::ReconcileResult> {
    let (zone_id, record_type) = database(state.store.clone(), {
        let actor = actor.clone();
        let id = id.clone();
        move |db| {
            db.dns_record(&actor, &id)
                .map(|record| (record.zone_id, record.record_type))
        }
    })
    .await?;
    if !matches!(
        record_type,
        crate::dns::RecordType::A | crate::dns::RecordType::Aaaa
    ) {
        return Err(Rejection {
            status: 400,
            message: "DDNS only updates A or AAAA records".into(),
        }
        .into());
    }
    database(state.store.clone(), move |db| {
        db.update_dns_record(
            &actor,
            &id,
            crate::store::DnsRecordPatch {
                content: Some(input.content),
                ..Default::default()
            },
        )
        .map(|_| ())
    })
    .await?;
    let result = crate::dns::reconcile(&state.store, &reqwest::Client::new(), &zone_id)
        .await
        .map_err(ApiError)?;
    Ok(Json(result))
}

async fn capabilities() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "version":env!("CARGO_PKG_VERSION"),"stage":"development","database":"sqlite-single-controller",
        "available":["two-factor-login","scoped-api-tokens","client-subscriptions","dns-records","ddns","announcements","commerce-wallet","commerce-orders","commerce-payments","commerce-coupons","commerce-gifts","http-connect","destination-acl","config-templates","mptcp-diagnostics","nat-pmp","pcp","upnp","tickets","node-identity-revocation-replacement","node-credential-rotation","node-inventory-lifecycle","durable-budget-run-recovery","node-execution-leases","tcp","udp","ipv4","ipv6","dns-targets","port-ranges","outbound-binding","dns-ttl-cache","node-local-loop-protection","proxy-protocol-tcp-v1-v2","proxy-protocol-udp-v2","udp-destination-tracking","websocket","secure-websocket","declared-multi-node-topology","atomic-config-batch","target-health-checks","priority-capacity-selection","lowest-latency-selection","node-telemetry","connection-prewarm","alert-notifications","multipath-aggregation","weighted-round-robin","source-hash","least-connections","source-cidr-acl","per-rule-quota","per-rule-bandwidth","durable-usage","config-revisions","tenant-isolation","session-revocation","tls-data-transport","mutual-tls","backup-reconciliation","global-user-budgets","global-rate-limits","hierarchical-budgets","budget-reservation-return","controller-recovery-log"],
        "pending":["mptcp","budget-disaster-recovery","wireguard","nat-traversal","commerce-entitlements","dns-health-removal","dns-authoritative-pool","federation","postgresql-ha"]
    }))
}

async fn recovery_status(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<crate::journal::JournalStatus> {
    Ok(Json(
        database(state.store, move |db| {
            if actor.role != Role::SystemAdmin {
                return crate::store::reject(
                    403,
                    "recovery status requires system administrator access",
                );
            }
            db.recovery_log_status()
        })
        .await?,
    ))
}

async fn budgets(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<BudgetOverview> {
    Ok(Json(
        database(state.store, move |db| db.budgets(&actor)).await?,
    ))
}
#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct ReservationQuery {
    after: Option<String>,
}
async fn budget_reservations(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
    Query(query): Query<ReservationQuery>,
) -> ApiResult<crate::budget::ReservationPage> {
    Ok(Json(
        database(state.store, move |db| {
            db.budget_reservations(&actor, &id, query.after.as_deref())
        })
        .await?,
    ))
}
async fn create_budget(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(input): Json<NewBudget>,
) -> ApiResult<Budget> {
    Ok(Json(
        database(state.store, move |db| db.create_budget(&actor, input)).await?,
    ))
}
async fn update_budget(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(id): Path<String>,
    Json(input): Json<BudgetUpdate>,
) -> ApiResult<Budget> {
    Ok(Json(
        database(state.store, move |db| db.update_budget(&actor, &id, input)).await?,
    ))
}
