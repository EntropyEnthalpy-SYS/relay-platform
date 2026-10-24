use crate::{
    budget::{Budget, BudgetOverview, BudgetUpdate, NewBudget},
    model::*,
    store::{Actor, Rejection, Role, Store, reject},
};
use axum::{
    Json, Router,
    extract::{ConnectInfo, DefaultBodyLimit, Path, Request, State},
    http::{HeaderMap, HeaderValue, StatusCode, header},
    middleware::{self, Next},
    response::{Html, IntoResponse, Response},
    routing::{get, post},
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
    login_slots: Arc<Semaphore>,
    sync_queue: crate::sync_queue::SyncQueue,
}
impl AppState {
    pub fn new(store: Store) -> Self {
        Self {
            sync_queue: crate::sync_queue::SyncQueue::new(store.clone(), 16).unwrap(),
            store,
            instance: uuid::Uuid::new_v4().to_string(),
            login_attempts: Arc::new(Mutex::new(HashMap::new())),
            login_slots: Arc::new(Semaphore::new(4)),
        }
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
        .filter(|s| s.len() == 64 && s.bytes().all(|b| b.is_ascii_hexdigit()))
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
    let actor = database(state.store, move |db| db.authenticate(&token)).await?;
    request.extensions_mut().insert(actor);
    Ok(next.run(request).await)
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
        .route("/api/v1/nodes/{node}/config", get(config).put(publish))
        .route("/api/v1/nodes/{node}/history", get(history))
        .route("/api/v1/nodes/{node}/health", get(node_health))
        .route("/api/v1/nodes/{node}/rollback", post(rollback))
        .route("/api/v1/topology", get(topology))
        .route("/api/v1/configurations/preview", post(preview_batch))
        .route("/api/v1/configurations/publish", post(publish_batch))
        .route("/api/v1/users", get(users).post(create_user))
        .route(
            "/api/v1/users/{user}/revoke-sessions",
            post(revoke_sessions),
        )
        .route("/api/v1/tenants", post(create_tenant))
        .route("/api/v1/usage", get(usage))
        .route("/api/v1/budgets", get(budgets).post(create_budget))
        .route("/api/v1/budgets/{id}", axum::routing::put(update_budget))
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
        .route("/healthz", get(health))
        .route("/api/v1/auth/login", post(login))
        .route("/api/v1/agent/enroll", post(enroll))
        .route("/api/v1/agent/reconcile", post(reconcile))
        .route("/api/v1/agent/sync", post(sync))
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
) -> ApiResult<LoginResponse> {
    if input.username.len() > 80 || input.password.len() > 1024 {
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
    let (token, user) = database(state.store, move |db| {
        db.login(&input.username, &input.password)
    })
    .await?;
    Ok(Json(LoginResponse {
        token,
        user,
        expires_in_seconds: 8 * 60 * 60,
    }))
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
) -> ApiResult<Vec<crate::store::Node>> {
    Ok(Json(
        database(state.store, move |db| db.nodes(&actor)).await?,
    ))
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct NewNode {
    name: String,
    tenant_id: Option<String>,
}
async fn create_node(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Json(input): Json<NewNode>,
) -> ApiResult<serde_json::Value> {
    let tenant = input.tenant_id.unwrap_or_else(|| actor.tenant_id.clone());
    let (node, token) = database(state.store, move |db| {
        db.create_node(&actor, &tenant, &input.name)
    })
    .await?;
    Ok(Json(
        serde_json::json!({"node":node,"enrollment_token":token}),
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
}
async fn publish(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
    Path(node): Path<String>,
    Json(input): Json<Publish>,
) -> ApiResult<NodeConfig> {
    Ok(Json(
        database(state.store, move |db| {
            db.set_config(&actor, &node, input.expected_revision, input.rules)
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
            db.set_config(&actor, &node, input.expected_revision, previous.rules)
        })
        .await?,
    ))
}
async fn users(
    State(state): State<AppState>,
    axum::Extension(actor): axum::Extension<Actor>,
) -> ApiResult<Vec<Actor>> {
    Ok(Json(
        database(state.store, move |db| db.users(&actor)).await?,
    ))
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
}
#[derive(Serialize, Deserialize)]
pub struct EnrollmentResponse {
    pub enrolled: bool,
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
    database(state.store, move |db| {
        db.enroll(&input.node_id, &input.enrollment_token, &input.credential)
    })
    .await?;
    Ok(Json(EnrollmentResponse { enrolled: true }))
}
async fn reconcile(
    State(state): State<AppState>,
    headers: HeaderMap,
    Json(input): Json<ReconcileRequest>,
) -> ApiResult<ReconcileResponse> {
    let token = bearer(&headers)?;
    Ok(Json(
        database(state.store, move |db| {
            let node = db.authenticate_node(&token)?;
            db.reconcile(&node, input)
        })
        .await?,
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
async fn capabilities() -> Json<serde_json::Value> {
    Json(serde_json::json!({
        "version":env!("CARGO_PKG_VERSION"),"stage":"development","database":"sqlite-single-controller",
        "available":["tcp","udp","ipv4","ipv6","dns-targets","port-ranges","outbound-binding","dns-ttl-cache","node-local-loop-protection","proxy-protocol-tcp-v1-v2","proxy-protocol-udp-v2","udp-destination-tracking","websocket","secure-websocket","declared-multi-node-topology","atomic-config-batch","target-health-checks","priority-capacity-selection","weighted-round-robin","source-hash","least-connections","source-cidr-acl","per-rule-quota","per-rule-bandwidth","durable-usage","config-revisions","tenant-isolation","session-revocation","tls-data-transport","mutual-tls","backup-reconciliation","global-user-budgets","hierarchical-budgets","budget-reservation-return","controller-recovery-log"],
        "pending":["mptcp","multipath-aggregation","budget-disaster-recovery","global-rate-limits","wireguard","nat-traversal","commerce","subscriptions","dns-management","federation","postgresql-ha"]
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
