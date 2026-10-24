use super::*;
use crate::credential::{RotateCredential, RotationReceipt, RotationRequest};
use crate::lease::LeaseProof;
use std::sync::Mutex;

#[derive(Clone, Serialize, Deserialize)]
pub(super) struct PendingRotation {
    request: RotationRequest,
    token: String,
}

/// Renewal and synchronization share the same durable credential transition.
/// No mutex is held across network I/O, and retries never extend lease deadlines.
#[derive(Clone)]
pub(super) struct SharedCredential {
    pub node_id: String,
    current: Arc<Mutex<Credential>>,
}
impl SharedCredential {
    pub fn new(credential: Credential) -> Result<Self> {
        ensure!(
            credential.revision > 0 && credential.revision <= i64::MAX as u64,
            "invalid saved credential revision"
        );
        if let Some(pending) = &credential.pending_rotation {
            ensure!(
                pending.request.expected_revision == credential.revision
                    && identifier(&pending.request.id)
                    && pending.token.len() == 64
                    && pending.token.bytes().all(|b| b.is_ascii_hexdigit())
                    && pending.token != credential.token,
                "invalid saved credential transition"
            );
        }
        Ok(Self {
            node_id: credential.node_id.clone(),
            current: Arc::new(Mutex::new(credential)),
        })
    }
    pub async fn send(&self, request: reqwest::RequestBuilder) -> Result<reqwest::Response> {
        let first = self.current.lock().unwrap().token.clone();
        let response = request
            .try_clone()
            .context("credential request must be replayable")?
            .bearer_auth(&first)
            .send()
            .await?;
        if response.status() != reqwest::StatusCode::UNAUTHORIZED {
            return Ok(response);
        }
        // Read again after the rejection: a concurrent rotation may have committed
        // while this request was in flight. Only the locally persisted candidate
        // or a newly confirmed credential is eligible for one retry.
        let replacement = {
            let saved = self.current.lock().unwrap();
            if saved.token != first {
                Some(saved.token.clone())
            } else {
                saved
                    .pending_rotation
                    .as_ref()
                    .map(|pending| pending.token.clone())
            }
        };
        if let Some(token) = replacement {
            let response = request.bearer_auth(&token).send().await?;
            if response.status() == reqwest::StatusCode::UNAUTHORIZED {
                let saved = self.current.lock().unwrap();
                let advanced = [
                    &saved.token,
                    saved
                        .pending_rotation
                        .as_ref()
                        .map(|p| &p.token)
                        .unwrap_or(&saved.token),
                ]
                .into_iter()
                .any(|candidate| candidate != &first && candidate != &token);
                if advanced {
                    return Err(ReconcileRetry(
                        "credential advanced again during the bounded retry".into(),
                    )
                    .into());
                }
            }
            return Ok(response);
        }
        Ok(response)
    }
    pub async fn rotate_if_requested(
        &self,
        client: &Client,
        base: &Url,
        store: &Store,
        requested: Option<RotationRequest>,
        lease: Option<&LeaseProof>,
    ) -> Result<()> {
        let mut saved = self.current.lock().unwrap().clone();
        if saved.pending_rotation.is_none() {
            let Some(request) = requested else {
                return Ok(());
            };
            ensure!(
                identifier(&request.id) && request.expected_revision == saved.revision,
                "controller credential rotation does not match local revision"
            );
            saved.pending_rotation = Some(PendingRotation {
                request,
                token: secret(),
            });
            self.persist(store, &saved).await?;
        }
        let pending = saved.pending_rotation.as_ref().unwrap();
        let input = RotateCredential {
            request_id: pending.request.id.clone(),
            expected_revision: pending.request.expected_revision,
            credential: pending.token.clone(),
            lease: lease.cloned(),
        };
        let response = self
            .send(
                client
                    .post(base.join("api/v1/agent/credential/rotate")?)
                    .json(&input),
            )
            .await?;
        ensure!(
            response.status().is_success(),
            "credential rotation pending: HTTP {}",
            response.status()
        );
        let receipt: RotationReceipt = bounded_json(response).await?;
        ensure!(
            receipt.id == pending.request.id && receipt.revision == saved.revision + 1,
            "controller returned an inconsistent credential rotation receipt"
        );
        saved.token = pending.token.clone();
        saved.revision = receipt.revision;
        saved.pending_rotation = None;
        self.persist(store, &saved).await?;
        tracing::info!(
            revision = receipt.revision,
            "node credential rotation confirmed"
        );
        Ok(())
    }
    async fn persist(&self, store: &Store, saved: &Credential) -> Result<()> {
        let value = serde_json::to_string(saved)?;
        let db = store.clone();
        tokio::task::spawn_blocking(move || db.set_metadata("agent_credential", &value)).await??;
        *self.current.lock().unwrap() = saved.clone();
        Ok(())
    }
}

pub(super) fn initial_revision() -> u64 {
    1
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicUsize, Ordering};

    fn saved() -> Credential {
        Credential {
            controller: "http://127.0.0.1/".into(),
            node_id: "test-node".into(),
            token: secret(),
            pending_enrollment_token: None,
            revision: 1,
            pending_rotation: None,
        }
    }
    #[tokio::test]
    async fn repeated_concurrent_rotations_use_a_bounded_retry_without_revoking_a_live_lease() {
        let tmp = tempfile::tempdir().unwrap();
        let db = Store::open(&tmp.path().join("agent.sqlite")).unwrap();
        let credential = SharedCredential::new(saved()).unwrap();
        let shared = credential.clone();
        let local = db.clone();
        let count = Arc::new(AtomicUsize::new(0));
        let calls = count.clone();
        let router = axum::Router::new().route(
            "/",
            axum::routing::get(move || {
                let shared = shared.clone();
                let local = local.clone();
                let calls = calls.clone();
                async move {
                    if calls.fetch_add(1, Ordering::SeqCst) < 2 {
                        let mut next = shared.current.lock().unwrap().clone();
                        next.token = secret();
                        next.revision += 1;
                        shared.persist(&local, &next).await.unwrap();
                        axum::http::StatusCode::UNAUTHORIZED
                    } else {
                        axum::http::StatusCode::OK
                    }
                }
            }),
        );
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let client = Client::builder().no_proxy().build().unwrap();
        let response = credential
            .send(client.get(format!("http://{address}/")))
            .await;
        assert!(response.unwrap_err().is::<ReconcileRetry>());
        assert_eq!(count.load(Ordering::SeqCst), 2);
        assert!(
            credential
                .send(client.get(format!("http://{address}/")))
                .await
                .unwrap()
                .status()
                .is_success()
        );
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }
    #[tokio::test]
    async fn failed_local_candidate_persistence_sends_no_rotation_request() {
        let tmp = tempfile::tempdir().unwrap();
        let path = tmp.path().join("agent.sqlite");
        let db = Store::open(&path).unwrap();
        let initial = saved();
        db.set_metadata(
            "agent_credential",
            &serde_json::to_string(&initial).unwrap(),
        )
        .unwrap();
        rusqlite::Connection::open(&path).unwrap().execute_batch("CREATE TRIGGER fail_credential BEFORE INSERT ON metadata WHEN NEW.key='agent_credential' BEGIN SELECT RAISE(ABORT,'injected durable credential failure'); END").unwrap();
        let shared = SharedCredential::new(initial.clone()).unwrap();
        let calls = Arc::new(AtomicUsize::new(0));
        let count = calls.clone();
        let router = axum::Router::new().fallback(move || {
            let count = count.clone();
            async move {
                count.fetch_add(1, Ordering::SeqCst);
                axum::http::StatusCode::OK
            }
        });
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        let server = tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        let request = RotationRequest {
            id: uuid::Uuid::new_v4().to_string(),
            expected_revision: 1,
            requested_at_ms: now_ms(),
            requested_by: "admin".into(),
        };
        assert!(
            shared
                .rotate_if_requested(
                    &Client::builder().no_proxy().build().unwrap(),
                    &Url::parse(&format!("http://{address}/")).unwrap(),
                    &db,
                    Some(request),
                    None
                )
                .await
                .is_err()
        );
        assert_eq!(calls.load(Ordering::SeqCst), 0);
        assert_eq!(shared.current.lock().unwrap().token, initial.token);
        assert!(shared.current.lock().unwrap().pending_rotation.is_none());
        assert_eq!(
            db.metadata("agent_credential").unwrap().unwrap(),
            serde_json::to_string(&initial).unwrap()
        );
        server.abort();
        assert!(server.await.unwrap_err().is_cancelled());
    }
}
