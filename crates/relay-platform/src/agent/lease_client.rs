use super::*;
use crate::lease::{LeaseProof, LeaseRelease, LeaseReply, LeaseRequest};
use std::{
    sync::Mutex,
    time::{Instant, SystemTime},
};
use tokio::task::JoinHandle;

struct Stamp {
    monotonic: Instant,
    wall: SystemTime,
}
impl Stamp {
    fn now() -> Self {
        Self {
            monotonic: Instant::now(),
            wall: SystemTime::now(),
        }
    }
    fn elapsed(&self) -> Option<Duration> {
        Some(self.monotonic.elapsed().max(self.wall.elapsed().ok()?))
    }
}
struct Window {
    began: Stamp,
    valid: Duration,
}
impl Window {
    fn new(began: Stamp, reply: &LeaseReply) -> Result<Self> {
        ensure!(
            reply.required
                && reply.generation.is_some()
                && (5_000..=120_000).contains(&reply.ttl_ms)
                && reply.valid_for_ms <= reply.ttl_ms,
            "invalid execution lease response"
        );
        let margin = (reply.ttl_ms / 10).max(250);
        ensure!(
            reply.valid_for_ms > margin,
            "execution lease reply arrived too late"
        );
        let window = Self {
            began,
            valid: Duration::from_millis(reply.valid_for_ms - margin),
        };
        ensure!(
            window.live(),
            "execution lease reply exceeded its local validity window"
        );
        Ok(window)
    }
    fn live(&self) -> bool {
        self.began
            .elapsed()
            .is_some_and(|elapsed| elapsed < self.valid)
    }
}

pub(super) struct AgentLease {
    pub proof: Option<LeaseProof>,
    pub lost: CancellationToken,
    stop: CancellationToken,
    worker: Option<JoinHandle<()>>,
    window: Option<Arc<Mutex<Window>>>,
}
impl Drop for AgentLease {
    fn drop(&mut self) {
        self.stop.cancel();
        if let Some(worker) = &self.worker {
            worker.abort();
        }
    }
}
impl AgentLease {
    fn offline() -> Self {
        Self {
            proof: None,
            lost: CancellationToken::new(),
            stop: CancellationToken::new(),
            worker: None,
            window: None,
        }
    }
    pub fn ensure_live(&self) -> Result<()> {
        if self.lost.is_cancelled()
            || self
                .window
                .as_ref()
                .is_some_and(|window| !window.lock().unwrap().live())
        {
            self.lost.cancel();
            bail!("node execution lease expired before activation");
        }
        Ok(())
    }
    pub async fn acquire(
        client: &Client,
        base: &Url,
        credential: &Credential,
        store: &Store,
        run_id: &str,
        stop: &CancellationToken,
    ) -> Result<Option<Self>> {
        let request = LeaseRequest {
            run_id: run_id.into(),
            token: secret(),
            generation: None,
        };
        let offline_known = store.metadata("agent_lease_mode")?.as_deref() == Some("offline");
        let mut waiting = false;
        loop {
            let began = Stamp::now();
            let attempt = async {
                let response = client
                    .post(base.join("api/v1/agent/lease")?)
                    .bearer_auth(&credential.token)
                    .timeout(Duration::from_secs(5))
                    .json(&request)
                    .send()
                    .await?;
                let status = response.status();
                if status == reqwest::StatusCode::LOCKED
                    || status.is_server_error()
                    || status == reqwest::StatusCode::TOO_MANY_REQUESTS
                {
                    return Err(ReconcileRetry(format!(
                        "execution lease unavailable: HTTP {status}"
                    ))
                    .into());
                }
                ensure!(
                    status.is_success(),
                    "controller rejected execution lease with HTTP {status}; upgrade the controller before this Agent"
                );
                bounded_json::<LeaseReply>(response).await
            };
            let response: Result<LeaseReply> =
                tokio::select! {biased;_=stop.cancelled()=>return Ok(None),result=attempt=>result};
            match response {
                Ok(reply) if !reply.required => {
                    ensure!(
                        reply.generation.is_none() && reply.ttl_ms == 0 && reply.valid_for_ms == 0,
                        "inconsistent offline-mode lease response"
                    );
                    store.set_metadata("agent_lease_mode", "offline")?;
                    return Ok(Some(Self::offline()));
                }
                Ok(reply) => {
                    let window = match Window::new(began, &reply) {
                        Ok(window) => window,
                        Err(error) => {
                            tracing::warn!(%error,"execution lease response was unusable; no forwarding activated");
                            tokio::select! {biased;_=stop.cancelled()=>return Ok(None),_=tokio::time::sleep(Duration::from_millis(500))=>{}}
                            continue;
                        }
                    };
                    store.set_metadata("agent_lease_mode", "strict")?;
                    let proof = LeaseProof {
                        run_id: run_id.into(),
                        generation: reply.generation.unwrap(),
                        token: request.token.clone(),
                    };
                    return Ok(Some(Self::start(
                        client.clone(),
                        base.clone(),
                        credential.token.clone(),
                        proof,
                        window,
                        reply.ttl_ms,
                    )));
                }
                Err(error)
                    if error.is::<ReconcileRetry>()
                        || error.downcast_ref::<reqwest::Error>().is_some() =>
                {
                    if offline_known {
                        tracing::warn!(
                            "controller unavailable; previously confirmed offline node policy retained"
                        );
                        return Ok(Some(Self::offline()));
                    }
                    if !waiting {
                        tracing::warn!(%error,"waiting for exclusive node lease; business listeners remain stopped");
                        waiting = true;
                    }
                }
                Err(error) => return Err(error),
            }
            tokio::select! {biased;_=stop.cancelled()=>return Ok(None),_=tokio::time::sleep(Duration::from_millis(500))=>{}}
        }
    }
    fn start(
        client: Client,
        base: Url,
        token: String,
        proof: LeaseProof,
        window: Window,
        ttl_ms: u64,
    ) -> Self {
        let stop = CancellationToken::new();
        let lost = CancellationToken::new();
        let worker_stop = stop.clone();
        let worker_lost = lost.clone();
        let renewal = proof.clone();
        let window = Arc::new(Mutex::new(window));
        let current_window = window.clone();
        let loss_on_exit = worker_lost.clone().drop_guard();
        let worker = tokio::spawn(async move {
            let _loss_on_exit = loss_on_exit;
            let monitor = async {
                loop {
                    if !window.lock().unwrap().live() {
                        return;
                    }
                    tokio::time::sleep(Duration::from_millis(50)).await;
                }
            };
            let renew = async {
                let mut delay = Duration::from_millis(ttl_ms / 3);
                loop {
                    tokio::time::sleep(delay).await;
                    ensure!(
                        window.lock().unwrap().live(),
                        "execution lease expired before renewal"
                    );
                    let began = Stamp::now();
                    let attempt = async {
                        let response = client
                            .post(base.join("api/v1/agent/lease")?)
                            .bearer_auth(&token)
                            .json(&LeaseRequest {
                                run_id: renewal.run_id.clone(),
                                token: renewal.token.clone(),
                                generation: Some(renewal.generation),
                            })
                            .send()
                            .await?;
                        let status = response.status();
                        if status.is_server_error()
                            || status == reqwest::StatusCode::TOO_MANY_REQUESTS
                        {
                            return Err(ReconcileRetry(format!(
                                "lease renewal temporarily unavailable: HTTP {status}"
                            ))
                            .into());
                        }
                        ensure!(
                            status.is_success(),
                            "execution lease renewal rejected with HTTP {status}"
                        );
                        let reply: LeaseReply = bounded_json(response).await?;
                        ensure!(
                            reply.generation == Some(renewal.generation) && reply.ttl_ms == ttl_ms,
                            "controller changed the current lease identity or policy"
                        );
                        Window::new(began, &reply)
                    };
                    let result: Result<Window> = attempt.await;
                    match result {
                        Ok(next) => {
                            let mut current = window.lock().unwrap();
                            ensure!(
                                current.live(),
                                "expired lease cannot be revived by a delayed renewal reply"
                            );
                            *current = next;
                            delay = Duration::from_millis(ttl_ms / 3);
                        }
                        Err(error)
                            if error.is::<ReconcileRetry>()
                                || error.downcast_ref::<reqwest::Error>().is_some() =>
                        {
                            delay = Duration::from_millis(500);
                            tracing::debug!(%error,"lease renewal failed; existing deadline remains in force");
                        }
                        Err(error) => return Err::<(), anyhow::Error>(error),
                    }
                }
            };
            tokio::select! {
                biased;
                _=worker_stop.cancelled()=>{},
                _=monitor=>{tracing::warn!("execution lease deadline reached; stopping business traffic");worker_lost.cancel();},
                result=renew=>{if let Err(error)=result {tracing::warn!(%error,"execution lease lost; stopping business traffic");}worker_lost.cancel();},
            }
        });
        Self {
            proof: Some(proof),
            lost,
            stop,
            worker: Some(worker),
            window: Some(current_window),
        }
    }
    pub async fn release(
        &self,
        client: &Client,
        base: &Url,
        credential: &Credential,
        stats: EngineStats,
    ) -> Result<()> {
        if let Some(proof) = &self.proof {
            client
                .post(base.join("api/v1/agent/lease/release")?)
                .bearer_auth(&credential.token)
                .json(&LeaseRelease {
                    proof: proof.clone(),
                    stats,
                })
                .send()
                .await?
                .error_for_status()?;
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn lease_window_rejects_delayed_replies_suspend_and_backward_wall_time() {
        let reply = LeaseReply {
            required: true,
            generation: Some(1),
            valid_for_ms: 5000,
            ttl_ms: 5000,
        };
        let current = Window::new(Stamp::now(), &reply).unwrap();
        assert!(current.live());
        assert_eq!(current.valid, Duration::from_millis(4500));
        let delayed = Stamp {
            monotonic: Instant::now() - Duration::from_secs(5),
            wall: SystemTime::now(),
        };
        assert!(Window::new(delayed, &reply).is_err());
        let suspended = Stamp {
            monotonic: Instant::now(),
            wall: SystemTime::now() - Duration::from_secs(6),
        };
        assert!(Window::new(suspended, &reply).is_err());
        let backward = Stamp {
            monotonic: Instant::now(),
            wall: SystemTime::now() + Duration::from_secs(1),
        };
        assert!(Window::new(backward, &reply).is_err());
    }
}
