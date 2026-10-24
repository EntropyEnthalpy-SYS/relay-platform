use crate::{
    metrics::{Timing, TimingStats},
    model::{SyncRequest, SyncResponse},
    store::{Store, reject},
};
use anyhow::{Result, anyhow, ensure};
use serde::Serialize;
use std::sync::{
    Arc, OnceLock, Weak,
    atomic::{AtomicU64, Ordering},
};
use tokio::sync::{mpsc, oneshot};

const CAPACITY: usize = 64;
const WINDOW: std::time::Duration = std::time::Duration::from_millis(2);

struct Job {
    queued_at: tokio::time::Instant,
    token: String,
    request: SyncRequest,
    response: oneshot::Sender<Result<SyncResponse>>,
}
#[derive(Default)]
struct Counters {
    queue_time: Timing,
    storage_batch_time: Timing,
    request_time: Timing,
    batches: AtomicU64,
    requests: AtomicU64,
    max_batch: AtomicU64,
    full: AtomicU64,
    failures: AtomicU64,
}
#[derive(Serialize)]
pub struct SyncQueueStats {
    pub queue_time: TimingStats,
    pub storage_batch_time: TimingStats,
    pub request_time: TimingStats,
    pub committed_batches: u64,
    pub processed_requests: u64,
    pub largest_batch: u64,
    pub queue_full_rejections: u64,
    pub failed_batches: u64,
    pub batch_limit: usize,
    pub queue_capacity: usize,
    pub coalesce_window_ms: u64,
}
struct Inner {
    store: Store,
    sender: OnceLock<mpsc::Sender<Job>>,
    counters: Arc<Counters>,
    max_batch: usize,
}
#[derive(Clone)]
pub(crate) struct SyncQueue(Arc<Inner>);
impl SyncQueue {
    pub fn new(store: Store, max_batch: usize) -> Result<Self> {
        ensure!(
            (1..=16).contains(&max_batch),
            "sync batch size must be 1..16"
        );
        Ok(Self(Arc::new(Inner {
            store,
            sender: OnceLock::new(),
            counters: Arc::default(),
            max_batch,
        })))
    }
    pub fn stats(&self) -> SyncQueueStats {
        let c = &self.0.counters;
        SyncQueueStats {
            queue_time: c.queue_time.snapshot(),
            storage_batch_time: c.storage_batch_time.snapshot(),
            request_time: c.request_time.snapshot(),
            committed_batches: c.batches.load(Ordering::Relaxed),
            processed_requests: c.requests.load(Ordering::Relaxed),
            largest_batch: c.max_batch.load(Ordering::Relaxed),
            queue_full_rejections: c.full.load(Ordering::Relaxed),
            failed_batches: c.failures.load(Ordering::Relaxed),
            batch_limit: self.0.max_batch,
            queue_capacity: CAPACITY,
            coalesce_window_ms: if self.0.max_batch == 1 { 0 } else { 2 },
        }
    }
    pub async fn submit(&self, token: String, request: SyncRequest) -> Result<SyncResponse> {
        let sender = self.0.sender.get_or_init(|| {
            let (sender, receiver) = mpsc::channel(CAPACITY);
            // Lazy initialization keeps AppState construction independent of a runtime.
            // The worker owns no sender; dropping the router drains then closes it.
            tokio::spawn(worker(
                receiver,
                Arc::downgrade(&self.0),
                self.0.counters.clone(),
                self.0.max_batch,
            ));
            sender
        });
        let (response, result) = oneshot::channel();
        match sender.try_send(Job {
            queued_at: tokio::time::Instant::now(),
            token,
            request,
            response,
        }) {
            Ok(()) => {}
            Err(mpsc::error::TrySendError::Full(_)) => {
                self.0.counters.full.fetch_add(1, Ordering::Relaxed);
                return reject(429, "agent synchronization queue is full; retry later");
            }
            Err(mpsc::error::TrySendError::Closed(_)) => {
                return Err(anyhow!("agent synchronization worker is unavailable"));
            }
        }
        result
            .await
            .map_err(|_| anyhow!("agent synchronization worker stopped before confirmation"))?
    }
}

async fn worker(
    mut receiver: mpsc::Receiver<Job>,
    owner: Weak<Inner>,
    counters: Arc<Counters>,
    max_batch: usize,
) {
    while let Some(first) = receiver.recv().await {
        let mut jobs = vec![first];
        let deadline = tokio::time::Instant::now() + WINDOW;
        while jobs.len() < max_batch {
            tokio::select! {
                biased;
                _ = tokio::time::sleep_until(deadline) => break,
                next = receiver.recv() => match next {Some(job) => jobs.push(job), None => break},
            }
        }
        jobs.retain(|job| !job.response.is_closed());
        if jobs.is_empty() {
            continue;
        }
        let mut inputs = Vec::with_capacity(jobs.len());
        let mut replies = Vec::with_capacity(jobs.len());
        let mut submitted = Vec::with_capacity(jobs.len());
        for job in jobs {
            counters.queue_time.record(job.queued_at.elapsed());
            submitted.push(job.queued_at);
            inputs.push((job.token, job.request));
            replies.push(job.response);
        }
        let count = inputs.len() as u64;
        let Some(inner) = owner.upgrade() else {
            break;
        };
        let db = inner.store.clone();
        drop(inner);
        let began = tokio::time::Instant::now();
        let result = tokio::task::spawn_blocking(move || db.sync_authenticated_batch(inputs)).await;
        counters.storage_batch_time.record(began.elapsed());
        for at in submitted {
            counters.request_time.record(at.elapsed());
        }
        match result {
            Ok(Ok(responses)) => {
                counters.batches.fetch_add(1, Ordering::Relaxed);
                counters.requests.fetch_add(count, Ordering::Relaxed);
                counters.max_batch.fetch_max(count, Ordering::Relaxed);
                for (reply, response) in replies.into_iter().zip(responses) {
                    let _ = reply.send(response);
                }
            }
            failure => {
                counters.failures.fetch_add(1, Ordering::Relaxed);
                tracing::error!(?failure, "agent sync batch could not be confirmed");
                for reply in replies {
                    let _ = reply.send(Err(anyhow!("agent synchronization commit failed")));
                }
            }
        }
    }
}
