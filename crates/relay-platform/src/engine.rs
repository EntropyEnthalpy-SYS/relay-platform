use crate::{
    datagram, destination_acl,
    health::{self, HealthSet, Observation},
    http_connect,
    metrics::{MeterStats, Timing},
    model::*,
    multipath,
    network::{self, TargetResolver},
    proxy::{self, ConnectionInfo},
    routing::{Endpoint as ListenerKey, LoopGuard, Routes, Topology, local_ips},
    shadowsocks, socks5,
    store::{Admission, AdmissionDecision, MeterFlush, Store},
    transport::{self, BoxStream, PreparedTls},
    websocket,
};
use anyhow::{Context, Result, bail, ensure};
use futures_util::{FutureExt, StreamExt, stream::FuturesUnordered};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, VecDeque},
    io,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex as StdMutex, Weak,
        atomic::{AtomicBool, AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
    sync::{Mutex, Semaphore, mpsc, oneshot, watch},
    task::JoinHandle,
    time::{Instant, sleep, sleep_until, timeout_at},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

const BUFFER_SIZE: usize = 64 * 1024;
/// TCP copy buffers start here and double, up to BUFFER_SIZE, whenever a read
/// fills them, so idle connections stay small and bulk transfers reach full size.
const MIN_STREAM_BUFFER: usize = 4 * 1024;
/// A UDP session holds up to this many datagrams and bytes from its listener,
/// so a burst or a short scheduling pause does not drop datagrams. One that
/// waited longer than UDP_QUEUE_DELAY is dropped when taken, so a throttled
/// session does not build up seconds of delay.
const UDP_QUEUE: usize = 256;
const UDP_QUEUE_BYTES: usize = 256 * 1024;
const UDP_QUEUE_DELAY: Duration = Duration::from_millis(50);

#[derive(Default)]
struct Counters {
    multipath: Arc<multipath::Counters>,
    active_probes: AtomicU64,
    active_tcp: AtomicU64,
    active_udp: AtomicU64,
    accepted_tcp: AtomicU64,
    rejected_connections: AtomicU64,
    failed_connections: AtomicU64,
    dropped_datagrams: AtomicU64,
    forwarded_upload_bytes: AtomicU64,
    forwarded_download_bytes: AtomicU64,
    prewarmed_connections: AtomicU64,
}
impl Counters {
    fn snapshot(&self) -> EngineStats {
        EngineStats {
            budget_recovery: None,
            multipath: Some(self.multipath.snapshot()),
            meter: None,
            active_probes: self.active_probes.load(Ordering::Relaxed),
            target_health: vec![],
            system: None,
            active_tcp: self.active_tcp.load(Ordering::Relaxed),
            active_udp: self.active_udp.load(Ordering::Relaxed),
            accepted_tcp: self.accepted_tcp.load(Ordering::Relaxed),
            rejected_connections: self.rejected_connections.load(Ordering::Relaxed),
            failed_connections: self.failed_connections.load(Ordering::Relaxed),
            dropped_datagrams: self.dropped_datagrams.load(Ordering::Relaxed),
            forwarded_upload_bytes: self.forwarded_upload_bytes.load(Ordering::Relaxed),
            forwarded_download_bytes: self.forwarded_download_bytes.load(Ordering::Relaxed),
            prewarmed_connections: self.prewarmed_connections.load(Ordering::Relaxed),
            user_rates: vec![],
        }
    }
}

struct MeterMessage {
    request: Option<Admission>,
    response: oneshot::Sender<Result<AdmissionDecision>>,
}
#[derive(Default)]
struct MeterCounters {
    batches: Timing,
    requests: AtomicU64,
    failures: AtomicU64,
    waits: Timing,
    waiting: AtomicU64,
    timeouts: AtomicU64,
}
struct BudgetWaitGuard(Arc<MeterCounters>, Instant);
impl Drop for BudgetWaitGuard {
    fn drop(&mut self) {
        self.0.waits.record(self.1.elapsed());
        self.0.waiting.fetch_sub(1, Ordering::Relaxed);
    }
}
/// Bytes reserved durably per rule before traffic spends them in memory. A
/// lane that drains before its refill lands doubles its chunk up to the
/// maximum, so a crash over-counts a rule by at most `MAX_ALLOWANCE_CHUNK`.
const ALLOWANCE_CHUNK: u64 = 4 << 20;
const MAX_ALLOWANCE_CHUNK: u64 = 64 << 20;
#[derive(Default)]
struct Lane {
    available: u64,
    unflushed_upload: u64,
    unflushed_download: u64,
    chunk: u64,
    refilling: bool,
    /// The quota is spent; only a release (new config) clears this.
    dry: bool,
}
impl Lane {
    fn chunk(&self) -> u64 {
        self.chunk.max(ALLOWANCE_CHUNK)
    }
}
enum Take {
    Taken(u64),
    Empty,
    Dry,
}
/// rule id -> meter epoch -> allowance shared by both directions, like the quota
type Allowances = Arc<StdMutex<HashMap<String, HashMap<String, Lane>>>>;
enum ReserveWork {
    Reserve {
        rule_id: String,
        meter_epoch: String,
        wanted: u64,
        minimum: u64,
        /// Receives the bytes now available, 0 when the quota cannot admit `minimum`.
        response: Option<oneshot::Sender<Result<u64>>>,
    },
    Flush {
        release: bool,
        response: Option<oneshot::Sender<Result<()>>>,
    },
}
fn take_flushes(allowances: &Allowances, release: bool) -> Vec<MeterFlush> {
    let mut map = allowances.lock().unwrap();
    let mut flushes = vec![];
    for (rule, epochs) in map.iter_mut() {
        for (epoch, lane) in epochs.iter_mut() {
            let upload = std::mem::take(&mut lane.unflushed_upload);
            let download = std::mem::take(&mut lane.unflushed_download);
            if upload + download > 0 {
                flushes.push(MeterFlush {
                    rule_id: rule.clone(),
                    meter_epoch: epoch.clone(),
                    upload,
                    download,
                });
            }
        }
    }
    if release {
        map.clear();
    }
    flushes
}
/// Keeps counting bytes whose flush failed so a later flush records them.
fn restore_flushes(allowances: &Allowances, flushes: Vec<MeterFlush>) {
    let mut map = allowances.lock().unwrap();
    for flush in flushes {
        let lane = map
            .entry(flush.rule_id)
            .or_default()
            .entry(flush.meter_epoch)
            .or_default();
        lane.unflushed_upload += flush.upload;
        lane.unflushed_download += flush.download;
    }
}
fn spawn_reservations(store: Store, allowances: Allowances) -> mpsc::Sender<ReserveWork> {
    let (sender, mut receiver) = mpsc::channel::<ReserveWork>(1024);
    tokio::spawn(async move {
        // Reservations left by an earlier run are counted before this run
        // reserves anything; a restored state waits for reconciliation first.
        let settle = |store: Store| async move {
            match tokio::task::spawn_blocking(move || store.settle_meter_reservations()).await {
                Ok(Ok(bytes)) => {
                    if bytes > 0 {
                        tracing::warn!(
                            bytes,
                            "counted unreleased meter reservations from the previous run as usage"
                        );
                    }
                    true
                }
                error => {
                    tracing::debug!(?error, "meter reservations not settled yet");
                    false
                }
            }
        };
        let mut settled = settle(store.clone()).await;
        let mut tick = tokio::time::interval(Duration::from_millis(500));
        loop {
            let work = tokio::select! {
                work = receiver.recv() => match work {
                    Some(work) => work,
                    None => ReserveWork::Flush { release: true, response: None },
                },
                _ = tick.tick() => ReserveWork::Flush { release: false, response: None },
            };
            match work {
                ReserveWork::Reserve {
                    rule_id,
                    meter_epoch,
                    wanted,
                    minimum,
                    response,
                } => {
                    {
                        let mut map = allowances.lock().unwrap();
                        let lane = map
                            .entry(rule_id.clone())
                            .or_default()
                            .entry(meter_epoch.clone())
                            .or_default();
                        // Another request may already have refilled this lane.
                        let enough = if response.is_some() {
                            minimum.max(1)
                        } else {
                            lane.chunk() / 2
                        };
                        if lane.available >= enough {
                            let available = lane.available;
                            lane.refilling &= response.is_some();
                            drop(map);
                            let _ = response.map(|r| r.send(Ok(available)));
                            continue;
                        }
                    }
                    if !settled {
                        settled = settle(store.clone()).await;
                    }
                    let result = if settled {
                        let flushes = take_flushes(&allowances, false);
                        let pending = flushes.clone();
                        let db = store.clone();
                        let (rule, epoch) = (rule_id.clone(), meter_epoch.clone());
                        let result = tokio::task::spawn_blocking(move || {
                            db.reserve_meter(&pending, &rule, &epoch, wanted, minimum)
                        })
                        .await
                        .map_err(anyhow::Error::from)
                        .and_then(|r| r);
                        if result.is_err() {
                            restore_flushes(&allowances, flushes);
                        }
                        result
                    } else {
                        Err(anyhow::anyhow!("durable metering unavailable"))
                    };
                    {
                        let mut map = allowances.lock().unwrap();
                        let lane = map
                            .entry(rule_id)
                            .or_default()
                            .entry(meter_epoch)
                            .or_default();
                        lane.refilling = false;
                        match &result {
                            Ok(granted) => {
                                lane.available += granted;
                                lane.dry = *granted == 0 && minimum <= 1;
                            }
                            Err(error) => tracing::error!(%error, "meter reservation failed"),
                        }
                    }
                    let _ = response.map(|r| r.send(result));
                }
                ReserveWork::Flush { release, response } => {
                    let flushes = take_flushes(&allowances, release);
                    // Nothing was reserved yet, and old rows must survive until settled.
                    let result = if !settled || (flushes.is_empty() && !release) {
                        Ok(())
                    } else {
                        let pending = flushes.clone();
                        let db = store.clone();
                        let result =
                            tokio::task::spawn_blocking(move || db.flush_meters(&pending, release))
                                .await
                                .map_err(anyhow::Error::from)
                                .and_then(|r| r);
                        if let Err(error) = &result {
                            // The runtime cancels queued blocking work when the
                            // process exits; reservations already cover those bytes.
                            if error
                                .downcast_ref::<tokio::task::JoinError>()
                                .is_some_and(|e| e.is_cancelled())
                            {
                                tracing::debug!(%error, "meter flush cancelled at shutdown");
                            } else {
                                tracing::error!(%error, "meter flush failed");
                            }
                            restore_flushes(&allowances, flushes);
                        }
                        result
                    };
                    let _ = response.map(|r| r.send(result));
                    if release && receiver.is_closed() {
                        break;
                    }
                }
            }
        }
    });
    sender
}

#[derive(Clone)]
struct Meter {
    sender: mpsc::Sender<MeterMessage>,
    reservations: mpsc::Sender<ReserveWork>,
    allowances: Allowances,
    store: Store,
    counters: Arc<MeterCounters>,
}
impl Meter {
    fn new(store: Store) -> Self {
        let allowances = Allowances::default();
        let reservations = spawn_reservations(store.clone(), allowances.clone());
        let (sender, mut receiver) = mpsc::channel::<MeterMessage>(1024);
        let actor_store = store.clone();
        let counters = Arc::new(MeterCounters::default());
        let worker_counters = counters.clone();
        tokio::spawn(async move {
            while let Some(first) = receiver.recv().await {
                let mut batch = vec![first];
                while batch.len() < 256 {
                    match receiver.try_recv() {
                        Ok(m) => batch.push(m),
                        Err(_) => break,
                    }
                }
                let requests: Vec<_> = batch.iter().filter_map(|m| m.request.clone()).collect();
                let count = requests.len() as u64;
                let db = actor_store.clone();
                let began = Instant::now();
                let result =
                    tokio::task::spawn_blocking(move || db.admit_batch_detailed(&requests)).await;
                if count > 0 {
                    worker_counters.batches.record(began.elapsed());
                    worker_counters.requests.fetch_add(count, Ordering::Relaxed);
                }
                match result {
                    Ok(Ok(values)) => {
                        let mut iter = values.into_iter();
                        for message in batch {
                            let value = if message.request.is_some() {
                                iter.next().unwrap()
                            } else {
                                AdmissionDecision::Rejected
                            };
                            let _ = message.response.send(Ok(value));
                        }
                    }
                    error => {
                        if count > 0 {
                            worker_counters.failures.fetch_add(1, Ordering::Relaxed);
                        }
                        tracing::error!(?error, "durable metering failed; rejecting payload");
                        for message in batch {
                            let _ = message
                                .response
                                .send(Err(anyhow::anyhow!("durable metering unavailable")));
                        }
                    }
                }
            }
        });
        Self {
            sender,
            reservations,
            allowances,
            store,
            counters,
        }
    }
    fn stats(&self) -> MeterStats {
        MeterStats {
            admission_batches: self.counters.batches.snapshot(),
            admission_requests: self.counters.requests.load(Ordering::Relaxed),
            failed_batches: self.counters.failures.load(Ordering::Relaxed),
            budget_wait: self.counters.waits.snapshot(),
            budget_waiting: self.counters.waiting.load(Ordering::Relaxed),
            budget_timeouts: self.counters.timeouts.load(Ordering::Relaxed),
        }
    }
    /// Spends reserved allowance without touching disk; reserves more when it
    /// runs out. Rules with shared budgets keep the per-request durable path.
    async fn admit(
        &self,
        rule: &Rule,
        upload: bool,
        bytes: usize,
        datagram: bool,
    ) -> Result<Option<usize>> {
        if !rule.budget_ids.is_empty() {
            return self.admit_durably(rule, upload, bytes, datagram).await;
        }
        if rule.expires_at_ms.is_some_and(|t| t <= now_ms()) {
            return Ok(None);
        }
        let bytes = bytes as u64;
        loop {
            let wanted = match self.take(rule, upload, bytes, datagram) {
                Take::Taken(taken) => return Ok(Some(taken as usize)),
                Take::Dry => return Ok(None),
                Take::Empty => self.chunk(rule).max(bytes),
            };
            // Other sessions can drain a fresh grant before this one retries,
            // so only a grant of 0 means the quota cannot admit these bytes.
            let (tx, rx) = oneshot::channel();
            self.reservations
                .send(ReserveWork::Reserve {
                    rule_id: rule.id.clone(),
                    meter_epoch: rule.meter_epoch.clone(),
                    wanted,
                    minimum: if datagram { bytes } else { 1 },
                    response: Some(tx),
                })
                .await
                .context("meter stopped")?;
            if rx.await.context("meter stopped")?? == 0 {
                return Ok(None);
            }
        }
    }
    fn chunk(&self, rule: &Rule) -> u64 {
        self.allowances
            .lock()
            .unwrap()
            .get(&rule.id)
            .and_then(|e| e.get(&rule.meter_epoch))
            .map_or(ALLOWANCE_CHUNK, Lane::chunk)
    }
    fn take(&self, rule: &Rule, upload: bool, bytes: u64, datagram: bool) -> Take {
        let mut map = self.allowances.lock().unwrap();
        let Some(lane) = map
            .get_mut(&rule.id)
            .and_then(|e| e.get_mut(&rule.meter_epoch))
        else {
            return Take::Empty;
        };
        let fits = if datagram {
            bytes <= lane.available
        } else {
            lane.available > 0
        };
        if !fits {
            if lane.dry {
                return Take::Dry;
            }
            if lane.refilling {
                // Demand outran the prefetch; reserve larger chunks.
                lane.chunk = (lane.chunk() * 2).min(MAX_ALLOWANCE_CHUNK);
            }
            return Take::Empty;
        }
        let taken = bytes.min(lane.available);
        lane.available -= taken;
        if upload {
            lane.unflushed_upload += taken;
        } else {
            lane.unflushed_download += taken;
        }
        let chunk = lane.chunk();
        let refill = lane.available < chunk / 2 && !lane.refilling && !lane.dry;
        lane.refilling |= refill;
        drop(map);
        if refill {
            let prefetch = ReserveWork::Reserve {
                rule_id: rule.id.clone(),
                meter_epoch: rule.meter_epoch.clone(),
                wanted: chunk,
                minimum: 1,
                response: None,
            };
            if self.reservations.try_send(prefetch).is_err()
                && let Some(lane) = self
                    .allowances
                    .lock()
                    .unwrap()
                    .get_mut(&rule.id)
                    .and_then(|e| e.get_mut(&rule.meter_epoch))
            {
                lane.refilling = false;
            }
        }
        Take::Taken(taken)
    }
    /// Records spent allowance and returns unused reservations, so new rule
    /// limits apply to the next packet.
    async fn release(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.reservations
            .send(ReserveWork::Flush {
                release: true,
                response: Some(tx),
            })
            .await
            .context("meter stopped")?;
        rx.await.context("meter stopped")?
    }
    async fn admit_durably(
        &self,
        rule: &Rule,
        upload: bool,
        bytes: usize,
        datagram: bool,
    ) -> Result<Option<usize>> {
        let deadline = Instant::now() + Duration::from_millis(rule.connect_timeout_ms);
        loop {
            let budget_updated = self.store.budget_updated();
            let (tx, rx) = oneshot::channel();
            self.sender
                .send(MeterMessage {
                    request: Some(Admission {
                        rule_id: rule.id.clone(),
                        meter_epoch: rule.meter_epoch.clone(),
                        upload,
                        bytes,
                        datagram,
                    }),
                    response: tx,
                })
                .await
                .context("meter stopped")?;
            match rx.await.context("meter stopped")?? {
                AdmissionDecision::Admitted(n) => return Ok(Some(n)),
                AdmissionDecision::Rejected => return Ok(None),
                AdmissionDecision::AwaitingBudget => {
                    if Instant::now() >= deadline {
                        self.counters.timeouts.fetch_add(1, Ordering::Relaxed);
                        return Ok(None);
                    }
                    self.counters.waiting.fetch_add(1, Ordering::Relaxed);
                    let _wait = BudgetWaitGuard(self.counters.clone(), Instant::now());
                    tokio::select! {_=budget_updated=>{},_=sleep_until((Instant::now()+Duration::from_millis(50)).min(deadline))=>{}}
                }
            }
        }
    }
    async fn barrier(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.sender
            .send(MeterMessage {
                request: None,
                response: tx,
            })
            .await
            .context("meter stopped")?;
        rx.await??;
        self.release().await
    }
}

struct Bucket {
    rate: Option<u64>,
    tokens: f64,
    updated: Instant,
    /// Sends of at least `SMALL_SEND` bytes wait here: one queue per user in
    /// arrival order, and the users take turns.
    line: VecDeque<(u64, VecDeque<u64>)>,
    next_ticket: u64,
}
impl Bucket {
    fn refill(&mut self, rate: u64) {
        let now = Instant::now();
        self.tokens = (self.tokens + now.duration_since(self.updated).as_secs_f64() * rate as f64)
            .min(rate.max(BUFFER_SIZE as u64) as f64);
        self.updated = now;
    }
}
/// Smaller sends (interactive traffic, a new connection's first reads) skip
/// the line, so bulk transfers cannot delay them.
const SMALL_SEND: usize = MIN_STREAM_BUFFER;
/// Token bucket over combined upload + download application bytes. Bulk sends
/// take turns: users in rotation, each user's sends in arrival order, and a
/// session reading again rejoins at the back. Users share the rate evenly
/// however many connections each opens, and so do one user's connections,
/// instead of racing for each refill.
struct Limiter {
    bucket: StdMutex<Bucket>,
    turn: tokio::sync::Notify,
}
/// Leaves the line when a send is admitted or abandoned (session cancelled).
struct Ticket<'a> {
    limiter: &'a Limiter,
    user: u64,
    id: u64,
}
impl Drop for Ticket<'_> {
    fn drop(&mut self) {
        let mut b = self.limiter.bucket.lock().unwrap();
        let first = b.line.front().and_then(|(_, q)| q.front()) == Some(&self.id);
        let Some(at) = b.line.iter().position(|(user, _)| *user == self.user) else {
            return;
        };
        b.line[at].1.retain(|&t| t != self.id);
        // The user who just sent goes to the back of the rotation.
        let (user, queue) = b.line.remove(at).unwrap();
        if !queue.is_empty() {
            if first {
                b.line.push_back((user, queue));
            } else {
                b.line.insert(at, (user, queue));
            }
        }
        drop(b);
        if first {
            self.limiter.turn.notify_waiters();
        }
    }
}
impl Limiter {
    fn new(rate: Option<u64>) -> Self {
        Self {
            bucket: StdMutex::new(Bucket {
                rate,
                tokens: rate.unwrap_or(0).max(BUFFER_SIZE as u64) as f64,
                updated: Instant::now(),
                line: VecDeque::new(),
                next_ticket: 0,
            }),
            turn: tokio::sync::Notify::new(),
        }
    }
    fn set_rate(&self, rate: Option<u64>) {
        let mut b = self.bucket.lock().unwrap();
        if b.rate != rate {
            b.rate = rate;
            b.tokens = b
                .tokens
                .min(rate.unwrap_or(0).max(BUFFER_SIZE as u64) as f64);
            b.updated = Instant::now();
        }
        drop(b);
        // Waiters re-check: a removed rate admits everyone at once.
        self.turn.notify_waiters();
    }
    async fn throttle(&self, bytes: usize, user: u64) {
        let mut ticket = None;
        loop {
            // Registered before checking, so a turn handed over in between is not missed.
            let turn = self.turn.notified();
            let wait = {
                let mut b = self.bucket.lock().unwrap();
                let Some(rate) = b.rate else {
                    return;
                };
                if bytes >= SMALL_SEND && ticket.is_none() {
                    let id = b.next_ticket;
                    b.next_ticket += 1;
                    match b.line.iter_mut().find(|(u, _)| *u == user) {
                        Some((_, queue)) => queue.push_back(id),
                        None => b.line.push_back((user, VecDeque::from([id]))),
                    }
                    ticket = Some(Ticket {
                        limiter: self,
                        user,
                        id,
                    });
                }
                b.refill(rate);
                let head = b.line.front().and_then(|(_, q)| q.front());
                let my_turn = ticket.as_ref().is_none_or(|t| head == Some(&t.id));
                if !my_turn {
                    None
                } else if b.tokens >= bytes as f64 {
                    b.tokens -= bytes as f64;
                    return;
                } else {
                    Some(Duration::from_secs_f64(
                        ((bytes as f64 - b.tokens) / rate as f64).clamp(0.001, 1.0),
                    ))
                }
            };
            match wait {
                Some(wait) => sleep(wait).await,
                None => turn.await,
            }
        }
    }
}
/// One user's share of a cross-node limit, used by all of the user's rules
/// on this node. Sends are counted only while a share is held.
struct UserLimit {
    tenant_id: String,
    owner_id: String,
    rate: Limiter,
    limited: AtomicBool,
    bytes: AtomicU64,
    waited_us: AtomicU64,
    share: StdMutex<Option<HeldShare>>,
}
#[derive(Clone, Copy)]
struct HeldShare {
    rate: u64,
    fallback: u64,
    until: Instant,
}
impl UserLimit {
    async fn throttle(&self, bytes: usize, user: u64) {
        if !self.limited.load(Ordering::Relaxed) {
            return;
        }
        self.bytes.fetch_add(bytes as u64, Ordering::Relaxed);
        let started = Instant::now();
        self.rate.throttle(bytes, user).await;
        let waited = started.elapsed().as_micros() as u64;
        // Ignores lock and scheduling noise; a real wait sleeps at least 1 ms.
        if waited >= 100 {
            self.waited_us.fetch_add(waited, Ordering::Relaxed);
        }
    }
    fn hold(&self, share: Option<HeldShare>) {
        *self.share.lock().unwrap() = share;
        self.limited.store(share.is_some(), Ordering::Relaxed);
        self.rate.set_rate(share.map(|s| s.rate));
    }
}
fn user_key(tenant_id: &str, owner_id: &str) -> u64 {
    let hash = Sha256::digest(format!("{tenant_id}\0{owner_id}"));
    u64::from_be_bytes(hash[0..8].try_into().unwrap())
}
#[derive(Default)]
struct UserLimits(StdMutex<HashMap<u64, Arc<UserLimit>>>);
impl UserLimits {
    fn get(&self, tenant_id: &str, owner_id: &str) -> Arc<UserLimit> {
        self.0
            .lock()
            .unwrap()
            .entry(user_key(tenant_id, owner_id))
            .or_insert_with(|| {
                Arc::new(UserLimit {
                    tenant_id: tenant_id.into(),
                    owner_id: owner_id.into(),
                    rate: Limiter::new(None),
                    limited: AtomicBool::new(false),
                    bytes: AtomicU64::new(0),
                    waited_us: AtomicU64::new(0),
                    share: StdMutex::new(None),
                })
            })
            .clone()
    }
    fn held(&self) -> Vec<(Arc<UserLimit>, HeldShare)> {
        self.0
            .lock()
            .unwrap()
            .values()
            .filter_map(|limit| Some((limit.clone(), (*limit.share.lock().unwrap())?)))
            .collect()
    }
}
struct SharedRule {
    tcp: Arc<AtomicUsize>,
    udp: Arc<AtomicUsize>,
    rate: Limiter,
    target_counts: StdMutex<HashMap<String, Weak<AtomicUsize>>>,
}
impl SharedRule {
    fn new(rate: Option<u64>) -> Self {
        Self {
            target_counts: StdMutex::new(HashMap::new()),
            tcp: Arc::new(AtomicUsize::new(0)),
            udp: Arc::new(AtomicUsize::new(0)),
            rate: Limiter::new(rate),
        }
    }
    fn target_counters(&self, targets: &[Target]) -> Vec<Arc<AtomicUsize>> {
        let mut counts = self.target_counts.lock().unwrap();
        counts.retain(|_, weak| weak.strong_count() > 0);
        targets
            .iter()
            .map(|target| {
                let entry = counts.entry(target.address.clone()).or_default();
                if let Some(count) = entry.upgrade() {
                    count
                } else {
                    let count = Arc::new(AtomicUsize::new(0));
                    *entry = Arc::downgrade(&count);
                    count
                }
            })
            .collect()
    }
}

struct CountGuard {
    count: Arc<AtomicUsize>,
    stats: Arc<Counters>,
    tcp: bool,
}
impl CountGuard {
    fn acquire(
        count: Arc<AtomicUsize>,
        limit: usize,
        stats: Arc<Counters>,
        tcp: bool,
    ) -> Option<Self> {
        let mut current = count.load(Ordering::Relaxed);
        loop {
            if current >= limit {
                return None;
            }
            match count.compare_exchange_weak(
                current,
                current + 1,
                Ordering::AcqRel,
                Ordering::Relaxed,
            ) {
                Ok(_) => break,
                Err(next) => current = next,
            }
        }
        if tcp {
            stats.active_tcp.fetch_add(1, Ordering::Relaxed);
        } else {
            stats.active_udp.fetch_add(1, Ordering::Relaxed);
        }
        Some(Self { count, stats, tcp })
    }
}
impl Drop for CountGuard {
    fn drop(&mut self) {
        self.count.fetch_sub(1, Ordering::AcqRel);
        if self.tcp {
            self.stats.active_tcp.fetch_sub(1, Ordering::Relaxed);
        } else {
            self.stats.active_udp.fetch_sub(1, Ordering::Relaxed);
        }
    }
}
struct TargetGuard(Arc<AtomicUsize>);
impl Drop for TargetGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, Ordering::Relaxed);
    }
}

struct RuleResources {
    node_rate: Arc<Limiter>,
    user_limit: Option<Arc<UserLimit>>,
    salts: Option<shadowsocks::SaltCache>,
}

struct RuntimeRule {
    shadowsocks: Option<shadowsocks::Server>,
    socks5: Option<socks5::Server>,
    http_connect: Option<http_connect::Server>,
    socks5_udp: Option<Arc<socks5::UdpRegistry>>,
    destination: destination_acl::DestinationPolicy,
    multipath_server: Option<Arc<multipath::Server>>,
    multipath_client: Option<Arc<Semaphore>>,
    health: Option<Arc<HealthSet>>,
    prewarm: Option<Arc<PrewarmSet>>,
    spec: Rule,
    resolver: Arc<TargetResolver>,
    routes: Arc<Routes>,
    tls: PreparedTls,
    shared: Arc<SharedRule>,
    node_rate: Arc<Limiter>,
    cancel: CancellationToken,
    cursor: AtomicU64,
    target_active: Vec<Arc<AtomicUsize>>,
    /// Per target: until when (ms since [`clock`]) a real connect failure keeps it last.
    target_cooldown: Vec<AtomicU64>,
    /// Target that `lowest_latency` currently sends new sessions to.
    preferred: AtomicUsize,
    /// The rule's owner; a node cap rotates between owners.
    user: u64,
    /// The owner's cross-node share. Every listener enforces it, including an
    /// advertised one, because an advertised address can also be reached
    /// directly and topology metadata alone proves no metered upstream.
    user_limit: Option<Arc<UserLimit>>,
}
/// Orders same-priority targets by probe latency, unmeasured ones last. The
/// current choice is kept until another target is faster by more than 10%
/// plus 1 ms, so close measurements do not move new sessions back and forth.
fn by_latency(
    pool: &[usize],
    latency: impl Fn(usize) -> Option<u64>,
    current: usize,
) -> Vec<usize> {
    let mut sorted = pool.to_vec();
    sorted.sort_by_key(|&index| (latency(index).is_none(), latency(index).unwrap_or(0), index));
    if pool.contains(&current)
        && let (Some(best), Some(held)) = (latency(sorted[0]), latency(current))
        && held <= best + best / 10 + 1000
    {
        sorted.retain(|&index| index != current);
        sorted.insert(0, current);
    }
    sorted
}
/// How long a target that failed a real connection is tried after the others.
const TARGET_COOLDOWN: Duration = Duration::from_secs(10);
fn clock() -> u64 {
    static START: std::sync::LazyLock<Instant> = std::sync::LazyLock::new(Instant::now);
    START.elapsed().as_millis() as u64
}
impl RuntimeRule {
    fn new(
        spec: Rule,
        shared: Option<Arc<SharedRule>>,
        tls: PreparedTls,
        resolver: Arc<TargetResolver>,
        routes: Arc<Routes>,
        resources: RuleResources,
    ) -> Self {
        let shared = shared.unwrap_or_else(|| Arc::new(SharedRule::new(spec.rate_bytes_per_sec)));
        let target_active = shared.target_counters(&spec.targets);
        Self {
            shadowsocks: spec.inbound_shadowsocks.as_ref().map(|config| {
                shadowsocks::Server::with_salts(
                    config,
                    resources
                        .salts
                        .unwrap_or_else(|| Arc::new(StdMutex::new(shadowsocks::Salts::default()))),
                )
                .expect("validated configuration")
            }),
            socks5: spec
                .inbound_socks5
                .as_ref()
                .map(|config| socks5::Server::new(config).expect("validated configuration")),
            http_connect: spec
                .inbound_http_connect
                .as_ref()
                .map(|config| http_connect::Server::new(config).expect("validated configuration")),
            socks5_udp: spec
                .inbound_socks5
                .as_ref()
                .map(|_| Arc::new(socks5::UdpRegistry::default())),
            destination: destination_acl::DestinationPolicy::parse(
                &spec.allow_destinations,
                &spec.deny_destinations,
            )
            .expect("validated configuration"),
            multipath_server: spec
                .inbound_multipath
                .clone()
                .map(|s| Arc::new(multipath::Server::new(s))),
            multipath_client: spec
                .outbound_multipath
                .as_ref()
                .map(|s| Arc::new(Semaphore::new(usize::from(s.limits.max_sessions)))),
            health: HealthSet::new(&spec),
            prewarm: PrewarmSet::new(&spec),
            target_cooldown: spec.targets.iter().map(|_| AtomicU64::new(0)).collect(),
            preferred: AtomicUsize::new(usize::MAX),
            user: user_key(&spec.tenant_id, &spec.owner_id),
            user_limit: resources.user_limit,
            spec,
            resolver,
            routes,
            tls,
            shared,
            node_rate: resources.node_rate,
            cancel: CancellationToken::new(),
            cursor: AtomicU64::new(0),
            target_active,
        }
    }
    /// Waits for the rule's, the user's and the node's byte rate.
    async fn throttle(&self, bytes: usize) {
        self.shared.rate.throttle(bytes, self.user).await;
        if let Some(limit) = &self.user_limit {
            limit.throttle(bytes, self.user).await;
        }
        self.node_rate.throttle(bytes, self.user).await;
    }
    /// Moves a target behind the others for new sessions without waiting for
    /// health probes; it stays eligible, so a lone target is still tried.
    fn cool(&self, index: usize) {
        self.target_cooldown[index].store(
            clock() + TARGET_COOLDOWN.as_millis() as u64,
            Ordering::Relaxed,
        );
    }
    fn order(&self, source: SocketAddr, inlet: ListenerKey) -> Vec<usize> {
        let targets = &self.spec.targets;
        let mut eligible: Vec<_> = (0..targets.len())
            .filter(|&index| {
                self.health.as_ref().is_none_or(|health| {
                    health
                        .point(index, inlet.address.port(), inlet.tcp)
                        .eligible()
                }) && targets[index].max_sessions.is_none_or(|limit| {
                    self.target_active[index].load(Ordering::Relaxed) < limit as usize
                })
            })
            .collect();
        eligible.sort_by_key(|&index| targets[index].priority);
        // Draining targets take new sessions only when nothing else can.
        let (active, mut last_resort): (Vec<_>, Vec<_>) = eligible
            .into_iter()
            .partition(|&index| !targets[index].draining);
        let eligible = if active.is_empty() {
            std::mem::take(&mut last_resort)
        } else {
            active
        };
        if eligible.is_empty() {
            return eligible;
        }
        let preferred = eligible
            .iter()
            .take_while(|&&index| targets[index].priority == targets[eligible[0]].priority)
            .count();
        // Within the top priority, degraded targets wait behind clean ones;
        // lowest_latency already counts loss in its ranking.
        let (clean, degraded): (Vec<usize>, Vec<usize>) =
            eligible[..preferred].iter().partition(|&&index| {
                self.spec.balance == Balance::LowestLatency
                    || self.health.as_ref().is_none_or(|health| {
                        !health
                            .point(index, inlet.address.port(), inlet.tcp)
                            .degraded()
                    })
            });
        let (primary, degraded) = if clean.is_empty() {
            (degraded, vec![])
        } else {
            (clean, degraded)
        };
        let primary = &primary[..];
        let next = self.cursor.fetch_add(1, Ordering::Relaxed);
        let rotate = |first: usize| -> Vec<usize> {
            (0..primary.len())
                .map(|i| primary[(first + i) % primary.len()])
                .collect()
        };
        let pool = match self.spec.balance {
            Balance::WeightedRoundRobin | Balance::SourceHash => {
                let sum: u64 = primary.iter().map(|&i| targets[i].weight as u64).sum();
                let value = if self.spec.balance == Balance::SourceHash {
                    let hash = Sha256::digest(
                        format!("{}:{}", self.spec.id, canonical_ip(source.ip())).as_bytes(),
                    );
                    u64::from_be_bytes(hash[0..8].try_into().unwrap())
                } else {
                    next
                };
                let mut position = value % sum;
                let mut selected = 0;
                for (i, &index) in primary.iter().enumerate() {
                    let t = &targets[index];
                    if position < t.weight as u64 {
                        selected = i;
                        break;
                    }
                    position -= t.weight as u64;
                }
                rotate(selected)
            }
            Balance::LeastConnections => {
                let offset = (next % primary.len() as u64) as usize;
                let first = (0..primary.len())
                    .map(|i| (i + offset) % primary.len())
                    .min_by(|&a, &b| {
                        let ia = primary[a];
                        let ib = primary[b];
                        let ca = self.target_active[ia].load(Ordering::Relaxed) as u64;
                        let cb = self.target_active[ib].load(Ordering::Relaxed) as u64;
                        (ca * targets[ib].weight as u64).cmp(&(cb * targets[ia].weight as u64))
                    })
                    .unwrap();
                rotate(first)
            }
            Balance::LowestLatency => {
                let latency = |index: usize| {
                    self.health.as_ref().and_then(|health| {
                        health
                            .point(index, inlet.address.port(), inlet.tcp)
                            .selection_latency_us()
                    })
                };
                let pool = by_latency(primary, latency, self.preferred.load(Ordering::Relaxed));
                self.preferred.store(pool[0], Ordering::Relaxed);
                pool
            }
        };
        let now = clock();
        let (ready, cooling): (Vec<_>, Vec<_>) = pool
            .into_iter()
            .chain(degraded)
            .chain(eligible[preferred..].iter().copied())
            .partition(|&index| self.target_cooldown[index].load(Ordering::Relaxed) <= now);
        ready
            .into_iter()
            .chain(cooling)
            .chain(last_resort)
            .collect()
    }
    fn target_guard(&self, index: usize) -> Option<TargetGuard> {
        let count = &self.target_active[index];
        if let Some(limit) = self.spec.targets[index].max_sessions {
            let mut current = count.load(Ordering::Relaxed);
            loop {
                if current >= limit as usize {
                    return None;
                }
                match count.compare_exchange_weak(
                    current,
                    current + 1,
                    Ordering::AcqRel,
                    Ordering::Relaxed,
                ) {
                    Ok(_) => break,
                    Err(next) => current = next,
                }
            }
        } else {
            count.fetch_add(1, Ordering::Relaxed);
        }
        Some(TargetGuard(count.clone()))
    }
    fn accepts(&self, peer: SocketAddr) -> bool {
        self.spec.permits(peer.ip())
            && self
                .spec
                .expires_at_ms
                .is_none_or(|expiry| expiry > now_ms())
    }
    fn accepts_transport(&self, peer: SocketAddr) -> bool {
        if let Some(proxy) = &self.spec.inbound_proxy {
            proxy.trusts(peer.ip())
                && self
                    .spec
                    .expires_at_ms
                    .is_none_or(|expiry| expiry > now_ms())
        } else {
            self.accepts(peer)
        }
    }
}

struct ProbeGuard(Arc<Counters>);
impl Drop for ProbeGuard {
    fn drop(&mut self) {
        self.0.active_probes.fetch_sub(1, Ordering::Relaxed);
    }
}
fn start_health(
    rule: Arc<RuntimeRule>,
    slots: Arc<Semaphore>,
    stats: Arc<Counters>,
    tasks: TaskTracker,
) {
    let health = rule.health.as_ref().expect("health worker has policy");
    for (&key, point) in &health.points {
        let rule = rule.clone();
        let stop = health.stop.clone();
        let point = point.clone();
        let slots = slots.clone();
        let stats = stats.clone();
        let probe_tasks = tasks.clone();
        tasks.spawn(async move {
            let mut udp=None;
            // The period follows each result: faster before a target's first
            // acceptance and while a healthy target fails (see probe_period).
            let mut next=Instant::now();
            loop {
                tokio::select!{biased;_=stop.cancelled()=>break,_=sleep_until(next)=>{}}
                let permit=tokio::select!{biased;_=stop.cancelled()=>break,permit=slots.clone().acquire_owned()=>match permit{Ok(p)=>p,Err(_)=>break}};
                stats.active_probes.fetch_add(1,Ordering::Relaxed);let guard=ProbeGuard(stats.clone());
                let began=Instant::now();
                let result=tokio::select!{biased;_=stop.cancelled()=>break,result=tokio::time::timeout(point.probe_timeout(),probe_target(&rule,key,&point,&stats,&probe_tasks,&mut udp))=>result};
                let outcome=match result{Ok(Ok(()))=>Ok(began.elapsed().as_micros().min(u128::from(u64::MAX)) as u64),Ok(Err(error))=>Err(error),Err(_)=>Err(health::Failure::Timeout)};
                if outcome.is_err(){udp=None;}
                point.observe(outcome);drop(guard);drop(permit);
                next=(began+point.probe_period()).max(Instant::now());
            }
        });
    }
}
/// A UDP probe socket kept between successful probes of one target. A fresh
/// source port per probe would open a new session on a downstream relay each
/// interval, held there for its idle timeout; reusing one keeps a single
/// session. Any failure discards it so the next probe starts a new session.
struct UdpProbe {
    address: SocketAddr,
    socket: UdpSocket,
    _route: crate::routing::LoopGuard,
}
async fn probe_target(
    rule: &RuntimeRule,
    key: health::Key,
    point: &Observation,
    stats: &Counters,
    tasks: &TaskTracker,
    udp: &mut Option<UdpProbe>,
) -> std::result::Result<(), health::Failure> {
    use health::{Failure as F, StreamProbe};
    if rule.spec.expires_at_ms.is_some_and(|at| at <= now_ms()) {
        return Err(F::Expired);
    }
    let policy = rule.spec.health_check.as_ref().unwrap();
    let mut inlet = ListenerKey {
        address: rule.spec.listen,
        tcp: key.tcp,
    };
    inlet.address.set_port(key.port);
    let target = rule
        .spec
        .target_address(key.index, key.port)
        .map_err(|_| F::Transport)?;
    let addresses = rule.resolver.resolve(&target).await.map_err(|_| F::Dns)?;
    let mut failure = F::Transport;
    for address in addresses {
        let result = async {
            if key.tcp {
                let (stream, route) = open_tcp_target(rule, key.index, address, inlet, None)
                    .await
                    .map_err(|_| F::Transport)?;
                let mut stream = transport::hold(stream, route);
                if rule.spec.outbound_multipath.is_some() {
                    let spec = multipath::ClientConfig {
                        limits: multipath::Limits {
                            window_frames: 4,
                            max_sessions: 1,
                            ..Default::default()
                        },
                        mode: multipath::Mode::Stripe,
                        min_paths: 1,
                        paths: vec![],
                    };
                    let (session, path) = multipath::Client::create(
                        multipath::Path {
                            stream,
                            slot: key.index,
                            send_weight: 1,
                            receive_weight: 1,
                        },
                        &spec,
                    )
                    .await
                    .map_err(|_| F::Transport)?;
                    stream = session
                        .finish(
                            vec![path],
                            stats.multipath.clone(),
                            tasks.clone(),
                            Box::new(()),
                        )
                        .await
                        .map_err(|_| F::Transport)?;
                }
                if let Some(StreamProbe::Exchange {
                    request_base64,
                    expected_base64,
                    half_close,
                }) = &policy.tcp
                {
                    let request = health::payload(request_base64, false).expect("validated probe");
                    let expected = health::payload(expected_base64, true).expect("validated probe");
                    let mut written = 0;
                    while written < request.len() {
                        let n = stream.write(&request[written..]).await.map_err(|_| F::Io)?;
                        if n == 0 {
                            return Err(F::Io);
                        }
                        written += n;
                        point.traffic(true, n);
                    }
                    stream.flush().await.map_err(|_| F::Io)?;
                    if *half_close {
                        stream.shutdown().await.map_err(|_| F::Io)?;
                    }
                    let mut reply = vec![0; expected.len()];
                    let mut read = 0;
                    while read < reply.len() {
                        let n = stream.read(&mut reply[read..]).await.map_err(|_| F::Io)?;
                        if n == 0 {
                            return Err(F::UnexpectedResponse);
                        }
                        read += n;
                        point.traffic(false, n);
                    }
                    if reply != expected {
                        return Err(F::UnexpectedResponse);
                    }
                }
                // Success depends on setup/response, not on a peer agreeing to close.
                // Dropping the stream also cancels the bounded WS driver.
            } else {
                if udp.as_ref().is_none_or(|cached| cached.address != address) {
                    *udp = None;
                    let route = rule
                        .routes
                        .reserve(inlet, address)
                        .map_err(|_| F::Transport)?;
                    let socket =
                        network::outbound_udp(rule.spec.outbound_bind.as_ref(), address.is_ipv4())
                            .map_err(|_| F::Transport)?;
                    socket.connect(address).await.map_err(|_| F::Transport)?;
                    *udp = Some(UdpProbe {
                        address,
                        socket,
                        _route: route,
                    });
                }
                let socket = &udp.as_ref().expect("probe socket prepared").socket;
                // Discard replies that arrived after an earlier probe finished.
                let mut stale = [0; health::MAX_PROBE_BYTES + 1];
                while socket.try_recv(&mut stale).is_ok() {}
                let probe = policy.udp.as_ref().unwrap();
                let request =
                    health::payload(&probe.request_base64, true).expect("validated probe");
                let expected =
                    health::payload(&probe.expected_base64, true).expect("validated probe");
                let mut wire = if let Some(proxy) = &rule.spec.targets[key.index].proxy_protocol {
                    proxy::encode(
                        proxy,
                        false,
                        ConnectionInfo {
                            source: socket.local_addr().map_err(|_| F::Transport)?,
                            destination: address,
                        },
                    )
                    .map_err(|_| F::Transport)?
                } else {
                    vec![]
                };
                let header = wire.len();
                wire.extend_from_slice(&request);
                let n = socket.send(&wire).await.map_err(|_| F::Io)?;
                point.traffic(true, n.saturating_sub(header));
                if n != wire.len() {
                    return Err(F::Io);
                }
                let mut reply = vec![0; health::MAX_PROBE_BYTES + 1];
                let n = socket.recv(&mut reply).await.map_err(|_| F::Io)?;
                point.traffic(false, n);
                if reply[..n] != expected {
                    return Err(F::UnexpectedResponse);
                }
            }
            Ok(())
        }
        .await;
        match result {
            Ok(()) => return Ok(()),
            Err(error) => failure = error,
        }
    }
    Err(failure)
}

struct ListenerHandle {
    rule_id: String,
    update: watch::Sender<Arc<RuntimeRule>>,
    stop: CancellationToken,
    task: JoinHandle<()>,
}
enum StagedSocket {
    Tcp(TcpListener),
    Udp(UdpSocket),
}
impl StagedSocket {
    fn bind(key: ListenerKey) -> Result<Self> {
        let address = key.address;
        Ok(if key.tcp {
            Self::Tcp(
                network::tcp_listener(address)
                    .with_context(|| format!("cannot stage TCP listener {address}"))?,
            )
        } else {
            Self::Udp(
                network::udp_listener(address)
                    .with_context(|| format!("cannot stage UDP listener {address}"))?,
            )
        })
    }
}
/// Whether `a` and `b` are distinct listeners the kernel will not bind at
/// once: same protocol, port and family, and one of them a wildcard.
fn overlapping(a: ListenerKey, b: ListenerKey) -> bool {
    a != b
        && a.tcp == b.tcp
        && a.address.port() == b.address.port()
        && a.address.is_ipv4() == b.address.is_ipv4()
        && (a.address.ip().is_unspecified() || b.address.ip().is_unspecified())
}
#[derive(Default)]
struct EngineInner {
    config: Option<NodeConfig>,
    listeners: HashMap<ListenerKey, ListenerHandle>,
    rules: HashMap<String, Arc<RuntimeRule>>,
    resolvers: HashMap<Option<DnsCache>, Arc<TargetResolver>>,
    /// Replay state per (method, key), shared by rule revisions so a rename
    /// or rate change keeps a captured request unacceptable.
    shadowsocks_salts: HashMap<Vec<u8>, shadowsocks::SaltCache>,
    stopped: bool,
}

pub struct Engine {
    health_runtimes: StdMutex<Vec<Arc<RuntimeRule>>>,
    probe_slots: Arc<Semaphore>,
    store: Store,
    tls_directory: Option<PathBuf>,
    meter: Meter,
    inner: Mutex<EngineInner>,
    stats: Arc<Counters>,
    tasks: TaskTracker,
    routes: Arc<Routes>,
    node_rate: Arc<Limiter>,
    user_limits: UserLimits,
}
impl Drop for Engine {
    fn drop(&mut self) {
        // Async callers can be aborted before shutdown(). Never detach live
        // forwarding tasks when the owner of this engine disappears.
        let inner = self.inner.get_mut();
        for rule in inner.rules.values() {
            rule.cancel.cancel();
            if let Some(health) = &rule.health {
                health.cancel();
            }
            if let Some(prewarm) = &rule.prewarm {
                prewarm.stop.cancel();
            }
        }
        for listener in inner.listeners.values() {
            listener.stop.cancel();
            listener.task.abort();
        }
        let runtimes = self
            .health_runtimes
            .get_mut()
            .unwrap_or_else(|error| error.into_inner());
        for rule in runtimes.iter() {
            if let Some(health) = &rule.health {
                health.cancel();
            }
        }
        self.tasks.close();
    }
}
impl Engine {
    pub fn new(store: Store) -> Self {
        Self::with_tls_directory(store, None)
    }
    pub fn with_tls_directory(store: Store, tls_directory: Option<PathBuf>) -> Self {
        Self {
            health_runtimes: StdMutex::new(vec![]),
            probe_slots: Arc::new(Semaphore::new(health::MAX_CONCURRENT)),
            tls_directory,
            meter: Meter::new(store.clone()),
            store,
            inner: Mutex::new(EngineInner::default()),
            stats: Arc::new(Counters::default()),
            tasks: TaskTracker::new(),
            routes: Arc::new(Routes::default()),
            node_rate: Arc::new(Limiter::new(None)),
            user_limits: UserLimits::default(),
        }
    }
    /// Holds each controller share until `sent + LEASE`, `sent` being when
    /// the sync request left, so it never outlives the controller's view.
    /// Users left out lose their limit.
    pub fn set_user_shares(&self, shares: &[UserShare], sent: Instant) {
        self.hold_user_shares(shares, sent + crate::user_rate::LEASE);
    }
    /// Extends the shares in force without changing them. Used while a new
    /// configuration is rejected: its listener is still the old one, so its
    /// limit must not expire or be replaced by the failed revision's list.
    pub fn renew_user_shares(&self, sent: Instant) {
        let shares = self.user_shares();
        self.hold_user_shares(&shares, sent + crate::user_rate::LEASE);
    }
    fn hold_user_shares(&self, shares: &[UserShare], until: Instant) {
        let mut kept = std::collections::HashSet::new();
        for share in shares {
            kept.insert(user_key(&share.tenant_id, &share.owner_id));
            self.user_limits
                .get(&share.tenant_id, &share.owner_id)
                .hold(Some(HeldShare {
                    rate: share.rate_bytes_per_sec.max(1),
                    fallback: share.fallback_bytes_per_sec.max(1),
                    until,
                }));
        }
        let mut limits = self.user_limits.0.lock().unwrap();
        for (key, limit) in limits.iter() {
            if !kept.contains(key) {
                limit.hold(None);
            }
        }
        // Users without rules or a share here.
        limits.retain(|key, limit| kept.contains(key) || Arc::strong_count(limit) > 1);
    }
    /// Shares whose lease ran out drop to their fallback. Returns whether any
    /// share is held, which makes the agent sync every second.
    pub fn expire_user_shares(&self) -> bool {
        let held = self.user_limits.held();
        let now = Instant::now();
        for (limit, share) in &held {
            if share.until <= now && share.rate > share.fallback {
                limit.hold(Some(HeldShare {
                    rate: share.fallback,
                    ..*share
                }));
            }
        }
        !held.is_empty()
    }
    /// The shares in force, kept across agent restarts.
    pub fn user_shares(&self) -> Vec<UserShare> {
        let mut shares: Vec<_> = self
            .user_limits
            .held()
            .into_iter()
            .map(|(limit, share)| UserShare {
                tenant_id: limit.tenant_id.clone(),
                owner_id: limit.owner_id.clone(),
                rate_bytes_per_sec: share.rate,
                fallback_bytes_per_sec: share.fallback,
            })
            .collect();
        shares.sort_by(|a, b| (&a.tenant_id, &a.owner_id).cmp(&(&b.tenant_id, &b.owner_id)));
        shares
    }
    /// Restores shares saved before a restart, already expired: until the
    /// controller answers, each user gets at most the fallback.
    pub fn restore_user_shares(&self, shares: &[UserShare]) {
        self.hold_user_shares(shares, Instant::now());
        self.expire_user_shares();
    }
    pub fn stats(&self) -> EngineStats {
        let mut stats = self.stats.snapshot();
        stats.user_rates = self
            .user_limits
            .held()
            .into_iter()
            .map(|(limit, share)| UserRateReport {
                tenant_id: limit.tenant_id.clone(),
                owner_id: limit.owner_id.clone(),
                bytes: limit.bytes.load(Ordering::Relaxed),
                waited_ms: limit.waited_us.load(Ordering::Relaxed) / 1000,
                enforced_bytes_per_sec: Some(share.rate),
            })
            .collect();
        stats.meter = Some(self.meter.stats());
        for runtime in self.health_runtimes.lock().unwrap().iter() {
            if let Some(health) = &runtime.health {
                stats
                    .target_health
                    .extend(health.reports(&runtime.spec, &runtime.target_active));
            }
        }
        let preferred: HashMap<_, _> = stats
            .target_health
            .iter()
            .filter(|r| r.eligible && r.selection_reason != "draining")
            .fold(HashMap::new(), |mut map, r| {
                map.entry((r.rule_id.clone(), r.listen_port, r.protocol.tcp()))
                    .and_modify(|p: &mut u16| *p = (*p).min(r.priority))
                    .or_insert(r.priority);
                map
            });
        for report in &mut stats.target_health {
            if report.eligible
                && report.selection_reason != "draining"
                && preferred
                    .get(&(
                        report.rule_id.clone(),
                        report.listen_port,
                        report.protocol.tcp(),
                    ))
                    .is_some_and(|&priority| report.priority > priority)
            {
                report.selection_reason = "standby".into();
            }
        }
        stats
    }
    pub async fn revision(&self) -> u64 {
        self.inner
            .lock()
            .await
            .config
            .as_ref()
            .map(|c| c.revision)
            .unwrap_or(0)
    }

    pub async fn apply(&self, config: NodeConfig) -> Result<()> {
        config.validate()?;
        let mut inner = self.inner.lock().await;
        ensure!(!inner.stopped, "engine stopped");
        // New quotas, expiry and periods apply to allowance reserved after this point.
        self.meter.release().await?;
        if let Some(old) = &inner.config {
            ensure!(config.node_id == old.node_id, "node identity mismatch");
            ensure!(config.revision >= old.revision, "stale config rejected");
            if config.revision == old.revision {
                ensure!(
                    serde_json::to_value(&config)? == serde_json::to_value(old)?,
                    "same revision with changed content"
                );
                return Ok(());
            }
        }
        let mut wanted = HashMap::new();
        let mut rules = HashMap::new();
        // Cloned so an early rejection leaves the running rules' replay state
        // untouched; the pruned map is installed only after a successful swap.
        let mut salts = inner.shadowsocks_salts.clone();
        let mut staged = HashMap::new();
        let mut resolvers = HashMap::new();
        let mut deferred = vec![];
        let topology = Topology::build(&config, local_ips()?)?;
        for spec in config.rules.iter().filter(|r| r.enabled) {
            network::preflight(spec)
                .with_context(|| format!("outbound binding preflight failed for {}", spec.id))?;
            let resolver = if let Some(existing) = resolvers
                .get(&spec.dns_cache)
                .or_else(|| inner.resolvers.get(&spec.dns_cache))
            {
                Arc::clone(existing)
            } else {
                Arc::new(TargetResolver::new(spec.dns_cache.as_ref())?)
            };
            resolvers.insert(spec.dns_cache.clone(), resolver.clone());
            let runtime = if let Some(old) = inner
                .rules
                .get(&spec.id)
                .filter(|old| old.spec == *spec && !spec.uses_tls())
            {
                old.clone()
            } else {
                let tls_spec = spec.clone();
                let directory = self.tls_directory.clone();
                let tls = tokio::task::spawn_blocking(move || {
                    PreparedTls::load(&tls_spec, directory.as_deref())
                })
                .await??;
                let mut new = RuntimeRule::new(
                    spec.clone(),
                    inner.rules.get(&spec.id).map(|old| old.shared.clone()),
                    tls,
                    resolver,
                    self.routes.clone(),
                    RuleResources {
                        node_rate: self.node_rate.clone(),
                        user_limit: Some(self.user_limits.get(&spec.tenant_id, &spec.owner_id)),
                        salts: spec.inbound_shadowsocks.as_ref().map(|config| {
                            let key = shadowsocks::replay_key(config)
                                .expect("Shadowsocks configuration validated above");
                            salts
                                .entry(key)
                                .or_insert_with(|| {
                                    Arc::new(StdMutex::new(shadowsocks::Salts::default()))
                                })
                                .clone()
                        }),
                    },
                );
                if let Some(old) = inner.rules.get(&spec.id)
                    && old.spec.health_check == spec.health_check
                    && old.spec.expires_at_ms == spec.expires_at_ms
                    && crate::topology::route_signature(&old.spec)
                        == crate::topology::route_signature(spec)
                    && old.tls.fingerprint == new.tls.fingerprint
                {
                    new.health = old.health.clone();
                }
                if let Some(old) = inner.rules.get(&spec.id).filter(|old| {
                    !security_policy_changed(&old.spec, spec)
                        && old.tls.fingerprint == new.tls.fingerprint
                }) {
                    new.cancel = old.cancel.clone();
                    new.multipath_server = old.multipath_server.clone();
                    new.multipath_client = old.multipath_client.clone();
                }
                Arc::new(new)
            };
            rules.insert(spec.id.clone(), runtime.clone());
            for tcp in [true, false] {
                if (tcp && !spec.protocol.tcp()) || (!tcp && !spec.protocol.udp()) {
                    continue;
                }
                for address in spec.listen_addresses() {
                    let key = ListenerKey { address, tcp };
                    wanted.insert(key, runtime.clone());
                    if let Some(existing) = inner.listeners.get(&key) {
                        ensure!(
                            existing.rule_id == spec.id,
                            "listener ownership change requires removing the old listener first"
                        );
                    } else {
                        match StagedSocket::bind(key) {
                            Ok(socket) => {
                                staged.insert(key, socket);
                            }
                            Err(error)
                                if error.downcast_ref::<std::io::Error>().map(|e| e.kind())
                                    == Some(std::io::ErrorKind::AddrInUse) =>
                            {
                                deferred.push((key, error))
                            }
                            Err(error) => return Err(error),
                        }
                    }
                }
            }
        }
        // Moving a listener between one address and the wildcard on the same
        // port cannot bind while the old listener is open, so that old
        // listener closes first; the port is closed for the time of one bind.
        // Any later failure reopens it before returning.
        let mut released = vec![];
        if !deferred.is_empty() {
            let blockers: Vec<Vec<_>> = deferred
                .iter()
                .map(|(key, _)| {
                    inner
                        .listeners
                        .keys()
                        .filter(|old| !wanted.contains_key(old) && overlapping(**old, *key))
                        .copied()
                        .collect()
                })
                .collect();
            // Something other than this node's own old listener holds the port.
            if let Some(index) = blockers.iter().position(Vec::is_empty) {
                return Err(deferred.swap_remove(index).1);
            }
            let mut blocking: Vec<_> = blockers.into_iter().flatten().collect();
            blocking.sort_by_key(|key| (key.address, key.tcp));
            blocking.dedup();
            for key in blocking {
                let listener = inner.listeners.remove(&key).expect("listed above");
                listener.stop.cancel();
                released.push((key, listener.update.borrow().clone()));
                if let Err(error) = listener.task.await {
                    self.reopen(&mut inner, released);
                    return Err(anyhow::Error::from(error).context("listener task failed"));
                }
            }
            for (key, _) in deferred {
                match StagedSocket::bind(key) {
                    Ok(socket) => {
                        staged.insert(key, socket);
                    }
                    Err(error) => {
                        self.reopen(&mut inner, released);
                        return Err(error);
                    }
                }
            }
        }
        // No running state is modified before the transaction and all binds succeed.
        let db = self.store.clone();
        let saved = config.clone();
        if let Err(error) = tokio::task::spawn_blocking(move || db.save_agent_config(&saved))
            .await
            .map_err(anyhow::Error::from)
            .and_then(|saved| saved)
        {
            self.reopen(&mut inner, released);
            return Err(error);
        }
        self.routes.install(topology);
        for (id, old) in &inner.rules {
            if let Some(health) = &old.health
                && !rules
                    .get(id)
                    .and_then(|new| new.health.as_ref())
                    .is_some_and(|next| Arc::ptr_eq(health, next))
            {
                health.cancel();
            }
            if let Some(prewarm) = &old.prewarm
                && !rules
                    .get(id)
                    .and_then(|new| new.prewarm.as_ref())
                    .is_some_and(|next| Arc::ptr_eq(prewarm, next))
            {
                prewarm.stop.cancel();
            }
            match rules.get(id) {
                None => old.cancel.cancel(),
                Some(new)
                    if security_policy_changed(&old.spec, &new.spec)
                        || old.tls.fingerprint != new.tls.fingerprint =>
                {
                    old.cancel.cancel()
                }
                _ => {}
            }
        }
        self.node_rate.set_rate(config.rate_bytes_per_sec);
        for runtime in rules.values() {
            runtime
                .shared
                .rate
                .set_rate(runtime.spec.rate_bytes_per_sec);
            if let Some(health) = &runtime.health
                && !inner
                    .rules
                    .get(&runtime.spec.id)
                    .and_then(|old| old.health.as_ref())
                    .is_some_and(|old| Arc::ptr_eq(old, health))
            {
                start_health(
                    runtime.clone(),
                    self.probe_slots.clone(),
                    self.stats.clone(),
                    self.tasks.clone(),
                );
            }
            if let Some(prewarm) = &runtime.prewarm
                && !inner
                    .rules
                    .get(&runtime.spec.id)
                    .and_then(|old| old.prewarm.as_ref())
                    .is_some_and(|old| Arc::ptr_eq(old, prewarm))
            {
                start_prewarm(runtime.clone(), self.tasks.clone());
            }
        }
        let removed: Vec<_> = inner
            .listeners
            .keys()
            .filter(|key| !wanted.contains_key(key))
            .copied()
            .collect();
        for key in removed {
            if let Some(listener) = inner.listeners.remove(&key) {
                listener.stop.cancel();
                listener.task.await.context("listener task failed")?;
            }
        }
        for (key, runtime) in wanted {
            if let Some(existing) = inner.listeners.get(&key) {
                existing.update.send_replace(runtime);
                continue;
            }
            let socket = staged.remove(&key).expect("every new listener staged");
            inner
                .listeners
                .insert(key, self.start_listener(runtime, socket));
        }
        let mut health_runtimes: Vec<_> = rules
            .values()
            .filter(|r| r.health.is_some())
            .cloned()
            .collect();
        health_runtimes.sort_by(|a, b| a.spec.id.cmp(&b.spec.id));
        *self.health_runtimes.lock().unwrap() = health_runtimes;
        inner.rules = rules;
        inner.resolvers = resolvers;
        inner.config = Some(config);
        // Old runtimes are gone now; keep only replay state still in use.
        salts.retain(|_, cache| Arc::strong_count(cache) > 1);
        inner.shadowsocks_salts = salts;
        Ok(())
    }

    fn start_listener(&self, runtime: Arc<RuntimeRule>, socket: StagedSocket) -> ListenerHandle {
        let (update, receiver) = watch::channel(runtime.clone());
        let stop = CancellationToken::new();
        let task = match socket {
            StagedSocket::Tcp(socket) => tokio::spawn(tcp_listener(
                socket,
                receiver,
                stop.clone(),
                self.meter.clone(),
                self.stats.clone(),
                self.tasks.clone(),
            )),
            StagedSocket::Udp(socket) => tokio::spawn(udp_listener(
                socket,
                receiver,
                stop.clone(),
                self.meter.clone(),
                self.stats.clone(),
                self.tasks.clone(),
            )),
        };
        ListenerHandle {
            rule_id: runtime.spec.id.clone(),
            update,
            stop,
            task,
        }
    }

    /// Restores listeners closed for a handover that did not complete.
    fn reopen(&self, inner: &mut EngineInner, released: Vec<(ListenerKey, Arc<RuntimeRule>)>) {
        for (key, runtime) in released {
            match StagedSocket::bind(key) {
                Ok(socket) => {
                    inner
                        .listeners
                        .insert(key, self.start_listener(runtime, socket));
                }
                Err(error) => {
                    tracing::error!(%error, "previous listener could not be reopened")
                }
            }
        }
    }

    pub async fn shutdown(&self) -> Result<()> {
        let mut inner = self.inner.lock().await;
        inner.stopped = true;
        for runtime in inner.rules.values() {
            runtime.cancel.cancel();
            if let Some(health) = &runtime.health {
                health.cancel();
            }
            if let Some(prewarm) = &runtime.prewarm {
                prewarm.stop.cancel();
            }
        }
        for listener in inner.listeners.values() {
            listener.stop.cancel();
        }
        for (_, listener) in inner.listeners.drain() {
            let _ = listener.task.await;
        }
        self.tasks.close();
        self.tasks.wait().await;
        self.health_runtimes.lock().unwrap().clear();
        self.meter.barrier().await?;
        Ok(())
    }
}

fn security_policy_changed(old: &Rule, new: &Rule) -> bool {
    old.inbound_multipath != new.inbound_multipath
        || old.outbound_multipath != new.outbound_multipath
        || old.budget_ids != new.budget_ids
        || ((crate::topology::participates(old) || crate::topology::participates(new))
            && crate::topology::route_signature(old) != crate::topology::route_signature(new))
        || old.inbound_websocket != new.inbound_websocket
        || old.targets.iter().any(|previous| {
            new.targets.iter().any(|current| {
                current.address == previous.address && current.websocket != previous.websocket
            })
        })
        || old
            .targets
            .iter()
            .filter_map(|t| t.websocket.as_ref())
            .collect::<Vec<_>>()
            != new
                .targets
                .iter()
                .filter_map(|t| t.websocket.as_ref())
                .collect::<Vec<_>>()
        || old.inbound_proxy != new.inbound_proxy
        || old.inbound_shadowsocks != new.inbound_shadowsocks
        || old.inbound_socks5 != new.inbound_socks5
        || old.inbound_http_connect != new.inbound_http_connect
        || old.allow_destinations != new.allow_destinations
        || old.deny_destinations != new.deny_destinations
        || old.targets.iter().any(|previous| {
            new.targets.iter().any(|current| {
                current.address == previous.address
                    && current.proxy_protocol != previous.proxy_protocol
            })
        })
        || old
            .targets
            .iter()
            .filter_map(|t| t.proxy_protocol.as_ref())
            .collect::<Vec<_>>()
            != new
                .targets
                .iter()
                .filter_map(|t| t.proxy_protocol.as_ref())
                .collect::<Vec<_>>()
        || old.outbound_bind != new.outbound_bind
        || old.dns_cache != new.dns_cache
        || old.port_mapping != new.port_mapping
        || old.inbound_tls != new.inbound_tls
        || old
            .targets
            .iter()
            .filter_map(|t| t.tls.as_ref())
            .collect::<Vec<_>>()
            != new
                .targets
                .iter()
                .filter_map(|t| t.tls.as_ref())
                .collect::<Vec<_>>()
        || old.meter_epoch != new.meter_epoch
        || old.protocol != new.protocol
        || old.allow_sources != new.allow_sources
        || old.deny_sources != new.deny_sources
        || old.expires_at_ms != new.expires_at_ms
        || old.quota_bytes != new.quota_bytes
        || old.rate_bytes_per_sec != new.rate_bytes_per_sec
        || old.idle_timeout_secs != new.idle_timeout_secs
}

async fn tcp_listener(
    listener: TcpListener,
    updates: watch::Receiver<Arc<RuntimeRule>>,
    stop: CancellationToken,
    meter: Meter,
    stats: Arc<Counters>,
    tasks: TaskTracker,
) {
    let inlet = ListenerKey {
        address: listener.local_addr().expect("bound TCP listener"),
        tcp: true,
    };
    loop {
        let accepted =
            tokio::select! {biased;_=stop.cancelled()=>break,result=listener.accept()=>result};
        let (stream, peer) = match accepted {
            Ok(pair) => pair,
            Err(error) => {
                tracing::warn!(%error,"TCP accept failed");
                sleep(Duration::from_millis(100)).await;
                continue;
            }
        };
        let rule = updates.borrow().clone();
        if !rule.accepts_transport(peer) {
            stats.rejected_connections.fetch_add(1, Ordering::Relaxed);
            continue;
        }
        let Some(guard) = CountGuard::acquire(
            rule.shared.tcp.clone(),
            rule.spec.max_connections as usize,
            stats.clone(),
            true,
        ) else {
            stats.rejected_connections.fetch_add(1, Ordering::Relaxed);
            continue;
        };
        stats.accepted_tcp.fetch_add(1, Ordering::Relaxed);
        let meter = meter.clone();
        let stats = stats.clone();
        let session_tasks = tasks.clone();
        tasks.spawn(async move {
            let outcome=tokio::select!{biased;_=rule.cancel.cancelled()=>Ok(()),result=tcp_session(stream,inlet,rule.clone(),meter,stats.clone(),guard,session_tasks)=>result};
            if let Err(error)=outcome {stats.failed_connections.fetch_add(1,Ordering::Relaxed);tracing::debug!(rule_id=%rule.spec.id,%error,"TCP session ended");}
        });
    }
}

/// A target connection opened up to the point where its PROXY header is
/// written: plain TCP when the header precedes TLS, otherwise after TLS.
struct Dialed {
    stream: DialedStream,
    local: SocketAddr,
    address: SocketAddr,
    route: LoopGuard,
    opened: Instant,
}
enum DialedStream {
    Tcp(TcpStream),
    Ready(BoxStream),
}
impl Dialed {
    /// True while the peer has neither closed nor sent anything; a relay
    /// waiting for the PROXY header sends nothing first.
    fn idle_and_open(&mut self) -> bool {
        let mut byte = [0u8; 1];
        match &mut self.stream {
            DialedStream::Tcp(stream) => matches!(
                stream.try_read(&mut byte),
                Err(error) if error.kind() == io::ErrorKind::WouldBlock
            ),
            DialedStream::Ready(stream) => stream.read(&mut byte).now_or_never().is_none(),
        }
    }
}

async fn dial_target(
    rule: &RuntimeRule,
    index: usize,
    address: SocketAddr,
    inlet: ListenerKey,
) -> Result<Dialed> {
    let route = rule.routes.reserve(inlet, address)?;
    let bind = rule
        .spec
        .outbound_multipath
        .as_ref()
        .and_then(|spec| spec.paths[index].outbound_bind.as_ref())
        .or(rule.spec.outbound_bind.as_ref());
    let stream = network::connect_tcp(bind, address).await?;
    stream.set_nodelay(true)?;
    let local = stream.local_addr()?;
    let header_first = rule.spec.targets[index]
        .proxy_protocol
        .as_ref()
        .is_some_and(|p| p.placement == ProxyPlacement::BeforeTls);
    let stream = if header_first {
        DialedStream::Tcp(stream)
    } else {
        DialedStream::Ready(rule.tls.connect(index, stream).await?)
    };
    Ok(Dialed {
        stream,
        local,
        address,
        route,
        opened: Instant::now(),
    })
}

/// Writes the PROXY header and completes TLS and WebSocket setup.
async fn activate_target(
    rule: &RuntimeRule,
    index: usize,
    dialed: Dialed,
    info: Option<ConnectionInfo>,
) -> Result<(BoxStream, LoopGuard)> {
    let info = info.unwrap_or(ConnectionInfo {
        source: dialed.local,
        destination: dialed.address,
    });
    let policy = rule.spec.targets[index].proxy_protocol.as_ref();
    let mut stream = match dialed.stream {
        DialedStream::Tcp(mut stream) => {
            if let Some(policy) = policy {
                stream
                    .write_all(&proxy::encode(policy, true, info)?)
                    .await?;
            }
            rule.tls.connect(index, stream).await?
        }
        DialedStream::Ready(mut stream) => {
            if let Some(policy) = policy {
                stream
                    .write_all(&proxy::encode(policy, true, info)?)
                    .await?;
                stream.flush().await?;
            }
            stream
        }
    };
    if let Some(spec) = &rule.spec.targets[index].websocket {
        stream = websocket::connect(
            stream,
            spec,
            rule.spec.targets[index].tls.is_some(),
            Duration::from_millis(rule.spec.connect_timeout_ms),
        )
        .await?;
    }
    Ok((stream, dialed.route))
}

async fn open_tcp_target(
    rule: &RuntimeRule,
    index: usize,
    address: SocketAddr,
    inlet: ListenerKey,
    info: Option<ConnectionInfo>,
) -> Result<(BoxStream, LoopGuard)> {
    let dialed = dial_target(rule, index, address, inlet).await?;
    activate_target(rule, index, dialed, info).await
}

/// Per target, connections opened before clients need them. A rule's set is
/// replaced, and its connections closed, whenever the rule itself changes.
struct PrewarmSet {
    stop: CancellationToken,
    targets: Vec<Option<Prewarm>>,
}
struct Prewarm {
    size: usize,
    ready: StdMutex<VecDeque<Dialed>>,
    taken: tokio::sync::Notify,
}
impl PrewarmSet {
    fn new(spec: &Rule) -> Option<Arc<Self>> {
        let targets: Vec<_> = spec
            .targets
            .iter()
            .map(|target| {
                target
                    .prewarm
                    .filter(|_| !target.draining)
                    .map(|size| Prewarm {
                        size: usize::from(size),
                        ready: StdMutex::default(),
                        taken: Default::default(),
                    })
            })
            .collect();
        targets.iter().any(Option::is_some).then(|| {
            Arc::new(Self {
                stop: CancellationToken::new(),
                targets,
            })
        })
    }
}
impl Prewarm {
    fn take(&self) -> Option<Dialed> {
        let max_age = Duration::from_millis(PREWARM_MAX_AGE_MS);
        let found = {
            let mut ready = self.ready.lock().unwrap();
            std::iter::from_fn(|| ready.pop_front())
                .find_map(|mut d| (d.opened.elapsed() < max_age && d.idle_and_open()).then_some(d))
        };
        self.taken.notify_one();
        found
    }
}
fn start_prewarm(rule: Arc<RuntimeRule>, tasks: TaskTracker) {
    let Some(set) = rule.prewarm.clone() else {
        return;
    };
    for index in 0..set.targets.len() {
        if set.targets[index].is_some() {
            tasks.spawn(fill_prewarm(rule.clone(), set.clone(), index));
        }
    }
}
async fn fill_prewarm(rule: Arc<RuntimeRule>, set: Arc<PrewarmSet>, index: usize) {
    let pool = set.targets[index].as_ref().expect("pool exists");
    let max_age = Duration::from_millis(PREWARM_MAX_AGE_MS);
    let inlet = ListenerKey {
        address: rule.spec.listen,
        tcp: true,
    };
    let mut backoff = Duration::from_millis(500);
    loop {
        let full_until = {
            let mut ready = pool.ready.lock().unwrap();
            ready.retain(|d| d.opened.elapsed() < max_age);
            (ready.len() >= pool.size).then(|| ready.front().expect("full pool").opened + max_age)
        };
        if let Some(expiry) = full_until {
            tokio::select! {
                biased;
                _ = set.stop.cancelled() => return,
                _ = pool.taken.notified() => {}
                _ = sleep_until(expiry) => {}
            }
            continue;
        }
        let dial = async {
            let target = rule.spec.target_address(index, rule.spec.listen.port())?;
            let mut last = None;
            for address in rule.resolver.resolve(&target).await? {
                match dial_target(&rule, index, address, inlet).await {
                    Ok(dialed) => return Ok(dialed),
                    Err(error) => last = Some(error),
                }
            }
            Err(last.unwrap_or_else(|| anyhow::anyhow!("target has no addresses")))
        };
        let deadline = Instant::now() + Duration::from_millis(rule.spec.connect_timeout_ms);
        let dialed = tokio::select! {
            biased;
            _ = set.stop.cancelled() => return,
            dialed = timeout_at(deadline, dial) => dialed,
        };
        if let Ok(Ok(dialed)) = dialed {
            pool.ready.lock().unwrap().push_back(dialed);
            backoff = Duration::from_millis(500);
        } else {
            tokio::select! {
                biased;
                _ = set.stop.cancelled() => return,
                _ = sleep(backoff) => {}
            }
            backoff = (backoff * 2).min(Duration::from_secs(30));
        }
    }
}

/// How long a target may take before the next candidate is dialed alongside
/// it: four probe round trips but at least 250 ms, or 1 s when unmeasured.
fn hedge_delay(rule: &RuntimeRule, index: usize, inlet: ListenerKey) -> Duration {
    rule.health
        .as_ref()
        .and_then(|health| {
            health
                .point(index, inlet.address.port(), inlet.tcp)
                .selection_latency_us()
        })
        .map_or(Duration::from_secs(1), |us| {
            Duration::from_micros(us * 4).max(Duration::from_millis(250))
        })
}

/// Dials one target: a pre-warmed connection first, then a fresh one.
async fn try_target(
    rule: &RuntimeRule,
    index: usize,
    info: ConnectionInfo,
    inlet: ListenerKey,
    stats: &Counters,
    deadline: Instant,
) -> Result<(BoxStream, LoopGuard), String> {
    let mut last = None;
    let target = rule
        .spec
        .target_address(index, inlet.address.port())
        .map_err(|error| error.to_string())?;
    let addresses = match timeout_at(deadline, rule.resolver.resolve(&target)).await {
        Ok(Ok(addresses)) => addresses,
        Ok(Err(error)) => return Err(error.to_string()),
        Err(_) => return Err("target resolution timed out".into()),
    };
    if !rule.destination.permits(
        destination_acl::host_from_endpoint(&target),
        addresses.iter().map(SocketAddr::ip),
    ) {
        return Err(format!("destination denied by rule policy: {target}"));
    }
    if let Some(dialed) = rule
        .prewarm
        .as_ref()
        .and_then(|set| set.targets[index].as_ref())
        .and_then(Prewarm::take)
    {
        // A pre-warmed connection that fails to activate falls back to a fresh dial.
        if !rule
            .destination
            .permits(&dialed.address.ip().to_string(), [dialed.address.ip()])
        {
            last = Some("pre-warmed destination denied by rule policy".into());
        } else {
            match timeout_at(deadline, activate_target(rule, index, dialed, Some(info))).await {
                Ok(Ok(dialed)) => {
                    stats.prewarmed_connections.fetch_add(1, Ordering::Relaxed);
                    return Ok(dialed);
                }
                Ok(Err(error)) => last = Some(error.to_string()),
                Err(_) => last = Some("pre-warmed connection timed out".into()),
            }
        }
    }
    for address in addresses {
        match timeout_at(
            deadline,
            open_tcp_target(rule, index, address, inlet, Some(info)),
        )
        .await
        {
            Ok(Ok(dialed)) => return Ok(dialed),
            Ok(Err(error)) => last = Some(error.to_string()),
            Err(_) => return Err("target connection timed out".into()),
        }
    }
    Err(last.unwrap_or_default())
}

/// Dials targets in order. A target that has not connected within its hedge
/// delay, or by its share of the connect timeout, keeps running while the
/// next one is dialed too, and the first connection wins. Networks that lose
/// a SYN-ACK now cost a fraction of a second instead of half the timeout.
async fn connect_tcp(
    rule: &RuntimeRule,
    info: ConnectionInfo,
    inlet: ListenerKey,
    stats: &Counters,
) -> Result<(BoxStream, TargetGuard, LoopGuard)> {
    let deadline = Instant::now() + Duration::from_millis(rule.spec.connect_timeout_ms);
    let order = rule.order(info.source, inlet);
    let mut pending = order.iter().copied().enumerate();
    let mut running = FuturesUnordered::new();
    let mut in_flight = vec![];
    let mut next_at = Some(Instant::now());
    let mut last = None;
    loop {
        if next_at.is_some_and(|at| Instant::now() >= at) {
            next_at = None;
            let now = Instant::now();
            for (position, index) in pending.by_ref() {
                if now >= deadline {
                    break;
                }
                let Some(guard) = rule.target_guard(index) else {
                    continue;
                };
                let share = now + (deadline - now) / (order.len() - position) as u32;
                next_at = Some((now + hedge_delay(rule, index, inlet)).min(share));
                in_flight.push(index);
                running.push(
                    try_target(rule, index, info, inlet, stats, deadline)
                        .map(move |result| (index, guard, result)),
                );
                break;
            }
            if running.is_empty() {
                break;
            }
        }
        let hedge = async {
            match next_at {
                Some(at) => sleep_until(at).await,
                None => std::future::pending().await,
            }
        };
        tokio::select! {
            Some((index, guard, result)) = running.next() => {
                in_flight.retain(|&other| other != index);
                match result {
                    Ok((stream, route)) => {
                        // Without health probes, a target that lost the race
                        // gets no other verdict, so it waits like a failure.
                        if rule.health.is_none() {
                            for &slow in &in_flight {
                                rule.cool(slow);
                            }
                        }
                        return Ok((stream, guard, route));
                    }
                    Err(error) => {
                        last = Some(error);
                        rule.cool(index);
                        next_at = Some(Instant::now());
                    }
                }
            }
            _ = hedge => {}
        }
    }
    bail!("all targets failed: {}", last.unwrap_or_default())
}

async fn resolve_destination(rule: &RuntimeRule, endpoint: &str) -> Result<Vec<SocketAddr>> {
    let addresses = rule.resolver.resolve(endpoint).await?;
    if !rule.destination.permits(
        destination_acl::host_from_endpoint(endpoint),
        addresses.iter().map(SocketAddr::ip),
    ) {
        bail!("destination denied by rule policy: {endpoint}");
    }
    Ok(addresses)
}

/// Connects a Shadowsocks client to the destination it named.
async fn connect_destination(
    rule: &RuntimeRule,
    server: &shadowsocks::Server,
    destination: &shadowsocks::Destination,
    inlet: ListenerKey,
) -> Result<BoxStream> {
    let deadline = Instant::now() + Duration::from_millis(rule.spec.connect_timeout_ms);
    timeout_at(deadline, async {
        let mut last = None;
        for address in resolve_destination(rule, &destination.to_string()).await? {
            if !server.permits(address.ip()) {
                last = Some(anyhow::anyhow!("{destination} is not a public address"));
                continue;
            }
            let route = rule.routes.reserve(inlet, address)?;
            match network::connect_tcp(rule.spec.outbound_bind.as_ref(), address).await {
                Ok(stream) => {
                    stream.set_nodelay(true)?;
                    return Ok(transport::hold(Box::new(stream), route));
                }
                Err(error) => last = Some(error),
            }
        }
        Err(last.unwrap_or_else(|| anyhow::anyhow!("{destination} has no addresses")))
    })
    .await
    .context("destination connection timed out")?
}

async fn connect_http_connect_destination(
    rule: &RuntimeRule,
    server: &http_connect::Server,
    destination: &shadowsocks::Destination,
    inlet: ListenerKey,
) -> Result<BoxStream> {
    let deadline = Instant::now() + Duration::from_millis(rule.spec.connect_timeout_ms);
    timeout_at(deadline, async {
        let mut last = None;
        for address in resolve_destination(rule, &destination.to_string()).await? {
            if !server.permits(address.ip()) {
                last = Some(anyhow::anyhow!("{destination} is not a public address"));
                continue;
            }
            let route = rule.routes.reserve(inlet, address)?;
            match network::connect_tcp(rule.spec.outbound_bind.as_ref(), address).await {
                Ok(stream) => {
                    stream.set_nodelay(true)?;
                    return Ok(transport::hold(Box::new(stream), route));
                }
                Err(error) => last = Some(error),
            }
        }
        Err(last.unwrap_or_else(|| anyhow::anyhow!("{destination} has no addresses")))
    })
    .await
    .context("HTTP CONNECT destination connection timed out")?
}

async fn socks5_udp_association(
    rule: Arc<RuntimeRule>,
    mut incoming: tokio::sync::mpsc::UnboundedReceiver<socks5::UdpDatagram>,
    reply: tokio::sync::mpsc::UnboundedSender<(SocketAddr, Vec<u8>)>,
    inlet: ListenerKey,
    stats: Arc<Counters>,
) {
    loop {
        let datagram = tokio::select! {
            biased;
            _ = rule.cancel.cancelled() => break,
            datagram = incoming.recv() => match datagram {
                Some(datagram) => datagram,
                None => break,
            },
        };
        let rule = rule.clone();
        let reply = reply.clone();
        let stats = stats.clone();
        tokio::spawn(async move {
            let Some(server) = &rule.socks5 else {
                return;
            };
            let endpoint = datagram.destination.to_string();
            let addresses = match resolve_destination(&rule, &endpoint).await {
                Ok(addresses) => addresses,
                Err(error) => {
                    stats.dropped_datagrams.fetch_add(1, Ordering::Relaxed);
                    tracing::debug!(%error, rule = %rule.spec.id, "SOCKS5 UDP destination rejected");
                    return;
                }
            };
            let mut last = None;
            for address in addresses {
                if !server.permits(address.ip()) {
                    last = Some("destination is not public");
                    continue;
                }
                let socket = match network::outbound_udp(
                    rule.spec.outbound_bind.as_ref(),
                    address.is_ipv4(),
                ) {
                    Ok(socket) => socket,
                    Err(error) => {
                        last = Some("outbound socket");
                        tracing::debug!(%error, "SOCKS5 UDP socket failed");
                        continue;
                    }
                };
                let route = match rule.routes.reserve(inlet, address) {
                    Ok(route) => route,
                    Err(error) => {
                        last = Some("route rejected");
                        tracing::debug!(%error, "SOCKS5 UDP route rejected");
                        continue;
                    }
                };
                if let Err(error) = socket.connect(address).await {
                    last = Some("connect failed");
                    tracing::debug!(%error, "SOCKS5 UDP connect failed");
                    continue;
                }
                if let Err(error) = socket.send(&datagram.payload).await {
                    last = Some("send failed");
                    tracing::debug!(%error, "SOCKS5 UDP send failed");
                    continue;
                }
                let mut buffer = vec![0u8; 65_535];
                match tokio::time::timeout(Duration::from_secs(2), socket.recv_from(&mut buffer))
                    .await
                {
                    Ok(Ok((size, source))) => {
                        let packet = socks5::encode_udp_datagram(
                            &shadowsocks::Destination::Ip(source),
                            &buffer[..size],
                        );
                        let _ = reply.send((datagram.client, packet));
                        return;
                    }
                    Ok(Err(error)) => {
                        last = Some("receive failed");
                        tracing::debug!(%error, "SOCKS5 UDP receive failed");
                    }
                    Err(_) => last = Some("receive timed out"),
                }
                drop(route);
            }
            if last.is_some() {
                stats.dropped_datagrams.fetch_add(1, Ordering::Relaxed);
            }
        });
    }
}

async fn connect_socks5_destination(
    rule: &RuntimeRule,
    server: &socks5::Server,
    destination: &shadowsocks::Destination,
    inlet: ListenerKey,
) -> Result<BoxStream> {
    let deadline = Instant::now() + Duration::from_millis(rule.spec.connect_timeout_ms);
    timeout_at(deadline, async {
        let mut last = None;
        for address in resolve_destination(rule, &destination.to_string()).await? {
            if !server.permits(address.ip()) {
                last = Some(anyhow::anyhow!("{destination} is not a public address"));
                continue;
            }
            let route = rule.routes.reserve(inlet, address)?;
            match network::connect_tcp(rule.spec.outbound_bind.as_ref(), address).await {
                Ok(stream) => {
                    stream.set_nodelay(true)?;
                    return Ok(transport::hold(Box::new(stream), route));
                }
                Err(error) => last = Some(error),
            }
        }
        Err(last.unwrap_or_else(|| anyhow::anyhow!("{destination} has no addresses")))
    })
    .await
    .context("SOCKS5 destination connection timed out")?
}

async fn open_multipath_path(
    rule: &RuntimeRule,
    index: usize,
    info: ConnectionInfo,
    inlet: ListenerKey,
) -> Result<multipath::Path> {
    let target_guard = rule
        .target_guard(index)
        .context("multipath target capacity reached")?;
    let target = rule.spec.target_address(index, inlet.address.port())?;
    let addresses = resolve_destination(rule, &target).await?;
    let mut last = None;
    for address in addresses {
        match open_tcp_target(rule, index, address, inlet, Some(info)).await {
            Ok((stream, route)) => {
                let path = &rule.spec.outbound_multipath.as_ref().unwrap().paths[index];
                return Ok(multipath::Path {
                    stream: transport::hold(stream, (target_guard, route)),
                    slot: index,
                    send_weight: path.upload_weight,
                    receive_weight: path.download_weight,
                });
            }
            Err(error) => last = Some(error.to_string()),
        }
    }
    bail!("multipath path failed: {}", last.unwrap_or_default())
}

async fn connect_multipath(
    rule: &RuntimeRule,
    info: ConnectionInfo,
    inlet: ListenerKey,
    stats: Arc<multipath::Counters>,
    tasks: TaskTracker,
) -> Result<BoxStream> {
    let spec = rule.spec.outbound_multipath.as_ref().unwrap();
    let permit = rule
        .multipath_client
        .as_ref()
        .unwrap()
        .clone()
        .try_acquire_owned()
        .context("multipath client session limit reached")?;
    let deadline = Instant::now() + Duration::from_millis(rule.spec.connect_timeout_ms);
    // Leave 20% of the common setup budget for the start barrier if a candidate stalls.
    let path_deadline = deadline - Duration::from_millis(rule.spec.connect_timeout_ms / 5);
    timeout_at(deadline, async {
        let mut opens: FuturesUnordered<_> = rule
            .order(info.source, inlet)
            .into_iter()
            .map(|index| timeout_at(path_deadline, open_multipath_path(rule, index, info, inlet)))
            .collect();
        let first = loop {
            match opens.next().await.context("no multipath path connected")? {
                Ok(Ok(path)) => break path,
                Ok(Err(_)) | Err(_) => continue,
            }
        };
        // CREATE is attempted once. An ambiguous result must not open another backend.
        let (session, first) = timeout_at(path_deadline, multipath::Client::create(first, spec))
            .await
            .context("multipath create timed out")??;
        let mut paths = vec![first];
        {
            let mut joins = FuturesUnordered::new();
            while !opens.is_empty() || !joins.is_empty() {
                tokio::select! {
                    opened = opens.next(), if !opens.is_empty() => {
                        if let Some(Ok(Ok(path))) = opened {
                            joins.push(timeout_at(path_deadline, session.join(path)));
                        }
                    }
                    joined = joins.next(), if !joins.is_empty() => {
                        if let Some(Ok(Ok(path))) = joined { paths.push(path); }
                    }
                }
            }
        }
        session.finish(paths, stats, tasks, Box::new(permit)).await
    })
    .await
    .context("multipath outbound setup timed out")?
}

async fn tcp_session(
    mut client: TcpStream,
    inlet: ListenerKey,
    rule: Arc<RuntimeRule>,
    meter: Meter,
    stats: Arc<Counters>,
    guard: CountGuard,
    tasks: TaskTracker,
) -> Result<()> {
    client.set_nodelay(true)?;
    let peer = client.peer_addr()?;
    let original = ConnectionInfo {
        source: peer,
        destination: client.local_addr()?,
    };
    let setup = Duration::from_millis(rule.spec.connect_timeout_ms);
    let mut handshake_deadline = Instant::now() + setup;
    let policy = rule.spec.inbound_proxy.as_ref();
    // A pre-warmed connection idles until the upstream has a client for it;
    // the remaining setup then gets the usual connect timeout.
    let prewarmed = policy.is_some_and(|p| p.accept_prewarmed);
    let header_deadline = if prewarmed {
        Instant::now() + Duration::from_millis(PREWARM_WAIT_MS)
    } else {
        handshake_deadline
    };
    let mut info = original;
    if let Some(policy) = policy.filter(|p| p.placement == ProxyPlacement::BeforeTls) {
        info = timeout_at(
            header_deadline,
            proxy::read_tcp(&mut client, policy, original),
        )
        .await
        .context("inbound PROXY header timed out")??;
        if prewarmed {
            handshake_deadline = Instant::now() + setup;
        }
    }
    let (mut client, certificate) =
        timeout_at(handshake_deadline, rule.tls.accept_authenticated(client))
            .await
            .context("inbound TLS handshake timed out")??;
    if let Some(policy) = policy.filter(|p| p.placement == ProxyPlacement::InsideTls) {
        info = timeout_at(
            header_deadline,
            proxy::read_tcp(&mut client, policy, original),
        )
        .await
        .context("inbound PROXY header timed out")??;
        if prewarmed {
            handshake_deadline = Instant::now() + setup;
        }
    }
    if !rule.accepts(info.source) {
        stats.rejected_connections.fetch_add(1, Ordering::Relaxed);
        return Ok(());
    }
    let client = if let Some(spec) = &rule.spec.inbound_websocket {
        timeout_at(
            handshake_deadline,
            websocket::accept(
                client,
                spec,
                Duration::from_millis(rule.spec.connect_timeout_ms),
            ),
        )
        .await
        .context("inbound WebSocket handshake timed out")??
    } else {
        client
    };
    let client = transport::hold(client, guard);
    let mut client = if let Some(server) = &rule.multipath_server {
        let identity =
            certificate.context("multipath requires a verified TLS client certificate")?;
        let accepted = timeout_at(
            handshake_deadline,
            server.accept(
                client,
                identity,
                rule.spec.inbound_proxy.as_ref().map(|_| info),
                stats.multipath.clone(),
                tasks.clone(),
            ),
        )
        .await
        .context("multipath inbound setup timed out")??;
        let Some(client) = accepted else {
            return Ok(());
        };
        client
    } else {
        client
    };
    let (client, target) = if let Some(server) = &rule.http_connect {
        let destination = match server.accept(&mut client, handshake_deadline).await {
            Ok(destination) => destination,
            Err(error) => {
                stats.rejected_connections.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(%error, rule = %rule.spec.id, "HTTP CONNECT request rejected");
                return Ok(());
            }
        };
        let target =
            match connect_http_connect_destination(&rule, server, &destination, inlet).await {
                Ok(target) => {
                    http_connect::ok(&mut client).await?;
                    target
                }
                Err(error) => {
                    let _ = http_connect::reply(&mut client, 502, "Bad Gateway").await;
                    return Err(error);
                }
            };
        (client, target)
    } else if let Some(server) = &rule.socks5 {
        let request = match server.accept(&mut client, handshake_deadline).await {
            Ok(request) => request,
            Err(error) => {
                stats.rejected_connections.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(%error, rule = %rule.spec.id, "SOCKS5 request rejected");
                return Ok(());
            }
        };
        let destination = match request {
            socks5::Request::Connect(destination) => destination,
            socks5::Request::UdpAssociate => {
                let Some(registry) = &rule.socks5_udp else {
                    let _ = socks5::reply(&mut client, 7).await;
                    return Ok(());
                };
                if rule.spec.protocol != Protocol::Both {
                    let _ = socks5::reply(&mut client, 7).await;
                    return Ok(());
                }
                let mut reply = registry.reply_sender();
                for _ in 0..20 {
                    if reply.is_some() {
                        break;
                    }
                    tokio::time::sleep(Duration::from_millis(10)).await;
                    reply = registry.reply_sender();
                }
                let Some(reply) = reply else {
                    let _ = socks5::reply(&mut client, 7).await;
                    return Ok(());
                };
                let relay = SocketAddr::new(info.destination.ip(), rule.spec.listen.port());
                let (association, receiver) = registry.register(peer.ip());
                if let Err(error) = socks5::udp_bind_reply(&mut client, relay).await {
                    registry.unregister(peer.ip(), association);
                    return Err(error);
                }
                tasks.spawn(socks5_udp_association(
                    rule.clone(),
                    receiver,
                    reply,
                    inlet,
                    stats.clone(),
                ));
                let mut control = client;
                let mut discard = [0u8; 512];
                loop {
                    tokio::select! {
                        biased;
                        _ = rule.cancel.cancelled() => break,
                        read = control.read(&mut discard) => match read {
                            Ok(0) | Err(_) => break,
                            Ok(_) => {}
                        }
                    }
                }
                registry.unregister(peer.ip(), association);
                return Ok(());
            }
        };
        let target = match connect_socks5_destination(&rule, server, &destination, inlet).await {
            Ok(target) => {
                socks5::reply(&mut client, 0).await?;
                target
            }
            Err(error) => {
                let _ = socks5::reply(&mut client, 5).await;
                return Err(error);
            }
        };
        (client, target)
    } else if let Some(server) = &rule.shadowsocks {
        let (destination, session) = match server.accept(client, handshake_deadline).await {
            Ok(accepted) => accepted,
            Err(error) => {
                stats.rejected_connections.fetch_add(1, Ordering::Relaxed);
                tracing::debug!(%error, rule = %rule.spec.id, "Shadowsocks request rejected");
                return Ok(());
            }
        };
        let target = connect_destination(&rule, server, &destination, inlet).await?;
        (Box::new(session) as BoxStream, target)
    } else if rule.spec.outbound_multipath.is_some() {
        let target = connect_multipath(&rule, info, inlet, stats.multipath.clone(), tasks).await?;
        (client, target)
    } else {
        let (target, target_guard, route_guard) = connect_tcp(&rule, info, inlet, &stats).await?;
        (client, transport::hold(target, (target_guard, route_guard)))
    };
    let activity = Arc::new(StdMutex::new(Instant::now()));
    let (cr, cw) = tokio::io::split(client);
    let (tr, tw) = tokio::io::split(target);
    let forward = async {
        tokio::try_join!(
            copy_direction(cr, tw, &rule, &meter, &stats, &activity, true),
            copy_direction(tr, cw, &rule, &meter, &stats, &activity, false)
        )?;
        Ok(())
    };
    tokio::select! {result=forward=>result,_=watch_deadline(&rule.spec,activity.clone())=>Ok(())}
}

async fn watch_deadline(rule: &Rule, activity: Arc<StdMutex<Instant>>) {
    loop {
        let idle = *activity.lock().unwrap() + Duration::from_secs(rule.idle_timeout_secs);
        let expiry = rule
            .expires_at_ms
            .map(|e| Instant::now() + Duration::from_millis((e - now_ms()).max(0) as u64));
        sleep_until(expiry.map(|e| e.min(idle)).unwrap_or(idle)).await;
        if activity.lock().unwrap().elapsed() >= Duration::from_secs(rule.idle_timeout_secs)
            || rule.expires_at_ms.is_some_and(|e| e <= now_ms())
        {
            return;
        }
    }
}

async fn copy_direction<R: AsyncRead + Unpin, W: AsyncWrite + Unpin>(
    mut reader: R,
    mut writer: W,
    rule: &RuntimeRule,
    meter: &Meter,
    stats: &Counters,
    activity: &StdMutex<Instant>,
    upload: bool,
) -> Result<()> {
    let mut buffer = vec![0u8; MIN_STREAM_BUFFER];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        let filled = read == buffer.len();
        *activity.lock().unwrap() = Instant::now();
        rule.throttle(read).await;
        let mut offset = 0;
        while offset < read {
            let allowed = meter
                .admit(&rule.spec, upload, read - offset, false)
                .await?
                .unwrap_or(0);
            if allowed == 0 {
                bail!("quota exhausted, budget unavailable or rule inactive");
            }
            let end = offset + allowed;
            while offset < end {
                let n = writer.write(&buffer[offset..end]).await?;
                if n == 0 {
                    return Err(io::Error::from(io::ErrorKind::WriteZero).into());
                }
                offset += n;
                // Flush TLS before waiting for more application input or budget.
                writer.flush().await?;
                if upload {
                    stats
                        .forwarded_upload_bytes
                        .fetch_add(n as u64, Ordering::Relaxed);
                } else {
                    stats
                        .forwarded_download_bytes
                        .fetch_add(n as u64, Ordering::Relaxed);
                }
                *activity.lock().unwrap() = Instant::now();
            }
        }
        if filled && buffer.len() < BUFFER_SIZE {
            buffer = vec![0u8; (buffer.len() * 2).min(BUFFER_SIZE)];
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
struct UdpSessionKey {
    peer: SocketAddr,
    local: SocketAddr,
    info: ConnectionInfo,
}
struct UdpEntry {
    generation: u64,
    sender: Backlog<Vec<u8>>,
}
/// The listener's end of a session's datagram queue.
struct Backlog<T> {
    sender: mpsc::Sender<(Instant, usize, T)>,
    bytes: Arc<AtomicUsize>,
}
/// The session's end.
struct Queued<T> {
    receiver: mpsc::Receiver<(Instant, usize, T)>,
    bytes: Arc<AtomicUsize>,
}
fn backlog<T>() -> (Backlog<T>, Queued<T>) {
    let (sender, receiver) = mpsc::channel(UDP_QUEUE);
    let bytes = Arc::new(AtomicUsize::new(0));
    (
        Backlog {
            sender,
            bytes: bytes.clone(),
        },
        Queued { receiver, bytes },
    )
}
impl<T> Backlog<T> {
    /// Queues a datagram of `size` bytes; false when the queue is full or the
    /// session has ended.
    fn push(&self, size: usize, item: T) -> bool {
        if self.bytes.fetch_add(size, Ordering::Relaxed) + size <= UDP_QUEUE_BYTES
            && self.sender.try_send((Instant::now(), size, item)).is_ok()
        {
            return true;
        }
        self.bytes.fetch_sub(size, Ordering::Relaxed);
        false
    }
    fn is_closed(&self) -> bool {
        self.sender.is_closed()
    }
}
impl<T> Queued<T> {
    /// The next datagram that has not waited too long; older ones count as
    /// dropped. Safe to cancel: nothing is taken after the only await.
    async fn recv(&mut self, stats: &Counters) -> Option<T> {
        loop {
            let (queued, size, item) = self.receiver.recv().await?;
            self.bytes.fetch_sub(size, Ordering::Relaxed);
            if queued.elapsed() <= UDP_QUEUE_DELAY {
                return Some(item);
            }
            stats.dropped_datagrams.fetch_add(1, Ordering::Relaxed);
        }
    }
}
/// How a Shadowsocks association is found: the 2022 methods by client
/// session, which survives a change of client address; older ones by address.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
enum AssociationKey {
    Session(u64),
    Peer(UdpSessionKey),
}
struct Association {
    generation: u64,
    sender: Backlog<ClientDatagram>,
    window: shadowsocks::ReplayWindow,
}
/// A Shadowsocks client datagram: where it came from, so replies follow the
/// client's latest address, and where it goes.
struct ClientDatagram {
    from: UdpSessionKey,
    destination: shadowsocks::Destination,
    payload: Vec<u8>,
}
/// Replay windows of 2022 associations that ended, kept for
/// [`shadowsocks::ASSOCIATION_MEMORY`]: an association can end early (rule
/// change, quota), and a captured datagram must not open a fresh one while
/// its timestamp is still accepted.
#[derive(Default)]
struct EndedWindows {
    windows: HashMap<u64, (Instant, shadowsocks::ReplayWindow)>,
    order: VecDeque<(Instant, u64)>,
}
impl EndedWindows {
    fn keep(&mut self, session: u64, window: shadowsocks::ReplayWindow) {
        self.forget_old();
        let now = Instant::now();
        self.windows.insert(session, (now, window));
        self.order.push_back((now, session));
    }
    fn take(&mut self, session: u64) -> Option<shadowsocks::ReplayWindow> {
        self.forget_old();
        self.windows.remove(&session).map(|(_, window)| window)
    }
    fn forget_old(&mut self) {
        while let Some(&(at, session)) = self.order.front() {
            if at.elapsed() < shadowsocks::ASSOCIATION_MEMORY {
                break;
            }
            self.order.pop_front();
            if self
                .windows
                .get(&session)
                .is_some_and(|(kept, _)| *kept == at)
            {
                self.windows.remove(&session);
            }
        }
    }
}
/// An association keeps at most this many loop guards for its destinations;
/// datagrams to further destinations are still checked, not tracked.
const MAX_ROUTE_GUARDS: usize = 1024;
/// Names a Shadowsocks association sends to are looked up again after this.
const NAME_MEMORY: Duration = Duration::from_secs(60);
const MAX_NAMES: usize = 256;

async fn udp_listener(
    listener: UdpSocket,
    mut updates: watch::Receiver<Arc<RuntimeRule>>,
    stop: CancellationToken,
    meter: Meter,
    stats: Arc<Counters>,
    tasks: TaskTracker,
) {
    let bound = listener.local_addr().expect("bound UDP listener");
    let listener = Arc::new(listener);
    let (reply_tx, mut reply_rx) = tokio::sync::mpsc::unbounded_channel::<(SocketAddr, Vec<u8>)>();
    if let Some(registry) = &updates.borrow().socks5_udp {
        registry.set_reply(reply_tx.clone());
    }
    let mut sessions = HashMap::<UdpSessionKey, UdpEntry>::new();
    let (finished_tx, mut finished_rx) = mpsc::unbounded_channel::<(UdpSessionKey, u64)>();
    let mut associations = HashMap::<AssociationKey, Association>::new();
    let mut ended_windows = EndedWindows::default();
    let (ended_tx, mut ended_rx) = mpsc::unbounded_channel::<(AssociationKey, u64)>();
    let mut generation = 0u64;
    let mut buffer = vec![0u8; BUFFER_SIZE];
    loop {
        tokio::select! {
            biased;
            _=stop.cancelled()=>break,
            Some((peer,packet))=reply_rx.recv()=>{
                if let Err(error)=listener.send_to(&packet,peer).await {
                    tracing::debug!(%error,"SOCKS5 UDP reply send failed");
                }
            },
            Some((key,id))=finished_rx.recv()=>{if sessions.get(&key).is_some_and(|s|s.generation==id){sessions.remove(&key);}},
            Some((key,id))=ended_rx.recv()=>{
                if associations.get(&key).is_some_and(|a|a.generation==id) {
                    let ended=associations.remove(&key).unwrap();
                    if let AssociationKey::Session(session)=key {ended_windows.keep(session,ended.window);}
                }
            },
            changed=updates.changed()=>{
                if changed.is_err(){break;}
                if let Some(registry)=&updates.borrow().socks5_udp {registry.set_reply(reply_tx.clone());}
                sessions.retain(|_,entry|!entry.sender.is_closed());
            },
            received=datagram::receive(&listener,&mut buffer,bound)=>{
                let (size,peer,local)=match received {
                    Ok(packet)=>packet,
                    Err(error)=>{
                        if error.kind()==io::ErrorKind::InvalidData {stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);continue;}
                        tracing::warn!(%error,"UDP receive failed");sleep(Duration::from_millis(100)).await;continue;
                    }
                };
                let runtime=updates.borrow().clone();
                if !runtime.accepts_transport(peer){stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);continue;}
                if let Some(registry)=&runtime.socks5_udp {
                    registry.set_reply(reply_tx.clone());
                    if let Some(sender)=registry.sender(peer.ip()) {
                        match socks5::parse_udp_datagram(&buffer[..size]) {
                            Ok(mut datagram) => {
                                datagram.client = peer;
                                if !sender.send(datagram).is_ok() {
                                    stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);
                                }
                            }
                            Err(error) => {
                                stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);
                                tracing::debug!(rule_id=%runtime.spec.id,%error,"SOCKS5 UDP datagram rejected");
                            }
                        }
                        continue;
                    }
                }
                let original=ConnectionInfo{source:peer,destination:local};
                let (info,header_size)=if let Some(policy)=&runtime.spec.inbound_proxy {
                    match proxy::decode_v2(&buffer[..size],false,policy.max_header_bytes,original) {
                        Ok(decoded)=>decoded,
                        Err(error)=>{stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);tracing::debug!(rule_id=%runtime.spec.id,%error,"UDP PROXY rejected");continue;}
                    }
                } else {(original,0)};
                if !runtime.accepts(info.source){stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);continue;}
                let key=UdpSessionKey{peer,local,info};
                if let Some(server)=&runtime.shadowsocks {
                    let datagram=match server.open_datagram(&mut buffer[header_size..size],shadowsocks::unix_now()) {
                        Ok(datagram)=>datagram,
                        Err(error)=>{stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);tracing::debug!(rule_id=%runtime.spec.id,%error,"Shadowsocks datagram rejected");continue;}
                    };
                    let id=datagram.session.map_or(AssociationKey::Peer(key),AssociationKey::Session);
                    let message=ClientDatagram{from:key,destination:datagram.destination,payload:datagram.payload.to_vec()};
                    if let Some(association)=associations.get_mut(&id).filter(|a|!a.sender.is_closed()) {
                        // Only an authenticated datagram with a fresh timestamp moves the window.
                        if datagram.session.is_some()&&!association.window.accept(datagram.packet_id){stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);continue;}
                        if !association.sender.push(message.payload.len(),message){stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);}
                        continue;
                    }
                    // A session seen in the last minute keeps its packet IDs.
                    let mut window=match id {
                        AssociationKey::Session(session)=>associations.remove(&id).map(|a|a.window).or_else(||ended_windows.take(session)).unwrap_or_default(),
                        AssociationKey::Peer(_)=>shadowsocks::ReplayWindow::default(),
                    };
                    let fresh=datagram.session.is_none()||window.accept(datagram.packet_id);
                    let guard=if fresh {CountGuard::acquire(runtime.shared.udp.clone(),runtime.spec.udp_max_sessions as usize,stats.clone(),false)} else {None};
                    let Some(guard)=guard else{
                        if let AssociationKey::Session(session)=id {ended_windows.keep(session,window);}
                        stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);continue;
                    };
                    let (sender,receiver)=backlog();
                    sender.push(message.payload.len(),message);generation=generation.wrapping_add(1);let generation_id=generation;
                    associations.insert(id,Association{generation:generation_id,sender,window});
                    let replies=server.replies(datagram.session);
                    let socket=listener.clone();let meter=meter.clone();let stats=stats.clone();let ended=ended_tx.clone();let listener_stop=stop.clone();
                    tasks.spawn(async move {
                        let _guard=guard;
                        let outcome=tokio::select!{biased;_=runtime.cancel.cancelled()=>Ok(()),_=listener_stop.cancelled()=>Ok(()),result=shadowsocks_association(socket,receiver,replies,runtime.clone(),meter,stats.clone())=>result};
                        if let Err(error)=outcome{stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);tracing::debug!(rule_id=%runtime.spec.id,%error,"Shadowsocks association ended");}
                        let _=ended.send((id,generation_id));
                    });
                    continue;
                }
                if sessions.get(&key).is_some_and(|entry|entry.sender.is_closed()){sessions.remove(&key);}
                if let Some(session)=sessions.get(&key) {
                    if !session.sender.push(size-header_size,buffer[header_size..size].to_vec()){stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);}
                    continue;
                }
                let Some(guard)=CountGuard::acquire(runtime.shared.udp.clone(),runtime.spec.udp_max_sessions as usize,stats.clone(),false) else{stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);continue;};
                let (sender,receiver)=backlog();
                sender.push(size-header_size,buffer[header_size..size].to_vec());generation=generation.wrapping_add(1);let id=generation;
                sessions.insert(key,UdpEntry{generation:id,sender});
                let socket=listener.clone();let meter=meter.clone();let stats=stats.clone();let finished=finished_tx.clone();let listener_stop=stop.clone();
                tasks.spawn(async move {
                    let _guard=guard;
                    let outcome=tokio::select!{biased;_=runtime.cancel.cancelled()=>Ok(()),_=listener_stop.cancelled()=>Ok(()),result=udp_session(socket,key,receiver,runtime.clone(),meter,stats.clone())=>result};
                    if let Err(error)=outcome{stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);tracing::debug!(rule_id=%runtime.spec.id,%error,"UDP session ended");}
                    let _=finished.send((key,id));
                });
            }
        }
    }
}

struct UdpTarget {
    index: usize,
    health: Option<Arc<Observation>>,
    socket: UdpSocket,
    header: Vec<u8>,
    wire_limit: usize,
    _target_guard: TargetGuard,
    _route_guard: LoopGuard,
}
async fn udp_target(
    rule: &RuntimeRule,
    info: ConnectionInfo,
    inlet: ListenerKey,
) -> Result<UdpTarget> {
    let deadline = Instant::now() + Duration::from_millis(rule.spec.connect_timeout_ms);
    let mut last = None;
    for index in rule.order(info.source, inlet) {
        let Some(guard) = rule.target_guard(index) else {
            continue;
        };
        let target = rule.spec.target_address(index, inlet.address.port())?;
        let addresses = match timeout_at(deadline, resolve_destination(rule, &target)).await {
            Ok(Ok(a)) => a,
            Ok(Err(error)) => {
                last = Some(error.to_string());
                continue;
            }
            Err(_) => bail!("UDP target resolution timed out"),
        };
        for address in addresses {
            match timeout_at(deadline, async {
                let route = rule.routes.reserve(inlet, address)?;
                let socket =
                    network::outbound_udp(rule.spec.outbound_bind.as_ref(), address.is_ipv4())?;
                socket.connect(address).await?;
                let header = rule.spec.targets[index]
                    .proxy_protocol
                    .as_ref()
                    .map(|policy| proxy::encode(policy, false, info))
                    .transpose()?
                    .unwrap_or_default();
                Ok::<_, anyhow::Error>((socket, route, header))
            })
            .await
            {
                Ok(Ok((socket, route, header))) => {
                    return Ok(UdpTarget {
                        index,
                        health: rule
                            .health
                            .as_ref()
                            .map(|h| h.point(index, inlet.address.port(), false).clone()),
                        socket,
                        header,
                        wire_limit: if address.is_ipv4() { 65507 } else { 65527 },
                        _target_guard: guard,
                        _route_guard: route,
                    });
                }
                Ok(Err(error)) => {
                    last = Some(error.to_string());
                    continue;
                }
                Err(_) => bail!("UDP target connection timed out"),
            }
        }
    }
    bail!("all UDP targets failed: {}", last.unwrap_or_default())
}

async fn udp_session(
    listener: Arc<UdpSocket>,
    key: UdpSessionKey,
    mut incoming: Queued<Vec<u8>>,
    rule: Arc<RuntimeRule>,
    meter: Meter,
    stats: Arc<Counters>,
) -> Result<()> {
    let inlet = ListenerKey {
        address: listener.local_addr()?,
        tcp: false,
    };
    let target = udp_target(&rule, key.info, inlet).await?;
    // The system reports a closed port on the target (ICMP port unreachable)
    // as a refused send or receive. New sessions then try other targets
    // first instead of waiting for health probes to notice.
    let refused = |error: io::Error| {
        if error.kind() == io::ErrorKind::ConnectionRefused {
            rule.cool(target.index);
        }
        error
    };
    let mut buffer = vec![0u8; BUFFER_SIZE];
    loop {
        let deadline = Instant::now() + Duration::from_secs(rule.spec.idle_timeout_secs);
        let deadline = rule
            .spec
            .expires_at_ms
            .map(|e| {
                deadline.min(Instant::now() + Duration::from_millis((e - now_ms()).max(0) as u64))
            })
            .unwrap_or(deadline);
        tokio::select! {
            biased;
            _=async {if let Some(health)=&target.health{health.wait_unavailable().await;}else{std::future::pending::<()>().await;}}=>bail!("UDP target is no longer healthy; session retired without replay"),
            _=sleep_until(deadline)=>return Ok(()),
            message=incoming.recv(&stats)=>{
                let Some(payload)=message else{return Ok(());};
                if payload.len()+target.header.len()>target.wire_limit {stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);continue;}
                rule.throttle(payload.len()).await;
                let allowed=meter.admit(&rule.spec,true,payload.len(),true).await?;
                if allowed!=Some(payload.len()){stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);return Ok(());}
                let wire=if target.header.is_empty() {payload} else {let mut wire=target.header.clone();wire.extend_from_slice(&payload);wire};
                let sent=target.socket.send(&wire).await.map_err(refused)?;
                ensure!(sent==wire.len(),"partial UDP send");
                stats.forwarded_upload_bytes.fetch_add((sent-target.header.len()) as u64,Ordering::Relaxed);
            },
            reply=target.socket.recv(&mut buffer)=>{
                let size=reply.map_err(refused)?;rule.throttle(size).await;
                let allowed=meter.admit(&rule.spec,false,size,true).await?;
                if allowed!=Some(size) {stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);return Ok(());}
                let sent=datagram::send(&listener,&buffer[..size],key.peer,key.local,inlet.address.ip().is_unspecified()).await?;
                stats.forwarded_download_bytes.fetch_add(sent as u64,Ordering::Relaxed);
            }
        }
    }
}

/// Carries one Shadowsocks association: each client datagram goes where it
/// names, and replies to the association's sockets go back to the client's
/// latest address. One socket per address family serves every destination.
async fn shadowsocks_association(
    listener: Arc<UdpSocket>,
    mut incoming: Queued<ClientDatagram>,
    mut replies: shadowsocks::Replies,
    rule: Arc<RuntimeRule>,
    meter: Meter,
    stats: Arc<Counters>,
) -> Result<()> {
    let server = rule.shadowsocks.as_ref().expect("Shadowsocks rule");
    let inlet = ListenerKey {
        address: listener.local_addr()?,
        tcp: false,
    };
    let idle =
        Duration::from_secs(rule.spec.idle_timeout_secs).max(shadowsocks::ASSOCIATION_MEMORY);
    let (mut ipv4, mut ipv6) = (None::<UdpSocket>, None::<UdpSocket>);
    let mut client = None::<UdpSessionKey>;
    let mut routes = HashMap::<SocketAddr, LoopGuard>::new();
    let mut names = HashMap::<String, (Instant, SocketAddr)>::new();
    let mut buffer = vec![0u8; BUFFER_SIZE];
    let mut sealed = Vec::with_capacity(BUFFER_SIZE);
    let dropped = || stats.dropped_datagrams.fetch_add(1, Ordering::Relaxed);
    loop {
        let deadline = Instant::now() + idle;
        let deadline = rule
            .spec
            .expires_at_ms
            .map(|e| {
                deadline.min(Instant::now() + Duration::from_millis((e - now_ms()).max(0) as u64))
            })
            .unwrap_or(deadline);
        tokio::select! {
            biased;
            _=sleep_until(deadline)=>return Ok(()),
            message=incoming.recv(&stats)=>{
                let Some(message)=message else{return Ok(());};
                client=Some(message.from);
                let address=match datagram_address(&rule,server,&message.destination,&mut names).await {
                    Ok(address)=>address,
                    Err(error)=>{dropped();tracing::debug!(rule_id=%rule.spec.id,%error,"Shadowsocks datagram not sent");continue;}
                };
                if !routes.contains_key(&address) {
                    match rule.routes.reserve(inlet,address) {
                        Ok(guard)=>{if routes.len()<MAX_ROUTE_GUARDS{routes.insert(address,guard);}}
                        Err(error)=>{dropped();tracing::debug!(rule_id=%rule.spec.id,%error,"Shadowsocks datagram not sent");continue;}
                    }
                }
                let slot=if address.is_ipv4(){&mut ipv4}else{&mut ipv6};
                if slot.is_none() {
                    match network::outbound_udp(rule.spec.outbound_bind.as_ref(),address.is_ipv4()) {
                        Ok(socket)=>*slot=Some(socket),
                        Err(error)=>{dropped();tracing::debug!(rule_id=%rule.spec.id,%error,"Shadowsocks datagram not sent");continue;}
                    }
                }
                let size=message.payload.len();
                rule.throttle(size).await;
                let allowed=meter.admit(&rule.spec,true,size,true).await?;
                if allowed!=Some(size){dropped();return Ok(());}
                match slot.as_ref().unwrap().send_to(&message.payload,address).await {
                    Ok(_)=>{stats.forwarded_upload_bytes.fetch_add(size as u64,Ordering::Relaxed);}
                    Err(error)=>{dropped();tracing::debug!(rule_id=%rule.spec.id,%error,"Shadowsocks datagram not sent");}
                }
            },
            readable=async {
                match (&ipv4,&ipv6) {
                    (Some(v4),Some(v6))=>tokio::select!{ready=v4.readable()=>ready.map(|_|true),ready=v6.readable()=>ready.map(|_|false)},
                    (Some(v4),None)=>v4.readable().await.map(|_|true),
                    (None,Some(v6))=>v6.readable().await.map(|_|false),
                    (None,None)=>std::future::pending().await,
                }
            }=>{
                let socket=if readable? {ipv4.as_ref()} else {ipv6.as_ref()};
                let (size,source)=match socket.unwrap().try_recv_from(&mut buffer) {
                    Ok(received)=>received,
                    Err(error) if error.kind()==io::ErrorKind::WouldBlock=>continue,
                    Err(error)=>{dropped();tracing::debug!(rule_id=%rule.spec.id,%error,"Shadowsocks reply not received");continue;}
                };
                let source=canonical_address(source);
                if !server.permits(source.ip()){dropped();continue;}
                rule.throttle(size).await;
                let allowed=meter.admit(&rule.spec,false,size,true).await?;
                if allowed!=Some(size){dropped();return Ok(());}
                let client=client.expect("an association starts with a client datagram");
                sealed.clear();
                server.seal_reply(&mut replies,source,&buffer[..size],&mut sealed);
                datagram::send(&listener,&sealed,client.peer,client.local,inlet.address.ip().is_unspecified()).await?;
                stats.forwarded_download_bytes.fetch_add(size as u64,Ordering::Relaxed);
            }
        }
    }
}

/// Where a Shadowsocks datagram goes. A name is looked up once per
/// [`NAME_MEMORY`] for each association, not for every datagram, and its
/// IPv4 address is preferred: unlike a TCP connect, a datagram sent to an
/// unreachable IPv6 address fails silently, so no other address is tried.
async fn datagram_address(
    rule: &RuntimeRule,
    server: &shadowsocks::Server,
    destination: &shadowsocks::Destination,
    names: &mut HashMap<String, (Instant, SocketAddr)>,
) -> Result<SocketAddr> {
    let address = match destination {
        shadowsocks::Destination::Ip(address) => canonical_address(*address),
        shadowsocks::Destination::Domain(..) => {
            let name = destination.to_string();
            match names.get(&name) {
                Some((at, address)) if at.elapsed() < NAME_MEMORY => *address,
                _ => {
                    let deadline =
                        Instant::now() + Duration::from_millis(rule.spec.connect_timeout_ms);
                    let address = timeout_at(deadline, rule.resolver.resolve(&name))
                        .await
                        .context("name lookup timed out")??
                        .into_iter()
                        .filter(|address| server.permits(address.ip()))
                        .min_by_key(|address| !address.is_ipv4())
                        .with_context(|| format!("{destination} has no public address"))?;
                    if names.len() >= MAX_NAMES {
                        names.clear();
                    }
                    names.insert(name, (Instant::now(), address));
                    address
                }
            }
        }
    };
    ensure!(
        server.permits(address.ip()),
        "{destination} is not a public address"
    );
    Ok(address)
}

#[cfg(test)]
mod tests {
    use super::by_latency;

    fn order(latencies: &[Option<u64>], current: usize) -> Vec<usize> {
        let pool: Vec<usize> = (0..latencies.len()).collect();
        by_latency(&pool, |index| latencies[index], current)
    }

    #[test]
    fn lowest_latency_orders_measured_targets_first_and_holds_a_close_choice() {
        // No current choice: fastest first, unmeasured last.
        assert_eq!(
            order(&[Some(50_000), Some(10_000), None], usize::MAX),
            [1, 0, 2]
        );
        // Current is within 10% + 1 ms of the best (10 ms -> 12 ms): keep it.
        assert_eq!(order(&[Some(12_000), Some(10_000)], 0), [0, 1]);
        // One microsecond past the margin: switch to the faster target.
        assert_eq!(order(&[Some(12_001), Some(10_000)], 0), [1, 0]);
        // A current target without a measurement does not block switching.
        assert_eq!(order(&[None, Some(10_000)], 0), [1, 0]);
    }
}
