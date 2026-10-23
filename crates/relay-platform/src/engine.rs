use crate::{
    model::*,
    store::{Admission, Store},
};
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket, lookup_host},
    sync::{Mutex, mpsc, oneshot, watch},
    task::JoinHandle,
    time::{Instant, sleep, sleep_until, timeout_at},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

const BUFFER_SIZE: usize = 64 * 1024;
const UDP_QUEUE: usize = 4;

#[derive(Default)]
struct Counters {
    active_tcp: AtomicU64,
    active_udp: AtomicU64,
    accepted_tcp: AtomicU64,
    rejected_connections: AtomicU64,
    failed_connections: AtomicU64,
    dropped_datagrams: AtomicU64,
    forwarded_upload_bytes: AtomicU64,
    forwarded_download_bytes: AtomicU64,
}
impl Counters {
    fn snapshot(&self) -> EngineStats {
        EngineStats {
            active_tcp: self.active_tcp.load(Ordering::Relaxed),
            active_udp: self.active_udp.load(Ordering::Relaxed),
            accepted_tcp: self.accepted_tcp.load(Ordering::Relaxed),
            rejected_connections: self.rejected_connections.load(Ordering::Relaxed),
            failed_connections: self.failed_connections.load(Ordering::Relaxed),
            dropped_datagrams: self.dropped_datagrams.load(Ordering::Relaxed),
            forwarded_upload_bytes: self.forwarded_upload_bytes.load(Ordering::Relaxed),
            forwarded_download_bytes: self.forwarded_download_bytes.load(Ordering::Relaxed),
        }
    }
}

struct MeterMessage {
    request: Option<Admission>,
    response: oneshot::Sender<Result<Option<usize>>>,
}
#[derive(Clone)]
struct Meter(mpsc::Sender<MeterMessage>);
impl Meter {
    fn new(store: Store) -> Self {
        let (sender, mut receiver) = mpsc::channel::<MeterMessage>(1024);
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
                let db = store.clone();
                let result = tokio::task::spawn_blocking(move || db.admit_batch(&requests)).await;
                match result {
                    Ok(Ok(values)) => {
                        let mut iter = values.into_iter();
                        for message in batch {
                            let value = if message.request.is_some() {
                                iter.next().unwrap()
                            } else {
                                None
                            };
                            let _ = message.response.send(Ok(value));
                        }
                    }
                    error => {
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
        Self(sender)
    }
    async fn admit(
        &self,
        rule: &Rule,
        upload: bool,
        bytes: usize,
        datagram: bool,
    ) -> Result<Option<usize>> {
        let (tx, rx) = oneshot::channel();
        self.0
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
        rx.await.context("meter stopped")?
    }
    async fn barrier(&self) -> Result<()> {
        let (tx, rx) = oneshot::channel();
        self.0
            .send(MeterMessage {
                request: None,
                response: tx,
            })
            .await
            .context("meter stopped")?;
        rx.await??;
        Ok(())
    }
}

struct Bucket {
    rate: Option<u64>,
    tokens: f64,
    updated: Instant,
}
struct SharedRule {
    tcp: Arc<AtomicUsize>,
    udp: Arc<AtomicUsize>,
    bucket: StdMutex<Bucket>,
}
impl SharedRule {
    fn new(rate: Option<u64>) -> Self {
        Self {
            tcp: Arc::new(AtomicUsize::new(0)),
            udp: Arc::new(AtomicUsize::new(0)),
            bucket: StdMutex::new(Bucket {
                rate,
                tokens: rate.unwrap_or(0).max(BUFFER_SIZE as u64) as f64,
                updated: Instant::now(),
            }),
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
    }
    async fn throttle(&self, bytes: usize) {
        loop {
            let wait = {
                let mut b = self.bucket.lock().unwrap();
                let Some(rate) = b.rate else {
                    return;
                };
                let now = Instant::now();
                b.tokens = (b.tokens + now.duration_since(b.updated).as_secs_f64() * rate as f64)
                    .min(rate.max(BUFFER_SIZE as u64) as f64);
                b.updated = now;
                if b.tokens >= bytes as f64 {
                    b.tokens -= bytes as f64;
                    return;
                }
                Duration::from_secs_f64(((bytes as f64 - b.tokens) / rate as f64).clamp(0.001, 1.0))
            };
            sleep(wait).await;
        }
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

struct RuntimeRule {
    spec: Rule,
    shared: Arc<SharedRule>,
    cancel: CancellationToken,
    cursor: AtomicU64,
    target_active: Vec<Arc<AtomicUsize>>,
}
impl RuntimeRule {
    fn new(spec: Rule, shared: Option<Arc<SharedRule>>) -> Self {
        let target_active = spec
            .targets
            .iter()
            .map(|_| Arc::new(AtomicUsize::new(0)))
            .collect();
        let shared = shared.unwrap_or_else(|| Arc::new(SharedRule::new(spec.rate_bytes_per_sec)));
        Self {
            spec,
            shared,
            cancel: CancellationToken::new(),
            cursor: AtomicU64::new(0),
            target_active,
        }
    }
    fn order(&self, source: SocketAddr) -> Vec<usize> {
        let targets = &self.spec.targets;
        let next = self.cursor.fetch_add(1, Ordering::Relaxed);
        let first = match self.spec.balance {
            Balance::WeightedRoundRobin | Balance::SourceHash => {
                let sum: u64 = targets.iter().map(|t| t.weight as u64).sum();
                let value = if self.spec.balance == Balance::SourceHash {
                    let hash =
                        Sha256::digest(format!("{}:{}", self.spec.id, source.ip()).as_bytes());
                    u64::from_be_bytes(hash[0..8].try_into().unwrap())
                } else {
                    next
                };
                let mut position = value % sum;
                let mut selected = 0;
                for (i, t) in targets.iter().enumerate() {
                    if position < t.weight as u64 {
                        selected = i;
                        break;
                    }
                    position -= t.weight as u64;
                }
                selected
            }
            Balance::LeastConnections => {
                let offset = (next % targets.len() as u64) as usize;
                (0..targets.len())
                    .map(|i| (i + offset) % targets.len())
                    .min_by(|&a, &b| {
                        let ca = self.target_active[a].load(Ordering::Relaxed) as u64;
                        let cb = self.target_active[b].load(Ordering::Relaxed) as u64;
                        (ca * targets[b].weight as u64).cmp(&(cb * targets[a].weight as u64))
                    })
                    .unwrap()
            }
        };
        (0..targets.len())
            .map(|i| (first + i) % targets.len())
            .collect()
    }
    fn target_guard(&self, index: usize) -> TargetGuard {
        self.target_active[index].fetch_add(1, Ordering::Relaxed);
        TargetGuard(self.target_active[index].clone())
    }
    fn accepts(&self, peer: SocketAddr) -> bool {
        self.spec.permits(peer.ip())
            && self
                .spec
                .expires_at_ms
                .is_none_or(|expiry| expiry > now_ms())
    }
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq)]
struct ListenerKey {
    address: SocketAddr,
    tcp: bool,
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
#[derive(Default)]
struct EngineInner {
    config: Option<NodeConfig>,
    listeners: HashMap<ListenerKey, ListenerHandle>,
    rules: HashMap<String, Arc<RuntimeRule>>,
    stopped: bool,
}

pub struct Engine {
    store: Store,
    meter: Meter,
    inner: Mutex<EngineInner>,
    stats: Arc<Counters>,
    tasks: TaskTracker,
}
impl Engine {
    pub fn new(store: Store) -> Self {
        Self {
            meter: Meter::new(store.clone()),
            store,
            inner: Mutex::new(EngineInner::default()),
            stats: Arc::new(Counters::default()),
            tasks: TaskTracker::new(),
        }
    }
    pub fn stats(&self) -> EngineStats {
        self.stats.snapshot()
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
        let mut staged = HashMap::new();
        for spec in config.rules.iter().filter(|r| r.enabled) {
            let runtime =
                if let Some(old) = inner.rules.get(&spec.id).filter(|old| old.spec == *spec) {
                    old.clone()
                } else {
                    let mut new = RuntimeRule::new(
                        spec.clone(),
                        inner.rules.get(&spec.id).map(|old| old.shared.clone()),
                    );
                    if let Some(old) = inner
                        .rules
                        .get(&spec.id)
                        .filter(|old| !security_policy_changed(&old.spec, spec))
                    {
                        new.cancel = old.cancel.clone();
                    }
                    Arc::new(new)
                };
            rules.insert(spec.id.clone(), runtime.clone());
            for tcp in [true, false] {
                if (tcp && !spec.protocol.tcp()) || (!tcp && !spec.protocol.udp()) {
                    continue;
                }
                let key = ListenerKey {
                    address: spec.listen,
                    tcp,
                };
                wanted.insert(key, runtime.clone());
                if let Some(existing) = inner.listeners.get(&key) {
                    ensure!(
                        existing.rule_id == spec.id,
                        "listener ownership change requires removing the old listener first"
                    );
                } else {
                    let socket = if tcp {
                        StagedSocket::Tcp(TcpListener::bind(spec.listen).await.with_context(
                            || format!("cannot stage TCP listener {}", spec.listen),
                        )?)
                    } else {
                        StagedSocket::Udp(UdpSocket::bind(spec.listen).await.with_context(
                            || format!("cannot stage UDP listener {}", spec.listen),
                        )?)
                    };
                    staged.insert(key, socket);
                }
            }
        }
        // No running state is modified before the transaction and all binds succeed.
        let db = self.store.clone();
        let saved = config.clone();
        tokio::task::spawn_blocking(move || db.save_agent_config(&saved)).await??;
        for (id, old) in &inner.rules {
            match rules.get(id) {
                None => old.cancel.cancel(),
                Some(new) if security_policy_changed(&old.spec, &new.spec) => old.cancel.cancel(),
                _ => {}
            }
        }
        for runtime in rules.values() {
            runtime.shared.set_rate(runtime.spec.rate_bytes_per_sec);
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
            let (update, receiver) = watch::channel(runtime.clone());
            let stop = CancellationToken::new();
            let task = match staged.remove(&key).expect("every new listener staged") {
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
            inner.listeners.insert(
                key,
                ListenerHandle {
                    rule_id: runtime.spec.id.clone(),
                    update,
                    stop,
                    task,
                },
            );
        }
        inner.rules = rules;
        inner.config = Some(config);
        Ok(())
    }

    pub async fn shutdown(&self) -> Result<()> {
        let mut inner = self.inner.lock().await;
        inner.stopped = true;
        for runtime in inner.rules.values() {
            runtime.cancel.cancel();
        }
        for listener in inner.listeners.values() {
            listener.stop.cancel();
        }
        for (_, listener) in inner.listeners.drain() {
            let _ = listener.task.await;
        }
        self.tasks.close();
        self.tasks.wait().await;
        self.meter.barrier().await?;
        Ok(())
    }
}

fn security_policy_changed(old: &Rule, new: &Rule) -> bool {
    old.meter_epoch != new.meter_epoch
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
        if !rule.accepts(peer) {
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
        tasks.spawn(async move {
            let _guard=guard;
            let outcome=tokio::select!{biased;_=rule.cancel.cancelled()=>Ok(()),result=tcp_session(stream,peer,rule.clone(),meter,stats.clone())=>result};
            if let Err(error)=outcome {stats.failed_connections.fetch_add(1,Ordering::Relaxed);tracing::debug!(rule_id=%rule.spec.id,%error,"TCP session ended");}
        });
    }
}

async fn connect_tcp(rule: &RuntimeRule, peer: SocketAddr) -> Result<(TcpStream, TargetGuard)> {
    let deadline = Instant::now() + Duration::from_millis(rule.spec.connect_timeout_ms);
    let mut last = None;
    for index in rule.order(peer) {
        let guard = rule.target_guard(index);
        match timeout_at(
            deadline,
            TcpStream::connect(&rule.spec.targets[index].address),
        )
        .await
        {
            Ok(Ok(stream)) => return Ok((stream, guard)),
            Ok(Err(error)) => last = Some(error.to_string()),
            Err(_) => bail!("target connection timed out"),
        }
    }
    bail!("all targets failed: {}", last.unwrap_or_default())
}

async fn tcp_session(
    mut client: TcpStream,
    peer: SocketAddr,
    rule: Arc<RuntimeRule>,
    meter: Meter,
    stats: Arc<Counters>,
) -> Result<()> {
    let (mut target, _target_guard) = connect_tcp(&rule, peer).await?;
    client.set_nodelay(true)?;
    target.set_nodelay(true)?;
    let activity = Arc::new(StdMutex::new(Instant::now()));
    let (cr, cw) = client.split();
    let (tr, tw) = target.split();
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
    let mut buffer = vec![0u8; BUFFER_SIZE];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        *activity.lock().unwrap() = Instant::now();
        rule.shared.throttle(read).await;
        let allowed = meter
            .admit(&rule.spec, upload, read, false)
            .await?
            .unwrap_or(0);
        if allowed == 0 {
            bail!("quota exhausted or rule inactive");
        }
        let mut written = 0;
        while written < allowed {
            let n = writer.write(&buffer[written..allowed]).await?;
            if n == 0 {
                return Err(io::Error::from(io::ErrorKind::WriteZero).into());
            }
            written += n;
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
        if allowed < read {
            bail!("quota exhausted");
        }
    }
}

struct UdpEntry {
    generation: u64,
    sender: mpsc::Sender<Vec<u8>>,
}

async fn udp_listener(
    listener: UdpSocket,
    mut updates: watch::Receiver<Arc<RuntimeRule>>,
    stop: CancellationToken,
    meter: Meter,
    stats: Arc<Counters>,
    tasks: TaskTracker,
) {
    let listener = Arc::new(listener);
    let mut sessions = HashMap::<SocketAddr, UdpEntry>::new();
    let (finished_tx, mut finished_rx) = mpsc::unbounded_channel::<(SocketAddr, u64)>();
    let mut generation = 0u64;
    let mut buffer = vec![0u8; BUFFER_SIZE];
    loop {
        tokio::select! {
            biased;
            _=stop.cancelled()=>break,
            Some((peer,id))=finished_rx.recv()=>{if sessions.get(&peer).is_some_and(|s|s.generation==id){sessions.remove(&peer);}},
            changed=updates.changed()=>{if changed.is_err(){break;}sessions.retain(|_,entry|!entry.sender.is_closed());},
            received=listener.recv_from(&mut buffer)=>{
                let (size,peer)=match received{Ok(pair)=>pair,Err(error)=>{tracing::warn!(%error,"UDP receive failed");sleep(Duration::from_millis(100)).await;continue;}};
                let runtime=updates.borrow().clone();
                if !runtime.accepts(peer){stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);continue;}
                if sessions.get(&peer).is_some_and(|entry|entry.sender.is_closed()){sessions.remove(&peer);}
                if let Some(session)=sessions.get(&peer) {
                    if session.sender.try_send(buffer[..size].to_vec()).is_err(){stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);}
                    continue;
                }
                let Some(guard)=CountGuard::acquire(runtime.shared.udp.clone(),runtime.spec.udp_max_sessions as usize,stats.clone(),false) else{stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);continue;};
                let (sender,receiver)=mpsc::channel(UDP_QUEUE);
                let _=sender.try_send(buffer[..size].to_vec());generation=generation.wrapping_add(1);let id=generation;
                sessions.insert(peer,UdpEntry{generation:id,sender});
                let socket=listener.clone();let meter=meter.clone();let stats=stats.clone();let finished=finished_tx.clone();let listener_stop=stop.clone();
                tasks.spawn(async move {
                    let _guard=guard;
                    let outcome=tokio::select!{biased;_=runtime.cancel.cancelled()=>Ok(()),_=listener_stop.cancelled()=>Ok(()),result=udp_session(socket,peer,receiver,runtime.clone(),meter,stats.clone())=>result};
                    if let Err(error)=outcome{stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);tracing::debug!(rule_id=%runtime.spec.id,%error,"UDP session ended");}
                    let _=finished.send((peer,id));
                });
            }
        }
    }
    // Dropping senders also ends sessions when the listener is removed.
}

async fn udp_target(rule: &RuntimeRule, peer: SocketAddr) -> Result<(UdpSocket, TargetGuard)> {
    let deadline = Instant::now() + Duration::from_millis(rule.spec.connect_timeout_ms);
    for index in rule.order(peer) {
        let guard = rule.target_guard(index);
        let addresses =
            match timeout_at(deadline, lookup_host(&rule.spec.targets[index].address)).await {
                Ok(Ok(a)) => a,
                _ => continue,
            };
        for address in addresses {
            let bind = if address.is_ipv4() {
                "0.0.0.0:0"
            } else {
                "[::]:0"
            };
            let socket = UdpSocket::bind(bind).await?;
            if socket.connect(address).await.is_ok() {
                return Ok((socket, guard));
            }
        }
    }
    bail!("no UDP target can be resolved and connected")
}

async fn udp_session(
    listener: Arc<UdpSocket>,
    peer: SocketAddr,
    mut incoming: mpsc::Receiver<Vec<u8>>,
    rule: Arc<RuntimeRule>,
    meter: Meter,
    stats: Arc<Counters>,
) -> Result<()> {
    let (target, _target_guard) = udp_target(&rule, peer).await?;
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
            _=sleep_until(deadline)=>return Ok(()),
            message=incoming.recv()=>{
                let Some(payload)=message else{return Ok(());};
                rule.shared.throttle(payload.len()).await;
                let allowed=meter.admit(&rule.spec,true,payload.len(),true).await?;
                if allowed!=Some(payload.len()){stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);return Ok(());}
                let sent=target.send(&payload).await?;
                stats.forwarded_upload_bytes.fetch_add(sent as u64,Ordering::Relaxed);
            },
            reply=target.recv(&mut buffer)=>{
                let size=reply?;rule.shared.throttle(size).await;
                let allowed=meter.admit(&rule.spec,false,size,true).await?;
                if allowed!=Some(size) {stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);return Ok(());}
                let sent=listener.send_to(&buffer[..size],peer).await?;
                stats.forwarded_download_bytes.fetch_add(sent as u64,Ordering::Relaxed);
            }
        }
    }
}
