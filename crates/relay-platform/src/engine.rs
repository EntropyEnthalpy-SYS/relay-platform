use crate::{
    datagram,
    model::*,
    network::{self, TargetResolver},
    proxy::{self, ConnectionInfo},
    routing::{Endpoint as ListenerKey, LoopGuard, Routes, Topology, local_ips},
    store::{Admission, AdmissionDecision, Store},
    transport::{BoxStream, PreparedTls},
    websocket,
};
use anyhow::{Context, Result, bail, ensure};
use sha2::{Digest, Sha256};
use std::{
    collections::HashMap,
    io,
    net::SocketAddr,
    path::PathBuf,
    sync::{
        Arc, Mutex as StdMutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt},
    net::{TcpListener, TcpStream, UdpSocket},
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
    response: oneshot::Sender<Result<AdmissionDecision>>,
}
#[derive(Clone)]
struct Meter {
    sender: mpsc::Sender<MeterMessage>,
    store: Store,
}
impl Meter {
    fn new(store: Store) -> Self {
        let (sender, mut receiver) = mpsc::channel::<MeterMessage>(1024);
        let actor_store = store.clone();
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
                let db = actor_store.clone();
                let result =
                    tokio::task::spawn_blocking(move || db.admit_batch_detailed(&requests)).await;
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
        Self { sender, store }
    }
    async fn admit(
        &self,
        rule: &Rule,
        upload: bool,
        bytes: usize,
        datagram: bool,
    ) -> Result<Option<usize>> {
        let deadline = Instant::now() + Duration::from_millis(rule.connect_timeout_ms);
        loop {
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
                        return Ok(None);
                    }
                    tokio::select! {_=self.store.budget_updated()=>{},_=sleep_until((Instant::now()+Duration::from_millis(50)).min(deadline))=>{}}
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
    resolver: Arc<TargetResolver>,
    routes: Arc<Routes>,
    tls: PreparedTls,
    shared: Arc<SharedRule>,
    cancel: CancellationToken,
    cursor: AtomicU64,
    target_active: Vec<Arc<AtomicUsize>>,
}
impl RuntimeRule {
    fn new(
        spec: Rule,
        shared: Option<Arc<SharedRule>>,
        tls: PreparedTls,
        resolver: Arc<TargetResolver>,
        routes: Arc<Routes>,
    ) -> Self {
        let target_active = spec
            .targets
            .iter()
            .map(|_| Arc::new(AtomicUsize::new(0)))
            .collect();
        let shared = shared.unwrap_or_else(|| Arc::new(SharedRule::new(spec.rate_bytes_per_sec)));
        Self {
            spec,
            resolver,
            routes,
            tls,
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
                    let hash = Sha256::digest(
                        format!("{}:{}", self.spec.id, canonical_ip(source.ip())).as_bytes(),
                    );
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
    resolvers: HashMap<Option<DnsCache>, Arc<TargetResolver>>,
    stopped: bool,
}

pub struct Engine {
    store: Store,
    tls_directory: Option<PathBuf>,
    meter: Meter,
    inner: Mutex<EngineInner>,
    stats: Arc<Counters>,
    tasks: TaskTracker,
    routes: Arc<Routes>,
}
impl Engine {
    pub fn new(store: Store) -> Self {
        Self::with_tls_directory(store, None)
    }
    pub fn with_tls_directory(store: Store, tls_directory: Option<PathBuf>) -> Self {
        Self {
            tls_directory,
            meter: Meter::new(store.clone()),
            store,
            inner: Mutex::new(EngineInner::default()),
            stats: Arc::new(Counters::default()),
            tasks: TaskTracker::new(),
            routes: Arc::new(Routes::default()),
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
        let mut resolvers = HashMap::new();
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
                );
                if let Some(old) = inner.rules.get(&spec.id).filter(|old| {
                    !security_policy_changed(&old.spec, spec)
                        && old.tls.fingerprint == new.tls.fingerprint
                }) {
                    new.cancel = old.cancel.clone();
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
                        let socket =
                            if tcp {
                                StagedSocket::Tcp(network::tcp_listener(address).with_context(
                                    || format!("cannot stage TCP listener {address}"),
                                )?)
                            } else {
                                StagedSocket::Udp(network::udp_listener(address).with_context(
                                    || format!("cannot stage UDP listener {address}"),
                                )?)
                            };
                        staged.insert(key, socket);
                    }
                }
            }
        }
        // No running state is modified before the transaction and all binds succeed.
        let db = self.store.clone();
        let saved = config.clone();
        tokio::task::spawn_blocking(move || db.save_agent_config(&saved)).await??;
        self.routes.install(topology);
        for (id, old) in &inner.rules {
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
        inner.resolvers = resolvers;
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
    old.budget_ids != new.budget_ids
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
        tasks.spawn(async move {
            let _guard=guard;
            let outcome=tokio::select!{biased;_=rule.cancel.cancelled()=>Ok(()),result=tcp_session(stream,peer,inlet,rule.clone(),meter,stats.clone())=>result};
            if let Err(error)=outcome {stats.failed_connections.fetch_add(1,Ordering::Relaxed);tracing::debug!(rule_id=%rule.spec.id,%error,"TCP session ended");}
        });
    }
}

async fn connect_tcp(
    rule: &RuntimeRule,
    info: ConnectionInfo,
    inlet: ListenerKey,
) -> Result<(BoxStream, TargetGuard, LoopGuard)> {
    let deadline = Instant::now() + Duration::from_millis(rule.spec.connect_timeout_ms);
    let mut last = None;
    for index in rule.order(info.source) {
        let guard = rule.target_guard(index);
        let target = rule.spec.target_address(index, inlet.address.port())?;
        let addresses = match timeout_at(deadline, rule.resolver.resolve(&target)).await {
            Ok(Ok(addresses)) => addresses,
            Ok(Err(error)) => {
                last = Some(error.to_string());
                continue;
            }
            Err(_) => bail!("target resolution timed out"),
        };
        for address in addresses {
            match timeout_at(deadline, async {
                let route = rule.routes.reserve(inlet, address)?;
                let mut stream =
                    network::connect_tcp(rule.spec.outbound_bind.as_ref(), address).await?;
                stream.set_nodelay(true)?;
                let policy = rule.spec.targets[index].proxy_protocol.as_ref();
                if let Some(policy) = policy.filter(|p| p.placement == ProxyPlacement::BeforeTls) {
                    stream
                        .write_all(&proxy::encode(policy, true, info)?)
                        .await?;
                }
                let mut stream = rule.tls.connect(index, stream).await?;
                if let Some(policy) = policy.filter(|p| p.placement == ProxyPlacement::InsideTls) {
                    stream
                        .write_all(&proxy::encode(policy, true, info)?)
                        .await?;
                    stream.flush().await?;
                }
                if let Some(spec) = &rule.spec.targets[index].websocket {
                    stream = websocket::connect(
                        stream,
                        spec,
                        rule.spec.targets[index].tls.is_some(),
                        Duration::from_millis(rule.spec.connect_timeout_ms),
                    )
                    .await?;
                }
                Ok::<_, anyhow::Error>((stream, route))
            })
            .await
            {
                Ok(Ok((stream, route))) => return Ok((stream, guard, route)),
                Ok(Err(error)) => last = Some(error.to_string()),
                Err(_) => bail!("target connection timed out"),
            }
        }
    }
    bail!("all targets failed: {}", last.unwrap_or_default())
}

async fn tcp_session(
    mut client: TcpStream,
    peer: SocketAddr,
    inlet: ListenerKey,
    rule: Arc<RuntimeRule>,
    meter: Meter,
    stats: Arc<Counters>,
) -> Result<()> {
    client.set_nodelay(true)?;
    let original = ConnectionInfo {
        source: peer,
        destination: client.local_addr()?,
    };
    let handshake_deadline = Instant::now() + Duration::from_millis(rule.spec.connect_timeout_ms);
    let (client, info) = timeout_at(handshake_deadline, async {
        let mut info = original;
        let policy = rule.spec.inbound_proxy.as_ref();
        if let Some(policy) = policy.filter(|p| p.placement == ProxyPlacement::BeforeTls) {
            info = proxy::read_tcp(&mut client, policy, original).await?;
        }
        let mut client = rule.tls.accept(client).await?;
        if let Some(policy) = policy.filter(|p| p.placement == ProxyPlacement::InsideTls) {
            info = proxy::read_tcp(&mut client, policy, original).await?;
        }
        Ok::<_, anyhow::Error>((client, info))
    })
    .await
    .context("inbound TLS/PROXY handshake timed out")??;
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
    let (target, _target_guard, _route_guard) = connect_tcp(&rule, info, inlet).await?;
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
    let mut buffer = vec![0u8; BUFFER_SIZE];
    loop {
        let read = reader.read(&mut buffer).await?;
        if read == 0 {
            writer.shutdown().await?;
            return Ok(());
        }
        *activity.lock().unwrap() = Instant::now();
        rule.shared.throttle(read).await;
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
    let bound = listener.local_addr().expect("bound UDP listener");
    let listener = Arc::new(listener);
    let mut sessions = HashMap::<UdpSessionKey, UdpEntry>::new();
    let (finished_tx, mut finished_rx) = mpsc::unbounded_channel::<(UdpSessionKey, u64)>();
    let mut generation = 0u64;
    let mut buffer = vec![0u8; BUFFER_SIZE];
    loop {
        tokio::select! {
            biased;
            _=stop.cancelled()=>break,
            Some((key,id))=finished_rx.recv()=>{if sessions.get(&key).is_some_and(|s|s.generation==id){sessions.remove(&key);}},
            changed=updates.changed()=>{if changed.is_err(){break;}sessions.retain(|_,entry|!entry.sender.is_closed());},
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
                let original=ConnectionInfo{source:peer,destination:local};
                let (info,header_size)=if let Some(policy)=&runtime.spec.inbound_proxy {
                    match proxy::decode_v2(&buffer[..size],false,policy.max_header_bytes,original) {
                        Ok(decoded)=>decoded,
                        Err(error)=>{stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);tracing::debug!(rule_id=%runtime.spec.id,%error,"UDP PROXY rejected");continue;}
                    }
                } else {(original,0)};
                if !runtime.accepts(info.source){stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);continue;}
                let key=UdpSessionKey{peer,local,info};
                if sessions.get(&key).is_some_and(|entry|entry.sender.is_closed()){sessions.remove(&key);}
                if let Some(session)=sessions.get(&key) {
                    if session.sender.try_send(buffer[header_size..size].to_vec()).is_err(){stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);}
                    continue;
                }
                let Some(guard)=CountGuard::acquire(runtime.shared.udp.clone(),runtime.spec.udp_max_sessions as usize,stats.clone(),false) else{stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);continue;};
                let (sender,receiver)=mpsc::channel(UDP_QUEUE);
                let _=sender.try_send(buffer[header_size..size].to_vec());generation=generation.wrapping_add(1);let id=generation;
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
    for index in rule.order(info.source) {
        let guard = rule.target_guard(index);
        let target = rule.spec.target_address(index, inlet.address.port())?;
        let addresses = match timeout_at(deadline, rule.resolver.resolve(&target)).await {
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
    mut incoming: mpsc::Receiver<Vec<u8>>,
    rule: Arc<RuntimeRule>,
    meter: Meter,
    stats: Arc<Counters>,
) -> Result<()> {
    let inlet = ListenerKey {
        address: listener.local_addr()?,
        tcp: false,
    };
    let target = udp_target(&rule, key.info, inlet).await?;
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
                if payload.len()+target.header.len()>target.wire_limit {stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);continue;}
                rule.shared.throttle(payload.len()).await;
                let allowed=meter.admit(&rule.spec,true,payload.len(),true).await?;
                if allowed!=Some(payload.len()){stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);return Ok(());}
                let wire=if target.header.is_empty() {payload} else {let mut wire=target.header.clone();wire.extend_from_slice(&payload);wire};
                let sent=target.socket.send(&wire).await?;
                ensure!(sent==wire.len(),"partial UDP send");
                stats.forwarded_upload_bytes.fetch_add((sent-target.header.len()) as u64,Ordering::Relaxed);
            },
            reply=target.socket.recv(&mut buffer)=>{
                let size=reply?;rule.shared.throttle(size).await;
                let allowed=meter.admit(&rule.spec,false,size,true).await?;
                if allowed!=Some(size) {stats.dropped_datagrams.fetch_add(1,Ordering::Relaxed);return Ok(());}
                let sent=datagram::send(&listener,&buffer[..size],key.peer,key.local,inlet.address.ip().is_unspecified()).await?;
                stats.forwarded_download_bytes.fetch_add(sent as u64,Ordering::Relaxed);
            }
        }
    }
}
