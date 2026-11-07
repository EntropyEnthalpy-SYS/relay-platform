//! The agent's side of speed tests: runs the tasks the controller sent,
//! each fixed code with bounded parameters, and reports their progress and
//! results. Test traffic uses its own sockets, never a rule, so nothing is
//! metered, limited or counted against a quota. A task the controller no
//! longer sends is stopped at once; every task also ends by itself after
//! [`Params::hard_limit`].
use crate::speed_test::*;
use anyhow::{Context, Result, bail};
use std::{
    collections::{HashMap, HashSet, VecDeque},
    net::SocketAddr,
    sync::{
        Arc, Mutex,
        atomic::{AtomicU64, AtomicUsize, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
    sync::Notify,
    task::JoinSet,
    time::{Instant, sleep, sleep_until, timeout, timeout_at},
};
use tokio_util::sync::CancellationToken;

/// Bytes per write.
const CHUNK: usize = 64 * 1024;
/// How long a dialer keeps trying while the other agent opens its listener.
const CONNECT_PATIENCE: Duration = Duration::from_secs(15);
/// Most connections a listener serves at once, test streams included.
const MAX_CONNECTIONS: usize = 32;
/// Bytes asked for per download request from the public service.
const DOWNLOAD_REQUEST: u64 = 25_000_000;
const MIN_UPLOAD_REQUEST: usize = 256 * 1024;
const MAX_UPLOAD_REQUEST: usize = 8 * 1024 * 1024;

struct Running {
    task: Task,
    cancel: CancellationToken,
    status: Arc<Mutex<TaskReport>>,
}

pub(super) struct SpeedTests {
    /// Cloudflare's speed service; tests construct agents with a local one.
    base: Arc<str>,
    running: HashMap<String, Running>,
    finished: Arc<Notify>,
}
impl Drop for SpeedTests {
    fn drop(&mut self) {
        for running in self.running.values() {
            running.cancel.cancel();
        }
    }
}

impl SpeedTests {
    pub fn new(base: &str) -> Self {
        Self {
            base: base.trim_end_matches('/').into(),
            running: HashMap::new(),
            finished: Arc::new(Notify::new()),
        }
    }
    /// Notified when a task ends, so its result is reported at once.
    pub fn finished(&self) -> Arc<Notify> {
        self.finished.clone()
    }
    /// Runs the tasks the controller sent and stops every other one.
    pub fn reconcile(&mut self, tasks: &[Task]) {
        self.running.retain(|id, running| {
            let keep = tasks.iter().any(|t| &t.id == id && *t == running.task);
            if !keep {
                running.cancel.cancel();
            }
            keep
        });
        for task in tasks {
            if self.running.contains_key(&task.id) || self.running.len() >= MAX_TASKS {
                continue;
            }
            let cancel = CancellationToken::new();
            let status = Arc::new(Mutex::new(TaskReport::new(&task.id)));
            match task.validate() {
                Ok(()) => {
                    tracing::info!(id = %task.id, role = ?task.role, "speed test started");
                    tokio::spawn(run(
                        task.clone(),
                        self.base.clone(),
                        cancel.clone(),
                        status.clone(),
                        self.finished.clone(),
                    ));
                }
                Err(error) => *status.lock().unwrap() = TaskReport::failed(&task.id, error),
            }
            self.running.insert(
                task.id.clone(),
                Running {
                    task: task.clone(),
                    cancel,
                    status,
                },
            );
        }
    }
    /// Whether a task is still running; the agent then reports every second.
    pub fn active(&self) -> bool {
        self.running
            .values()
            .any(|r| r.status.lock().unwrap().state == TaskState::Running)
    }
    pub fn report(&self) -> Report {
        let mut tasks: Vec<TaskReport> = self
            .running
            .values()
            .map(|r| r.status.lock().unwrap().clone())
            .collect();
        tasks.sort_by(|a, b| a.id.cmp(&b.id));
        tasks.truncate(MAX_TASKS);
        Report { tasks }
    }
}

async fn run(
    task: Task,
    base: Arc<str>,
    cancel: CancellationToken,
    status: Arc<Mutex<TaskReport>>,
    finished: Arc<Notify>,
) {
    let work = async {
        match task.role {
            TaskRole::Listen => listen(&task, &status).await,
            TaskRole::Dial => dial(&task, &status).await,
            TaskRole::Cloudflare => cloudflare(&task, &base, &status).await,
            TaskRole::Connect => connect(&task, &status).await,
        }
    };
    let outcome = tokio::select! {
        _ = cancel.cancelled() => {
            tracing::info!(id = %task.id, "speed test stopped");
            return;
        }
        outcome = timeout(task.params.hard_limit(), work) => outcome,
    };
    {
        let mut status = status.lock().unwrap();
        status.phase = None;
        status.current_bps = 0;
        match outcome {
            Ok(Ok(())) => status.state = TaskState::Finished,
            // A listener that was never stopped closes at the hard limit.
            Err(_) if task.role == TaskRole::Listen => status.state = TaskState::Finished,
            Err(_) => {
                status.state = TaskState::Failed;
                status.error = Some("the test did not finish in time".into());
            }
            Ok(Err(error)) => {
                status.state = TaskState::Failed;
                status.error = Some(clip(&format!("{error:#}")));
            }
        }
        tracing::info!(id = %task.id, state = ?status.state, error = ?status.error, "speed test ended");
    }
    finished.notify_one();
}

fn token(task: &Task) -> Result<[u8; TOKEN_BYTES]> {
    task.token
        .as_deref()
        .and_then(parse_token)
        .context("missing test token")
}

/// Fills `buffer` with bytes that do not compress.
fn payload(size: usize) -> Vec<u8> {
    let mut state = 0x9e37_79b9_7f4a_7c15u64;
    (0..size)
        .map(|_| {
            state ^= state << 13;
            state ^= state >> 7;
            state ^= state << 17;
            state as u8
        })
        .collect()
}

/// Errors of one direction's streams, without repeats.
#[derive(Default)]
struct Failures {
    count: u8,
    errors: Vec<String>,
}
impl Failures {
    fn add(&mut self, error: &anyhow::Error) {
        self.count = self.count.saturating_add(1);
        let text = clip(&format!("{error:#}"));
        if self.errors.len() < MAX_ERRORS && !self.errors.contains(&text) {
            self.errors.push(text);
        }
    }
}

fn result(
    direction: Direction,
    buckets: &Buckets,
    limit_ms: u64,
    streams: u8,
    failures: Failures,
) -> DirectionResult {
    let summary = summarize(&buckets.0, limit_ms);
    DirectionResult {
        direction,
        bytes: summary.bytes,
        measured_ms: summary.measured_ms,
        average_bps: summary.average_bps,
        peak_bps: summary.peak_bps,
        streams: streams.saturating_sub(failures.count),
        failed_streams: failures.count,
        errors: failures.errors,
        limited: false,
    }
}

/// Shows a direction's progress twice a second until `stop` is notified.
async fn progress(
    status: &Mutex<TaskReport>,
    direction: Direction,
    start: Instant,
    moved: &AtomicU64,
    stop: &Notify,
) {
    let mut recent: VecDeque<(Instant, u64)> = VecDeque::new();
    loop {
        let now = Instant::now();
        let total = moved.load(Ordering::Relaxed);
        recent.push_back((now, total));
        while recent
            .front()
            .is_some_and(|(at, _)| now.duration_since(*at) > Duration::from_millis(1100))
        {
            recent.pop_front();
        }
        let (since, before) = recent[0];
        let span = now.duration_since(since).as_millis() as u64;
        {
            let mut status = status.lock().unwrap();
            status.phase = Some(direction);
            status.elapsed_ms = now.duration_since(start).as_millis() as u64;
            status.bytes = total;
            status.current_bps = (total - before)
                .saturating_mul(8000)
                .checked_div(span)
                .unwrap_or(0);
        }
        tokio::select! {
            _ = stop.notified() => return,
            _ = sleep(Duration::from_millis(500)) => {}
        }
    }
}

// ---- Server ↔ server: the listening side ----

struct Listening {
    token: [u8; TOKEN_BYTES],
    params: Params,
    directions: Vec<Direction>,
    starts: Mutex<HashMap<Direction, Instant>>,
    seen: Mutex<HashSet<(Direction, u8)>>,
    done: AtomicUsize,
    all_done: Notify,
    rejected: AtomicU64,
}

async fn listen(task: &Task, status: &Arc<Mutex<TaskReport>>) -> Result<()> {
    let address = task.listen.context("missing listen address")?;
    let listener = TcpListener::bind(address)
        .await
        .with_context(|| format!("cannot listen on {address}"))?;
    let directions = task.params.direction.list();
    let expected = directions.len() * usize::from(task.params.streams);
    let state = Arc::new(Listening {
        token: token(task)?,
        params: task.params.clone(),
        directions,
        starts: Mutex::default(),
        seen: Mutex::default(),
        done: AtomicUsize::new(0),
        all_done: Notify::new(),
        rejected: AtomicU64::new(0),
    });
    let mut connections = JoinSet::new();
    let report_rejected = |state: &Listening| {
        status.lock().unwrap().rejected = state.rejected.load(Ordering::Relaxed);
    };
    // Closes the port once every expected stream ended; otherwise the
    // controller stops the task, or the hard limit ends it.
    while state.done.load(Ordering::SeqCst) < expected {
        tokio::select! {
            accepted = listener.accept() => {
                let Ok((stream, _)) = accepted else {
                    sleep(Duration::from_millis(100)).await;
                    continue;
                };
                if connections.len() >= MAX_CONNECTIONS {
                    state.rejected.fetch_add(1, Ordering::Relaxed);
                    report_rejected(&state);
                    continue;
                }
                let state = state.clone();
                connections.spawn(async move {
                    if serve(stream, &state).await.is_err() {
                        state.rejected.fetch_add(1, Ordering::Relaxed);
                    }
                });
            }
            Some(_) = connections.join_next(), if !connections.is_empty() => report_rejected(&state),
            _ = state.all_done.notified() => {}
        }
    }
    drop(listener);
    while connections.join_next().await.is_some() {}
    report_rejected(&state);
    Ok(())
}

/// Serves one connection. `Err` when it is not a stream of this test.
async fn serve(mut stream: TcpStream, state: &Listening) -> Result<(), ()> {
    let mut header = [0u8; HEADER_LEN];
    match timeout(Duration::from_secs(5), stream.read_exact(&mut header)).await {
        Ok(Ok(_)) => {}
        _ => return Err(()),
    }
    let Some((direction, index)) = check_header(&state.token, &header) else {
        return Err(());
    };
    if !state.directions.contains(&direction)
        || index >= state.params.streams
        || !state.seen.lock().unwrap().insert((direction, index))
    {
        return Err(());
    }
    let start = *state
        .starts
        .lock()
        .unwrap()
        .entry(direction)
        .or_insert_with(Instant::now);
    let limit = Duration::from_millis(state.params.limit_ms());
    let _ = match direction {
        Direction::Upload => {
            receive_upload(&mut stream, start, limit + Duration::from_secs(5)).await
        }
        Direction::Download => {
            send(
                &mut stream,
                start + limit,
                state.params.stream_bytes(),
                None,
            )
            .await
        }
    };
    if state.done.fetch_add(1, Ordering::SeqCst) + 1
        >= state.directions.len() * usize::from(state.params.streams)
    {
        state.all_done.notify_one();
    }
    Ok(())
}

/// Counts what the dialer sends until it closes, then replies with the
/// buckets so the dialer can report the result.
async fn receive_upload(stream: &mut TcpStream, start: Instant, patience: Duration) -> Result<()> {
    let deadline = start + patience;
    let mut buckets = Buckets::default();
    let mut buffer = vec![0u8; CHUNK];
    loop {
        let read = tokio::select! {
            read = stream.read(&mut buffer) => read?,
            _ = sleep_until(deadline) => break,
        };
        if read == 0 {
            break;
        }
        buckets.add(start.elapsed(), read as u64);
    }
    timeout(
        Duration::from_secs(10),
        stream.write_all(&encode_buckets(&buckets.0)),
    )
    .await??;
    stream.shutdown().await?;
    Ok(())
}

/// Sends until `deadline` or `bytes`, then closes the sending side.
async fn send(
    stream: &mut TcpStream,
    deadline: Instant,
    bytes: Option<u64>,
    moved: Option<&AtomicU64>,
) -> Result<()> {
    let data = payload(CHUNK);
    let mut left = bytes.unwrap_or(u64::MAX);
    while left > 0 && Instant::now() < deadline {
        let size = (left.min(CHUNK as u64)) as usize;
        tokio::select! {
            written = stream.write_all(&data[..size]) => written?,
            _ = sleep_until(deadline) => break,
        }
        left -= size as u64;
        if let Some(moved) = moved {
            moved.fetch_add(size as u64, Ordering::Relaxed);
        }
    }
    stream.shutdown().await?;
    Ok(())
}

// ---- Server ↔ server: the dialing side ----

async fn connect_patiently(address: &str, patience: Duration) -> Result<TcpStream> {
    let deadline = Instant::now() + patience;
    loop {
        let error = match timeout(Duration::from_secs(5), TcpStream::connect(address)).await {
            Ok(Ok(stream)) => return Ok(stream),
            Ok(Err(error)) => anyhow::Error::from(error),
            Err(_) => anyhow::anyhow!("connecting timed out after 5 s"),
        };
        if Instant::now() + Duration::from_millis(300) >= deadline {
            return Err(error.context(format!("cannot connect to {address}")));
        }
        sleep(Duration::from_millis(300)).await;
    }
}

async fn dial(task: &Task, status: &Arc<Mutex<TaskReport>>) -> Result<()> {
    let address = task.address.clone().context("missing address")?;
    let token = token(task)?;
    let params = &task.params;
    let limit = Duration::from_millis(params.limit_ms());
    let mut results = vec![];
    for (round, direction) in params.direction.list().into_iter().enumerate() {
        let opened = Instant::now();
        // The direction's clock starts when its first stream is through,
        // as the listener's does, so time spent waiting for the other
        // agent to open its listener does not shorten the test.
        let begun: Arc<Mutex<Option<Instant>>> = Arc::default();
        let moved = Arc::new(AtomicU64::new(0));
        let stop = Arc::new(Notify::new());
        let buckets = Arc::new(Mutex::new(Buckets::default()));
        let mut streams = JoinSet::new();
        for index in 0..params.streams {
            let (address, moved, buckets, begun) = (
                address.clone(),
                moved.clone(),
                buckets.clone(),
                begun.clone(),
            );
            let bytes = params.stream_bytes();
            // The first direction waits for the other agent's listener.
            let patience = if round == 0 {
                CONNECT_PATIENCE
            } else {
                Duration::from_secs(5)
            };
            streams.spawn(async move {
                let mut stream = connect_patiently(&address, patience).await?;
                stream.write_all(&header(&token, direction, index)).await?;
                let start = *begun.lock().unwrap().get_or_insert_with(Instant::now);
                match direction {
                    Direction::Upload => {
                        send(&mut stream, start + limit, bytes, Some(&moved)).await?;
                        let mut count = [0u8; 4];
                        timeout(Duration::from_secs(15), stream.read_exact(&mut count))
                            .await
                            .context("no result from the listening server")??;
                        let count = u32::from_be_bytes(count) as usize;
                        anyhow::ensure!(
                            count <= MAX_BUCKETS,
                            "invalid result from the listening server"
                        );
                        let mut raw = vec![0u8; count * 8];
                        timeout(Duration::from_secs(10), stream.read_exact(&mut raw))
                            .await
                            .context("no result from the listening server")??;
                        let received: Vec<u64> = raw
                            .as_chunks::<8>()
                            .0
                            .iter()
                            .map(|c| u64::from_be_bytes(*c))
                            .collect();
                        buckets.lock().unwrap().merge(&received);
                    }
                    Direction::Download => {
                        let deadline = start + limit + Duration::from_secs(10);
                        let mut buffer = vec![0u8; CHUNK];
                        loop {
                            let read = tokio::select! {
                                read = stream.read(&mut buffer) => read?,
                                _ = sleep_until(deadline) => break,
                            };
                            if read == 0 {
                                break;
                            }
                            buckets.lock().unwrap().add(start.elapsed(), read as u64);
                            moved.fetch_add(read as u64, Ordering::Relaxed);
                        }
                    }
                }
                Ok::<_, anyhow::Error>(())
            });
        }
        let mut failures = Failures::default();
        let watch = progress(status, direction, opened, &moved, &stop);
        let collect = async {
            while let Some(joined) = streams.join_next().await {
                match joined {
                    Ok(Ok(())) => {}
                    Ok(Err(error)) => failures.add(&error),
                    Err(error) => failures.add(&anyhow::Error::from(error)),
                }
            }
            stop.notify_one();
        };
        tokio::join!(watch, collect);
        let buckets = buckets.lock().unwrap().clone();
        results.push(result(
            direction,
            &buckets,
            params.limit_ms(),
            params.streams,
            failures,
        ));
        status.lock().unwrap().results = results.clone();
    }
    if results.iter().all(|r| r.failed_streams == params.streams) {
        bail!(
            "{}",
            results
                .iter()
                .flat_map(|r| r.errors.first())
                .next()
                .cloned()
                .unwrap_or_else(|| "every stream failed".into())
        );
    }
    Ok(())
}

// ---- Server ↔ public service ----

fn client() -> Result<reqwest::Client> {
    Ok(reqwest::Client::builder()
        .no_proxy()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(Duration::from_secs(10))
        .user_agent(concat!("relay-speed-test/", env!("CARGO_PKG_VERSION")))
        .build()?)
}

/// Whether the speed service's answer ends this stream. Cloudflare answers
/// HTTP 429 once a server has fetched a certain amount in a short time, so
/// a 429 after data moved in this direction is the end of what it will
/// serve, not a failed stream: `Ok(true)`, and the result is marked
/// limited. Before any data it is an error.
fn refused(status: reqwest::StatusCode, moved: &AtomicU64) -> Result<bool> {
    if status.is_success() {
        return Ok(false);
    }
    if status == reqwest::StatusCode::TOO_MANY_REQUESTS {
        anyhow::ensure!(
            moved.load(Ordering::Relaxed) > 0,
            "speed.cloudflare.com is limiting tests from this server (HTTP 429); try again in a few minutes"
        );
        return Ok(true);
    }
    bail!("the speed service answered HTTP {status}")
}

/// Downloads until the deadline or `left` bytes; true when the service
/// limited it ([`refused`]).
async fn download_stream(
    client: &reqwest::Client,
    base: &str,
    start: Instant,
    deadline: Instant,
    mut left: u64,
    buckets: &Mutex<Buckets>,
    moved: &AtomicU64,
) -> Result<bool> {
    while left > 0 && Instant::now() < deadline {
        let size = left.min(DOWNLOAD_REQUEST);
        let response = match timeout_at(
            deadline,
            client.get(format!("{base}/__down?bytes={size}")).send(),
        )
        .await
        {
            Ok(response) => response?,
            Err(_) => break,
        };
        if refused(response.status(), moved)? {
            return Ok(true);
        }
        let mut response = response;
        loop {
            let chunk = match timeout_at(deadline, response.chunk()).await {
                Ok(chunk) => chunk?,
                Err(_) => return Ok(false),
            };
            let Some(chunk) = chunk else { break };
            let read = chunk.len() as u64;
            buckets.lock().unwrap().add(start.elapsed(), read);
            moved.fetch_add(read, Ordering::Relaxed);
            left = left.saturating_sub(read);
        }
    }
    Ok(false)
}

/// Uploads until the deadline or `left` bytes; true when the service
/// limited it ([`refused`]).
async fn upload_stream(
    client: &reqwest::Client,
    base: &str,
    start: Instant,
    deadline: Instant,
    mut left: u64,
    buckets: &Mutex<Buckets>,
    moved: &AtomicU64,
) -> Result<bool> {
    // Requests grow while they finish quickly, so even a fast line is
    // measured with few requests, and shrink when they are slow, so a
    // slow line still has a result every second or two.
    let mut size = MIN_UPLOAD_REQUEST;
    while left > 0 && Instant::now() < deadline {
        let body = payload((size as u64).min(left) as usize);
        let sent = body.len() as u64;
        let begun = Instant::now();
        let response = match timeout_at(
            deadline,
            client.post(format!("{base}/__up")).body(body).send(),
        )
        .await
        {
            Ok(response) => response?,
            Err(_) => break,
        };
        if refused(response.status(), moved)? {
            return Ok(true);
        }
        buckets.lock().unwrap().add(start.elapsed(), sent);
        moved.fetch_add(sent, Ordering::Relaxed);
        left = left.saturating_sub(sent);
        let took = begun.elapsed();
        if took < Duration::from_millis(500) {
            size = (size * 2).min(MAX_UPLOAD_REQUEST);
        } else if took > Duration::from_secs(2) {
            size = (size / 2).max(MIN_UPLOAD_REQUEST);
        }
    }
    Ok(false)
}

async fn cloudflare(task: &Task, base: &str, status: &Arc<Mutex<TaskReport>>) -> Result<()> {
    let client = client()?;
    let params = &task.params;
    let limit = Duration::from_millis(params.limit_ms());
    let mut results = vec![];
    for direction in params.direction.list() {
        let start = Instant::now();
        let deadline = start + limit;
        let moved = AtomicU64::new(0);
        let stop = Notify::new();
        let buckets = Mutex::new(Buckets::default());
        let left = params.stream_bytes().unwrap_or(u64::MAX);
        let mut failures = Failures::default();
        let mut limited = false;
        let watch = progress(status, direction, start, &moved, &stop);
        let streams = async {
            let outcomes = futures_util::future::join_all((0..params.streams).map(|_| async {
                match direction {
                    Direction::Download => {
                        download_stream(&client, base, start, deadline, left, &buckets, &moved)
                            .await
                    }
                    Direction::Upload => {
                        upload_stream(&client, base, start, deadline, left, &buckets, &moved).await
                    }
                }
            }))
            .await;
            for outcome in outcomes {
                match outcome {
                    Ok(stopped) => limited |= stopped,
                    Err(error) => failures.add(&error),
                }
            }
            stop.notify_one();
        };
        tokio::join!(watch, streams);
        let buckets = buckets.into_inner().unwrap();
        let mut measured = result(
            direction,
            &buckets,
            params.limit_ms(),
            params.streams,
            failures,
        );
        measured.limited = limited;
        results.push(measured);
        status.lock().unwrap().results = results.clone();
    }
    if results.iter().all(|r| r.failed_streams == params.streams) {
        bail!(
            "{}",
            results
                .iter()
                .flat_map(|r| r.errors.first())
                .next()
                .cloned()
                .unwrap_or_else(|| "every stream failed".into())
        );
    }
    Ok(())
}

// ---- The last hop's target ----

async fn connect(task: &Task, status: &Arc<Mutex<TaskReport>>) -> Result<()> {
    let address = task.address.clone().context("missing address")?;
    let resolved: Vec<SocketAddr> =
        timeout(Duration::from_secs(5), tokio::net::lookup_host(&address))
            .await
            .context("resolving the target timed out")?
            .with_context(|| format!("cannot resolve {address}"))?
            .take(4)
            .collect();
    let mut last = anyhow::anyhow!("{address} has no address");
    for ip in resolved {
        let started = Instant::now();
        match timeout(Duration::from_secs(5), TcpStream::connect(ip)).await {
            Ok(Ok(stream)) => {
                let took = started.elapsed();
                drop(stream);
                status.lock().unwrap().connect_us = Some(took.as_micros().max(1) as u64);
                return Ok(());
            }
            Ok(Err(error)) => {
                last = anyhow::Error::from(error).context(format!("cannot connect to {ip}"))
            }
            Err(_) => last = anyhow::anyhow!("connecting to {ip} timed out after 5 s"),
        }
    }
    Err(last)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn task(role: TaskRole, port: u16) -> Task {
        Task {
            id: "late-listener".into(),
            role,
            params: Params {
                direction: Directions::Upload,
                duration_secs: Some(5),
                bytes: None,
                streams: 1,
            },
            listen: Some(SocketAddr::from(([127, 0, 0, 1], port))),
            address: Some(format!("127.0.0.1:{port}")),
            token: Some("ab".repeat(TOKEN_BYTES)),
        }
    }

    // The listening agent may get its task a little after the dialing one;
    // the dialer waits for it and the time waited is not taken from the test.
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_late_listener_does_not_shorten_the_test() {
        let port = std::net::TcpListener::bind("127.0.0.1:0")
            .unwrap()
            .local_addr()
            .unwrap()
            .port();
        let listening = tokio::spawn(async move {
            sleep(Duration::from_secs(2)).await;
            let status = Arc::new(Mutex::new(TaskReport::new("late-listener")));
            listen(&task(TaskRole::Listen, port), &status).await
        });
        let status = Arc::new(Mutex::new(TaskReport::new("late-listener")));
        dial(&task(TaskRole::Dial, port), &status).await.unwrap();
        listening.await.unwrap().unwrap();
        let results = status.lock().unwrap().results.clone();
        assert_eq!(results.len(), 1);
        let upload = &results[0];
        assert_eq!(upload.failed_streams, 0, "{upload:?}");
        // Without the fix the window is about 3 s: 5 s less the 2 s waited.
        assert!(upload.measured_ms >= 4_500, "{upload:?}");
        assert!(upload.bytes > 0 && upload.average_bps > 0, "{upload:?}");
    }

    /// A stand-in for the speed service that serves `served` downloads of
    /// 2 MB, then answers HTTP 429 as Cloudflare does once a server has
    /// fetched enough.
    async fn limiting_service(served: usize) -> String {
        use axum::{http::StatusCode, response::IntoResponse, routing::get};
        let count = Arc::new(AtomicUsize::new(0));
        let router = axum::Router::new().route(
            "/__down",
            get(move || {
                let count = count.clone();
                async move {
                    if count.fetch_add(1, Ordering::Relaxed) < served {
                        vec![7u8; 2_000_000].into_response()
                    } else {
                        StatusCode::TOO_MANY_REQUESTS.into_response()
                    }
                }
            }),
        );
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let origin = format!("http://{}", listener.local_addr().unwrap());
        tokio::spawn(async move { axum::serve(listener, router).await.unwrap() });
        origin
    }

    fn download() -> Task {
        Task {
            id: "limited".into(),
            role: TaskRole::Cloudflare,
            params: Params {
                direction: Directions::Download,
                duration_secs: Some(5),
                bytes: None,
                streams: 2,
            },
            listen: None,
            address: None,
            token: None,
        }
    }

    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_service_that_stops_serving_limits_the_result_instead_of_failing_it() {
        let status = Arc::new(Mutex::new(TaskReport::new("limited")));
        cloudflare(&download(), &limiting_service(4).await, &status)
            .await
            .unwrap();
        let down = status.lock().unwrap().results[0].clone();
        assert!(down.limited && down.failed_streams == 0, "{down:?}");
        assert_eq!(down.bytes, 8_000_000, "{down:?}");

        // Refused before any data: a failure that says to wait.
        let status = Arc::new(Mutex::new(TaskReport::new("limited")));
        let error = cloudflare(&download(), &limiting_service(0).await, &status)
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("try again in a few minutes"),
            "{error:#}"
        );
        let down = status.lock().unwrap().results[0].clone();
        assert!(!down.limited && down.failed_streams == 2, "{down:?}");
    }
}
