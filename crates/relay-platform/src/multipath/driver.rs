use super::{
    APP_BUFFER_BYTES, CHUNK_BYTES, Counters, Limits, MAX_PATHS, Mode,
    wire::{self, CopyKind, Frame, Job},
};
use crate::transport::BoxStream;
use anyhow::{Context as _, Result, bail, ensure};
use futures_util::task::AtomicWaker;
use std::{
    collections::BTreeMap,
    io,
    pin::Pin,
    sync::{
        Arc, Mutex,
        atomic::{AtomicUsize, Ordering},
    },
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt, DuplexStream, ReadBuf},
    sync::{mpsc, watch},
    task::{JoinHandle, JoinSet},
    time::{Instant, timeout},
};
use tokio_util::{sync::CancellationToken, task::TaskTracker};

pub(crate) struct Path {
    pub stream: BoxStream,
    pub slot: usize,
    pub send_weight: u16,
    pub receive_weight: u16,
}
#[derive(Default)]
struct Completion {
    local_fin: bool,
    remote_fin: bool,
    error: Option<String>,
}
#[derive(Default)]
struct Status {
    state: Mutex<Completion>,
    read: AtomicWaker,
    write: AtomicWaker,
}
impl Status {
    fn update(&self, update: impl FnOnce(&mut Completion)) {
        update(&mut self.state.lock().unwrap());
        self.read.wake();
        self.write.wake();
    }
}
struct Stream {
    io: DuplexStream,
    status: Arc<Status>,
    driver: JoinHandle<()>,
}
struct ExitGuard(Arc<Status>);
impl Drop for ExitGuard {
    fn drop(&mut self) {
        self.0.update(|status| {
            if status.error.is_none() && !(status.local_fin && status.remote_fin) {
                status.error = Some("multipath driver stopped before completing the stream".into());
            }
        });
    }
}
impl Drop for Stream {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
impl AsyncRead for Stream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buf.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        self.status.read.register(cx.waker());
        let before = buf.filled().len();
        ready!(Pin::new(&mut self.io).poll_read(cx, buf))?;
        if buf.filled().len() != before {
            return Poll::Ready(Ok(()));
        }
        let status = self.status.state.lock().unwrap();
        if let Some(error) = &status.error {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                error.clone(),
            )))
        } else if status.remote_fin {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}
impl AsyncWrite for Stream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        if let Some(error) = &self.status.state.lock().unwrap().error {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                error.clone(),
            )));
        }
        Pin::new(&mut self.io).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(error) = &self.status.state.lock().unwrap().error {
            return Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                error.clone(),
            )));
        }
        Pin::new(&mut self.io).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.status.write.register(cx.waker());
        ready!(Pin::new(&mut self.io).poll_shutdown(cx))?;
        let status = self.status.state.lock().unwrap();
        if let Some(error) = &status.error {
            Poll::Ready(Err(io::Error::new(
                io::ErrorKind::ConnectionReset,
                error.clone(),
            )))
        } else if status.local_fin {
            Poll::Ready(Ok(()))
        } else {
            Poll::Pending
        }
    }
}
struct SessionGuard(Arc<Counters>);
impl Drop for SessionGuard {
    fn drop(&mut self) {
        self.0.active_sessions.fetch_sub(1, Ordering::Relaxed);
    }
}
struct PathGuard(Arc<Counters>);
impl Drop for PathGuard {
    fn drop(&mut self) {
        self.0.active_paths.fetch_sub(1, Ordering::Relaxed);
    }
}
pub(crate) fn bridge(
    paths: Vec<Path>,
    limits: Limits,
    mode: Mode,
    stats: Arc<Counters>,
    tasks: TaskTracker,
    lifetime: Box<dyn Send>,
) -> BoxStream {
    let (app, driver_io) = tokio::io::duplex(APP_BUFFER_BYTES);
    let status = Arc::new(Status::default());
    let signal = status.clone();
    stats.sessions.fetch_add(1, Ordering::Relaxed);
    stats.active_sessions.fetch_add(1, Ordering::Relaxed);
    let guard = SessionGuard(stats.clone());
    let child_tasks = tasks.clone();
    let driver = tasks.spawn(async move {
        let (_guard, _lifetime) = (guard, lifetime);
        let _exit = ExitGuard(signal.clone());
        if let Err(error) = run(
            driver_io,
            paths,
            limits,
            mode,
            stats,
            signal.clone(),
            child_tasks,
        )
        .await
        {
            signal.update(|s| s.error = Some(error.to_string()));
        }
    });
    Box::new(Stream {
        io: app,
        status,
        driver,
    })
}

enum Event {
    Frame(usize, Frame),
    AckWritten(usize, u64),
    Writable,
    Failed(usize, bool),
}
struct Lane {
    slot: usize,
    weight: u16,
    receive_weight: u16,
    jobs: mpsc::Sender<Job>,
    ack: watch::Sender<(u64, [u8; 32])>,
    ack_written: u64,
    stop: CancellationToken,
    live: bool,
    pending_jobs: Arc<AtomicUsize>,
}
fn enqueue(lane: &Lane, job: Job) -> bool {
    lane.pending_jobs.fetch_add(1, Ordering::AcqRel);
    if lane.jobs.try_send(job).is_err() {
        lane.pending_jobs.fetch_sub(1, Ordering::AcqRel);
        return false;
    }
    true
}
fn start_path(
    path: Path,
    events: mpsc::Sender<Event>,
    stats: Arc<Counters>,
    workers: &mut JoinSet<()>,
    tasks: &TaskTracker,
    stall: Duration,
) -> Lane {
    let (jobs, mut receiver) = mpsc::channel::<Job>(1);
    let (ack, mut updates) = watch::channel((0, [0; 32]));
    let stop = CancellationToken::new();
    let token = stop.clone();
    let slot = path.slot;
    let pending_jobs = Arc::new(AtomicUsize::new(0));
    let lane = Lane {
        slot,
        weight: path.send_weight,
        receive_weight: path.receive_weight,
        jobs,
        ack,
        ack_written: 0,
        stop,
        live: true,
        pending_jobs: pending_jobs.clone(),
    };
    stats.active_paths.fetch_add(1, Ordering::Relaxed);
    let guard = PathGuard(stats.clone());
    workers.spawn(tasks.track_future(async move {
        let _guard = guard;
        let (mut reader, mut writer) = tokio::io::split(path.stream);
        let read = async {
            loop {
                match Frame::read(&mut reader).await {
                    Ok(frame) => {
                        if events.send(Event::Frame(slot, frame)).await.is_err() {
                            return false;
                        }
                    }
                    Err(error) => return !error.is::<io::Error>(),
                }
            }
        };
        let write = async {
            loop {
                let (frame, kind, acknowledgement) = tokio::select! {
                    changed = updates.changed() => {
                        if changed.is_err() { return; }
                        let (seq, received) = *updates.borrow_and_update();
                        (Arc::new(Frame::Ack(seq, received)), CopyKind::Primary, Some(seq))
                    }
                    job = receiver.recv() => {
                        let Some(job) = job else { return; };
                        (job.frame, job.kind, None)
                    }
                };
                if !matches!(
                    timeout(stall, wire::write(&mut writer, &frame, kind, slot, &stats)).await,
                    Ok(Ok(()))
                ) {
                    return;
                }
                if acknowledgement.is_none() {
                    pending_jobs.fetch_sub(1, Ordering::AcqRel);
                }
                let event =
                    acknowledgement.map_or(Event::Writable, |seq| Event::AckWritten(slot, seq));
                if events.send(event).await.is_err() {
                    return;
                }
            }
        };
        let fatal = tokio::select! {
            _ = token.cancelled() => return,
            fatal = read => fatal,
            _ = write => false,
        };
        let _ = events.send(Event::Failed(slot, fatal)).await;
    }));
    lane
}

struct Pending {
    frame: Arc<Frame>,
    sent: u8,
    last_path: usize,
    last_sent: Option<Instant>,
    received: bool,
}
fn broadcast_ack(lanes: &[Lane], sequence: u64, pending: &BTreeMap<u64, Arc<Frame>>) {
    let mut received = [0u8; 32];
    for &seq in pending.keys() {
        let offset = (seq - sequence) as usize;
        received[offset / 8] |= 1 << (offset % 8);
    }
    for lane in lanes.iter().filter(|l| l.live) {
        // send_replace wakes the writer even for repeated acknowledgements.
        lane.ack.send_replace((sequence, received));
    }
}
fn schedule(
    pending: &mut BTreeMap<u64, Pending>,
    lanes: &[Lane],
    mode: Mode,
    rto: Duration,
    cursor: &mut usize,
    busy_since: &mut [Option<Instant>; MAX_PATHS],
) {
    let mut assigned = [0u64; MAX_PATHS];
    for item in pending.values().filter(|item| !item.received) {
        for lane in lanes {
            if item.sent & (1 << lane.slot) != 0 {
                assigned[lane.slot] += item.frame.payload().len().max(1) as u64;
            }
        }
    }
    let now = Instant::now();
    for lane in lanes {
        if lane.jobs.capacity() > 0 {
            busy_since[lane.slot] = None;
        } else {
            busy_since[lane.slot].get_or_insert(now);
        }
    }
    for item in pending.values_mut() {
        if item.received {
            continue;
        }
        // Do not let FIN overtake queued copies on another live path.
        if matches!(item.frame.as_ref(), Frame::Fin(_))
            && lanes
                .iter()
                .any(|lane| lane.live && lane.pending_jobs.load(Ordering::Acquire) != 0)
        {
            continue;
        }
        let fresh = item.sent == 0;
        if !fresh
            && item
                .last_sent
                .is_some_and(|at| now.duration_since(at) < rto)
        {
            continue;
        }
        let available: Vec<_> = lanes
            .iter()
            .filter(|lane| lane.live && lane.weight > 0 && lane.jobs.capacity() > 0)
            .collect();
        if available.is_empty() {
            return;
        }
        if fresh && mode == Mode::Replicate {
            let enabled = lanes
                .iter()
                .filter(|lane| lane.live && lane.weight > 0)
                .count();
            if available.len() != enabled {
                return;
            }
            for (index, lane) in available.iter().enumerate() {
                let kind = if index == 0 {
                    CopyKind::Primary
                } else {
                    CopyKind::Replica
                };
                if enqueue(
                    lane,
                    Job {
                        frame: item.frame.clone(),
                        kind,
                    },
                ) {
                    item.sent |= 1 << lane.slot;
                    item.last_path = lane.slot;
                    assigned[lane.slot] += item.frame.payload().len().max(1) as u64;
                }
            }
        } else {
            // A short scheduling delay in the preferred writer must not turn
            // directional weights into equal alternation. A persistently full
            // queue is excluded after one RTO so another live path can progress.
            let candidates: Vec<_> = if fresh {
                lanes
                    .iter()
                    .filter(|lane| {
                        lane.live
                            && lane.weight > 0
                            && busy_since[lane.slot]
                                .is_none_or(|since| now.duration_since(since) < rto)
                    })
                    .collect()
            } else {
                available.clone()
            };
            if candidates.is_empty() {
                return;
            }
            let different = !fresh && candidates.iter().any(|l| l.slot != item.last_path);
            let lane = candidates
                .iter()
                .copied()
                .filter(|l| !different || l.slot != item.last_path)
                .min_by(|a, b| {
                    (assigned[a.slot] * u64::from(b.weight))
                        .cmp(&(assigned[b.slot] * u64::from(a.weight)))
                        .then_with(|| {
                            ((a.slot + MAX_PATHS - *cursor) % MAX_PATHS)
                                .cmp(&((b.slot + MAX_PATHS - *cursor) % MAX_PATHS))
                        })
                })
                .unwrap();
            if lane.jobs.capacity() == 0 {
                return;
            }
            let kind = if fresh {
                CopyKind::Primary
            } else {
                CopyKind::Retransmission
            };
            if enqueue(
                lane,
                Job {
                    frame: item.frame.clone(),
                    kind,
                },
            ) {
                item.sent |= 1 << lane.slot;
                item.last_path = lane.slot;
                *cursor = (lane.slot + 1) % MAX_PATHS;
                assigned[lane.slot] += item.frame.payload().len().max(1) as u64;
            }
        }
        item.last_sent = Some(now);
    }
}

async fn run(
    app: DuplexStream,
    paths: Vec<Path>,
    limits: Limits,
    mode: Mode,
    stats: Arc<Counters>,
    status: Arc<Status>,
    tasks: TaskTracker,
) -> Result<()> {
    let mut workers = JoinSet::new();
    let (events, mut incoming) = mpsc::channel(4 * MAX_PATHS);
    let stall = Duration::from_millis(limits.stall_timeout_ms);
    let rto = Duration::from_millis(limits.retransmit_ms);
    let mut lanes: Vec<_> = paths
        .into_iter()
        .map(|p| {
            start_path(
                p,
                events.clone(),
                stats.clone(),
                &mut workers,
                &tasks,
                stall,
            )
        })
        .collect();
    drop(events);
    let (mut app_read, mut app_write) = tokio::io::split(app);
    let mut buffer = vec![0; CHUNK_BYTES];
    let mut send: BTreeMap<u64, Pending> = BTreeMap::new();
    let mut receive: BTreeMap<u64, Arc<Frame>> = BTreeMap::new();
    let (mut tx_next, mut tx_ack, mut rx_next) = (0u64, 0u64, 0u64);
    let (mut tx_bytes, mut rx_bytes, mut rx_offset) = (0usize, 0usize, 0usize);
    let (mut local_fin, mut remote_fin) = (None, None);
    let mut remote_fin_delivered = false;
    let mut progress = Instant::now();
    let mut cursor = 0;
    let mut busy_since = [None; MAX_PATHS];
    let mut timer = tokio::time::interval(rto / 2);
    timer.set_missed_tick_behavior(tokio::time::MissedTickBehavior::Skip);
    loop {
        let local_done = local_fin.is_some_and(|sequence| tx_ack > sequence)
            && lanes
                .iter()
                .filter(|l| l.live)
                .all(|l| l.pending_jobs.load(Ordering::Acquire) == 0);
        let remote_done = remote_fin_delivered
            && lanes
                .iter()
                .filter(|l| l.live)
                .all(|l| l.ack_written >= rx_next);
        if local_done || remote_done {
            status.update(|s| {
                s.local_fin |= local_done;
                s.remote_fin |= remote_done;
            });
        }
        if local_done && remote_done {
            return Ok(());
        }
        ensure!(lanes.iter().any(|l| l.live), "all multipath paths failed");
        ensure!(
            local_done || lanes.iter().any(|l| l.live && l.weight > 0),
            "no multipath sending path remains"
        );
        ensure!(
            remote_fin_delivered || lanes.iter().any(|l| l.live && l.receive_weight > 0),
            "no multipath receiving path remains"
        );
        if matches!(receive.get(&rx_next).map(Arc::as_ref), Some(Frame::Fin(_))) {
            receive.remove(&rx_next);
            rx_next = rx_next
                .checked_add(1)
                .context("multipath receive sequence overflow")?;
            remote_fin_delivered = true;
            app_write.shutdown().await?;
            broadcast_ack(&lanes, rx_next, &receive);
            continue;
        }
        schedule(&mut send, &lanes, mode, rto, &mut cursor, &mut busy_since);
        let delivery = receive.get(&rx_next).cloned();
        let payload = delivery.as_deref().map(Frame::payload).unwrap_or(&[]);
        tokio::select! {
            result = app_read.read(&mut buffer), if local_fin.is_none() && tx_next - tx_ack < u64::from(limits.window_frames) => {
                let n = result?;
                let sequence = tx_next;
                tx_next = tx_next.checked_add(1).context("multipath send sequence overflow")?;
                let frame = if n == 0 { local_fin = Some(sequence); Frame::Fin(sequence) }
                    else { Frame::Data { sequence, bytes: buffer[..n].into() } };
                if send.is_empty() { progress = Instant::now(); }
                tx_bytes += n;
                stats.peak_send_window_bytes.fetch_max(tx_bytes as u64, Ordering::Relaxed);
                send.insert(sequence, Pending { frame: Arc::new(frame), sent: 0, last_path: 0, last_sent: None, received: false });
            }
            result = app_write.write(&payload[rx_offset..]), if !payload.is_empty() => {
                let n = result?;
                ensure!(n > 0, "multipath application stopped reading");
                rx_offset += n;
                if rx_offset == payload.len() {
                    rx_bytes -= payload.len();
                    stats.delivered_payload_bytes.fetch_add(payload.len() as u64, Ordering::Relaxed);
                    receive.remove(&rx_next);
                    rx_next = rx_next.checked_add(1).context("multipath receive sequence overflow")?;
                    rx_offset = 0;
                    broadcast_ack(&lanes, rx_next, &receive);
                }
            }
            event = incoming.recv() => match event.context("multipath path workers stopped")? {
                Event::Writable => {},
                Event::AckWritten(slot, seq) => {
                    let lane = lanes.iter_mut().find(|l| l.slot == slot).unwrap();
                    lane.ack_written = lane.ack_written.max(seq);
                }
                Event::Failed(slot, fatal) => {
                    ensure!(!fatal, "invalid multipath frame");
                    let lane = lanes.iter_mut().find(|l| l.slot == slot).unwrap();
                    if lane.live {
                        lane.live = false; lane.stop.cancel();
                        if !(remote_fin_delivered && local_fin.is_some_and(|sequence| tx_ack > sequence)) {
                            stats.failed_paths.fetch_add(1, Ordering::Relaxed);
                        }
                        for item in send.values_mut().filter(|p| p.sent & (1 << slot) != 0) { item.last_sent = None; }
                    }
                }
                Event::Frame(slot, Frame::Ack(sequence, received)) => {
                    let _ = slot;
                    ensure!(sequence <= tx_next && send.range(..sequence).all(|(_, item)| item.sent != 0),
                        "multipath peer acknowledged unsent data");
                    for offset in 0..256 {
                        if received[offset / 8] & (1 << (offset % 8)) == 0 { continue; }
                        ensure!(offset < usize::from(limits.window_frames), "multipath receipt exceeds negotiated window");
                        let seq = sequence.checked_add(offset as u64).context("multipath receipt overflow")?;
                        ensure!(seq < tx_next, "multipath receipt names unsent data");
                        if let Some(item) = send.get_mut(&seq) {
                            ensure!(item.sent != 0, "multipath receipt names an unscheduled frame");
                            item.received = true;
                        }
                    }
                    if sequence > tx_ack {
                        tx_ack = sequence; progress = Instant::now();
                        while send.first_key_value().is_some_and(|(&seq, _)| seq < tx_ack) {
                            tx_bytes -= send.pop_first().unwrap().1.frame.payload().len();
                        }
                    }
                }
                Event::Frame(slot, frame) => {
                    let length = frame.payload().len();
                    stats.received_payload_bytes.fetch_add(length as u64, Ordering::Relaxed);
                    ensure!(length == 0 || lanes.iter().find(|l| l.slot == slot).unwrap().receive_weight > 0,
                        "multipath peer used a disabled direction");
                    let sequence = frame.sequence();
                    if sequence < rx_next {
                        stats.duplicate_payload_bytes.fetch_add(length as u64, Ordering::Relaxed);
                        broadcast_ack(&lanes, rx_next, &receive);
                        continue;
                    }
                    ensure!(!remote_fin_delivered && sequence - rx_next < u64::from(limits.window_frames),
                        "multipath receive window exceeded");
                    if let Frame::Fin(_) = frame {
                        ensure!(remote_fin.is_none_or(|at| at == sequence)
                            && receive.last_key_value().is_none_or(|(&seq, _)| seq <= sequence),
                            "inconsistent multipath FIN");
                        remote_fin = Some(sequence);
                    } else {
                        ensure!(remote_fin.is_none_or(|end| sequence < end), "multipath data after FIN");
                    }
                    if let Some(previous) = receive.get(&sequence) {
                        ensure!(previous.as_ref() == &frame, "inconsistent multipath retransmission");
                        stats.duplicate_payload_bytes.fetch_add(length as u64, Ordering::Relaxed);
                    } else {
                        rx_bytes += length;
                        stats.peak_reorder_bytes.fetch_max(rx_bytes as u64, Ordering::Relaxed);
                        receive.insert(sequence, Arc::new(frame));
                    }
                    broadcast_ack(&lanes, rx_next, &receive);
                }
            },
            _ = timer.tick() => {
                if !send.is_empty() && progress.elapsed() >= stall { bail!("multipath acknowledgement stalled"); }
                // Recover a lost cumulative ACK even when every frame was selectively received.
                if rx_next > 0 || !receive.is_empty() { broadcast_ack(&lanes, rx_next, &receive); }
            }
        }
    }
}
