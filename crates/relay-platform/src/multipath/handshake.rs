use super::{ClientConfig, Counters, Limits, MAX_PATHS, Mode, Path, ServerConfig, bridge};
use crate::{proxy::ConnectionInfo, transport::BoxStream};
use anyhow::{Context as _, Result, ensure};
use rand::RngCore;
use std::{
    collections::HashMap,
    sync::{Arc, Mutex},
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    sync::{OwnedSemaphorePermit, Semaphore, mpsc},
};
use tokio_util::task::TaskTracker;

const HELLO: &[u8; 8] = b"RLYMP001";
const REPLY: &[u8; 8] = b"RLYMPA01";
const BEGIN: &[u8; 8] = b"RLYMPS01";
const READY: &[u8; 8] = b"RLYMPOK1";
const CREATE: u8 = 1;
const JOIN: u8 = 2;
type Key = ([u8; 32], [u8; 32]); // authenticated leaf certificate, random client session
struct Hello {
    kind: u8,
    slot: usize,
    mode: Mode,
    window: u16,
    upload: u16,
    download: u16,
    session: [u8; 32],
    token: [u8; 32],
}
impl Hello {
    async fn read(stream: &mut BoxStream) -> Result<Self> {
        let mut bytes = [0; 84];
        stream.read_exact(&mut bytes).await?;
        ensure!(
            &bytes[..8] == HELLO && bytes[11] == 0 && bytes[18..20] == [0; 2],
            "invalid multipath handshake"
        );
        ensure!(
            matches!(bytes[8], CREATE | JOIN) && usize::from(bytes[9]) < MAX_PATHS,
            "invalid multipath handshake operation or path"
        );
        let mode = match bytes[10] {
            0 => Mode::Stripe,
            1 => Mode::Replicate,
            _ => anyhow::bail!("invalid multipath mode"),
        };
        let result = Self {
            kind: bytes[8],
            slot: usize::from(bytes[9]),
            mode,
            window: u16::from_be_bytes(bytes[12..14].try_into().unwrap()),
            upload: u16::from_be_bytes(bytes[14..16].try_into().unwrap()),
            download: u16::from_be_bytes(bytes[16..18].try_into().unwrap()),
            session: bytes[20..52].try_into().unwrap(),
            token: bytes[52..84].try_into().unwrap(),
        };
        ensure!(
            (4..=256).contains(&result.window)
                && result.upload <= 1000
                && result.download <= 1000
                && (result.upload > 0 || result.download > 0)
                && result.session != [0; 32],
            "invalid multipath handshake limits"
        );
        Ok(result)
    }
    async fn write(&self, stream: &mut BoxStream) -> Result<()> {
        let mut bytes = [0; 84];
        bytes[..8].copy_from_slice(HELLO);
        bytes[8] = self.kind;
        bytes[9] = self.slot as u8;
        bytes[10] = if self.mode == Mode::Stripe { 0 } else { 1 };
        bytes[12..14].copy_from_slice(&self.window.to_be_bytes());
        bytes[14..16].copy_from_slice(&self.upload.to_be_bytes());
        bytes[16..18].copy_from_slice(&self.download.to_be_bytes());
        bytes[20..52].copy_from_slice(&self.session);
        bytes[52..84].copy_from_slice(&self.token);
        stream.write_all(&bytes).await?;
        stream.flush().await?;
        Ok(())
    }
}
async fn reply(stream: &mut BoxStream, window: u16, token: &[u8; 32]) -> Result<()> {
    let mut bytes = [0; 42];
    bytes[..8].copy_from_slice(REPLY);
    bytes[8..10].copy_from_slice(&window.to_be_bytes());
    bytes[10..].copy_from_slice(token);
    stream.write_all(&bytes).await?;
    stream.flush().await?;
    Ok(())
}
async fn read_reply(stream: &mut BoxStream) -> Result<(u16, [u8; 32])> {
    let mut bytes = [0; 42];
    stream.read_exact(&mut bytes).await?;
    ensure!(&bytes[..8] == REPLY, "multipath server handshake mismatch");
    Ok((
        u16::from_be_bytes(bytes[8..10].try_into().unwrap()),
        bytes[10..].try_into().unwrap(),
    ))
}
fn equal_token(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter()
        .zip(b)
        .fold(0u8, |difference, (a, b)| difference | (a ^ b))
        == 0
}
struct Entry {
    token: [u8; 32],
    window: u16,
    mode: Mode,
    mask: u8,
    sealed: bool,
    source: Option<ConnectionInfo>,
    sender: mpsc::Sender<Path>,
}
struct Lease {
    registry: Arc<Mutex<HashMap<Key, Entry>>>,
    key: Key,
    _permit: OwnedSemaphorePermit,
}
impl Drop for Lease {
    fn drop(&mut self) {
        self.registry.lock().unwrap().remove(&self.key);
    }
}
pub(crate) struct Server {
    spec: ServerConfig,
    sessions: Arc<Semaphore>,
    registry: Arc<Mutex<HashMap<Key, Entry>>>,
}
impl Server {
    pub(crate) fn new(spec: ServerConfig) -> Self {
        Self {
            sessions: Arc::new(Semaphore::new(usize::from(spec.limits.max_sessions))),
            spec,
            registry: Arc::new(Mutex::new(HashMap::new())),
        }
    }
    /// Caller supplies the verified outer TLS identity, never a PROXY or wire identity.
    /// Some returns the single reassembled application stream. None is a joined subflow.
    pub(crate) async fn accept(
        &self,
        mut stream: BoxStream,
        certificate: [u8; 32],
        source: Option<ConnectionInfo>,
        stats: Arc<Counters>,
        tasks: TaskTracker,
    ) -> Result<Option<BoxStream>> {
        let hello = Hello::read(&mut stream).await?;
        let key = (certificate, hello.session);
        if hello.kind == JOIN {
            let sender = {
                let mut registry = self.registry.lock().unwrap();
                let entry = registry
                    .get_mut(&key)
                    .context("unknown multipath session or TLS identity")?;
                ensure!(
                    !entry.sealed
                        && equal_token(&entry.token, &hello.token)
                        && entry.source == source
                        && entry.mode == hello.mode
                        && entry.window == hello.window,
                    "multipath join credentials or parameters differ"
                );
                ensure!(
                    entry.mask & (1 << hello.slot) == 0
                        && entry.mask.count_ones() < u32::from(self.spec.max_paths),
                    "multipath path slot already used or limit reached"
                );
                entry.mask |= 1 << hello.slot;
                entry.sender.clone()
            };
            reply(&mut stream, hello.window, &hello.token).await?;
            sender
                .send(Path {
                    stream,
                    slot: hello.slot,
                    send_weight: hello.download,
                    receive_weight: hello.upload,
                })
                .await
                .map_err(|_| anyhow::anyhow!("multipath session setup was cancelled"))?;
            return Ok(None);
        }
        ensure!(
            hello.token == [0; 32],
            "multipath create must not contain a join token"
        );
        ensure!(
            hello.mode != Mode::Replicate || self.spec.allow_replication,
            "multipath replication is disabled at the server"
        );
        let permit = self
            .sessions
            .clone()
            .try_acquire_owned()
            .context("multipath server session limit reached")?;
        let window = self.spec.limits.window_frames.min(hello.window);
        let mut token = [0; 32];
        rand::thread_rng().fill_bytes(&mut token);
        let (sender, mut joined) = mpsc::channel(MAX_PATHS);
        {
            let mut registry = self.registry.lock().unwrap();
            ensure!(
                !registry.contains_key(&key),
                "multipath session already exists"
            );
            registry.insert(
                key,
                Entry {
                    token,
                    window,
                    mode: hello.mode,
                    mask: 1 << hello.slot,
                    sealed: false,
                    source,
                    sender,
                },
            );
        }
        let lease = Lease {
            registry: self.registry.clone(),
            key,
            _permit: permit,
        };
        reply(&mut stream, window, &token).await?;
        let mut begin = [0; 9];
        stream.read_exact(&mut begin).await?;
        ensure!(
            &begin[..8] == BEGIN && begin[8] & (1 << hello.slot) != 0,
            "multipath start must include its original path"
        );
        {
            let mut registry = self.registry.lock().unwrap();
            let entry = registry
                .get_mut(&key)
                .context("multipath setup disappeared")?;
            ensure!(
                begin[8] & !entry.mask == 0,
                "multipath start references an unregistered path"
            );
            entry.sealed = true;
        }
        let mut paths = vec![Path {
            stream,
            slot: hello.slot,
            send_weight: hello.download,
            receive_weight: hello.upload,
        }];
        let mut received = 1 << hello.slot;
        while received != begin[8] {
            let path = joined
                .recv()
                .await
                .context("multipath join channel closed")?;
            if begin[8] & (1 << path.slot) != 0 {
                received |= 1 << path.slot;
                paths.push(path);
            }
        }
        ensure!(
            paths.iter().any(|p| p.send_weight > 0) && paths.iter().any(|p| p.receive_weight > 0),
            "multipath setup lacks a direction"
        );
        paths[0].stream.write_all(READY).await?;
        paths[0].stream.flush().await?;
        let mut limits = self.spec.limits.clone();
        limits.window_frames = window;
        Ok(Some(bridge(
            paths,
            limits,
            hello.mode,
            stats,
            tasks,
            Box::new(lease),
        )))
    }
}

pub(crate) struct Client {
    session: [u8; 32],
    token: [u8; 32],
    limits: Limits,
    mode: Mode,
    min_paths: u8,
}
impl Client {
    pub(crate) async fn create(mut path: Path, spec: &ClientConfig) -> Result<(Self, Path)> {
        let mut session = [0; 32];
        rand::thread_rng().fill_bytes(&mut session);
        let hello = Hello {
            kind: CREATE,
            slot: path.slot,
            mode: spec.mode,
            window: spec.limits.window_frames,
            upload: path.send_weight,
            download: path.receive_weight,
            session,
            token: [0; 32],
        };
        hello.write(&mut path.stream).await?;
        let (window, token) = read_reply(&mut path.stream).await?;
        ensure!(
            (4..=spec.limits.window_frames).contains(&window) && token != [0; 32],
            "invalid multipath negotiated window or token"
        );
        let mut limits = spec.limits.clone();
        limits.window_frames = window;
        Ok((
            Self {
                session,
                token,
                limits,
                mode: spec.mode,
                min_paths: spec.min_paths,
            },
            path,
        ))
    }
    pub(crate) async fn join(&self, mut path: Path) -> Result<Path> {
        Hello {
            kind: JOIN,
            slot: path.slot,
            mode: self.mode,
            window: self.limits.window_frames,
            upload: path.send_weight,
            download: path.receive_weight,
            session: self.session,
            token: self.token,
        }
        .write(&mut path.stream)
        .await?;
        let (window, token) = read_reply(&mut path.stream).await?;
        ensure!(
            window == self.limits.window_frames && equal_token(&self.token, &token),
            "multipath join reached a different session"
        );
        Ok(path)
    }
    pub(crate) async fn finish(
        self,
        mut paths: Vec<Path>,
        stats: Arc<Counters>,
        tasks: TaskTracker,
        lifetime: Box<dyn Send>,
    ) -> Result<BoxStream> {
        ensure!(
            paths.len() >= usize::from(self.min_paths)
                && paths.iter().any(|p| p.send_weight > 0)
                && paths.iter().any(|p| p.receive_weight > 0),
            "multipath initial path requirement not met"
        );
        let mask = paths.iter().fold(0u8, |mask, p| mask | (1 << p.slot));
        let mut begin = [0; 9];
        begin[..8].copy_from_slice(BEGIN);
        begin[8] = mask;
        paths[0].stream.write_all(&begin).await?;
        paths[0].stream.flush().await?;
        let mut ready = [0; 8];
        paths[0].stream.read_exact(&mut ready).await?;
        ensure!(&ready == READY, "multipath server did not confirm setup");
        Ok(bridge(
            paths,
            self.limits,
            self.mode,
            stats,
            tasks,
            lifetime,
        ))
    }
}
