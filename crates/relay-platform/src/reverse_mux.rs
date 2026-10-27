//! Single-connection multiplexed reverse TCP tunnel.
//!
//! The control connection carries length-prefixed frames for many public
//! connections. This is separate from the legacy line protocol in `reverse`;
//! the legacy commands keep their one-public-connection-per-control behavior.
use anyhow::{Context, Result, bail, ensure};
use std::{
    collections::HashMap,
    net::SocketAddr,
    sync::{
        Arc,
        atomic::{AtomicU32, Ordering},
    },
    time::Duration,
};
use tokio::{
    io::{AsyncReadExt, AsyncWriteExt},
    net::{
        TcpListener, TcpStream,
        tcp::{OwnedReadHalf, OwnedWriteHalf},
    },
    sync::{Mutex, mpsc, oneshot},
};
use tokio_util::sync::CancellationToken;

const MAX_LINE: usize = 512;
const MAX_FRAME: usize = 64 * 1024;
const READY: &str = "READY";
const DENY: &str = "DENY";
const OPEN: u8 = 1;
const OK: u8 = 2;
const FAIL: u8 = 3;
const DATA: u8 = 4;
const FIN: u8 = 5;
const RESET: u8 = 6;
const OPEN_TIMEOUT: Duration = Duration::from_secs(5);

type Writer = Arc<Mutex<OwnedWriteHalf>>;
type Sessions = Arc<Mutex<HashMap<u32, mpsc::Sender<(u8, Vec<u8>)>>>>;
type Frame = (u8, u32, Vec<u8>);

pub async fn serve_mux(control: TcpListener, public: TcpListener, token: String) -> Result<()> {
    ensure!(
        !token.is_empty() && token.len() <= 256,
        "reverse token must be 1..256 bytes"
    );
    let public = Arc::new(public);
    loop {
        let (mut control_stream, peer) = control.accept().await?;
        let authorized = match read_line(&mut control_stream).await {
            Ok(line) => line == format!("REVERSE-MUX {token}"),
            Err(_) => false,
        };
        if !authorized {
            let _ = control_stream.write_all(b"DENY\n").await;
            tracing::warn!(%peer, "reverse mux authentication failed");
            continue;
        }
        if control_stream.write_all(b"READY\n").await.is_err() {
            continue;
        }
        tracing::info!(%peer, "reverse mux client connected");
        let public = public.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_control(control_stream, public).await {
                tracing::warn!(%error, "reverse mux control ended");
            }
        });
    }
}

async fn serve_control(control: TcpStream, public: Arc<TcpListener>) -> Result<()> {
    control.set_nodelay(true).ok();
    let (reader, writer) = control.into_split();
    let writer: Writer = Arc::new(Mutex::new(writer));
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    let responses: Arc<Mutex<HashMap<u32, oneshot::Sender<bool>>>> =
        Arc::new(Mutex::new(HashMap::new()));
    let cancel = CancellationToken::new();
    let read_task = tokio::spawn(read_frames(
        reader,
        sessions.clone(),
        responses.clone(),
        cancel.clone(),
    ));
    let next_id = AtomicU32::new(1);
    let result: Result<()> = loop {
        let (mut exposed, peer) = tokio::select! {
            accepted = public.accept() => match accepted { Ok(pair) => pair, Err(error) => break Err(error.into()) },
            _ = cancel.cancelled() => break Ok(()),
        };
        let id = next_id.fetch_add(1, Ordering::Relaxed);
        let (data_tx, data_rx) = mpsc::channel(32);
        let (response_tx, response_rx) = oneshot::channel();
        sessions.lock().await.insert(id, data_tx);
        responses.lock().await.insert(id, response_tx);
        if let Err(error) = write_frame(&writer, OPEN, id, &[]).await {
            sessions.lock().await.remove(&id);
            responses.lock().await.remove(&id);
            let _ = exposed.shutdown().await;
            break Err(error.into());
        }
        let opened = tokio::time::timeout(OPEN_TIMEOUT, response_rx)
            .await
            .ok()
            .and_then(Result::ok)
            .unwrap_or(false);
        if !opened {
            sessions.lock().await.remove(&id);
            responses.lock().await.remove(&id);
            let _ = exposed.shutdown().await;
            tracing::warn!(%peer, "reverse mux client did not open the target");
            continue;
        }
        let writer = writer.clone();
        let sessions = sessions.clone();
        let cancel = cancel.clone();
        tokio::spawn(async move {
            if let Err(error) = bridge_public(id, exposed, data_rx, writer, sessions, cancel).await
            {
                tracing::debug!(%error, "reverse mux public bridge ended");
            }
        });
    };
    cancel.cancel();
    let _ = read_task.await;
    result
}

async fn bridge_public(
    id: u32,
    exposed: TcpStream,
    mut frames: mpsc::Receiver<(u8, Vec<u8>)>,
    writer: Writer,
    sessions: Sessions,
    cancel: CancellationToken,
) -> Result<()> {
    exposed.set_nodelay(true).ok();
    let (mut reader, mut writer_stream) = exposed.into_split();
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        tokio::select! {
            read = reader.read(&mut buffer) => match read {
                Ok(0) => { let _ = write_frame(&writer, FIN, id, &[]).await; break; }
                Ok(size) => if write_frame(&writer, DATA, id, &buffer[..size]).await.is_err() { break; }
                Err(_) => { let _ = write_frame(&writer, RESET, id, &[]).await; break; }
            },
            frame = frames.recv() => match frame {
                Some((DATA, payload)) => if writer_stream.write_all(&payload).await.is_err() { break; },
                Some((FIN, _)) => { let _ = writer_stream.shutdown().await; break; }
                Some((RESET, _)) | None => break,
                _ => {}
            },
            _ = cancel.cancelled() => break,
        }
    }
    sessions.lock().await.remove(&id);
    Ok(())
}

async fn read_frames(
    mut reader: OwnedReadHalf,
    sessions: Sessions,
    responses: Arc<Mutex<HashMap<u32, oneshot::Sender<bool>>>>,
    cancel: CancellationToken,
) {
    loop {
        match read_frame(&mut reader).await {
            Ok(Some((kind, id, payload))) => match kind {
                OK | FAIL => {
                    if let Some(response) = responses.lock().await.remove(&id) {
                        let _ = response.send(kind == OK);
                    }
                }
                DATA | FIN | RESET => {
                    let sender = sessions.lock().await.get(&id).cloned();
                    if let Some(sender) = sender {
                        let _ = sender.send((kind, payload)).await;
                    }
                }
                _ => {}
            },
            _ => {
                cancel.cancel();
                return;
            }
        }
    }
}

pub async fn client_mux(server: SocketAddr, target: String, token: String) -> Result<()> {
    ensure!(
        !token.is_empty() && token.len() <= 256,
        "reverse token must be 1..256 bytes"
    );
    let mut control = TcpStream::connect(server)
        .await
        .with_context(|| format!("connect reverse mux server {server}"))?;
    control.set_nodelay(true).ok();
    control
        .write_all(format!("REVERSE-MUX {token}\n").as_bytes())
        .await?;
    let reply = read_line(&mut control).await?;
    match reply.as_str() {
        READY => {}
        DENY => bail!("reverse mux server rejected the token"),
        other => bail!("unexpected reverse mux handshake: {other}"),
    }
    let (reader, writer) = control.into_split();
    let writer: Writer = Arc::new(Mutex::new(writer));
    let sessions: Sessions = Arc::new(Mutex::new(HashMap::new()));
    let cancel = CancellationToken::new();
    let read_task = tokio::spawn(client_read_loop(
        reader,
        target,
        writer.clone(),
        sessions.clone(),
        cancel.clone(),
    ));
    let _ = read_task.await;
    cancel.cancel();
    Ok(())
}

async fn client_read_loop(
    mut reader: OwnedReadHalf,
    target: String,
    writer: Writer,
    sessions: Sessions,
    cancel: CancellationToken,
) {
    loop {
        match read_frame(&mut reader).await {
            Ok(Some((OPEN, id, _))) => {
                let (data_tx, data_rx) = mpsc::channel(32);
                sessions.lock().await.insert(id, data_tx);
                let target = target.clone();
                let writer = writer.clone();
                let sessions = sessions.clone();
                let cancel = cancel.clone();
                tokio::spawn(async move {
                    if let Err(error) = bridge_local(
                        id,
                        target,
                        data_rx,
                        writer.clone(),
                        sessions.clone(),
                        cancel,
                    )
                    .await
                    {
                        let _ = write_frame(&writer, FAIL, id, &[]).await;
                        sessions.lock().await.remove(&id);
                        tracing::debug!(%error, "reverse mux local bridge ended");
                    }
                });
            }
            Ok(Some((DATA, id, payload))) => {
                let sender = sessions.lock().await.get(&id).cloned();
                if let Some(sender) = sender {
                    let _ = sender.send((DATA, payload)).await;
                }
            }
            Ok(Some((FIN, id, _))) => {
                let sender = sessions.lock().await.get(&id).cloned();
                if let Some(sender) = sender {
                    let _ = sender.send((FIN, Vec::new())).await;
                }
            }
            Ok(Some((RESET, id, _))) => {
                let sender = sessions.lock().await.get(&id).cloned();
                if let Some(sender) = sender {
                    let _ = sender.send((RESET, Vec::new())).await;
                }
            }
            _ => {
                cancel.cancel();
                return;
            }
        }
    }
}

async fn bridge_local(
    id: u32,
    target: String,
    mut frames: mpsc::Receiver<(u8, Vec<u8>)>,
    writer: Writer,
    sessions: Sessions,
    cancel: CancellationToken,
) -> Result<()> {
    let local = TcpStream::connect(&target)
        .await
        .with_context(|| format!("connect reverse mux target {target}"))?;
    local.set_nodelay(true).ok();
    write_frame(&writer, OK, id, &[]).await?;
    let (mut reader, mut writer_stream) = local.into_split();
    let mut buffer = vec![0u8; 16 * 1024];
    loop {
        tokio::select! {
            read = reader.read(&mut buffer) => match read {
                Ok(0) => { let _ = write_frame(&writer, FIN, id, &[]).await; break; }
                Ok(size) => if write_frame(&writer, DATA, id, &buffer[..size]).await.is_err() { break; }
                Err(_) => { let _ = write_frame(&writer, RESET, id, &[]).await; break; }
            },
            frame = frames.recv() => match frame {
                Some((DATA, payload)) => if writer_stream.write_all(&payload).await.is_err() { break; },
                Some((FIN, _)) => { let _ = writer_stream.shutdown().await; break; }
                Some((RESET, _)) | None => break,
                _ => {}
            },
            _ = cancel.cancelled() => break,
        }
    }
    sessions.lock().await.remove(&id);
    Ok(())
}

async fn write_frame(writer: &Writer, kind: u8, id: u32, payload: &[u8]) -> std::io::Result<()> {
    ensure_frame(payload.len())?;
    let mut stream = writer.lock().await;
    let mut header = [0u8; 9];
    header[0] = kind;
    header[1..5].copy_from_slice(&id.to_be_bytes());
    header[5..9].copy_from_slice(&(payload.len() as u32).to_be_bytes());
    stream.write_all(&header).await?;
    stream.write_all(payload).await?;
    stream.flush().await
}

fn ensure_frame(length: usize) -> std::io::Result<()> {
    if length > MAX_FRAME {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "reverse mux frame too large",
        ));
    }
    Ok(())
}

async fn read_frame(reader: &mut OwnedReadHalf) -> Result<Option<Frame>> {
    let mut header = [0u8; 9];
    let first = reader.read(&mut header[..1]).await?;
    if first == 0 {
        return Ok(None);
    }
    reader.read_exact(&mut header[1..]).await?;
    let id = u32::from_be_bytes([header[1], header[2], header[3], header[4]]);
    let length = u32::from_be_bytes([header[5], header[6], header[7], header[8]]) as usize;
    if length > MAX_FRAME {
        bail!("reverse mux frame too large");
    }
    let mut payload = vec![0u8; length];
    reader.read_exact(&mut payload).await?;
    Ok(Some((header[0], id, payload)))
}

async fn read_line(stream: &mut TcpStream) -> Result<String> {
    let mut line = Vec::with_capacity(32);
    loop {
        let mut byte = [0u8; 1];
        if stream.read(&mut byte).await? == 0 {
            bail!("reverse control connection closed");
        }
        if byte[0] == b'\n' {
            break;
        }
        if line.len() >= MAX_LINE {
            bail!("reverse control line too long");
        }
        line.push(byte[0]);
    }
    String::from_utf8(line).context("reverse control line is not UTF-8")
}
