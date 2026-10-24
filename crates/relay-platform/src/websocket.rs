//! RFC 6455 transport for the documented relay-stream-v1 byte-stream protocol.
//! One bounded driver owns framing; application flush waits for socket flush.
use crate::{
    model::{WebSocketClient, WebSocketServer},
    transport::BoxStream,
};
use anyhow::{Context as _, Result, bail, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use futures_util::{
    SinkExt, StreamExt,
    stream::{SplitSink, SplitStream},
};
use std::{
    collections::HashSet,
    future::Future,
    io,
    pin::Pin,
    sync::Arc,
    task::{Context, Poll, ready},
    time::Duration,
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    sync::{mpsc, oneshot, watch},
    task::JoinHandle,
    time::{Instant, timeout_at},
};
use tokio_tungstenite::{
    WebSocketStream, accept_hdr_async_with_config, client_async_with_config,
    tungstenite::{
        self, Message,
        client::IntoClientRequest,
        handshake::server::{Callback, ErrorResponse, Request, Response},
        http::{
            HeaderValue, StatusCode, header,
            uri::{Authority, PathAndQuery},
        },
        protocol::{WebSocketConfig, frame::coding::CloseCode},
    },
};

pub const SUBPROTOCOL: &str = "relay-stream-v1";
pub const MAX_PAYLOAD: usize = 64 * 1024;
const MAX_HTTP_HEADER: usize = 16 * 1024;

fn valid_path(path: &str) -> Result<()> {
    ensure!(
        path.len() <= 1024
            && path.starts_with('/')
            && !path.starts_with("//")
            && path.is_ascii()
            && !path
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
            && !path.contains(['#', '\\']),
        "invalid WebSocket path"
    );
    let parsed: PathAndQuery = path.parse()?;
    ensure!(
        parsed.as_str() == path,
        "WebSocket path must be an exact origin-form path"
    );
    Ok(())
}
fn valid_host(host: &str) -> Result<()> {
    ensure!(
        !host.is_empty()
            && host.len() <= 255
            && host.is_ascii()
            && !host
                .bytes()
                .any(|b| b.is_ascii_whitespace() || b.is_ascii_control())
            && !host.contains(['@', '/', '\\', '?', '#']),
        "invalid WebSocket Host"
    );
    let authority: Authority = host.parse()?;
    let suffix = if host.starts_with('[') {
        &host[host.find(']').context("invalid bracketed WebSocket Host")? + 1..]
    } else {
        host.find(':').map_or("", |index| &host[index..])
    };
    ensure!(
        !authority.host().is_empty()
            && (suffix.is_empty()
                || suffix.strip_prefix(':').is_some_and(|port| !port.is_empty()
                    && port.bytes().all(|b| b.is_ascii_digit())
                    && port.parse::<u16>().is_ok())),
        "invalid WebSocket Host authority"
    );
    Ok(())
}
fn valid_origin(origin: &str) -> Result<()> {
    ensure!(
        origin.len() <= 512 && origin.is_ascii(),
        "invalid WebSocket Origin"
    );
    let url: reqwest::Url = origin.parse()?;
    ensure!(
        matches!(url.scheme(), "http" | "https")
            && url.host_str().is_some()
            && url.origin().ascii_serialization() == origin,
        "Origin must be a canonical HTTP(S) origin without path"
    );
    Ok(())
}
pub fn validate_server(spec: &WebSocketServer) -> Result<()> {
    valid_path(&spec.path)?;
    if let Some(host) = &spec.host {
        valid_host(host)?;
    }
    ensure!(
        spec.allowed_origins.len() <= 64
            && spec.allowed_origins.iter().collect::<HashSet<_>>().len()
                == spec.allowed_origins.len(),
        "WebSocket allows at most 64 distinct Origins"
    );
    for origin in &spec.allowed_origins {
        valid_origin(origin)?;
    }
    Ok(())
}
pub fn validate_client(spec: &WebSocketClient) -> Result<()> {
    valid_path(&spec.path)?;
    valid_host(&spec.host)?;
    if let Some(origin) = &spec.origin {
        valid_origin(origin)?;
    }
    Ok(())
}
fn config() -> WebSocketConfig {
    WebSocketConfig::default()
        .read_buffer_size(16 * 1024)
        .write_buffer_size(0)
        .max_write_buffer_size(2 * (MAX_PAYLOAD + 32))
        .max_frame_size(Some(MAX_PAYLOAD + 1))
        .max_message_size(Some(MAX_PAYLOAD + 1))
}

struct CheckUpgrade(WebSocketServer);
impl CheckUpgrade {
    fn check(&self, request: &Request) -> Result<()> {
        ensure!(
            request.uri().path_and_query().map(|p| p.as_str()) == Some(self.0.path.as_str()),
            "WebSocket path mismatch"
        );
        let headers = request.headers();
        ensure!(
            headers.get_all(header::SEC_WEBSOCKET_KEY).iter().count() == 1
                && headers
                    .get_all(header::SEC_WEBSOCKET_VERSION)
                    .iter()
                    .count()
                    == 1,
            "one WebSocket key and version are required"
        );
        ensure!(
            STANDARD
                .decode(headers[header::SEC_WEBSOCKET_KEY].as_bytes())?
                .len()
                == 16,
            "WebSocket key must encode 16 bytes"
        );
        ensure!(
            headers.get_all(header::HOST).iter().count() == 1,
            "one Host is required"
        );
        let host = headers[header::HOST].to_str()?;
        valid_host(host)?;
        ensure!(
            self.0
                .host
                .as_ref()
                .is_none_or(|expected| expected.eq_ignore_ascii_case(host)),
            "WebSocket Host mismatch"
        );
        ensure!(
            headers.get_all(header::ORIGIN).iter().count() <= 1,
            "duplicate Origin"
        );
        if let Some(origin) = headers.get(header::ORIGIN) {
            let origin = origin.to_str()?;
            valid_origin(origin)?;
            ensure!(
                self.0
                    .allowed_origins
                    .iter()
                    .any(|allowed| allowed == origin),
                "Origin is not allowed"
            );
        }
        ensure!(
            headers
                .get_all(header::SEC_WEBSOCKET_PROTOCOL)
                .iter()
                .count()
                == 1
                && headers
                    .get(header::SEC_WEBSOCKET_PROTOCOL)
                    .and_then(|v| v.to_str().ok())
                    .is_some_and(|v| v.split(',').any(|p| p.trim() == SUBPROTOCOL)),
            "relay-stream-v1 subprotocol is required"
        );
        Ok(())
    }
}
impl Callback for CheckUpgrade {
    fn on_request(
        self,
        request: &Request,
        mut response: Response,
    ) -> std::result::Result<Response, ErrorResponse> {
        if self.check(request).is_err() {
            return Err(tungstenite::http::Response::builder()
                .status(StatusCode::FORBIDDEN)
                .body(Some("WebSocket endpoint parameters rejected".into()))
                .unwrap());
        }
        response.headers_mut().insert(
            header::SEC_WEBSOCKET_PROTOCOL,
            HeaderValue::from_static(SUBPROTOCOL),
        );
        Ok(response)
    }
}

/// Count only HTTP header bytes; a frame coalesced after CRLFCRLF is preserved.
struct HeaderIo {
    stream: BoxStream,
    seen: usize,
    window: u32,
    complete: bool,
}
impl HeaderIo {
    fn new(stream: BoxStream) -> Self {
        Self {
            stream,
            seen: 0,
            window: 0,
            complete: false,
        }
    }
}
impl AsyncRead for HeaderIo {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        let before = buffer.filled().len();
        ready!(Pin::new(&mut self.stream).poll_read(cx, buffer))?;
        if !self.complete {
            for &byte in &buffer.filled()[before..] {
                self.seen += 1;
                if self.seen > MAX_HTTP_HEADER {
                    return Poll::Ready(Err(io::Error::new(
                        io::ErrorKind::InvalidData,
                        "WebSocket HTTP headers exceed 16 KiB",
                    )));
                }
                self.window = (self.window << 8) | u32::from(byte);
                if self.window == 0x0d0a0d0a {
                    self.complete = true;
                    break;
                }
            }
        }
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for HeaderIo {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, bytes)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}

pub async fn accept(
    stream: BoxStream,
    spec: &WebSocketServer,
    close_timeout: Duration,
) -> Result<BoxStream> {
    validate_server(spec)?;
    let ws = accept_hdr_async_with_config(
        HeaderIo::new(stream),
        CheckUpgrade(spec.clone()),
        Some(config()),
    )
    .await?;
    Ok(bridge(ws, close_timeout))
}
pub async fn connect(
    stream: BoxStream,
    spec: &WebSocketClient,
    secure: bool,
    close_timeout: Duration,
) -> Result<BoxStream> {
    validate_client(spec)?;
    let mut request = format!(
        "{}://{}{}",
        if secure { "wss" } else { "ws" },
        spec.host,
        spec.path
    )
    .into_client_request()?;
    request.headers_mut().insert(
        header::SEC_WEBSOCKET_PROTOCOL,
        HeaderValue::from_static(SUBPROTOCOL),
    );
    if let Some(origin) = &spec.origin {
        request
            .headers_mut()
            .insert(header::ORIGIN, origin.parse()?);
    }
    let (ws, response) =
        client_async_with_config(request, HeaderIo::new(stream), Some(config())).await?;
    ensure!(
        response
            .headers()
            .get_all(header::SEC_WEBSOCKET_PROTOCOL)
            .iter()
            .count()
            == 1
            && response
                .headers()
                .get(header::SEC_WEBSOCKET_PROTOCOL)
                .is_some_and(|v| v == SUBPROTOCOL)
            && !response
                .headers()
                .contains_key(header::SEC_WEBSOCKET_EXTENSIONS),
        "WebSocket subprotocol or extensions mismatch"
    );
    Ok(bridge(ws, close_timeout))
}

type Ws = WebSocketStream<HeaderIo>;
type Ack = oneshot::Sender<()>;
enum Outgoing {
    Data(Vec<u8>, Ack),
    Fin(Ack),
}
enum Incoming {
    Data(tungstenite::Bytes),
    Fin,
}
#[derive(Clone, Default)]
struct State {
    local_fin: bool,
    remote_fin: bool,
    peer_close: bool,
    close_flushed: bool,
    pulse: u64,
    error: Option<Arc<str>>,
}

async fn read_frames(
    mut stream: SplitStream<Ws>,
    incoming: mpsc::Sender<Incoming>,
    state: watch::Sender<State>,
) -> Result<()> {
    let mut delivered_fin = false;
    let mut changes = state.subscribe();
    while let Some(message) = stream.next().await {
        match message? {
            Message::Binary(bytes) => {
                ensure!(!state.borrow().remote_fin, "WebSocket record after FIN");
                match bytes.first() {
                    Some(0) if bytes.len() > 1 => incoming
                        .send(Incoming::Data(bytes.slice(1..)))
                        .await
                        .context("WebSocket reader dropped")?,
                    Some(1) if bytes.len() == 1 => {
                        state.send_modify(|s| s.remote_fin = true);
                        if !state.borrow().local_fin {
                            incoming
                                .send(Incoming::Fin)
                                .await
                                .context("WebSocket reader dropped")?;
                            delivered_fin = true;
                        }
                    }
                    _ => bail!("invalid relay-stream-v1 record"),
                }
            }
            Message::Ping(_) => state.send_modify(|s| s.pulse = s.pulse.wrapping_add(1)),
            Message::Pong(_) => {}
            Message::Close(close) => {
                let snapshot = state.borrow().clone();
                ensure!(
                    snapshot.local_fin && snapshot.remote_fin,
                    "WebSocket closed before both FIN records"
                );
                ensure!(
                    close.as_ref().is_none_or(|c| c.code == CloseCode::Normal),
                    "WebSocket peer closed with error"
                );
                state.send_modify(|s| s.peer_close = true);
                while !state.borrow().close_flushed {
                    changes.changed().await?;
                }
                if !delivered_fin {
                    incoming
                        .send(Incoming::Fin)
                        .await
                        .context("WebSocket reader dropped")?;
                }
                return Ok(());
            }
            _ => bail!("relay-stream-v1 requires binary messages"),
        }
    }
    bail!("WebSocket ended without a complete close handshake")
}

async fn write_frames(
    mut sink: SplitSink<Ws, Message>,
    mut outgoing: mpsc::Receiver<Outgoing>,
    state: watch::Sender<State>,
    close_timeout: Duration,
) -> Result<()> {
    let mut changes = state.subscribe();
    let mut fin_ack: Option<Ack> = None;
    let mut deadline = None;
    loop {
        let snapshot = state.borrow().clone();
        if snapshot.local_fin && snapshot.remote_fin {
            let until = *deadline.get_or_insert_with(|| Instant::now() + close_timeout);
            if !snapshot.close_flushed {
                timeout_at(until, sink.close())
                    .await
                    .context("WebSocket close write timed out")??;
                state.send_modify(|s| s.close_flushed = true);
            }
            if state.borrow().peer_close {
                if let Some(ack) = fin_ack.take() {
                    let _ = ack.send(());
                }
                return Ok(());
            }
        }
        tokio::select! {
            biased;
            changed = changes.changed() => {
                changed?;
                if !state.borrow().close_flushed {
                    // A blocked Pong can otherwise prevent the close state
                    // from being processed, even after both application FINs.
                    tokio::time::timeout(close_timeout, sink.flush())
                        .await.context("WebSocket control flush timed out")??;
                }
            }
            request = outgoing.recv(), if !snapshot.local_fin => {
                match request.context("WebSocket writer dropped before FIN")? {
                    Outgoing::Data(data, ack) => { sink.send(Message::Binary(data.into())).await?; let _ = ack.send(()); }
                    Outgoing::Fin(ack) => {
                        sink.send(Message::Binary(vec![1].into())).await?;
                        state.send_modify(|s| s.local_fin = true);
                        if state.borrow().remote_fin { fin_ack = Some(ack); } else { let _ = ack.send(()); }
                    }
                }
            }
            _ = async { if let Some(until) = deadline { tokio::time::sleep_until(until).await } else { std::future::pending::<()>().await } } => bail!("WebSocket peer close timed out"),
        }
    }
}

fn bridge(ws: Ws, close_timeout: Duration) -> BoxStream {
    let (sink, stream) = ws.split();
    let (outgoing, requests) = mpsc::channel(1);
    let (responses, incoming) = mpsc::channel(1);
    let (state, status) = watch::channel(State::default());
    let driver = tokio::spawn(async move {
        if let Err(error) = tokio::try_join!(
            read_frames(stream, responses, state.clone()),
            write_frames(sink, requests, state.clone(), close_timeout)
        ) {
            state.send_modify(|s| s.error = Some(format!("{error:#}").into()));
        }
    });
    Box::new(ByteStream {
        outgoing,
        incoming,
        status,
        driver,
        pending: None,
        buffer: Default::default(),
        read_fin: false,
        write_fin: false,
    })
}
struct ByteStream {
    outgoing: mpsc::Sender<Outgoing>,
    incoming: mpsc::Receiver<Incoming>,
    status: watch::Receiver<State>,
    driver: JoinHandle<()>,
    pending: Option<oneshot::Receiver<()>>,
    buffer: tungstenite::Bytes,
    read_fin: bool,
    write_fin: bool,
}
impl Drop for ByteStream {
    fn drop(&mut self) {
        self.driver.abort();
    }
}
impl ByteStream {
    fn failure(&self) -> io::Error {
        io::Error::new(
            io::ErrorKind::ConnectionAborted,
            self.status
                .borrow()
                .error
                .as_deref()
                .unwrap_or("WebSocket driver stopped")
                .to_owned(),
        )
    }
    fn poll_ack(&mut self, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        if let Some(pending) = &mut self.pending {
            let result = ready!(Pin::new(pending).poll(cx));
            self.pending = None;
            if result.is_err() {
                return Poll::Ready(Err(self.failure()));
            }
        }
        if self.status.borrow().error.is_some() {
            return Poll::Ready(Err(self.failure()));
        }
        Poll::Ready(Ok(()))
    }
    fn enqueue(&mut self, data: Option<Vec<u8>>) -> io::Result<()> {
        let (ack, pending) = oneshot::channel();
        self.outgoing
            .try_send(match data {
                Some(data) => Outgoing::Data(data, ack),
                None => Outgoing::Fin(ack),
            })
            .map_err(|_| self.failure())?;
        self.pending = Some(pending);
        Ok(())
    }
}
impl AsyncRead for ByteStream {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        buffer: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        if buffer.remaining() == 0 {
            return Poll::Ready(Ok(()));
        }
        if self.buffer.is_empty() && !self.read_fin {
            match ready!(self.incoming.poll_recv(cx)) {
                Some(Incoming::Data(data)) => self.buffer = data,
                Some(Incoming::Fin) => self.read_fin = true,
                None => return Poll::Ready(Err(self.failure())),
            }
        }
        let amount = buffer.remaining().min(self.buffer.len());
        buffer.put_slice(&self.buffer[..amount]);
        self.buffer = self.buffer.slice(amount..);
        Poll::Ready(Ok(()))
    }
}
impl AsyncWrite for ByteStream {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut Context<'_>,
        bytes: &[u8],
    ) -> Poll<io::Result<usize>> {
        ready!(self.poll_ack(cx))?;
        if self.write_fin {
            return Poll::Ready(Err(io::ErrorKind::BrokenPipe.into()));
        }
        if bytes.is_empty() {
            return Poll::Ready(Ok(0));
        }
        let size = bytes.len().min(MAX_PAYLOAD);
        let mut message = Vec::with_capacity(size + 1);
        message.push(0);
        message.extend_from_slice(&bytes[..size]);
        self.enqueue(Some(message))?;
        Poll::Ready(Ok(size))
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        self.poll_ack(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<io::Result<()>> {
        ready!(self.poll_ack(cx))?;
        if !self.write_fin {
            self.enqueue(None)?;
            self.write_fin = true;
        }
        self.poll_ack(cx)
    }
}
