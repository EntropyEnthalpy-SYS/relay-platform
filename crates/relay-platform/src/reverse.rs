//! Minimal single-session reverse TCP tunnel.
//!
//! A private client keeps an authenticated control connection to a public
//! server. For each accepted public TCP connection the server asks the client
//! to open its local target, then the two TCP streams are bridged. Only one
//! public connection is active at a time; this is not a multiplexed reverse
//! tunnel yet. Use an authenticated private network or an external TLS tunnel
//! for the control/public listeners.
use anyhow::{Context, Result, bail, ensure};
use std::net::SocketAddr;
use tokio::io::{AsyncReadExt, AsyncWriteExt, copy_bidirectional};
use tokio::net::{TcpListener, TcpStream};

const MAX_LINE: usize = 512;
const READY: &str = "READY";
const OPEN: &str = "OPEN";
const OK: &str = "OK";

pub async fn serve(control: TcpListener, public: TcpListener, token: String) -> Result<()> {
    ensure!(
        !token.is_empty() && token.len() <= 256,
        "reverse token must be 1..256 bytes"
    );
    let public = std::sync::Arc::new(public);
    loop {
        let (mut control_stream, peer) = control.accept().await?;
        let authorized = match read_line(&mut control_stream).await {
            Ok(line) => line
                .strip_prefix("REVERSE ")
                .is_some_and(|provided| token_matches(&token, provided)),
            Err(_) => false,
        };
        if !authorized {
            let _ = control_stream.write_all(b"DENY\n").await;
            tracing::warn!(%peer, "reverse control authentication failed");
            continue;
        }
        if control_stream
            .write_all(format!("{READY}\n").as_bytes())
            .await
            .is_err()
        {
            continue;
        }
        tracing::info!(%peer, "reverse client connected");
        let public = public.clone();
        tokio::spawn(async move {
            serve_session(control_stream, public).await;
        });
    }
}

async fn serve_session(mut control_stream: TcpStream, public: std::sync::Arc<TcpListener>) {
    let (mut exposed, public_peer) = match public.accept().await {
        Ok(pair) => pair,
        Err(error) => {
            tracing::warn!(%error, "reverse public accept failed");
            return;
        }
    };
    if control_stream
        .write_all(format!("{OPEN}\n").as_bytes())
        .await
        .is_err()
    {
        return;
    }
    let reply = match read_line(&mut control_stream).await {
        Ok(line) => line,
        Err(_) => return,
    };
    if reply != OK {
        tracing::warn!(%public_peer, reply = %reply, "reverse client refused public connection");
        let _ = exposed.shutdown().await;
        return;
    }
    if let Err(error) = copy_bidirectional(&mut exposed, &mut control_stream).await {
        tracing::debug!(%error, %public_peer, "reverse bridge ended");
    }
}

pub async fn client(server: SocketAddr, target: String, token: String) -> Result<()> {
    client_pool(server, target, token, 1).await
}

/// Run several independent control sessions. Each public connection occupies
/// one session; a pool therefore provides bounded concurrency without a
/// multiplexing frame protocol.
pub async fn client_pool(
    server: SocketAddr,
    target: String,
    token: String,
    sessions: usize,
) -> Result<()> {
    ensure!(
        !token.is_empty() && token.len() <= 256,
        "reverse token must be 1..256 bytes"
    );
    ensure!(
        (1..=64).contains(&sessions),
        "reverse sessions must be 1..=64"
    );
    let mut tasks = tokio::task::JoinSet::new();
    for _ in 0..sessions {
        let target = target.clone();
        let token = token.clone();
        tasks.spawn(async move {
            loop {
                if let Err(error) = client_session(server, &target, &token).await {
                    tracing::warn!(%error, "reverse client session ended; reconnecting");
                    tokio::time::sleep(std::time::Duration::from_millis(250)).await;
                }
            }
        });
    }
    while tasks.join_next().await.is_some() {}
    Ok(())
}

async fn client_session(server: SocketAddr, target: &str, token: &str) -> Result<()> {
    let mut control = TcpStream::connect(server)
        .await
        .with_context(|| format!("connect reverse server {server}"))?;
    control
        .write_all(format!("REVERSE {token}\n").as_bytes())
        .await?;
    let reply = read_line(&mut control).await?;
    match reply.as_str() {
        READY => {}
        "DENY" => bail!("reverse server rejected the token"),
        other => bail!("unexpected reverse handshake: {other}"),
    }
    let line = read_line(&mut control).await?;
    if line != OPEN {
        bail!("unexpected reverse command: {line}");
    }
    let mut local = match TcpStream::connect(target).await {
        Ok(stream) => stream,
        Err(error) => {
            let message = format!("FAIL {error}\n");
            let _ = control.write_all(message.as_bytes()).await;
            bail!("reverse target connect failed: {error}");
        }
    };
    control.write_all(format!("{OK}\n").as_bytes()).await?;
    copy_bidirectional(&mut local, &mut control).await?;
    Ok(())
}

fn token_matches(expected: &str, provided: &str) -> bool {
    if expected.len() != provided.len() {
        return false;
    }
    let mut difference = 0u8;
    for (left, right) in expected.bytes().zip(provided.bytes()) {
        difference |= left ^ right;
    }
    difference == 0
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
