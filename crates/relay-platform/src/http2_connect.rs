//! HTTP/2 cleartext (h2c) CONNECT forward proxy.
//!
//! This is a standalone listener for clients that use HTTP/2 prior knowledge.
//! It reuses the HTTP CONNECT authentication/private-destination policy but
//! speaks HTTP/2 frames instead of HTTP/1.1. It is intentionally separate from
//! the rule engine until rule-level metering and ACL integration is added.
use crate::{http_connect, shadowsocks::Destination};
use anyhow::{Context, Result};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http_body_util::Empty;
use hyper::{
    Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header::PROXY_AUTHORIZATION,
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::{net::SocketAddr, sync::Arc, time::Duration};
use tokio::{
    io::copy_bidirectional,
    net::{TcpListener, TcpStream},
    time::timeout,
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn serve(listener: TcpListener, config: http_connect::ServerConfig) -> Result<()> {
    http_connect::validate(&config)?;
    let server = Arc::new(config);
    loop {
        let (stream, peer) = listener.accept().await?;
        let server = server.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_connection(stream, server, peer).await {
                tracing::debug!(%peer, %error, "HTTP/2 CONNECT connection ended");
            }
        });
    }
}

async fn serve_connection(
    stream: TcpStream,
    server: Arc<http_connect::ServerConfig>,
    peer: SocketAddr,
) -> Result<()> {
    stream.set_nodelay(true).ok();
    let service = service_fn(move |request| {
        let server = server.clone();
        async move { handle(request, server, peer).await }
    });
    timeout(
        HANDSHAKE_TIMEOUT,
        hyper::server::conn::http2::Builder::new(TokioExecutor::new())
            .serve_connection(TokioIo::new(stream), service),
    )
    .await
    .context("HTTP/2 CONNECT handshake timed out")??;
    Ok(())
}

async fn handle(
    mut request: Request<Incoming>,
    server: Arc<http_connect::ServerConfig>,
    peer: SocketAddr,
) -> Result<Response<Empty<Bytes>>, hyper::Error> {
    if request.method() != hyper::Method::CONNECT {
        return Ok(reply(StatusCode::METHOD_NOT_ALLOWED));
    }
    let Some(authority) = request.uri().authority().map(|value| value.to_string()) else {
        return Ok(reply(StatusCode::BAD_REQUEST));
    };
    if server.username.is_some() && !authorized(request.headers(), &server) {
        return Ok(reply(StatusCode::PROXY_AUTHENTICATION_REQUIRED));
    }
    let destination = match http_connect::parse_authority(&authority) {
        Ok(destination) => destination,
        Err(_) => return Ok(reply(StatusCode::BAD_REQUEST)),
    };
    let target = match resolve_target(&destination, server.allow_private_destinations).await {
        Some(target) => target,
        None => return Ok(reply(StatusCode::FORBIDDEN)),
    };
    let upstream = match timeout(CONNECT_TIMEOUT, TcpStream::connect(target)).await {
        Ok(Ok(stream)) => stream,
        _ => return Ok(reply(StatusCode::BAD_GATEWAY)),
    };
    upstream.set_nodelay(true).ok();
    let upgrade = hyper::upgrade::on(&mut request);
    tokio::spawn(async move {
        if let Ok(upgraded) = upgrade.await {
            let mut upgraded = TokioIo::new(upgraded);
            let mut upstream = upstream;
            let _ = copy_bidirectional(&mut upstream, &mut upgraded).await;
        }
    });
    tracing::debug!(%peer, %target, %destination, "HTTP/2 CONNECT tunnel established");
    Ok(reply(StatusCode::OK))
}

fn reply(status: StatusCode) -> Response<Empty<Bytes>> {
    let mut response = Response::new(Empty::new());
    *response.status_mut() = status;
    if status == StatusCode::PROXY_AUTHENTICATION_REQUIRED {
        response.headers_mut().insert(
            hyper::header::PROXY_AUTHENTICATE,
            hyper::header::HeaderValue::from_static("Basic realm=\"relay\""),
        );
    }
    response
}

fn authorized(headers: &hyper::HeaderMap, server: &http_connect::ServerConfig) -> bool {
    headers
        .get(PROXY_AUTHORIZATION)
        .and_then(|value| value.to_str().ok())
        .and_then(|value| value.strip_prefix("Basic "))
        .and_then(|encoded| STANDARD.decode(encoded).ok())
        .and_then(|decoded| String::from_utf8(decoded).ok())
        .is_some_and(|credentials| {
            credentials
                == format!(
                    "{}:{}",
                    server.username.as_deref().unwrap_or_default(),
                    server.password.as_deref().unwrap_or_default()
                )
        })
}

async fn resolve_target(destination: &Destination, allow_private: bool) -> Option<SocketAddr> {
    match destination {
        Destination::Ip(address) => {
            (allow_private || crate::shadowsocks::public(address.ip())).then_some(*address)
        }
        Destination::Domain(name, port) => {
            let mut addresses = tokio::net::lookup_host((name.as_str(), *port)).await.ok()?;
            addresses.find(|address| allow_private || crate::shadowsocks::public(address.ip()))
        }
    }
}
