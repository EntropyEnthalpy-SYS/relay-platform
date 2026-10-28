//! HTTP/2 cleartext (h2c) CONNECT forward proxy.
//!
//! This is a standalone listener for clients that use HTTP/2 prior knowledge.
//! It reuses the HTTP CONNECT authentication/private-destination policy but
//! speaks HTTP/2 frames instead of HTTP/1.1. It is intentionally separate from
//! the rule engine until rule-level metering and ACL integration is added.
use crate::{http_connect, shadowsocks::Destination};
use anyhow::{Context, Result, ensure};
use base64::{Engine as _, engine::general_purpose::STANDARD};
use http_body_util::Empty;
use hyper::{
    Request, Response, StatusCode,
    body::{Bytes, Incoming},
    header::PROXY_AUTHORIZATION,
    service::service_fn,
};
use hyper_util::rt::{TokioExecutor, TokioIo};
use std::{net::SocketAddr, path::Path, sync::Arc, time::Duration};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWrite, copy_bidirectional},
    net::{TcpListener, TcpStream},
    time::timeout,
};
use tokio_rustls::{
    TlsAcceptor,
    rustls::{
        RootCertStore, ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    },
};

const CONNECT_TIMEOUT: Duration = Duration::from_secs(10);
const HANDSHAKE_TIMEOUT: Duration = Duration::from_secs(10);

pub async fn serve(listener: TcpListener, config: http_connect::ServerConfig) -> Result<()> {
    http_connect::validate(&config)?;
    let server = Arc::new(config);
    loop {
        let (stream, peer) = listener.accept().await?;
        stream.set_nodelay(true).ok();
        let server = server.clone();
        tokio::spawn(async move {
            if let Err(error) = serve_connection(stream, server, peer).await {
                tracing::debug!(%peer, %error, "HTTP/2 CONNECT connection ended");
            }
        });
    }
}

pub async fn serve_tls(
    listener: TcpListener,
    config: http_connect::ServerConfig,
    acceptor: TlsAcceptor,
) -> Result<()> {
    http_connect::validate(&config)?;
    let server = Arc::new(config);
    loop {
        let (stream, peer) = listener.accept().await?;
        let acceptor = acceptor.clone();
        let server = server.clone();
        tokio::spawn(async move {
            let stream = match timeout(HANDSHAKE_TIMEOUT, acceptor.accept(stream)).await {
                Ok(Ok(stream)) => stream,
                Ok(Err(error)) => {
                    tracing::debug!(%peer, %error, "HTTP/2 TLS handshake failed");
                    return;
                }
                Err(_) => {
                    tracing::debug!(%peer, "HTTP/2 TLS handshake timed out");
                    return;
                }
            };
            if let Err(error) = serve_connection(stream, server, peer).await {
                tracing::debug!(%peer, %error, "HTTP/2 CONNECT connection ended");
            }
        });
    }
}

async fn serve_connection<S>(
    mut stream: S,
    server: Arc<http_connect::ServerConfig>,
    peer: SocketAddr,
) -> Result<()>
where
    S: AsyncRead + AsyncWrite + Send + Unpin + 'static,
{
    // Bound the client's actual preface, including its initial SETTINGS, rather
    // than the connection future (which also owns every established tunnel).
    let preface = timeout(HANDSHAKE_TIMEOUT, read_preface(&mut stream))
        .await
        .context("HTTP/2 CONNECT handshake timed out")??;
    let (reader, writer) = tokio::io::split(stream);
    let stream = tokio::io::join(std::io::Cursor::new(preface).chain(reader), writer);
    let service = service_fn(move |request| {
        let server = server.clone();
        async move { handle(request, server, peer).await }
    });
    hyper::server::conn::http2::Builder::new(TokioExecutor::new())
        .serve_connection(TokioIo::new(stream), service)
        .await?;
    Ok(())
}

async fn read_preface<S: AsyncRead + Unpin>(stream: &mut S) -> Result<Vec<u8>> {
    const MAGIC: &[u8; 24] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
    let mut preface = vec![0; MAGIC.len() + 9];
    stream.read_exact(&mut preface[..MAGIC.len()]).await?;
    ensure!(&preface[..MAGIC.len()] == MAGIC, "invalid HTTP/2 preface");
    stream.read_exact(&mut preface[MAGIC.len()..]).await?;
    let header = &preface[MAGIC.len()..];
    let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    ensure!(
        header[3] == 4
            && header[4] & 1 == 0
            && u32::from_be_bytes(header[5..9].try_into()?) & 0x7fff_ffff == 0
            && length <= 16_384
            && length.is_multiple_of(6),
        "invalid initial HTTP/2 SETTINGS frame"
    );
    let offset = preface.len();
    preface.resize(offset + length, 0);
    stream.read_exact(&mut preface[offset..]).await?;
    // Hyper still validates SETTINGS values and the rest of the protocol. Replay
    // the exact bytes so its connection state sees an ordinary client handshake.
    Ok(preface)
}

pub fn tls_acceptor_h2(
    cert_path: &Path,
    key_path: &Path,
    client_ca_path: Option<&Path>,
) -> Result<TlsAcceptor> {
    let certs = CertificateDer::pem_slice_iter(&std::fs::read(cert_path)?)
        .collect::<std::result::Result<Vec<_>, _>>()?;
    ensure!(!certs.is_empty(), "TLS certificate file is empty");
    let key = PrivateKeyDer::from_pem_slice(&std::fs::read(key_path)?)
        .context("cannot parse TLS private key")?;
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let builder = ServerConfig::builder_with_provider(provider.clone())
        .with_safe_default_protocol_versions()?;
    let builder = if let Some(ca_path) = client_ca_path {
        let mut roots = RootCertStore::empty();
        for cert in CertificateDer::pem_slice_iter(&std::fs::read(ca_path)?) {
            roots.add(cert?)?;
        }
        ensure!(!roots.is_empty(), "TLS client CA file has no certificates");
        let verifier = tokio_rustls::rustls::server::WebPkiClientVerifier::builder_with_provider(
            Arc::new(roots),
            provider,
        )
        .build()?;
        builder.with_client_cert_verifier(verifier)
    } else {
        builder.with_no_client_auth()
    };
    let mut config = builder.with_single_cert(certs, key)?;
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok(TlsAcceptor::from(Arc::new(config)))
}

pub fn tls_connector_h2(
    ca_path: &Path,
    server_name: &str,
) -> Result<(
    tokio_rustls::TlsConnector,
    tokio_rustls::rustls::pki_types::ServerName<'static>,
)> {
    let mut roots = RootCertStore::empty();
    for cert in CertificateDer::pem_slice_iter(&std::fs::read(ca_path)?) {
        roots.add(cert?)?;
    }
    ensure!(!roots.is_empty(), "TLS CA file has no certificates");
    let provider = Arc::new(tokio_rustls::rustls::crypto::ring::default_provider());
    let mut config = tokio_rustls::rustls::ClientConfig::builder_with_provider(provider)
        .with_safe_default_protocol_versions()?
        .with_root_certificates(roots)
        .with_no_client_auth();
    config.alpn_protocols = vec![b"h2".to_vec()];
    Ok((
        tokio_rustls::TlsConnector::from(Arc::new(config)),
        tokio_rustls::rustls::pki_types::ServerName::try_from(server_name.to_owned())?,
    ))
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
    let (target, upstream) = match timeout(CONNECT_TIMEOUT, async {
        let target = resolve_target(&destination, server.allow_private_destinations)
            .await
            .ok_or(StatusCode::FORBIDDEN)?;
        let upstream = TcpStream::connect(target)
            .await
            .map_err(|_| StatusCode::BAD_GATEWAY)?;
        Ok::<_, StatusCode>((target, upstream))
    })
    .await
    {
        Ok(Ok(connected)) => connected,
        Ok(Err(status)) => return Ok(reply(status)),
        Err(_) => return Ok(reply(StatusCode::BAD_GATEWAY)),
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
