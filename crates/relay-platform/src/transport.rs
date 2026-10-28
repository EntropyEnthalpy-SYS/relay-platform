//! TLS wraps the same metered TCP byte stream. Keys are read only from local
//! operator-provisioned profiles; control configuration carries profile IDs.
use crate::model::{Rule, identifier};
use anyhow::{Context, Result, ensure};
use sha2::{Digest, Sha256};
use std::{
    fs,
    io::{self, Read},
    path::Path,
    pin::Pin,
    sync::Arc,
    task::{Context as PollContext, Poll},
};
use tokio::{
    io::{AsyncRead, AsyncWrite, ReadBuf},
    net::TcpStream,
};
use tokio_rustls::{
    TlsAcceptor, TlsConnector,
    rustls::{
        self, ClientConfig, RootCertStore, ServerConfig,
        pki_types::{CertificateDer, PrivateKeyDer, ServerName, pem::PemObject},
    },
};

pub trait Stream: AsyncRead + AsyncWrite + Unpin + Send {}
impl<T: AsyncRead + AsyncWrite + Unpin + Send> Stream for T {}
pub type BoxStream = Box<dyn Stream>;
struct Held<T> {
    stream: BoxStream,
    _guard: T,
}
pub(crate) fn hold<T: Send + Unpin + 'static>(stream: BoxStream, guard: T) -> BoxStream {
    Box::new(Held {
        stream,
        _guard: guard,
    })
}
impl<T: Unpin> AsyncRead for Held<T> {
    fn poll_read(
        mut self: Pin<&mut Self>,
        cx: &mut PollContext<'_>,
        buf: &mut ReadBuf<'_>,
    ) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_read(cx, buf)
    }
}
impl<T: Unpin> AsyncWrite for Held<T> {
    fn poll_write(
        mut self: Pin<&mut Self>,
        cx: &mut PollContext<'_>,
        buf: &[u8],
    ) -> Poll<io::Result<usize>> {
        Pin::new(&mut self.stream).poll_write(cx, buf)
    }
    fn poll_flush(mut self: Pin<&mut Self>, cx: &mut PollContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_flush(cx)
    }
    fn poll_shutdown(mut self: Pin<&mut Self>, cx: &mut PollContext<'_>) -> Poll<io::Result<()>> {
        Pin::new(&mut self.stream).poll_shutdown(cx)
    }
}
struct Outbound {
    connector: TlsConnector,
    name: ServerName<'static>,
}
pub struct PreparedTls {
    inbound: Option<TlsAcceptor>,
    require_h2: bool,
    outbound: Vec<Option<Outbound>>,
    pub fingerprint: [u8; 32],
}
struct Material<'a> {
    root: Option<&'a Path>,
    digest: Sha256,
}
impl Material<'_> {
    fn read(&mut self, profile: &str, filename: &str, private: bool) -> Result<Vec<u8>> {
        ensure!(identifier(profile), "invalid TLS profile ID");
        let root = self.root.context("TLS profiles require --tls-directory")?;
        let root_meta = fs::symlink_metadata(root)?;
        ensure!(
            root_meta.is_dir() && !root_meta.file_type().is_symlink(),
            "TLS root must be a real directory"
        );
        let directory = root.join(profile);
        let meta = fs::symlink_metadata(&directory)
            .with_context(|| format!("missing TLS profile {profile}"))?;
        ensure!(
            meta.is_dir() && !meta.file_type().is_symlink(),
            "TLS profile must be a real directory"
        );
        let path = directory.join(filename);
        let metadata = fs::symlink_metadata(&path)?;
        ensure!(
            metadata.is_file() && !metadata.file_type().is_symlink(),
            "TLS material must be a regular file"
        );
        ensure!(metadata.len() <= 128 * 1024, "TLS material exceeds 128 KiB");
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            if private {
                ensure!(
                    metadata.permissions().mode() & 0o077 == 0,
                    "TLS private key must not be readable by group or others"
                );
            }
            ensure!(
                (root_meta.permissions().mode()
                    | meta.permissions().mode()
                    | metadata.permissions().mode())
                    & 0o022
                    == 0,
                "TLS directory and material must not be writable by group or others"
            );
        }
        let mut bytes = Vec::new();
        fs::File::open(&path)?
            .take(128 * 1024 + 1)
            .read_to_end(&mut bytes)?;
        ensure!(bytes.len() <= 128 * 1024, "TLS material exceeds 128 KiB");
        // Length prefixes prevent concatenation ambiguity. Fingerprints stay local.
        self.digest.update((bytes.len() as u64).to_be_bytes());
        self.digest.update(&bytes);
        Ok(bytes)
    }
    fn certificates(
        &mut self,
        profile: &str,
        filename: &str,
    ) -> Result<Vec<CertificateDer<'static>>> {
        let bytes = self.read(profile, filename, false)?;
        let chain = CertificateDer::pem_slice_iter(&bytes).collect::<Result<Vec<_>, _>>()?;
        ensure!(
            !chain.is_empty() && chain.len() <= 32,
            "TLS certificate file requires 1..32 certificates"
        );
        Ok(chain)
    }
    fn key(&mut self, profile: &str) -> Result<PrivateKeyDer<'static>> {
        let bytes = self.read(profile, "key.pem", true)?;
        PrivateKeyDer::from_pem_slice(&bytes).context("cannot parse TLS private key")
    }
    fn roots(&mut self, profile: Option<&str>) -> Result<RootCertStore> {
        let mut roots = RootCertStore::empty();
        if let Some(id) = profile {
            for cert in self.certificates(id, "ca.pem")? {
                roots.add(cert)?;
            }
        } else {
            roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
        }
        Ok(roots)
    }
}
impl PreparedTls {
    pub fn load(rule: &Rule, directory: Option<&Path>) -> Result<Self> {
        let mut material = Material {
            root: directory,
            digest: Sha256::new(),
        };
        let provider = Arc::new(rustls::crypto::ring::default_provider());
        let inbound = if let Some(spec) = &rule.inbound_tls {
            let builder = ServerConfig::builder_with_provider(provider.clone())
                .with_safe_default_protocol_versions()?;
            let builder = if let Some(ca) = &spec.client_ca {
                let verifier = rustls::server::WebPkiClientVerifier::builder_with_provider(
                    Arc::new(material.roots(Some(ca))?),
                    provider.clone(),
                )
                .build()?;
                builder.with_client_cert_verifier(verifier)
            } else {
                builder.with_no_client_auth()
            };
            let mut config = builder.with_single_cert(
                material.certificates(&spec.identity, "cert.pem")?,
                material.key(&spec.identity)?,
            )?;
            if rule.inbound_http2_connect.is_some() {
                config.alpn_protocols = vec![b"h2".to_vec()];
            }
            if rule.inbound_websocket.is_some() {
                config.alpn_protocols = vec![b"http/1.1".to_vec()];
            }
            Some(TlsAcceptor::from(Arc::new(config)))
        } else {
            None
        };
        let mut outbound = Vec::with_capacity(rule.targets.len());
        for target in &rule.targets {
            let client = if let Some(spec) = &target.tls {
                let builder = ClientConfig::builder_with_provider(provider.clone())
                    .with_safe_default_protocol_versions()?
                    .with_root_certificates(material.roots(spec.ca.as_deref())?);
                let mut config = if let Some(identity) = &spec.identity {
                    builder.with_client_auth_cert(
                        material.certificates(identity, "cert.pem")?,
                        material.key(identity)?,
                    )?
                } else {
                    builder.with_no_client_auth()
                };
                if target.websocket.is_some() {
                    config.alpn_protocols = vec![b"http/1.1".to_vec()];
                }
                Some(Outbound {
                    connector: TlsConnector::from(Arc::new(config)),
                    name: ServerName::try_from(spec.server_name.clone())?,
                })
            } else {
                None
            };
            outbound.push(client);
        }
        Ok(Self {
            require_h2: rule.inbound_http2_connect.is_some(),
            inbound,
            outbound,
            fingerprint: material.digest.finalize().into(),
        })
    }
    pub async fn accept(&self, stream: TcpStream) -> Result<BoxStream> {
        Ok(self.accept_authenticated(stream).await?.0)
    }
    pub(crate) async fn accept_authenticated(
        &self,
        stream: TcpStream,
    ) -> Result<(BoxStream, Option<[u8; 32]>)> {
        Ok(if let Some(tls) = &self.inbound {
            let accepted = tls.accept(stream).await?;
            ensure!(
                !self.require_h2 || accepted.get_ref().1.alpn_protocol() == Some(&b"h2"[..]),
                "HTTP/2 TLS requires h2 ALPN"
            );
            let identity = accepted
                .get_ref()
                .1
                .peer_certificates()
                .and_then(|chain| chain.first())
                .map(|cert| Sha256::digest(cert.as_ref()).into());
            (Box::new(accepted), identity)
        } else {
            (Box::new(stream), None)
        })
    }
    pub async fn connect(&self, index: usize, stream: TcpStream) -> Result<BoxStream> {
        Ok(if let Some(tls) = &self.outbound[index] {
            Box::new(tls.connector.connect(tls.name.clone(), stream).await?)
        } else {
            Box::new(stream)
        })
    }
}

/// Validate and copy local TLS material into a gateway's private immutable generation.
pub(crate) fn identity_pem(root: Option<&Path>, profile: &str) -> Result<(String, String)> {
    let mut material = Material {
        root,
        digest: Sha256::new(),
    };
    let certificate = material.read(profile, "cert.pem", false)?;
    let key = material.read(profile, "key.pem", true)?;
    let certs = CertificateDer::pem_slice_iter(&certificate).collect::<Result<Vec<_>, _>>()?;
    ensure!(
        !certs.is_empty() && certs.len() <= 32,
        "TLS identity requires 1..32 certificates"
    );
    let private = PrivateKeyDer::from_pem_slice(&key)?;
    rustls::ServerConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
        .with_safe_default_protocol_versions()?
        .with_no_client_auth()
        .with_single_cert(certs, private)?;
    Ok((String::from_utf8(certificate)?, String::from_utf8(key)?))
}
