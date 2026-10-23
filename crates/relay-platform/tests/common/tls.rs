use std::{
    fs,
    path::{Path, PathBuf},
    process::Command,
    sync::Arc,
};
use tokio_rustls::{
    TlsConnector,
    rustls::{
        self, ClientConfig, RootCertStore,
        pki_types::{CertificateDer, PrivateKeyDer, pem::PemObject},
    },
};

pub struct Certificates {
    _temp: tempfile::TempDir,
    pub root: PathBuf,
}
fn openssl(dir: &Path, args: &[&str]) {
    let result = Command::new("openssl")
        .current_dir(dir)
        .args(args)
        .output()
        .expect("TLS tests require OpenSSL or LibreSSL on PATH");
    assert!(
        result.status.success(),
        "certificate fixture failed: {}",
        String::from_utf8_lossy(&result.stderr)
    );
}
impl Certificates {
    pub fn new() -> Self {
        let temp = tempfile::tempdir().unwrap();
        let root = temp.path().join("tls");
        fs::create_dir(&root).unwrap();
        let ca = root.join("root");
        fs::create_dir(&ca).unwrap();
        fs::write(ca.join("ca.cnf"), "[req]\ndistinguished_name=dn\nx509_extensions=ca\nprompt=no\n[dn]\nCN=Relay isolated test CA\n[ca]\nbasicConstraints=critical,CA:TRUE\nkeyUsage=critical,keyCertSign,cRLSign\nsubjectKeyIdentifier=hash\n").unwrap();
        openssl(
            &ca,
            &[
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                "root.key",
            ],
        );
        openssl(
            &ca,
            &[
                "req", "-new", "-x509", "-sha256", "-key", "root.key", "-out", "ca.pem", "-days",
                "2", "-config", "ca.cnf",
            ],
        );
        let result = Self { _temp: temp, root };
        result.issue("server");
        result.issue("client");
        result
    }
    pub fn issue(&self, identity: &str) {
        let path = self.root.join(identity);
        fs::create_dir_all(&path).unwrap();
        fs::write(path.join("leaf.cnf"), "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\nextendedKeyUsage=serverAuth,clientAuth\nsubjectAltName=DNS:relay.test,DNS:localhost,IP:127.0.0.1\n").unwrap();
        openssl(
            &path,
            &[
                "ecparam",
                "-name",
                "prime256v1",
                "-genkey",
                "-noout",
                "-out",
                "key.pem",
            ],
        );
        openssl(
            &path,
            &[
                "req",
                "-new",
                "-key",
                "key.pem",
                "-out",
                "leaf.csr",
                "-subj",
                "/CN=relay.test",
            ],
        );
        openssl(
            &path,
            &[
                "x509",
                "-sha256",
                "-req",
                "-in",
                "leaf.csr",
                "-CA",
                "../root/ca.pem",
                "-CAkey",
                "../root/root.key",
                "-CAcreateserial",
                "-out",
                "cert.pem",
                "-days",
                "2",
                "-extfile",
                "leaf.cnf",
            ],
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            fs::set_permissions(path.join("key.pem"), fs::Permissions::from_mode(0o600)).unwrap();
        }
    }
    pub fn connector(&self, client_auth: bool) -> TlsConnector {
        self.connector_with_identity(if client_auth { Some(self) } else { None })
    }
    pub fn connector_with_identity(&self, identity: Option<&Self>) -> TlsConnector {
        let mut roots = RootCertStore::empty();
        for cert in
            CertificateDer::pem_slice_iter(&fs::read(self.root.join("root/ca.pem")).unwrap())
        {
            roots.add(cert.unwrap()).unwrap();
        }
        let builder =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .unwrap()
                .with_root_certificates(roots);
        let config = if let Some(identity) = identity {
            let chain = CertificateDer::pem_slice_iter(
                &fs::read(identity.root.join("client/cert.pem")).unwrap(),
            )
            .collect::<Result<Vec<_>, _>>()
            .unwrap();
            let key = PrivateKeyDer::from_pem_slice(
                &fs::read(identity.root.join("client/key.pem")).unwrap(),
            )
            .unwrap();
            builder.with_client_auth_cert(chain, key).unwrap()
        } else {
            builder.with_no_client_auth()
        };
        TlsConnector::from(Arc::new(config))
    }
}
