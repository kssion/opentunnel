//! Certificate trust for the control plane: the API and the bridge
//! WebSocket. Tunneled traffic never uses it; that TLS terminates locally
//! with the tunnel's own certificate.

use std::path::{Path, PathBuf};
use std::sync::Arc;

use rustls::{ClientConfig, RootCertStore};
use rustls_pki_types::CertificateDer;
use rustls_pki_types::pem::PemObject;
use tokio_tungstenite::tungstenite::client::IntoClientRequest;
use tracing::{debug, warn};

use crate::error::{Error, Result};
use crate::http_proxy::{Io, Proxies};

/// Environment variable naming a PEM file of extra CA certificates to trust.
pub const CA_CERT_ENV: &str = "OPENTUNNEL_CA_CERT";

/// Reads the certificates in a PEM file, failing when it has none.
pub fn read_ca_certificates(path: &Path) -> Result<Vec<CertificateDer<'static>>> {
    let pem = std::fs::read(path).map_err(|source| Error::Io {
        context: format!("reading CA certificates from {}", path.display()),
        source,
    })?;
    let certificates = CertificateDer::pem_slice_iter(&pem)
        .collect::<std::result::Result<Vec<_>, _>>()
        .map_err(|error| {
            Error::Invalid(format!(
                "invalid CA certificates in {}: {error}",
                path.display()
            ))
        })?;
    if certificates.is_empty() {
        return Err(Error::Invalid(format!(
            "no PEM certificates in {}",
            path.display()
        )));
    }
    Ok(certificates)
}

/// The roots the client trusts: the bundled Mozilla roots, the OS store
/// (which honors `SSL_CERT_FILE` and `SSL_CERT_DIR`), and the CA file given
/// here or by `OPENTUNNEL_CA_CERT`. Problems with any source but the bundled
/// roots are logged and skipped.
pub(crate) fn roots(ca_cert: Option<&Path>) -> RootCertStore {
    let ca_cert = ca_cert
        .map(Path::to_path_buf)
        .or_else(|| std::env::var_os(CA_CERT_ENV).map(PathBuf::from));
    let extra = match ca_cert {
        Some(path) => read_ca_certificates(&path).unwrap_or_else(|error| {
            warn!(%error, "ignoring the configured CA certificates");
            Vec::new()
        }),
        None => Vec::new(),
    };
    build_roots(rustls_native_certs::load_native_certs(), extra)
}

pub(crate) fn build_roots(
    native: rustls_native_certs::CertificateResult,
    extra: Vec<CertificateDer<'static>>,
) -> RootCertStore {
    let mut roots = RootCertStore::empty();
    roots.add_parsable_certificates(webpki_root_certs::TLS_SERVER_ROOT_CERTS.iter().cloned());
    for error in &native.errors {
        debug!(%error, "skipping native root certificates");
    }
    let (added, ignored) = roots.add_parsable_certificates(native.certs);
    debug!(added, ignored, "loaded native root certificates");
    for certificate in extra {
        if let Err(error) = roots.add(certificate) {
            warn!(%error, "ignoring an invalid CA certificate");
        }
    }
    roots
}

/// TLS settings for the API (`h2` and `http/1.1` offered) and the bridge
/// WebSocket (no ALPN), sharing one root store.
#[derive(Debug, Clone)]
pub(crate) struct Trust {
    pub http: ClientConfig,
    pub websocket: Arc<ClientConfig>,
}

impl Trust {
    pub fn new(roots: RootCertStore) -> Self {
        let websocket =
            ClientConfig::builder_with_provider(Arc::new(rustls::crypto::ring::default_provider()))
                .with_safe_default_protocol_versions()
                .expect("ring supports the default protocol versions")
                .with_root_certificates(roots)
                .with_no_client_auth();
        let mut http = websocket.clone();
        http.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
        Self {
            http,
            websocket: Arc::new(websocket),
        }
    }
}

pub(crate) type WebSocket =
    tokio_tungstenite::WebSocketStream<tokio_tungstenite::MaybeTlsStream<Box<dyn Io>>>;

/// Opens a WebSocket that verifies `wss://` servers against `trust`,
/// through the proxy `proxies` select for it.
pub(crate) async fn connect_websocket(
    request: impl IntoClientRequest,
    trust: &Trust,
    proxies: &Proxies,
) -> Result<WebSocket> {
    let request = request
        .into_client_request()
        .map_err(|error| Error::Bridge(error.to_string()))?;
    let stream = crate::http_proxy::open(request.uri(), proxies, trust).await?;
    let connector = tokio_tungstenite::Connector::Rustls(trust.websocket.clone());
    tokio_tungstenite::client_async_tls_with_config(request, stream, None, Some(connector))
        .await
        .map(|(socket, _)| socket)
        .map_err(crate::tunnel::connect_error)
}

#[cfg(test)]
pub(crate) mod tests {
    use super::*;
    use crate::api::Api;
    use futures_util::StreamExt;
    use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
    use reqwest::Url;
    use rustls_pki_types::PrivateKeyDer;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;
    use tokio_rustls::TlsAcceptor;

    /// A throwaway CA and a `localhost` server certificate it signed.
    pub struct Authority {
        pub ca_pem: String,
        pub ca_der: CertificateDer<'static>,
        pub server: Arc<rustls::ServerConfig>,
    }

    impl Authority {
        pub fn new() -> Self {
            let ca_key = KeyPair::generate().unwrap();
            let mut ca_params = CertificateParams::new(Vec::new()).unwrap();
            ca_params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            let ca = ca_params.self_signed(&ca_key).unwrap();
            let issuer = Issuer::new(ca_params, ca_key);
            let key = KeyPair::generate().unwrap();
            let leaf = CertificateParams::new(vec!["localhost".to_owned()])
                .unwrap()
                .signed_by(&key, &issuer)
                .unwrap();
            let server = rustls::ServerConfig::builder_with_provider(Arc::new(
                rustls::crypto::ring::default_provider(),
            ))
            .with_safe_default_protocol_versions()
            .unwrap()
            .with_no_client_auth()
            .with_single_cert(
                vec![leaf.der().clone()],
                PrivateKeyDer::try_from(key.serialize_der()).unwrap(),
            )
            .unwrap();
            Self {
                ca_pem: ca.pem(),
                ca_der: ca.der().clone(),
                server: Arc::new(server),
            }
        }

        /// Serves HTTPS on `localhost`, answering every request with
        /// `200 ok`. Returns the `https://` base.
        pub async fn serve(&self) -> Url {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let acceptor = TlsAcceptor::from(self.server.clone());
            tokio::spawn(async move {
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let Ok(mut stream) = acceptor.accept(stream).await else {
                            return;
                        };
                        let mut buffer = vec![0u8; 4096];
                        let mut request = Vec::new();
                        while !request.windows(4).any(|window| window == b"\r\n\r\n") {
                            let Ok(read) = stream.read(&mut buffer).await else {
                                return;
                            };
                            if read == 0 {
                                return;
                            }
                            request.extend_from_slice(&buffer[..read]);
                        }
                        let _ = stream
                            .write_all(
                                b"HTTP/1.1 200 OK\r\ncontent-length: 2\r\nconnection: close\r\n\r\nok",
                            )
                            .await;
                    });
                }
            });
            Url::parse(&format!("https://localhost:{port}")).unwrap()
        }

        /// Serves bridge WebSockets on `localhost`. Returns the `https://` base.
        pub async fn serve_websocket(&self) -> Url {
            let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
            let port = listener.local_addr().unwrap().port();
            let acceptor = TlsAcceptor::from(self.server.clone());
            tokio::spawn(async move {
                loop {
                    let (stream, _) = listener.accept().await.unwrap();
                    let acceptor = acceptor.clone();
                    tokio::spawn(async move {
                        let Ok(stream) = acceptor.accept(stream).await else {
                            return;
                        };
                        if let Ok(mut socket) = tokio_tungstenite::accept_async(stream).await {
                            while socket.next().await.is_some() {}
                        }
                    });
                }
            });
            Url::parse(&format!("https://localhost:{port}")).unwrap()
        }
    }

    /// Whether the API client and the bridge connector reach the servers.
    async fn reaches(roots: RootCertStore, http: &Url, websocket: &Url) -> (bool, bool) {
        let trust = Trust::new(roots);
        let api = Api::with_trust(http.clone(), trust.clone());
        let http_ok = api.http.get(http.clone()).send().await.is_ok();
        let url = Api::with_trust(websocket.clone(), trust.clone()).connect_url("demo");
        let websocket_ok = connect_websocket(url.as_str(), &trust, &no_proxies())
            .await
            .is_ok();
        (http_ok, websocket_ok)
    }

    pub fn no_proxies() -> Proxies {
        Proxies::new(hyper_util::client::proxy::matcher::Matcher::builder().build())
    }

    fn native(certs: Vec<CertificateDer<'static>>) -> rustls_native_certs::CertificateResult {
        let mut result = rustls_native_certs::CertificateResult::default();
        result.certs = certs;
        result
    }

    pub fn temp_path() -> PathBuf {
        std::env::temp_dir().join(format!("opentunnel-ca-{}.pem", rand::random::<u64>()))
    }

    #[tokio::test]
    async fn bundled_roots_reject_a_private_ca() {
        let authority = Authority::new();
        let (http, websocket) = (authority.serve().await, authority.serve_websocket().await);
        let roots = build_roots(native(Vec::new()), Vec::new());
        assert_eq!(
            reaches(roots.clone(), &http, &websocket).await,
            (false, false)
        );
        let api = Api::with_trust(http.clone(), Trust::new(roots));
        let error = api.http.get(http.clone()).send().await.unwrap_err();
        assert!(format!("{error:?}").contains("UnknownIssuer"), "{error:?}");
    }

    #[tokio::test]
    async fn trusts_an_explicit_ca_file() {
        let authority = Authority::new();
        let (http, websocket) = (authority.serve().await, authority.serve_websocket().await);
        let path = temp_path();
        std::fs::write(&path, &authority.ca_pem).unwrap();
        let extra = read_ca_certificates(&path).unwrap();
        std::fs::remove_file(&path).unwrap();
        let roots = build_roots(native(Vec::new()), extra);
        assert_eq!(reaches(roots, &http, &websocket).await, (true, true));
    }

    #[tokio::test]
    async fn trusts_the_native_store_despite_errors() {
        let authority = Authority::new();
        let (http, websocket) = (authority.serve().await, authority.serve_websocket().await);
        let mut native = native(vec![
            CertificateDer::from(b"not a certificate".to_vec()),
            authority.ca_der.clone(),
        ]);
        native.errors.push(rustls_native_certs::Error {
            context: "test",
            kind: rustls_native_certs::ErrorKind::Os("unreadable store".into()),
        });
        let roots = build_roots(native, Vec::new());
        assert!(roots.len() > webpki_root_certs::TLS_SERVER_ROOT_CERTS.len() / 2);
        assert_eq!(reaches(roots, &http, &websocket).await, (true, true));
    }

    #[test]
    fn rejects_files_without_certificates() {
        let path = temp_path();
        std::fs::write(&path, "not pem").unwrap();
        assert!(read_ca_certificates(&path).is_err());
        std::fs::remove_file(&path).unwrap();
        assert!(read_ca_certificates(&path).is_err());
    }
}
