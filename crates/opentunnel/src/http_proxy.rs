//! The bridge WebSocket's connection, through an HTTP proxy when the
//! environment names one. The proxy is chosen by the same matcher reqwest
//! uses for the API (`HTTPS_PROXY` for `wss://`, `HTTP_PROXY` for `ws://`,
//! then `ALL_PROXY`, minus `NO_PROXY`), so both connections agree.

use std::fmt;
use std::sync::Arc;

use hyper_util::client::proxy::matcher::{Intercept, Matcher};
use rustls_pki_types::ServerName;
use tokio::io::{AsyncRead, AsyncReadExt, AsyncWrite, AsyncWriteExt};
use tokio::net::TcpStream;
use tokio_rustls::TlsConnector;
use tokio_tungstenite::tungstenite::http::Uri;
use tracing::debug;

use crate::error::{Error, Result};
use crate::tls::Trust;

/// Longest response head accepted from a proxy.
const MAX_RESPONSE_HEAD: usize = 16 * 1024;

pub(crate) trait Io: AsyncRead + AsyncWrite + Send + Unpin {}
impl<T: AsyncRead + AsyncWrite + Send + Unpin> Io for T {}

/// The proxy settings, read from the environment once, like reqwest's.
#[derive(Clone)]
pub(crate) struct Proxies(Arc<Matcher>);

impl fmt::Debug for Proxies {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The matcher's own output would include proxy credentials.
        formatter.write_str("Proxies")
    }
}

impl Proxies {
    pub fn from_env() -> Self {
        Self::new(Matcher::from_system())
    }

    pub fn new(matcher: Matcher) -> Self {
        Self(Arc::new(matcher))
    }

    /// The proxy for a `ws://` or `wss://` destination, matched as the
    /// `http://` or `https://` one it upgrades.
    fn intercept(&self, host: &str, port: u16, secure: bool) -> Option<Intercept> {
        let scheme = if secure { "https" } else { "http" };
        let uri: Uri = format!("{scheme}://{}/", authority(host, port))
            .parse()
            .ok()?;
        self.0.intercept(&uri)
    }
}

fn authority(host: &str, port: u16) -> String {
    if host.contains(':') {
        format!("[{host}]:{port}")
    } else {
        format!("{host}:{port}")
    }
}

/// Opens a connection to the WebSocket server of `uri`, a tunnel through the
/// proxy `proxies` select for it or a direct one.
pub(crate) async fn open(uri: &Uri, proxies: &Proxies, trust: &Trust) -> Result<Box<dyn Io>> {
    let secure = uri.scheme_str() == Some("wss");
    let host = uri
        .host()
        .ok_or_else(|| Error::Bridge("bridge URL has no host".into()))?;
    let host = host.trim_start_matches('[').trim_end_matches(']');
    let port = uri.port_u16().unwrap_or(if secure { 443 } else { 80 });
    match proxies.intercept(host, port, secure) {
        None => {
            let stream = TcpStream::connect((host, port))
                .await
                .map_err(|error| Error::Bridge(format!("connecting to {host}:{port}: {error}")))?;
            Ok(Box::new(stream))
        }
        Some(proxy) => tunnel(&proxy, host, port, trust).await,
    }
}

/// Connects to the proxy (over TLS for an `https://` one) and asks it to
/// `CONNECT` to `host:port`.
async fn tunnel(proxy: &Intercept, host: &str, port: u16, trust: &Trust) -> Result<Box<dyn Io>> {
    let uri = proxy.uri();
    let secure = match uri.scheme_str() {
        Some("http") => false,
        Some("https") => true,
        scheme => {
            return Err(Error::Invalid(format!(
                "unsupported proxy scheme '{}' for the bridge: OpenTunnel connects through http:// and https:// proxies",
                scheme.unwrap_or_default()
            )));
        }
    };
    let proxy_host = uri
        .host()
        .ok_or_else(|| Error::Invalid("the proxy URL has no host".into()))?
        .trim_start_matches('[')
        .trim_end_matches(']');
    let proxy_port = uri.port_u16().unwrap_or(if secure { 443 } else { 80 });
    let proxy_address = authority(proxy_host, proxy_port);
    debug!(proxy = %proxy_address, "connecting the bridge through a proxy");
    let failed = |error: std::io::Error| Error::Bridge(format!("proxy {proxy_address}: {error}"));

    let tcp = TcpStream::connect((proxy_host, proxy_port))
        .await
        .map_err(failed)?;
    let mut stream: Box<dyn Io> = if secure {
        let name = ServerName::try_from(proxy_host.to_owned())
            .map_err(|_| Error::Invalid(format!("invalid proxy host {proxy_host}")))?;
        let connector = TlsConnector::from(trust.websocket.clone());
        Box::new(connector.connect(name, tcp).await.map_err(failed)?)
    } else {
        Box::new(tcp)
    };

    let target = authority(host, port);
    let mut request = format!("CONNECT {target} HTTP/1.1\r\nHost: {target}\r\n");
    if let Some(credentials) = proxy.basic_auth().and_then(|value| value.to_str().ok()) {
        request.push_str("Proxy-Authorization: ");
        request.push_str(credentials);
        request.push_str("\r\n");
    }
    request.push_str("\r\n");
    stream.write_all(request.as_bytes()).await.map_err(failed)?;

    match read_status(&mut stream).await.map_err(failed)? {
        200..=299 => Ok(stream),
        407 => Err(Error::Bridge(format!(
            "proxy {proxy_address} requires authentication (HTTP 407)"
        ))),
        status => Err(Error::Bridge(format!(
            "proxy {proxy_address} refused to connect to {target} (HTTP {status})"
        ))),
    }
}

/// Reads a response head byte by byte, so nothing after it is consumed, and
/// returns its status.
async fn read_status(stream: &mut Box<dyn Io>) -> std::io::Result<u16> {
    let mut head = Vec::new();
    while !head.ends_with(b"\r\n\r\n") {
        if head.len() >= MAX_RESPONSE_HEAD {
            return Err(std::io::Error::other("response head too long"));
        }
        let mut byte = [0u8];
        if stream.read(&mut byte).await? == 0 {
            return Err(std::io::ErrorKind::UnexpectedEof.into());
        }
        head.push(byte[0]);
    }
    let line = head.split(|byte| *byte == b'\n').next().unwrap_or_default();
    String::from_utf8_lossy(line)
        .split_whitespace()
        .nth(1)
        .and_then(|status| status.parse().ok())
        .filter(|_| line.starts_with(b"HTTP/1."))
        .ok_or_else(|| std::io::Error::other("invalid response"))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tls::tests::Authority;
    use rustls::RootCertStore;
    use tokio::net::TcpListener;
    use tokio::sync::mpsc;
    use tokio_rustls::TlsAcceptor;

    /// A request a test proxy received: its request line and `Proxy-Authorization`.
    type Received = (String, Option<String>);

    /// An HTTP proxy that answers `CONNECT` with `status`, tunnelling to
    /// 127.0.0.1 on the requested port when it is 200. Serves TLS with `tls`.
    async fn proxy(
        status: u16,
        tls: Option<Arc<rustls::ServerConfig>>,
    ) -> (u16, mpsc::UnboundedReceiver<Received>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let (sender, receiver) = mpsc::unbounded_channel();
        tokio::spawn(async move {
            loop {
                let (stream, _) = listener.accept().await.unwrap();
                let sender = sender.clone();
                let tls = tls.clone();
                tokio::spawn(async move {
                    let mut client: Box<dyn Io> = match tls {
                        Some(config) => match TlsAcceptor::from(config).accept(stream).await {
                            Ok(stream) => Box::new(stream),
                            Err(_) => return,
                        },
                        None => Box::new(stream),
                    };
                    let mut head = Vec::new();
                    while !head.ends_with(b"\r\n\r\n") {
                        let mut byte = [0u8];
                        if client.read(&mut byte).await.unwrap_or(0) == 0 {
                            return;
                        }
                        head.push(byte[0]);
                    }
                    let head = String::from_utf8(head).unwrap();
                    let line = head.lines().next().unwrap().to_owned();
                    let authorization = head.lines().find_map(|line| {
                        let (name, value) = line.split_once(':')?;
                        name.eq_ignore_ascii_case("proxy-authorization")
                            .then(|| value.trim().to_owned())
                    });
                    let port: u16 = line
                        .split(' ')
                        .nth(1)
                        .and_then(|target| target.rsplit(':').next())
                        .and_then(|port| port.parse().ok())
                        .unwrap();
                    let _ = sender.send((line, authorization));
                    if status != 200 {
                        let response = format!("HTTP/1.1 {status} No\r\ncontent-length: 0\r\n\r\n");
                        let _ = client.write_all(response.as_bytes()).await;
                        return;
                    }
                    let Ok(mut upstream) = TcpStream::connect(("127.0.0.1", port)).await else {
                        return;
                    };
                    let _ = client
                        .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                        .await;
                    let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
                });
            }
        });
        (port, receiver)
    }

    fn trusting(authority: &Authority) -> Trust {
        let mut roots = RootCertStore::empty();
        roots.add(authority.ca_der.clone()).unwrap();
        Trust::new(roots)
    }

    fn connect_url(base: &reqwest::Url) -> String {
        format!(
            "wss://localhost:{}/api/tunnel/demo/connect",
            base.port().unwrap()
        )
    }

    async fn connect(url: &str, trust: &Trust, matcher: Matcher) -> Result<()> {
        crate::tls::connect_websocket(url, trust, &Proxies::new(matcher))
            .await
            .map(drop)
    }

    #[tokio::test]
    async fn wss_goes_through_an_http_proxy_with_credentials() {
        let authority = Authority::new();
        let server = authority.serve_websocket().await;
        let (port, mut received) = proxy(200, None).await;
        let matcher = Matcher::builder()
            .https(format!("http://user:p%40ss@127.0.0.1:{port}"))
            .http("http://127.0.0.1:1".to_owned())
            .build();
        connect(&connect_url(&server), &trusting(&authority), matcher)
            .await
            .unwrap();
        let (line, authorization) = received.recv().await.unwrap();
        let target = format!("localhost:{}", server.port().unwrap());
        assert_eq!(line, format!("CONNECT {target} HTTP/1.1"));
        // base64("user:p@ss")
        assert_eq!(authorization.as_deref(), Some("Basic dXNlcjpwQHNz"));
    }

    #[tokio::test]
    async fn wss_goes_through_an_https_proxy() {
        let authority = Authority::new();
        let server = authority.serve_websocket().await;
        let (port, mut received) = proxy(200, Some(authority.server.clone())).await;
        let matcher = Matcher::builder()
            .all(format!("https://localhost:{port}"))
            .build();
        connect(&connect_url(&server), &trusting(&authority), matcher)
            .await
            .unwrap();
        assert!(received.recv().await.unwrap().0.starts_with("CONNECT "));
    }

    #[tokio::test]
    async fn no_proxy_connects_directly() {
        let authority = Authority::new();
        let server = authority.serve_websocket().await;
        let (port, mut received) = proxy(200, None).await;
        let matcher = Matcher::builder()
            .https(format!("http://127.0.0.1:{port}"))
            .no("example.com, localhost".to_owned())
            .build();
        connect(&connect_url(&server), &trusting(&authority), matcher)
            .await
            .unwrap();
        assert!(received.try_recv().is_err());
    }

    #[test]
    fn selects_the_proxy_for_the_scheme() {
        let proxies = Proxies::new(
            Matcher::builder()
                .http("http://plain:1".to_owned())
                .https("http://secure:1".to_owned())
                .no("internal".to_owned())
                .build(),
        );
        let host = |host: &str, port, secure| {
            proxies
                .intercept(host, port, secure)
                .map(|proxy| proxy.uri().host().unwrap().to_owned())
        };
        assert_eq!(host("relay.test", 443, true).as_deref(), Some("secure"));
        assert_eq!(host("relay.test", 80, false).as_deref(), Some("plain"));
        assert_eq!(host("relay.internal", 443, true), None);
        assert_eq!(host("::1", 443, true).as_deref(), Some("secure"));
        let all = Proxies::new(Matcher::builder().all("http://all:1".to_owned()).build());
        assert!(all.intercept("relay.test", 443, true).is_some());
        assert!(all.intercept("relay.test", 80, false).is_some());
    }

    #[tokio::test]
    async fn rejects_socks_proxies() {
        let authority = Authority::new();
        let matcher = Matcher::builder()
            .all("socks5://user:secret@127.0.0.1:1080".to_owned())
            .build();
        let error = connect(
            "wss://localhost:1/api/tunnel/demo/connect",
            &trusting(&authority),
            matcher,
        )
        .await
        .unwrap_err();
        assert!(matches!(error, Error::Invalid(_)), "{error:?}");
        let message = error.to_string();
        assert!(
            message.contains("unsupported proxy scheme 'socks5'"),
            "{message}"
        );
        assert!(!message.contains("secret"), "{message}");
    }

    #[tokio::test]
    async fn reports_refusals() {
        let authority = Authority::new();
        for (status, expected) in [
            (407, "requires authentication (HTTP 407)"),
            (403, "refused to connect to localhost:1 (HTTP 403)"),
        ] {
            let (port, _received) = proxy(status, None).await;
            let matcher = Matcher::builder()
                .https(format!("http://127.0.0.1:{port}"))
                .build();
            let error = connect(
                "wss://localhost:1/api/tunnel/demo/connect",
                &trusting(&authority),
                matcher,
            )
            .await
            .unwrap_err();
            assert!(error.to_string().contains(expected), "{error}");
        }
    }
}
