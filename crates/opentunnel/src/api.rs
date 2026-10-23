use std::time::Duration;

use crate::protocol::api::{
    ApiError, BindCertificateRequest, CertificateInfo, CreateTunnelResponse, RETRIES, Repeat,
    TunnelInfo, retry_delay_ms, retryable_status, status_message,
};
use reqwest::{Method, RequestBuilder, Response, Url};
use tracing::debug;

use crate::error::{Error, Result};
use crate::http_proxy::Proxies;
use crate::tls::Trust;

#[derive(Debug, Clone)]
pub struct Api {
    base: Url,
    pub(crate) http: reqwest::Client,
    trust: Trust,
    proxies: Proxies,
    /// Divides the retry delays, so tests need not wait for them.
    pub(crate) retry_scale: u64,
}

impl Api {
    /// An API client trusting the bundled Mozilla roots, the OS store, and
    /// the CA file in `OPENTUNNEL_CA_CERT`, if any.
    pub fn new(base: Url) -> Self {
        Self::with_trust(base, Trust::new(crate::tls::roots(None)))
    }

    pub(crate) fn with_trust(base: Url, trust: Trust) -> Self {
        crate::install_crypto_provider();
        let http = reqwest::Client::builder()
            .tls_backend_preconfigured(trust.http.clone())
            .build()
            .expect("HTTP client configuration is valid");
        Self {
            base,
            http,
            trust,
            proxies: Proxies::from_env(),
            retry_scale: 1,
        }
    }

    /// TLS settings for the bridge WebSocket, sharing the API's roots.
    pub(crate) fn trust(&self) -> &Trust {
        &self.trust
    }

    /// The proxies for the bridge WebSocket, chosen like the API's.
    pub(crate) fn proxies(&self) -> &Proxies {
        &self.proxies
    }

    pub fn base(&self) -> &Url {
        &self.base
    }

    fn request(&self, method: Method, path: &str, token: Option<&str>) -> RequestBuilder {
        let url = self.base.join(path).expect("API paths are valid");
        let request = self.http.request(method, url).header(
            "user-agent",
            concat!("opentunnel/", env!("CARGO_PKG_VERSION")),
        );
        match token {
            Some(token) => request.bearer_auth(token),
            None => request,
        }
    }

    /// Sends a request, again after transient failures (network errors, 429, 5xx including Cloudflare's 52x)
    /// as far as `repeat` allows, with capped exponential backoff. Fails with the last error.
    async fn send(&self, repeat: Repeat, build: impl Fn() -> RequestBuilder) -> Result<Response> {
        let mut attempt = 0;
        loop {
            let retry_after = match build().send().await {
                Ok(response) if response.status().is_success() => return Ok(response),
                Ok(response) => {
                    let status = response.status().as_u16();
                    if attempt >= RETRIES || !retryable_status(status, repeat) {
                        return Err(error_response(response).await);
                    }
                    debug!(status, attempt, "API request failed; retrying");
                    response
                        .headers()
                        .get(reqwest::header::RETRY_AFTER)
                        .and_then(|value| value.to_str().ok())
                        .map(str::to_owned)
                }
                Err(error) => {
                    if attempt >= RETRIES || !retryable_error(&error, repeat) {
                        return Err(error.into());
                    }
                    debug!(%error, attempt, "API request failed; retrying");
                    None
                }
            };
            let (min, max) = retry_delay_ms(attempt, retry_after.as_deref());
            let delay = rand::random_range(min..=max) / self.retry_scale;
            tokio::time::sleep(Duration::from_millis(delay)).await;
            attempt += 1;
        }
    }

    pub async fn create(&self) -> Result<CreateTunnelResponse> {
        let response = self
            .send(Repeat::Once, || {
                self.request(Method::POST, "/api/tunnel", None)
                    .json(&serde_json::json!({}))
            })
            .await?;
        Ok(response.json().await?)
    }

    pub async fn get(&self, token: &str, id: &str) -> Result<TunnelInfo> {
        let response = self
            .send(Repeat::Idempotent, || {
                self.request(Method::GET, &tunnel_path(id, ""), Some(token))
            })
            .await?;
        Ok(response.json().await?)
    }

    /// Binding the CSR a tunnel already has answers with its current certificate, so this is retried like a read.
    pub async fn bind_certificate(
        &self,
        token: &str,
        id: &str,
        csr: &str,
    ) -> Result<CertificateInfo> {
        let body = BindCertificateRequest {
            csr: csr.to_owned(),
        };
        let response = self
            .send(Repeat::Idempotent, || {
                self.request(Method::POST, &tunnel_path(id, "/certificate"), Some(token))
                    .json(&body)
            })
            .await?;
        Ok(response.json().await?)
    }

    pub async fn certificate(&self, token: &str, id: &str) -> Result<CertificateInfo> {
        let response = self
            .send(Repeat::Idempotent, || {
                self.request(Method::GET, &tunnel_path(id, "/certificate"), Some(token))
            })
            .await?;
        Ok(response.json().await?)
    }

    /// A repeated delete would answer 404, so it is retried only when it cannot have arrived.
    pub async fn remove(&self, token: &str, id: &str) -> Result<()> {
        self.send(Repeat::Once, || {
            self.request(Method::DELETE, &tunnel_path(id, ""), Some(token))
        })
        .await
        .map(drop)
    }

    /// The bridge WebSocket URL for a tunnel.
    pub fn connect_url(&self, id: &str) -> Url {
        let mut url = self
            .base
            .join(&tunnel_path(id, "/connect"))
            .expect("API paths are valid");
        let scheme = if url.scheme() == "https" { "wss" } else { "ws" };
        url.set_scheme(scheme).expect("ws schemes are valid");
        url
    }
}

fn tunnel_path(id: &str, suffix: &str) -> String {
    format!("/api/tunnel/{id}{suffix}")
}

/// Network failures worth another attempt: for a request sent only once, only those before it left.
fn retryable_error(error: &reqwest::Error, repeat: Repeat) -> bool {
    match repeat {
        Repeat::Idempotent => error.is_connect() || error.is_timeout() || error.is_request(),
        Repeat::Once => error.is_connect(),
    }
}

/// The error for a response that failed: the API's own error body, or the status (and Cloudflare's meaning of it).
async fn error_response(response: Response) -> Error {
    let status = response.status().as_u16();
    let body = response.text().await.unwrap_or_default();
    let error = serde_json::from_str::<ApiError>(&body).unwrap_or_else(|_| ApiError {
        tag: "HttpError".into(),
        message: status_message(status, &body),
    });
    Error::Api {
        status,
        tag: error.tag,
        message: error.message,
    }
}

#[cfg(test)]
mod tests {
    use std::sync::Arc;
    use std::sync::atomic::{AtomicUsize, Ordering};

    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    use super::*;

    /// A server answering each request with the next status, then 200 with a tunnel; counts requests.
    async fn server(statuses: Vec<u16>) -> (Api, Arc<AtomicUsize>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let url = format!("http://{}", listener.local_addr().unwrap());
        let count = Arc::new(AtomicUsize::new(0));
        let counter = count.clone();
        tokio::spawn(async move {
            loop {
                let (mut stream, _) = listener.accept().await.unwrap();
                let index = counter.fetch_add(1, Ordering::SeqCst);
                let status = statuses.get(index).copied().unwrap_or(200);
                let mut buffer = vec![0u8; 8192];
                let _ = stream.read(&mut buffer).await;
                let body = if status == 200 {
                    r#"{"id":"abc","hostname":"abc.opentunnel.xyz","state":"offline"}"#.to_owned()
                } else {
                    "<html><body>error code: 525</body></html>".to_owned()
                };
                let response = format!(
                    "HTTP/1.1 {status} X\r\ncontent-type: text/html\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{body}",
                    body.len()
                );
                let _ = stream.write_all(response.as_bytes()).await;
            }
        });
        let mut api = Api::new(Url::parse(&url).unwrap());
        api.retry_scale = 1000;
        (api, count)
    }

    #[tokio::test]
    async fn retries_transient_failures() {
        let (api, count) = server(vec![525, 502, 429]).await;
        let info = api.get("token", "abc").await.unwrap();
        assert_eq!(info.id, "abc");
        assert_eq!(count.load(Ordering::SeqCst), 4);
    }

    #[tokio::test]
    async fn gives_up_with_the_status() {
        let (api, count) = server(vec![525; 10]).await;
        let error = api.certificate("token", "abc").await.unwrap_err();
        assert_eq!(count.load(Ordering::SeqCst), RETRIES as usize + 1);
        assert!(matches!(error, Error::Api { status: 525, .. }));
        assert_eq!(
            error.to_string(),
            "HttpError: Cloudflare 525: the SSL handshake with the server failed (HTTP 525)"
        );
    }

    #[tokio::test]
    async fn retries_creation_only_when_it_cannot_have_arrived() {
        let (api, count) = server(vec![525, 520]).await;
        let error = api.create().await.unwrap_err();
        assert!(matches!(error, Error::Api { status: 520, .. }));
        assert_eq!(count.load(Ordering::SeqCst), 2);
    }

    #[tokio::test]
    async fn does_not_retry_client_errors() {
        let (api, count) = server(vec![404]).await;
        assert!(matches!(
            api.get("token", "abc").await,
            Err(Error::Api { status: 404, .. })
        ));
        assert_eq!(count.load(Ordering::SeqCst), 1);
    }

    #[tokio::test]
    async fn retries_connection_failures() {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let address = listener.local_addr().unwrap();
        drop(listener);
        let mut api = Api::new(Url::parse(&format!("http://{address}")).unwrap());
        api.retry_scale = 1000;
        let started = std::time::Instant::now();
        assert!(matches!(api.create().await, Err(Error::Http(_))));
        // Every attempt was refused, so all were made.
        assert!(started.elapsed() >= Duration::from_millis(7));
    }
}
