//! Helpers shared by the tests that change the process environment.

use std::sync::Arc;

use futures_util::StreamExt;
use opentunnel::Identity;
use opentunnel::protocol::ClientMessage;
use rcgen::{BasicConstraints, CertificateParams, IsCa, Issuer, KeyPair};
use rustls_pki_types::PrivateKeyDer;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::TcpListener;
use tokio::sync::mpsc;
use tokio_rustls::TlsAcceptor;
use tokio_tungstenite::WebSocketStream;
use tokio_tungstenite::tungstenite::Message;
use tokio_tungstenite::tungstenite::handshake::derive_accept_key;
use tokio_tungstenite::tungstenite::protocol::Role;

pub const TUNNEL: &str = r#"{"id":"demo","hostname":"demo.test","state":"offline"}"#;
pub const TOKEN: &str = "secret-token";

/// A throwaway CA as PEM, and a TLS server config for `localhost` it signed.
pub fn authority() -> (String, Arc<rustls::ServerConfig>) {
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
    (ca.pem(), Arc::new(server))
}

/// Serves `GET /api/tunnel/demo` and bridge WebSockets over TLS, reporting
/// the token of each bridge attach.
pub async fn serve(server: Arc<rustls::ServerConfig>) -> (String, mpsc::Receiver<String>) {
    let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
    let base = format!(
        "https://localhost:{}",
        listener.local_addr().unwrap().port()
    );
    let acceptor = TlsAcceptor::from(server);
    let (attaches, receiver) = mpsc::channel(8);
    tokio::spawn(async move {
        loop {
            let (stream, _) = listener.accept().await.unwrap();
            let acceptor = acceptor.clone();
            let attaches = attaches.clone();
            tokio::spawn(async move {
                let Ok(mut stream) = acceptor.accept(stream).await else {
                    return;
                };
                let mut head = Vec::new();
                let mut buffer = [0u8; 4096];
                while !head.windows(4).any(|window| window == b"\r\n\r\n") {
                    match stream.read(&mut buffer).await {
                        Ok(0) | Err(_) => return,
                        Ok(read) => head.extend_from_slice(&buffer[..read]),
                    }
                }
                let head = String::from_utf8_lossy(&head).into_owned();
                let key = head.lines().find_map(|line| {
                    let (name, value) = line.split_once(':')?;
                    name.eq_ignore_ascii_case("sec-websocket-key")
                        .then(|| value.trim().to_owned())
                });
                let Some(key) = key else {
                    let response = format!(
                        "HTTP/1.1 200 OK\r\ncontent-type: application/json\r\ncontent-length: {}\r\nconnection: close\r\n\r\n{TUNNEL}",
                        TUNNEL.len()
                    );
                    let _ = stream.write_all(response.as_bytes()).await;
                    return;
                };
                let response = format!(
                    "HTTP/1.1 101 Switching Protocols\r\nupgrade: websocket\r\nconnection: Upgrade\r\nsec-websocket-accept: {}\r\nsec-websocket-protocol: opentunnel\r\n\r\n",
                    derive_accept_key(key.as_bytes())
                );
                if stream.write_all(response.as_bytes()).await.is_err() {
                    return;
                }
                let mut socket = WebSocketStream::from_raw_socket(stream, Role::Server, None).await;
                if let Some(Ok(Message::Text(text))) = socket.next().await
                    && let Ok(ClientMessage::Attach { token, .. }) = serde_json::from_str(&text)
                {
                    let _ = attaches.send(token).await;
                }
            });
        }
    });
    (base, receiver)
}

pub fn identity() -> Identity {
    let key = KeyPair::generate().unwrap();
    let certificate = CertificateParams::new(vec!["demo.test".to_owned()])
        .unwrap()
        .self_signed(&key)
        .unwrap();
    Identity {
        id: "demo".into(),
        hostname: "demo.test".into(),
        token: TOKEN.into(),
        private_key: key.serialize_pem(),
        certificate: certificate.pem(),
        chain: String::new(),
        certificate_expiry: "2099-01-01T00:00:00.000Z".into(),
    }
}
