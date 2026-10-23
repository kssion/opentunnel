//! End to end: the API (reqwest) and the bridge go through the proxy
//! `HTTPS_PROXY` names, and both skip it for hosts in `NO_PROXY`. The test
//! changes the process environment, so it is the only one in this binary.

mod common;

use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::Duration;

use common::{TOKEN, authority, identity, serve};
use opentunnel::{Client, ClientOptions, Route, Storage};
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};

/// Runs an HTTP proxy on `listener` that tunnels `CONNECT` to 127.0.0.1 on
/// the requested port, counting the tunnels to `localhost`.
fn proxy(listener: std::net::TcpListener) -> Arc<AtomicUsize> {
    listener.set_nonblocking(true).unwrap();
    let listener = TcpListener::from_std(listener).unwrap();
    let tunnels = Arc::new(AtomicUsize::new(0));
    let counter = tunnels.clone();
    tokio::spawn(async move {
        loop {
            let (mut client, _) = listener.accept().await.unwrap();
            let counter = counter.clone();
            tokio::spawn(async move {
                let mut head = Vec::new();
                while !head.ends_with(b"\r\n\r\n") {
                    let mut byte = [0u8];
                    if client.read(&mut byte).await.unwrap_or(0) == 0 {
                        return;
                    }
                    head.push(byte[0]);
                }
                let head = String::from_utf8(head).unwrap();
                let Some(target) = head
                    .strip_prefix("CONNECT localhost:")
                    .and_then(|rest| rest.split(' ').next())
                else {
                    return;
                };
                let port: u16 = target.parse().unwrap();
                counter.fetch_add(1, Ordering::SeqCst);
                let mut upstream = TcpStream::connect(("127.0.0.1", port)).await.unwrap();
                client
                    .write_all(b"HTTP/1.1 200 Connection established\r\n\r\n")
                    .await
                    .unwrap();
                let _ = tokio::io::copy_bidirectional(&mut client, &mut upstream).await;
            });
        }
    });
    tunnels
}

/// Whether a client built now reaches the API and the bridge, and whether
/// the proxy opened a tunnel meanwhile. `env` is applied before the client is
/// built; the proxy's address replaces `{proxy}` in it.
fn reaches(
    server: &Arc<rustls::ServerConfig>,
    ca: &std::path::Path,
    env: &[(&str, &str)],
) -> (bool, bool, bool) {
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let proxy_port = listener.local_addr().unwrap().port();
    for name in [
        "HTTPS_PROXY",
        "https_proxy",
        "HTTP_PROXY",
        "http_proxy",
        "ALL_PROXY",
        "all_proxy",
        "NO_PROXY",
        "no_proxy",
    ] {
        // SAFETY: no other threads run while the environment changes; each
        // check builds and drops its own runtime.
        unsafe { std::env::remove_var(name) };
    }
    for (name, value) in env {
        let value = value.replace("{proxy}", &format!("127.0.0.1:{proxy_port}"));
        // SAFETY: as above.
        unsafe { std::env::set_var(name, value) };
    }
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let tunnels = proxy(listener);
        let (base, mut attaches) = serve(server.clone()).await;
        let storage = Storage::at(std::env::temp_dir().join(format!(
            "opentunnel-proxy-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        )));
        storage.save("default", &identity()).unwrap();
        let client = Client::new(ClientOptions {
            api: Some(base.parse().unwrap()),
            storage: Some(storage.clone()),
            ca_cert: Some(ca.to_owned()),
        });
        let api = tokio::time::timeout(Duration::from_secs(1), client.api().get(TOKEN, "demo"))
            .await
            .is_ok_and(|info| info.is_ok_and(|info| info.id == "demo"));
        let routes = [("app".to_owned(), Route::new("127.0.0.1:9"))].into();
        let tunnel = client.connect("default", routes).unwrap();
        let bridge = tokio::time::timeout(Duration::from_secs(2), attaches.recv())
            .await
            .is_ok_and(|token| token.as_deref() == Some(TOKEN));
        drop(tunnel);
        let _ = std::fs::remove_dir_all(storage.root());
        (api, bridge, tunnels.load(Ordering::SeqCst) > 0)
    })
}

#[test]
fn api_and_bridge_share_the_environment_proxy() {
    let (ca_pem, server) = authority();
    let ca = std::env::temp_dir().join(format!(
        "opentunnel-proxy-ca-{}-{}.pem",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::write(&ca, &ca_pem).unwrap();

    // Neither goes around a proxy that refuses connections, so when they
    // connect with a working one, both went through it.
    assert_eq!(
        reaches(&server, &ca, &[("HTTPS_PROXY", "http://127.0.0.1:1")]),
        (false, false, false)
    );
    assert_eq!(
        reaches(&server, &ca, &[("HTTPS_PROXY", "http://{proxy}")]),
        (true, true, true)
    );
    assert_eq!(
        reaches(&server, &ca, &[("ALL_PROXY", "{proxy}")]),
        (true, true, true)
    );
    // HTTP_PROXY is for http:// and ws:// only.
    assert_eq!(
        reaches(&server, &ca, &[("HTTP_PROXY", "http://{proxy}")]),
        (true, true, false)
    );
    assert_eq!(
        reaches(
            &server,
            &ca,
            &[
                ("HTTPS_PROXY", "http://{proxy}"),
                ("NO_PROXY", "example.com,localhost")
            ]
        ),
        (true, true, false)
    );

    // A SOCKS proxy stops the tunnel instead of being bypassed.
    // SAFETY: no runtime is running.
    unsafe {
        std::env::remove_var("NO_PROXY");
        std::env::remove_var("HTTPS_PROXY");
        std::env::set_var("ALL_PROXY", "socks5://127.0.0.1:1080");
    }
    let runtime = tokio::runtime::Runtime::new().unwrap();
    let error = runtime.block_on(async {
        let (base, _attaches) = serve(server.clone()).await;
        let storage = Storage::at(std::env::temp_dir().join(format!(
            "opentunnel-proxy-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        )));
        storage.save("default", &identity()).unwrap();
        let client = Client::new(ClientOptions {
            api: Some(base.parse().unwrap()),
            storage: Some(storage.clone()),
            ca_cert: Some(ca.clone()),
        });
        let routes = [("app".to_owned(), Route::new("127.0.0.1:9"))].into();
        let mut tunnel = client.connect("default", routes).unwrap();
        let result = tokio::time::timeout(Duration::from_secs(2), tunnel.wait()).await;
        let _ = std::fs::remove_dir_all(storage.root());
        result.expect("the tunnel stops").unwrap_err()
    });
    drop(runtime);
    assert!(
        error
            .to_string()
            .contains("unsupported proxy scheme 'socks5'"),
        "{error}"
    );

    for name in ["HTTPS_PROXY", "HTTP_PROXY", "ALL_PROXY", "NO_PROXY"] {
        // SAFETY: no runtime is running anymore.
        unsafe { std::env::remove_var(name) };
    }
    std::fs::remove_file(&ca).unwrap();
}
