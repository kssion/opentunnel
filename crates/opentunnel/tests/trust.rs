//! End to end: the API and the bridge trust a private CA named by
//! `SSL_CERT_FILE` (the OS store path) or `OPENTUNNEL_CA_CERT`. The test
//! changes the process environment, so it is the only one in this binary.

mod common;

use std::sync::Arc;
use std::time::Duration;

use common::{TOKEN, authority, identity, serve};
use opentunnel::{Client, ClientOptions, Route, Storage};

/// Whether a client built now reaches the API and the bridge.
fn reaches(server: &Arc<rustls::ServerConfig>) -> (bool, bool) {
    let runtime = tokio::runtime::Runtime::new().unwrap();
    runtime.block_on(async {
        let (base, mut attaches) = serve(server.clone()).await;
        let storage = Storage::at(std::env::temp_dir().join(format!(
            "opentunnel-trust-{}-{}",
            std::process::id(),
            rand::random::<u64>()
        )));
        let identity = identity();
        storage.save("default", &identity).unwrap();
        let client = Client::new(ClientOptions {
            api: Some(base.parse().unwrap()),
            storage: Some(storage.clone()),
            ..Default::default()
        });
        // Failed handshakes are retried with backoff, so only wait briefly.
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
        (api, bridge)
    })
}

#[test]
fn trusts_ca_from_the_environment() {
    let (ca_pem, server) = authority();
    let path = std::env::temp_dir().join(format!(
        "opentunnel-trust-ca-{}-{}.pem",
        std::process::id(),
        rand::random::<u64>()
    ));
    std::fs::write(&path, &ca_pem).unwrap();
    // SAFETY: no other threads run while the environment changes; each
    // check below builds and drops its own runtime.
    unsafe {
        std::env::remove_var("OPENTUNNEL_CA_CERT");
        std::env::remove_var("SSL_CERT_DIR");
        std::env::remove_var("SSL_CERT_FILE");
    }
    assert_eq!(reaches(&server), (false, false));

    unsafe { std::env::set_var("SSL_CERT_FILE", &path) };
    assert_eq!(reaches(&server), (true, true));

    unsafe {
        std::env::remove_var("SSL_CERT_FILE");
        std::env::set_var("OPENTUNNEL_CA_CERT", &path);
    }
    assert_eq!(reaches(&server), (true, true));

    unsafe { std::env::remove_var("OPENTUNNEL_CA_CERT") };
    std::fs::remove_file(&path).unwrap();
}
