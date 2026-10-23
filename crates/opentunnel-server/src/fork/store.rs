//! Fork: the SQLite store, selected with `--features sqlite`.
//!
//! `lib.rs` swaps `crate::store` for this module, so nothing else in the crate changes. Every upstream item is
//! re-exported unchanged (the shared types, `LEASE_MS`, `connect_options`, and the upstream tests, which still
//! run against MySQL when `TEST_DATABASE_URL` is set) except `Store`, which points at the SQLite implementation
//! in `sqlite.rs`.
//!
//! Removing the fork is deleting `src/fork/`, the `sqlite` feature in `Cargo.toml` and the `cfg` in `lib.rs`.

#[allow(dead_code)] // The upstream MySQL store compiles, but nothing in this build constructs it.
#[path = "../store.rs"]
mod upstream;

#[path = "sqlite.rs"]
mod sqlite;

pub use self::sqlite::{NewerSchema, Store};
pub use upstream::*;

/// A store in a new, empty SQLite database. Tests in [`upstream`] still use `TEST_DATABASE_URL` (MySQL); these
/// use `TEST_SQLITE_DIR` (a directory, `/tmp` by default) so several test processes do not collide.
#[doc(hidden)]
pub async fn test_store() -> Option<Store> {
    Some(
        Store::open(&sqlite::test_url())
            .await
            .expect("migrating the test database"),
    )
}

/// The whole crate's tests use [`test_store`] in this build. The one test that needs a real MySQL round trip
/// skips itself here: it parses the URL as `mysql://` and drives the MySQL pool directly.
#[doc(hidden)]
pub async fn test_database_url() -> Option<String> {
    eprintln!(
        "skipping: this build stores in SQLite (--features sqlite); the test needs a mysql:// TEST_DATABASE_URL \
         and a build without the feature"
    );
    None
}
