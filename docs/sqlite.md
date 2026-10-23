# SQLite storage (fork only)

This fork can store everything in SQLite instead of MySQL. It is a fork-only change: the default build is
upstream's MySQL store, byte for byte, so merges from upstream barely touch it.

## How the swap works

`crates/opentunnel-server/src/lib.rs` picks the module:

```rust
#[cfg(not(feature = "sqlite"))]
pub mod store;
#[cfg(feature = "sqlite")]
#[path = "fork/store.rs"]
pub mod store;
```

- Without `--features sqlite`: upstream's `src/store.rs` compiles. None of the fork code does.
- With it: `src/fork/store.rs` is `crate::store`. It re-exports everything from upstream's store (the shared
  types, `LEASE_MS`, `connect_options`, and upstream's own tests) and shadows `Store` with `src/fork/sqlite.rs`.
  The rest of the crate, including `service.rs`, `jobs.rs` and `migration.rs`, is unchanged.

Upstream files touched: `src/lib.rs` (the `cfg` above), `Cargo.toml` (the `sqlite` feature and nothing else),
and `Cargo.lock` (generated), plus the one-line build change in the `Dockerfile` below.

The plan file at `src/fork/UPSTREAM` records the upstream commit the SQLite SQL was last compared against, and
`scripts/fork-sync-check.sh` reports what changed in upstream's `store.rs` since then.

## Building and running

```bash
cargo build --release --features sqlite -p opentunnel-server
DATABASE_URL=sqlite:///var/lib/opentunnel/opentunnel.db ./target/release/opentunnel-server serve
```

`DATABASE_URL` must be a `sqlite:` URL. A `mysql://` URL is refused at startup with a clear message: this build
has one backend, chosen at compile time.

- `sqlite:///absolute/path.db` (three slashes) and `sqlite://relative/path.db` both work.
- `sqlite::memory:` works for a throwaway process; WAL is skipped for it.
- The parent directory must already exist and be writable. The file is created when missing.
- SQLite creates `path.db-wal` and `path.db-shm` next to the file. Keep all three together; do not put them on
  NFS or a network filesystem.

For the Fly.io image, add the feature to the existing build step (the only Dockerfile change):

```dockerfile
cargo build --release --locked --features sqlite -p opentunnel-server
```

If that one line is undesirable, `default = ["sqlite"]` in `crates/opentunnel-server/Cargo.toml` builds SQLite by
default instead; then verify upstream with `cargo test -p opentunnel-server --no-default-features --lib`.

## Limits

SQLite has one writer and one file, so this build serves one database from **one machine at a time**:

- Do not run the blue-green or multi-machine setup of `fly.toml` against one SQLite file. With a Fly volume,
  keep a single machine (`fly scale count 1`); two machines on one volume would contend on the write lock, and
  two machines on different volumes would each have half the tunnels.
- The mesh (`INTERNAL_LISTEN`) exists to share tunnels between machines. With one machine it has nothing to share;
  leave it off.
- The pool is capped at 8 connections internally (WAL lets readers continue during a write). Writes wait up to
  5 seconds for the write lock before returning a storage error, which the callers already treat as transient.

Everything else behaves as on MySQL, including tunnel revisions, import outcomes, alarms, job leases and rate
limits. The SQLite code uses `BEGIN IMMEDIATE` where MySQL used `SELECT ... FOR UPDATE`, `MAX(a, b)` where MySQL
used `GREATEST`, `ON CONFLICT` for upserts, and deletes rate-limit rows through a subquery instead of
`DELETE ... LIMIT`.

## Backups and moving data

- Copy the file with SQLite's backup command, which handles a live WAL:
  `sqlite3 /var/lib/opentunnel/opentunnel.db ".backup '/backup/opentunnel.db'"`.
- Or stop the server and copy `opentunnel.db` together with `opentunnel.db-wal` and `opentunnel.db-shm`.
- The CLI still imports and exports upstream's JSON format, so moving between MySQL and SQLite uses the normal
  tools:
  - from a MySQL build: `DATABASE_URL=mysql://... opentunnel-server export tunnels.json`
  - to this build: `DATABASE_URL=sqlite:///var/lib/opentunnel/opentunnel.db opentunnel-server import tunnels.json`

## Tests

The integration tests in `crates/opentunnel-server/tests/` are written against MySQL (they parse the URL for a
host and port, query rows through `sqlx::mysql`, and unwrap `TEST_DATABASE_URL`), so in this build run the
library tests, which include the SQLite store tests and the whole service suite:

```bash
cargo test -p opentunnel-server --features sqlite --lib
```

Each test gets a fresh database file in `TEST_SQLITE_DIR` (default: the system temporary directory). Set it to
keep them somewhere else:

```bash
TEST_SQLITE_DIR=/var/tmp/opentunnel-tests cargo test -p opentunnel-server --features sqlite --lib
```

`TEST_DATABASE_URL` stays MySQL-only. Upstream's own `store.rs` tests still compile under the feature and run when
it is set; `test_database_url()` in the SQLite build returns `None`, so the one test that needs a real MySQL round
trip skips itself. The full integration suite can still be run against MySQL with the default build:

```bash
TEST_DATABASE_URL=mysql://root@127.0.0.1:3306/opentunnel cargo test -p opentunnel-server
```

## Merging upstream

```bash
git fetch upstream            # or: git fetch origin   (this repo's default branch is master)
git merge upstream/master
# Cargo.lock conflicts: take either side, then regenerate against the merged manifests
git checkout --theirs Cargo.lock && cargo check -p opentunnel-server && git add Cargo.lock

cargo test -p opentunnel-server --lib                     # upstream build, untouched
cargo test -p opentunnel-server --features sqlite --lib   # the SQLite implementation
scripts/fork-sync-check.sh                                # what changed in store.rs since the last review
```

The compiler is the main safety net: if upstream adds or changes a `Store` method, a type field or a signature,
the service code fails to compile against `src/fork/sqlite.rs` until it is mirrored. What the compiler cannot see
is **SQL semantics**: a changed `WHERE` clause, a new conditional update, a new column. `scripts/fork-sync-check.sh`
shows the diff, the `SCHEMA_VERSION` on both sides, and the method names that exist on only one side. After
reviewing it, update `synced-upstream:` in `src/fork/UPSTREAM` and commit that with the merge.

When upstream bumps `SCHEMA_VERSION`, mirror the schema change in `src/fork/sqlite.rs` (the `TABLES`, `INDEXES`
or `RATE_LIMITS` constants) and bump the local `SCHEMA_VERSION` in the same commit. A SQLite file opened by a
newer server is refused, exactly like MySQL, so an old binary cannot corrupt a migrated file.

## Removing the fork

1. Delete `crates/opentunnel-server/src/fork/`.
2. Replace the `cfg` block in `src/lib.rs` with the upstream `pub mod store;`.
3. Delete the `[features]` section from `crates/opentunnel-server/Cargo.toml` (or just the `sqlite` line).
4. Regenerate `Cargo.lock` with `cargo check -p opentunnel-server`.
