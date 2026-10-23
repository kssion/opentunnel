//! SQLite storage for the fork, with the same API as upstream's MySQL [`Store`]. See `fork/store.rs` for how it
//! is swapped in.
//!
//! Records keep the Durable Object's JSON shape byte for byte, exactly like the MySQL store. The schema mirrors
//! `store.rs`'s tables one for one, with SQLite types: every table has a primary key, ids are `TEXT` with the
//! default binary collation (case sensitive, like MySQL's `utf8mb4_bin`), and migrations are idempotent
//! `CREATE TABLE IF NOT EXISTS` statements run at startup.
//!
//! A single process serves the database (SQLite has one writer, see `docs/sqlite.md`). WAL lets readers continue
//! while a write is in flight; writes are short, so `busy_timeout` absorbs the contention. Statements that MySQL
//! ran in a transaction with `FOR UPDATE` use `BEGIN IMMEDIATE`, which takes the write lock up front.

use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result, anyhow, bail};
use sqlx::sqlite::{
    Sqlite, SqliteConnectOptions, SqliteJournalMode, SqlitePool, SqlitePoolOptions,
    SqliteSynchronous,
};
use tracing::{info, warn};

use super::upstream::{
    AttachSnapshot, Conflict, FailedJob, ImportOutcome, Job, JobKind, LEASE_MS, Loaded,
    ServerCertificate,
};
use crate::record::StoredTunnel;

/// The schema version this server writes, kept in sync with upstream's `SCHEMA_VERSION` by hand (the sync script
/// and the tests flag a mismatch): a database at a newer version is refused, so a newer server's file is never
/// opened by an older one.
const SCHEMA_VERSION: i64 = 2;

const TABLES: &[&str] = &[
    r#"CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER NOT NULL PRIMARY KEY,
  applied_at INTEGER NOT NULL
)"#,
    r#"CREATE TABLE IF NOT EXISTS tunnels (
  id TEXT NOT NULL PRIMARY KEY,
  -- The record, exactly as serialized in the Durable Object's StoredTunnel JSON shape.
  record TEXT NOT NULL,
  -- Bumped by every write; writers update only the revision they read.
  revision INTEGER NOT NULL,
  -- Derived from the record on every write, for queries.
  deleted INTEGER NOT NULL DEFAULT 0,
  issuing INTEGER NOT NULL DEFAULT 0,
  -- The renewal alarm (the Durable Object's storage alarm), Unix milliseconds.
  alarm_at INTEGER NULL,
  updated_at INTEGER NOT NULL,
  imported_at INTEGER NULL,
  -- 0 while the row is exactly as last imported, so a later import may refresh it; 1 once this server wrote it.
  local_update INTEGER NOT NULL DEFAULT 1
)"#,
    r#"CREATE TABLE IF NOT EXISTS jobs (
  certificate_id TEXT NOT NULL PRIMARY KEY,
  -- NULL for the server's own certificates.
  tunnel_id TEXT NULL,
  kind TEXT NOT NULL,
  identifiers TEXT NOT NULL,
  csr TEXT NOT NULL,
  -- pending, done, failed or abandoned (no longer wanted).
  status TEXT NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  run_at INTEGER NOT NULL,
  -- The process running the job and until when; another may take it over once the lease expires.
  lease_owner TEXT NULL,
  lease_until INTEGER NULL,
  last_error TEXT NULL,
  created_at INTEGER NOT NULL,
  updated_at INTEGER NOT NULL
)"#,
    r#"CREATE TABLE IF NOT EXISTS server_certificates (
  name TEXT NOT NULL PRIMARY KEY,
  private_key TEXT NOT NULL,
  csr TEXT NOT NULL,
  certificate TEXT NULL,
  chain TEXT NULL,
  expiry TEXT NULL,
  updated_at INTEGER NOT NULL
)"#,
    r#"CREATE TABLE IF NOT EXISTS meta (
  name TEXT NOT NULL PRIMARY KEY,
  value TEXT NOT NULL
)"#,
];

const INDEXES: &[&str] = &[
    "CREATE INDEX IF NOT EXISTS tunnels_alarm ON tunnels (alarm_at)",
    "CREATE INDEX IF NOT EXISTS tunnels_issuing ON tunnels (issuing, deleted)",
    "CREATE INDEX IF NOT EXISTS jobs_due ON jobs (status, run_at)",
    "CREATE INDEX IF NOT EXISTS rate_limits_tat ON rate_limits (tat)",
];

/// Rate limits (`limits.rs`), added without a schema version upstream, so a database at this version gets it
/// when missing (`migrate`).
const RATE_LIMITS: &str = r#"CREATE TABLE IF NOT EXISTS rate_limits (
  -- `create:<client address>` or `issue:<tunnel>`.
  name TEXT NOT NULL PRIMARY KEY,
  -- When the key's budget is full again (GCRA's theoretical arrival time), Unix ms.
  tat INTEGER NOT NULL
)"#;

/// Every statement gives up after this long, so a stalled file cannot hang a request.
const QUERY_TIMEOUT: Duration = Duration::from_secs(10);
/// How long opening a connection may take.
const CONNECT_TIMEOUT: Duration = Duration::from_secs(20);
/// How long a writer waits for the write lock before SQLite returns `SQLITE_BUSY`.
const BUSY_TIMEOUT: Duration = Duration::from_secs(5);
/// Concurrent connections. WAL allows readers during a write; more only queue on the write lock.
const MAX_CONNECTIONS: u32 = 8;

#[derive(Clone)]
pub struct Store {
    pool: SqlitePool,
}

/// The database was migrated by a newer server.
#[derive(Debug, thiserror::Error)]
#[error("database schema {0} is newer than this server ({SCHEMA_VERSION})")]
pub struct NewerSchema(pub(crate) i64);

/// Parses `DATABASE_URL`. This build stores in SQLite only, so a `mysql://` URL is a configuration error rather
/// than a silent fallback.
fn connect_options(url: &str) -> Result<SqliteConnectOptions> {
    let scheme = url.split(':').next().unwrap_or_default();
    if scheme != "sqlite" {
        bail!(
            "this build stores in SQLite (built with --features sqlite): DATABASE_URL must be a sqlite:// URL, \
             not {:?}",
            scheme
        );
    }
    let memory = url.contains(":memory:") || url.contains("mode=memory");
    let mut options = SqliteConnectOptions::from_str(url).context("reading DATABASE_URL")?;
    options = options
        .create_if_missing(true)
        // No foreign keys are used, but turning them on documents the intent and catches accidental ones.
        .foreign_keys(true)
        .busy_timeout(BUSY_TIMEOUT);
    if !memory {
        // WAL survives a restart, readers do not block the writer, and NORMAL is durable across process crashes
        // (only an OS crash may lose the last transactions, which is fine for this data).
        options = options
            .journal_mode(SqliteJournalMode::Wal)
            .synchronous(SqliteSynchronous::Normal);
    }
    Ok(options)
}

fn db(error: sqlx::Error) -> anyhow::Error {
    anyhow::Error::new(error).context("storage unavailable")
}

fn is_unique_violation(error: &sqlx::Error) -> bool {
    error
        .as_database_error()
        .is_some_and(|error| error.is_unique_violation())
}

/// `SQLITE_BUSY` and `SQLITE_LOCKED` (including their extended codes), usually absorbed by `busy_timeout`.
fn retryable(error: &anyhow::Error) -> bool {
    error
        .downcast_ref::<sqlx::Error>()
        .and_then(sqlx::Error::as_database_error)
        .and_then(|error| error.code())
        .and_then(|code| code.parse::<i32>().ok())
        .is_some_and(|code| matches!(code & 0xff, 5 | 6))
}

async fn timed<T>(operation: &'static str, future: impl Future<Output = Result<T>>) -> Result<T> {
    timed_within(operation, QUERY_TIMEOUT, future).await
}

/// [`timed`] with a shorter limit, for operations a client waits on.
async fn timed_within<T>(
    operation: &'static str,
    limit: Duration,
    future: impl Future<Output = Result<T>>,
) -> Result<T> {
    let started = std::time::Instant::now();
    // Boxed, so the futures of callers that make many storage calls stay shallow enough for the compiler's
    // layout computation in release builds.
    let result = match tokio::time::timeout(limit, Box::pin(future)).await {
        Ok(result) => result,
        Err(_) => Err(anyhow!("storage timed out").context("storage unavailable")),
    };
    crate::metrics::db_operation(operation, started.elapsed(), result.is_ok());
    result
}

fn record_flags(record: &StoredTunnel) -> (bool, bool) {
    use opentunnel::protocol::api::CertificateState;
    let issuing = record.renewal.is_some()
        || record.certificate.as_ref().is_some_and(|certificate| {
            matches!(
                certificate.state,
                CertificateState::Issuing | CertificateState::Challenge { .. }
            )
        });
    (record.is_deleted(), issuing)
}

fn parse_kind(value: &str) -> JobKind {
    // `JobKind::parse` is private upstream, so keep this in step with it.
    match value {
        "renew" => JobKind::Renew,
        "server" => JobKind::Server,
        _ => JobKind::Issue,
    }
}

type ServerCertificateRow = (
    String,
    String,
    Option<String>,
    Option<String>,
    Option<String>,
);
type FailedJobRow = (String, Option<String>, String, Option<String>, i64, i64);
type JobRow = (String, Option<String>, String, String, String, i64, i64);

fn failed_job_from_row(
    (certificate_id, tunnel_id, status, last_error, created_at, updated_at): FailedJobRow,
) -> FailedJob {
    FailedJob {
        certificate_id,
        tunnel_id,
        status,
        last_error: last_error.unwrap_or_default(),
        created_at: created_at as u64,
        updated_at: updated_at as u64,
    }
}

fn job_from_row(row: JobRow) -> Result<Job> {
    let (certificate_id, tunnel_id, kind, identifiers, csr, attempts, created_at) = row;
    Ok(Job {
        certificate_id,
        tunnel_id,
        kind: parse_kind(&kind),
        identifiers: serde_json::from_str(&identifiers).context("decoding job identifiers")?,
        csr,
        attempts: attempts.max(0) as u32,
        created_at: created_at as u64,
    })
}

/// Creates the tables unless the database is already at this version. Idempotent and safe to run twice.
async fn migrate(pool: &SqlitePool) -> Result<()> {
    // Read the version first: a file written by a newer server must be refused before any DDL runs against it.
    sqlx::query(
        "CREATE TABLE IF NOT EXISTS schema_migrations (
  version INTEGER NOT NULL PRIMARY KEY,
  applied_at INTEGER NOT NULL
)",
    )
    .execute(pool)
    .await
    .map_err(db)?;
    let version: Option<i64> = sqlx::query_scalar("SELECT MAX(version) FROM schema_migrations")
        .fetch_one(pool)
        .await
        .map_err(db)?;
    if let Some(version) = version {
        if version > SCHEMA_VERSION {
            return Err(NewerSchema(version).into());
        }
        if version == SCHEMA_VERSION {
            // Tables added without a version: created and indexed only while missing, so no DDL runs once they
            // exist.
            sqlx::query(RATE_LIMITS).execute(pool).await.map_err(db)?;
            for index in INDEXES {
                sqlx::query(*index).execute(pool).await.map_err(db)?;
            }
            drop_bridges(pool).await;
            return Ok(());
        }
    }
    for statement in TABLES {
        sqlx::query(*statement).execute(pool).await.map_err(db)?;
    }
    sqlx::query(RATE_LIMITS).execute(pool).await.map_err(db)?;
    for index in INDEXES {
        sqlx::query(*index).execute(pool).await.map_err(db)?;
    }
    sqlx::query(
        "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)
         ON CONFLICT (version) DO NOTHING",
    )
    .bind(SCHEMA_VERSION)
    .bind(crate::clock::Clock::system().now_ms() as i64)
    .execute(pool)
    .await
    .map_err(db)?;
    Ok(())
}

/// Drops `bridges`, the bridge registry of servers before the mesh (schema 2), which nothing reads any more.
async fn drop_bridges(pool: &SqlitePool) {
    let exists: Result<i64> = sqlx::query_scalar(
        "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'bridges'",
    )
    .fetch_one(pool)
    .await
    .map_err(db);
    match exists {
        Ok(0) => {}
        Ok(_) => match sqlx::query("DROP TABLE IF EXISTS bridges")
            .execute(pool)
            .await
        {
            Ok(_) => info!("dropped the unused bridges table"),
            Err(error) => warn!(%error, "could not drop the unused bridges table"),
        },
        Err(error) => warn!(%error, "could not check for the unused bridges table"),
    }
}

impl Store {
    /// A pool that connects on demand, so a database that cannot be opened at startup only delays it.
    pub fn connect(url: &str, max_connections: u32) -> Result<Self> {
        let options = self::connect_options(url)?;
        let max_connections = max_connections.clamp(1, MAX_CONNECTIONS);
        let pool = SqlitePoolOptions::new()
            .max_connections(max_connections)
            .min_connections(1)
            .acquire_timeout(CONNECT_TIMEOUT)
            .connect_lazy_with(options);
        Ok(Self { pool })
    }

    /// Opens and migrates, failing if the database is unavailable (the CLI's import and export).
    pub async fn open(url: &str) -> Result<Self> {
        let store = Self::connect(url, 2)?;
        store.migrate().await?;
        Ok(store)
    }

    /// Migrates, retrying with backoff until the database answers and opens the file (a missing directory, a
    /// permission problem). An incompatible schema is an error at once, and so is a database still unreachable
    /// after `limit` (`None` waits forever), with the last error.
    pub async fn wait_ready(&self, limit: Option<Duration>) -> Result<()> {
        let started = tokio::time::Instant::now();
        let mut delay = Duration::from_millis(500);
        loop {
            match self.migrate().await {
                Ok(()) => {
                    info!(
                        "using SQLite storage: one server process per database file (no mesh or multi-machine \
                         blue-green; see docs/sqlite.md)"
                    );
                    return Ok(());
                }
                Err(error) if error.downcast_ref::<NewerSchema>().is_some() => return Err(error),
                Err(error) => {
                    let waited = started.elapsed();
                    let sleep = match limit {
                        Some(limit) if waited >= limit => {
                            return Err(error.context(format!(
                                "the database was unreachable for {}s at startup",
                                waited.as_secs()
                            )));
                        }
                        Some(limit) => delay.min(limit - waited),
                        None => delay,
                    };
                    warn!(error = %format!("{error:#}"), retry_in = ?sleep, "the database is not ready");
                    tokio::time::sleep(sleep).await;
                    delay = (delay * 2).min(Duration::from_secs(15));
                }
            }
        }
    }

    /// Creates the tables unless the database is already at this version.
    pub async fn migrate(&self) -> Result<()> {
        timed("migrate", migrate(&self.pool)).await
    }

    /// Open connections in the pool, and how many of them are idle.
    pub fn pool_connections(&self) -> (u32, usize) {
        (self.pool.size(), self.pool.num_idle())
    }

    pub async fn close(&self) {
        self.pool.close().await;
    }

    pub async fn tunnel(&self, id: &str) -> Result<Option<Loaded>> {
        Ok(self
            .tunnel_with_alarm(id)
            .await?
            .map(|snapshot| snapshot.loaded))
    }

    /// The tunnel and its alarm, which come in the same read.
    pub async fn tunnel_with_alarm(&self, id: &str) -> Result<Option<AttachSnapshot>> {
        timed("tunnel", self.read(id)).await
    }

    /// The tunnel and its alarm in one read, for an attach. Gives up after `limit`.
    pub async fn attach_snapshot(
        &self,
        id: &str,
        limit: Duration,
    ) -> Result<Option<AttachSnapshot>> {
        timed_within("attach_snapshot", limit, self.read(id)).await
    }

    async fn read(&self, id: &str) -> Result<Option<AttachSnapshot>> {
        let row: Option<(String, i64, Option<i64>)> =
            sqlx::query_as("SELECT record, revision, alarm_at FROM tunnels WHERE id = ?")
                .bind(id)
                .fetch_optional(&self.pool)
                .await
                .map_err(db)?;
        row.map(|(record, revision, alarm)| {
            Ok(AttachSnapshot {
                loaded: Loaded {
                    record: serde_json::from_str(&record).context("decoding a stored tunnel")?,
                    revision: revision as u64,
                },
                alarm: alarm.map(|alarm| alarm as u64),
            })
        })
        .transpose()
    }

    /// Writes a record read at `revision` (0: no row existed) and returns its new revision. Fails with
    /// [`Conflict`] when the row changed meanwhile.
    pub async fn save_tunnel(&self, record: &StoredTunnel, revision: u64, now: u64) -> Result<u64> {
        let json = serde_json::to_string(record)?;
        let (deleted, issuing) = record_flags(record);
        timed("save_tunnel", async {
            if revision == 0 {
                let inserted = sqlx::query(
                    "INSERT INTO tunnels (id, record, revision, deleted, issuing, updated_at, local_update)
                     VALUES (?, ?, 1, ?, ?, ?, 1)",
                )
                .bind(&record.id)
                .bind(&json)
                .bind(deleted)
                .bind(issuing)
                .bind(now as i64)
                .execute(&self.pool)
                .await;
                return match inserted {
                    Ok(_) => Ok(1),
                    Err(error) if is_unique_violation(&error) => Err(Conflict.into()),
                    Err(error) => Err(db(error)),
                };
            }
            let updated = sqlx::query(
                "UPDATE tunnels SET record = ?, revision = revision + 1, deleted = ?, issuing = ?,
                   updated_at = ?, local_update = 1
                 WHERE id = ? AND revision = ?",
            )
            .bind(&json)
            .bind(deleted)
            .bind(issuing)
            .bind(now as i64)
            .bind(&record.id)
            .bind(revision as i64)
            .execute(&self.pool)
            .await
            .map_err(db)?;
            if updated.rows_affected() == 0 {
                return Err(Conflict.into());
            }
            Ok(revision + 1)
        })
        .await
    }

    /// Writes a record whatever its revision, for seeding tests.
    #[doc(hidden)]
    pub async fn put_tunnel(&self, record: &StoredTunnel, now: u64) -> Result<()> {
        let json = serde_json::to_string(record)?;
        let (deleted, issuing) = record_flags(record);
        timed("put_tunnel", async {
            sqlx::query(
                "INSERT INTO tunnels (id, record, revision, deleted, issuing, updated_at, local_update)
                 VALUES (?, ?, 1, ?, ?, ?, 1)
                 ON CONFLICT (id) DO UPDATE SET record = excluded.record, revision = revision + 1,
                   deleted = excluded.deleted, issuing = excluded.issuing, updated_at = excluded.updated_at,
                   local_update = 1",
            )
            .bind(&record.id)
            .bind(&json)
            .bind(deleted)
            .bind(issuing)
            .bind(now as i64)
            .execute(&self.pool)
            .await
            .map_err(db)?;
            Ok(())
        })
        .await
    }

    pub async fn alarm(&self, id: &str) -> Result<Option<u64>> {
        timed("alarm", async {
            let alarm: Option<Option<i64>> =
                sqlx::query_scalar("SELECT alarm_at FROM tunnels WHERE id = ?")
                    .bind(id)
                    .fetch_optional(&self.pool)
                    .await
                    .map_err(db)?;
            Ok(alarm.flatten().map(|alarm| alarm as u64))
        })
        .await
    }

    pub async fn set_alarm(&self, id: &str, at: Option<u64>) -> Result<()> {
        timed("set_alarm", async {
            sqlx::query("UPDATE tunnels SET alarm_at = ? WHERE id = ?")
                .bind(at.map(|at| at as i64))
                .bind(id)
                .execute(&self.pool)
                .await
                .map_err(db)?;
            Ok(())
        })
        .await
    }

    /// Clears and returns the alarms due at `now`, like a Durable Object alarm firing once. Each alarm is
    /// cleared only if it is still the one that was read, so concurrent callers never both take it.
    pub async fn take_due_alarms(&self, now: u64) -> Result<Vec<String>> {
        Ok(self.take_due_alarms_and_next(now).await?.0)
    }

    /// [`Store::take_due_alarms`], and when the next alarm after those is due (with the same query).
    pub async fn take_due_alarms_and_next(&self, now: u64) -> Result<(Vec<String>, Option<u64>)> {
        const LIMIT: usize = 500;
        timed("take_due_alarms", async {
            let mut due: Vec<(String, i64)> = sqlx::query_as(
                "SELECT id, alarm_at FROM tunnels WHERE alarm_at IS NOT NULL ORDER BY alarm_at LIMIT ?",
            )
            .bind(LIMIT as i64 + 1)
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
            let later = due
                .iter()
                .position(|(_, alarm)| *alarm as u64 > now)
                .unwrap_or(due.len())
                .min(LIMIT);
            let next = due.get(later).map(|(_, alarm)| (*alarm as u64).max(now));
            due.truncate(later);
            let mut taken = Vec::with_capacity(due.len());
            for (id, alarm) in due {
                let cleared =
                    sqlx::query("UPDATE tunnels SET alarm_at = NULL WHERE id = ? AND alarm_at = ?")
                        .bind(&id)
                        .bind(alarm)
                        .execute(&self.pool)
                        .await
                        .map_err(db)?;
                if cleared.rows_affected() == 1 {
                    taken.push(id);
                }
            }
            Ok((taken, next))
        })
        .await
    }

    pub async fn next_alarm(&self) -> Result<Option<u64>> {
        timed("next_alarm", async {
            let next: Option<i64> = sqlx::query_scalar("SELECT MIN(alarm_at) FROM tunnels")
                .fetch_one(&self.pool)
                .await
                .map_err(db)?;
            Ok(next.map(|next| next as u64))
        })
        .await
    }

    /// Records whose certificate is issuing or renewing, for resuming issuance that has no job.
    pub async fn issuing_tunnels(&self) -> Result<Vec<StoredTunnel>> {
        timed("issuing_tunnels", async {
            let rows: Vec<String> =
                sqlx::query_scalar("SELECT record FROM tunnels WHERE issuing = 1 AND deleted = 0")
                    .fetch_all(&self.pool)
                    .await
                    .map_err(db)?;
            rows.iter()
                .map(|row| serde_json::from_str(row).context("decoding a stored tunnel"))
                .collect()
        })
        .await
    }

    /// Imports a record exported from the Worker (or another server). A row this server has written since its
    /// last import is kept unless `force`.
    pub async fn import_tunnel(
        &self,
        record: StoredTunnel,
        alarm: Option<u64>,
        force: bool,
        now: u64,
    ) -> Result<ImportOutcome> {
        let json = serde_json::to_string(&record)?;
        let mut attempt = 0;
        loop {
            match timed(
                "import_tunnel",
                self.try_import(&record, &json, alarm, force, now),
            )
            .await
            {
                Err(error) if attempt < 5 && retryable(&error) => {
                    attempt += 1;
                    tokio::time::sleep(Duration::from_millis(20 * attempt)).await;
                }
                result => return result,
            }
        }
    }

    async fn try_import(
        &self,
        record: &StoredTunnel,
        json: &str,
        alarm: Option<u64>,
        force: bool,
        now: u64,
    ) -> Result<ImportOutcome> {
        let (deleted, issuing) = record_flags(record);
        let inserted = sqlx::query(
            "INSERT INTO tunnels (id, record, revision, deleted, issuing, alarm_at, updated_at, imported_at,
               local_update)
             VALUES (?, ?, 1, ?, ?, ?, ?, ?, 0)",
        )
        .bind(&record.id)
        .bind(json)
        .bind(deleted)
        .bind(issuing)
        .bind(alarm.map(|alarm| alarm as i64))
        .bind(now as i64)
        .bind(now as i64)
        .execute(&self.pool)
        .await;
        match inserted {
            Ok(_) => return Ok(ImportOutcome::Inserted),
            Err(error) if is_unique_violation(&error) => {}
            Err(error) => return Err(db(error)),
        }
        // `BEGIN IMMEDIATE` takes the write lock before the read, which is SQLite's `SELECT ... FOR UPDATE`:
        // another importer cannot change the row between the comparison and the update. Rows are never deleted.
        let mut transaction = self.pool.begin_with("BEGIN IMMEDIATE").await.map_err(db)?;
        let (existing, local_update): (String, i64) =
            sqlx::query_as("SELECT record, local_update FROM tunnels WHERE id = ?")
                .bind(&record.id)
                .fetch_one(&mut *transaction)
                .await
                .map_err(db)?;
        let outcome = if local_update == 1 && !force {
            ImportOutcome::KeptLocal
        } else if existing == json {
            ImportOutcome::Unchanged
        } else {
            sqlx::query(
                "UPDATE tunnels SET record = ?, revision = revision + 1, deleted = ?, issuing = ?,
                   alarm_at = ?, updated_at = ?, imported_at = ?, local_update = 0
                 WHERE id = ?",
            )
            .bind(json)
            .bind(deleted)
            .bind(issuing)
            .bind(alarm.map(|alarm| alarm as i64))
            .bind(now as i64)
            .bind(now as i64)
            .bind(&record.id)
            .execute(&mut *transaction)
            .await
            .map_err(db)?;
            ImportOutcome::Updated
        };
        transaction.commit().await.map_err(db)?;
        Ok(outcome)
    }

    /// Up to `limit` tunnels with IDs after `after`, in ID order, with their renewal alarms: one page of an export.
    pub async fn export_page(
        &self,
        after: Option<&str>,
        limit: usize,
    ) -> Result<Vec<(String, StoredTunnel, Option<u64>)>> {
        timed("export_page", async {
            let rows: Vec<(String, String, Option<i64>)> = sqlx::query_as(
                "SELECT id, record, alarm_at FROM tunnels WHERE id > ? ORDER BY id LIMIT ?",
            )
            .bind(after.unwrap_or(""))
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
            rows.into_iter()
                .map(|(id, record, alarm)| {
                    let record = serde_json::from_str(&record)
                        .with_context(|| format!("the record of {id}"))?;
                    Ok((id, record, alarm.map(|alarm| alarm as u64)))
                })
                .collect()
        })
        .await
    }

    /// Adds an issuance job unless one exists for the certificate ID. Returns whether it was added.
    pub async fn add_job(&self, job: Job, run_at: u64) -> Result<bool> {
        let identifiers = serde_json::to_string(&job.identifiers)?;
        timed("add_job", async {
            let added = sqlx::query(
                "INSERT INTO jobs (certificate_id, tunnel_id, kind, identifiers, csr, status, attempts, run_at,
                                   created_at, updated_at)
                 VALUES (?, ?, ?, ?, ?, 'pending', ?, ?, ?, ?)",
            )
            .bind(&job.certificate_id)
            .bind(&job.tunnel_id)
            .bind(job.kind.as_str())
            .bind(&identifiers)
            .bind(&job.csr)
            .bind(job.attempts as i64)
            .bind(run_at as i64)
            .bind(job.created_at as i64)
            .bind(job.created_at as i64)
            .execute(&self.pool)
            .await;
            match added {
                Ok(_) => Ok(true),
                Err(error) if is_unique_violation(&error) => Ok(false),
                Err(error) => Err(db(error)),
            }
        })
        .await
    }

    pub async fn job_exists(&self, certificate_id: &str) -> Result<bool> {
        self.job_status(certificate_id)
            .await
            .map(|status| status.is_some())
    }

    pub async fn job_pending(&self, certificate_id: &str) -> Result<bool> {
        self.job_status(certificate_id)
            .await
            .map(|status| status.as_deref() == Some("pending"))
    }

    async fn job_status(&self, certificate_id: &str) -> Result<Option<String>> {
        timed("job_status", async {
            sqlx::query_scalar("SELECT status FROM jobs WHERE certificate_id = ?")
                .bind(certificate_id)
                .fetch_optional(&self.pool)
                .await
                .map_err(db)
        })
        .await
    }

    pub async fn counts(&self) -> Result<serde_json::Value> {
        timed("counts", async {
            let mut counts = serde_json::Map::new();
            for (name, sql) in [
                ("tunnels", "SELECT COUNT(*) FROM tunnels WHERE deleted = 0"),
                ("deleted", "SELECT COUNT(*) FROM tunnels WHERE deleted = 1"),
                (
                    "imported_unchanged",
                    "SELECT COUNT(*) FROM tunnels WHERE local_update = 0",
                ),
                (
                    "alarms",
                    "SELECT COUNT(*) FROM tunnels WHERE alarm_at IS NOT NULL",
                ),
                (
                    "jobs_pending",
                    "SELECT COUNT(*) FROM jobs WHERE status = 'pending'",
                ),
                (
                    "jobs_failed",
                    "SELECT COUNT(*) FROM jobs WHERE status = 'failed'",
                ),
            ] {
                let count: i64 = sqlx::query_scalar(sql)
                    .fetch_one(&self.pool)
                    .await
                    .map_err(db)?;
                counts.insert(name.into(), count.into());
            }
            Ok(serde_json::Value::Object(counts))
        })
        .await
    }

    /// Pending jobs, and jobs that failed since `since`, for the metrics.
    pub async fn job_counts(&self, since: u64) -> Result<(u64, u64)> {
        timed("job_counts", async {
            let (pending, failed): (i64, i64) = sqlx::query_as(
                "SELECT
                   (SELECT COUNT(*) FROM jobs WHERE status = 'pending'),
                   (SELECT COUNT(*) FROM jobs WHERE status = 'failed' AND updated_at >= ?)",
            )
            .bind(since as i64)
            .fetch_one(&self.pool)
            .await
            .map_err(db)?;
            Ok((pending.max(0) as u64, failed.max(0) as u64))
        })
        .await
    }

    /// The names of every job some process is running now (an unexpired lease), whose challenge records are
    /// in use.
    pub async fn leased_job_identifiers(&self, now: u64) -> Result<Vec<String>> {
        timed("leased_job_identifiers", async {
            let rows: Vec<String> = sqlx::query_scalar(
                "SELECT identifiers FROM jobs WHERE status = 'pending' AND lease_until >= ?",
            )
            .bind(now as i64)
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
            Ok(rows
                .iter()
                .filter_map(|row| serde_json::from_str::<Vec<String>>(row).ok())
                .flatten()
                .collect())
        })
        .await
    }

    /// Certificate jobs pending, cluster-wide, for the issuance backlog limit.
    pub async fn pending_jobs(&self) -> Result<u64> {
        timed("pending_jobs", async {
            let pending: i64 =
                sqlx::query_scalar("SELECT COUNT(*) FROM jobs WHERE status = 'pending'")
                    .fetch_one(&self.pool)
                    .await
                    .map_err(db)?;
            Ok(pending.max(0) as u64)
        })
        .await
    }

    /// Takes one request from `name`'s budget (GCRA, see `limits.rs`) at `now`. Usually one statement: a
    /// conditional update that only succeeds within the budget; a key not seen before is inserted.
    pub async fn take_rate(
        &self,
        name: &str,
        now: u64,
        rate: crate::limits::Rate,
    ) -> Result<crate::limits::Verdict> {
        use crate::limits::Verdict;
        let (now, interval, tolerance) = (
            now as i64,
            rate.interval_ms as i64,
            rate.tolerance_ms as i64,
        );
        timed("take_rate", async {
            for _ in 0..2 {
                let taken = sqlx::query(
                    "UPDATE rate_limits SET tat = MAX(tat, ?) + ?
                     WHERE name = ? AND MAX(tat, ?) <= ?",
                )
                .bind(now)
                .bind(interval)
                .bind(name)
                .bind(now)
                .bind(now + tolerance)
                .execute(&self.pool)
                .await
                .map_err(db)?;
                if taken.rows_affected() == 1 {
                    return Ok(Verdict::Allowed);
                }
                let inserted = sqlx::query("INSERT INTO rate_limits (name, tat) VALUES (?, ?)")
                    .bind(name)
                    .bind(now + interval)
                    .execute(&self.pool)
                    .await;
                match inserted {
                    Ok(_) => return Ok(Verdict::Allowed),
                    // It exists: over budget, or inserted by someone else in between (then try once more).
                    Err(error) if is_unique_violation(&error) => {}
                    Err(error) => return Err(db(error)),
                }
            }
            let tat: Option<i64> = sqlx::query_scalar("SELECT tat FROM rate_limits WHERE name = ?")
                .bind(name)
                .fetch_optional(&self.pool)
                .await
                .map_err(db)?;
            let retry_after_ms = tat.map_or(0, |tat| tat - tolerance - now).max(1) as u64;
            Ok(Verdict::Limited { retry_after_ms })
        })
        .await
    }

    /// Deletes rate limit rows whose budget is full again (the same as no row). Returns how many.
    pub async fn prune_rate_limits(&self, now: u64) -> Result<u64> {
        timed("prune_rate_limits", async {
            // SQLite only accepts LIMIT on DELETE when compiled with SQLITE_ENABLE_UPDATE_DELETE_LIMIT, which the
            // bundled build is not; delete through a subquery instead.
            let pruned = sqlx::query(
                "DELETE FROM rate_limits WHERE name IN
                   (SELECT name FROM rate_limits WHERE tat < ? LIMIT 10000)",
            )
            .bind(now as i64)
            .execute(&self.pool)
            .await
            .map_err(db)?;
            Ok(pruned.rows_affected())
        })
        .await
    }

    /// Pending jobs due at `now` that nobody else holds, without taking them.
    pub async fn due_job_ids(&self, owner: &str, now: u64, limit: usize) -> Result<Vec<String>> {
        timed("due_job_ids", async {
            sqlx::query_scalar(
                "SELECT certificate_id FROM jobs
                 WHERE status = 'pending' AND run_at <= ?
                   AND (lease_until IS NULL OR lease_until < ? OR lease_owner = ?)
                 ORDER BY run_at LIMIT ?",
            )
            .bind(now as i64)
            .bind(now as i64)
            .bind(owner)
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await
            .map_err(db)
        })
        .await
    }

    /// Takes a due job for `owner` until `now + LEASE_MS`, unless another process holds an unexpired lease.
    /// Returns the job as it is once taken.
    pub async fn claim_job(
        &self,
        certificate_id: &str,
        owner: &str,
        now: u64,
    ) -> Result<Option<Job>> {
        timed("claim_job", async {
            let claimed = sqlx::query(
                "UPDATE jobs SET lease_owner = ?, lease_until = ?
                 WHERE certificate_id = ? AND status = 'pending' AND run_at <= ?
                   AND (lease_until IS NULL OR lease_until < ? OR lease_owner = ?)",
            )
            .bind(owner)
            .bind((now + LEASE_MS) as i64)
            .bind(certificate_id)
            .bind(now as i64)
            .bind(now as i64)
            .bind(owner)
            .execute(&self.pool)
            .await
            .map_err(db)?;
            if claimed.rows_affected() == 0 {
                return Ok(None);
            }
            let row: Option<JobRow> = sqlx::query_as(
                "SELECT certificate_id, tunnel_id, kind, identifiers, csr, attempts, created_at FROM jobs
                 WHERE certificate_id = ? AND lease_owner = ?",
            )
            .bind(certificate_id)
            .bind(owner)
            .fetch_optional(&self.pool)
            .await
            .map_err(db)?;
            row.map(job_from_row).transpose()
        })
        .await
    }

    /// Takes up to `limit` due jobs for `owner`.
    pub async fn claim_due_jobs(&self, owner: &str, now: u64, limit: usize) -> Result<Vec<Job>> {
        let mut claimed = Vec::new();
        for id in self.due_job_ids(owner, now, limit).await? {
            if let Some(job) = self.claim_job(&id, owner, now).await? {
                claimed.push(job);
            }
        }
        Ok(claimed)
    }

    /// Extends a lease `owner` still holds. Returns false once it lost it.
    pub async fn extend_lease(&self, certificate_id: &str, owner: &str, now: u64) -> Result<bool> {
        timed("extend_lease", async {
            let extended = sqlx::query(
                "UPDATE jobs SET lease_until = ? WHERE certificate_id = ? AND lease_owner = ? AND status = 'pending'",
            )
            .bind((now + LEASE_MS) as i64)
            .bind(certificate_id)
            .bind(owner)
            .execute(&self.pool)
            .await
            .map_err(db)?;
            Ok(extended.rows_affected() == 1)
        })
        .await
    }

    /// Gives up every lease `owner` holds, on shutdown, so a restarted server resumes the jobs at once.
    pub async fn release_leases(&self, owner: &str) -> Result<()> {
        timed("release_leases", async {
            sqlx::query(
                "UPDATE jobs SET lease_owner = NULL, lease_until = NULL WHERE lease_owner = ?",
            )
            .bind(owner)
            .execute(&self.pool)
            .await
            .map_err(db)?;
            Ok(())
        })
        .await
    }

    /// Records a job's final status and releases its lease. Returns false if `owner` no longer held it.
    pub async fn finish_job(
        &self,
        certificate_id: &str,
        owner: &str,
        status: &'static str,
        error: Option<String>,
        now: u64,
    ) -> Result<bool> {
        timed("finish_job", async {
            let finished = sqlx::query(
                "UPDATE jobs SET status = ?, last_error = ?, updated_at = ?, lease_owner = NULL, lease_until = NULL
                 WHERE certificate_id = ? AND lease_owner = ?",
            )
            .bind(status)
            .bind(error)
            .bind(now as i64)
            .bind(certificate_id)
            .bind(owner)
            .execute(&self.pool)
            .await
            .map_err(db)?;
            Ok(finished.rows_affected() == 1)
        })
        .await
    }

    /// Schedules another attempt and releases the lease. Returns false if `owner` no longer held it.
    pub async fn retry_job(
        &self,
        certificate_id: &str,
        owner: &str,
        attempts: u32,
        run_at: u64,
        error: String,
        now: u64,
    ) -> Result<bool> {
        timed("retry_job", async {
            let retried = sqlx::query(
                "UPDATE jobs SET attempts = ?, run_at = ?, last_error = ?, updated_at = ?, lease_owner = NULL,
                   lease_until = NULL
                 WHERE certificate_id = ? AND lease_owner = ?",
            )
            .bind(attempts as i64)
            .bind(run_at as i64)
            .bind(error)
            .bind(now as i64)
            .bind(certificate_id)
            .bind(owner)
            .execute(&self.pool)
            .await
            .map_err(db)?;
            Ok(retried.rows_affected() == 1)
        })
        .await
    }

    /// Failed first-issuance jobs that last changed at or after `since`.
    pub async fn failed_issue_jobs(&self, since: u64) -> Result<Vec<FailedJob>> {
        timed("failed_issue_jobs", async {
            let rows: Vec<FailedJobRow> = sqlx::query_as(
                "SELECT certificate_id, tunnel_id, status, last_error, created_at, updated_at FROM jobs
                 WHERE status = 'failed' AND kind = 'issue' AND updated_at >= ?",
            )
            .bind(since as i64)
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
            Ok(rows.into_iter().map(failed_job_from_row).collect())
        })
        .await
    }

    /// First-issuance jobs queued before `before`, failed since `since` or still retrying, whose last attempt
    /// ended with an ACME authorization still pending.
    pub async fn authz_pending_issue_jobs(
        &self,
        before: u64,
        since: u64,
    ) -> Result<Vec<FailedJob>> {
        timed("authz_pending_issue_jobs", async {
            let rows: Vec<FailedJobRow> = sqlx::query_as(
                "SELECT certificate_id, tunnel_id, status, last_error, created_at, updated_at FROM jobs
                 WHERE kind = 'issue' AND status IN ('failed', 'pending') AND created_at < ? AND updated_at >= ?
                   AND last_error LIKE '%authorization ended in pending%'",
            )
            .bind(before as i64)
            .bind(since as i64)
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
            Ok(rows.into_iter().map(failed_job_from_row).collect())
        })
        .await
    }

    /// Queues a failed or retrying job that was queued before `before` again as if it were new, unless a
    /// server is running it. It counts as queued at `before` at the earliest, so it is requeued like this once.
    /// Only one caller wins. Returns whether this one did.
    pub async fn requeue_job_queued_before(
        &self,
        certificate_id: &str,
        before: u64,
        now: u64,
    ) -> Result<bool> {
        timed("requeue_job_queued_before", async {
            let requeued = sqlx::query(
                "UPDATE jobs SET status = 'pending', attempts = 0, run_at = ?, created_at = ?, updated_at = ?,
                   lease_owner = NULL, lease_until = NULL
                 WHERE certificate_id = ? AND status IN ('failed', 'pending') AND created_at < ?
                   AND (lease_until IS NULL OR lease_until < ?)",
            )
            .bind(now as i64)
            .bind(now.max(before) as i64)
            .bind(now as i64)
            .bind(certificate_id)
            .bind(before as i64)
            .bind(now as i64)
            .execute(&self.pool)
            .await
            .map_err(db)?;
            Ok(requeued.rows_affected() == 1)
        })
        .await
    }

    /// Queues a failed job again as if it were new, keeping its last error. Only one caller wins. Returns
    /// whether this one did.
    pub async fn requeue_failed_job(&self, certificate_id: &str, now: u64) -> Result<bool> {
        timed("requeue_failed_job", async {
            let requeued = sqlx::query(
                "UPDATE jobs SET status = 'pending', attempts = 0, run_at = ?, created_at = ?, updated_at = ?,
                   lease_owner = NULL, lease_until = NULL
                 WHERE certificate_id = ? AND status = 'failed'",
            )
            .bind(now as i64)
            .bind(now as i64)
            .bind(now as i64)
            .bind(certificate_id)
            .execute(&self.pool)
            .await
            .map_err(db)?;
            Ok(requeued.rows_affected() == 1)
        })
        .await
    }

    /// Up to `limit` pending jobs with when `owner` may take each (Unix ms) and their kind: when it is due and
    /// any lease of another process has expired. Those that may be taken at `now` come first, renewals and the
    /// server's own before first issuance (so a flood of new certificates cannot hold renewals up), then the
    /// rest soonest first. The job runner's one query per wakeup.
    pub async fn job_schedule(
        &self,
        owner: &str,
        now: u64,
        limit: usize,
    ) -> Result<Vec<(String, u64, JobKind)>> {
        timed("job_schedule", async {
            let rows: Vec<(String, i64, String)> = sqlx::query_as(
                // SQLite's scalar MAX(a, b) replaces MySQL's GREATEST.
                "SELECT certificate_id,
                   MAX(run_at, CASE WHEN lease_until IS NULL OR lease_owner = ? THEN 0 ELSE lease_until + 1 END)
                     AS ready_at,
                   kind
                 FROM jobs WHERE status = 'pending'
                 ORDER BY ready_at > ?, kind = 'issue', ready_at LIMIT ?",
            )
            .bind(owner)
            .bind(now as i64)
            .bind(limit as i64)
            .fetch_all(&self.pool)
            .await
            .map_err(db)?;
            Ok(rows
                .into_iter()
                .map(|(id, ready_at, kind)| (id, ready_at.max(0) as u64, parse_kind(&kind)))
                .collect())
        })
        .await
    }

    pub async fn server_certificate(&self, name: &str) -> Result<Option<ServerCertificate>> {
        timed("server_certificate", async {
            let row: Option<ServerCertificateRow> =
                sqlx::query_as(
                    "SELECT private_key, csr, certificate, chain, expiry FROM server_certificates WHERE name = ?",
                )
                .bind(name)
                .fetch_optional(&self.pool)
                .await
                .map_err(db)?;
            Ok(
                row.map(|(private_key, csr, certificate, chain, expiry)| ServerCertificate {
                    private_key,
                    csr,
                    certificate,
                    chain,
                    expiry,
                }),
            )
        })
        .await
    }

    /// Stores the first key and CSR for `name` unless another server already did; returns what is stored.
    pub async fn create_server_certificate(
        &self,
        name: &str,
        certificate: ServerCertificate,
        now: u64,
    ) -> Result<ServerCertificate> {
        timed("create_server_certificate", async {
            sqlx::query(
                "INSERT INTO server_certificates (name, private_key, csr, certificate, chain, expiry, updated_at)
                 VALUES (?, ?, ?, ?, ?, ?, ?)
                 ON CONFLICT (name) DO NOTHING",
            )
            .bind(name)
            .bind(&certificate.private_key)
            .bind(&certificate.csr)
            .bind(&certificate.certificate)
            .bind(&certificate.chain)
            .bind(&certificate.expiry)
            .bind(now as i64)
            .execute(&self.pool)
            .await
            .map_err(db)?;
            Ok(())
        })
        .await?;
        self.server_certificate(name)
            .await?
            .ok_or_else(|| anyhow!("the server certificate disappeared"))
    }

    /// Stores an issued certificate, only for the CSR it was issued for.
    pub async fn save_server_certificate(
        &self,
        name: &str,
        certificate: ServerCertificate,
        now: u64,
    ) -> Result<()> {
        timed("save_server_certificate", async {
            sqlx::query(
                "UPDATE server_certificates SET certificate = ?, chain = ?, expiry = ?, updated_at = ?
                 WHERE name = ? AND csr = ?",
            )
            .bind(&certificate.certificate)
            .bind(&certificate.chain)
            .bind(&certificate.expiry)
            .bind(now as i64)
            .bind(name)
            .bind(&certificate.csr)
            .execute(&self.pool)
            .await
            .map_err(db)?;
            Ok(())
        })
        .await
    }

    pub async fn meta(&self, key: &str) -> Result<Option<String>> {
        timed("meta", async {
            sqlx::query_scalar("SELECT value FROM meta WHERE name = ?")
                .bind(key)
                .fetch_optional(&self.pool)
                .await
                .map_err(db)
        })
        .await
    }

    /// Sets `key` to `value`, whatever it was.
    pub async fn set_meta(&self, key: &str, value: &str) -> Result<()> {
        timed("set_meta", async {
            sqlx::query(
                "INSERT INTO meta (name, value) VALUES (?, ?)
                 ON CONFLICT (name) DO UPDATE SET value = excluded.value",
            )
            .bind(key)
            .bind(value)
            .execute(&self.pool)
            .await
            .map_err(db)?;
            Ok(())
        })
        .await
    }

    /// Sets `key` to `value` only if it is still `expected` (`None`: absent). Returns whether it did.
    pub async fn swap_meta(&self, key: &str, expected: Option<&str>, value: &str) -> Result<bool> {
        timed("swap_meta", async {
            let result = match expected {
                None => {
                    sqlx::query("INSERT INTO meta (name, value) VALUES (?, ?)")
                        .bind(key)
                        .bind(value)
                        .execute(&self.pool)
                        .await
                }
                Some(expected) => {
                    sqlx::query("UPDATE meta SET value = ? WHERE name = ? AND value = ?")
                        .bind(value)
                        .bind(key)
                        .bind(expected)
                        .execute(&self.pool)
                        .await
                }
            };
            match result {
                Ok(done) => Ok(done.rows_affected() == 1),
                Err(error) if is_unique_violation(&error) => Ok(false),
                Err(error) => Err(db(error)),
            }
        })
        .await
    }

    /// Which of `ids` are deleted.
    pub async fn deleted_tunnels(&self, ids: &[String]) -> Result<Vec<String>> {
        let mut deleted = Vec::new();
        for chunk in ids.chunks(500) {
            let found: Vec<String> = timed("deleted_tunnels", async {
                let mut query = sqlx::QueryBuilder::<Sqlite>::new(
                    "SELECT id FROM tunnels WHERE deleted = 1 AND id IN (",
                );
                let mut separated = query.separated(", ");
                for id in chunk {
                    separated.push_bind(id);
                }
                query.push(")");
                query
                    .build_query_scalar()
                    .fetch_all(&self.pool)
                    .await
                    .map_err(db)
            })
            .await?;
            deleted.extend(found);
        }
        Ok(deleted)
    }

    /// Closes the pool and waits for the file's WAL checkpoint, so a test can reopen the same file.
    #[cfg(test)]
    async fn close_and_reopen(&self, url: &str) -> Self {
        self.close().await;
        Store::open(url).await.expect("reopening the test database")
    }
}

/// A new database file for one test, in `TEST_SQLITE_DIR` (`/tmp` by default) so processes do not collide.
pub(crate) fn test_url() -> String {
    let dir = std::env::var_os("TEST_SQLITE_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(std::env::temp_dir);
    let name = format!(
        "opentunnel-test-{}.db",
        crate::crypto::uuid().replace('-', "")
    );
    format!("sqlite://{}", dir.join(name).display())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::clock::iso;
    use opentunnel::protocol::api::TunnelState;

    async fn store() -> Store {
        crate::store::test_store().await.expect("a test database")
    }

    fn record(id: &str) -> StoredTunnel {
        StoredTunnel {
            version: 1,
            id: id.into(),
            hostname: format!("{id}.opentunnel.test"),
            state: TunnelState::Offline,
            certificate_id: None,
            token_hash: "00ff".into(),
            created_at: iso(1_800_000_000_000),
            deleted_at: None,
            certificate: None,
            certificate_csr: None,
            certificate_identifiers: None,
            certificate_started_at: None,
            last_connected_at: None,
            renewal: None,
        }
    }

    fn job(id: &str) -> Job {
        Job {
            certificate_id: id.into(),
            tunnel_id: Some("abcdefghijkl".into()),
            kind: JobKind::Issue,
            identifiers: vec!["abcdefghijkl.opentunnel.test".into()],
            csr: "CSR".into(),
            attempts: 0,
            created_at: 1,
        }
    }

    #[test]
    fn only_sqlite_urls_are_accepted() {
        assert!(connect_options("sqlite:///tmp/opentunnel.db").is_ok());
        assert!(connect_options("sqlite::memory:").is_ok());
        let error = connect_options("mysql://u:p@localhost/opentunnel").unwrap_err();
        assert!(error.to_string().contains("SQLite"), "{error}");
        assert!(connect_options("postgres://localhost/opentunnel").is_err());
    }

    #[tokio::test]
    async fn migrates_repeatedly_and_refuses_a_newer_schema() {
        let store = store().await;
        // Migrating again is a no-op.
        store.migrate().await.unwrap();
        let version: i64 = sqlx::query_scalar("SELECT MAX(version) FROM schema_migrations")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);

        sqlx::query("INSERT INTO schema_migrations (version, applied_at) VALUES (?, 0)")
            .bind(SCHEMA_VERSION + 1)
            .execute(&store.pool)
            .await
            .unwrap();
        let error = store.migrate().await.unwrap_err();
        assert!(error.is::<NewerSchema>(), "{error:#}");
    }

    #[tokio::test]
    async fn startup_creates_the_file_and_gives_up_on_a_missing_directory() {
        let url = test_url();
        let store = Store::connect(&url, 4).unwrap();
        store
            .wait_ready(Some(Duration::from_secs(5)))
            .await
            .unwrap();
        store.put_tunnel(&record("abcdefghijkl"), 1).await.unwrap();

        // A directory that does not exist cannot be created by SQLite; startup retries until the limit and then
        // reports how long it waited, which is what the platform's restart policy keys on.
        let missing = std::env::temp_dir().join(format!(
            "opentunnel-missing-{}",
            crate::crypto::uuid().replace('-', "")
        ));
        let store = Store::connect(&format!("sqlite://{}/x.db", missing.display()), 2).unwrap();
        let error = store
            .wait_ready(Some(Duration::from_millis(300)))
            .await
            .unwrap_err();
        assert!(
            format!("{error:#}").contains("unreachable for"),
            "{error:#}"
        );
    }

    #[tokio::test]
    async fn keeps_records_byte_for_byte_and_checks_revisions() {
        let store = store().await;
        let mut tunnel = record("abcdefghijkl");
        tunnel.renewal = Some(crate::record::Renewal {
            certificate_id: "cert_✓".into(),
            started_at: iso(1),
        });
        assert_eq!(store.save_tunnel(&tunnel, 0, 1).await.unwrap(), 1);
        assert!(
            store
                .save_tunnel(&tunnel, 0, 1)
                .await
                .unwrap_err()
                .is::<Conflict>()
        );
        let loaded = store.tunnel("abcdefghijkl").await.unwrap().unwrap();
        assert_eq!(loaded.revision, 1);
        assert_eq!(
            serde_json::to_string(&loaded.record).unwrap(),
            serde_json::to_string(&tunnel).unwrap()
        );
        assert_eq!(store.issuing_tunnels().await.unwrap().len(), 1);
        // IDs are case-sensitive, like MySQL's binary collation.
        assert!(store.tunnel("ABCDEFGHIJKL").await.unwrap().is_none());

        assert_eq!(store.save_tunnel(&tunnel, 1, 2).await.unwrap(), 2);
        assert!(
            store
                .save_tunnel(&tunnel, 1, 3)
                .await
                .unwrap_err()
                .is::<Conflict>()
        );
        tunnel.deleted_at = Some(iso(3));
        store.save_tunnel(&tunnel, 2, 3).await.unwrap();
        assert!(store.issuing_tunnels().await.unwrap().is_empty());
        assert_eq!(store.counts().await.unwrap()["deleted"], 1);
    }

    #[tokio::test]
    async fn imports_keep_local_changes_and_bump_revisions() {
        let store = store().await;
        let tunnel = record("abcdefghijkl");
        let import = |force| store.import_tunnel(tunnel.clone(), Some(5), force, 1);
        assert_eq!(import(false).await.unwrap(), ImportOutcome::Inserted);
        assert_eq!(import(false).await.unwrap(), ImportOutcome::Unchanged);
        assert_eq!(store.alarm("abcdefghijkl").await.unwrap(), Some(5));
        let mut changed = tunnel.clone();
        changed.state = TunnelState::Online;
        assert_eq!(
            store
                .import_tunnel(changed.clone(), None, false, 2)
                .await
                .unwrap(),
            ImportOutcome::Updated
        );
        let loaded = store.tunnel("abcdefghijkl").await.unwrap().unwrap();
        assert_eq!(loaded.revision, 2);
        store.save_tunnel(&loaded.record, 2, 3).await.unwrap();
        assert_eq!(import(false).await.unwrap(), ImportOutcome::KeptLocal);
        assert_eq!(import(true).await.unwrap(), ImportOutcome::Updated);

        // Concurrent imports of new records all land once.
        let imports = (0..8).map(|index| {
            let store = store.clone();
            async move {
                store
                    .import_tunnel(record(&format!("concurrent{index:02}")), None, false, 1)
                    .await
            }
        });
        for outcome in futures_util::future::join_all(imports).await {
            assert_eq!(outcome.unwrap(), ImportOutcome::Inserted);
        }

        // Machines importing the same record at once (the pull-through on first use) insert it once.
        let same = (0..8).map(|_| {
            let store = store.clone();
            async move {
                store
                    .import_tunnel(record("pulledthrugh"), Some(9), false, 1)
                    .await
            }
        });
        let mut outcomes: Vec<ImportOutcome> = futures_util::future::join_all(same)
            .await
            .into_iter()
            .map(Result::unwrap)
            .collect();
        outcomes.sort_by_key(|outcome| *outcome != ImportOutcome::Inserted);
        assert_eq!(outcomes[0], ImportOutcome::Inserted);
        assert!(
            outcomes[1..]
                .iter()
                .all(|outcome| *outcome == ImportOutcome::Unchanged)
        );
        let loaded = store.tunnel("pulledthrugh").await.unwrap().unwrap();
        assert_eq!(loaded.revision, 1);
    }

    #[tokio::test]
    async fn put_tunnel_replaces_records_and_bumps_revisions() {
        let store = store().await;
        store.put_tunnel(&record("abcdefghijkl"), 1).await.unwrap();
        let mut changed = record("abcdefghijkl");
        changed.state = TunnelState::Online;
        store.put_tunnel(&changed, 2).await.unwrap();
        let loaded = store.tunnel("abcdefghijkl").await.unwrap().unwrap();
        assert_eq!(loaded.revision, 2);
        assert_eq!(loaded.record.state, TunnelState::Online);
    }

    #[tokio::test]
    async fn lists_deleted_tunnels() {
        let store = store().await;
        store.put_tunnel(&record("abcdefghijkl"), 1).await.unwrap();
        let mut deleted = record("deletedtunnl");
        deleted.deleted_at = Some(iso(1));
        store.put_tunnel(&deleted, 1).await.unwrap();
        assert_eq!(
            store
                .deleted_tunnels(&[
                    "abcdefghijkl".into(),
                    "deletedtunnl".into(),
                    "unknown".into()
                ])
                .await
                .unwrap(),
            vec!["deletedtunnl".to_owned()]
        );
        assert!(store.deleted_tunnels(&[]).await.unwrap().is_empty());
    }

    #[tokio::test]
    async fn attach_snapshots_read_the_record_and_alarm_at_once() {
        let store = store().await;
        let limit = Duration::from_secs(5);
        assert!(
            store
                .attach_snapshot("abcdefghijkl", limit)
                .await
                .unwrap()
                .is_none()
        );
        store.put_tunnel(&record("abcdefghijkl"), 1).await.unwrap();
        let snapshot = store
            .attach_snapshot("abcdefghijkl", limit)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.loaded.revision, 1);
        assert_eq!(snapshot.loaded.record.id, "abcdefghijkl");
        assert_eq!(snapshot.alarm, None);
        store.set_alarm("abcdefghijkl", Some(77)).await.unwrap();
        let snapshot = store
            .attach_snapshot("abcdefghijkl", limit)
            .await
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.alarm, Some(77));
        assert!(
            store
                .attach_snapshot("abc'def", limit)
                .await
                .unwrap()
                .is_none()
        );
        assert!(store.tunnel("abc'def").await.unwrap().is_none());
    }

    #[tokio::test]
    async fn alarm_scans_report_the_next_alarm() {
        let store = store().await;
        assert_eq!(
            store.take_due_alarms_and_next(100).await.unwrap(),
            (vec![], None)
        );
        for (id, at) in [
            ("tunnel000001", 50),
            ("tunnel000002", 300),
            ("tunnel000003", 400),
        ] {
            store.put_tunnel(&record(id), 1).await.unwrap();
            store.set_alarm(id, Some(at)).await.unwrap();
        }
        assert_eq!(
            store.take_due_alarms_and_next(100).await.unwrap(),
            (vec!["tunnel000001".to_owned()], Some(300))
        );
        assert_eq!(
            store.take_due_alarms_and_next(100).await.unwrap(),
            (vec![], Some(300))
        );
    }

    #[tokio::test]
    async fn alarms_fire_once_across_concurrent_callers() {
        let store = store().await;
        for index in 0..20 {
            let id = format!("tunnel{index:06}");
            store.put_tunnel(&record(&id), 1).await.unwrap();
            store.set_alarm(&id, Some(100 + index)).await.unwrap();
        }
        let (first, second) = tokio::join!(store.take_due_alarms(200), store.take_due_alarms(200));
        let mut taken = first.unwrap();
        taken.extend(second.unwrap());
        taken.sort();
        taken.dedup();
        assert_eq!(taken.len(), 20);
        assert_eq!(store.next_alarm().await.unwrap(), None);
    }

    #[tokio::test]
    async fn jobs_are_leased_to_one_owner() {
        let store = store().await;
        assert!(store.add_job(job("cert_1"), 10).await.unwrap());
        assert!(!store.add_job(job("cert_1"), 10).await.unwrap());
        assert!(store.claim_due_jobs("a", 5, 10).await.unwrap().is_empty());

        let (a, b) = tokio::join!(
            store.claim_job("cert_1", "a", 20),
            store.claim_job("cert_1", "b", 20)
        );
        let (a, b) = (a.unwrap(), b.unwrap());
        assert!(
            a.is_some() != b.is_some(),
            "exactly one owner takes the job"
        );
        let (owner, other) = if a.is_some() { ("a", "b") } else { ("b", "a") };
        assert!(
            store
                .claim_due_jobs(other, 20 + LEASE_MS - 1, 10)
                .await
                .unwrap()
                .is_empty()
        );
        assert!(
            !store
                .finish_job("cert_1", other, "done", None, 30)
                .await
                .unwrap()
        );
        assert!(store.extend_lease("cert_1", owner, 1_000).await.unwrap());

        let taken = store
            .claim_due_jobs(other, 1_000 + LEASE_MS + 1, 10)
            .await
            .unwrap();
        assert_eq!(taken.len(), 1);
        assert!(
            !store
                .retry_job("cert_1", owner, 1, 0, "x".into(), 40)
                .await
                .unwrap()
        );
        assert!(
            store
                .retry_job("cert_1", other, 1, 50, "x".into(), 40)
                .await
                .unwrap()
        );
        let retried = store.claim_due_jobs(owner, 60, 10).await.unwrap();
        assert_eq!(retried[0].attempts, 1);
        store.release_leases(owner).await.unwrap();
        assert!(
            store
                .claim_job("cert_1", other, 61)
                .await
                .unwrap()
                .is_some()
        );
        assert!(
            store
                .finish_job("cert_1", other, "done", None, 70)
                .await
                .unwrap()
        );
        assert!(!store.job_pending("cert_1").await.unwrap());
        assert!(store.job_exists("cert_1").await.unwrap());
        assert_eq!(store.job_counts(0).await.unwrap(), (0, 0));
    }

    #[tokio::test]
    async fn job_schedules_say_when_each_job_may_be_taken() {
        let store = store().await;
        assert!(store.job_schedule("a", 30, 10).await.unwrap().is_empty());
        store.add_job(job("cert_due"), 10).await.unwrap();
        store.add_job(job("cert_later"), 500).await.unwrap();
        store.add_job(job("cert_leased"), 10).await.unwrap();
        store
            .claim_job("cert_leased", "b", 20)
            .await
            .unwrap()
            .unwrap();
        let issue = JobKind::Issue;
        assert_eq!(
            store.job_schedule("a", 30, 10).await.unwrap(),
            [
                ("cert_due".to_owned(), 10, issue),
                ("cert_later".to_owned(), 500, issue),
                ("cert_leased".to_owned(), 20 + LEASE_MS + 1, issue),
            ]
        );
        assert_eq!(
            store.job_schedule("b", 30, 2).await.unwrap(),
            [
                ("cert_due".to_owned(), 10, issue),
                ("cert_leased".to_owned(), 10, issue)
            ]
        );
        store
            .add_job(
                Job {
                    kind: JobKind::Renew,
                    ..job("cert_renew")
                },
                25,
            )
            .await
            .unwrap();
        assert_eq!(
            store.job_schedule("b", 30, 2).await.unwrap(),
            [
                ("cert_renew".to_owned(), 25, JobKind::Renew),
                ("cert_due".to_owned(), 10, issue),
            ]
        );
        assert_eq!(
            store.job_schedule("a", 20, 10).await.unwrap()[..2],
            [
                ("cert_due".to_owned(), 10, issue),
                ("cert_renew".to_owned(), 25, JobKind::Renew),
            ]
        );
        store
            .finish_job("cert_leased", "b", "done", None, 30)
            .await
            .unwrap();
        assert_eq!(store.job_schedule("a", 30, 10).await.unwrap().len(), 3);
        assert_eq!(store.pending_jobs().await.unwrap(), 3);
    }

    #[tokio::test]
    async fn adds_the_rate_limits_table_to_a_database_at_this_version() {
        let store = store().await;
        sqlx::query("DROP TABLE rate_limits")
            .execute(&store.pool)
            .await
            .unwrap();
        store.migrate().await.unwrap();
        let version: i64 = sqlx::query_scalar("SELECT MAX(version) FROM schema_migrations")
            .fetch_one(&store.pool)
            .await
            .unwrap();
        assert_eq!(version, SCHEMA_VERSION);
        let rate = crate::limits::Rate {
            interval_ms: 100,
            tolerance_ms: 0,
        };
        assert_eq!(
            store.take_rate("k", 1_000, rate).await.unwrap(),
            crate::limits::Verdict::Allowed
        );
        store.migrate().await.unwrap();
    }

    #[tokio::test]
    async fn rates_allow_a_burst_then_one_per_interval() {
        let store = store().await;
        let rate = crate::limits::Rate {
            interval_ms: 100,
            tolerance_ms: 200,
        };
        use crate::limits::Verdict::{Allowed, Limited};
        for _ in 0..3 {
            assert_eq!(store.take_rate("k", 1_000, rate).await.unwrap(), Allowed);
        }
        assert_eq!(
            store.take_rate("k", 1_000, rate).await.unwrap(),
            Limited {
                retry_after_ms: 100
            }
        );
        assert_eq!(
            store.take_rate("k", 1_050, rate).await.unwrap(),
            Limited { retry_after_ms: 50 }
        );
        assert_eq!(store.take_rate("k", 1_100, rate).await.unwrap(), Allowed);
        assert!(matches!(
            store.take_rate("k", 1_100, rate).await.unwrap(),
            Limited { .. }
        ));
        assert_eq!(
            store.take_rate("other", 1_100, rate).await.unwrap(),
            Allowed
        );
        let results =
            futures_util::future::join_all((0..10).map(|_| store.take_rate("new", 5_000, rate)))
                .await;
        let allowed = results
            .into_iter()
            .filter(|result| *result.as_ref().unwrap() == Allowed)
            .count();
        assert_eq!(allowed, 3);
        assert_eq!(store.prune_rate_limits(1_401).await.unwrap(), 2);
        assert!(matches!(
            store.take_rate("new", 5_000, rate).await.unwrap(),
            Limited { .. }
        ));
    }

    #[tokio::test]
    async fn server_certificates_and_meta_are_set_once() {
        let store = store().await;
        let created = |key: &str| ServerCertificate {
            private_key: key.into(),
            csr: format!("csr-{key}"),
            certificate: None,
            chain: None,
            expiry: None,
        };
        let first = store
            .create_server_certificate("opentunnel.test", created("a"), 1)
            .await
            .unwrap();
        let second = store
            .create_server_certificate("opentunnel.test", created("b"), 1)
            .await
            .unwrap();
        assert_eq!(first.private_key, "a");
        assert_eq!(second.private_key, "a");
        let stale = ServerCertificate {
            certificate: Some("C".into()),
            ..created("b")
        };
        store
            .save_server_certificate("opentunnel.test", stale, 2)
            .await
            .unwrap();
        assert!(
            store
                .server_certificate("opentunnel.test")
                .await
                .unwrap()
                .unwrap()
                .certificate
                .is_none()
        );

        assert!(store.swap_meta("k", None, "1").await.unwrap());
        assert!(!store.swap_meta("k", None, "2").await.unwrap());
        assert!(!store.swap_meta("k", Some("0"), "2").await.unwrap());
        assert!(store.swap_meta("k", Some("1"), "2").await.unwrap());
        assert_eq!(store.meta("k").await.unwrap().as_deref(), Some("2"));
    }

    #[tokio::test]
    async fn export_pages_walk_the_table_in_id_order() {
        let store = store().await;
        for id in ["tunnel000001", "tunnel000002", "tunnel000003"] {
            store.put_tunnel(&record(id), 1).await.unwrap();
        }
        store.set_alarm("tunnel000002", Some(9)).await.unwrap();
        let first = store.export_page(None, 2).await.unwrap();
        assert_eq!(
            first
                .iter()
                .map(|(id, _, alarm)| (id.as_str(), *alarm))
                .collect::<Vec<_>>(),
            [("tunnel000001", None), ("tunnel000002", Some(9))]
        );
        let after = first.last().unwrap().0.clone();
        let second = store.export_page(Some(&after), 2).await.unwrap();
        assert_eq!(second.len(), 1);
        assert_eq!(second[0].0, "tunnel000003");
    }

    #[tokio::test]
    async fn records_survive_reopening_the_file() {
        let url = test_url();
        let store = Store::open(&url).await.unwrap();
        store.put_tunnel(&record("abcdefghijkl"), 1).await.unwrap();
        store.set_alarm("abcdefghijkl", Some(5)).await.unwrap();
        let store = store.close_and_reopen(&url).await;
        let snapshot = store
            .tunnel_with_alarm("abcdefghijkl")
            .await
            .unwrap()
            .unwrap();
        assert_eq!(snapshot.loaded.revision, 1);
        assert_eq!(snapshot.alarm, Some(5));
        store.migrate().await.unwrap();
    }
}
