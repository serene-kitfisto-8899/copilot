//! Connection pool, migrations and the single-ingester lock.

use std::str::FromStr;
use std::time::Duration;

use anyhow::{Context, Result};
use sha2::{Digest, Sha256};
use sqlx::postgres::{PgConnectOptions, PgConnection, PgPool, PgPoolOptions};
use sqlx::{AssertSqlSafe, Connection};

use crate::MIGRATOR;

const VIEWS_SQL: &str = include_str!("../sql/views.sql");

/// Lowercase hex of a SHA-256 digest.
pub fn sha256_hex(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    let mut out = String::with_capacity(64);
    for byte in digest.iter() {
        out.push_str(&format!("{byte:02x}"));
    }
    out
}

/// Opens a pool. `schema` pins `search_path` to one schema (integration tests
/// run in a scratch schema because the role may not create databases).
pub async fn connect(
    url: &str,
    application_name: &str,
    schema: Option<&str>,
    max_connections: u32,
) -> Result<PgPool> {
    let options = PgConnectOptions::from_str(url)
        .with_context(|| "invalid PostgreSQL connection URL")?
        .application_name(application_name);
    let schema = schema.map(|s| s.to_owned());
    if let Some(s) = &schema {
        anyhow::ensure!(
            !s.is_empty()
                && s.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
            "schema names are limited to [a-z0-9_]"
        );
        // Once, on a single connection: `CREATE SCHEMA IF NOT EXISTS` races
        // with itself when several pooled connections run it at the same time.
        let mut conn = PgConnection::connect_with(&options)
            .await
            .context("cannot connect to PostgreSQL (is the server up and the role allowed?)")?;
        sqlx::query(AssertSqlSafe(format!("CREATE SCHEMA IF NOT EXISTS {s}")))
            .execute(&mut conn)
            .await?;
        conn.close().await?;
    }
    PgPoolOptions::new()
        .max_connections(max_connections)
        .acquire_timeout(Duration::from_secs(30))
        .after_connect(move |conn, _meta| {
            let schema = schema.clone();
            Box::pin(async move {
                if let Some(schema) = schema {
                    // Validated above, so interpolating it is safe.
                    sqlx::query(AssertSqlSafe(format!("SET search_path TO {schema}")))
                        .execute(&mut *conn)
                        .await?;
                }
                Ok(())
            })
        })
        .connect_with(options)
        .await
        .context("cannot connect to PostgreSQL (is the server up and the role allowed?)")
}

/// Applies the table migrations, then (re)creates the report views whenever
/// `views.sql` changed. Views live outside the sqlx migrations on purpose: they
/// are derived objects, so editing them must not need a new migration file.
pub async fn migrate(pool: &PgPool) -> Result<()> {
    MIGRATOR.run(pool).await.context("running migrations")?;
    apply_views(pool).await
}

async fn apply_views(pool: &PgPool) -> Result<()> {
    let sha = sha256_hex(VIEWS_SQL.as_bytes());
    let mut tx = pool.begin().await?;
    // Serialises concurrent `migrate()` calls (service restart vs manual run).
    sqlx::query("SELECT pg_advisory_xact_lock(hashtext('ctx-views:' || current_schema()))")
        .execute(&mut *tx)
        .await?;
    let current: Option<String> =
        sqlx::query_scalar("SELECT value FROM ctx_meta WHERE key = 'views_sha256'")
            .fetch_optional(&mut *tx)
            .await?;
    if current.as_deref() != Some(sha.as_str()) {
        sqlx::raw_sql(VIEWS_SQL)
            .execute(&mut *tx)
            .await
            .context("creating report views")?;
        sqlx::query(
            "INSERT INTO ctx_meta (key, value) VALUES ('views_sha256', $1)
             ON CONFLICT (key) DO UPDATE SET value = EXCLUDED.value",
        )
        .bind(&sha)
        .execute(&mut *tx)
        .await?;
    }
    tx.commit().await?;
    Ok(())
}

/// Row counts of the data tables, for status output.
pub async fn table_counts(pool: &PgPool) -> Result<Vec<(&'static str, i64)>> {
    const TABLES: [(&str, &str); 9] = [
        ("sessions", "SELECT count(*) FROM sessions"),
        ("events", "SELECT count(*) FROM events"),
        ("tool_calls", "SELECT count(*) FROM tool_calls"),
        ("usage", "SELECT count(*) FROM usage"),
        ("turns", "SELECT count(*) FROM turns"),
        ("checkpoints", "SELECT count(*) FROM checkpoints"),
        ("session_files", "SELECT count(*) FROM session_files"),
        ("session_refs", "SELECT count(*) FROM session_refs"),
        (
            "redactions",
            "SELECT coalesce(sum(n), 0)::bigint FROM redactions",
        ),
    ];
    let mut out = Vec::with_capacity(TABLES.len());
    for (name, query) in TABLES {
        let n: i64 = sqlx::query_scalar(query).fetch_one(pool).await?;
        out.push((name, n));
    }
    Ok(out)
}

/// Drops a scratch schema created by [`connect`] with `schema = Some(..)`.
pub async fn drop_schema(pool: &PgPool, schema: &str) -> Result<()> {
    anyhow::ensure!(
        !schema.is_empty()
            && schema
                .chars()
                .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '_'),
        "schema names are limited to [a-z0-9_]"
    );
    sqlx::query(AssertSqlSafe(format!(
        "DROP SCHEMA IF EXISTS {schema} CASCADE"
    )))
    .execute(pool)
    .await?;
    Ok(())
}

/// Held for the lifetime of an ingesting process. PostgreSQL releases a
/// session-level advisory lock when its connection closes, so dropping this
/// (or the process dying) frees it; the connection is detached from the pool
/// so it can never be recycled with the lock still held.
pub struct IngestLock {
    conn: PgConnection,
}

impl IngestLock {
    /// `Ok(None)` when another ingester already holds the lock.
    pub async fn try_acquire(pool: &PgPool) -> Result<Option<Self>> {
        let mut conn = pool.acquire().await?.detach();
        let got: bool = sqlx::query_scalar(
            "SELECT pg_try_advisory_lock(hashtext('ctx-ingest:' || current_schema()))",
        )
        .fetch_one(&mut conn)
        .await?;
        if got {
            Ok(Some(Self { conn }))
        } else {
            let _ = conn.close().await;
            Ok(None)
        }
    }

    /// Fails once the connection holding the lock is gone. PostgreSQL drops
    /// the lock with its session (a server restart, a terminated backend) and
    /// nothing else tells a long-running process that it no longer keeps other
    /// ingesters out. A live session still holds the lock, because nothing
    /// here ever unlocks it.
    pub async fn check(&mut self) -> Result<()> {
        sqlx::query("SELECT 1").execute(&mut self.conn).await?;
        Ok(())
    }
}
