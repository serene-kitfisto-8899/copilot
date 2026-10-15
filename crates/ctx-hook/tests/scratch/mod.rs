//! A scratch PostgreSQL schema, the way ctx-core's tests have one: nothing in
//! the hook's database tests touches the real `public` schema.
//!
//! The tests need a reachable PostgreSQL (by default the one `ctx-ingest` uses;
//! `CTX_TEST_DATABASE_URL` overrides it). Without one they print a "SKIPPED"
//! line and pass, unless `CTX_REQUIRE_DB` is set, which makes a missing
//! database a failure (use it in CI).
#![allow(dead_code)]

use std::future::Future;
use std::panic;

use ctx_core::config::Config;
use ctx_core::db;
use sqlx::PgPool;

pub fn database_url() -> String {
    std::env::var("CTX_TEST_DATABASE_URL")
        .ok()
        .filter(|url| !url.is_empty())
        .unwrap_or_else(|| {
            Config::from_env()
                .expect("reading the environment")
                .database_url
        })
}

/// `url`, but landing in `schema`: for code that opens its own connections,
/// as the hook does.
pub fn in_schema(url: &str, schema: &str) -> String {
    let sep = if url.contains('?') { '&' } else { '?' };
    format!("{url}{sep}options=-c%20search_path%3D{schema}")
}

pub struct Scratch {
    pub pool: PgPool,
    pub schema: String,
    /// What the code under test is given to connect with.
    pub url: String,
}

/// Runs `body` against a scratch schema with the migrations applied.
pub async fn with_schema<F, Fut>(name: &str, body: F)
where
    F: FnOnce(Scratch) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    run(name, true, body).await;
}

/// Runs `body` against a scratch schema with nothing in it.
pub async fn with_empty_schema<F, Fut>(name: &str, body: F)
where
    F: FnOnce(Scratch) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    run(name, false, body).await;
}

async fn run<F, Fut>(name: &str, migrated: bool, body: F)
where
    F: FnOnce(Scratch) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let base = database_url();
    let schema = format!("ctxhook_{name}_{}", std::process::id());
    let pool = match db::connect(&base, "ctx-hook-tests", Some(&schema), 4).await {
        Ok(pool) => pool,
        Err(error) if std::env::var_os("CTX_REQUIRE_DB").is_some() => {
            panic!("PostgreSQL is required (CTX_REQUIRE_DB is set): {error:#}")
        }
        Err(error) => {
            eprintln!("SKIPPED {name}: PostgreSQL is not reachable ({error:#})");
            return;
        }
    };
    let task = tokio::spawn({
        let pool = pool.clone();
        let url = in_schema(&base, &schema);
        let schema = schema.clone();
        async move {
            if migrated {
                db::migrate(&pool).await.expect("applying the migrations");
            }
            body(Scratch { pool, schema, url }).await;
        }
    });
    let outcome = task.await;
    db::drop_schema(&pool, &schema)
        .await
        .expect("dropping the scratch schema");
    pool.close().await;
    if let Err(error) = outcome {
        match error.try_into_panic() {
            Ok(payload) => panic::resume_unwind(payload),
            Err(error) => panic!("the test task did not finish: {error}"),
        }
    }
}
