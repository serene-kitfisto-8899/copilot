//! Fixtures shared by the integration tests: a scratch PostgreSQL schema, a
//! synthetic Copilot state directory and the SQLite session store the CLI
//! keeps next to it. Nothing here touches the real `~/.copilot` or the real
//! `public` schema.
//!
//! The tests need a reachable PostgreSQL (by default the one `ctx-ingest`
//! uses; `CTX_TEST_DATABASE_URL` overrides it). Without one they print a
//! "SKIPPED" line and pass, unless `CTX_REQUIRE_DB` is set, which makes a
//! missing database a failure (use it in CI).
#![allow(dead_code)]

use std::fs::{self, OpenOptions};
use std::future::Future;
use std::io::Write;
use std::panic;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use ctx_core::config::{self, Config};
use ctx_core::db;
use ctx_core::ingest::Ingester;
use ctx_core::watch::{self, Summary, TailOptions};
use rusqlite::{Connection, params};
use serde_json::{Value, json};
use sqlx::PgPool;
use tempfile::TempDir;
use tokio::sync::{Semaphore, oneshot};
use tokio::task::JoinHandle;

/// At most this many tests use PostgreSQL at once: each holds a small pool,
/// and the tail tests are timing sensitive, so they must not queue behind a
/// dozen busy neighbours.
static GATE: Semaphore = Semaphore::const_new(4);

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

/// What a test works with: a migrated scratch schema and an empty Copilot
/// directory, both removed afterwards.
pub struct Env {
    pub pool: PgPool,
    pub ingester: Ingester,
    pub config: Config,
    copilot: TempDir,
}

/// Runs `body` against a fresh scratch schema named after the test. The
/// schema is dropped when the body ends, also when it panics.
pub async fn with_env<F, Fut>(name: &str, body: F)
where
    F: FnOnce(Env) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let _slot = GATE.acquire().await.expect("the gate is never closed");
    let url = database_url();
    let schema = format!("ctxtest_{name}_{}", std::process::id());
    let pool = match db::connect(&url, "ctx-core-tests", Some(&schema), 4).await {
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
        async move {
            db::migrate(&pool).await.expect("applying the migrations");
            let copilot = tempfile::tempdir().expect("creating the Copilot directory");
            let config = Config {
                copilot_dir: copilot.path().to_owned(),
                database_url: url,
            };
            fs::create_dir_all(config.session_state_dir()).expect("creating session-state");
            let ingester = Ingester::new(pool.clone(), config.clone());
            body(Env {
                pool,
                ingester,
                config,
                copilot,
            })
            .await;
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

// ------------------------------------------------------------------ events

/// `n` seconds after 2026-10-01T08:00:00Z, as the CLI writes timestamps.
pub fn ts(n: usize) -> String {
    format!("2026-10-01T08:{:02}:{:02}.000Z", n / 60 % 60, n % 60)
}

pub fn ev(id: &str, ty: &str, n: usize, data: Value) -> Value {
    json!({"type": ty, "id": id, "parentId": null, "timestamp": ts(n), "data": data})
}

/// One user turn that runs a shell command: five events, `1 + 5t ..= 5 + 5t`
/// seconds into the session, with ids unique to `prefix`.
pub fn turn(prefix: &str, t: usize) -> Vec<Value> {
    let n = 1 + 5 * t;
    let call = format!("{prefix}-call{t}");
    vec![
        ev(
            &format!("{prefix}-u{t}"),
            "user.message",
            n,
            json!({"content": format!("please do step {t}"), "agentMode": "interactive"}),
        ),
        ev(
            &format!("{prefix}-a{t}"),
            "assistant.turn_start",
            n + 1,
            json!({"turnId": t.to_string()}),
        ),
        ev(
            &format!("{prefix}-ts{t}"),
            "tool.execution_start",
            n + 2,
            json!({"toolCallId": call, "toolName": "bash", "arguments": {"command": format!("echo {t}")}}),
        ),
        ev(
            &format!("{prefix}-te{t}"),
            "tool.execution_complete",
            n + 3,
            json!({"toolCallId": call, "success": true, "result": {"content": format!("{t}\n")}, "shellExecution": {"exitCode": 0}}),
        ),
        ev(
            &format!("{prefix}-z{t}"),
            "assistant.turn_end",
            n + 4,
            json!({"turnId": t.to_string()}),
        ),
    ]
}

/// A session start followed by `turns` turns: `1 + 5 * turns` events and
/// `turns` tool calls.
pub fn story(prefix: &str, turns: usize) -> Vec<Value> {
    let mut events = vec![ev(
        &format!("{prefix}-start"),
        "session.start",
        0,
        json!({
            "sessionId": prefix,
            "selectedModel": "claude-sonnet-5.5",
            "reasoningEffort": "high",
            "context": {
                "cwd": "/work/demo",
                "gitRoot": "/work/demo",
                "repository": "acme/demo",
                "branch": "main",
                "hostType": "github",
            },
        }),
    )];
    for t in 0..turns {
        events.extend(turn(prefix, t));
    }
    events
}

pub fn jsonl(events: &[Value]) -> String {
    events.iter().map(|e| format!("{e}\n")).collect()
}

impl Env {
    pub fn copilot(&self) -> &Path {
        self.copilot.path()
    }

    pub fn session_dir(&self, id: &str) -> PathBuf {
        self.config.session_state_dir().join(id)
    }

    pub fn events_file(&self, id: &str) -> PathBuf {
        config::events_path(&self.session_dir(id))
    }

    /// Creates the session directory with an `events.jsonl` holding `events`.
    pub fn add_session(&self, id: &str, events: &[Value]) {
        fs::create_dir_all(self.session_dir(id)).expect("creating the session directory");
        fs::write(self.events_file(id), jsonl(events)).expect("writing events.jsonl");
    }

    pub fn append_events(&self, id: &str, events: &[Value]) {
        self.append_bytes(id, jsonl(events).as_bytes());
    }

    pub fn append_bytes(&self, id: &str, bytes: &[u8]) {
        let mut file = OpenOptions::new()
            .append(true)
            .open(self.events_file(id))
            .expect("opening events.jsonl");
        file.write_all(bytes).expect("appending to events.jsonl");
    }

    /// `workspace.yaml` with a title and, optionally, a summary. Values are
    /// written as JSON strings, which YAML reads as double-quoted scalars.
    pub fn write_workspace(&self, id: &str, name: &str, summary: Option<&str>) {
        fs::create_dir_all(self.session_dir(id)).expect("creating the session directory");
        let mut yaml = format!(
            "id: {id}\ncwd: /work/demo\nrepository: acme/demo\nbranch: main\nname: {}\n",
            json!(name)
        );
        if let Some(summary) = summary {
            yaml.push_str(&format!("summary: {}\n", json!(summary)));
        }
        yaml.push_str(
            "created_at: 2026-10-01T08:00:00.000Z\nupdated_at: 2026-10-01T09:00:00.000Z\n",
        );
        fs::write(config::workspace_path(&self.session_dir(id)), yaml)
            .expect("writing workspace.yaml");
    }

    /// Creates `session-store.db` next to the session directories.
    pub fn store(&self) -> StoreFixture {
        StoreFixture::create(self.copilot())
    }

    pub async fn count(&self, sql: &'static str) -> i64 {
        sqlx::query_scalar(sql)
            .fetch_one(&self.pool)
            .await
            .unwrap_or_else(|e| panic!("{sql}: {e}"))
    }

    pub async fn execute(&self, sql: &'static str) -> u64 {
        sqlx::query(sql)
            .execute(&self.pool)
            .await
            .unwrap_or_else(|e| panic!("{sql}: {e}"))
            .rows_affected()
    }

    /// Rows holding `needle` in any column that receives text from a source.
    /// Only the number is ever reported, never the match.
    pub async fn leaks(&self, needle: &str) -> i64 {
        sqlx::query_scalar(
            "SELECT (SELECT count(*) FROM events WHERE strpos(body::text, $1) > 0)
                  + (SELECT count(*) FROM tool_calls
                      WHERE strpos(coalesce(args::text, '') || ' ' || coalesce(result_text, ''), $1) > 0)
                  + (SELECT count(*) FROM sessions
                      WHERE strpos(coalesce(name, '') || ' ' || coalesce(summary, ''), $1) > 0)
                  + (SELECT count(*) FROM turns
                      WHERE strpos(coalesce(user_message, '') || ' ' || coalesce(assistant_response, ''), $1) > 0)
                  + (SELECT count(*) FROM checkpoints
                      WHERE strpos(coalesce(title, '') || ' ' || coalesce(overview, ''), $1) > 0)
                  + (SELECT count(*) FROM session_files WHERE strpos(file_path, $1) > 0)
                  + (SELECT count(*) FROM session_refs WHERE strpos(ref_value, $1) > 0)",
        )
        .bind(needle)
        .fetch_one(&self.pool)
        .await
        .expect("counting leaks")
    }
}

/// The distinctive part of a planted secret: its longest alphanumeric run,
/// which cannot occur in a redaction marker.
pub fn needle(secret: &str) -> String {
    let run = secret
        .split(|c: char| !c.is_ascii_alphanumeric())
        .max_by_key(|run| run.len())
        .unwrap_or_default();
    assert!(run.len() >= 12, "no distinctive part in a planted secret");
    run.to_owned()
}

// ------------------------------------------------------------ session store

/// The SQLite store the CLI keeps, in WAL mode like the real one.
pub struct StoreFixture {
    conn: Connection,
}

/// One model call. Prices are the CLI's (nano-AIU per million tokens), so
/// `nano_aiu` is what the CLI itself would have recorded.
#[derive(Clone)]
pub struct Usage<'a> {
    pub session: &'a str,
    pub turn: i64,
    pub agent: Option<&'a str>,
    pub model: &'a str,
    pub initiator: &'a str,
    pub at: &'a str,
    pub fresh: i64,
    pub cache_read: i64,
    pub cache_write: i64,
    pub output: i64,
}

impl Usage<'_> {
    fn parts(&self) -> [(&'static str, i64, i64); 4] {
        [
            ("input", self.fresh, 200_000_000_000),
            ("cache_read", self.cache_read, 10_000_000_000),
            ("cache_write", self.cache_write, 250_000_000_000),
            ("output", self.output, 1_000_000_000_000),
        ]
    }

    /// The whole prompt: uncached plus both cache kinds.
    pub fn input(&self) -> i64 {
        self.fresh + self.cache_read + self.cache_write
    }

    pub fn nano_aiu(&self) -> i64 {
        self.parts()
            .iter()
            .map(|(_, tokens, price)| tokens * price / 1_000_000)
            .sum()
    }

    pub fn aiu(&self) -> f64 {
        self.nano_aiu() as f64 / 1e9
    }

    fn price_table(&self) -> String {
        let rows: Vec<Value> = self
            .parts()
            .iter()
            .map(|(kind, tokens, price)| {
                json!({"batchSize": 1_000_000, "costPerBatch": price, "tokenCount": tokens,
                       "tokenType": kind, "model": self.model})
            })
            .collect();
        Value::Array(rows).to_string()
    }
}

impl StoreFixture {
    fn create(copilot_dir: &Path) -> Self {
        let conn =
            Connection::open(copilot_dir.join(config::STORE_FILE)).expect("creating the store");
        conn.execute_batch(
            "PRAGMA journal_mode = WAL;
             CREATE TABLE sessions (id TEXT PRIMARY KEY, cwd TEXT, repository TEXT, host_type TEXT,
                 branch TEXT, summary TEXT, created_at TEXT, updated_at TEXT);
             CREATE TABLE turns (id INTEGER PRIMARY KEY, session_id TEXT, turn_index INTEGER,
                 user_message TEXT, assistant_response TEXT, timestamp TEXT);
             CREATE TABLE checkpoints (id INTEGER PRIMARY KEY, session_id TEXT,
                 checkpoint_number INTEGER, title TEXT, overview TEXT, history TEXT,
                 work_done TEXT, technical_details TEXT, important_files TEXT, next_steps TEXT,
                 created_at TEXT);
             CREATE TABLE session_files (id INTEGER PRIMARY KEY, session_id TEXT, file_path TEXT,
                 tool_name TEXT, turn_index INTEGER, first_seen_at TEXT);
             CREATE TABLE session_refs (id INTEGER PRIMARY KEY, session_id TEXT, ref_type TEXT,
                 ref_value TEXT, turn_index INTEGER, created_at TEXT);
             CREATE TABLE assistant_usage_events (id INTEGER PRIMARY KEY, session_id TEXT,
                 turn_index INTEGER, agent_id TEXT, parent_tool_call_id TEXT, model TEXT,
                 input_tokens INTEGER, output_tokens INTEGER, cache_read_tokens INTEGER,
                 cache_write_tokens INTEGER, reasoning_tokens INTEGER, total_nano_aiu INTEGER,
                 request_multiplier REAL, duration_ms INTEGER, time_to_first_token_ms REAL,
                 inter_token_latency_ms REAL, initiator TEXT, api_endpoint TEXT,
                 reasoning_effort TEXT, finish_reason TEXT, content_filter_triggered INTEGER,
                 token_details_json TEXT, created_at TEXT, output_ttft_ms REAL,
                 copilot_usage_model TEXT);",
        )
        .expect("creating the store schema");
        Self { conn }
    }

    pub fn session(&self, id: &str, summary: &str) {
        self.conn
            .execute(
                "INSERT INTO sessions VALUES (?1, '/work/demo', 'acme/demo', 'github', 'main', ?2,
                     '2026-10-01 08:00:00', '2026-10-01T09:00:00.000Z')",
                params![id, summary],
            )
            .expect("inserting a session");
    }

    pub fn turn(&self, session: &str, index: i64, user: &str, assistant: Option<&str>) {
        self.conn
            .execute(
                "INSERT INTO turns (session_id, turn_index, user_message, assistant_response, timestamp)
                 VALUES (?1, ?2, ?3, ?4, '2026-10-01 08:00:01')",
                params![session, index, user, assistant],
            )
            .expect("inserting a turn");
    }

    pub fn checkpoint(&self, session: &str, number: i64, title: &str, overview: &str) {
        self.conn
            .execute(
                "INSERT INTO checkpoints (session_id, checkpoint_number, title, overview, created_at)
                 VALUES (?1, ?2, ?3, ?4, '2026-10-01 08:30:00')",
                params![session, number, title, overview],
            )
            .expect("inserting a checkpoint");
    }

    pub fn file(&self, session: &str, path: &str, turn: i64) {
        self.conn
            .execute(
                "INSERT INTO session_files (session_id, file_path, tool_name, turn_index, first_seen_at)
                 VALUES (?1, ?2, 'edit', ?3, '2026-10-01 08:00:02')",
                params![session, path, turn],
            )
            .expect("inserting a file");
    }

    pub fn reference(&self, session: &str, kind: &str, value: &str, turn: i64) {
        self.conn
            .execute(
                "INSERT INTO session_refs (session_id, ref_type, ref_value, turn_index, created_at)
                 VALUES (?1, ?2, ?3, ?4, '2026-10-01 08:00:03')",
                params![session, kind, value, turn],
            )
            .expect("inserting a reference");
    }

    pub fn usage(&self, u: &Usage<'_>) {
        self.conn
            .execute(
                "INSERT INTO assistant_usage_events
                     (session_id, turn_index, agent_id, model, input_tokens, output_tokens,
                      cache_read_tokens, cache_write_tokens, total_nano_aiu, request_multiplier,
                      initiator, token_details_json, created_at)
                 VALUES (?1, ?2, ?3, ?4, ?5, ?6, ?7, ?8, ?9, 1.0, ?10, ?11, ?12)",
                params![
                    u.session,
                    u.turn,
                    u.agent,
                    u.model,
                    u.input(),
                    u.output,
                    u.cache_read,
                    u.cache_write,
                    u.nano_aiu(),
                    u.initiator,
                    u.price_table(),
                    u.at
                ],
            )
            .expect("inserting a usage row");
    }
}

/// Five model calls in two sessions, laid out so that every report rule has
/// something to bite on: a sub-agent call, one cold-cache rebuild after a long
/// idle gap (a user-initiated one), and a second session.
pub fn usages() -> Vec<Usage<'static>> {
    let call =
        |session, turn, agent, initiator, at, fresh, cache_read, cache_write, output| Usage {
            session,
            turn,
            agent,
            model: "claude-sonnet-5.5",
            initiator,
            at,
            fresh,
            cache_read,
            cache_write,
            output,
        };
    vec![
        call(
            "alpha",
            0,
            None,
            "user",
            "2026-10-01T08:00:10.000Z",
            100,
            0,
            30_000,
            500,
        ),
        call(
            "alpha",
            0,
            None,
            "agent",
            "2026-10-01T08:00:40.000Z",
            50,
            30_000,
            200,
            300,
        ),
        call(
            "alpha",
            0,
            Some("agent-1"),
            "agent",
            "2026-10-01T08:00:45.000Z",
            80,
            0,
            10_000,
            400,
        ),
        call(
            "alpha",
            1,
            None,
            "user",
            "2026-10-01T08:40:00.000Z",
            60,
            1_000,
            29_000,
            200,
        ),
        call(
            "beta",
            0,
            None,
            "user",
            "2026-10-01T09:00:00.000Z",
            10,
            40_000,
            0,
            100,
        ),
    ]
}

/// Rows each table must hold after [`populate`] has been ingested, in the
/// order of `db::table_counts`.
pub fn expected_counts() -> Vec<(&'static str, i64)> {
    vec![
        ("sessions", 4),
        ("events", 27),
        ("tool_calls", 5),
        ("usage", 5),
        ("turns", 5),
        ("checkpoints", 1),
        ("session_files", 2),
        ("session_refs", 1),
        ("redactions", 0),
    ]
}

/// A small but complete Copilot directory:
///   * `alpha` (3 turns) and `beta` (2 turns) with events and a store entry;
///   * `gamma`, which has only a `workspace.yaml`;
///   * `delta`, which only the store knows (its state directory is gone).
///
/// Returns the open store, so that a test can keep writing to it.
pub fn populate(env: &Env) -> StoreFixture {
    env.add_session("alpha", &story("alpha", 3));
    env.write_workspace("alpha", "Alpha task", Some("Alpha does a thing"));
    env.add_session("beta", &story("beta", 2));
    env.write_workspace("beta", "Beta task", None);
    env.write_workspace("gamma", "Gamma task", None);

    let store = env.store();
    store.session("alpha", "Alpha, as the store sees it");
    store.session("beta", "Beta, as the store sees it");
    store.session("delta", "Delta, long gone from disk");
    for i in 0..3 {
        store.turn(
            "alpha",
            i,
            &format!("alpha asks {i}"),
            Some("alpha answers"),
        );
    }
    for i in 0..2 {
        store.turn("beta", i, &format!("beta asks {i}"), None);
    }
    store.checkpoint("alpha", 1, "First checkpoint", "What alpha did so far");
    store.file("alpha", "/work/demo/src/main.rs", 0);
    store.file("alpha", "/work/demo/README.md", 1);
    store.reference("alpha", "pr", "https://example.test/acme/demo/pull/7", 1);
    for usage in usages() {
        store.usage(&usage);
    }
    store
}

// ----------------------------------------------------------------- waiting

/// Polls `check` until it holds, or fails the test after `within`.
pub async fn eventually<F, Fut>(what: &str, within: Duration, mut check: F)
where
    F: FnMut() -> Fut,
    Fut: Future<Output = bool>,
{
    let deadline = Instant::now() + within;
    loop {
        if check().await {
            return;
        }
        assert!(
            Instant::now() < deadline,
            "gave up after {within:?} waiting for {what}"
        );
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Generous: the tests share a machine with compilers.
pub const PATIENCE: Duration = Duration::from_secs(30);

// -------------------------------------------------------------------- tail

/// Short timers so that a test does not wait seconds for a flush, and a
/// rescan so far away that whatever arrives came through a notification.
pub fn quick_tail() -> TailOptions {
    TailOptions {
        jobs: 2,
        debounce: Duration::from_millis(100),
        max_delay: Duration::from_millis(500),
        store_interval: Duration::from_millis(200),
        rescan: Duration::from_secs(600),
    }
}

/// A running `watch::run`, stopped by [`Tailing::stop`] or, when the test
/// ends early, aborted on drop.
pub struct Tailing {
    stop: Option<oneshot::Sender<()>>,
    task: Option<JoinHandle<anyhow::Result<Summary>>>,
}

impl Env {
    pub fn start_tail(&self, opts: TailOptions) -> Tailing {
        let (stop, stopped) = oneshot::channel::<()>();
        let task = tokio::spawn(watch::run(self.ingester.clone(), opts, async move {
            let _ = stopped.await;
        }));
        Tailing {
            stop: Some(stop),
            task: Some(task),
        }
    }
}

impl Tailing {
    pub async fn stop(mut self) -> Summary {
        let _ = self.stop.take().expect("stopped once").send(());
        self.task
            .take()
            .expect("stopped once")
            .await
            .expect("the tail task panicked")
            .expect("the tail failed")
    }
}

impl Drop for Tailing {
    fn drop(&mut self) {
        if let Some(task) = self.task.take() {
            task.abort();
        }
    }
}
