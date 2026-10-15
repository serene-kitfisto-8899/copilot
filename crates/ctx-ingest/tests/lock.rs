//! The ingest lock, end to end: the real `ctx-ingest` binary against a scratch
//! schema and an empty Copilot directory. Nothing here touches `~/.copilot`,
//! the `public` schema or a running service (the lock is per schema).
//!
//! Needs a reachable PostgreSQL, like the `ctx-core` integration tests:
//! `CTX_TEST_DATABASE_URL` overrides the default URL, and without a database
//! the tests print "SKIPPED" and pass unless `CTX_REQUIRE_DB` is set.

use std::fs;
use std::future::Future;
use std::path::PathBuf;
use std::process::{Child, Command, ExitStatus, Stdio};
use std::sync::atomic::{AtomicU32, Ordering};
use std::time::{Duration, Instant};

use ctx_core::config::Config;
use ctx_core::db;
use sqlx::PgPool;
use tempfile::TempDir;

const BIN: &str = env!("CARGO_BIN_EXE_ctx-ingest");

fn database_url() -> String {
    std::env::var("CTX_TEST_DATABASE_URL")
        .ok()
        .filter(|url| !url.is_empty())
        .unwrap_or_else(|| {
            Config::from_env()
                .expect("reading the environment")
                .database_url
        })
}

/// A scratch schema plus an empty Copilot directory. The log files of the
/// processes live beside the Copilot directory, not in it: the tail watches
/// that one, so writing its own log there would feed it its own events.
struct Scene {
    root: TempDir,
    url: String,
    schema: String,
    logs: AtomicU32,
}

impl Scene {
    fn copilot(&self) -> PathBuf {
        self.root.path().join("copilot")
    }

    fn command(&self, subcommand: &str) -> Command {
        let mut command = Command::new(BIN);
        command
            .args(["--database-url", &self.url, "--schema", &self.schema])
            .arg("--copilot-dir")
            .arg(self.copilot())
            .arg(subcommand)
            .args(["--jobs", "1"])
            // The tests wait for INFO lines whatever the caller exported.
            .env("RUST_LOG", "info")
            .stdout(Stdio::null());
        command
    }

    fn spawn(&self, subcommand: &str, extra: &[&str]) -> Process {
        let log = self.root.path().join(format!(
            "process-{}.log",
            self.logs.fetch_add(1, Ordering::SeqCst)
        ));
        let child = self
            .command(subcommand)
            .args(extra)
            .stderr(fs::File::create(&log).expect("creating a log file"))
            .spawn()
            .expect("starting ctx-ingest");
        Process { child, log }
    }
}

/// A child process that cannot outlive the test, however it ends.
struct Process {
    child: Child,
    log: PathBuf,
}

impl Drop for Process {
    fn drop(&mut self) {
        let _ = self.child.kill();
        let _ = self.child.wait();
    }
}

impl Process {
    fn log(&self) -> String {
        fs::read_to_string(&self.log).unwrap_or_default()
    }

    async fn caught_up(&mut self) {
        let deadline = Instant::now() + Duration::from_secs(60);
        while !self.log().contains("caught up") {
            assert!(
                self.child.try_wait().unwrap().is_none(),
                "the tail exited before it caught up:\n{}",
                self.log()
            );
            assert!(Instant::now() < deadline, "no catch-up:\n{}", self.log());
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    async fn exit(&mut self, within: Duration) -> ExitStatus {
        let deadline = Instant::now() + within;
        loop {
            if let Some(status) = self.child.try_wait().unwrap() {
                return status;
            }
            assert!(
                Instant::now() < deadline,
                "still running after {within:?}:\n{}",
                self.log()
            );
            tokio::time::sleep(Duration::from_millis(50)).await;
        }
    }

    fn still_running(&mut self) -> bool {
        self.child.try_wait().unwrap().is_none()
    }

    fn terminate(&self) {
        let status = Command::new("kill")
            .args(["-TERM", &self.child.id().to_string()])
            .status()
            .expect("running kill");
        assert!(status.success());
    }
}

/// The backend that holds the advisory lock of `schema`, if there is one:
/// `pg_try_advisory_lock(bigint)` shows up in `pg_locks` as the key's high
/// half in `classid`, its low half in `objid` and `objsubid = 1`.
async fn lock_holder(pool: &PgPool, schema: &str) -> Option<i32> {
    sqlx::query_scalar(
        "SELECT pid FROM pg_locks
          WHERE locktype = 'advisory' AND objsubid = 1 AND granted
            AND ((classid::bigint << 32) | objid::bigint)
                = hashtext('ctx-ingest:' || $1::text)::bigint",
    )
    .bind(schema)
    .fetch_optional(pool)
    .await
    .expect("reading pg_locks")
}

/// PostgreSQL frees the lock when it notices that the connection is closed,
/// which is a moment after the process is gone.
async fn lock_freed(pool: &PgPool, schema: &str) {
    let deadline = Instant::now() + Duration::from_secs(10);
    while lock_holder(pool, schema).await.is_some() {
        assert!(Instant::now() < deadline, "the lock is still held");
        tokio::time::sleep(Duration::from_millis(50)).await;
    }
}

/// Runs `body` with a fresh scene and drops the schema afterwards, also when
/// the body panics (its processes are killed first, when it unwinds).
async fn with_scene<F, Fut>(name: &str, body: F)
where
    F: FnOnce(Scene, PgPool) -> Fut + Send + 'static,
    Fut: Future<Output = ()> + Send + 'static,
{
    let url = database_url();
    let schema = format!("ctxtest_cli_{name}_{}", std::process::id());
    let pool = match db::connect(&url, "ctx-ingest-cli-tests", Some(&schema), 2).await {
        Ok(pool) => pool,
        Err(error) if std::env::var_os("CTX_REQUIRE_DB").is_some() => {
            panic!("PostgreSQL is required (CTX_REQUIRE_DB is set): {error:#}")
        }
        Err(error) => {
            eprintln!("SKIPPED {name}: PostgreSQL is not reachable ({error:#})");
            return;
        }
    };
    let root = tempfile::tempdir().expect("creating a temporary directory");
    fs::create_dir_all(root.path().join("copilot/session-state")).expect("creating the state dir");
    let scene = Scene {
        root,
        url,
        schema: schema.clone(),
        logs: AtomicU32::new(0),
    };
    let outcome = tokio::spawn(body(scene, pool.clone())).await;
    db::drop_schema(&pool, &schema)
        .await
        .expect("dropping the scratch schema");
    if let Err(error) = outcome {
        std::panic::resume_unwind(error.into_panic());
    }
}

#[tokio::test]
async fn a_tail_keeps_every_other_ingester_out_and_frees_the_lock_when_it_stops() {
    with_scene("exclusion", |scene, pool| async move {
        // Checking every 100 ms also shows that a healthy lock is never
        // mistaken for a lost one.
        let mut tail = scene.spawn("tail", &["--lock-check", "100ms"]);
        tail.caught_up().await;
        assert!(lock_holder(&pool, &scene.schema).await.is_some());

        for subcommand in ["once", "tail"] {
            let mut second = scene.spawn(subcommand, &[]);
            let status = second.exit(Duration::from_secs(30)).await;
            assert_eq!(status.code(), Some(3), "{subcommand}:\n{}", second.log());
            assert!(
                second
                    .log()
                    .contains("another ctx-ingest is already running")
            );
        }

        tokio::time::sleep(Duration::from_secs(1)).await;
        assert!(tail.still_running(), "the tail stopped:\n{}", tail.log());

        // SIGTERM is the clean stop the service relies on.
        tail.terminate();
        let status = tail.exit(Duration::from_secs(30)).await;
        assert_eq!(status.code(), Some(0), "{}", tail.log());
        lock_freed(&pool, &scene.schema).await;

        let mut once = scene.spawn("once", &[]);
        let status = once.exit(Duration::from_secs(30)).await;
        assert_eq!(status.code(), Some(0), "{}", once.log());
    })
    .await;
}

#[tokio::test]
async fn a_tail_that_loses_its_lock_connection_stops_so_that_it_is_restarted() {
    with_scene("lost", |scene, pool| async move {
        let mut tail = scene.spawn("tail", &["--lock-check", "100ms"]);
        tail.caught_up().await;
        let pid = lock_holder(&pool, &scene.schema)
            .await
            .expect("the tail holds its lock");

        // What a PostgreSQL restart does to the connection, without the restart.
        let ended: bool = sqlx::query_scalar("SELECT pg_terminate_backend($1)")
            .bind(pid)
            .fetch_one(&pool)
            .await
            .expect("terminating the lock connection");
        assert!(ended);

        let status = tail.exit(Duration::from_secs(30)).await;
        assert_eq!(status.code(), Some(1), "{}", tail.log());
        assert!(
            tail.log().contains("held the ingest lock is gone"),
            "{}",
            tail.log()
        );

        // Nothing holds the lock now, so the next ingester starts normally.
        lock_freed(&pool, &scene.schema).await;
        let mut once = scene.spawn("once", &[]);
        let status = once.exit(Duration::from_secs(30)).await;
        assert_eq!(status.code(), Some(0), "{}", once.log());
    })
    .await;
}
