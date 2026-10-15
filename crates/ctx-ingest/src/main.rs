//! `ctx-ingest`: Copilot CLI session logs -> PostgreSQL.

use std::path::PathBuf;
use std::process::ExitCode;
use std::sync::Arc;
use std::sync::atomic::{AtomicBool, Ordering};
use std::time::Duration;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};
use ctx_core::config::Config;
use ctx_core::db::{self, IngestLock};
use ctx_core::ingest::Ingester;
use ctx_core::verify::Verifier;
use ctx_core::watch::{self, TailOptions};
use tokio::signal::unix::{SignalKind, signal};
use tracing_subscriber::EnvFilter;

/// `2`, `2s`, `0.5s` or `500ms`.
fn parse_duration(text: &str) -> Result<Duration, String> {
    let (number, per_unit) = match text.strip_suffix("ms") {
        Some(number) => (number, 0.001),
        None => (text.strip_suffix('s').unwrap_or(text), 1.0),
    };
    let seconds: f64 = number
        .trim()
        .parse::<f64>()
        .map_err(|_| format!("{text:?} is not a duration such as 2s or 500ms"))?
        * per_unit;
    // Also rejects NaN.
    if !(0.0..=86_400.0).contains(&seconds) {
        return Err(format!("{text:?} is outside 0..=86400 seconds"));
    }
    Ok(Duration::from_secs_f64(seconds))
}

#[derive(Parser)]
#[command(version, about = "Ingest Copilot CLI session logs into PostgreSQL")]
struct Cli {
    /// PostgreSQL URL [default: $CTX_DATABASE_URL, $DATABASE_URL, the local socket]
    #[arg(long, global = true, value_name = "URL")]
    database_url: Option<String>,
    /// Copilot CLI state directory [default: $CTX_COPILOT_DIR, $COPILOT_HOME, ~/.copilot]
    #[arg(long, global = true, value_name = "DIR")]
    copilot_dir: Option<PathBuf>,
    /// Work in this schema instead of `public` (used by the integration tests)
    #[arg(long, global = true, hide = true)]
    schema: Option<String>,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Import everything new; the first run imports the whole history.
    /// Re-running adds nothing.
    #[command(alias = "backfill")]
    Once {
        /// Re-read every source from the start (after the redaction rules changed)
        #[arg(long)]
        force: bool,
        /// Sessions read concurrently
        #[arg(long, default_value_t = 4)]
        jobs: usize,
    },
    /// Check the database against the files it was built from and look for
    /// secrets in it. Writes nothing, prints counts only, and exits 2 when a
    /// check fails. Safe to run while `once` or `tail` is running.
    Verify {
        /// Session files compared concurrently
        #[arg(long, default_value_t = 4)]
        jobs: usize,
    },
    /// Catch up, then keep the database current while the Copilot CLI writes
    /// (inotify plus a periodic full pass). Runs until SIGTERM or Ctrl-C;
    /// meant for a service started at low priority (systemd/ctx-ingest.service).
    Tail {
        /// Sessions read concurrently
        #[arg(long, default_value_t = 4)]
        jobs: usize,
        /// How long the files must stay quiet before they are read
        #[arg(long, default_value = "2s", value_parser = parse_duration)]
        debounce: Duration,
        /// The longest a change waits when the files never go quiet
        #[arg(long, default_value = "10s", value_parser = parse_duration)]
        max_delay: Duration,
        /// The shortest time between two syncs of session-store.db
        #[arg(long, default_value = "15s", value_parser = parse_duration)]
        store_interval: Duration,
        /// Period of the full pass that backs up the notifications
        #[arg(long, default_value = "60s", value_parser = parse_duration)]
        rescan: Duration,
        /// How often the tail checks that it still holds the ingest lock
        /// (the integration tests shorten it)
        #[arg(long, default_value = "30s", value_parser = parse_duration, hide = true)]
        lock_check: Duration,
    },
}

/// Completes, with the error, once the connection that holds `lock` is gone.
/// PostgreSQL drops an advisory lock together with its session, so a tail
/// that outlived a server restart would go on running without keeping anyone
/// out. Exiting lets the service manager start a fresh one, which takes the
/// lock again (or finds it taken and steps aside).
async fn lock_lost(mut lock: IngestLock, every: Duration) -> anyhow::Error {
    let every = every.max(Duration::from_millis(50));
    loop {
        tokio::time::sleep(every).await;
        if let Err(error) = lock.check().await {
            return error;
        }
    }
}

async fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    let mut config = Config::from_env()?;
    if let Some(url) = cli.database_url {
        config.database_url = url;
    }
    if let Some(dir) = cli.copilot_dir {
        config.copilot_dir = dir;
    }
    let jobs = match &cli.command {
        Cmd::Once { jobs, .. } | Cmd::Verify { jobs } | Cmd::Tail { jobs, .. } => (*jobs).max(1),
    };
    let pool = db::connect(
        &config.database_url,
        "ctx-ingest",
        cli.schema.as_deref(),
        u32::try_from(jobs + 4).unwrap_or(8),
    )
    .await?;
    db::migrate(&pool).await?;
    // Held until the command ends. `verify` only reads, so it never competes
    // for it. `tail` hands it to the watchdog that notices when it is lost.
    let mut lock = match &cli.command {
        Cmd::Once { .. } | Cmd::Tail { .. } => {
            let Some(lock) = IngestLock::try_acquire(&pool).await? else {
                eprintln!("another ctx-ingest is already running against this database");
                return Ok(ExitCode::from(3));
            };
            Some(lock)
        }
        Cmd::Verify { .. } => None,
    };
    let ingester = Ingester::new(pool.clone(), config);

    match cli.command {
        Cmd::Tail {
            jobs,
            debounce,
            max_delay,
            store_interval,
            rescan,
            lock_check,
        } => {
            // Installed before anything else runs, so a signal that arrives
            // during the catch-up is not lost.
            let mut term =
                signal(SignalKind::terminate()).context("installing the SIGTERM handler")?;
            let mut int =
                signal(SignalKind::interrupt()).context("installing the SIGINT handler")?;
            let lock = lock.take().context("the tail must hold the ingest lock")?;
            let lost = Arc::new(AtomicBool::new(false));
            let shutdown = {
                let lost = Arc::clone(&lost);
                async move {
                    tokio::select! {
                        _ = term.recv() => {}
                        _ = int.recv() => {}
                        error = lock_lost(lock, lock_check) => {
                            eprintln!(
                                "error: the connection that held the ingest lock is gone \
                                 ({error}); stopping so that a fresh ingester can take over"
                            );
                            lost.store(true, Ordering::SeqCst);
                        }
                    }
                }
            };
            let options = TailOptions {
                jobs,
                debounce,
                max_delay,
                store_interval,
                rescan,
            };
            watch::run(ingester, options, shutdown).await?;
            Ok(if lost.load(Ordering::SeqCst) {
                ExitCode::from(1)
            } else {
                ExitCode::SUCCESS
            })
        }
        Cmd::Verify { .. } => {
            let started = std::time::Instant::now();
            let report = Verifier::new(ingester).run(jobs).await?;
            print!("{}", report.render());
            println!("({:.1}s)", started.elapsed().as_secs_f64());
            Ok(if report.ok() {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            })
        }
        Cmd::Once { force, jobs } => {
            let started = std::time::Instant::now();
            let run = ingester.run_all(force, jobs.max(1)).await?;
            let t = &run.totals;
            let s = &run.store;
            println!(
                "sessions: {} read ({} restarted), {} unchanged | lines: {} ({} rejected) | \
                 changed rows: events {}, tool_calls {} | redactions: {} | {:.1}s",
                t.sessions_read,
                t.sessions_restarted,
                t.sessions_skipped,
                t.lines,
                t.rejected,
                t.events_changed,
                t.tool_calls_changed,
                t.redactions,
                started.elapsed().as_secs_f64()
            );
            println!(
                "store: {} sessions | changed rows: usage {} ({} rejected), turns {}, \
                 checkpoints {}, files {}, refs {}",
                s.sessions_seen,
                s.usage_changed,
                s.usage_rejected,
                s.turns_changed,
                s.checkpoints_changed,
                s.files_changed,
                s.refs_changed
            );
            for (table, n) in db::table_counts(&pool).await? {
                println!("{table:<14} {n}");
            }
            if run.failed.is_empty() {
                Ok(ExitCode::SUCCESS)
            } else {
                for (id, error) in &run.failed {
                    eprintln!("FAILED {id}: {error}");
                }
                Ok(ExitCode::from(1))
            }
        }
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::try_from_default_env().unwrap_or_else(|_| {
            // sqlx narrates every `CREATE ... IF NOT EXISTS` and logs statements slower than 1 s
            EnvFilter::new("info,sqlx::query=error,sqlx::postgres::notice=warn")
        }))
        .with_writer(std::io::stderr)
        .init();
    match run().await.context("ctx-ingest failed") {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(1)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn durations_take_seconds_or_milliseconds() {
        assert_eq!(parse_duration("2"), Ok(Duration::from_secs(2)));
        assert_eq!(parse_duration("2s"), Ok(Duration::from_secs(2)));
        assert_eq!(parse_duration("0.5s"), Ok(Duration::from_millis(500)));
        assert_eq!(parse_duration("250ms"), Ok(Duration::from_millis(250)));
        assert_eq!(parse_duration("0"), Ok(Duration::ZERO));
    }

    #[test]
    fn nonsense_durations_are_refused() {
        for text in ["", "s", "ms", "fast", "-1s", "nan", "inf", "86401", "1m"] {
            assert!(parse_duration(text).is_err(), "{text:?}");
        }
    }
}
