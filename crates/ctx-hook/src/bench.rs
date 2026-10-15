//! `ctx-hook bench`: how long the hook takes, as the CLI sees it: a process
//! started, a request on its stdin, its exit awaited. PLAN.md §5 asks for a
//! 95th percentile under 50 ms.
//!
//! The runs are the real thing: this binary, the real configuration and the
//! real database, under a session of their own whose rows are deleted
//! afterwards. A row that misses the database deadline goes to a spool in a
//! directory of its own (`XDG_STATE_HOME`), so that a benchmark never leaves
//! rows in the spool `review` imports.

use std::io::Write;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use chrono::Utc;
use ctx_core::config::hook_database_url;
use ctx_core::db;
use serde_json::json;
use sqlx::PgPool;

use crate::audit::{self, BENCH_SESSION_PREFIX, DB_DEADLINE, Row};
use crate::config::Config;
use crate::hook::Policy;
use crate::review::{P95_BUDGET_MS, Spread, spread};
use crate::vars::Vars;

/// What the CLI runs the hook for, in the proportions that matter little: the
/// cost is the process, the redaction and the row, not the analysis. A command
/// that is allowed, ones passed for different reasons, a pipeline, a list, and
/// one that is not worth parsing twice.
const COMMANDS: &[&str] = &[
    "ls -la",
    "git log --oneline | head -n 5",
    "rm -rf /tmp/ctx-hook-bench-x",
    "cat README.md | grep -n foo",
    "grep -rn \"fn main\" src | head -n 20",
    "cd src && git status && git diff | head -n 50",
    "curl -s https://example.invalid/api | jq .",
    "find . -name '*.rs' -exec wc -l {} +",
];
const ALLOW: &str = r#"{"behavior":"allow"}"#;
/// How long the read-back may take to reach the database.
const READ_BACK: Duration = Duration::from_secs(5);

pub struct Options {
    pub runs: usize,
    pub warmup: usize,
}

/// What the runs measured.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Timings {
    /// Milliseconds from starting the process to its exit.
    pub wall_ms: Vec<f64>,
    /// What the hook measured about itself (the `latency_us` of its rows).
    pub in_process_ms: Vec<f64>,
    pub runs: usize,
    pub warmup: usize,
    /// Rows of the measured runs found in `hook_audit` and in the spool, and
    /// whether the database could be reached to look.
    pub stored: usize,
    pub spooled: usize,
    pub database: bool,
}

pub struct Header {
    pub binary: PathBuf,
    pub mode: String,
    pub policy: String,
    pub cwd: PathBuf,
}

pub fn render(t: &Timings, head: &Header) -> String {
    use std::fmt::Write as _;
    let mut o = String::new();
    let _ = writeln!(
        o,
        "ctx-hook bench   {}   mode: {}   policy: {}",
        head.binary.display(),
        head.mode,
        head.policy
    );
    let _ = writeln!(
        o,
        "   {} runs after {} warm-up runs, from {}, over {} commands",
        t.runs,
        t.warmup,
        head.cwd.display(),
        COMMANDS.len()
    );
    let _ = writeln!(
        o,
        "\n   {:<34} {:>6} {:>8} {:>8} {:>8} {:>8} {:>8}",
        "milliseconds", "runs", "min", "p50", "p95", "p99", "max"
    );
    let row = |o: &mut String, name: &str, s: Option<&Spread>| match s {
        Some(s) => {
            let _ = writeln!(
                o,
                "   {name:<34} {:>6} {:>8.1} {:>8.1} {:>8.1} {:>8.1} {:>8.1}",
                s.n, s.min, s.p50, s.p95, s.p99, s.max
            );
        }
        None => {
            let _ = writeln!(o, "   {name:<34} none recorded");
        }
    };
    let wall = spread(t.wall_ms.clone());
    row(&mut o, "process start to exit (the CLI's)", wall.as_ref());
    row(
        &mut o,
        "inside the process (its own clock)",
        spread(t.in_process_ms.clone()).as_ref(),
    );

    let lost = t.runs.saturating_sub(t.stored + t.spooled);
    let _ = if t.database {
        writeln!(
            o,
            "\n   rows: {} in hook_audit, {} spooled (the database did not answer within {} ms), {} neither; the benchmark's rows were deleted",
            t.stored,
            t.spooled,
            DB_DEADLINE.as_millis(),
            lost
        )
    } else {
        writeln!(
            o,
            "\n   rows: the database could not be reached to read them back; {} were spooled, in a directory of the benchmark's own",
            t.spooled
        )
    };
    match wall {
        Some(s) => {
            let _ = writeln!(
                o,
                "   p95 under {P95_BUDGET_MS:.0} ms: {} ({:.1} ms)",
                if s.p95 < P95_BUDGET_MS { "ok" } else { "FAIL" },
                s.p95
            );
        }
        None => {
            let _ = writeln!(
                o,
                "   p95 under {P95_BUDGET_MS:.0} ms: nothing was measured"
            );
        }
    }
    o
}

/// The directory the benchmark's spool is in, removed when it goes out of scope.
struct Scratch(PathBuf);

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// One run of the hook: its wall-clock time in milliseconds.
fn once(exe: &Path, state: &Path, input: &[u8]) -> Result<f64> {
    let started = Instant::now();
    let mut child = Command::new(exe)
        .arg("permission")
        .env("XDG_STATE_HOME", state)
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .with_context(|| format!("starting {}", exe.display()))?;
    child
        .stdin
        .take()
        .context("the hook has no stdin")?
        .write_all(input)
        .context("writing the request")?;
    let out = child.wait_with_output()?;
    let ms = started.elapsed().as_secs_f64() * 1000.0;
    // a hook that does anything else than log and, in enforce mode, allow is a
    // finding, not a timing
    let stdout = String::from_utf8_lossy(&out.stdout);
    if out.status.code() != Some(0)
        || !out.stderr.is_empty()
        || !(stdout.is_empty() || stdout.trim() == ALLOW)
    {
        bail!(
            "the hook did not behave: status {:?}, stdout {:?}, stderr {:?}",
            out.status.code(),
            stdout,
            String::from_utf8_lossy(&out.stderr)
        );
    }
    Ok(ms)
}

/// The `latency_us` of the rows the measured runs made, and then they are
/// deleted, with any left by a benchmark that did not finish.
async fn read_back(pool: &PgPool, session: &str, since_ms: i64) -> Result<(usize, Vec<f64>)> {
    let found: Vec<Option<i32>> = sqlx::query_scalar(
        "SELECT latency_us FROM hook_audit
          WHERE session_id = $1 AND ts >= to_timestamp($2::float8 / 1000.0)",
    )
    .bind(session)
    .bind(since_ms as f64)
    .fetch_all(pool)
    .await
    .context("reading the benchmark's rows")?;
    sqlx::query("DELETE FROM hook_audit WHERE session_id LIKE $1")
        .bind(format!("{BENCH_SESSION_PREFIX}%"))
        .execute(pool)
        .await
        .context("deleting the benchmark's rows")?;
    let in_process = found
        .iter()
        .flatten()
        .map(|us| f64::from(*us) / 1000.0)
        .collect();
    Ok((found.len(), in_process))
}

/// The rows the measured runs spooled.
fn spooled(path: &Path, since_ms: i64) -> Vec<Row> {
    std::fs::read_to_string(path)
        .unwrap_or_default()
        .lines()
        .filter_map(|line| serde_json::from_str::<Row>(line).ok())
        .filter(|row| row.ts.timestamp_millis() >= since_ms)
        .collect()
}

pub fn run(opts: &Options) -> Result<String> {
    if opts.runs == 0 {
        bail!("--runs must be at least 1");
    }
    let process = Vars::Process;
    let Some(home) = process
        .get("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_absolute())
    else {
        bail!("HOME is not set to an absolute path");
    };
    let home_text = home.to_string_lossy().into_owned();
    let config = Config::load(&process, &home);
    let policy = Policy::new(&home, &config, Vars::fixed(&[("HOME", home_text.as_str())]));
    let exe = std::env::current_exe().context("finding the binary to run")?;
    let cwd = std::env::current_dir().unwrap_or_else(|_| home.clone());

    let session = format!("{BENCH_SESSION_PREFIX}{}", std::process::id());
    let scratch = Scratch(std::env::temp_dir().join(&session));
    std::fs::create_dir_all(&scratch.0).context("making the benchmark's spool directory")?;
    let state = scratch.0.to_string_lossy().into_owned();
    let spool = audit::spool_path(&Vars::fixed(&[("XDG_STATE_HOME", state.as_str())]), &home);

    let mut wall = Vec::with_capacity(opts.runs);
    let mut since_ms = Utc::now().timestamp_millis();
    for i in 0..opts.warmup + opts.runs {
        if i == opts.warmup {
            since_ms = Utc::now().timestamp_millis();
        }
        let input = json!({
            "hookName": "permissionRequest",
            "sessionId": session,
            "timestamp": Utc::now().timestamp_millis(),
            "cwd": cwd,
            "toolName": "bash",
            "toolInput": {"command": COMMANDS[i % COMMANDS.len()]},
            "permissionSuggestions": [],
        })
        .to_string();
        let ms = once(&exe, &scratch.0, input.as_bytes())?;
        if i >= opts.warmup {
            wall.push(ms);
        }
    }

    let spooled = spooled(&spool, since_ms);
    let mut timings = Timings {
        wall_ms: wall,
        in_process_ms: spooled
            .iter()
            .filter_map(|row| row.latency_us)
            .map(|us| f64::from(us) / 1000.0)
            .collect(),
        runs: opts.runs,
        warmup: opts.warmup,
        spooled: spooled.len(),
        ..Timings::default()
    };

    // The database the hook itself writes to
    let url = hook_database_url(&|key| process.get(key).filter(|v| !v.is_empty()));
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let found = runtime.block_on(async {
        let pool = tokio::time::timeout(READ_BACK, db::connect(&url, "ctx-hook-bench", None, 1))
            .await
            .ok()?
            .ok()?;
        let found = read_back(&pool, &session, since_ms).await;
        pool.close().await;
        Some(found)
    });
    match found {
        Some(found) => {
            let (stored, in_process) = found?;
            timings.database = true;
            timings.stored = stored;
            timings.in_process_ms.extend(in_process);
        }
        None => timings.database = false,
    }

    let head = Header {
        binary: exe,
        mode: config.mode.as_str().to_owned(),
        policy: policy.id().to_owned(),
        cwd,
    };
    Ok(render(&timings, &head))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn head() -> Header {
        Header {
            binary: PathBuf::from("/bin/ctx-hook"),
            mode: "shadow".to_owned(),
            policy: "v1:aaaaaaaa".to_owned(),
            cwd: PathBuf::from("/home/u/kms"),
        }
    }

    fn timings(wall: &[f64]) -> Timings {
        Timings {
            wall_ms: wall.to_vec(),
            in_process_ms: wall.iter().map(|w| w / 2.0).collect(),
            runs: wall.len(),
            warmup: 3,
            stored: wall.len(),
            spooled: 0,
            database: true,
        }
    }

    #[test]
    fn a_fast_hook_passes_the_budget() {
        let text = render(&timings(&[8.0, 9.0, 10.0, 11.0, 30.0]), &head());
        for want in [
            "ctx-hook bench   /bin/ctx-hook   mode: shadow   policy: v1:aaaaaaaa",
            "5 runs after 3 warm-up runs, from /home/u/kms, over 8 commands",
            "process start to exit (the CLI's)",
            "inside the process (its own clock)",
            "rows: 5 in hook_audit, 0 spooled",
            "0 neither; the benchmark's rows were deleted",
            "p95 under 50 ms: ok (30.0 ms)",
        ] {
            assert!(text.contains(want), "missing {want:?} in\n{text}");
        }
    }

    #[test]
    fn a_slow_tail_fails_it() {
        let mut wall = vec![9.0; 19];
        wall.push(80.0);
        // 19 of 20 are fast: the 95th percentile is the 19th, still fast
        assert!(render(&timings(&wall), &head()).contains("p95 under 50 ms: ok (9.0 ms)"));
        wall.push(80.0);
        let text = render(&timings(&wall), &head());
        assert!(text.contains("p95 under 50 ms: FAIL (80.0 ms)"), "{text}");
    }

    #[test]
    fn rows_that_went_missing_are_counted() {
        let mut t = timings(&[9.0, 9.0]);
        t.stored = 1;
        t.spooled = 1;
        let text = render(&t, &head());
        assert!(text.contains("rows: 1 in hook_audit, 1 spooled"), "{text}");
        assert!(text.contains("0 neither"), "{text}");
        t.stored = 0;
        assert!(render(&t, &head()).contains("1 neither"));
        t.database = false;
        let text = render(&t, &head());
        assert!(
            text.contains("the database could not be reached to read them back"),
            "{text}"
        );
    }

    #[test]
    fn nothing_measured_is_not_a_pass() {
        let text = render(&Timings::default(), &head());
        assert!(text.contains("nothing was measured"), "{text}");
        assert!(text.contains("none recorded"), "{text}");
    }

    #[test]
    fn the_spool_of_the_benchmark_is_read_from_the_measured_runs_on() {
        let dir = std::env::temp_dir().join(format!("ctx-hook-bench-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let _scratch = Scratch(dir.clone());
        let path = dir.join("spool.jsonl");
        let row = |ms: i64, latency: i32| Row {
            uid: format!("u{ms}"),
            ts: chrono::DateTime::from_timestamp_millis(ms).unwrap(),
            session_id: "ctx-hook-bench-1".to_owned(),
            tool: "bash".to_owned(),
            cmd_sha: None,
            cmd_preview: None,
            cwd: None,
            decision: "pass".to_owned(),
            rule: "pass:x".to_owned(),
            shadow: true,
            latency_us: Some(latency),
            policy: "v1:x".to_owned(),
        };
        let mut text = String::new();
        for r in [row(1_000, 1), row(2_000, 2), row(3_000, 3)] {
            text.push_str(&serde_json::to_string(&r).unwrap());
            text.push('\n');
        }
        text.push_str("not a row\n");
        std::fs::write(&path, text).unwrap();
        let rows = spooled(&path, 2_000);
        assert_eq!(
            rows.iter().map(|r| r.latency_us).collect::<Vec<_>>(),
            [Some(2), Some(3)]
        );
        assert!(spooled(&dir.join("missing"), 0).is_empty());
    }
}
