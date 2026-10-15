//! `ctx-hook bench` against a real PostgreSQL: the real binary is run as a
//! hook a few times, timed, and nothing of the benchmark is left behind.

mod scratch;

use std::path::Path;
use std::process::{Command, Output, Stdio};

use chrono::Utc;
use ctx_core::db::sha256_hex;
use ctx_hook::audit::{self, Row};
use regex::Regex;
use scratch::with_schema;

fn bench(home: &Path, tmp: &Path, url: &str, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_ctx-hook"))
        .arg("bench")
        .args(args)
        .env_clear()
        .env("HOME", home)
        .env("TMPDIR", tmp)
        .env("CTX_DATABASE_URL", url)
        .current_dir(home.join("kms"))
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .output()
        .unwrap()
}

fn row(uid: &str, session: &str) -> Row {
    Row {
        uid: uid.to_owned(),
        ts: Utc::now(),
        session_id: session.to_owned(),
        tool: "bash".to_owned(),
        cmd_sha: Some(sha256_hex(b"ls")),
        cmd_preview: Some("ls".to_owned()),
        cwd: Some("/tmp".to_owned()),
        decision: "pass".to_owned(),
        rule: "pass:test".to_owned(),
        shadow: true,
        latency_us: Some(1000),
        policy: "v1:test".to_owned(),
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_benchmark_times_the_hook_and_leaves_nothing_behind() {
    with_schema("bench", |s| async move {
        let dir = tempfile::tempdir().unwrap();
        let root = std::fs::canonicalize(dir.path()).unwrap();
        let (home, tmp) = (root.join("home"), root.join("tmp"));
        std::fs::create_dir_all(home.join("kms/.git")).unwrap();
        std::fs::create_dir_all(&tmp).unwrap();

        // someone's own row must stay, and what an earlier benchmark that did
        // not finish left must go
        let mut conn = s.pool.acquire().await.unwrap();
        for (uid, session) in [("keep", "a-real-session"), ("sweep", "ctx-hook-bench-1")] {
            assert!(audit::insert(&mut conn, &row(uid, session)).await.unwrap());
        }
        drop(conn);

        let out = tokio::task::spawn_blocking({
            let (home, tmp, url) = (home.clone(), tmp.clone(), s.url.clone());
            move || bench(&home, &tmp, &url, &["--runs", "6", "--warmup", "2"])
        })
        .await
        .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        let errors = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(out.status.code(), Some(0), "{text}\n{errors}");
        assert!(errors.is_empty(), "{errors}");
        for want in [
            "6 runs after 2 warm-up runs",
            "process start to exit (the CLI's)",
            "inside the process (its own clock)",
            "p95 under 50 ms:",
        ] {
            assert!(text.contains(want), "missing {want:?} in\n{text}");
        }
        // in a debug build a row may miss the database deadline and be spooled,
        // but none may be lost
        let rows = Regex::new(r"rows: (\d+) in hook_audit, (\d+) spooled").unwrap();
        let found = rows
            .captures(&text)
            .unwrap_or_else(|| panic!("no rows line in\n{text}"));
        let total: usize = found[1].parse::<usize>().unwrap() + found[2].parse::<usize>().unwrap();
        assert_eq!(total, 6, "{text}");

        let left: Vec<String> = sqlx::query_scalar("SELECT session_id FROM hook_audit")
            .fetch_all(&s.pool)
            .await
            .unwrap();
        assert_eq!(left, ["a-real-session"], "{text}");
        let scratch: Vec<_> = std::fs::read_dir(&tmp).unwrap().collect();
        assert!(
            scratch.is_empty(),
            "the benchmark's directory is still there: {scratch:?}"
        );
        assert!(
            !home.join(".local/state/ctx").exists(),
            "the benchmark wrote to the real spool"
        );

        let out = tokio::task::spawn_blocking({
            let (home, tmp, url) = (home.clone(), tmp.clone(), s.url.clone());
            move || bench(&home, &tmp, &url, &["--runs", "0"])
        })
        .await
        .unwrap();
        assert_eq!(out.status.code(), Some(1));
        assert!(String::from_utf8_lossy(&out.stderr).contains("--runs must be at least 1"));
    })
    .await;
}
