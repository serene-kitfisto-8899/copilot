//! `ctx-hook review` against a real PostgreSQL: the query that joins the audit
//! table to what the CLI logged about the same requests (in the shapes the
//! real events have), and the whole trip from the hook's process to the
//! report.

mod scratch;

use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

use chrono::{DateTime, Duration, Utc};
use ctx_core::db::sha256_hex;
use ctx_hook::audit::{self, Row};
use ctx_hook::review::{self, Calls};
use scratch::with_schema;
use serde_json::{Value, json};
use sqlx::PgPool;

const KMS: &str = "/home/u/kms";
const SUB: &str = "/home/u/kms/sub";
const POLICY: &str = "v1:test";

async fn session(pool: &PgPool, id: &str, cwd: Option<&str>) {
    sqlx::query("INSERT INTO sessions (id, cwd) VALUES ($1, $2)")
        .bind(id)
        .bind(cwd)
        .execute(pool)
        .await
        .unwrap();
}

async fn event(pool: &PgPool, session: &str, time: DateTime<Utc>, kind: &str, body: Value) {
    sqlx::query(
        "INSERT INTO events (session_id, event_id, ts, type, src_offset, body)
         VALUES ($1, gen_random_uuid()::text, $2, $3, 0, $4)",
    )
    .bind(session)
    .bind(time)
    .bind(kind)
    .bind(body)
    .execute(pool)
    .await
    .unwrap();
}

/// What the CLI logs about a call of a hook: `hook.start` with the input it
/// gave the hook, and, if the hook came back, `hook.end`.
async fn hook_call(
    pool: &PgPool,
    session: &str,
    id: &str,
    kind: &str,
    input_ts: Value,
    started: DateTime<Utc>,
    ended: Option<(DateTime<Utc>, bool)>,
) {
    let start = json!({
        "input": {
            "cwd": KMS,
            "hookName": kind,
            "toolName": "bash",
            "sessionId": session,
            "timestamp": input_ts,
            "toolInput": {"command": "x"},
            "permissionSuggestions": [],
        },
        "hookType": kind,
        "hookInvocationId": id,
    });
    event(pool, session, started, "hook.start", start).await;
    if let Some((at, success)) = ended {
        let end = json!({"success": success, "hookType": kind, "hookInvocationId": id});
        event(pool, session, at, "hook.end", end).await;
    }
}

/// A question to a person, as the CLI records it. A `path` question has no
/// command text in its prompt.
fn asked(request_id: &str, command: &str, kind: &str, cwd: Option<&str>) -> Value {
    let prompt = if kind == "commands" {
        json!({"kind": kind, "fullCommandText": command})
    } else {
        json!({"kind": kind, "paths": ["/etc"]})
    };
    let mut request = json!({"kind": "shell", "fullCommandText": command, "commands": []});
    if let Some(cwd) = cwd {
        request["commandSegments"] =
            json!([{"identifier": "x", "fullCommandText": command, "workingDirectory": cwd}]);
    }
    json!({"requestId": request_id, "promptRequest": prompt, "permissionRequest": request})
}

fn answered(request_id: &str, result: &str) -> Value {
    json!({"requestId": request_id, "result": {"kind": result}})
}

fn row(
    uid: &str,
    session: &str,
    ts: DateTime<Utc>,
    tool: &str,
    command: Option<&str>,
    cwd: &str,
    rule: &str,
) -> Row {
    Row {
        uid: uid.to_owned(),
        ts,
        session_id: session.to_owned(),
        tool: tool.to_owned(),
        cmd_sha: command.map(|c| sha256_hex(c.as_bytes())),
        cmd_preview: command.map(str::to_owned),
        cwd: Some(cwd.to_owned()),
        decision: if rule.starts_with("allow") {
            "allow"
        } else {
            "pass"
        }
        .to_owned(),
        rule: rule.to_owned(),
        shadow: true,
        latency_us: Some(3000),
        policy: POLICY.to_owned(),
    }
}

async fn log(pool: &PgPool, row: Row) {
    let mut conn = pool.acquire().await.unwrap();
    assert!(audit::insert(&mut conn, &row).await.unwrap());
}

fn close(value: Option<f64>, want: f64) -> bool {
    value.is_some_and(|v| (v - want).abs() < 1e-6)
}

/// Every oddity the join has to get right, in one history. Sessions `s1` (the
/// one most things happen in), `s2` (a question about a path, a session
/// directory only `sessions` knows) and `s3` (not ingested at all).
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_audit_rows_are_joined_to_what_the_cli_logged_about_them() {
    with_schema("review_load", |s| async move {
        let pool = &s.pool;
        let t0 =
            DateTime::from_timestamp_millis((Utc::now() - Duration::days(2)).timestamp_millis())
                .unwrap();
        let at = |ms: i64| t0 + Duration::milliseconds(ms);
        let stamp = |ms: i64| json!(at(ms).timestamp_millis());
        let (s1, s2, s3, bench) = (
            "s1-00000001",
            "s2-00000002",
            "s3-00000003",
            "ctx-hook-bench-777",
        );
        let call = "permissionRequest";

        session(pool, s1, Some("/stale/cwd")).await;
        session(pool, s2, Some("/home/u/other")).await;
        event(
            pool,
            s1,
            at(-60_000),
            "session.start",
            json!({"context": {"cwd": KMS}}),
        )
        .await;
        event(
            pool,
            s1,
            at(100_000),
            "session.context_changed",
            json!({"cwd": SUB}),
        )
        .await;

        // a: asked, answered twice (the first answer is the one that counts)
        log(
            pool,
            row("a", s1, at(0), "bash", Some("ls -la"), KMS, "allow:ls"),
        )
        .await;
        hook_call(
            pool,
            s1,
            "inv-a",
            call,
            stamp(0),
            at(5),
            Some((at(14), true)),
        )
        .await;
        event(
            pool,
            s1,
            at(30),
            "permission.requested",
            asked("r1", "ls -la", "commands", Some(KMS)),
        )
        .await;
        event(
            pool,
            s1,
            at(4_030),
            "permission.completed",
            answered("r1", "approved"),
        )
        .await;
        event(
            pool,
            s1,
            at(10_030),
            "permission.completed",
            answered("r1", "denied-interactively-by-user"),
        )
        .await;

        // g: another session, a question about a path, no answer, and the
        // session directory only the session row has
        log(
            pool,
            row(
                "g",
                s2,
                at(10_000),
                "bash",
                Some("ls"),
                "/home/u/other",
                "allow:ls",
            ),
        )
        .await;
        hook_call(
            pool,
            s2,
            "inv-g",
            call,
            stamp(10_000),
            at(10_004),
            Some((at(10_010), true)),
        )
        .await;
        event(
            pool,
            s2,
            at(10_030),
            "permission.requested",
            asked("r6", "ls", "path", None),
        )
        .await;

        // b: refused by a person; the CLI never logged the hook coming back
        log(
            pool,
            row(
                "b",
                s1,
                at(60_000),
                "bash",
                Some("rm -rf x"),
                KMS,
                "pass:cmd-not-allowed",
            ),
        )
        .await;
        hook_call(pool, s1, "inv-b", call, stamp(60_000), at(60_004), None).await;
        event(
            pool,
            s1,
            at(60_030),
            "permission.requested",
            asked("r2", "rm -rf x", "commands", Some(KMS)),
        )
        .await;
        event(
            pool,
            s1,
            at(72_030),
            "permission.completed",
            answered("r2", "denied-interactively-by-user"),
        )
        .await;

        // c: nobody was asked (the question that follows is another command's),
        // and the session has moved by now
        log(
            pool,
            row(
                "c",
                s1,
                at(120_000),
                "bash",
                Some("cat README.md"),
                SUB,
                "allow:cat",
            ),
        )
        .await;
        hook_call(
            pool,
            s1,
            "inv-c",
            call,
            stamp(120_000),
            at(120_003),
            Some((at(120_011), true)),
        )
        .await;
        event(
            pool,
            s1,
            at(120_100),
            "permission.requested",
            asked("r3", "cat other", "commands", Some(SUB)),
        )
        .await;

        // d1 and d2: the same command twice within seconds, asked about once
        log(
            pool,
            row(
                "d1",
                s1,
                at(180_000),
                "bash",
                Some("ls -la"),
                SUB,
                "allow:ls",
            ),
        )
        .await;
        log(
            pool,
            row(
                "d2",
                s1,
                at(183_000),
                "bash",
                Some("ls -la"),
                SUB,
                "allow:ls",
            ),
        )
        .await;
        hook_call(
            pool,
            s1,
            "inv-d1",
            call,
            stamp(180_000),
            at(180_004),
            Some((at(180_010), true)),
        )
        .await;
        hook_call(
            pool,
            s1,
            "inv-d2",
            call,
            stamp(183_000),
            at(183_004),
            Some((at(183_010), true)),
        )
        .await;
        event(
            pool,
            s1,
            at(183_030),
            "permission.requested",
            asked("r4", "ls -la", "commands", Some(SUB)),
        )
        .await;
        event(
            pool,
            s1,
            at(184_030),
            "permission.completed",
            answered("r4", "approved-for-location"),
        )
        .await;

        // e: the question comes eleven seconds later, too late to be this
        // call's, and the CLI's record of the input is a millisecond off
        log(
            pool,
            row(
                "e",
                s1,
                at(240_000),
                "bash",
                Some("git status"),
                SUB,
                "allow:git-status",
            ),
        )
        .await;
        hook_call(
            pool,
            s1,
            "inv-e",
            call,
            stamp(240_001),
            at(240_004),
            Some((at(240_010), true)),
        )
        .await;
        event(
            pool,
            s1,
            at(251_000),
            "permission.requested",
            asked("r5", "git status", "commands", Some(SUB)),
        )
        .await;

        // x: a call that left no row, because the hook timed out
        hook_call(
            pool,
            s1,
            "inv-x",
            call,
            stamp(270_000),
            at(270_004),
            Some((at(275_004), false)),
        )
        .await;

        // f: not a shell command
        log(
            pool,
            row("f", s1, at(300_000), "view", None, SUB, "pass:tool"),
        )
        .await;
        hook_call(
            pool,
            s1,
            "inv-f",
            call,
            stamp(300_000),
            at(300_004),
            Some((at(300_009), true)),
        )
        .await;

        // i: a session that is not in the table (yet)
        log(
            pool,
            row(
                "i",
                s3,
                at(330_000),
                "bash",
                Some("pwd"),
                "/tmp",
                "pass:cmd-not-allowed",
            ),
        )
        .await;

        // h: a benchmark's row, which is nobody's business
        log(
            pool,
            row("h", bench, at(5_000), "bash", Some("ls"), KMS, "allow:ls"),
        )
        .await;

        // calls that are not to be counted, or must not break the query: another
        // kind of hook whose input has a timestamp that is not a number, a call
        // before the log starts, and one too recent for the ingester to have it all
        hook_call(
            pool,
            s1,
            "inv-pre",
            "preToolUse",
            json!("2026-10-01T08:00:00Z"),
            at(1_000),
            Some((at(1_002), true)),
        )
        .await;
        hook_call(
            pool,
            s1,
            "inv-odd",
            call,
            json!({"unexpected": true}),
            at(1_500),
            Some((at(1_502), true)),
        )
        .await;
        hook_call(
            pool,
            s1,
            "inv-old",
            call,
            stamp(-300_000),
            at(-300_000),
            Some((at(-299_990), true)),
        )
        .await;
        let now = Utc::now();
        hook_call(
            pool,
            s1,
            "inv-new",
            call,
            json!(now.timestamp_millis()),
            now - Duration::seconds(30),
            None,
        )
        .await;

        let rows = review::load(pool, None).await.unwrap();
        let order: Vec<_> = rows
            .iter()
            .map(|r| (r.session_id.as_str(), r.command.as_deref().unwrap_or("-")))
            .collect();
        assert_eq!(
            order,
            [
                (s1, "ls -la"),
                (s2, "ls"),
                (s1, "rm -rf x"),
                (s1, "cat README.md"),
                (s1, "ls -la"),
                (s1, "ls -la"),
                (s1, "git status"),
                (s1, "-"),
                (s3, "pwd"),
            ]
        );
        let [a, g, b, c, d1, d2, e, f, i] = &rows[..] else {
            panic!("{} rows", rows.len())
        };

        assert!(a.allowed && a.shadow, "{a:?}");
        assert_eq!(
            (a.rule.as_str(), a.policy.as_str(), a.latency_us),
            ("allow:ls", POLICY, Some(3000))
        );
        assert_eq!(a.cwd.as_deref(), Some(KMS));
        assert!(close(a.wall_ms, 9.0), "{:?}", a.wall_ms);
        assert_eq!(a.session_cwd.as_deref(), Some(KMS));
        let q = a.question.as_ref().expect("a was asked about");
        assert_eq!((q.request_id.as_str(), q.kind.as_str()), ("r1", "commands"));
        assert_eq!(q.cli_cwd.as_deref(), Some(KMS));
        assert_eq!(q.result.as_deref(), Some("approved"));
        assert!(close(q.waited_s, 4.0), "{:?}", q.waited_s);

        assert_eq!(g.session_cwd.as_deref(), Some("/home/u/other"));
        assert!(close(g.wall_ms, 6.0), "{:?}", g.wall_ms);
        let q = g.question.as_ref().expect("g was asked about");
        assert_eq!((q.request_id.as_str(), q.kind.as_str()), ("r6", "path"));
        assert_eq!(
            (q.cli_cwd.as_deref(), q.result.as_deref(), q.waited_s),
            (None, None, None)
        );

        assert!(!b.allowed);
        assert_eq!(b.wall_ms, None);
        assert_eq!(b.session_cwd.as_deref(), Some(KMS));
        let q = b.question.as_ref().expect("b was asked about");
        assert_eq!(q.result.as_deref(), Some("denied-interactively-by-user"));
        assert!(close(q.waited_s, 12.0), "{:?}", q.waited_s);

        assert!(close(c.wall_ms, 8.0), "{:?}", c.wall_ms);
        assert_eq!(c.question, None);
        assert_eq!(c.session_cwd.as_deref(), Some(SUB));

        for d in [d1, d2] {
            let q = d.question.as_ref().expect("both calls see the question");
            assert_eq!(q.request_id, "r4");
            assert_eq!(q.result.as_deref(), Some("approved-for-location"));
            assert!(close(q.waited_s, 1.0), "{:?}", q.waited_s);
            assert!(close(d.wall_ms, 6.0), "{:?}", d.wall_ms);
        }

        assert_eq!(e.question, None);
        assert_eq!(e.wall_ms, None);

        assert_eq!(
            (f.tool.as_str(), f.command.as_deref(), f.question.as_ref()),
            ("view", None, None)
        );
        assert!(close(f.wall_ms, 5.0), "{:?}", f.wall_ms);

        assert_eq!(
            (i.session_cwd.as_deref(), i.question.as_ref(), i.wall_ms),
            (None, None, None)
        );

        // from a later day on only
        let later = review::load(pool, Some(at(100_000))).await.unwrap();
        assert_eq!(later.len(), 6);
        assert!(later.iter().all(|r| r.ts >= at(100_000)));

        let calls = review::calls(pool, at(-60_000)).await.unwrap();
        assert_eq!(
            calls,
            Calls {
                logged: 10,
                with_row: 7,
                failed: 1
            }
        );
        let none = review::calls(pool, now).await.unwrap();
        assert_eq!(none, Calls::default());

        // and what the report makes of it
        let r = review::analyze(&rows, calls, POLICY, 0);
        assert_eq!((r.rows, r.shadow, r.allowed, r.shared), (9, 9, 6, 1));
        let allow = &r.shadow_allow;
        assert_eq!(
            (
                allow.rows,
                allow.asked(),
                allow.approved,
                allow.unanswered,
                allow.not_asked
            ),
            (6, 3, 2, 1, 3)
        );
        let pass = &r.shadow_pass;
        assert_eq!(
            (pass.rows, pass.asked(), pass.refused, pass.not_asked),
            (3, 1, 1, 2)
        );
        assert!(
            r.refused.is_empty(),
            "a person refusing what the hook passed is no refusal of an allow"
        );
        assert_eq!(r.tools, [("view".to_owned(), 1)]);
    })
    .await;
}

fn hook_process(home: &Path, url: &str, args: &[&str], input: &[u8]) -> Output {
    let mut child = Command::new(env!("CARGO_BIN_EXE_ctx-hook"))
        .args(args)
        .env_clear()
        .env("HOME", home)
        .env("CTX_DATABASE_URL", url)
        .current_dir(home.join("kms"))
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(input).unwrap();
    drop(stdin);
    child.wait_with_output().unwrap()
}

/// The real binary, twice, with no database to write to: both rows are
/// spooled. Then `review`, which imports the spool and reads the rows with the
/// events the CLI would have logged.
#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_hook_spools_and_review_imports_and_reads_the_log() {
    with_schema("review_e2e", |s| async move {
        let dir = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(dir.path()).unwrap().join("home");
        std::fs::create_dir_all(home.join("kms/.git")).unwrap();
        std::fs::create_dir_all(home.join("kms/src")).unwrap();
        let nowhere = "postgres:///nope?host=/nonexistent/dir&user=x";
        let session_id = "e2e-review-session";
        let pool = &s.pool;
        session(pool, session_id, None).await;

        let now = Utc::now();
        let t1 = DateTime::from_timestamp_millis((now - Duration::minutes(5)).timestamp_millis()).unwrap();
        let t2 = t1 + Duration::minutes(1);
        let payload = |ts: DateTime<Utc>, command: &str| {
            json!({
                "hookName": "permissionRequest",
                "sessionId": session_id,
                "timestamp": ts.timestamp_millis(),
                "cwd": home.join("kms"),
                "toolName": "bash",
                "toolInput": {"command": command},
                "permissionSuggestions": [],
            })
            .to_string()
        };

        for (ts, command) in [(t1, "ls src"), (t2, "rm -rf src")] {
            let out = tokio::task::spawn_blocking({
                let (home, input) = (home.clone(), payload(ts, command));
                move || hook_process(&home, nowhere, &["permission"], input.as_bytes())
            })
            .await
            .unwrap();
            assert_eq!(out.status.code(), Some(0), "{out:?}");
            assert!(out.stdout.is_empty(), "shadow mode says nothing: {out:?}");
        }
        let in_table: i64 = sqlx::query_scalar("SELECT count(*) FROM hook_audit")
            .fetch_one(pool)
            .await
            .unwrap();
        assert_eq!(in_table, 0, "the database was out of reach");

        // what the CLI logged: the first request was asked about and approved
        // after three seconds, the second was refused
        let call = "permissionRequest";
        hook_call(pool, session_id, "inv-1", call, json!(t1.timestamp_millis()), t1 + Duration::milliseconds(5), Some((t1 + Duration::milliseconds(12), true))).await;
        hook_call(pool, session_id, "inv-2", call, json!(t2.timestamp_millis()), t2 + Duration::milliseconds(5), Some((t2 + Duration::milliseconds(30), true))).await;
        event(pool, session_id, t1 + Duration::milliseconds(40), "permission.requested", asked("q1", "ls src", "commands", None)).await;
        event(pool, session_id, t1 + Duration::milliseconds(3_040), "permission.completed", answered("q1", "approved")).await;
        event(pool, session_id, t2 + Duration::milliseconds(40), "permission.requested", asked("q2", "rm -rf src", "commands", None)).await;
        event(pool, session_id, t2 + Duration::milliseconds(9_040), "permission.completed", answered("q2", "denied-interactively-by-user")).await;

        let out = tokio::task::spawn_blocking({
            let (home, url) = (home.clone(), s.url.clone());
            move || hook_process(&home, &url, &["review", "--top", "5"], b"")
        })
        .await
        .unwrap();
        let text = String::from_utf8_lossy(&out.stdout).into_owned();
        assert_eq!(out.status.code(), Some(0), "{text}\n{}", String::from_utf8_lossy(&out.stderr));

        let stored: Vec<(String, String, bool)> =
            sqlx::query_as("SELECT cmd_preview, rule, shadow FROM hook_audit ORDER BY ts")
                .fetch_all(pool)
                .await
                .unwrap();
        assert_eq!(
            stored,
            [
                ("ls src".to_owned(), "allow:ls".to_owned(), true),
                ("rm -rf src".to_owned(), "pass:cmd-not-allowed:rm".to_owned(), true),
            ],
            "{text}"
        );

        for want in [
            "mode now: shadow",
            "imported 2 new of 2 spooled rows from 1 file(s); 0 lines rejected",
            "rows        2 from",
            "the hook would allow 1 of 2 (50.0%)",
            "of the 2 questions put to a person in shadow mode, the policy would have answered 1 (50.0%)",
            "the CLI logged 2 calls since the first row; 2 have a row; 0 did not succeed",
            "hook.start to hook.end (the CLI's)",
            "ok    no one refused an allow",
            "ok    p95 under 50 ms",
            "wait  three days of log",
            "ready to enable: not yet: waiting for three days of log",
        ] {
            assert!(text.contains(want), "missing {want:?} in\n{text}");
        }
        assert!(!text.contains("REFUSED"), "{text}");

        // the spool was emptied, so a second review has nothing to import
        let again = tokio::task::spawn_blocking({
            let (home, url) = (home.clone(), s.url.clone());
            move || hook_process(&home, &url, &["review"], b"")
        })
        .await
        .unwrap();
        let again = String::from_utf8_lossy(&again.stdout).into_owned();
        assert!(again.contains("nothing was waiting"), "{again}");
        assert!(again.contains("rows        2 from"), "{again}");
    })
    .await;
}
