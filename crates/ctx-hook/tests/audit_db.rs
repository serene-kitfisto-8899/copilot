//! The audit trail against a real PostgreSQL: the table the migration makes,
//! the insert, the spool the hook falls back on, and its import.

mod scratch;

use std::path::Path;

use chrono::{DateTime, TimeZone, Utc};
use ctx_core::db;
use ctx_hook::audit::{self, Drained, Recorded, Row};
use scratch::{Scratch, in_schema, with_empty_schema, with_schema};
use sqlx::Row as _;

fn row(uid: &str, rule: &str) -> Row {
    Row {
        uid: uid.to_owned(),
        ts: Utc.with_ymd_and_hms(2026, 10, 1, 8, 0, 0).unwrap(),
        session_id: "s-db".to_owned(),
        tool: "bash".to_owned(),
        cmd_sha: Some("a".repeat(64)),
        cmd_preview: Some("ls src".to_owned()),
        cwd: Some("/home/u/kms".to_owned()),
        decision: "allow".to_owned(),
        rule: rule.to_owned(),
        shadow: true,
        latency_us: Some(1234),
        policy: "v1:abcdef12".to_owned(),
    }
}

async fn uids(s: &Scratch) -> Vec<String> {
    sqlx::query_scalar("SELECT uid FROM hook_audit ORDER BY id")
        .fetch_all(&s.pool)
        .await
        .unwrap()
}

async fn insert(s: &Scratch, row: &Row) -> Result<bool, sqlx::Error> {
    let mut conn = s.pool.acquire().await.unwrap();
    audit::insert(&mut conn, row).await
}

async fn drain(s: &Scratch, spool: &Path) -> anyhow::Result<Drained> {
    let mut conn = s.pool.acquire().await.unwrap();
    audit::drain(&mut conn, spool).await
}

/// `record` has a runtime of its own, as it has in the hook.
async fn record(row: &Row, url: &str, spool: &Path) -> Recorded {
    let (row, url, spool) = (row.clone(), url.to_owned(), spool.to_owned());
    tokio::task::spawn_blocking(move || audit::record(&row, &url, &spool))
        .await
        .unwrap()
}

fn names(dir: &Path) -> Vec<String> {
    let mut names: Vec<String> = std::fs::read_dir(dir)
        .map(|entries| {
            entries
                .flatten()
                .map(|e| e.file_name().to_string_lossy().into_owned())
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    names
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_row_is_stored_column_for_column() {
    with_schema("roundtrip", |s| async move {
        let want = row("u-1", "allow:ls");
        assert!(insert(&s, &want).await.unwrap());
        let got = sqlx::query("SELECT * FROM hook_audit")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(got.get::<String, _>("uid"), want.uid);
        assert_eq!(got.get::<DateTime<Utc>, _>("ts"), want.ts);
        assert_eq!(got.get::<String, _>("session_id"), want.session_id);
        assert_eq!(got.get::<String, _>("tool"), want.tool);
        assert_eq!(got.get::<Option<String>, _>("cmd_sha"), want.cmd_sha);
        assert_eq!(
            got.get::<Option<String>, _>("cmd_preview"),
            want.cmd_preview
        );
        assert_eq!(got.get::<Option<String>, _>("cwd"), want.cwd);
        assert_eq!(got.get::<String, _>("decision"), want.decision);
        assert_eq!(got.get::<String, _>("rule"), want.rule);
        assert_eq!(got.get::<bool, _>("shadow"), want.shadow);
        assert_eq!(got.get::<Option<i32>, _>("latency_us"), want.latency_us);
        assert_eq!(got.get::<String, _>("policy"), want.policy);
        let age: f64 = sqlx::query_scalar(
            "SELECT extract(epoch FROM now() - inserted_at)::float8 FROM hook_audit",
        )
        .fetch_one(&s.pool)
        .await
        .unwrap();
        assert!(
            (0.0..60.0).contains(&age),
            "inserted_at is filled in: {age}"
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn what_the_hook_could_not_know_is_null() {
    with_schema("nulls", |s| async move {
        let mut r = row("u-null", "pass:payload:not-a-json-object");
        r.cmd_sha = None;
        r.cmd_preview = None;
        r.cwd = None;
        r.latency_us = None;
        r.decision = "pass".to_owned();
        assert!(insert(&s, &r).await.unwrap());
        let got = sqlx::query("SELECT * FROM hook_audit")
            .fetch_one(&s.pool)
            .await
            .unwrap();
        assert_eq!(got.get::<Option<String>, _>("cmd_sha"), None);
        assert_eq!(got.get::<Option<String>, _>("cmd_preview"), None);
        assert_eq!(got.get::<Option<String>, _>("cwd"), None);
        assert_eq!(got.get::<Option<i32>, _>("latency_us"), None);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_uid_is_stored_once() {
    with_schema("uid", |s| async move {
        assert!(insert(&s, &row("u-1", "allow:ls")).await.unwrap());
        assert!(!insert(&s, &row("u-1", "allow:ls")).await.unwrap());
        assert!(insert(&s, &row("u-2", "allow:ls")).await.unwrap());
        assert_eq!(uids(&s).await, ["u-1", "u-2"]);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_table_has_no_room_for_a_deny() {
    with_schema("check", |s| async move {
        for decision in ["deny", "maybe", "ALLOW", ""] {
            let mut r = row("u-x", "allow:ls");
            r.decision = decision.to_owned();
            let error = insert(&s, &r).await.unwrap_err();
            assert_eq!(
                error.as_database_error().and_then(|e| e.code()).as_deref(),
                Some("23514"),
                "{decision:?}: {error}"
            );
        }
        assert!(uids(&s).await.is_empty());
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn record_writes_through_the_url_it_is_given() {
    with_schema("record", |s| async move {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("state/hook-spool.jsonl");
        let r = row("u-rec", "allow:ls");
        assert_eq!(record(&r, &s.url, &spool).await, Recorded::Db);
        assert_eq!(uids(&s).await, ["u-rec"]);
        assert!(
            !spool.exists(),
            "a row that is in the table is not also spooled"
        );
        // the same row again is not a second row and not an error
        assert_eq!(record(&r, &s.url, &spool).await, Recorded::Db);
        assert_eq!(uids(&s).await, ["u-rec"]);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn record_spools_the_row_the_table_cannot_take() {
    with_empty_schema("record_spool", |s| async move {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("state/hook-spool.jsonl");
        let r = row("u-spool", "allow:ls");
        let Recorded::Spool(why) = record(&r, &s.url, &spool).await else {
            panic!("expected the spool");
        };
        assert!(
            why.starts_with("insert:") && why.contains("hook_audit"),
            "{why}"
        );
        let text = std::fs::read_to_string(&spool).unwrap();
        assert_eq!(text.lines().count(), 1);
        assert_eq!(serde_json::from_str::<Row>(text.trim()).unwrap(), r);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drain_imports_what_was_spooled_once() {
    with_schema("drain", |s| async move {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("state/hook-spool.jsonl");
        for i in 0..3 {
            audit::append_spool(&spool, &row(&format!("u-{i}"), "allow:ls")).unwrap();
        }
        // a row that got to the table some other way
        insert(&s, &row("u-1", "allow:ls")).await.unwrap();

        let got = drain(&s, &spool).await.unwrap();
        assert_eq!(
            got,
            Drained {
                files: 1,
                rows: 3,
                inserted: 2,
                rejected: 0
            }
        );
        assert_eq!(uids(&s).await, ["u-1", "u-0", "u-2"]);
        assert!(!spool.exists());
        assert!(names(spool.parent().unwrap()).is_empty());

        assert_eq!(drain(&s, &spool).await.unwrap(), Drained::default());
        assert_eq!(uids(&s).await.len(), 3);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drain_keeps_aside_what_cannot_be_a_row() {
    with_schema("poison", |s| async move {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("state/hook-spool.jsonl");
        audit::append_spool(&spool, &row("u-ok", "allow:ls")).unwrap();
        let mut refused = row("u-no", "allow:ls");
        refused.decision = "deny".to_owned();
        audit::append_spool(&spool, &refused).unwrap();
        {
            use std::io::Write;
            let mut file = std::fs::OpenOptions::new()
                .append(true)
                .open(&spool)
                .unwrap();
            writeln!(file, "this is not json").unwrap();
            writeln!(file).unwrap();
        }
        audit::append_spool(&spool, &row("u-ok2", "allow:cat")).unwrap();

        let got = drain(&s, &spool).await.unwrap();
        assert_eq!(
            got,
            Drained {
                files: 1,
                rows: 2,
                inserted: 2,
                rejected: 2
            }
        );
        assert_eq!(uids(&s).await, ["u-ok", "u-ok2"]);
        let rejected =
            std::fs::read_to_string(dir.path().join("state/hook-spool.jsonl.rejected")).unwrap();
        assert_eq!(rejected.lines().count(), 2);
        assert!(rejected.contains("u-no") && rejected.contains("this is not json"));
        assert_eq!(
            names(spool.parent().unwrap()),
            ["hook-spool.jsonl.rejected"]
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn drain_gives_up_no_row_while_the_table_is_missing() {
    with_empty_schema("nomigration", |s| async move {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("state/hook-spool.jsonl");
        audit::append_spool(&spool, &row("u-1", "allow:ls")).unwrap();
        audit::append_spool(&spool, &row("u-2", "allow:ls")).unwrap();

        let error = drain(&s, &spool).await.unwrap_err();
        assert!(format!("{error:#}").contains("hook_audit"), "{error:#}");
        // nothing was judged unfit: the rows wait in the file set aside
        let left = names(spool.parent().unwrap());
        assert_eq!(left.len(), 1, "{left:?}");
        assert!(left[0].ends_with(".draining"), "{left:?}");

        // the migration arrives, and the next drain takes the file up
        db::migrate(&s.pool).await.unwrap();
        let got = drain(&s, &spool).await.unwrap();
        assert_eq!(
            got,
            Drained {
                files: 1,
                rows: 2,
                inserted: 2,
                rejected: 0
            }
        );
        assert_eq!(uids(&s).await.len(), 2);
        assert!(names(spool.parent().unwrap()).is_empty());
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn two_drains_at_once_leave_every_row_there_once() {
    with_schema("twodrains", |s| async move {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("state/hook-spool.jsonl");
        for i in 0..40 {
            audit::append_spool(&spool, &row(&format!("u-{i:02}"), "allow:ls")).unwrap();
        }
        let (a, b) = tokio::join!(drain(&s, &spool), drain(&s, &spool));
        let (a, b) = (a.unwrap(), b.unwrap());
        assert_eq!(a.inserted + b.inserted, 40, "{a:?} {b:?}");
        assert_eq!(a.rejected + b.rejected, 0);
        assert_eq!(uids(&s).await.len(), 40);
        assert!(names(spool.parent().unwrap()).is_empty());
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rows_appended_while_draining_are_not_lost() {
    with_schema("late", |s| async move {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("state/hook-spool.jsonl");
        audit::append_spool(&spool, &row("u-early", "allow:ls")).unwrap();
        let writer = {
            let spool = spool.clone();
            tokio::spawn(async move {
                // lands in the fresh spool, after the old one was moved aside
                tokio::time::sleep(std::time::Duration::from_millis(30)).await;
                audit::append_spool(&spool, &row("u-late", "allow:ls")).unwrap();
            })
        };
        let first = drain(&s, &spool).await.unwrap();
        writer.await.unwrap();
        let second = drain(&s, &spool).await.unwrap();
        assert_eq!(first.inserted + second.inserted, 2, "{first:?} {second:?}");
        let mut got = uids(&s).await;
        got.sort();
        assert_eq!(got, ["u-early", "u-late"]);
    })
    .await;
}

#[test]
fn in_schema_extends_a_url_with_or_without_a_query() {
    assert_eq!(
        in_schema("postgres:///db", "x"),
        "postgres:///db?options=-c%20search_path%3Dx"
    );
    assert_eq!(
        in_schema("postgres:///db?host=/run", "x"),
        "postgres:///db?host=/run&options=-c%20search_path%3Dx"
    );
}
