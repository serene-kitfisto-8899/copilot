//! `watch::run` against a scratch directory: it follows appends, new
//! sessions, renamed workspaces and the session store, stays quiet when
//! nothing happens, and its periodic rescan catches what no notification
//! announced.

mod common;

use std::fs::{self, OpenOptions};
use std::io::Write;
use std::time::Duration;

use common::*;

/// Waits until `sql`, a single `count(*)`, returns `want`.
async fn reaches(env: &Env, what: &str, sql: &'static str, want: i64) {
    eventually(
        what,
        PATIENCE,
        || async move { env.count(sql).await == want },
    )
    .await;
}

async fn name_of(env: &Env, id: &'static str) -> Option<String> {
    sqlx::query_scalar("SELECT name FROM sessions WHERE id = $1")
        .bind(id)
        .fetch_optional(&env.pool)
        .await
        .unwrap()
        .flatten()
}

fn call(session: &'static str, turn: i64, at: &'static str) -> Usage<'static> {
    Usage {
        session,
        turn,
        agent: None,
        model: "claude-sonnet-5.5",
        initiator: "user",
        at,
        fresh: 20,
        cache_read: 30_000,
        cache_write: 100,
        output: 150,
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn follows_appends_new_sessions_renamed_workspaces_and_the_store() {
    with_env("tail_follows", |env| async move {
        let store = populate(&env);
        let tail = env.start_tail(quick_tail());

        // The catch-up at startup reads everything that is already there.
        reaches(
            &env,
            "the catch-up to read 27 events",
            "SELECT count(*) FROM events",
            27,
        )
        .await;
        reaches(
            &env,
            "the catch-up to mirror the store",
            "SELECT count(*) FROM usage",
            5,
        )
        .await;
        assert_eq!(name_of(&env, "alpha").await.as_deref(), Some("Alpha task"));

        // A session that is being written to.
        env.append_events("alpha", &turn("alpha", 3)[..2]);
        reaches(
            &env,
            "two appended events",
            "SELECT count(*) FROM events",
            29,
        )
        .await;

        // A session that did not exist when the tail started: directory,
        // events and workspace arrive one after the other.
        env.add_session("epsilon", &story("epsilon", 1));
        reaches(
            &env,
            "the events of a new session",
            "SELECT count(*) FROM events",
            35,
        )
        .await;
        env.write_workspace("epsilon", "Epsilon task", None);
        eventually("the title of the new session", PATIENCE, || async {
            name_of(&env, "epsilon").await.as_deref() == Some("Epsilon task")
        })
        .await;
        env.append_events("epsilon", &turn("epsilon", 1));
        reaches(
            &env,
            "the events appended to it",
            "SELECT count(*) FROM events",
            40,
        )
        .await;

        // The user renames a session.
        env.write_workspace("alpha", "Alpha, renamed", Some("Alpha does a thing"));
        eventually("the new title", PATIENCE, || async {
            name_of(&env, "alpha").await.as_deref() == Some("Alpha, renamed")
        })
        .await;

        // The CLI writes to its SQLite store.
        store.turn("alpha", 3, "a late question", None);
        store.usage(&call("alpha", 3, "2026-10-01T08:41:00.000Z"));
        reaches(
            &env,
            "the new turn",
            "SELECT count(*) FROM turns WHERE session_id = 'alpha'",
            4,
        )
        .await;
        reaches(&env, "the new call", "SELECT count(*) FROM usage", 6).await;

        let summary = tail.stop().await;
        assert_eq!(summary.failures, 0, "{summary:?}");
        assert_eq!(summary.full_passes, 1, "no rescan was due: {summary:?}");
        assert!(summary.flushes >= 1, "{summary:?}");
        assert!(summary.store_rows >= 7, "{summary:?}");
        // Whatever the tail wrote is what a full read of the sources gives: no
        // row twice, none missing.
        let before = ctx_core::db::table_counts(&env.pool).await.unwrap();
        let rerun = env.ingester.run_all(false, 2).await.unwrap();
        assert!(rerun.failed.is_empty(), "{:?}", rerun.failed);
        assert_eq!(
            (
                rerun.totals.lines,
                rerun.totals.events_changed,
                rerun.store.changed()
            ),
            (0, 0, 0)
        );
        assert_eq!(ctx_core::db::table_counts(&env.pool).await.unwrap(), before);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_idle_tail_does_not_feed_on_itself() {
    with_env("tail_idle", |env| async move {
        let _store = populate(&env);
        let tail = env.start_tail(quick_tail());
        reaches(
            &env,
            "the catch-up to read 27 events",
            "SELECT count(*) FROM events",
            27,
        )
        .await;
        reaches(
            &env,
            "the catch-up to mirror the store",
            "SELECT count(*) FROM usage",
            5,
        )
        .await;

        // Reading the files and the store opens, reads and closes them. None
        // of that may count as a change, or the tail would run in a circle.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        let summary = tail.stop().await;
        assert_eq!(
            summary.flushes, 0,
            "an idle tail woke up on its own: {summary:?}"
        );
        assert_eq!(summary.full_passes, 1, "{summary:?}");
        assert_eq!(summary.failures, 0, "{summary:?}");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_store_that_appears_after_the_tail_started_is_mirrored() {
    with_env("tail_store_later", |env| async move {
        env.add_session("alpha", &story("alpha", 1));
        let tail = env.start_tail(quick_tail());
        reaches(
            &env,
            "the catch-up to read 6 events",
            "SELECT count(*) FROM events",
            6,
        )
        .await;
        assert_eq!(env.count("SELECT count(*) FROM turns").await, 0);

        let store = env.store();
        store.session("alpha", "Alpha, as the store sees it");
        store.turn("alpha", 0, "hello", Some("hi"));
        store.usage(&call("alpha", 0, "2026-10-01T08:00:10.000Z"));
        reaches(&env, "the turn", "SELECT count(*) FROM turns", 1).await;
        reaches(&env, "the call", "SELECT count(*) FROM usage", 1).await;

        let summary = tail.stop().await;
        assert_eq!(summary.failures, 0, "{summary:?}");
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_rescan_catches_what_no_notification_announced() {
    with_env("tail_rescan", |env| async move {
        // events.jsonl has two names. The tail watches the directory of one;
        // a write through the other raises no event there.
        let hidden = env.copilot().join("hidden");
        fs::create_dir_all(&hidden).unwrap();
        let elsewhere = hidden.join("alpha-events.jsonl");
        fs::write(&elsewhere, jsonl(&story("alpha", 1))).unwrap();
        fs::create_dir_all(env.session_dir("alpha")).unwrap();
        fs::hard_link(&elsewhere, env.events_file("alpha")).unwrap();

        let tail = env.start_tail(ctx_core::watch::TailOptions {
            rescan: Duration::from_secs(6),
            ..quick_tail()
        });
        reaches(
            &env,
            "the catch-up to read 6 events",
            "SELECT count(*) FROM events",
            6,
        )
        .await;

        let mut file = OpenOptions::new().append(true).open(&elsewhere).unwrap();
        file.write_all(jsonl(&turn("alpha", 1)).as_bytes()).unwrap();
        drop(file);
        assert_eq!(
            fs::metadata(env.events_file("alpha")).unwrap().len(),
            fs::metadata(&elsewhere).unwrap().len(),
            "both names are the same file"
        );

        // Long enough for any notification, far shorter than the rescan.
        tokio::time::sleep(Duration::from_millis(1500)).await;
        assert_eq!(
            env.count("SELECT count(*) FROM events").await,
            6,
            "a notification did arrive"
        );

        reaches(
            &env,
            "the rescan to find the new events",
            "SELECT count(*) FROM events",
            11,
        )
        .await;
        let summary = tail.stop().await;
        assert!(summary.full_passes >= 2, "{summary:?}");
        assert_eq!(summary.failures, 0, "{summary:?}");
    })
    .await;
}
