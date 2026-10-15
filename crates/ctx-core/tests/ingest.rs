//! Backfill and incremental ingest against a scratch schema and synthetic
//! `events.jsonl` / `session-store.db` files.

mod common;

use common::*;
use ctx_core::db::{self, IngestLock};
use ctx_core::verify::{Verifier, planted_secrets};
use serde_json::json;

type Titles = Vec<(String, Option<String>, Option<String>)>;

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn backfill_maps_every_source() {
    with_env("backfill", |env| async move {
        let _store = populate(&env);
        let run = env.ingester.run_all(false, 2).await.unwrap();
        assert!(run.failed.is_empty(), "{:?}", run.failed);
        assert_eq!(run.totals.lines, 27);
        assert_eq!(run.totals.rejected, 0);
        assert_eq!(run.totals.sessions_restarted, 2);
        assert_eq!(
            db::table_counts(&env.pool).await.unwrap(),
            expected_counts()
        );

        // workspace.yaml has the last word on a title, the store only fills gaps,
        // whichever is read first.
        let titles: Titles = sqlx::query_as("SELECT id, name, summary FROM sessions ORDER BY id")
            .fetch_all(&env.pool)
            .await
            .unwrap();
        let title = |id: &str, name: Option<&str>, summary: Option<&str>| {
            (
                id.to_owned(),
                name.map(str::to_owned),
                summary.map(str::to_owned),
            )
        };
        assert_eq!(
            titles,
            vec![
                title("alpha", Some("Alpha task"), Some("Alpha does a thing")),
                title(
                    "beta",
                    Some("Beta task"),
                    Some("Beta, as the store sees it")
                ),
                title("delta", None, Some("Delta, long gone from disk")),
                title("gamma", Some("Gamma task"), None),
            ]
        );

        // Facts come from the event stream.
        let facts: (
            Option<String>,
            Option<String>,
            Option<String>,
            Option<String>,
            bool,
        ) = sqlx::query_as(
            "SELECT model, effort, repository, branch, started_at < ended_at
               FROM sessions WHERE id = 'alpha'",
        )
        .fetch_one(&env.pool)
        .await
        .unwrap();
        assert_eq!(
            facts,
            (
                Some("claude-sonnet-5.5".into()),
                Some("high".into()),
                Some("acme/demo".into()),
                Some("main".into()),
                true
            )
        );

        // The start and the completion of one tool call are one row.
        let call: (
            Option<String>,
            Option<bool>,
            Option<i32>,
            Option<String>,
            bool,
        ) = sqlx::query_as(
            "SELECT tool, ok, exit_code, result_text, t_start < t_end
               FROM tool_calls WHERE session_id = 'alpha' AND tool_call_id = 'alpha-call1'",
        )
        .fetch_one(&env.pool)
        .await
        .unwrap();
        assert_eq!(
            call,
            (
                Some("bash".into()),
                Some(true),
                Some(0),
                Some("1\n".into()),
                true
            )
        );

        // The sub-agent call keeps its identity and the price table survives.
        let sub: (Option<String>, i64, i64) = sqlx::query_as(
            "SELECT agent_id, nano_aiu, jsonb_array_length(price)::bigint
               FROM usage WHERE agent_id IS NOT NULL",
        )
        .fetch_one(&env.pool)
        .await
        .unwrap();
        assert_eq!(sub, (Some("agent-1".into()), usages()[2].nano_aiu(), 4));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rerunning_and_forcing_add_no_rows() {
    with_env("rerun", |env| async move {
        let _store = populate(&env);
        env.ingester.run_all(false, 2).await.unwrap();

        let again = env.ingester.run_all(false, 2).await.unwrap();
        assert!(again.failed.is_empty(), "{:?}", again.failed);
        assert_eq!(again.totals.sessions_skipped, 2);
        assert_eq!(again.totals.lines, 0);
        assert_eq!(again.totals.events_changed, 0);
        assert_eq!(again.store.changed(), 0);
        assert_eq!(
            db::table_counts(&env.pool).await.unwrap(),
            expected_counts()
        );

        let forced = env.ingester.run_all(true, 2).await.unwrap();
        assert!(forced.failed.is_empty(), "{:?}", forced.failed);
        assert_eq!(forced.totals.sessions_restarted, 2);
        assert_eq!(forced.totals.lines, 27);
        assert_eq!(forced.totals.events_changed, 0);
        assert_eq!(forced.totals.tool_calls_changed, 0);
        assert_eq!(forced.store.changed(), 0);
        assert_eq!(
            db::table_counts(&env.pool).await.unwrap(),
            expected_counts()
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn appended_lines_resume_and_a_partial_line_waits() {
    with_env("append", |env| async move {
        env.add_session("alpha", &story("alpha", 1));
        let first = env.ingester.ingest_session("alpha", false).await.unwrap();
        assert_eq!((first.lines, first.sessions_restarted), (6, 1));

        let idle = env.ingester.ingest_session("alpha", false).await.unwrap();
        assert_eq!((idle.sessions_skipped, idle.lines), (1, 0));

        env.append_events("alpha", &turn("alpha", 1));
        let more = env.ingester.ingest_session("alpha", false).await.unwrap();
        assert_eq!((more.sessions_read, more.sessions_restarted, more.lines), (1, 0, 5));
        assert_eq!(env.count("SELECT count(*) FROM events").await, 11);

        // The CLI is half way through a line: nothing of it may be consumed.
        let next = turn("alpha", 2);
        let first_line = next[0].to_string();
        let (head, rest) = first_line.split_at(first_line.len() / 2);
        env.append_bytes("alpha", head.as_bytes());
        let stub = env.ingester.ingest_session("alpha", false).await.unwrap();
        assert_eq!(stub.lines, 0);
        assert_eq!(env.count("SELECT count(*) FROM events").await, 11);

        // Once it is complete, it is read from where the last pass stopped.
        env.append_bytes("alpha", format!("{rest}\n").as_bytes());
        env.append_events("alpha", &next[1..]);
        let done = env.ingester.ingest_session("alpha", false).await.unwrap();
        assert_eq!((done.sessions_restarted, done.lines), (0, 5));
        assert_eq!(env.count("SELECT count(*) FROM events").await, 16);
        assert_eq!(env.count("SELECT count(*) FROM tool_calls").await, 3);

        let size = i64::try_from(std::fs::metadata(env.events_file("alpha")).unwrap().len()).unwrap();
        let state: (i64, Option<i64>) = sqlx::query_as(
            "SELECT byte_offset, file_size FROM ingest_state WHERE source = 'events' AND key = 'alpha'",
        )
        .fetch_one(&env.pool)
        .await
        .unwrap();
        assert_eq!(state, (size, Some(size)));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn garbage_is_counted_and_a_nul_stub_is_stepped_over() {
    with_env("garbage", |env| async move {
        env.add_session("alpha", &story("alpha", 1));
        env.append_bytes("alpha", b"this is not json\n{\"type\":\"no-id\"}\n\n");
        // What a crash leaves behind: a block of NULs that is never completed.
        env.append_bytes("alpha", &[0u8; 64]);

        let first = env.ingester.ingest_session("alpha", false).await.unwrap();
        assert_eq!((first.lines, first.rejected), (8, 2));
        assert_eq!(env.count("SELECT count(*) FROM events").await, 6);

        // The stub keeps its size, so it is not read over and over.
        let idle = env.ingester.ingest_session("alpha", false).await.unwrap();
        assert_eq!((idle.sessions_skipped, idle.lines), (1, 0));

        // The CLI appends after it: the new line is found behind the NULs.
        env.append_events("alpha", &turn("alpha", 1));
        let resumed = env.ingester.ingest_session("alpha", false).await.unwrap();
        assert_eq!(
            (resumed.sessions_restarted, resumed.lines, resumed.rejected),
            (0, 5, 0)
        );
        assert_eq!(env.count("SELECT count(*) FROM events").await, 11);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn forked_sessions_repeat_event_ids_without_clashing() {
    with_env("fork", |env| async move {
        let parent = story("alpha", 2);
        env.add_session("alpha", &parent);
        // A fork starts with a copy of its parent's history.
        let mut child = parent.clone();
        child.extend(turn("fork", 0));
        env.add_session("fork", &child);

        let run = env.ingester.run_all(false, 2).await.unwrap();
        assert!(run.failed.is_empty(), "{:?}", run.failed);
        assert_eq!(
            env.count("SELECT count(*) FROM events WHERE session_id = 'alpha'")
                .await,
            11
        );
        assert_eq!(
            env.count("SELECT count(*) FROM events WHERE session_id = 'fork'")
                .await,
            16
        );
        assert_eq!(
            env.count(
                "SELECT count(*) FROM (SELECT event_id FROM events GROUP BY event_id
                                       HAVING count(DISTINCT session_id) = 2) shared"
            )
            .await,
            11
        );
        assert_eq!(env.count("SELECT count(*) FROM tool_calls").await, 5);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn deleting_a_session_purges_it_and_it_is_read_again_when_its_source_is_still_there() {
    with_env("purge", |env| async move {
        let _store = populate(&env);
        env.ingester.run_all(false, 2).await.unwrap();

        env.execute("DELETE FROM sessions WHERE id = 'alpha'").await;
        for sql in [
            "SELECT count(*) FROM events WHERE session_id = 'alpha'",
            "SELECT count(*) FROM tool_calls WHERE session_id = 'alpha'",
            "SELECT count(*) FROM usage WHERE session_id = 'alpha'",
            "SELECT count(*) FROM turns WHERE session_id = 'alpha'",
            "SELECT count(*) FROM session_files WHERE session_id = 'alpha'",
            "SELECT count(*) FROM ingest_state WHERE source = 'events' AND key = 'alpha'",
        ] {
            assert_eq!(env.count(sql).await, 0, "{sql}");
        }

        // The offset went with the session, so the file is read from the start.
        let run = env.ingester.run_all(false, 2).await.unwrap();
        assert!(run.failed.is_empty(), "{:?}", run.failed);
        assert_eq!(run.totals.sessions_restarted, 1);
        assert_eq!(
            db::table_counts(&env.pool).await.unwrap(),
            expected_counts()
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn no_planted_secret_reaches_the_database() {
    with_env("secrets", |env| async move {
        let secrets = planted_secrets();
        let github = secrets.iter().find(|(family, _)| *family == "github").unwrap().1.clone();
        let stripe = secrets.iter().find(|(family, _)| *family == "stripe").unwrap().1.clone();

        // The same secrets through every door: event bodies, tool arguments,
        // tool results, workspace.yaml, and the session store.
        let mut events = story("alpha", 1);
        for (i, (family, secret)) in secrets.iter().enumerate() {
            let call = format!("alpha-leak{i}");
            events.push(ev(
                &format!("alpha-note{i}"),
                "user.message",
                10 + i,
                json!({"content": format!("note for {family}: {secret} end"), "agentMode": "interactive"}),
            ));
            events.push(ev(
                &format!("alpha-xs{i}"),
                "tool.execution_start",
                10 + i,
                json!({"toolCallId": call, "toolName": "bash",
                       "arguments": {"command": format!("echo {secret}"), "env": {"NOTE": [secret]}}}),
            ));
            events.push(ev(
                &format!("alpha-xe{i}"),
                "tool.execution_complete",
                10 + i,
                json!({"toolCallId": call, "success": true, "result": {"content": format!("got {secret}")}}),
            ));
        }
        env.add_session("alpha", &events);
        env.write_workspace(
            "alpha",
            &format!("Deploy with {github}"),
            Some(&format!("rotate {stripe} soon")),
        );
        let store = env.store();
        store.session("alpha", &format!("summary with {github}"));
        for (i, (_, secret)) in secrets.iter().enumerate() {
            store.turn("alpha", i as i64, secret, Some(secret));
            store.file("alpha", &format!("/tmp/{secret}"), 0);
            store.reference("alpha", "url", secret, 0);
        }
        store.checkpoint("alpha", 1, "Checkpoint", &format!("the key was {github}"));

        let run = env.ingester.run_all(false, 2).await.unwrap();
        assert!(run.failed.is_empty(), "{:?}", run.failed);

        // The probe can see a leak: plant one by hand and look for it.
        let probe = needle(&github);
        sqlx::query(
            "INSERT INTO turns (session_id, turn_index, user_message, src_hash)
             VALUES ('alpha', 9999, $1, 'control')",
        )
        .bind(format!("control {probe}"))
        .execute(&env.pool)
        .await
        .unwrap();
        assert_eq!(env.leaks(&probe).await, 1, "the leak probe is blind");
        env.execute("DELETE FROM turns WHERE turn_index = 9999").await;

        // The sources do hold the secrets, the database does not.
        let raw = std::fs::read_to_string(env.events_file("alpha")).unwrap();
        for (family, secret) in &secrets {
            let part = needle(secret);
            assert!(raw.contains(&part), "{family} was not planted");
            let leaked = env.leaks(&part).await;
            assert_eq!(leaked, 0, "{family}: {leaked} rows still hold the secret");
        }
        assert!(env.count("SELECT coalesce(sum(n), 0)::bigint FROM redactions").await >= secrets.len() as i64);

        let verdict = Verifier::new(env.ingester.clone()).run(2).await.unwrap();
        assert!(verdict.ok(), "{}", verdict.render());
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn only_one_ingester_may_run_at_a_time() {
    with_env("lock", |env| async move {
        let held = IngestLock::try_acquire(&env.pool)
            .await
            .unwrap()
            .expect("the lock is free");
        assert!(IngestLock::try_acquire(&env.pool).await.unwrap().is_none());
        drop(held);

        // PostgreSQL frees the lock when it notices that the connection closed.
        let pool = env.pool.clone();
        eventually("the lock to be released", PATIENCE, || {
            let pool = pool.clone();
            async move { IngestLock::try_acquire(&pool).await.unwrap().is_some() }
        })
        .await;
    })
    .await;
}
