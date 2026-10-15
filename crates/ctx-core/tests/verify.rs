//! `Verifier`: it passes on a faithful mirror, notices damage, and never
//! prints what it found.

mod common;

use common::*;
use ctx_core::verify::{Finding, Verification, Verifier, planted_secrets};

async fn verify(env: &Env) -> Verification {
    Verifier::new(env.ingester.clone()).run(2).await.unwrap()
}

fn find<'a>(verdict: &'a Verification, name: &str) -> &'a Finding {
    verdict
        .findings()
        .find(|f| f.name == name)
        .unwrap_or_else(|| panic!("no finding named {name:?} in\n{}", verdict.render()))
}

fn failed(verdict: &Verification) -> Vec<&str> {
    verdict
        .findings()
        .filter(|f| !f.ok)
        .map(|f| f.name.as_str())
        .collect()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_faithful_mirror_passes_every_check() {
    with_env("verify_clean", |env| async move {
        let _store = populate(&env);
        env.ingester.run_all(false, 2).await.unwrap();

        let verdict = verify(&env).await;
        assert!(verdict.ok(), "{}", verdict.render());
        assert!(verdict.render().ends_with("result: PASS\n"));
        // Nothing was skipped quietly: the comparisons really ran.
        assert!(
            find(&verdict, "events").detail.starts_with("27 "),
            "{}",
            verdict.render()
        );
        assert!(find(&verdict, "tool_calls").detail.starts_with("5 "));
        assert!(
            find(&verdict, "usage rows")
                .detail
                .starts_with("5 in the source, 5 in PostgreSQL")
        );
        assert!(find(&verdict, "canaries").ok);
        assert!(find(&verdict, "masked values").ok);
        assert!(find(&verdict, "stored text").ok);
        assert!(find(&verdict, "re-redaction").ok);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_leaked_secret_is_flagged_by_count_and_never_shown() {
    with_env("verify_leak", |env| async move {
        let _store = populate(&env);
        env.ingester.run_all(false, 2).await.unwrap();

        let secrets = planted_secrets();
        let github = secrets.iter().find(|(family, _)| *family == "github").unwrap().1.clone();
        let jwt = secrets.iter().find(|(family, _)| *family == "jwt").unwrap().1.clone();
        // One in a text column, one in a JSON document.
        sqlx::query(
            "UPDATE tool_calls SET result_text = 'oops ' || $1
              WHERE session_id = 'alpha' AND tool_call_id = 'alpha-call1'",
        )
        .bind(&github)
        .execute(&env.pool)
        .await
        .unwrap();
        sqlx::query("UPDATE events SET body = jsonb_build_object('note', $1::text) WHERE event_id = 'beta-u0'")
            .bind(&jwt)
            .execute(&env.pool)
            .await
            .unwrap();

        let verdict = verify(&env).await;
        assert!(!verdict.ok(), "{}", verdict.render());
        let text = find(&verdict, "tool_calls.result_text");
        assert!(!text.ok && text.detail.contains("github=1"), "{text:?}");
        let json = find(&verdict, "events.body");
        assert!(!json.ok && json.detail.contains("jwt=1"), "{json:?}");
        assert!(!find(&verdict, "stored text").ok);
        assert!(!find(&verdict, "re-redaction").ok);

        // Counts only: neither the secret nor any recognisable part of it.
        let report = verdict.render();
        for secret in [&github, &jwt] {
            assert!(!report.contains(secret.as_str()));
            assert!(!report.contains(&needle(secret)));
        }
        assert!(report.contains("FAIL"));

        // Reading the sources again rewrites both rows through the redactor.
        let repaired = env.ingester.run_all(true, 2).await.unwrap();
        assert!(repaired.failed.is_empty(), "{:?}", repaired.failed);
        assert_eq!(repaired.totals.events_changed, 1);
        assert_eq!(repaired.totals.tool_calls_changed, 1);
        for secret in [&github, &jwt] {
            assert_eq!(env.leaks(&needle(secret)).await, 0);
        }
        let verdict = verify(&env).await;
        assert!(verdict.ok(), "{}", verdict.render());
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_event_rows_and_unread_sessions_are_flagged_and_forcing_repairs_them() {
    with_env("verify_events", |env| async move {
        let _store = populate(&env);
        env.ingester.run_all(false, 2).await.unwrap();
        assert!(verify(&env).await.ok());

        // Damage: an event and a tool call vanish from two sessions, and the
        // CLI has started a session that no pass has seen yet.
        env.add_session("zeta", &story("zeta", 1));
        env.execute("DELETE FROM events WHERE event_id = 'alpha-u1'")
            .await;
        env.execute("DELETE FROM tool_calls WHERE tool_call_id = 'beta-call0'")
            .await;

        let verdict = verify(&env).await;
        let report = verdict.render();
        assert!(!verdict.ok(), "{report}");
        for name in ["events", "tool_calls", "never read", "out of step"] {
            assert!(!find(&verdict, name).ok, "{name} should fail:\n{report}");
        }
        assert!(
            find(&verdict, "events")
                .detail
                .starts_with("27 in the files up to the recorded offsets, 26 "),
            "{report}"
        );
        assert!(
            find(&verdict, "never read").detail.contains("zeta"),
            "{report}"
        );
        let off = &find(&verdict, "out of step").detail;
        assert!(
            off.contains("alpha") && off.contains("beta") && !off.contains("zeta"),
            "{report}"
        );
        // Nothing else is blamed: the store and the text are fine.
        let blamed = failed(&verdict);
        assert!(
            blamed
                .iter()
                .all(|name| ["events", "tool_calls", "never read", "out of step"].contains(name)),
            "{blamed:?}"
        );

        // A plain pass reads the new session, but the recorded offsets say that
        // there is nothing more to read in the other two.
        let plain = env.ingester.run_all(false, 2).await.unwrap();
        assert_eq!(
            (plain.totals.sessions_restarted, plain.totals.events_changed),
            (1, 6)
        );
        assert_eq!(env.count("SELECT count(*) FROM events").await, 27 - 1 + 6);

        // Only a full re-read puts the lost rows back.
        let repaired = env.ingester.run_all(true, 2).await.unwrap();
        assert!(repaired.failed.is_empty(), "{:?}", repaired.failed);
        assert_eq!(
            (
                repaired.totals.events_changed,
                repaired.totals.tool_calls_changed
            ),
            (1, 1)
        );
        let verdict = verify(&env).await;
        assert!(verdict.ok(), "{}", verdict.render());
        assert!(
            find(&verdict, "events").detail.starts_with("33 "),
            "{}",
            verdict.render()
        );
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn lost_store_rows_are_flagged_and_the_next_sync_brings_them_back() {
    with_env("verify_store", |env| async move {
        let _store = populate(&env);
        env.ingester.run_all(false, 2).await.unwrap();
        assert!(verify(&env).await.ok());

        env.execute("DELETE FROM usage WHERE session_id = 'beta'")
            .await;
        env.execute("DELETE FROM turns WHERE session_id = 'beta' AND turn_index = 1")
            .await;
        env.execute("DELETE FROM checkpoints").await;
        env.execute("DELETE FROM session_files").await;
        env.execute("DELETE FROM session_refs").await;

        let verdict = verify(&env).await;
        let report = verdict.render();
        assert!(!verdict.ok(), "{report}");
        for name in [
            "usage rows",
            "usage totals",
            "turns",
            "checkpoints",
            "session_files",
            "session_refs",
        ] {
            assert!(!find(&verdict, name).ok, "{name} should fail:\n{report}");
        }
        assert!(
            find(&verdict, "usage rows").detail.contains("1 missing"),
            "{report}"
        );
        // The event files were not touched.
        assert!(
            find(&verdict, "events").ok && find(&verdict, "out of step").ok,
            "{report}"
        );

        let synced = env.ingester.sync_store(false).await.unwrap();
        assert_eq!(
            (
                synced.usage_changed,
                synced.turns_changed,
                synced.checkpoints_changed,
                synced.files_changed,
                synced.refs_changed
            ),
            (1, 1, 1, 2, 1)
        );
        let verdict = verify(&env).await;
        assert!(verdict.ok(), "{}", verdict.render());
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn rows_written_after_the_last_sync_are_not_a_mismatch() {
    with_env("verify_newer", |env| async move {
        let store = populate(&env);
        env.ingester.run_all(false, 2).await.unwrap();

        // The CLI keeps writing while verify looks: both sources move on.
        env.append_events("alpha", &turn("alpha", 3));
        store.turn("alpha", 3, "a question asked just now", None);
        store.usage(&Usage {
            session: "alpha",
            turn: 3,
            agent: None,
            model: "claude-sonnet-5.5",
            initiator: "user",
            at: "2026-10-01T08:41:00.000Z",
            fresh: 20,
            cache_read: 30_000,
            cache_write: 100,
            output: 150,
        });

        let verdict = verify(&env).await;
        assert!(verdict.ok(), "{}", verdict.render());
        assert!(
            find(&verdict, "events").detail.starts_with("27 "),
            "bounded by the offsets"
        );
        let newer = find(&verdict, "newer");
        assert!(
            newer.ok && newer.detail.starts_with("2 store rows"),
            "{newer:?}"
        );

        // Once synced, the new rows are part of the comparison.
        let run = env.ingester.run_all(false, 2).await.unwrap();
        assert_eq!(
            (
                run.totals.lines,
                run.store.turns_changed,
                run.store.usage_changed
            ),
            (5, 1, 1)
        );
        let verdict = verify(&env).await;
        assert!(verdict.ok(), "{}", verdict.render());
        assert!(find(&verdict, "events").detail.starts_with("32 "));
        assert!(verdict.findings().all(|f| f.name != "newer"));
    })
    .await;
}

/// What `ctx-hook` writes: identifiers and a hash kept as they are, text that
/// went through the redactor. The `uid` is the shape `new_uid()` makes.
const HOOK_ROW: &str = "INSERT INTO hook_audit
    (uid, ts, session_id, tool, cmd_sha, cmd_preview, cwd, decision, rule, shadow, latency_us, policy)
    VALUES ('18f2a3b4c5d6e7f8-1a2b-0', now(), 'b5b9fbf1-124d-4b43-8215-1f8ece76583c', 'bash',
            'ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12cd34ef56ab12',
            'ls src', '/home/u/kms', 'allow', 'allow:ls', true, 812, 'v1:3fa9c0de')";

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_hook_audit_table_passes_when_clean_and_is_scanned_when_not() {
    with_env("verify_hook_audit", |env| async move {
        let _store = populate(&env);
        env.ingester.run_all(false, 2).await.unwrap();
        sqlx::query(HOOK_ROW).execute(&env.pool).await.unwrap();

        // The ids and the hash are listed as verbatim: they were never
        // redacted, so the fixed point is not asked of them
        let verdict = verify(&env).await;
        assert!(verdict.ok(), "{}", verdict.render());
        assert!(find(&verdict, "re-redaction").ok);

        // A secret in any of the text columns is found, by count only
        let secrets = planted_secrets();
        let github = secrets
            .iter()
            .find(|(family, _)| *family == "github")
            .unwrap()
            .1
            .clone();
        for column in ["cmd_preview", "cwd", "rule", "tool"] {
            sqlx::query(sqlx::AssertSqlSafe(format!(
                "UPDATE hook_audit SET {column} = 'x ' || $1"
            )))
            .bind(&github)
            .execute(&env.pool)
            .await
            .unwrap();
            let verdict = verify(&env).await;
            assert!(!verdict.ok(), "{column}: {}", verdict.render());
            let flagged = find(&verdict, &format!("hook_audit.{column}"));
            assert!(
                !flagged.ok && flagged.detail.contains("github=1"),
                "{flagged:?}"
            );
            let report = verdict.render();
            assert!(!report.contains(&github) && !report.contains(&needle(&github)));
            sqlx::query("DELETE FROM hook_audit")
                .execute(&env.pool)
                .await
                .unwrap();
            sqlx::query(HOOK_ROW).execute(&env.pool).await.unwrap();
        }

        // The columns that are kept verbatim are still read by the scan
        sqlx::query("UPDATE hook_audit SET session_id = 'x-' || $1")
            .bind(&github)
            .execute(&env.pool)
            .await
            .unwrap();
        let verdict = verify(&env).await;
        let flagged = find(&verdict, "hook_audit.session_id");
        assert!(
            !flagged.ok && flagged.detail.contains("github=1"),
            "{flagged:?}"
        );
    })
    .await;
}
