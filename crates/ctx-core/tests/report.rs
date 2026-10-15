//! The report views over a small world whose numbers can be worked out by
//! hand (see `common::usages`): five calls worth 19.57 AIU in two sessions,
//! one sub-agent call and one cold-cache rebuild.

mod common;

use chrono::{DateTime, Utc};
use common::*;
use ctx_core::db;
use ctx_core::report::{BASELINE, Reporter, Verdict};

fn close(what: &str, got: f64, want: f64) {
    let slack = 1e-9 * want.abs().max(1.0);
    assert!(
        (got - want).abs() <= slack,
        "{what}: got {got}, want {want}"
    );
}

async fn metrics(env: &Env, as_of: Option<&str>) -> std::collections::HashMap<String, f64> {
    let as_of: Option<DateTime<Utc>> = as_of.map(|t| t.parse().expect("an RFC 3339 time"));
    Reporter::new(&env.pool, as_of)
        .await
        .unwrap()
        .metrics()
        .await
        .unwrap()
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn headline_numbers_follow_from_the_calls() {
    with_env("report_summary", |env| async move {
        let _store = populate(&env);
        env.ingester.run_all(false, 2).await.unwrap();
        let m = metrics(&env, None).await;
        let get = |name: &str| *m.get(name).unwrap_or_else(|| panic!("no metric {name}"));

        let calls = usages();
        let total: f64 = calls.iter().map(|u| u.aiu()).sum();
        close("total, worked out by hand", total, 19.57);
        assert_eq!(get("calls"), 5.0);
        assert_eq!(get("sessions_with_usage"), 2.0);
        close("aiu_total", get("aiu_total"), total);
        close(
            "mean_prompt_tokens",
            get("mean_prompt_tokens"),
            140_500.0 / 5.0,
        );

        // Per token type, from the price table of each call.
        let share = |price: i64, tokens: fn(&Usage<'_>) -> i64| {
            let nano: i64 = calls.iter().map(|u| tokens(u) * price / 1_000_000).sum();
            100.0 * nano as f64 / 1e9 / total
        };
        close(
            "cache read share",
            get("aiu_pct_cache_read"),
            share(10_000_000_000, |u| u.cache_read),
        );
        close(
            "cache write share",
            get("aiu_pct_cache_write"),
            share(250_000_000_000, |u| u.cache_write),
        );
        close(
            "output share",
            get("aiu_pct_output"),
            share(1_000_000_000_000, |u| u.output),
        );
        close(
            "input share",
            get("aiu_pct_input"),
            share(200_000_000_000, |u| u.fresh),
        );
        let split = ["cache_read", "cache_write", "output", "input"]
            .iter()
            .map(|kind| get(&format!("aiu_pct_{kind}")))
            .sum::<f64>();
        close("the four shares", split, 100.0);
        close("split minus total", get("split_minus_total_aiu"), 0.0);

        // Turns: alpha 0 (two main calls and a sub-agent call), alpha 1, beta 0.
        assert_eq!(get("turns"), 3.0);
        close("aiu_per_turn", get("aiu_per_turn"), total / 3.0);
        close("main_calls_per_turn", get("main_calls_per_turn"), 4.0 / 3.0);
        assert_eq!(get("one_call_turns"), 2.0);
        close(
            "one_call_turn_mean_aiu",
            get("one_call_turn_mean_aiu"),
            (7.472 + 0.502) / 2.0,
        );

        // The sub-agent call is the third one, and a sub-agent call is never cold.
        close(
            "aiu_pct_subagent",
            get("aiu_pct_subagent"),
            100.0 * calls[2].aiu() / total,
        );

        // Only the call after 39 minutes of silence rebuilt a big prompt from scratch.
        assert_eq!(get("cold_calls"), 1.0);
        assert_eq!(get("cold_user_calls"), 1.0);
        assert_eq!(get("cold_agent_calls"), 0.0);
        close(
            "aiu_pct_cold",
            get("aiu_pct_cold"),
            100.0 * calls[3].aiu() / total,
        );
        close(
            "cold_user_mean_idle_min",
            get("cold_user_mean_idle_min"),
            39.0 + 20.0 / 60.0,
        );
        close(
            "cold_user_mean_context_tokens",
            get("cold_user_mean_context_tokens"),
            30_060.0,
        );

        // Nothing here is big, long-running or automatic.
        for zero in [
            "aiu_pct_prompt_ge_100k",
            "aiu_pct_prompt_gt_400k",
            "sessions_gt_1000_aiu",
            "autopilot_sessions",
            "aborts",
            "failures_retries_errors",
            "task_completes",
            "permission_requests",
        ] {
            assert_eq!(get(zero), 0.0, "{zero}");
        }
        assert_eq!(get("user_messages"), 5.0);
        assert_eq!(get("assistant_turns"), 5.0);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn a_report_pinned_to_a_moment_ignores_what_came_later() {
    with_env("report_as_of", |env| async move {
        let _store = populate(&env);
        env.ingester.run_all(false, 2).await.unwrap();

        // 08:01 is after the first three calls and before the rebuild.
        let early = metrics(&env, Some("2026-10-01T08:01:00Z")).await;
        assert_eq!(early["calls"], 3.0);
        assert_eq!(early["sessions_with_usage"], 1.0);
        assert_eq!(early["turns"], 1.0);
        assert_eq!(early["cold_calls"], 0.0);
        let first = usages();
        close(
            "aiu_total",
            early["aiu_total"],
            first[..3].iter().map(|u| u.aiu()).sum(),
        );

        let all = metrics(&env, Some("2026-10-01T09:30:00Z")).await;
        assert_eq!((all["calls"], all["cold_calls"]), (5.0, 1.0));
        let unpinned = metrics(&env, None).await;
        assert_eq!(unpinned["aiu_total"], all["aiu_total"]);

        // The pin belongs to one connection and does not leak into the next.
        let again = metrics(&env, None).await;
        assert_eq!(again["calls"], 5.0);
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn weekly_and_split_views_add_up() {
    with_env("report_weekly", |env| async move {
        let _store = populate(&env);
        env.ingester.run_all(false, 2).await.unwrap();

        // 2026-10-01 is a Thursday; the ISO week starts on Monday the 28th.
        let week: (String, i64, i64, i64, f64, i64) = sqlx::query_as(
            "SELECT week::text, calls, sessions, turns, calls_per_turn, user_messages FROM v_weekly",
        )
        .fetch_one(&env.pool)
        .await
        .unwrap();
        assert_eq!((week.0.as_str(), week.1, week.2, week.3), ("2026-09-28", 5, 2, 3));
        close("calls_per_turn", week.4, 4.0 / 3.0);
        assert_eq!(week.5, 5);

        for dim in ["token_type", "initiator"] {
            let (n, pct): (i64, f64) = sqlx::query_as(
                "SELECT count(*), sum(aiu_pct) FROM v_split WHERE dim = $1",
            )
            .bind(dim)
            .fetch_one(&env.pool)
            .await
            .unwrap();
            assert!(n >= 2, "{dim}");
            close(dim, pct, 100.0);
        }
        let by_initiator: Vec<(String, i64)> = sqlx::query_as(
            "SELECT value, calls FROM v_split WHERE dim = 'initiator' ORDER BY value",
        )
        .fetch_all(&env.pool)
        .await
        .unwrap();
        assert_eq!(by_initiator, [("agent".to_owned(), 2), ("user".to_owned(), 3)]);

        let model: (i64, bool) = sqlx::query_as(
            "SELECT calls, is_sub FROM v_model WHERE is_sub",
        )
        .fetch_one(&env.pool)
        .await
        .unwrap();
        assert_eq!(model, (1, true));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn an_empty_database_reports_nothing_and_matches_no_baseline() {
    with_env("report_empty", |env| async move {
        let mut reporter = Reporter::new(&env.pool, None).await.unwrap();
        let m = reporter.metrics().await.unwrap();
        assert_eq!(m["calls"], 0.0);
        assert_eq!(m["aiu_total"], 0.0);
        assert!(
            !m.contains_key("aiu_per_turn"),
            "a ratio over nothing is not a number"
        );

        let checks = reporter.baseline().await.unwrap();
        assert_eq!(checks.len(), BASELINE.len());
        let verdict = Verdict::of(&checks);
        assert!(
            !verdict.ok(),
            "an empty database must not reproduce PLAN §2"
        );
        assert_eq!(
            verdict.required_failed,
            verdict.required - 1,
            "only the zero split passes"
        );
        assert_eq!(reporter.coverage().await.unwrap(), (None, None));
    })
    .await;
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn migrating_again_keeps_the_views_and_the_data() {
    with_env("report_migrate", |env| async move {
        let _store = populate(&env);
        env.ingester.run_all(false, 2).await.unwrap();
        db::migrate(&env.pool).await.unwrap();
        db::migrate(&env.pool).await.unwrap();

        assert_eq!(
            db::table_counts(&env.pool).await.unwrap(),
            expected_counts()
        );
        let views: Vec<String> = sqlx::query_scalar(
            "SELECT viewname::text FROM pg_views WHERE schemaname = current_schema() ORDER BY 1",
        )
        .fetch_all(&env.pool)
        .await
        .unwrap();
        assert_eq!(
            views,
            [
                "v_call",
                "v_model",
                "v_permission_wait",
                "v_quality",
                "v_session",
                "v_split",
                "v_summary",
                "v_token_aiu",
                "v_turn",
                "v_weekly"
            ]
        );
        assert_eq!(metrics(&env, None).await["calls"], 5.0);
    })
    .await;
}
