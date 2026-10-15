//! The replay against a real PostgreSQL (the query that reads the history of
//! permission requests out of `events`) and against the real policy (the
//! report over a history, with the trusted roots it tries one at a time).

mod common;
mod scratch;

use std::fs;
use std::path::Path;

use chrono::{DateTime, Utc};
use common::World;
use ctx_hook::config::Config;
use ctx_hook::hook::Policy;
use ctx_hook::policy::Verdict;
use ctx_hook::replay::{Judges, Past, analyze, load};
use ctx_hook::vars::Vars;
use scratch::with_schema;
use serde_json::{Value, json};
use sqlx::PgPool;
use tempfile::TempDir;

fn at(text: &str) -> DateTime<Utc> {
    text.parse().expect("an RFC 3339 time")
}

async fn session(pool: &PgPool, id: &str, cwd: Option<&str>) {
    sqlx::query("INSERT INTO sessions (id, cwd) VALUES ($1, $2)")
        .bind(id)
        .bind(cwd)
        .execute(pool)
        .await
        .unwrap();
}

async fn event(pool: &PgPool, session: &str, time: &str, kind: &str, body: Value) {
    sqlx::query(
        "INSERT INTO events (session_id, event_id, ts, type, src_offset, body)
         VALUES ($1, gen_random_uuid()::text, $2, $3, 0, $4)",
    )
    .bind(session)
    .bind(at(time))
    .bind(kind)
    .bind(body)
    .execute(pool)
    .await
    .unwrap();
}

/// A question about a shell command as the CLI records it.
fn asked(request_id: &str, command: &str, prompt: Value, commands: Value) -> Value {
    json!({
        "requestId": request_id,
        "promptRequest": prompt,
        "permissionRequest": {
            "kind": "shell",
            "fullCommandText": command,
            "commands": commands,
        },
    })
}

fn commands_prompt(command: &str) -> Value {
    json!({ "kind": "commands", "fullCommandText": command })
}

fn answered(request_id: &str, result: &str) -> Value {
    json!({ "requestId": request_id, "result": { "kind": result } })
}

/// Where each session was and what it asked, with every oddity that the real
/// history has: a question recorded twice, two answers, a directory that
/// changed, a command only the prompt carries, an answer before the question.
async fn the_history(pool: &PgPool, a: &str, b: &str, gone: &str) {
    session(pool, "s1", Some(gone)).await;
    event(
        pool,
        "s1",
        "2026-10-01T07:59:00Z",
        "session.start",
        json!({"context": {"cwd": a}}),
    )
    .await;
    event(
        pool,
        "s1",
        "2026-10-01T08:00:00Z",
        "permission.requested",
        asked(
            "r1",
            "ls first",
            commands_prompt("ls first"),
            json!([
                {"readOnly": true, "identifier": "ls"},
                {"readOnly": false, "identifier": "rm"},
                {"readOnly": false, "identifier": "git push"},
            ]),
        ),
    )
    .await;
    event(
        pool,
        "s1",
        "2026-10-01T08:00:05Z",
        "permission.requested",
        asked("r1", "ls second", commands_prompt("ls second"), json!([])),
    )
    .await;
    event(
        pool,
        "s1",
        "2026-10-01T08:00:30Z",
        "permission.completed",
        answered("r1", "approved"),
    )
    .await;
    event(
        pool,
        "s1",
        "2026-10-01T08:01:00Z",
        "permission.completed",
        answered("r1", "denied-interactively-by-user"),
    )
    .await;
    event(
        pool,
        "s1",
        "2026-10-01T08:10:00Z",
        "session.context_changed",
        json!({"cwd": b}),
    )
    .await;
    event(
        pool,
        "s1",
        "2026-10-01T08:20:00Z",
        "permission.requested",
        asked("r2", "cat file", commands_prompt("cat file"), json!([])),
    )
    .await;
    // not a shell command: only shell requests are replayed
    event(
        pool,
        "s1",
        "2026-10-01T08:21:00Z",
        "permission.requested",
        json!({
            "requestId": "r3",
            "promptRequest": {"kind": "read"},
            "permissionRequest": {"kind": "read", "path": "/etc/hosts", "fullCommandText": "cat /etc/hosts"},
        }),
    )
    .await;
    // the command is only in the prompt, which has no kind
    event(
        pool,
        "s1",
        "2026-10-01T08:22:00Z",
        "permission.requested",
        json!({
            "requestId": "r4",
            "promptRequest": {"fullCommandText": "pwd"},
            "permissionRequest": {"kind": "shell"},
        }),
    )
    .await;
    event(
        pool,
        "s1",
        "2026-10-01T08:23:00Z",
        "permission.requested",
        json!({
            "requestId": "r5",
            "promptRequest": {"kind": "path", "paths": ["/etc", "/usr/src"]},
            "permissionRequest": {"kind": "shell", "fullCommandText": "ls /etc /usr/src"},
        }),
    )
    .await;
    event(
        pool,
        "s1",
        "2026-10-01T08:23:02Z",
        "permission.completed",
        answered("r5", "approved"),
    )
    .await;
    // answered before it was asked: the clocks of two writers disagree
    event(
        pool,
        "s1",
        "2026-10-01T08:24:00Z",
        "permission.requested",
        asked("r6", "echo skew", commands_prompt("echo skew"), json!([])),
    )
    .await;
    event(
        pool,
        "s1",
        "2026-10-01T08:23:59Z",
        "permission.completed",
        answered("r6", "approved"),
    )
    .await;

    // no event says where it was: the session row does, and the same request
    // id in another session is another request
    session(pool, "s2", Some(a)).await;
    event(
        pool,
        "s2",
        "2026-10-01T09:00:00Z",
        "permission.requested",
        asked("r1", "ls other", commands_prompt("ls other"), json!([])),
    )
    .await;

    session(pool, "s3", None).await;
    event(
        pool,
        "s3",
        "2026-10-01T09:30:00Z",
        "permission.requested",
        asked("r8", "ls nowhere", commands_prompt("ls nowhere"), json!([])),
    )
    .await;

    // started in one place and resumed in another
    session(pool, "s4", None).await;
    event(
        pool,
        "s4",
        "2026-10-01T09:50:00Z",
        "session.start",
        json!({"context": {"cwd": a}}),
    )
    .await;
    event(
        pool,
        "s4",
        "2026-10-01T09:55:00Z",
        "permission.requested",
        asked("r9", "ls before", commands_prompt("ls before"), json!([])),
    )
    .await;
    event(
        pool,
        "s4",
        "2026-10-01T10:00:00Z",
        "session.resume",
        json!({"context": {"cwd": b}}),
    )
    .await;
    event(
        pool,
        "s4",
        "2026-10-01T10:05:00Z",
        "permission.requested",
        asked("r10", "ls after", commands_prompt("ls after"), json!([])),
    )
    .await;

    // started in a directory that is gone now
    session(pool, "s5", None).await;
    event(
        pool,
        "s5",
        "2026-10-01T11:00:00Z",
        "session.start",
        json!({"context": {"cwd": gone}}),
    )
    .await;
    event(
        pool,
        "s5",
        "2026-10-01T11:01:00Z",
        "permission.requested",
        asked("r11", "ls gone", commands_prompt("ls gone"), json!([])),
    )
    .await;
}

fn ids(history: &[Past]) -> Vec<(&str, &str)> {
    history
        .iter()
        .map(|p| (p.session_id.as_str(), p.request_id.as_str()))
        .collect()
}

fn find<'a>(history: &'a [Past], session: &str, request: &str) -> &'a Past {
    history
        .iter()
        .find(|p| p.session_id == session && p.request_id == request)
        .unwrap_or_else(|| panic!("no request {request} in {session}: {:?}", ids(history)))
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn the_history_is_read_the_way_the_report_needs_it() {
    let tmp = TempDir::new().unwrap();
    let (a, b, gone) = (
        tmp.path().join("a"),
        tmp.path().join("b"),
        tmp.path().join("gone"),
    );
    fs::create_dir_all(&a).unwrap();
    fs::create_dir_all(&b).unwrap();
    let text = |p: &Path| p.to_string_lossy().into_owned();
    let (a, b, gone) = (text(&a), text(&b), text(&gone));

    with_schema("replay_load", move |s| async move {
        let _keep = tmp;
        the_history(&s.pool, &a, &b, &gone).await;
        let all = load(&s.pool, None, None).await.unwrap();

        // oldest first; the read request is not a shell request
        assert_eq!(
            ids(&all),
            [
                ("s1", "r1"),
                ("s1", "r2"),
                ("s1", "r4"),
                ("s1", "r5"),
                ("s1", "r6"),
                ("s2", "r1"),
                ("s3", "r8"),
                ("s4", "r9"),
                ("s4", "r10"),
                ("s5", "r11"),
            ]
        );

        // the first question and the first answer are the ones that count
        let first = find(&all, "s1", "r1");
        assert_eq!(first.command, "ls first");
        assert_eq!(first.prompt_kind, "commands");
        assert_eq!(first.result.as_deref(), Some("approved"));
        assert_eq!(first.waited_s, Some(30.0));
        assert_eq!(first.not_read_only, ["rm", "git push"]);
        assert_eq!(first.asked_at, at("2026-10-01T08:00:00Z"));

        // the directory is the latest one at the time of the question
        assert_eq!(first.cwd.as_deref(), Some(a.as_str()));
        assert!(!first.cwd_gone);
        let later = find(&all, "s1", "r2");
        assert_eq!(later.cwd.as_deref(), Some(b.as_str()));
        assert_eq!((later.waited_s, later.result.as_deref()), (None, None));
        assert_eq!(find(&all, "s4", "r9").cwd.as_deref(), Some(a.as_str()));
        assert_eq!(find(&all, "s4", "r10").cwd.as_deref(), Some(b.as_str()));

        // without an event about it, the session's own directory, else none
        assert_eq!(find(&all, "s2", "r1").cwd.as_deref(), Some(a.as_str()));
        assert_eq!(find(&all, "s2", "r1").command, "ls other");
        let nowhere = find(&all, "s3", "r8");
        assert_eq!(nowhere.cwd, None);
        assert!(!nowhere.cwd_gone);

        let missing = find(&all, "s5", "r11");
        assert_eq!(missing.cwd.as_deref(), Some(gone.as_str()));
        assert!(missing.cwd_gone);

        // the command may be only in the prompt; a prompt may have no kind
        let prompt_only = find(&all, "s1", "r4");
        assert_eq!(prompt_only.command, "pwd");
        assert_eq!(prompt_only.prompt_kind, "unknown");

        let path = find(&all, "s1", "r5");
        assert_eq!(path.prompt_kind, "path");
        assert_eq!(path.paths, ["/etc", "/usr/src"]);
        assert_eq!(path.waited_s, Some(2.0));

        // an answer that came before the question says nothing about waiting
        let skew = find(&all, "s1", "r6");
        assert_eq!(skew.result.as_deref(), Some("approved"));
        assert_eq!(skew.waited_s, None);

        // since: from that moment on, inclusive
        let since = load(&s.pool, Some(at("2026-10-01T09:00:00Z")), None)
            .await
            .unwrap();
        assert_eq!(
            ids(&since),
            [
                ("s2", "r1"),
                ("s3", "r8"),
                ("s4", "r9"),
                ("s4", "r10"),
                ("s5", "r11")
            ]
        );

        // limit: the most recent ones, still oldest first
        let recent = load(&s.pool, None, Some(3)).await.unwrap();
        assert_eq!(ids(&recent), [("s4", "r9"), ("s4", "r10"), ("s5", "r11")]);

        let none = load(&s.pool, Some(at("2027-01-01T00:00:00Z")), None)
            .await
            .unwrap();
        assert!(none.is_empty());
    })
    .await;
}

fn past(id: &str, command: &str, cwd: &str, waited_s: Option<f64>, result: &str) -> Past {
    Past {
        session_id: "s".to_owned(),
        request_id: id.to_owned(),
        asked_at: at("2026-10-01T08:00:00Z"),
        prompt_kind: "commands".to_owned(),
        command: command.to_owned(),
        cwd: Some(cwd.to_owned()),
        cwd_gone: !Path::new(cwd).is_dir(),
        waited_s,
        result: Some(result.to_owned()),
        not_read_only: Vec::new(),
        paths: Vec::new(),
    }
}

#[test]
fn the_real_policy_answers_the_history_and_names_the_root_that_would_help() {
    let world = World::new();
    let home = world.home.to_string_lossy().into_owned();
    let config = Config::default();
    let policy = Policy::new(
        &world.home,
        &config,
        Vars::fixed(&[("HOME", home.as_str())]),
    );
    let judges = Judges::new(&policy, &config, &world.home);
    let judge =
        |command: &str, cwd: Option<&str>, assume: &[&str]| judges.judge(command, cwd, assume);

    let text = |name: &str| world.path(name).to_string_lossy().into_owned();
    let (kms, work, gone) = (text("kms"), text("work"), text("gone"));
    let history = vec![
        past("1", "ls -la", &kms, Some(0.2), "approved"),
        // outside the trusted roots: a root of `~/work` would answer both
        past("2", "cat x.txt", &work, Some(45.0), "approved"),
        past("3", "cat x.txt | sort", &work, Some(10.0), "approved"),
        // `sed` is not on the allow-list
        past("4", "sed -n 1p README.md", &kms, Some(20.0), "approved"),
        // a person said no to what the policy would have said yes to
        past(
            "5",
            "cat README.md",
            &kms,
            Some(90.0),
            "denied-interactively-by-user",
        ),
        // in a directory that is not there: its relative paths mean nothing
        past("6", "cat README.md", &gone, Some(5.0), "approved"),
    ];
    let report = analyze(&history, &judge, &home, 5);

    assert_eq!(report.requests, 6);
    assert_eq!(report.allowed, 2, "{:?}", report.allowed_by_rule);
    assert_eq!(report.in_place.requests, 5);
    assert_eq!(report.in_place.allowed, 2);
    assert_eq!(report.gone_cwd, 1);
    assert_eq!(report.slips.len(), 1);
    assert_eq!(report.slips[0].request_id, "5");
    assert!(report.flagged.is_empty());

    // 0.2 s and 90 s of 170.2 s were spent on what the policy would answer
    assert_eq!(report.waits.allowed, 2);
    assert!((report.waits.allowed_total_s - 90.2).abs() < 1e-9);
    assert!((report.waits.total_s - 170.2).abs() < 1e-9);
    assert_eq!(report.buckets.iter().map(|b| b.requests).sum::<usize>(), 6);
    assert_eq!(report.buckets[0].requests, 1);
    assert_eq!(report.buckets[0].allowed, 1);

    // a missing command, and what it would take to have it
    assert_eq!(report.missing.len(), 1);
    assert_eq!(report.missing[0].0, "sed");
    assert_eq!(report.what_if.unlockable, 1);
    assert_eq!(report.what_if.steps[0].command, "sed");
    assert_eq!(report.what_if.steps[0].gained, 1);
    assert!((report.what_if.steps[0].gained_wait_s - 20.0).abs() < 1e-9);

    // one more root: only `~/work` helps, and it helps two requests; the
    // directory that is gone cannot be judged at all, whatever is trusted
    assert_eq!(report.roots.untrusted, 2, "{:?}", report.pass_codes);
    let no_cwd = report.pass_codes.iter().find(|(code, _)| code == "no-cwd");
    assert_eq!(no_cwd.map(|(_, tally)| tally.requests), Some(1));
    assert_eq!(report.roots.unlockable, 2);
    assert_eq!(report.roots.rows.len(), 1, "{:?}", report.roots.rows);
    let row = &report.roots.rows[0];
    assert_eq!(row.root, "~/work");
    assert_eq!(row.requests, 2);
    assert!((row.wait_s - 55.0).abs() < 1e-9);
    assert_eq!(row.example, "cat x.txt");
}

#[test]
fn assumptions_lift_the_one_rule_they_name_and_no_other() {
    let world = World::new();
    let home = world.home.to_string_lossy().into_owned();
    let config = Config::default();
    let policy = Policy::new(
        &world.home,
        &config,
        Vars::fixed(&[("HOME", home.as_str())]),
    );
    let judges = Judges::new(&policy, &config, &world.home);
    let work = world.path("work").to_string_lossy().into_owned();
    let allowed = |assume: &[&str], command: &str| {
        matches!(
            judges.judge(command, Some(&work), assume),
            Verdict::Allow { .. }
        )
    };

    assert!(!allowed(&[], "cat x.txt"));
    assert!(allowed(&["root:~/work"], "cat x.txt"));
    // a root puts no command on the allow-list
    assert!(!allowed(&["root:~/work"], "sed -n 1p x.txt"));
    // an assumed command is taken as it comes, in any directory: that is the
    // bound the replay reports, and not a rule of the policy
    assert!(allowed(&["sed"], "sed -n 1p x.txt"));
    // but it lifts nothing for the other commands in the line
    assert!(!allowed(&["sed"], "cat x.txt | sed -n 1p"));
    assert!(allowed(&["root:~/work", "sed"], "cat x.txt | sed -n 1p"));
    // some other directory does not vouch for this one
    assert!(!allowed(&["root:~/other"], "cat x.txt"));
    assert!(!allowed(&["root:~/kms"], "cat x.txt"));
    // the deny list still holds inside a root that was added
    assert!(!allowed(&["root:~/work"], "cat .env"));
    // the same assumption twice is the same policy
    assert!(allowed(&["root:~/work", "root:~/work"], "cat x.txt"));
}
