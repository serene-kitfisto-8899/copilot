//! The audit trail: one `hook_audit` row per hook invocation (PLAN.md §6.6).
//!
//! What the hook decided is written down before anything is said to the CLI, so
//! that an automatic approval can always be explained afterwards. The row goes
//! to PostgreSQL when that answers within [`DB_DEADLINE`]; otherwise it is
//! appended to a spool file that `ctx-hook review` imports later, each row once
//! (`uid` is unique). An approval is sent only when the row has reached one of
//! the two.
//!
//! Everything that came from the request is redacted first, like the rest of
//! the database (`ctx_core::redact`). `session_id`, `uid`, `cmd_sha` and
//! `policy` are identifiers and hashes, stored as they are.

use std::io::Write as _;
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::str::FromStr;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use ctx_core::db::sha256_hex;
use ctx_core::redact::{Counts, Redactor, cap};
use serde::{Deserialize, Serialize};
use sqlx::postgres::PgConnectOptions;
use sqlx::{Connection, PgConnection};

use crate::config::xdg;
use crate::payload::Request;
use crate::policy::Verdict;
use crate::vars::Vars;

/// The part of a command kept readable in `cmd_preview`.
pub const PREVIEW_BYTES: usize = 500;
/// How long the hook waits for PostgreSQL before it spools the row instead.
/// A connection over the local socket takes a few milliseconds.
pub const DB_DEADLINE: Duration = Duration::from_millis(40);
/// A spool this big means PostgreSQL has been away for a long time: nothing is
/// appended any more (so nothing is approved) until `review` has drained it.
pub const MAX_SPOOL_BYTES: u64 = 8 * 1024 * 1024;
/// How long a drain waits after moving the spool aside, for a hook that had
/// opened the old file a moment earlier to finish its single write.
const WRITER_GRACE: Duration = Duration::from_millis(100);
/// The sessions that `ctx-hook bench` makes its rows under. `review` leaves
/// them out, so a benchmark that was interrupted before it cleaned up cannot
/// leave its rows in the numbers.
pub const BENCH_SESSION_PREFIX: &str = "ctx-hook-bench-";

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Row {
    pub uid: String,
    pub ts: DateTime<Utc>,
    pub session_id: String,
    pub tool: String,
    pub cmd_sha: Option<String>,
    pub cmd_preview: Option<String>,
    pub cwd: Option<String>,
    /// `allow` or `pass`, whatever the mode: in shadow mode an `allow` is what
    /// the hook would have approved.
    pub decision: String,
    pub rule: String,
    /// The hook was not approving anything: shadow mode, or a configuration it
    /// could not use.
    pub shadow: bool,
    pub latency_us: Option<i32>,
    pub policy: String,
}

impl Row {
    pub fn build(
        redactor: &Redactor,
        req: &Request,
        verdict: &Verdict,
        shadow: bool,
        policy: &str,
        uid: String,
    ) -> Row {
        let mut counts = Counts::default();
        // The hash is of the same text the ingester stores for the command in
        // the `permission.requested` event, which is how `review` joins them.
        let command = req
            .command
            .as_deref()
            .map(|c| redactor.field(c, &mut counts));
        Row {
            uid,
            ts: req.ts,
            session_id: req.session_id.clone(),
            tool: redactor.text(&req.tool, &mut counts),
            cmd_sha: command.as_deref().map(|c| sha256_hex(c.as_bytes())),
            cmd_preview: command.as_deref().map(|c| cap(c, PREVIEW_BYTES)),
            cwd: req.cwd.as_deref().map(|c| redactor.field(c, &mut counts)),
            decision: if verdict.is_allow() { "allow" } else { "pass" }.to_owned(),
            rule: redactor.text(&verdict.rule(), &mut counts),
            shadow,
            latency_us: None,
            policy: policy.to_owned(),
        }
    }
}

/// Unique for every row ever made: the clock, the process and a counter.
pub fn new_uid() -> String {
    static COUNTER: AtomicU64 = AtomicU64::new(0);
    let nanos = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| d.as_nanos());
    format!(
        "{nanos:x}-{:x}-{:x}",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed)
    )
}

const INSERT: &str = "INSERT INTO hook_audit
    (uid, ts, session_id, tool, cmd_sha, cmd_preview, cwd, decision, rule, shadow, latency_us, policy)
    VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10, $11, $12)
    ON CONFLICT (uid) DO NOTHING";

/// `false` when a row with this `uid` is already there.
pub async fn insert(conn: &mut PgConnection, row: &Row) -> Result<bool, sqlx::Error> {
    let done = sqlx::query(INSERT)
        .persistent(false)
        .bind(&row.uid)
        .bind(row.ts)
        .bind(&row.session_id)
        .bind(&row.tool)
        .bind(&row.cmd_sha)
        .bind(&row.cmd_preview)
        .bind(&row.cwd)
        .bind(&row.decision)
        .bind(&row.rule)
        .bind(row.shadow)
        .bind(row.latency_us)
        .bind(&row.policy)
        .execute(conn)
        .await?;
    Ok(done.rows_affected() == 1)
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Recorded {
    /// In `hook_audit`.
    Db,
    /// In the spool file, because PostgreSQL did not answer in time.
    Spool(String),
    /// Nowhere.
    Lost(String),
}

impl Recorded {
    pub fn kept(&self) -> bool {
        !matches!(self, Recorded::Lost(_))
    }
}

/// Writes the row to PostgreSQL, or failing that to the spool.
pub fn record(row: &Row, database_url: &str, spool: &Path) -> Recorded {
    match insert_within(database_url, row, DB_DEADLINE) {
        Ok(_) => Recorded::Db,
        Err(why) => match append_spool(spool, row) {
            Ok(()) => Recorded::Spool(why),
            Err(e) => Recorded::Lost(format!("{why}; spool {}: {e}", spool.display())),
        },
    }
}

fn insert_within(url: &str, row: &Row, deadline: Duration) -> Result<bool, String> {
    let rt = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()
        .map_err(|e| format!("runtime: {e}"))?;
    // `timeout` looks for the timer when it is called, which has to be inside
    // the runtime and not in the argument of `block_on`
    let outcome = rt.block_on(async {
        tokio::time::timeout(deadline, async {
            let options = PgConnectOptions::from_str(url)
                .map_err(|e| format!("url: {e}"))?
                .application_name("ctx-hook");
            let mut conn = PgConnection::connect_with(&options)
                .await
                .map_err(|e| format!("connect: {e}"))?;
            let fresh = insert(&mut conn, row)
                .await
                .map_err(|e| format!("insert: {e}"))?;
            let _ = conn.close().await;
            Ok::<bool, String>(fresh)
        })
        .await
    });
    rt.shutdown_background();
    outcome.unwrap_or_else(|_| Err(format!("no answer within {} ms", deadline.as_millis())))
}

/// `$XDG_STATE_HOME/ctx/hook-spool.jsonl`, `~/.local/state/ctx/hook-spool.jsonl`
/// by default.
pub fn spool_path(vars: &Vars, home: &Path) -> PathBuf {
    xdg(vars, "XDG_STATE_HOME", home, ".local/state").join("ctx/hook-spool.jsonl")
}

/// One line per row, in a single `write` on a file opened for appending, so
/// that hooks running at the same time cannot interleave their rows.
pub fn append_spool(path: &Path, row: &Row) -> std::io::Result<()> {
    if let Some(dir) = path.parent() {
        std::fs::DirBuilder::new()
            .recursive(true)
            .mode(0o700)
            .create(dir)?;
    }
    let mut line = serde_json::to_vec(row).map_err(std::io::Error::other)?;
    line.push(b'\n');
    let mut file = std::fs::OpenOptions::new()
        .create(true)
        .append(true)
        .mode(0o600)
        .open(path)?;
    if file.metadata()?.len() > MAX_SPOOL_BYTES {
        return Err(std::io::Error::other(format!(
            "the spool is over {MAX_SPOOL_BYTES} bytes: run `ctx-hook review` to import it"
        )));
    }
    file.write_all(&line)
}

/// Whether an error says something about this one row and nothing about the
/// database: a value that cannot be stored (SQLSTATE class 22, data exception)
/// or a constraint it breaks (class 23). A missing table is class 42 and a
/// server on its way down is 57, and neither is a reason to give up a row.
fn row_is_at_fault(error: &sqlx::Error) -> bool {
    match error {
        sqlx::Error::Encode(_) => true,
        other => other
            .as_database_error()
            .and_then(|e| e.code())
            .is_some_and(|code| code.starts_with("22") || code.starts_with("23")),
    }
}

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Drained {
    pub files: usize,
    pub rows: usize,
    /// Rows that were not in the table yet.
    pub inserted: usize,
    /// Lines that are not rows, or that the table refused. They are kept in
    /// `<spool>.rejected` for a human to look at.
    pub rejected: usize,
}

/// Imports the spool into `hook_audit` and removes it. Safe to repeat and to
/// run twice at once: rows are keyed by `uid`, and the spool is moved aside
/// first, so that rows appended meanwhile land in a fresh file.
pub async fn drain(conn: &mut PgConnection, spool: &Path) -> Result<Drained> {
    let mut drained = Drained::default();
    let (Some(dir), Some(name)) = (spool.parent(), spool.file_name().and_then(|n| n.to_str()))
    else {
        return Ok(drained);
    };
    let aside = dir.join(format!("{name}.{}.draining", new_uid()));
    match std::fs::rename(spool, &aside) {
        Ok(()) => tokio::time::sleep(WRITER_GRACE).await,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
        Err(e) => return Err(e).with_context(|| format!("moving {} aside", spool.display())),
    }
    let mut files: Vec<PathBuf> = match std::fs::read_dir(dir) {
        Ok(entries) => entries
            .flatten()
            .map(|e| e.path())
            .filter(|p| {
                p.file_name()
                    .and_then(|n| n.to_str())
                    .is_some_and(|n| n.starts_with(&format!("{name}.")) && n.ends_with(".draining"))
            })
            .collect(),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Vec::new(),
        Err(e) => return Err(e).with_context(|| format!("listing {}", dir.display())),
    };
    files.sort();
    for file in files {
        let bytes = match std::fs::read(&file) {
            Ok(bytes) => bytes,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => continue,
            Err(e) => return Err(e).with_context(|| format!("reading {}", file.display())),
        };
        drained.files += 1;
        let mut rejects: Vec<&str> = Vec::new();
        let text = String::from_utf8_lossy(&bytes);
        for line in text.lines().filter(|l| !l.trim().is_empty()) {
            let Ok(row) = serde_json::from_str::<Row>(line) else {
                rejects.push(line);
                continue;
            };
            drained.rows += 1;
            match insert(conn, &row).await {
                Ok(true) => drained.inserted += 1,
                Ok(false) => {}
                Err(e) if row_is_at_fault(&e) => {
                    drained.rows -= 1;
                    rejects.push(line);
                }
                // Not the row's doing (no table yet, the server going down, a
                // deadlock): the file stays where it is and the next drain
                // tries it again
                Err(e) => return Err(e).context("importing the spooled audit rows"),
            }
        }
        if !rejects.is_empty() {
            drained.rejected += rejects.len();
            let mut kept = std::fs::OpenOptions::new()
                .create(true)
                .append(true)
                .mode(0o600)
                .open(dir.join(format!("{name}.rejected")))?;
            for line in rejects {
                writeln!(kept, "{line}")?;
            }
        }
        match std::fs::remove_file(&file) {
            Ok(()) => {}
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => return Err(e).with_context(|| format!("removing {}", file.display())),
        }
    }
    Ok(drained)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::CAPTURED;
    use ctx_core::verify::planted_secrets;
    use std::os::unix::fs::PermissionsExt;
    use std::sync::LazyLock;

    /// Building a `Redactor` compiles every rule: once per test run is plenty.
    fn redactor() -> &'static Redactor {
        static REDACTOR: LazyLock<Redactor> = LazyLock::new(Redactor::new);
        &REDACTOR
    }

    fn verdict(allow: bool) -> Verdict {
        if allow {
            Verdict::Allow {
                tags: "ls".to_owned(),
            }
        } else {
            Verdict::Pass {
                code: "cmd-not-allowed:python3".to_owned(),
            }
        }
    }

    fn request(command: &str) -> Request {
        let mut req = Request::bash(command, Some("/home/u/kms"), Utc::now());
        req.session_id = "s-1".to_owned();
        req
    }

    fn row(command: &str) -> Row {
        Row::build(
            redactor(),
            &request(command),
            &verdict(true),
            true,
            "v1:abcd1234",
            new_uid(),
        )
    }

    #[test]
    fn a_row_says_what_was_decided_about_what() {
        let r = row("ls -la src");
        assert_eq!(r.session_id, "s-1");
        assert_eq!(r.tool, "bash");
        assert_eq!(r.decision, "allow");
        assert_eq!(r.rule, "allow:ls");
        assert!(r.shadow);
        assert_eq!(r.cmd_preview.as_deref(), Some("ls -la src"));
        assert_eq!(r.cwd.as_deref(), Some("/home/u/kms"));
        assert_eq!(r.policy, "v1:abcd1234");
        assert_eq!(r.latency_us, None);
        let pass = Row::build(
            redactor(),
            &request("python3 x.py"),
            &verdict(false),
            false,
            "p",
            new_uid(),
        );
        assert_eq!(
            (pass.decision.as_str(), pass.rule.as_str()),
            ("pass", "pass:cmd-not-allowed:python3")
        );
        assert!(!pass.shadow);
    }

    #[test]
    fn the_hash_is_of_the_redacted_text_and_there_is_none_without_a_command() {
        let long = "x ".repeat(6000);
        for command in ["ls", "echo hi # a comment", long.as_str()] {
            let r = row(command);
            let stored = redactor().field(command, &mut Counts::default());
            assert_eq!(
                r.cmd_sha,
                Some(sha256_hex(stored.as_bytes())),
                "{command:.30}"
            );
        }
        let mut req = request("ls");
        req.command = None;
        let r = Row::build(redactor(), &req, &verdict(false), true, "p", new_uid());
        assert_eq!((r.cmd_sha, r.cmd_preview), (None, None));
    }

    #[test]
    fn long_commands_are_previewed_in_part_and_hashed_whole() {
        let command = format!("echo {}", "word ".repeat(400));
        let r = row(&command);
        let preview = r.cmd_preview.unwrap();
        assert!(preview.starts_with("echo word word"));
        assert!(preview.len() < PREVIEW_BYTES + 40, "{}", preview.len());
        assert!(preview.contains("bytes]"), "{preview}");
        assert_eq!(r.cmd_sha.unwrap(), sha256_hex(command.as_bytes()));
    }

    #[test]
    fn secrets_never_reach_a_row() {
        let secrets = planted_secrets();
        assert!(secrets.len() >= 10, "the families: {}", secrets.len());
        for (family, secret) in &secrets {
            let mut req = request(&format!(
                "curl -H 'Authorization: {secret}' https://x.example"
            ));
            req.cwd = Some(format!("/home/u/{secret}"));
            req.tool = format!("tool-{secret}");
            let v = Verdict::Pass {
                code: format!("cmd-not-allowed:{secret}"),
            };
            let r = Row::build(redactor(), &req, &v, true, "p", new_uid());
            let all = serde_json::to_string(&r).unwrap();
            let needle = secret
                .split(|c: char| !c.is_ascii_alphanumeric())
                .max_by_key(|run| run.len())
                .unwrap();
            assert!(needle.len() >= 12, "{family}");
            assert!(!all.contains(needle), "{family} leaked into {all}");
            assert!(all.contains("[REDACTED:"), "{family}: {all}");
        }
    }

    #[test]
    fn nul_bytes_do_not_get_through() {
        let r = row("echo a\u{0}b");
        let all = serde_json::to_string(&r).unwrap();
        assert!(!all.contains("\\u0000"), "{all}");
    }

    #[test]
    fn captured_payload_becomes_a_row() {
        let req = Request::parse(CAPTURED.as_bytes(), Utc::now());
        let r = Row::build(redactor(), &req, &verdict(true), true, "p", new_uid());
        assert_eq!(r.session_id, "b5b9fbf1-124d-4b43-8215-1f8ece76583c");
        assert_eq!(r.cmd_preview.as_deref(), Some("ls /usr/lib/postgresql"));
        assert_eq!(r.cwd.as_deref(), Some("/tmp/p3nest"));
    }

    #[test]
    fn uids_do_not_repeat() {
        let mut seen = std::collections::HashSet::new();
        for _ in 0..20_000 {
            assert!(seen.insert(new_uid()));
        }
        assert!(
            seen.iter()
                .all(|u| u.bytes().all(|b| b.is_ascii_hexdigit() || b == b'-'))
        );
    }

    #[test]
    fn spool_files_are_private_and_hold_one_row_per_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("state/ctx/hook-spool.jsonl");
        let rows: Vec<Row> = (0..3).map(|i| row(&format!("ls {i}"))).collect();
        for r in &rows {
            append_spool(&path, r).unwrap();
        }
        let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode(&path), 0o600);
        assert_eq!(mode(path.parent().unwrap()), 0o700);
        let text = std::fs::read_to_string(&path).unwrap();
        let back: Vec<Row> = text
            .lines()
            .map(|l| serde_json::from_str(l).unwrap())
            .collect();
        assert_eq!(back, rows);
    }

    #[test]
    fn a_full_spool_refuses_more_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        std::fs::write(&path, vec![b'x'; MAX_SPOOL_BYTES as usize + 1]).unwrap();
        let err = append_spool(&path, &row("ls")).unwrap_err();
        assert!(err.to_string().contains("ctx-hook review"), "{err}");
    }

    #[test]
    fn spooling_races_do_not_interleave_rows() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("spool.jsonl");
        std::thread::scope(|s| {
            for t in 0..8 {
                let path = &path;
                s.spawn(move || {
                    for i in 0..50 {
                        let command = format!("echo {t} {i} {}", "y".repeat(3000));
                        append_spool(path, &row(&command)).unwrap();
                    }
                });
            }
        });
        let text = std::fs::read_to_string(&path).unwrap();
        assert_eq!(text.lines().count(), 400);
        for line in text.lines() {
            serde_json::from_str::<Row>(line).unwrap();
        }
    }

    const NO_DATABASE: &str = "postgres:///nope?host=/nonexistent/dir&user=x";

    #[test]
    fn without_a_database_the_row_is_spooled_quickly() {
        let dir = tempfile::tempdir().unwrap();
        let spool = dir.path().join("spool.jsonl");
        let started = std::time::Instant::now();
        let recorded = record(&row("ls"), NO_DATABASE, &spool);
        assert!(
            matches!(recorded, Recorded::Spool(ref why) if why.contains("connect")),
            "{recorded:?}"
        );
        assert!(recorded.kept());
        assert!(
            started.elapsed() < Duration::from_millis(500),
            "{:?}",
            started.elapsed()
        );
        assert_eq!(std::fs::read_to_string(&spool).unwrap().lines().count(), 1);
    }

    #[test]
    fn with_no_database_and_no_spool_the_row_is_lost_and_says_so() {
        let dir = tempfile::tempdir().unwrap();
        let blocker = dir.path().join("file");
        std::fs::write(&blocker, "x").unwrap();
        let spool = blocker.join("sub/spool.jsonl");
        let recorded = record(&row("ls"), NO_DATABASE, &spool);
        assert!(matches!(recorded, Recorded::Lost(_)), "{recorded:?}");
        assert!(!recorded.kept());
    }

    #[test]
    fn a_malformed_url_is_a_spool_not_a_panic() {
        let dir = tempfile::tempdir().unwrap();
        let recorded = record(&row("ls"), "not a url at all", &dir.path().join("s.jsonl"));
        assert!(
            matches!(recorded, Recorded::Spool(ref why) if why.contains("url")),
            "{recorded:?}"
        );
    }

    #[test]
    fn the_spool_lives_under_the_xdg_state_directory() {
        let home = Path::new("/home/u");
        assert_eq!(
            spool_path(&Vars::fixed(&[]), home),
            PathBuf::from("/home/u/.local/state/ctx/hook-spool.jsonl")
        );
        assert_eq!(
            spool_path(&Vars::fixed(&[("XDG_STATE_HOME", "/st")]), home),
            PathBuf::from("/st/ctx/hook-spool.jsonl")
        );
    }
}
