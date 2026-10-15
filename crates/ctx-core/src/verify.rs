//! Acceptance checks for the mirror (PLAN §5, P1). Read-only, and it prints
//! counts only, never a value from the data.
//!
//!   1. every `events.jsonl` against `events` and `tool_calls`, up to the byte
//!      offset the ingester recorded, so a session that is still being written
//!      cannot cause a false alarm;
//!   2. the CLI's `session-store.db` against its mirror (keys everywhere, and
//!      token and price totals for usage);
//!   3. a secret scan run by PostgreSQL's own regex engine, with patterns
//!      written separately from the redactor's so one mistake cannot hide in
//!      both. It is proven first on canaries it must find and on redaction
//!      markers it must ignore;
//!   4. a fixed-point pass: running the redactor over the stored text must
//!      change nothing. Unlike (3) this covers the entropy rule, which SQL
//!      cannot express.
//!
//! The CLI keeps writing while this runs, so both comparisons stop where the
//! ingester says it stopped: events at the recorded byte offset of each file,
//! the store at the newest row id of each table that the last sync recorded.
//! What was written after that is not lost, only not synced yet. Whatever
//! still disagrees (a session that appeared since the last sync, a re-read in
//! progress) is looked at again a few seconds later; a mismatch that survives
//! three looks is real.
//!
//! The scan reads decoded string values (JSON leaves), not JSON text. The
//! redactor sees decoded strings too; scanning JSON syntax instead flags
//! numbers that follow a key like `"TokenMs":` and the `\n` of an escaped
//! newline after `SECRET=`, which are not leaks.

use std::collections::{HashMap, HashSet};
use std::fmt::Write as _;
use std::hash::Hash;
use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use futures_util::TryStreamExt;
use serde_json::{Value, json};
use sqlx::types::Json;
use sqlx::{AssertSqlSafe, PgExecutor, PgPool, Row};
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::info;

use crate::config::events_path;
use crate::db;
use crate::events::{DROP_KEYS, map_line};
use crate::ingest::{BATCH_BYTES, BATCH_LINES, Ingester};
use crate::reader::LineReader;
use crate::redact::{Counts, Redactor};
use crate::store;

/// Counts that disagree are looked at this many times before they are real.
const ATTEMPTS: u32 = 3;
const RETRY_DELAY: Duration = Duration::from_secs(3);
/// Values shorter than this cannot hold any secret pattern below (the
/// redactor skips them for the same reason).
const MIN_SCANNED_CHARS: usize = 12;
/// Session ids named in one finding.
const LISTED: usize = 6;

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Finding {
    pub name: String,
    pub ok: bool,
    pub detail: String,
}

impl Finding {
    pub fn new(name: impl Into<String>, ok: bool, detail: impl Into<String>) -> Self {
        Self {
            name: name.into(),
            ok,
            detail: detail.into(),
        }
    }
}

#[derive(Debug, Default)]
pub struct Verification {
    sections: Vec<(String, Vec<Finding>)>,
}

impl Verification {
    pub fn section(&mut self, title: &str, findings: impl IntoIterator<Item = Finding>) {
        self.sections
            .push((title.to_owned(), findings.into_iter().collect()));
    }

    pub fn findings(&self) -> impl Iterator<Item = &Finding> {
        self.sections.iter().flat_map(|(_, findings)| findings)
    }

    pub fn failures(&self) -> usize {
        self.findings().filter(|f| !f.ok).count()
    }

    pub fn ok(&self) -> bool {
        self.failures() == 0
    }

    pub fn render(&self) -> String {
        let mut out = String::new();
        for (title, findings) in &self.sections {
            let width = findings
                .iter()
                .map(|f| f.name.chars().count())
                .max()
                .unwrap_or(0);
            let _ = writeln!(out, "\n{title}");
            for f in findings {
                let mark = if f.ok { "ok  " } else { "FAIL" };
                let _ = writeln!(out, "  {mark}  {:<width$}  {}", f.name, f.detail);
            }
        }
        let verdict = if self.ok() {
            "PASS".to_owned()
        } else {
            format!("FAIL ({} checks)", self.failures())
        };
        let _ = writeln!(out, "\nresult: {verdict}");
        out
    }
}

/// `source` and `mirrored` hold the same number of rows.
fn same_count(name: &str, source_label: &str, source: u64, mirrored: u64) -> Finding {
    Finding::new(
        name,
        source == mirrored,
        format!("{source} {source_label}, {mirrored} in PostgreSQL"),
    )
}

/// Every source key is mirrored. Keys PostgreSQL holds beyond the source are
/// reported but fine: it is an archive and the CLI may delete what it wrote.
fn keyed<K: Hash + Eq>(
    name: &str,
    source: &HashSet<K>,
    mirrored: &HashSet<K>,
    extra: &str,
) -> Finding {
    let missing = source.iter().filter(|k| !mirrored.contains(*k)).count();
    let beyond = mirrored.iter().filter(|k| !source.contains(*k)).count();
    let mut detail = format!(
        "{} in the source, {} in PostgreSQL, {missing} missing",
        source.len(),
        mirrored.len()
    );
    if beyond > 0 {
        let _ = write!(detail, ", {beyond} {extra}");
    }
    Finding::new(name, missing == 0, detail)
}

// ---------------------------------------------------------------- events

#[derive(Debug, Default, Clone, PartialEq, Eq)]
struct Tally {
    events: u64,
    tool_calls: u64,
}

#[derive(Debug, Clone)]
struct SessionAudit {
    id: String,
    /// The ingester has a recorded offset for the file.
    read: bool,
    source: Tally,
    mirrored: Tally,
    rejected: u64,
}

impl SessionAudit {
    fn ok(&self) -> bool {
        self.read && self.source == self.mirrored
    }
}

/// Distinct event ids and tool-call ids in the first `limit` bytes of a file,
/// mapped by the code the ingester uses, and the number of lines that are not
/// events.
fn scan_prefix(path: &Path, limit: u64, redactor: &Redactor) -> io::Result<(Tally, u64)> {
    let mut reader = LineReader::open(path, 0)?;
    let mut events = HashSet::new();
    let mut tools = HashSet::new();
    let mut rejected = 0u64;
    let mut sink = Counts::default();
    'file: loop {
        let chunk = reader.next_chunk(BATCH_LINES, BATCH_BYTES)?;
        for line in &chunk.lines {
            if line.offset >= limit {
                break 'file;
            }
            match map_line(redactor, &line.bytes, line.offset, &mut sink) {
                Ok(mapped) => {
                    events.insert(mapped.event.event_id);
                    tools.extend(mapped.tool.map(|t| t.tool_call_id));
                }
                Err(_) => rejected += 1,
            }
        }
        if chunk.done {
            break;
        }
    }
    let tally = Tally {
        events: events.len() as u64,
        tool_calls: tools.len() as u64,
    };
    Ok((tally, rejected))
}

/// `None` when the file is gone by the time it is read.
async fn audit_session(
    pool: PgPool,
    redactor: Arc<Redactor>,
    dir: PathBuf,
    id: String,
) -> Result<Option<SessionAudit>> {
    // One statement, so the offset and both counts come from one snapshot.
    let row = sqlx::query(
        "SELECT (SELECT byte_offset FROM ingest_state WHERE source = 'events' AND key = $1),
                (SELECT count(*) FROM events WHERE session_id = $1),
                (SELECT count(*) FROM tool_calls WHERE session_id = $1)",
    )
    .bind(&id)
    .fetch_one(&pool)
    .await
    .with_context(|| format!("counting rows of session {id}"))?;
    let offset: Option<i64> = row.try_get(0)?;
    let mirrored = Tally {
        events: u64::try_from(row.try_get::<i64, _>(1)?).unwrap_or(0),
        tool_calls: u64::try_from(row.try_get::<i64, _>(2)?).unwrap_or(0),
    };
    let limit = offset.and_then(|o| u64::try_from(o).ok()).unwrap_or(0);
    let path = events_path(&dir.join(&id));
    let scanned = tokio::task::spawn_blocking(move || scan_prefix(&path, limit, &redactor)).await?;
    let (source, rejected) = match scanned {
        Ok(found) => found,
        Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(e).with_context(|| format!("reading the events of session {id}")),
    };
    Ok(Some(SessionAudit {
        id,
        read: offset.is_some(),
        source,
        mirrored,
        rejected,
    }))
}

// ------------------------------------------------------------ secret scan

/// A secret shape in PostgreSQL's regex dialect (ARE: `\y` is a word
/// boundary, `(?!…)` a lookahead).
struct Family {
    name: &'static str,
    pattern: &'static str,
}

const FAMILIES: &[Family] = &[
    Family {
        name: "pem",
        pattern: r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY( BLOCK)?-----[A-Za-z0-9+/=[:space:]\\:,._-]{16}",
    },
    Family {
        name: "github",
        pattern: r"gh[pousr]_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{22}",
    },
    Family {
        name: "aws",
        pattern: r"\y(AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}\y",
    },
    Family {
        name: "jwt",
        pattern: r"eyJ[A-Za-z0-9_-]{8}[A-Za-z0-9_-]*\.[A-Za-z0-9_-]{8}[A-Za-z0-9_-]*\.[A-Za-z0-9_-]{8}",
    },
    Family {
        name: "bearer",
        pattern: r"(?i)\ybearer[[:space:]]+[A-Za-z0-9._~+/=-]{30}",
    },
    Family {
        name: "slack",
        pattern: r"xox[baprs]-[A-Za-z0-9-]{10}|xapp-[0-9]-[A-Za-z0-9-]{10}",
    },
    Family {
        name: "stripe",
        pattern: r"\y[sr]k_(live|test)_[A-Za-z0-9]{16}",
    },
    Family {
        name: "google",
        pattern: r"AIza[0-9A-Za-z_-]{35}",
    },
    Family {
        name: "sk",
        pattern: r"\ysk-(ant-|proj-)?[A-Za-z0-9_-]{32}",
    },
    Family {
        name: "npm",
        pattern: r"\ynpm_[A-Za-z0-9]{36}",
    },
    Family {
        name: "gitlab",
        pattern: r"\yglpat-[A-Za-z0-9_-]{20}",
    },
    Family {
        name: "hf",
        pattern: r"\yhf_[A-Za-z0-9]{34}",
    },
    Family {
        name: "pypi",
        pattern: r"\ypypi-[A-Za-z0-9_-]{50}",
    },
    Family {
        name: "sendgrid",
        pattern: r"\ySG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}",
    },
    // The password of `scheme://user:password@host` that is not a marker.
    Family {
        name: "url_cred",
        pattern: r"://[^/[:space:]:@]+:(?!\[REDACTED:)[^@[:space:]/]{6,}@",
    },
    Family {
        name: "auth_header",
        pattern: r#"(?i)\yauthorization\y\\?["']?[[:space:]]*[:=][[:space:]]*\\?["']?(basic|bearer|token|digest)?[[:space:]]*[A-Za-z0-9._~+/=-]{16}"#,
    },
    // A secret-looking name, `:` or `=`, then a 12+ character literal (not a
    // `$variable`, path, call or marker).
    Family {
        name: "assign",
        pattern: r#"(?i)(password|passwd|pwd|secret|api[_-]?key|token|private[_-]?key|credential)[A-Za-z0-9_.-]*\\?["']?[ \t]*[:=][ \t]*\\?["']?[^[:space:]"'<>;&|)(\\$:/\[][^[:space:]"'<>;&|)(\\]{11,}"#,
    },
];

const ALNUM: &[u8; 62] = b"abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
const UPPER_DIGITS: &[u8; 36] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";

/// `n` characters that vary like a random token. Deterministic, and no real
/// secret is involved.
fn alnum(n: usize, seed: usize) -> String {
    (0..n)
        .map(|i| char::from(ALNUM[(i * 7 + seed * 13 + i * i) % ALNUM.len()]))
        .collect()
}

fn upper_digits(n: usize, seed: usize) -> String {
    (0..n)
        .map(|i| char::from(UPPER_DIGITS[(i * 5 + seed * 11 + i * i) % UPPER_DIGITS.len()]))
        .collect()
}

/// A planted secret of each family. Assembled at run time, in pieces, so this
/// file never contains a literal that real secret scanners would flag.
fn canary(family: &str) -> String {
    match family {
        "pem" => format!(
            "-----{} RSA PRIVATE KEY-----\n{}\n-----{} RSA PRIVATE KEY-----",
            "BEGIN",
            alnum(64, 1),
            "END"
        ),
        "github" => format!("gh{}_{}", "p", alnum(36, 2)),
        "aws" => format!("AK{}{}", "IA", upper_digits(16, 3)),
        "jwt" => format!(
            "ey{}{}.{}.{}",
            "J",
            alnum(12, 4),
            alnum(12, 5),
            alnum(12, 6)
        ),
        "bearer" => format!("Bearer {}", alnum(34, 7)),
        "slack" => format!("xox{}-{}", "b", "1234567890123"),
        "stripe" => format!("sk_{}_{}", "live", alnum(24, 8)),
        "google" => format!("AI{}{}", "za", alnum(35, 9)),
        "sk" => format!("sk-{}", alnum(40, 10)),
        "npm" => format!("npm_{}", alnum(36, 11)),
        "gitlab" => format!("glpat-{}", alnum(22, 12)),
        "hf" => format!("hf_{}", alnum(36, 13)),
        "pypi" => format!("pypi-{}", alnum(60, 14)),
        "sendgrid" => format!("SG.{}.{}", alnum(22, 15), alnum(43, 16)),
        "url_cred" => format!("postgres://svc_user:{}@db.internal/app", alnum(12, 17)),
        "auth_header" => format!("Authorization: Basic {}", alnum(24, 18)),
        "assign" => format!("db_password = {}", alnum(16, 19)),
        other => panic!("no canary for the `{other}` family"),
    }
}

/// One synthetic secret per family the scan looks for, as `(family, value)`.
/// The integration tests plant them in the sources to show that none of them
/// reaches PostgreSQL.
pub fn planted_secrets() -> Vec<(&'static str, String)> {
    FAMILIES.iter().map(|f| (f.name, canary(f.name))).collect()
}

/// Text that looks like a secret's neighbourhood but holds none: what the
/// redactor leaves behind, and ordinary prose. The scan must stay silent.
const MASKED: &[&str] = &[
    "Authorization: Bearer [REDACTED:bearer:0a1b2c3d]",
    "curl -H 'Authorization: Basic [REDACTED:auth_header:0a1b2c3d]' https://example.test",
    "postgres://svc_user:[REDACTED:url_cred:0a1b2c3d]@db.internal/app",
    "db_password = [REDACTED:assign:0a1b2c3d] and token: [REDACTED:key:0a1b2c3d]",
    "see ssh://git@example.test:org/repo.git, then https://example.test/a?b=c",
    "the tokens are counted per request; the secret is in the vault, not here",
    "export TOKEN=$(cat /run/secrets/token) && echo password=$PASSWORD_FILE_CONTENTS",
];

#[derive(Clone, Copy, PartialEq, Eq)]
enum Kind {
    Text,
    Json,
}

/// Something the scan reads: a table column (quoted for SQL by PostgreSQL
/// itself, never by hand) and an optional row filter.
struct Source {
    table: String,
    column: String,
    kind: Kind,
    filter: Option<&'static str>,
}

impl Source {
    /// A query yielding one `t` per scanned string: the column itself for
    /// text, every decoded string leaf for JSON.
    fn strings_sql(&self) -> String {
        let (table, column) = (&self.table, &self.column);
        let filter = self.filter.map(|f| format!(" AND {f}")).unwrap_or_default();
        match self.kind {
            Kind::Text => format!(
                "SELECT x.{column}::text AS t FROM {table} x WHERE x.{column} IS NOT NULL{filter}"
            ),
            Kind::Json => format!(
                "SELECT l #>> '{{}}' AS t FROM {table} x \
                 CROSS JOIN LATERAL jsonb_path_query(x.{column}::jsonb, 'strict $.** ? (@.type() == \"string\")') AS l \
                 WHERE x.{column} IS NOT NULL{filter}"
            ),
        }
    }

    fn scan_sql(&self) -> String {
        let mut sql = String::from("SELECT count(*)");
        for i in 1..=FAMILIES.len() {
            let _ = write!(sql, ", count(*) FILTER (WHERE s.t ~ ${i})");
        }
        let _ = write!(
            sql,
            " FROM ({}) s WHERE length(s.t) >= {MIN_SCANNED_CHARS}",
            self.strings_sql()
        );
        sql
    }
}

#[derive(Debug, Default, PartialEq, Eq)]
struct Scan {
    /// Strings long enough to hold a secret.
    scanned: i64,
    /// Strings matching each family, in `FAMILIES` order.
    hits: Vec<i64>,
}

impl Scan {
    fn total(&self) -> i64 {
        self.hits.iter().sum()
    }

    fn families(&self) -> String {
        FAMILIES
            .iter()
            .zip(&self.hits)
            .filter(|(_, n)| **n > 0)
            .map(|(f, n)| format!("{}={n}", f.name))
            .collect::<Vec<_>>()
            .join(", ")
    }
}

async fn scan_source<'e, E: PgExecutor<'e>>(exec: E, source: &Source) -> Result<Scan> {
    let sql = source.scan_sql();
    let mut query = sqlx::query(AssertSqlSafe(sql));
    for family in FAMILIES {
        query = query.bind(family.pattern);
    }
    let row = query.fetch_one(exec).await?;
    let mut hits = Vec::with_capacity(FAMILIES.len());
    for i in 0..FAMILIES.len() {
        hits.push(row.try_get::<i64, _>(i + 1)?);
    }
    Ok(Scan {
        scanned: row.try_get(0)?,
        hits,
    })
}

#[derive(Debug, Clone)]
struct Column {
    /// Quoted by PostgreSQL's `quote_ident`.
    table: String,
    column: String,
    /// For messages.
    label: String,
    json: bool,
    /// Stored verbatim, see [`VERBATIM`].
    verbatim: bool,
}

impl Column {
    fn source(&self) -> Source {
        Source {
            table: self.table.clone(),
            column: self.column.clone(),
            kind: if self.json { Kind::Json } else { Kind::Text },
            filter: None,
        }
    }
}

/// Columns the ingester stores as they come: identifiers, hashes and keys. They
/// never went through the redactor (random-looking ids would trip its entropy
/// rule and stop being joinable), so the fixed-point pass leaves them out; the
/// pattern scan still reads every one of them. The list is explicit on
/// purpose: a column added later is re-checked until someone decides it is an
/// identifier and says so here.
const VERBATIM: &[(&str, &str)] = &[
    ("checkpoints", "session_id"),
    ("checkpoints", "src_hash"),
    ("ctx_meta", "key"),
    ("ctx_meta", "value"),
    ("events", "session_id"),
    ("events", "event_id"),
    ("events", "parent_id"),
    ("events", "ctx"),
    ("events", "agent_id"),
    ("events", "parent_tool_call_id"),
    ("hook_audit", "uid"),
    ("hook_audit", "session_id"),
    ("hook_audit", "cmd_sha"),
    ("hook_audit", "policy"),
    ("ingest_state", "key"),
    ("ingest_state", "head_sha"),
    ("redactions", "session_id"),
    ("session_files", "session_id"),
    ("session_refs", "session_id"),
    ("sessions", "id"),
    ("tool_calls", "session_id"),
    ("tool_calls", "tool_call_id"),
    ("tool_calls", "ctx"),
    ("tool_calls", "parent_tool_call_id"),
    ("turns", "session_id"),
    ("turns", "src_hash"),
    ("usage", "session_id"),
    ("usage", "agent_id"),
    ("usage", "parent_tool_call_id"),
];

fn is_verbatim(table: &str, column: &str) -> bool {
    VERBATIM.contains(&(table, column))
}

// --------------------------------------------------------------- verifier

pub struct Verifier {
    ingester: Ingester,
}

impl Verifier {
    pub fn new(ingester: Ingester) -> Self {
        Self { ingester }
    }

    fn pool(&self) -> &PgPool {
        self.ingester.pool()
    }

    /// Runs every check. An `Err` means a check could not run (database or
    /// file trouble); a failed check is a [`Finding`] with `ok == false`.
    pub async fn run(&self, jobs: usize) -> Result<Verification> {
        let mut report = Verification::default();

        let counts = db::table_counts(self.pool()).await?;
        let rows = counts
            .iter()
            .map(|(table, n)| format!("{table} {n}"))
            .collect::<Vec<_>>()
            .join(", ");
        report.section("PostgreSQL rows", [Finding::new("tables", true, rows)]);

        info!("comparing events.jsonl files with the mirror");
        report.section(
            "events.jsonl files against events and tool_calls",
            self.events(jobs).await?,
        );

        info!("comparing session-store.db with the mirror");
        report.section("session-store.db against its mirror", self.store().await?);

        info!("scanning for secrets");
        let columns = self.columns().await?;
        let mut scan = self.canaries().await?;
        scan.extend(self.scan(&columns).await?);
        report.section(
            "secret scan (PostgreSQL regexes, written apart from the redactor's)",
            scan,
        );

        info!("re-redacting stored text in memory");
        report.section(
            "redactor fixed point (stored text must not change when redacted again)",
            self.fixed_point(&columns).await?,
        );
        Ok(report)
    }

    // ---- events

    async fn audit_sessions(&self, ids: Vec<String>, jobs: usize) -> Result<Vec<SessionAudit>> {
        let root = self.ingester.config().session_state_dir();
        let permits = Arc::new(Semaphore::new(jobs.max(1)));
        let mut tasks = JoinSet::new();
        for id in ids {
            let permit = Arc::clone(&permits).acquire_owned().await?;
            let (pool, redactor, root) = (
                self.pool().clone(),
                Arc::clone(self.ingester.redactor()),
                root.clone(),
            );
            tasks.spawn(async move {
                let _permit = permit;
                audit_session(pool, redactor, root, id).await
            });
        }
        let mut audits = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            audits.extend(joined.context("an audit task panicked")??);
        }
        Ok(audits)
    }

    async fn events(&self, jobs: usize) -> Result<Vec<Finding>> {
        let with_files: Vec<String> = self
            .ingester
            .list_sessions()?
            .into_iter()
            .filter(|s| s.events_size.is_some())
            .map(|s| s.id)
            .collect();
        let mut audits: HashMap<String, SessionAudit> = HashMap::new();
        let mut pending = with_files.clone();
        let mut attempt = 1;
        loop {
            for audit in self
                .audit_sessions(std::mem::take(&mut pending), jobs)
                .await?
            {
                audits.insert(audit.id.clone(), audit);
            }
            pending = audits
                .values()
                .filter(|a| !a.ok())
                .map(|a| a.id.clone())
                .collect();
            if pending.is_empty() || attempt == ATTEMPTS {
                break;
            }
            attempt += 1;
            tokio::time::sleep(RETRY_DELAY).await;
        }

        let sum = |pick: fn(&Tally) -> u64, mirrored: bool| -> u64 {
            audits
                .values()
                .map(|a| pick(if mirrored { &a.mirrored } else { &a.source }))
                .sum()
        };
        let mut out = vec![Finding::new(
            "files",
            true,
            format!("{} sessions have an events.jsonl", with_files.len()),
        )];
        out.push(same_count(
            "events",
            "in the files up to the recorded offsets",
            sum(|t| t.events, false),
            sum(|t| t.events, true),
        ));
        out.push(same_count(
            "tool_calls",
            "in the files up to the recorded offsets",
            sum(|t| t.tool_calls, false),
            sum(|t| t.tool_calls, true),
        ));

        let mut unread: Vec<&SessionAudit> = audits.values().filter(|a| !a.read).collect();
        unread.sort_by(|a, b| a.id.cmp(&b.id));
        out.push(Finding::new(
            "never read",
            unread.is_empty(),
            listing(
                unread.iter().map(|a| a.id.as_str()),
                "sessions have a file but no ingest state",
            ),
        ));
        let mut off: Vec<&SessionAudit> = audits.values().filter(|a| a.read && !a.ok()).collect();
        off.sort_by(|a, b| a.id.cmp(&b.id));
        out.push(Finding::new(
            "out of step",
            off.is_empty(),
            listing(
                off.iter().map(|a| a.id.as_str()),
                "sessions whose row counts differ from their file",
            ),
        ));
        let rejected: u64 = audits.values().map(|a| a.rejected).sum();
        out.push(Finding::new(
            "rejected lines",
            true,
            format!("{rejected} lines are not events and are skipped, as at ingest"),
        ));

        let ids: Vec<String> = audits.keys().cloned().collect();
        let kept: i64 = sqlx::query_scalar(
            "SELECT count(DISTINCT session_id) FROM events WHERE session_id <> ALL($1)",
        )
        .bind(&ids)
        .fetch_one(self.pool())
        .await?;
        out.push(Finding::new(
            "kept",
            true,
            format!("{kept} sessions in PostgreSQL have events but no events.jsonl any more"),
        ));
        if attempt > 1 && out.iter().all(|f| f.ok) {
            out.push(Finding::new(
                "settled",
                true,
                format!("agreed on look {attempt}: the files were still being written"),
            ));
        }
        Ok(out)
    }

    // ---- session-store.db

    async fn store(&self) -> Result<Vec<Finding>> {
        let db = self.ingester.config().store_db();
        if !db.exists() {
            return Ok(vec![Finding::new(
                "session-store.db",
                true,
                "not present, nothing to compare",
            )]);
        }
        let mut attempt = 1;
        loop {
            let mut findings = self.compare_store(&db).await?;
            let clean = findings.iter().all(|f| f.ok);
            if clean || attempt == ATTEMPTS {
                if clean && attempt > 1 {
                    findings.push(Finding::new(
                        "settled",
                        true,
                        format!("agreed on look {attempt}: the store was still being written"),
                    ));
                }
                return Ok(findings);
            }
            attempt += 1;
            tokio::time::sleep(RETRY_DELAY).await;
        }
    }

    async fn compare_store(&self, db: &Path) -> Result<Vec<Finding>> {
        let pool = self.pool();
        // Marks first: whatever a sync running right now commits afterwards
        // can only add to what the marks already promise.
        let marks: HashMap<String, i64> = sqlx::query_as::<_, (String, Option<i64>)>(
            "SELECT key, watermark FROM ingest_state WHERE source = 'store'",
        )
        .fetch_all(pool)
        .await?
        .into_iter()
        .filter_map(|(table, mark)| Some((table, mark?)))
        .collect();
        let unsynced: Vec<&str> = store::MARKED_TABLES
            .iter()
            .copied()
            .filter(|table| !marks.contains_key(*table))
            .collect();
        if !unsynced.is_empty() {
            return Ok(vec![Finding::new(
                "synced",
                false,
                format!(
                    "the store was never mirrored (no mark for {})",
                    unsynced.join(", ")
                ),
            )]);
        }

        let redactor = Arc::clone(self.ingester.redactor());
        let path = db.to_owned();
        let inv = {
            let marks = marks.clone();
            tokio::task::spawn_blocking(move || store::inventory(&path, &redactor, &marks))
                .await??
        };

        let sessions: HashSet<String> = sqlx::query_scalar("SELECT id FROM sessions")
            .fetch_all(pool)
            .await?
            .into_iter()
            .collect();
        let turns: HashSet<(String, i32)> =
            sqlx::query_as("SELECT session_id, turn_index FROM turns")
                .fetch_all(pool)
                .await?
                .into_iter()
                .collect();
        let checkpoints: HashSet<(String, i32)> =
            sqlx::query_as("SELECT session_id, checkpoint_number FROM checkpoints")
                .fetch_all(pool)
                .await?
                .into_iter()
                .collect();
        let files: HashSet<(String, String)> =
            sqlx::query_as("SELECT session_id, file_path FROM session_files")
                .fetch_all(pool)
                .await?
                .into_iter()
                .collect();
        let refs: HashSet<(String, String, String)> =
            sqlx::query_as("SELECT session_id, ref_type, ref_value FROM session_refs")
                .fetch_all(pool)
                .await?
                .into_iter()
                .collect();
        let usage_ids: HashSet<i64> = sqlx::query_scalar("SELECT src_id FROM usage")
            .fetch_all(pool)
            .await?
            .into_iter()
            .collect();
        let source_ids: HashSet<i64> = inv.usage_ids.iter().copied().collect();

        // Totals over the rows both sides have, so one missing row does not
        // hide behind a compensating one.
        let (n, nano_aiu, input, output, cache_read, cache_write): (i64, i64, i64, i64, i64, i64) =
            sqlx::query_as(
                "SELECT count(*), coalesce(sum(nano_aiu), 0)::bigint, coalesce(sum(input), 0)::bigint,
                        coalesce(sum(output), 0)::bigint, coalesce(sum(cache_read), 0)::bigint,
                        coalesce(sum(cache_write), 0)::bigint
                   FROM usage WHERE src_id = ANY($1)",
            )
            .bind(&inv.usage_ids)
            .fetch_one(pool)
            .await?;
        let mirrored = store::UsageSums {
            nano_aiu,
            input,
            output,
            cache_read,
            cache_write,
        };
        let totals = &inv.usage_sums;

        let mut out = vec![
            keyed(
                "sessions",
                &inv.sessions,
                &sessions,
                "more come from session directories and events",
            ),
            keyed(
                "usage rows",
                &source_ids,
                &usage_ids,
                "kept after the source dropped them",
            ),
            Finding::new(
                "usage totals",
                *totals == mirrored && usize::try_from(n).ok() == Some(inv.usage_ids.len()),
                format!(
                    "nano-AIU {} / {}, input tokens {} / {}, output {} / {}, cache read {} / {}, cache write {} / {} (source / PostgreSQL)",
                    totals.nano_aiu,
                    mirrored.nano_aiu,
                    totals.input,
                    mirrored.input,
                    totals.output,
                    mirrored.output,
                    totals.cache_read,
                    mirrored.cache_read,
                    totals.cache_write,
                    mirrored.cache_write,
                ),
            ),
            keyed(
                "turns",
                &inv.turns,
                &turns,
                "kept after the source dropped them",
            ),
            keyed(
                "checkpoints",
                &inv.checkpoints,
                &checkpoints,
                "kept after the source dropped them",
            ),
            keyed(
                "session_files",
                &inv.files,
                &files,
                "kept after the source dropped them",
            ),
            keyed(
                "session_refs",
                &inv.refs,
                &refs,
                "kept after the source dropped them",
            ),
        ];
        if inv.newer > 0 {
            out.push(Finding::new(
                "newer",
                true,
                format!(
                    "{} store rows were written after the last sync and are left out of the comparison",
                    inv.newer
                ),
            ));
        }
        if inv.usage_unmirrorable > 0 {
            out.push(Finding::new(
                "usage skipped",
                true,
                format!(
                    "{} source rows have no session or timestamp and are not mirrored",
                    inv.usage_unmirrorable
                ),
            ));
        }
        Ok(out)
    }

    // ---- secret scan

    /// Every text or JSON column of the schema.
    async fn columns(&self) -> Result<Vec<Column>> {
        let rows = sqlx::query(
            "SELECT c.relname::text, quote_ident(c.relname), a.attname::text, quote_ident(a.attname),
                    t.typname IN ('json', 'jsonb')
               FROM pg_class c
               JOIN pg_namespace n ON n.oid = c.relnamespace
               JOIN pg_attribute a ON a.attrelid = c.oid
               JOIN pg_type t ON t.oid = a.atttypid
              WHERE n.nspname = current_schema() AND c.relkind IN ('r', 'p')
                AND a.attnum > 0 AND NOT a.attisdropped
                AND t.typname IN ('text', 'varchar', 'bpchar', 'name', 'json', 'jsonb')
              ORDER BY c.relname, a.attnum",
        )
        .fetch_all(self.pool())
        .await?;
        let mut out = Vec::with_capacity(rows.len());
        for row in rows {
            let raw_table: String = row.try_get(0)?;
            let raw_column: String = row.try_get(2)?;
            out.push(Column {
                table: row.try_get(1)?,
                column: row.try_get(3)?,
                label: format!("{raw_table}.{raw_column}"),
                json: row.try_get(4)?,
                verbatim: is_verbatim(&raw_table, &raw_column),
            });
        }
        Ok(out)
    }

    /// Proves the scan can see: each family finds a planted secret, in plain
    /// text and nested in JSON, and ignores markers and ordinary prose.
    /// Everything happens in a transaction that is rolled back.
    async fn canaries(&self) -> Result<Vec<Finding>> {
        let mut tx = self.pool().begin().await?;
        sqlx::query(
            "CREATE TEMP TABLE ctx_canary_text (t text NOT NULL, planted boolean NOT NULL)",
        )
        .execute(&mut *tx)
        .await?;
        sqlx::query(
            "CREATE TEMP TABLE ctx_canary_json (b jsonb NOT NULL, planted boolean NOT NULL)",
        )
        .execute(&mut *tx)
        .await?;
        let planted = FAMILIES.iter().map(|f| (canary(f.name), true));
        let masked = MASKED.iter().map(|m| ((*m).to_owned(), false));
        for (value, is_planted) in planted.chain(masked) {
            sqlx::query("INSERT INTO ctx_canary_text (t, planted) VALUES ($1, $2)")
                .bind(format!("value: {value} end"))
                .bind(is_planted)
                .execute(&mut *tx)
                .await?;
            sqlx::query("INSERT INTO ctx_canary_json (b, planted) VALUES ($1, $2)")
                .bind(Json(json!({"outer": [{"inner": value}], "n": 1})))
                .bind(is_planted)
                .execute(&mut *tx)
                .await?;
        }

        let sources = [
            ("plain text", Kind::Text, "pg_temp.ctx_canary_text", "t"),
            ("nested JSON", Kind::Json, "pg_temp.ctx_canary_json", "b"),
        ];
        let mut missed: Vec<String> = Vec::new();
        let mut noisy: Vec<String> = Vec::new();
        for (label, kind, table, column) in sources {
            let source = |filter| Source {
                table: table.to_owned(),
                column: column.to_owned(),
                kind,
                filter: Some(filter),
            };
            let found = scan_source(&mut *tx, &source("x.planted")).await?;
            for (family, hits) in FAMILIES.iter().zip(&found.hits) {
                if *hits < 1 {
                    missed.push(format!("{} in {label}", family.name));
                }
            }
            let quiet = scan_source(&mut *tx, &source("NOT x.planted")).await?;
            if quiet.total() > 0 {
                noisy.push(format!("{label}: {}", quiet.families()));
            }
        }
        tx.rollback().await?;

        Ok(vec![
            Finding::new(
                "canaries",
                missed.is_empty(),
                if missed.is_empty() {
                    format!(
                        "{} patterns each found a planted secret, in plain text and nested in JSON",
                        FAMILIES.len()
                    )
                } else {
                    format!("not found: {}", missed.join(", "))
                },
            ),
            Finding::new(
                "masked values",
                noisy.is_empty(),
                if noisy.is_empty() {
                    format!(
                        "{} redaction markers and look-alikes are not flagged",
                        MASKED.len()
                    )
                } else {
                    format!("wrongly flagged: {}", noisy.join("; "))
                },
            ),
        ])
    }

    async fn scan(&self, columns: &[Column]) -> Result<Vec<Finding>> {
        let mut values = 0i64;
        let mut hits = 0i64;
        let mut flagged = Vec::new();
        for column in columns {
            let found = scan_source(self.pool(), &column.source())
                .await
                .with_context(|| format!("scanning {}", column.label))?;
            values += found.scanned;
            hits += found.total();
            if found.total() > 0 {
                flagged.push(Finding::new(column.label.clone(), false, found.families()));
            }
        }
        let mut out = vec![Finding::new(
            "stored text",
            hits == 0,
            format!(
                "{values} strings in {} columns, {} patterns: {hits} matches",
                columns.len(),
                FAMILIES.len()
            ),
        )];
        out.extend(flagged);
        Ok(out)
    }

    // ---- fixed point

    async fn fixed_point(&self, columns: &[Column]) -> Result<Vec<Finding>> {
        let redactor = self.ingester.redactor();
        let mut values = 0u64;
        let mut total = Counts::default();
        let mut flagged = Vec::new();
        let mut scanned_columns = 0usize;
        for column in columns.iter().filter(|c| !c.verbatim) {
            scanned_columns += 1;
            let cast = if column.json { "::jsonb" } else { "::text" };
            let sql = format!(
                "SELECT {c}{cast} FROM {t} WHERE {c} IS NOT NULL",
                c = column.column,
                t = column.table
            );
            let mut counts = Counts::default();
            let mut rows = sqlx::query(AssertSqlSafe(sql)).fetch(self.pool());
            while let Some(row) = rows.try_next().await? {
                values += 1;
                if column.json {
                    let Json(value): Json<Value> = row.try_get(0)?;
                    redactor.json(value, DROP_KEYS, &mut counts);
                } else {
                    let text: String = row.try_get(0)?;
                    redactor.text(&text, &mut counts);
                }
            }
            if !counts.is_empty() {
                flagged.push(Finding::new(column.label.clone(), false, kinds(&counts)));
                total.merge(&counts);
            }
        }
        let mut out = vec![Finding::new(
            "re-redaction",
            total.is_empty(),
            format!(
                "{values} values in {scanned_columns} columns re-read; the redactor would still replace {}",
                total.total()
            ),
        )];
        out.extend(flagged);
        Ok(out)
    }
}

fn kinds(counts: &Counts) -> String {
    counts
        .iter()
        .map(|(kind, n)| format!("{kind}={n}"))
        .collect::<Vec<_>>()
        .join(", ")
}

/// `0` when empty, else `N what: id, id, ... (+M more)`.
fn listing<'a>(ids: impl Iterator<Item = &'a str>, what: &str) -> String {
    let ids: Vec<&str> = ids.collect();
    if ids.is_empty() {
        return "0".to_owned();
    }
    let shown = ids
        .iter()
        .take(LISTED)
        .copied()
        .collect::<Vec<_>>()
        .join(", ");
    let more = ids.len().saturating_sub(LISTED);
    if more > 0 {
        format!("{} {what}: {shown} (+{more} more)", ids.len())
    } else {
        format!("{} {what}: {shown}", ids.len())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn events_file(lines: &[&str], tail: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        let mut file = std::fs::File::create(&path).unwrap();
        for line in lines {
            writeln!(file, "{line}").unwrap();
        }
        file.write_all(tail).unwrap();
        (dir, path)
    }

    fn event(id: &str, ty: &str, data: &str) -> String {
        format!(
            r#"{{"id":"{id}","type":"{ty}","timestamp":"2026-10-01T08:00:00.000Z","data":{data}}}"#
        )
    }

    #[test]
    fn prefix_counts_distinct_ids_and_stops_at_the_limit() {
        let first = event(
            "e1",
            "tool.execution_start",
            r#"{"toolCallId":"t1","toolName":"bash"}"#,
        );
        let again = event(
            "e1",
            "tool.execution_start",
            r#"{"toolCallId":"t1","toolName":"bash"}"#,
        );
        let done = event(
            "e2",
            "tool.execution_complete",
            r#"{"toolCallId":"t1","success":true}"#,
        );
        let other = event("e3", "assistant.turn_start", "{}");
        let late = event("e4", "assistant.turn_start", "{}");
        let (_dir, path) = events_file(
            &[&first, &again, &done, "this is not an event", &other, &late],
            &[0u8; 64],
        );
        let redactor = Redactor::new();

        let whole = std::fs::metadata(&path).unwrap().len();
        let (tally, rejected) = scan_prefix(&path, whole, &redactor).unwrap();
        assert_eq!(
            tally,
            Tally {
                events: 4,
                tool_calls: 1
            }
        );
        assert_eq!(rejected, 1);

        // Up to the byte where the last line starts: the late event is not counted.
        let late_offset = std::fs::read(&path)
            .unwrap()
            .windows(late.len())
            .position(|w| w == late.as_bytes())
            .unwrap() as u64;
        let (tally, _) = scan_prefix(&path, late_offset, &redactor).unwrap();
        assert_eq!(
            tally,
            Tally {
                events: 3,
                tool_calls: 1
            }
        );

        let (tally, rejected) = scan_prefix(&path, 0, &redactor).unwrap();
        assert_eq!((tally, rejected), (Tally::default(), 0));
    }

    #[test]
    fn a_missing_file_is_not_found() {
        let err =
            scan_prefix(Path::new("/nonexistent/events.jsonl"), 10, &Redactor::new()).unwrap_err();
        assert_eq!(err.kind(), io::ErrorKind::NotFound);
    }

    #[test]
    fn keyed_fails_only_on_missing_keys() {
        let source: HashSet<i32> = [1, 2, 3].into();
        let all: HashSet<i32> = [1, 2, 3, 4].into();
        let some: HashSet<i32> = [1, 3].into();
        let fine = keyed("t", &source, &all, "kept");
        assert!(fine.ok);
        assert!(fine.detail.contains("1 kept"), "{}", fine.detail);
        let bad = keyed("t", &source, &some, "kept");
        assert!(!bad.ok);
        assert!(bad.detail.contains("1 missing"), "{}", bad.detail);
    }

    #[test]
    fn the_report_lines_up_and_the_verdict_follows_the_findings() {
        let mut report = Verification::default();
        report.section(
            "first",
            [
                Finding::new("a", true, "fine"),
                Finding::new("longer", true, "also fine"),
            ],
        );
        assert!(report.ok());
        report.section("second", [Finding::new("b", false, "broken")]);
        assert_eq!(report.failures(), 1);
        let text = report.render();
        assert!(text.contains("  ok    a       fine\n"), "{text}");
        assert!(text.contains("  ok    longer  also fine\n"), "{text}");
        assert!(text.contains("  FAIL  b  broken\n"), "{text}");
        assert!(text.ends_with("result: FAIL (1 checks)\n"), "{text}");
    }

    #[test]
    fn listing_names_a_few_sessions() {
        assert_eq!(listing(std::iter::empty(), "x"), "0");
        assert_eq!(
            listing(["a", "b"].into_iter(), "sessions differ"),
            "2 sessions differ: a, b"
        );
        let many: Vec<String> = (0..9).map(|i| format!("s{i}")).collect();
        let text = listing(many.iter().map(String::as_str), "sessions differ");
        assert!(
            text.starts_with("9 sessions differ: s0, s1, s2, s3, s4, s5 (+3 more)"),
            "{text}"
        );
    }

    #[test]
    fn only_identifiers_and_hashes_are_exempt_from_the_fixed_point() {
        for (table, column) in [
            ("events", "ctx"),
            ("tool_calls", "ctx"),
            ("events", "event_id"),
            ("turns", "src_hash"),
            ("ingest_state", "head_sha"),
            ("hook_audit", "cmd_sha"),
            ("hook_audit", "policy"),
        ] {
            assert!(is_verbatim(table, column), "{table}.{column}");
        }
        for (table, column) in [
            ("hook_audit", "cmd_preview"),
            ("hook_audit", "cwd"),
            ("hook_audit", "tool"),
            ("hook_audit", "rule"),
            ("events", "body"),
            ("tool_calls", "args"),
            ("tool_calls", "result_text"),
            ("turns", "user_message"),
            ("sessions", "summary"),
            ("session_files", "file_path"),
            ("session_refs", "ref_value"),
            ("checkpoints", "overview"),
            ("events", "no_such_column"),
        ] {
            assert!(!is_verbatim(table, column), "{table}.{column}");
        }
        let unique: HashSet<_> = VERBATIM.iter().collect();
        assert_eq!(unique.len(), VERBATIM.len(), "duplicate entries");
    }

    #[test]
    fn every_family_has_a_canary_the_redactor_also_recognises() {
        let redactor = Redactor::new();
        for family in FAMILIES {
            let planted = canary(family.name);
            let mut counts = Counts::default();
            let cleaned = redactor.text(&planted, &mut counts);
            assert!(
                counts.total() > 0 && cleaned != planted,
                "the redactor does not see the `{}` canary",
                family.name
            );
        }
    }

    #[test]
    fn masked_values_are_left_alone_by_the_redactor_too() {
        let redactor = Redactor::new();
        for text in MASKED {
            let mut counts = Counts::default();
            assert_eq!(redactor.text(text, &mut counts), *text);
            assert!(counts.is_empty(), "redactor changed: {text}");
        }
    }

    #[test]
    fn canaries_are_distinct_and_built_from_pieces() {
        let all: HashSet<String> = FAMILIES.iter().map(|f| canary(f.name)).collect();
        assert_eq!(all.len(), FAMILIES.len());
    }

    #[test]
    fn scan_sql_binds_one_pattern_per_family_and_reads_json_leaves() {
        let text = Source {
            table: "\"turns\"".into(),
            column: "\"user_message\"".into(),
            kind: Kind::Text,
            filter: None,
        };
        let sql = text.scan_sql();
        assert_eq!(sql.matches("FILTER").count(), FAMILIES.len());
        assert!(sql.contains(&format!("${}", FAMILIES.len())));
        assert!(!sql.contains(&format!("${}", FAMILIES.len() + 1)));
        assert!(!sql.contains("jsonb_path_query"));

        let json = Source {
            table: "\"events\"".into(),
            column: "\"body\"".into(),
            kind: Kind::Json,
            filter: Some("x.planted"),
        };
        let sql = json.scan_sql();
        assert!(sql.contains("jsonb_path_query(x.\"body\"::jsonb"), "{sql}");
        assert!(sql.contains("AND x.planted"), "{sql}");
    }
}
