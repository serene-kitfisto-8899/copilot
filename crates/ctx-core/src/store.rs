//! Mirror of the CLI's `session-store.db` (SQLite) into PostgreSQL.
//!
//! The file is opened read-only and read inside one deferred transaction, so
//! the tables are consistent with each other. Text columns go through the
//! redactor; `assistant_usage_events` (the only per-call source of cache
//! read/write tokens and of the price table) is copied as numbers.
//!
//! Change detection is by content, not by position:
//!   * `turns` / `checkpoints`: SHA-256 of the raw source row (`src_hash`);
//!   * `assistant_usage_events`: the set of source ids already in PostgreSQL.
//!     A watermark would miss rows after id reuse, and reading all ids is a
//!     few milliseconds, so every sync reconciles the complete id set.

use std::collections::{HashMap, HashSet};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;

use anyhow::{Context, Result};
use chrono::{DateTime, NaiveDateTime, SecondsFormat, Utc};
use rusqlite::types::ValueRef;
use rusqlite::{Connection, OpenFlags, Row};
use serde_json::{Value, json};
use sqlx::PgPool;
use sqlx::types::Json;
use tracing::{info, warn};

use crate::db::sha256_hex;
use crate::events::parse_ts;
use crate::redact::{Counts, Redactor};
use crate::writer::{self, SessionMeta, TitleAuthority};

/// Long-form columns (messages, checkpoint sections) are capped, defensively;
/// the largest value seen in real data is ~40 KB.
const MAX_TEXT_BYTES: usize = 64 * 1024;
const MAX_TITLE_BYTES: usize = 4096;
const WRITE_CHUNK: usize = 500;
const USAGE_CHUNK: usize = 2000;

/// Source tables whose newest row id every sync records (`ingest_state`,
/// `source = 'store'`, `key = <table>`). It lets `verify` tell a row the mirror
/// has not seen yet, because it was written after the sync's snapshot, from a
/// row the mirror lost.
pub const MARKED_TABLES: [&str; 6] = [
    "sessions",
    "turns",
    "checkpoints",
    "session_files",
    "session_refs",
    "assistant_usage_events",
];

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    pub sessions_seen: u64,
    /// Rows inserted or changed in PostgreSQL by this sync.
    pub turns_changed: u64,
    pub checkpoints_changed: u64,
    pub files_changed: u64,
    pub refs_changed: u64,
    pub usage_changed: u64,
    /// Usage rows that could not be mapped (unparseable timestamp).
    pub usage_rejected: u64,
}

impl Report {
    pub fn changed(&self) -> u64 {
        self.turns_changed
            + self.checkpoints_changed
            + self.files_changed
            + self.refs_changed
            + self.usage_changed
    }
}

/// What PostgreSQL already holds, to skip unchanged source rows.
#[derive(Default)]
struct Have {
    turns: HashMap<(String, i32), String>,
    checkpoints: HashMap<(String, i32), String>,
    usage: HashSet<i64>,
}

#[derive(Default)]
struct Prepared {
    sessions: Vec<(String, SessionMeta)>,
    turns: Vec<Value>,
    checkpoints: Vec<Value>,
    files: Vec<Value>,
    refs: Vec<Value>,
    usage: Vec<Value>,
    usage_rejected: u64,
    /// `max(rowid)` of each [`MARKED_TABLES`] table, 0 when empty, from the
    /// snapshot the rows were read from.
    marks: Vec<(&'static str, i64)>,
    sessions_seen: u64,
}

/// `2026-10-01T08:00:00.123Z` or `2026-10-01 08:00:00` (UTC), both occur.
pub fn parse_store_ts(text: &str) -> Option<DateTime<Utc>> {
    let text = text.trim();
    parse_ts(text).or_else(|| {
        ["%Y-%m-%d %H:%M:%S%.f", "%Y-%m-%dT%H:%M:%S%.f"]
            .iter()
            .find_map(|fmt| NaiveDateTime::parse_from_str(text, fmt).ok())
            .map(|naive| naive.and_utc())
    })
}

fn iso(ts: DateTime<Utc>) -> String {
    ts.to_rfc3339_opts(SecondsFormat::Micros, true)
}

// SQLite is dynamically typed: a column declared INTEGER may hold REAL and
// vice versa, so values are read by their stored type, not their declared one.
fn text(row: &Row<'_>, idx: usize) -> rusqlite::Result<Option<String>> {
    Ok(match row.get_ref(idx)? {
        ValueRef::Null => None,
        ValueRef::Text(t) => Some(String::from_utf8_lossy(t).into_owned()),
        ValueRef::Integer(i) => Some(i.to_string()),
        ValueRef::Real(f) => Some(f.to_string()),
        ValueRef::Blob(_) => None,
    })
}

fn int(row: &Row<'_>, idx: usize) -> rusqlite::Result<Option<i64>> {
    Ok(match row.get_ref(idx)? {
        ValueRef::Integer(i) => Some(i),
        ValueRef::Real(f) if f.is_finite() => Some(f.round() as i64),
        ValueRef::Text(t) => std::str::from_utf8(t)
            .ok()
            .and_then(|s| s.trim().parse().ok()),
        _ => None,
    })
}

fn real(row: &Row<'_>, idx: usize) -> rusqlite::Result<Option<f64>> {
    Ok(match row.get_ref(idx)? {
        ValueRef::Integer(i) => Some(i as f64),
        ValueRef::Real(f) if f.is_finite() => Some(f),
        ValueRef::Text(t) => std::str::from_utf8(t)
            .ok()
            .and_then(|s| s.trim().parse().ok()),
        _ => None,
    })
}

fn flag(row: &Row<'_>, idx: usize) -> rusqlite::Result<Option<bool>> {
    Ok(int(row, idx)?.map(|v| v != 0))
}

/// SHA-256 over length-prefixed parts, so no two different rows collide by
/// moving a boundary between fields.
fn row_hash(parts: &[Option<&str>]) -> String {
    let mut buf = Vec::new();
    for part in parts {
        match part {
            Some(s) => {
                buf.extend_from_slice(s.len().to_string().as_bytes());
                buf.push(b':');
                buf.extend_from_slice(s.as_bytes());
            }
            None => buf.push(b'~'),
        }
        buf.push(0);
    }
    sha256_hex(&buf)
}

fn redact_opt(
    redactor: &Redactor,
    value: Option<String>,
    max_bytes: usize,
    counts: &mut Counts,
) -> Option<String> {
    value.map(|v| redactor.field_capped(&v, max_bytes, counts))
}

fn redact_nonblank(
    redactor: &Redactor,
    value: Option<String>,
    max_bytes: usize,
    counts: &mut Counts,
) -> Option<String> {
    redact_opt(
        redactor,
        value.filter(|v| !v.trim().is_empty()),
        max_bytes,
        counts,
    )
}

/// The form in which a source file path or reference value is stored (it is
/// part of the primary key, so redaction and the cap decide what "the same row"
/// means). `verify` uses it to line the two sides up.
pub fn mirrored_key(redactor: &Redactor, raw: &str) -> String {
    redactor.field_capped(raw, MAX_TITLE_BYTES, &mut Counts::default())
}

fn open(db: &Path) -> Result<Connection> {
    let conn = Connection::open_with_flags(
        db,
        OpenFlags::SQLITE_OPEN_READ_ONLY | OpenFlags::SQLITE_OPEN_NO_MUTEX,
    )
    .with_context(|| format!("opening {} read-only", db.display()))?;
    conn.busy_timeout(Duration::from_secs(10))?;
    conn.pragma_update(None, "query_only", true)?;
    Ok(conn)
}

/// Reads the whole store and returns only what PostgreSQL does not have yet.
fn prepare(db: &Path, redactor: &Redactor, have: &Have, force: bool) -> Result<Prepared> {
    let conn = open(db)?;
    let tx = conn.unchecked_transaction()?;
    let mut out = Prepared::default();
    // Ids only grow (AUTOINCREMENT; `sessions` has the implicit rowid, which
    // repeats only if its newest row is deleted), so everything at or below a
    // mark is part of this snapshot.
    for table in MARKED_TABLES {
        let mark: i64 = tx.query_row(
            &format!("SELECT coalesce(max(rowid), 0) FROM {table}"),
            [],
            |row| row.get(0),
        )?;
        out.marks.push((table, mark));
    }
    // 'store' redaction counts are recounted from the mirrored text in SQL
    // (unchanged rows are not re-redacted, so they could not be tallied here).
    let mut counts = Counts::default();

    {
        let mut stmt = tx.prepare(
            "SELECT id, cwd, repository, host_type, branch, summary, created_at, updated_at
             FROM sessions",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let Some(id) = text(row, 0)? else { continue };
            out.sessions_seen += 1;
            let meta = SessionMeta {
                cwd: redact_nonblank(redactor, text(row, 1)?, MAX_TITLE_BYTES, &mut counts),
                repository: redact_nonblank(redactor, text(row, 2)?, MAX_TITLE_BYTES, &mut counts),
                host_type: redact_nonblank(redactor, text(row, 3)?, MAX_TITLE_BYTES, &mut counts),
                branch: redact_nonblank(redactor, text(row, 4)?, MAX_TITLE_BYTES, &mut counts),
                summary: redact_nonblank(redactor, text(row, 5)?, MAX_TITLE_BYTES, &mut counts),
                started_at: text(row, 6)?.as_deref().and_then(parse_store_ts),
                ended_at: text(row, 7)?.as_deref().and_then(parse_store_ts),
                ..SessionMeta::default()
            };
            out.sessions.push((id, meta));
        }
    }

    {
        let mut stmt = tx.prepare(
            "SELECT session_id, turn_index, user_message, assistant_response, timestamp
             FROM turns ORDER BY session_id, turn_index",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let (Some(sid), Some(idx)) = (text(row, 0)?, int(row, 1)?) else {
                continue;
            };
            let user = text(row, 2)?;
            let assistant = text(row, 3)?;
            let ts = text(row, 4)?;
            let hash = row_hash(&[
                Some(&sid),
                Some(&idx.to_string()),
                user.as_deref(),
                assistant.as_deref(),
                ts.as_deref(),
            ]);
            let idx32 = i32::try_from(idx).unwrap_or(i32::MAX);
            if !force && have.turns.get(&(sid.clone(), idx32)) == Some(&hash) {
                continue;
            }
            out.turns.push(json!({
                "session_id": sid,
                "turn_index": idx32,
                "user_message": redact_opt(redactor, user, MAX_TEXT_BYTES, &mut counts),
                "assistant_response": redact_opt(redactor, assistant, MAX_TEXT_BYTES, &mut counts),
                "ts": ts.as_deref().and_then(parse_store_ts).map(iso),
                "src_hash": hash,
            }));
        }
    }

    {
        let mut stmt = tx.prepare(
            "SELECT session_id, checkpoint_number, title, overview, history, work_done,
                    technical_details, important_files, next_steps, created_at
             FROM checkpoints ORDER BY session_id, checkpoint_number",
        )?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            let (Some(sid), Some(num)) = (text(row, 0)?, int(row, 1)?) else {
                continue;
            };
            let mut sections = Vec::with_capacity(7);
            for idx in 2..9 {
                sections.push(text(row, idx)?);
            }
            let created = text(row, 9)?;
            let num32 = i32::try_from(num).unwrap_or(i32::MAX);
            let mut parts: Vec<Option<&str>> = vec![Some(&sid)];
            let num_text = num.to_string();
            parts.push(Some(&num_text));
            parts.extend(sections.iter().map(Option::as_deref));
            parts.push(created.as_deref());
            let hash = row_hash(&parts);
            if !force && have.checkpoints.get(&(sid.clone(), num32)) == Some(&hash) {
                continue;
            }
            let mut red = sections
                .into_iter()
                .map(|s| redact_opt(redactor, s, MAX_TEXT_BYTES, &mut counts));
            out.checkpoints.push(json!({
                "session_id": sid,
                "checkpoint_number": num32,
                "title": red.next().flatten(),
                "overview": red.next().flatten(),
                "history": red.next().flatten(),
                "work_done": red.next().flatten(),
                "technical_details": red.next().flatten(),
                "important_files": red.next().flatten(),
                "next_steps": red.next().flatten(),
                "created_at": created.as_deref().and_then(parse_store_ts).map(iso),
                "src_hash": hash,
            }));
        }
    }

    {
        let mut stmt = tx.prepare(
            "SELECT session_id, file_path, tool_name, turn_index, first_seen_at FROM session_files",
        )?;
        let mut rows = stmt.query([])?;
        let mut seen: HashMap<(String, String), usize> = HashMap::new();
        while let Some(row) = rows.next()? {
            let (Some(sid), Some(path)) = (text(row, 0)?, text(row, 1)?) else {
                continue;
            };
            let path = mirrored_key(redactor, &path);
            let value = json!({
                "session_id": sid,
                "file_path": path,
                "tool_name": text(row, 2)?,
                "turn_index": int(row, 3)?.and_then(|v| i32::try_from(v).ok()),
                "first_seen_at": text(row, 4)?.as_deref().and_then(parse_store_ts).map(iso),
            });
            // Redaction can map two different raw paths to one value.
            match seen.entry((sid, path)) {
                std::collections::hash_map::Entry::Occupied(slot) => out.files[*slot.get()] = value,
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(out.files.len());
                    out.files.push(value);
                }
            }
        }
    }

    {
        let mut stmt = tx.prepare(
            "SELECT session_id, ref_type, ref_value, turn_index, created_at FROM session_refs",
        )?;
        let mut rows = stmt.query([])?;
        let mut seen: HashMap<(String, String, String), usize> = HashMap::new();
        while let Some(row) = rows.next()? {
            let (Some(sid), Some(kind), Some(value)) =
                (text(row, 0)?, text(row, 1)?, text(row, 2)?)
            else {
                continue;
            };
            let value = mirrored_key(redactor, &value);
            let entry = json!({
                "session_id": sid,
                "ref_type": kind,
                "ref_value": value,
                "turn_index": int(row, 3)?.and_then(|v| i32::try_from(v).ok()),
                "created_at": text(row, 4)?.as_deref().and_then(parse_store_ts).map(iso),
            });
            match seen.entry((sid, kind, value)) {
                std::collections::hash_map::Entry::Occupied(slot) => out.refs[*slot.get()] = entry,
                std::collections::hash_map::Entry::Vacant(slot) => {
                    slot.insert(out.refs.len());
                    out.refs.push(entry);
                }
            }
        }
    }

    // Usage: reconcile the complete id set, then read only the missing rows.
    let mut wanted: Vec<i64> = Vec::new();
    {
        let mut stmt = tx.prepare("SELECT id FROM assistant_usage_events ORDER BY id")?;
        let mut rows = stmt.query([])?;
        while let Some(row) = rows.next()? {
            if let Some(id) = int(row, 0)?
                && (force || !have.usage.contains(&id))
            {
                wanted.push(id);
            }
        }
    }
    if let Some(&first) = wanted.first() {
        let wanted: HashSet<i64> = wanted.into_iter().collect();
        let mut stmt = tx.prepare(
            "SELECT id, session_id, turn_index, agent_id, parent_tool_call_id, model,
                    input_tokens, output_tokens, cache_read_tokens, cache_write_tokens,
                    reasoning_tokens, total_nano_aiu, request_multiplier, duration_ms,
                    time_to_first_token_ms, inter_token_latency_ms, initiator, api_endpoint,
                    reasoning_effort, finish_reason, content_filter_triggered,
                    token_details_json, created_at, output_ttft_ms, copilot_usage_model
             FROM assistant_usage_events WHERE id >= ?1 ORDER BY id",
        )?;
        let mut rows = stmt.query([first])?;
        while let Some(row) = rows.next()? {
            let Some(id) = int(row, 0)? else { continue };
            if !wanted.contains(&id) {
                continue;
            }
            let Some(session_id) = text(row, 1)? else {
                out.usage_rejected += 1;
                continue;
            };
            let Some(ts) = text(row, 22)?.as_deref().and_then(parse_store_ts) else {
                warn!(src_id = id, "usage row has no parseable timestamp; skipped");
                out.usage_rejected += 1;
                continue;
            };
            let price = text(row, 21)?.and_then(|t| serde_json::from_str::<Value>(&t).ok());
            out.usage.push(json!({
                "session_id": session_id,
                "src_id": id,
                "ts": iso(ts),
                "turn_index": int(row, 2)?.and_then(|v| i32::try_from(v).ok()),
                "agent_id": text(row, 3)?,
                "parent_tool_call_id": text(row, 4)?,
                "model": text(row, 5)?,
                "copilot_usage_model": text(row, 24)?,
                "initiator": text(row, 16)?,
                "effort": text(row, 18)?,
                "input": int(row, 6)?,
                "cache_read": int(row, 8)?,
                "cache_write": int(row, 9)?,
                "output": int(row, 7)?,
                "reasoning": int(row, 10)?,
                "nano_aiu": int(row, 11)?,
                "request_multiplier": real(row, 12)?,
                "duration_ms": int(row, 13)?,
                "ttft_ms": real(row, 14)?,
                "itl_ms": real(row, 15)?,
                "output_ttft_ms": real(row, 23)?,
                "api_endpoint": text(row, 17)?,
                "finish_reason": text(row, 19)?,
                "content_filter": flag(row, 20)?,
                "price": price,
            }));
        }
    }
    Ok(out)
}

async fn load_have(pool: &PgPool) -> Result<Have> {
    let turns: Vec<(String, i32, String)> =
        sqlx::query_as("SELECT session_id, turn_index, src_hash FROM turns")
            .fetch_all(pool)
            .await?;
    let checkpoints: Vec<(String, i32, String)> =
        sqlx::query_as("SELECT session_id, checkpoint_number, src_hash FROM checkpoints")
            .fetch_all(pool)
            .await?;
    let usage: Vec<i64> = sqlx::query_scalar("SELECT src_id FROM usage")
        .fetch_all(pool)
        .await?;
    Ok(Have {
        turns: turns.into_iter().map(|(s, i, h)| ((s, i), h)).collect(),
        checkpoints: checkpoints
            .into_iter()
            .map(|(s, i, h)| ((s, i), h))
            .collect(),
        usage: usage.into_iter().collect(),
    })
}

/// What the CLI's own store holds, keyed the way it is mirrored. `verify`
/// compares this with PostgreSQL without trusting the mirror's bookkeeping.
#[derive(Debug, Default)]
pub struct Inventory {
    pub sessions: HashSet<String>,
    pub turns: HashSet<(String, i32)>,
    pub checkpoints: HashSet<(String, i32)>,
    pub files: HashSet<(String, String)>,
    pub refs: HashSet<(String, String, String)>,
    /// Usage rows that can be mirrored: a session and a parseable timestamp.
    pub usage_ids: Vec<i64>,
    pub usage_sums: UsageSums,
    /// Usage rows `sync` cannot mirror (counted by `Report::usage_rejected`).
    pub usage_unmirrorable: u64,
    /// Rows above the marks: written after the last sync's snapshot, so not
    /// part of the comparison.
    pub newer: u64,
}

#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct UsageSums {
    pub nano_aiu: i64,
    pub input: i64,
    pub output: i64,
    pub cache_read: i64,
    pub cache_write: i64,
}

/// Reads the keys (and, for usage, the token and price totals) of the rows at
/// or below each table's mark, in one read-only transaction. `marks` come from
/// `ingest_state` (see [`MARKED_TABLES`]); rows above them were written after
/// the last sync's snapshot and are only counted, in `Inventory::newer`.
pub fn inventory(
    db: &Path,
    redactor: &Redactor,
    marks: &HashMap<String, i64>,
) -> Result<Inventory> {
    let conn = open(db)?;
    let tx = conn.unchecked_transaction()?;
    let mut out = Inventory::default();
    let mark = |table: &str| marks.get(table).copied().unwrap_or(0);

    for table in MARKED_TABLES {
        let newer: i64 = tx.query_row(
            &format!("SELECT count(*) FROM {table} WHERE rowid > ?1"),
            [mark(table)],
            |row| row.get(0),
        )?;
        out.newer += u64::try_from(newer).unwrap_or(0);
    }

    scan(
        &tx,
        "SELECT id FROM sessions WHERE rowid <= ?1",
        mark("sessions"),
        |row| {
            out.sessions.extend(text(row, 0)?);
            Ok(())
        },
    )?;
    scan(
        &tx,
        "SELECT session_id, turn_index FROM turns WHERE rowid <= ?1",
        mark("turns"),
        |row| {
            if let (Some(sid), Some(idx)) = (text(row, 0)?, int(row, 1)?) {
                out.turns
                    .insert((sid, i32::try_from(idx).unwrap_or(i32::MAX)));
            }
            Ok(())
        },
    )?;
    scan(
        &tx,
        "SELECT session_id, checkpoint_number FROM checkpoints WHERE rowid <= ?1",
        mark("checkpoints"),
        |row| {
            if let (Some(sid), Some(num)) = (text(row, 0)?, int(row, 1)?) {
                out.checkpoints
                    .insert((sid, i32::try_from(num).unwrap_or(i32::MAX)));
            }
            Ok(())
        },
    )?;
    scan(
        &tx,
        "SELECT session_id, file_path FROM session_files WHERE rowid <= ?1",
        mark("session_files"),
        |row| {
            if let (Some(sid), Some(path)) = (text(row, 0)?, text(row, 1)?) {
                out.files.insert((sid, mirrored_key(redactor, &path)));
            }
            Ok(())
        },
    )?;
    scan(
        &tx,
        "SELECT session_id, ref_type, ref_value FROM session_refs WHERE rowid <= ?1",
        mark("session_refs"),
        |row| {
            if let (Some(sid), Some(kind), Some(value)) =
                (text(row, 0)?, text(row, 1)?, text(row, 2)?)
            {
                out.refs.insert((sid, kind, mirrored_key(redactor, &value)));
            }
            Ok(())
        },
    )?;
    scan(
        &tx,
        "SELECT id, session_id, input_tokens, output_tokens, cache_read_tokens,
                cache_write_tokens, total_nano_aiu, created_at
         FROM assistant_usage_events WHERE rowid <= ?1",
        mark("assistant_usage_events"),
        |row| {
            let Some(id) = int(row, 0)? else {
                return Ok(());
            };
            let mirrorable = text(row, 1)?.is_some()
                && text(row, 7)?.as_deref().and_then(parse_store_ts).is_some();
            if !mirrorable {
                out.usage_unmirrorable += 1;
                return Ok(());
            }
            out.usage_ids.push(id);
            let sums = &mut out.usage_sums;
            sums.input += int(row, 2)?.unwrap_or(0);
            sums.output += int(row, 3)?.unwrap_or(0);
            sums.cache_read += int(row, 4)?.unwrap_or(0);
            sums.cache_write += int(row, 5)?.unwrap_or(0);
            sums.nano_aiu += int(row, 6)?.unwrap_or(0);
            Ok(())
        },
    )?;
    Ok(out)
}

/// Runs `sql`, which takes the table's mark as `?1`, and hands every row to `each`.
fn scan(
    conn: &Connection,
    sql: &str,
    mark: i64,
    mut each: impl FnMut(&Row<'_>) -> rusqlite::Result<()>,
) -> rusqlite::Result<()> {
    let mut stmt = conn.prepare(sql)?;
    let mut rows = stmt.query([mark])?;
    while let Some(row) = rows.next()? {
        each(row)?;
    }
    Ok(())
}

const UPSERT_TURNS: &str = "
INSERT INTO turns (session_id, turn_index, user_message, assistant_response, ts, src_hash)
SELECT t.session_id, t.turn_index, t.user_message, t.assistant_response, t.ts, t.src_hash
FROM jsonb_to_recordset($1) AS t(session_id text, turn_index int, user_message text,
                                 assistant_response text, ts timestamptz, src_hash text)
ON CONFLICT (session_id, turn_index) DO UPDATE SET
    user_message = EXCLUDED.user_message, assistant_response = EXCLUDED.assistant_response,
    ts = EXCLUDED.ts, src_hash = EXCLUDED.src_hash
WHERE (turns.user_message, turns.assistant_response, turns.ts, turns.src_hash)
      IS DISTINCT FROM
      (EXCLUDED.user_message, EXCLUDED.assistant_response, EXCLUDED.ts, EXCLUDED.src_hash)
";

const UPSERT_CHECKPOINTS: &str = "
INSERT INTO checkpoints (session_id, checkpoint_number, title, overview, history, work_done,
                         technical_details, important_files, next_steps, created_at, src_hash)
SELECT t.session_id, t.checkpoint_number, t.title, t.overview, t.history, t.work_done,
       t.technical_details, t.important_files, t.next_steps, t.created_at, t.src_hash
FROM jsonb_to_recordset($1) AS t(session_id text, checkpoint_number int, title text,
         overview text, history text, work_done text, technical_details text,
         important_files text, next_steps text, created_at timestamptz, src_hash text)
ON CONFLICT (session_id, checkpoint_number) DO UPDATE SET
    title = EXCLUDED.title, overview = EXCLUDED.overview, history = EXCLUDED.history,
    work_done = EXCLUDED.work_done, technical_details = EXCLUDED.technical_details,
    important_files = EXCLUDED.important_files, next_steps = EXCLUDED.next_steps,
    created_at = EXCLUDED.created_at, src_hash = EXCLUDED.src_hash
WHERE (checkpoints.title, checkpoints.overview, checkpoints.history, checkpoints.work_done,
       checkpoints.technical_details, checkpoints.important_files, checkpoints.next_steps,
       checkpoints.created_at, checkpoints.src_hash)
      IS DISTINCT FROM
      (EXCLUDED.title, EXCLUDED.overview, EXCLUDED.history, EXCLUDED.work_done,
       EXCLUDED.technical_details, EXCLUDED.important_files, EXCLUDED.next_steps,
       EXCLUDED.created_at, EXCLUDED.src_hash)
";

const UPSERT_FILES: &str = "
INSERT INTO session_files (session_id, file_path, tool_name, turn_index, first_seen_at)
SELECT t.session_id, t.file_path, t.tool_name, t.turn_index, t.first_seen_at
FROM jsonb_to_recordset($1) AS t(session_id text, file_path text, tool_name text,
                                 turn_index int, first_seen_at timestamptz)
ON CONFLICT (session_id, file_path) DO UPDATE SET
    tool_name = EXCLUDED.tool_name, turn_index = EXCLUDED.turn_index,
    first_seen_at = EXCLUDED.first_seen_at
WHERE (session_files.tool_name, session_files.turn_index, session_files.first_seen_at)
      IS DISTINCT FROM
      (EXCLUDED.tool_name, EXCLUDED.turn_index, EXCLUDED.first_seen_at)
";

const UPSERT_REFS: &str = "
INSERT INTO session_refs (session_id, ref_type, ref_value, turn_index, created_at)
SELECT t.session_id, t.ref_type, t.ref_value, t.turn_index, t.created_at
FROM jsonb_to_recordset($1) AS t(session_id text, ref_type text, ref_value text,
                                 turn_index int, created_at timestamptz)
ON CONFLICT (session_id, ref_type, ref_value) DO UPDATE SET
    turn_index = EXCLUDED.turn_index, created_at = EXCLUDED.created_at
WHERE (session_refs.turn_index, session_refs.created_at)
      IS DISTINCT FROM (EXCLUDED.turn_index, EXCLUDED.created_at)
";

const UPSERT_USAGE: &str = "
INSERT INTO usage (session_id, src_id, ts, turn_index, agent_id, parent_tool_call_id, model,
                   copilot_usage_model, initiator, effort, input, cache_read, cache_write,
                   output, reasoning, nano_aiu, request_multiplier, duration_ms, ttft_ms,
                   itl_ms, output_ttft_ms, api_endpoint, finish_reason, content_filter, price)
SELECT t.session_id, t.src_id, t.ts, t.turn_index, t.agent_id, t.parent_tool_call_id, t.model,
       t.copilot_usage_model, t.initiator, t.effort, t.input, t.cache_read, t.cache_write,
       t.output, t.reasoning, t.nano_aiu, t.request_multiplier, t.duration_ms, t.ttft_ms,
       t.itl_ms, t.output_ttft_ms, t.api_endpoint, t.finish_reason, t.content_filter, t.price
FROM jsonb_to_recordset($1) AS t(session_id text, src_id bigint, ts timestamptz, turn_index int,
         agent_id text, parent_tool_call_id text, model text, copilot_usage_model text,
         initiator text, effort text, input bigint, cache_read bigint, cache_write bigint,
         output bigint, reasoning bigint, nano_aiu bigint, request_multiplier double precision,
         duration_ms bigint, ttft_ms double precision, itl_ms double precision,
         output_ttft_ms double precision, api_endpoint text, finish_reason text,
         content_filter boolean, price jsonb)
ON CONFLICT (session_id, src_id) DO UPDATE SET
    ts = EXCLUDED.ts, turn_index = EXCLUDED.turn_index, agent_id = EXCLUDED.agent_id,
    parent_tool_call_id = EXCLUDED.parent_tool_call_id, model = EXCLUDED.model,
    copilot_usage_model = EXCLUDED.copilot_usage_model, initiator = EXCLUDED.initiator,
    effort = EXCLUDED.effort, input = EXCLUDED.input, cache_read = EXCLUDED.cache_read,
    cache_write = EXCLUDED.cache_write, output = EXCLUDED.output,
    reasoning = EXCLUDED.reasoning, nano_aiu = EXCLUDED.nano_aiu,
    request_multiplier = EXCLUDED.request_multiplier, duration_ms = EXCLUDED.duration_ms,
    ttft_ms = EXCLUDED.ttft_ms, itl_ms = EXCLUDED.itl_ms,
    output_ttft_ms = EXCLUDED.output_ttft_ms, api_endpoint = EXCLUDED.api_endpoint,
    finish_reason = EXCLUDED.finish_reason, content_filter = EXCLUDED.content_filter,
    price = EXCLUDED.price
WHERE usage IS DISTINCT FROM EXCLUDED
";

/// Counts the markers left by the redactor in the mirrored text, per session
/// and kind. Counts only; the text itself never leaves the database.
const RECOUNT_STORE_REDACTIONS: &str = r"
INSERT INTO redactions (session_id, source, kind, n)
SELECT d.session_id, 'store', m[1], count(*)
FROM (
    SELECT session_id, concat_ws(E'\n', user_message, assistant_response) AS body FROM turns
    UNION ALL
    SELECT session_id, concat_ws(E'\n', title, overview, history, work_done,
                                 technical_details, important_files, next_steps) FROM checkpoints
    UNION ALL
    SELECT session_id, file_path FROM session_files
    UNION ALL
    SELECT session_id, ref_value FROM session_refs
) d,
LATERAL regexp_matches(d.body, '\[REDACTED:([a-z_]+):[0-9a-f]{8}\]', 'g') AS m
GROUP BY d.session_id, m[1]
";

/// Upserts `rows` (JSON objects with a `session_id`) in chunks, one
/// transaction per chunk. Returns the number of rows inserted or changed.
async fn write_rows(pool: &PgPool, sql: &'static str, rows: &[Value], chunk: usize) -> Result<u64> {
    let mut changed = 0;
    for part in rows.chunks(chunk) {
        let mut ids: Vec<String> = part
            .iter()
            .filter_map(|r| {
                r.get("session_id")
                    .and_then(Value::as_str)
                    .map(str::to_owned)
            })
            .collect();
        ids.sort();
        ids.dedup();
        let mut tx = pool.begin().await?;
        writer::ensure_sessions(&mut tx, &ids).await?;
        changed += sqlx::query(sql)
            .bind(Json(part))
            .execute(&mut *tx)
            .await?
            .rows_affected();
        tx.commit().await?;
    }
    Ok(changed)
}

/// Copies what is new in the store. `force` re-reads and rewrites everything
/// (after the redaction rules changed).
pub async fn sync(
    pool: &PgPool,
    redactor: &Arc<Redactor>,
    db: &Path,
    force: bool,
) -> Result<Report> {
    if !db.exists() {
        info!(path = %db.display(), "no session store to mirror");
        return Ok(Report::default());
    }
    let have = load_have(pool).await?;
    let prepared = {
        let redactor = Arc::clone(redactor);
        let db = db.to_owned();
        tokio::task::spawn_blocking(move || prepare(&db, &redactor, &have, force)).await??
    };

    for chunk in prepared.sessions.chunks(100) {
        let mut tx = pool.begin().await?;
        for (id, meta) in chunk {
            writer::upsert_session_meta(&mut tx, id, meta, TitleAuthority::FillOnly).await?;
        }
        tx.commit().await?;
    }

    let report = Report {
        sessions_seen: prepared.sessions_seen,
        turns_changed: write_rows(pool, UPSERT_TURNS, &prepared.turns, WRITE_CHUNK).await?,
        checkpoints_changed: write_rows(
            pool,
            UPSERT_CHECKPOINTS,
            &prepared.checkpoints,
            WRITE_CHUNK,
        )
        .await?,
        files_changed: write_rows(pool, UPSERT_FILES, &prepared.files, WRITE_CHUNK).await?,
        refs_changed: write_rows(pool, UPSERT_REFS, &prepared.refs, WRITE_CHUNK).await?,
        usage_changed: write_rows(pool, UPSERT_USAGE, &prepared.usage, USAGE_CHUNK).await?,
        usage_rejected: prepared.usage_rejected,
    };

    // After the rows: a mark never claims more than what was committed.
    let (tables, marks): (Vec<&str>, Vec<i64>) = prepared.marks.iter().copied().unzip();
    sqlx::query(
        "INSERT INTO ingest_state (source, key, watermark, updated_at)
         SELECT 'store', t.key, t.mark, now()
           FROM UNNEST($1::text[], $2::bigint[]) AS t(key, mark)
         ON CONFLICT (source, key) DO UPDATE SET watermark = EXCLUDED.watermark, updated_at = now()",
    )
    .bind(&tables)
    .bind(&marks)
    .execute(pool)
    .await?;

    let text_changed = report.turns_changed
        + report.checkpoints_changed
        + report.files_changed
        + report.refs_changed;
    if force || text_changed > 0 {
        let mut tx = pool.begin().await?;
        sqlx::query("DELETE FROM redactions WHERE source = 'store'")
            .execute(&mut *tx)
            .await?;
        sqlx::query(RECOUNT_STORE_REDACTIONS)
            .execute(&mut *tx)
            .await?;
        tx.commit().await?;
    }
    Ok(report)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn both_timestamp_formats_parse_as_utc() {
        let a = parse_store_ts("2026-10-01T08:00:00.123Z").unwrap();
        let b = parse_store_ts("2026-10-01 08:00:00.123").unwrap();
        assert_eq!(a, b);
        assert_eq!(iso(a), "2026-10-01T08:00:00.123000Z");
        assert!(parse_store_ts("2026-10-01 08:00:00").is_some());
        assert!(parse_store_ts("yesterday").is_none());
    }

    #[test]
    fn row_hash_is_boundary_safe_and_null_aware() {
        let a = row_hash(&[Some("ab"), Some("c")]);
        let b = row_hash(&[Some("a"), Some("bc")]);
        assert_ne!(a, b);
        assert_ne!(row_hash(&[Some("")]), row_hash(&[None]));
        assert_eq!(a, row_hash(&[Some("ab"), Some("c")]));
    }

    fn store_with_rows() -> (tempfile::TempDir, std::path::PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("session-store.db");
        let conn = Connection::open(&path).unwrap();
        conn.execute_batch(
            "CREATE TABLE sessions (id TEXT PRIMARY KEY, cwd TEXT, repository TEXT, host_type TEXT,
                 branch TEXT, summary TEXT, created_at TEXT, updated_at TEXT);
             CREATE TABLE turns (id INTEGER PRIMARY KEY, session_id TEXT, turn_index INTEGER,
                 user_message TEXT, assistant_response TEXT, timestamp TEXT);
             CREATE TABLE checkpoints (id INTEGER PRIMARY KEY, session_id TEXT,
                 checkpoint_number INTEGER, title TEXT, overview TEXT, history TEXT,
                 work_done TEXT, technical_details TEXT, important_files TEXT, next_steps TEXT,
                 created_at TEXT);
             CREATE TABLE session_files (id INTEGER PRIMARY KEY, session_id TEXT, file_path TEXT,
                 tool_name TEXT, turn_index INTEGER, first_seen_at TEXT);
             CREATE TABLE session_refs (id INTEGER PRIMARY KEY, session_id TEXT, ref_type TEXT,
                 ref_value TEXT, turn_index INTEGER, created_at TEXT);
             CREATE TABLE assistant_usage_events (id INTEGER PRIMARY KEY, session_id TEXT,
                 turn_index INTEGER, agent_id TEXT, parent_tool_call_id TEXT, model TEXT,
                 input_tokens INTEGER, output_tokens INTEGER, cache_read_tokens INTEGER,
                 cache_write_tokens INTEGER, reasoning_tokens INTEGER, total_nano_aiu INTEGER,
                 request_multiplier REAL, duration_ms INTEGER, time_to_first_token_ms REAL,
                 inter_token_latency_ms REAL, initiator TEXT, api_endpoint TEXT,
                 reasoning_effort TEXT, finish_reason TEXT, content_filter_triggered INTEGER,
                 token_details_json TEXT, created_at TEXT, output_ttft_ms REAL,
                 copilot_usage_model TEXT);
             INSERT INTO sessions VALUES ('s1', '/w', NULL, NULL, 'main', 'A title',
                 '2026-10-01 08:00:00', '2026-10-01T09:00:00.000Z');
             INSERT INTO turns VALUES (1, 's1', 0, 'hello', NULL, '2026-10-01 08:00:01');
             INSERT INTO session_files VALUES (1, 's1', '/w/a.rs', 'edit', 0, '2026-10-01 08:00:02');
             INSERT INTO session_refs VALUES (1, 's1', 'pr', '7', 0, '2026-10-01 08:00:03');
             INSERT INTO assistant_usage_events VALUES (5, 's1', 0, NULL, NULL, 'm', 100, 10, 60, 30,
                 NULL, 123456, 1.0, 1500, 812.5, 4.25, 'user', '/chat', 'high', 'stop', 0,
                 '[{\"tokenType\":\"output\",\"tokenCount\":10,\"costPerBatch\":5,\"batchSize\":1}]',
                 '2026-10-01 08:00:04', 700.5, NULL);",
        )
        .unwrap();
        (dir, path)
    }

    #[test]
    fn prepare_maps_every_table_and_skips_known_rows() {
        let (_d, path) = store_with_rows();
        let redactor = Redactor::new();
        let first = prepare(&path, &redactor, &Have::default(), false).unwrap();
        assert_eq!(first.sessions_seen, 1);
        assert_eq!(first.turns.len(), 1);
        assert_eq!(first.files.len(), 1);
        assert_eq!(first.refs.len(), 1);
        assert_eq!(first.usage.len(), 1);
        assert_eq!(
            first.marks,
            vec![
                ("sessions", 1),
                ("turns", 1),
                ("checkpoints", 0),
                ("session_files", 1),
                ("session_refs", 1),
                ("assistant_usage_events", 5),
            ]
        );
        let usage = &first.usage[0];
        assert_eq!(usage["src_id"], 5);
        assert_eq!(usage["input"], 100);
        assert_eq!(usage["ttft_ms"], 812.5);
        assert_eq!(usage["content_filter"], false);
        assert_eq!(usage["price"][0]["tokenType"], "output");
        assert_eq!(usage["ts"], "2026-10-01T08:00:04.000000Z");
        assert_eq!(first.turns[0]["assistant_response"], Value::Null);

        let mut have = Have::default();
        have.usage.insert(5);
        let hash = first.turns[0]["src_hash"].as_str().unwrap().to_owned();
        have.turns.insert(("s1".into(), 0), hash);
        let second = prepare(&path, &redactor, &have, false).unwrap();
        assert!(second.turns.is_empty());
        assert!(second.usage.is_empty());
        let forced = prepare(&path, &redactor, &have, true).unwrap();
        assert_eq!(forced.turns.len(), 1);
        assert_eq!(forced.usage.len(), 1);
    }

    #[test]
    fn inventory_stops_at_the_marks_and_counts_what_is_newer() {
        let (_d, path) = store_with_rows();
        let redactor = Redactor::new();
        // One usage row the mirror cannot take (no session).
        Connection::open(&path)
            .unwrap()
            .execute(
                "INSERT INTO assistant_usage_events (id, session_id, model, created_at)
                 VALUES (4, NULL, 'm', '2026-10-01 08:00:00')",
                [],
            )
            .unwrap();
        let marks: HashMap<String, i64> = prepare(&path, &redactor, &Have::default(), false)
            .unwrap()
            .marks
            .into_iter()
            .map(|(table, mark)| (table.to_owned(), mark))
            .collect();
        assert_eq!(marks.len(), MARKED_TABLES.len());

        let synced = inventory(&path, &redactor, &marks).unwrap();
        assert_eq!(synced.newer, 0);
        assert!(synced.sessions.contains("s1"));
        assert!(synced.turns.contains(&("s1".to_owned(), 0)));
        assert!(
            synced
                .files
                .contains(&("s1".to_owned(), "/w/a.rs".to_owned()))
        );
        assert!(
            synced
                .refs
                .contains(&("s1".to_owned(), "pr".to_owned(), "7".to_owned()))
        );
        assert_eq!(synced.usage_ids, vec![5]);
        assert_eq!(synced.usage_unmirrorable, 1);
        assert_eq!(
            synced.usage_sums,
            UsageSums {
                nano_aiu: 123_456,
                input: 100,
                output: 10,
                cache_read: 60,
                cache_write: 30
            }
        );

        // The CLI keeps writing after the sync.
        Connection::open(&path)
            .unwrap()
            .execute_batch(
                "INSERT INTO sessions VALUES ('s2', NULL, NULL, NULL, NULL, NULL,
                     '2026-10-02 08:00:00', '2026-10-02 08:00:00');
                 INSERT INTO turns VALUES (2, 's2', 0, 'later', NULL, '2026-10-02 08:00:01');
                 INSERT INTO assistant_usage_events (id, session_id, model, total_nano_aiu, created_at)
                     VALUES (6, 's2', 'm', 999, '2026-10-02 08:00:02');",
            )
            .unwrap();
        let later = inventory(&path, &redactor, &marks).unwrap();
        assert_eq!(later.newer, 3);
        assert_eq!(later.sessions, synced.sessions);
        assert_eq!(later.turns, synced.turns);
        assert_eq!(later.usage_ids, synced.usage_ids);
        assert_eq!(later.usage_sums, synced.usage_sums);

        // Never synced: no marks, so nothing is required of the mirror.
        let bare = inventory(&path, &redactor, &HashMap::new()).unwrap();
        assert!(bare.sessions.is_empty() && bare.usage_ids.is_empty());
        assert_eq!(bare.newer, 2 + 2 + 1 + 1 + 3);
    }

    #[test]
    fn secrets_in_turn_text_are_redacted_before_they_leave_the_reader() {
        let (_d, path) = store_with_rows();
        let secret = format!(
            "gh{}_{}",
            "p",
            "Zy9Xw8Vu7Ts6Rq5Po4Nm3Lk2Ji1Hg0Fe9Dc8".get(..36).unwrap()
        );
        Connection::open(&path)
            .unwrap()
            .execute(
                "UPDATE turns SET user_message = ?1",
                [format!("my token is {secret} ok")],
            )
            .unwrap();
        let out = prepare(&path, &Redactor::new(), &Have::default(), false).unwrap();
        let message = out.turns[0]["user_message"].as_str().unwrap();
        assert!(!message.contains(&secret));
        assert!(message.contains("[REDACTED:github:"));
    }
}
