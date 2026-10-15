//! Bulk, idempotent writes into PostgreSQL.
//!
//! Every statement is an upsert keyed by the source identity and guarded by
//! `IS DISTINCT FROM`, so re-reading a source rewrites nothing: the returned
//! row counts are "rows actually inserted or changed", which makes a re-run
//! visibly add zero.

use std::collections::HashMap;

use anyhow::Result;
use chrono::{DateTime, Utc};
use sqlx::PgConnection;

use crate::events::{EventRow, SessionFacts, ToolFragment};
use crate::redact::Counts;

/// Keeps the last row per key (a statement may not upsert the same key twice).
pub fn dedupe_last<T>(rows: &[T], key: impl Fn(&T) -> String) -> Vec<&T> {
    let mut index: HashMap<String, usize> = HashMap::with_capacity(rows.len());
    let mut out: Vec<&T> = Vec::with_capacity(rows.len());
    for row in rows {
        match index.entry(key(row)) {
            std::collections::hash_map::Entry::Occupied(slot) => out[*slot.get()] = row,
            std::collections::hash_map::Entry::Vacant(slot) => {
                slot.insert(out.len());
                out.push(row);
            }
        }
    }
    out
}

/// Child rows reference `sessions(id)`; make sure the parents exist.
pub async fn ensure_sessions(conn: &mut PgConnection, ids: &[String]) -> Result<()> {
    if ids.is_empty() {
        return Ok(());
    }
    sqlx::query(
        "INSERT INTO sessions (id) SELECT id FROM (SELECT DISTINCT unnest($1::text[]) AS id) s
         ORDER BY id ON CONFLICT (id) DO NOTHING",
    )
    .bind(ids)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

const UPSERT_EVENTS: &str = "
INSERT INTO events (session_id, event_id, parent_id, ts, type, ctx, agent_id,
                    parent_tool_call_id, src_offset, body)
SELECT $1, t.event_id, t.parent_id, t.ts, t.type, t.ctx, t.agent_id,
       t.parent_tool_call_id, t.src_offset, t.body::jsonb
FROM UNNEST($2::text[], $3::text[], $4::timestamptz[], $5::text[], $6::text[], $7::text[],
            $8::text[], $9::bigint[], $10::text[])
     AS t(event_id, parent_id, ts, type, ctx, agent_id, parent_tool_call_id, src_offset, body)
ON CONFLICT (session_id, event_id) DO UPDATE SET
    parent_id = EXCLUDED.parent_id, ts = EXCLUDED.ts, type = EXCLUDED.type,
    ctx = EXCLUDED.ctx, agent_id = EXCLUDED.agent_id,
    parent_tool_call_id = EXCLUDED.parent_tool_call_id,
    src_offset = EXCLUDED.src_offset, body = EXCLUDED.body
WHERE (events.parent_id, events.ts, events.type, events.ctx, events.agent_id,
       events.parent_tool_call_id, events.src_offset, events.body)
      IS DISTINCT FROM
      (EXCLUDED.parent_id, EXCLUDED.ts, EXCLUDED.type, EXCLUDED.ctx, EXCLUDED.agent_id,
       EXCLUDED.parent_tool_call_id, EXCLUDED.src_offset, EXCLUDED.body)
";

/// Returns the number of rows inserted or changed.
pub async fn upsert_events(
    conn: &mut PgConnection,
    session_id: &str,
    rows: &[EventRow],
) -> Result<u64> {
    let rows = dedupe_last(rows, |r| r.event_id.clone());
    if rows.is_empty() {
        return Ok(0);
    }
    let n = rows.len();
    let mut event_id = Vec::with_capacity(n);
    let mut parent_id = Vec::with_capacity(n);
    let mut ts: Vec<DateTime<Utc>> = Vec::with_capacity(n);
    let mut ty = Vec::with_capacity(n);
    let mut ctx = Vec::with_capacity(n);
    let mut agent_id = Vec::with_capacity(n);
    let mut parent_tool_call_id = Vec::with_capacity(n);
    let mut src_offset = Vec::with_capacity(n);
    let mut body = Vec::with_capacity(n);
    for r in rows {
        event_id.push(r.event_id.as_str());
        parent_id.push(r.parent_id.as_deref());
        ts.push(r.ts);
        ty.push(r.ty.as_str());
        ctx.push(r.ctx.as_str());
        agent_id.push(r.agent_id.as_deref());
        parent_tool_call_id.push(r.parent_tool_call_id.as_deref());
        src_offset.push(r.src_offset);
        body.push(serde_json::to_string(&r.body)?);
    }
    let done = sqlx::query(UPSERT_EVENTS)
        .bind(session_id)
        .bind(&event_id)
        .bind(&parent_id)
        .bind(&ts)
        .bind(&ty)
        .bind(&ctx)
        .bind(&agent_id)
        .bind(&parent_tool_call_id)
        .bind(&src_offset)
        .bind(&body)
        .execute(&mut *conn)
        .await?;
    Ok(done.rows_affected())
}

const UPSERT_TOOL_CALLS: &str = "
INSERT INTO tool_calls (session_id, tool_call_id, ctx, parent_tool_call_id, tool, mcp_server,
                        args, result_text, result_bytes, ok, exit_code, t_start, t_end)
SELECT $1, t.tool_call_id, COALESCE(t.ctx, 'main'), t.parent_tool_call_id, t.tool, t.mcp_server,
       t.args::jsonb, t.result_text, t.result_bytes, t.ok, t.exit_code, t.t_start, t.t_end
FROM UNNEST($2::text[], $3::text[], $4::text[], $5::text[], $6::text[], $7::text[], $8::text[],
            $9::int[], $10::bool[], $11::int[], $12::timestamptz[], $13::timestamptz[])
     AS t(tool_call_id, ctx, parent_tool_call_id, tool, mcp_server, args, result_text,
          result_bytes, ok, exit_code, t_start, t_end)
ON CONFLICT (session_id, tool_call_id) DO UPDATE SET
    ctx = EXCLUDED.ctx,
    parent_tool_call_id = COALESCE(EXCLUDED.parent_tool_call_id, tool_calls.parent_tool_call_id),
    tool = COALESCE(EXCLUDED.tool, tool_calls.tool),
    mcp_server = COALESCE(EXCLUDED.mcp_server, tool_calls.mcp_server),
    args = COALESCE(EXCLUDED.args, tool_calls.args),
    result_text = COALESCE(EXCLUDED.result_text, tool_calls.result_text),
    result_bytes = COALESCE(EXCLUDED.result_bytes, tool_calls.result_bytes),
    ok = COALESCE(EXCLUDED.ok, tool_calls.ok),
    exit_code = COALESCE(EXCLUDED.exit_code, tool_calls.exit_code),
    t_start = COALESCE(EXCLUDED.t_start, tool_calls.t_start),
    t_end = COALESCE(EXCLUDED.t_end, tool_calls.t_end)
WHERE (tool_calls.ctx, tool_calls.parent_tool_call_id, tool_calls.tool, tool_calls.mcp_server,
       tool_calls.args, tool_calls.result_text, tool_calls.result_bytes, tool_calls.ok,
       tool_calls.exit_code, tool_calls.t_start, tool_calls.t_end)
      IS DISTINCT FROM
      (EXCLUDED.ctx,
       COALESCE(EXCLUDED.parent_tool_call_id, tool_calls.parent_tool_call_id),
       COALESCE(EXCLUDED.tool, tool_calls.tool),
       COALESCE(EXCLUDED.mcp_server, tool_calls.mcp_server),
       COALESCE(EXCLUDED.args, tool_calls.args),
       COALESCE(EXCLUDED.result_text, tool_calls.result_text),
       COALESCE(EXCLUDED.result_bytes, tool_calls.result_bytes),
       COALESCE(EXCLUDED.ok, tool_calls.ok),
       COALESCE(EXCLUDED.exit_code, tool_calls.exit_code),
       COALESCE(EXCLUDED.t_start, tool_calls.t_start),
       COALESCE(EXCLUDED.t_end, tool_calls.t_end))
";

/// Merges the fragments of one batch per tool call, then upserts them; a
/// fragment of a call whose other half was written earlier fills in its
/// NULL columns (and only those).
pub async fn upsert_tool_calls(
    conn: &mut PgConnection,
    session_id: &str,
    fragments: &[ToolFragment],
) -> Result<u64> {
    let mut merged: Vec<ToolFragment> = Vec::new();
    let mut index: HashMap<&str, usize> = HashMap::new();
    for fragment in fragments {
        match index.get(fragment.tool_call_id.as_str()) {
            Some(&i) => merged[i].merge(fragment.clone()),
            None => {
                index.insert(fragment.tool_call_id.as_str(), merged.len());
                merged.push(fragment.clone());
            }
        }
    }
    if merged.is_empty() {
        return Ok(0);
    }
    let n = merged.len();
    let mut tool_call_id = Vec::with_capacity(n);
    let mut ctx = Vec::with_capacity(n);
    let mut parent = Vec::with_capacity(n);
    let mut tool = Vec::with_capacity(n);
    let mut mcp = Vec::with_capacity(n);
    let mut args: Vec<Option<String>> = Vec::with_capacity(n);
    let mut result_text = Vec::with_capacity(n);
    let mut result_bytes = Vec::with_capacity(n);
    let mut ok = Vec::with_capacity(n);
    let mut exit_code = Vec::with_capacity(n);
    let mut t_start = Vec::with_capacity(n);
    let mut t_end = Vec::with_capacity(n);
    for f in &merged {
        tool_call_id.push(f.tool_call_id.as_str());
        ctx.push(f.ctx.as_deref());
        parent.push(f.parent_tool_call_id.as_deref());
        tool.push(f.tool.as_deref());
        mcp.push(f.mcp_server.as_deref());
        args.push(f.args.as_ref().map(serde_json::to_string).transpose()?);
        result_text.push(f.result_text.as_deref());
        result_bytes.push(f.result_bytes);
        ok.push(f.ok);
        exit_code.push(f.exit_code);
        t_start.push(f.t_start);
        t_end.push(f.t_end);
    }
    let done = sqlx::query(UPSERT_TOOL_CALLS)
        .bind(session_id)
        .bind(&tool_call_id)
        .bind(&ctx)
        .bind(&parent)
        .bind(&tool)
        .bind(&mcp)
        .bind(&args)
        .bind(&result_text)
        .bind(&result_bytes)
        .bind(&ok)
        .bind(&exit_code)
        .bind(&t_start)
        .bind(&t_end)
        .execute(&mut *conn)
        .await?;
    Ok(done.rows_affected())
}

const MERGE_FACTS: &str = "
UPDATE sessions SET
    cwd = COALESCE($2, cwd), git_root = COALESCE($3, git_root),
    repository = COALESCE($4, repository), branch = COALESCE($5, branch),
    host_type = COALESCE($6, host_type), model = COALESCE($7, model),
    effort = COALESCE($8, effort), context_tier = COALESCE($9, context_tier),
    max_ai_credits = COALESCE($10, max_ai_credits),
    autopilot = autopilot OR $11,
    started_at = LEAST(started_at, $12), ended_at = GREATEST(ended_at, $13)
WHERE id = $1
  AND (cwd, git_root, repository, branch, host_type, model, effort, context_tier,
       max_ai_credits, autopilot, started_at, ended_at)
      IS DISTINCT FROM
      (COALESCE($2, cwd), COALESCE($3, git_root), COALESCE($4, repository),
       COALESCE($5, branch), COALESCE($6, host_type), COALESCE($7, model),
       COALESCE($8, effort), COALESCE($9, context_tier), COALESCE($10, max_ai_credits),
       autopilot OR $11, LEAST(started_at, $12), GREATEST(ended_at, $13))
";

/// Events are authoritative for what a session ran with: the latest non-null
/// value in file order wins.
pub async fn merge_session_facts(
    conn: &mut PgConnection,
    session_id: &str,
    facts: &SessionFacts,
) -> Result<()> {
    sqlx::query(MERGE_FACTS)
        .bind(session_id)
        .bind(facts.cwd.as_deref())
        .bind(facts.git_root.as_deref())
        .bind(facts.repository.as_deref())
        .bind(facts.branch.as_deref())
        .bind(facts.host_type.as_deref())
        .bind(facts.model.as_deref())
        .bind(facts.effort.as_deref())
        .bind(facts.context_tier.as_deref())
        .bind(facts.max_ai_credits)
        .bind(facts.autopilot)
        .bind(facts.first_ts)
        .bind(facts.last_ts)
        .execute(&mut *conn)
        .await?;
    Ok(())
}

/// Adds `counts` to the session's redaction tally for `source`. `replace`
/// first clears the old tally (a pass that re-reads a source from the start).
pub async fn add_redactions(
    conn: &mut PgConnection,
    session_id: &str,
    source: &str,
    counts: &Counts,
    replace: bool,
) -> Result<()> {
    if replace {
        sqlx::query("DELETE FROM redactions WHERE session_id = $1 AND source = $2")
            .bind(session_id)
            .bind(source)
            .execute(&mut *conn)
            .await?;
    }
    if counts.is_empty() {
        return Ok(());
    }
    let kinds: Vec<&str> = counts.iter().map(|(k, _)| k).collect();
    let totals: Vec<i64> = counts
        .iter()
        .map(|(_, n)| i64::try_from(n).unwrap_or(i64::MAX))
        .collect();
    sqlx::query(
        "INSERT INTO redactions (session_id, source, kind, n)
         SELECT $1, $2, k, n FROM UNNEST($3::text[], $4::bigint[]) AS t(k, n)
         ON CONFLICT (session_id, source, kind)
         DO UPDATE SET n = redactions.n + EXCLUDED.n",
    )
    .bind(session_id)
    .bind(source)
    .bind(&kinds)
    .bind(&totals)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Where the ingester resumes for one session's `events.jsonl`.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct EventsState {
    pub byte_offset: i64,
    pub file_size: Option<i64>,
    pub head_sha: Option<String>,
}

pub async fn load_events_state(
    conn: &mut PgConnection,
    session_id: &str,
) -> Result<Option<EventsState>> {
    let row: Option<(i64, Option<i64>, Option<String>)> = sqlx::query_as(
        "SELECT byte_offset, file_size, head_sha FROM ingest_state
         WHERE source = 'events' AND key = $1",
    )
    .bind(session_id)
    .fetch_optional(&mut *conn)
    .await?;
    Ok(row.map(|(byte_offset, file_size, head_sha)| EventsState {
        byte_offset,
        file_size,
        head_sha,
    }))
}

pub async fn save_events_state(
    conn: &mut PgConnection,
    session_id: &str,
    state: &EventsState,
    mtime: Option<DateTime<Utc>>,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO ingest_state (source, key, byte_offset, file_size, head_sha, mtime, updated_at)
         VALUES ('events', $1, $2, $3, $4, $5, now())
         ON CONFLICT (source, key) DO UPDATE SET
             byte_offset = EXCLUDED.byte_offset, file_size = EXCLUDED.file_size,
             head_sha = EXCLUDED.head_sha, mtime = EXCLUDED.mtime, updated_at = now()",
    )
    .bind(session_id)
    .bind(state.byte_offset)
    .bind(state.file_size)
    .bind(state.head_sha.as_deref())
    .bind(mtime)
    .execute(&mut *conn)
    .await?;
    Ok(())
}

/// Session attributes from a source that is NOT authoritative for them
/// (`workspace.yaml`, `session-store.db`): they fill what events left empty.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct SessionMeta {
    pub cwd: Option<String>,
    pub git_root: Option<String>,
    pub repository: Option<String>,
    pub branch: Option<String>,
    pub host_type: Option<String>,
    pub name: Option<String>,
    pub summary: Option<String>,
    pub started_at: Option<DateTime<Utc>>,
    pub ended_at: Option<DateTime<Utc>>,
}

/// `workspace.yaml` is the CLI's own, current title for a session, so it
/// overwrites `name`/`summary`; the store's copy only fills a missing one.
/// Either order of the two syncs therefore ends in the same row.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum TitleAuthority {
    Overwrite,
    FillOnly,
}

pub async fn upsert_session_meta(
    conn: &mut PgConnection,
    session_id: &str,
    meta: &SessionMeta,
    titles: TitleAuthority,
) -> Result<()> {
    sqlx::query(
        "INSERT INTO sessions (id, cwd, git_root, repository, branch, host_type, name, summary,
                               started_at, ended_at)
         VALUES ($1, $2, $3, $4, $5, $6, $7, $8, $9, $10)
         ON CONFLICT (id) DO UPDATE SET
             cwd = COALESCE(sessions.cwd, EXCLUDED.cwd),
             git_root = COALESCE(sessions.git_root, EXCLUDED.git_root),
             repository = COALESCE(sessions.repository, EXCLUDED.repository),
             branch = COALESCE(sessions.branch, EXCLUDED.branch),
             host_type = COALESCE(sessions.host_type, EXCLUDED.host_type),
             name = CASE WHEN $11 THEN COALESCE(EXCLUDED.name, sessions.name)
                         ELSE COALESCE(sessions.name, EXCLUDED.name) END,
             summary = CASE WHEN $11 THEN COALESCE(EXCLUDED.summary, sessions.summary)
                            ELSE COALESCE(sessions.summary, EXCLUDED.summary) END,
             started_at = LEAST(sessions.started_at, EXCLUDED.started_at),
             ended_at = GREATEST(sessions.ended_at, EXCLUDED.ended_at)",
    )
    .bind(session_id)
    .bind(meta.cwd.as_deref())
    .bind(meta.git_root.as_deref())
    .bind(meta.repository.as_deref())
    .bind(meta.branch.as_deref())
    .bind(meta.host_type.as_deref())
    .bind(meta.name.as_deref())
    .bind(meta.summary.as_deref())
    .bind(meta.started_at)
    .bind(meta.ended_at)
    .bind(titles == TitleAuthority::Overwrite)
    .execute(&mut *conn)
    .await?;
    Ok(())
}
