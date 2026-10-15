-- Core schema for the Copilot context database (PLAN.md §6.2, phase P1).
--
-- Design rules that the rest of the code relies on:
--   * Everything stored here has been through ctx_core::redact (single choke
--     point); raw text only ever stays in the CLI's own events.jsonl.
--   * Every child table references sessions(id) ON DELETE CASCADE, so
--     `DELETE FROM sessions WHERE id = ...` purges a session completely (and
--     the trigger below also forgets its ingest offset, otherwise the ingester
--     would consider the deleted session "already up to date").
--   * All writes are idempotent upserts keyed by the source identity, so a
--     re-read of any source (crash, --force, fork copying history) adds no rows.
--   * The database is an archive: rows deleted from the CLI's own stores are
--     never deleted here.
--   * Timestamps are timestamptz; sources are UTC and the pool pins TimeZone=UTC.

CREATE TABLE sessions (
    id             text PRIMARY KEY,
    cwd            text,
    git_root       text,
    repository     text,
    branch         text,
    host_type      text,
    -- latest model / effort / context tier seen in the event stream
    model          text,
    effort         text,
    context_tier   text,
    max_ai_credits bigint,
    -- true once any mode change to autopilot, autopilot user message or
    -- autopilot continuation has been seen (monotonic, never reset)
    autopilot      boolean NOT NULL DEFAULT false,
    started_at     timestamptz,
    ended_at       timestamptz,
    name           text,
    summary        text,
    inserted_at    timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX sessions_repo_branch_idx ON sessions (git_root, branch);
CREATE INDEX sessions_started_idx ON sessions (started_at);

-- One row per events.jsonl line (redacted, binary/opaque fields stripped,
-- every string capped). A forked session copies its parent's history, so the
-- same event id legitimately appears under several sessions.
CREATE TABLE events (
    session_id          text        NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    event_id            text        NOT NULL,
    parent_id           text,
    ts                  timestamptz NOT NULL,
    type                text        NOT NULL,
    -- 'main' or the sub-agent's agentId (agentId maps 1:1 to a parentToolCallId)
    ctx                 text        NOT NULL DEFAULT 'main',
    agent_id            text,
    parent_tool_call_id text,
    -- byte offset of the line in events.jsonl, to fetch the raw event later
    src_offset          bigint      NOT NULL,
    body                jsonb       NOT NULL,
    PRIMARY KEY (session_id, event_id)
);
CREATE INDEX events_type_ts_idx ON events (type, ts);
CREATE INDEX events_session_ts_idx ON events (session_id, ts);

-- Built by merging the tool.execution_start / tool.execution_complete
-- fragments of one toolCallId. Permission waits are derived from the
-- permission.* events (see views), not stored here.
CREATE TABLE tool_calls (
    session_id          text NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    tool_call_id        text NOT NULL,
    ctx                 text NOT NULL DEFAULT 'main',
    parent_tool_call_id text,
    tool                text,
    mcp_server          text,
    args                jsonb,
    result_text         text,
    -- length in bytes of the result before redaction and the 8 KB cap
    result_bytes        integer,
    ok                  boolean,
    exit_code           integer,
    t_start             timestamptz,
    t_end               timestamptz,
    PRIMARY KEY (session_id, tool_call_id)
);
CREATE INDEX tool_calls_tool_idx ON tool_calls (tool, t_start);

-- Mirror of session-store.db assistant_usage_events, the ONLY per-call source
-- of cache_read / cache_write tokens and of the price table.
CREATE TABLE usage (
    session_id          text             NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    src_id              bigint           NOT NULL,
    ts                  timestamptz      NOT NULL,
    turn_index          integer,
    agent_id            text,
    parent_tool_call_id text,
    model               text,
    copilot_usage_model text,
    initiator           text,
    effort              text,
    -- input is the WHOLE prompt: uncached + cache_read + cache_write
    input               bigint,
    cache_read          bigint,
    cache_write         bigint,
    output              bigint,
    reasoning           bigint,
    -- NULL on the few calls the CLI could not price (content filter etc.)
    nano_aiu            bigint,
    request_multiplier  double precision,
    duration_ms         bigint,
    -- REAL in the source (fractional milliseconds)
    ttft_ms             double precision,
    itl_ms              double precision,
    output_ttft_ms      double precision,
    api_endpoint        text,
    finish_reason       text,
    content_filter      boolean,
    -- token_details_json: [{tokenType, tokenCount, costPerBatch, batchSize, model?}]
    price               jsonb,
    PRIMARY KEY (session_id, src_id)
);
CREATE INDEX usage_ts_idx ON usage (ts);
CREATE INDEX usage_session_ts_idx ON usage (session_id, ts);

-- Mirrors of session-store.db tables. src_hash is the SHA-256 of the raw source
-- row, so unchanged rows are skipped without re-redacting them.
CREATE TABLE turns (
    session_id         text    NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    turn_index         integer NOT NULL,
    user_message       text,
    assistant_response text,
    ts                 timestamptz,
    src_hash           text    NOT NULL,
    PRIMARY KEY (session_id, turn_index)
);

CREATE TABLE checkpoints (
    session_id         text    NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    checkpoint_number  integer NOT NULL,
    title              text,
    overview           text,
    history            text,
    work_done          text,
    technical_details  text,
    important_files    text,
    next_steps         text,
    created_at         timestamptz,
    src_hash           text    NOT NULL,
    PRIMARY KEY (session_id, checkpoint_number)
);

CREATE TABLE session_files (
    session_id    text NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    file_path     text NOT NULL,
    tool_name     text,
    turn_index    integer,
    first_seen_at timestamptz,
    PRIMARY KEY (session_id, file_path)
);
CREATE INDEX session_files_path_idx ON session_files (file_path);

CREATE TABLE session_refs (
    session_id text NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    ref_type   text NOT NULL,
    ref_value  text NOT NULL,
    turn_index integer,
    created_at timestamptz,
    PRIMARY KEY (session_id, ref_type, ref_value)
);
CREATE INDEX session_refs_value_idx ON session_refs (ref_type, ref_value);

-- source = 'events': key is a session id, byte_offset is the end of the last
-- complete line consumed from its events.jsonl.
-- source = 'store':  key is a table name, watermark is the highest source id
-- consumed (assistant_usage_events only).
-- head_sha (hash of the first bytes of the file) detects a replaced file whose
-- size happens to be larger than the stored offset.
CREATE TABLE ingest_state (
    source      text        NOT NULL,
    key         text        NOT NULL,
    byte_offset bigint      NOT NULL DEFAULT 0,
    file_size   bigint,
    head_sha    text,
    watermark   bigint,
    mtime       timestamptz,
    updated_at  timestamptz NOT NULL DEFAULT now(),
    PRIMARY KEY (source, key)
);

-- How many secrets were replaced, per session and kind. Counts only, never
-- values. 'events' is accumulated by the ingester (reset whenever a session is
-- re-read from offset 0); 'store' is recounted from the mirrored tables.
CREATE TABLE redactions (
    session_id text   NOT NULL REFERENCES sessions (id) ON DELETE CASCADE,
    source     text   NOT NULL,
    kind       text   NOT NULL,
    n          bigint NOT NULL,
    PRIMARY KEY (session_id, source, kind)
);

CREATE TABLE ctx_meta (
    key   text PRIMARY KEY,
    value text NOT NULL
);

CREATE FUNCTION ctx_forget_session_state() RETURNS trigger
LANGUAGE plpgsql AS
$$
BEGIN
    DELETE FROM ingest_state WHERE source = 'events' AND key = OLD.id;
    RETURN OLD;
END;
$$;

CREATE TRIGGER sessions_forget_state
    AFTER DELETE ON sessions
    FOR EACH ROW EXECUTE FUNCTION ctx_forget_session_state();
