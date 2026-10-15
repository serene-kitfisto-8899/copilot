-- Audit trail of the permissionRequest hook (PLAN.md §6.6, phase P3).
--
-- One row per hook invocation: what `ctx-hook permission` decided about a
-- request and why. In shadow mode (`shadow = true`) the decision was only
-- logged and the CLI went on to prompt as usual, so joining a row with the
-- `permission.requested` / `permission.completed` events that follow it tells
-- what the user did with exactly the request the hook would have allowed.
--
--   * No foreign key to sessions(id): the hook fires before the ingester has
--     seen a brand-new session, and the audit must never lose a row to a race.
--     Deleting a session therefore does not purge its audit rows; delete them
--     by session_id when forgetting a session.
--   * Text is redacted before it gets here (ctx_core::redact), like everything
--     else in this database. `cmd_sha` is the SHA-256 of the redacted, capped
--     text, which is also what the events table holds for the same command.
--   * `uid` makes imports idempotent: when PostgreSQL is unreachable the hook
--     spools rows to a local file and `ctx-hook review` imports them later.

CREATE TABLE hook_audit (
    id          bigserial PRIMARY KEY,
    uid         text        NOT NULL UNIQUE,
    ts          timestamptz NOT NULL,
    session_id  text        NOT NULL,
    -- the tool the CLI asked about (bash, view, create, web_fetch, ...)
    tool        text        NOT NULL,
    cmd_sha     text,
    cmd_preview text,
    -- the directory the CLI reported for the request (redacted); the persistent
    -- shell may have moved on since, so `ctx-hook review` compares it with
    -- sessions.cwd to see how often the two differ
    cwd         text,
    -- allow: every rule held; pass: left to the normal prompt (never a deny)
    decision    text        NOT NULL CHECK (decision IN ('allow', 'pass')),
    -- allow:<command names> or pass:<first reason that stopped it>
    rule        text        NOT NULL,
    shadow      boolean     NOT NULL,
    -- wall-clock microseconds from process start to the decision
    latency_us  integer,
    -- policy version and config fingerprint that produced the decision
    policy      text        NOT NULL,
    inserted_at timestamptz NOT NULL DEFAULT now()
);
CREATE INDEX hook_audit_ts_idx ON hook_audit (ts);
CREATE INDEX hook_audit_session_ts_idx ON hook_audit (session_id, ts);
