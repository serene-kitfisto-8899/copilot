-- Report views (PLAN.md §6.8). Re-applied by `db::migrate()` whenever this file
-- changes; everything below is derived, so it is dropped and rebuilt.

DROP FUNCTION IF EXISTS ctx_as_of() CASCADE;

-- Reports can be pinned to a moment (`ctx-report --as-of`) by setting the
-- session variable ctx.as_of; unset means "now and later".
CREATE FUNCTION ctx_as_of() RETURNS timestamptz
LANGUAGE sql STABLE AS
$$
    SELECT COALESCE(NULLIF(current_setting('ctx.as_of', true), '')::timestamptz,
                    'infinity'::timestamptz)
$$;

-- Conventions
--   * Weeks are ISO weeks (Monday start) in UTC, as a date.
--   * AIU is `nano_aiu / 1e9` and stays `numeric` until the last view, so sums
--     are exact; the outward-facing views (v_summary, v_split, v_weekly) cast
--     to float8 because sqlx has no numeric decoder enabled.
--   * Usage rows are model calls. A call is a sub-agent call when agent_id is
--     set; sub-agent calls carry the parent's turn_index, so grouping by
--     (session_id, turn_index) gives the all-in cost of one user turn.
--   * Quality proxies count events per file, so forked sessions, which repeat
--     their parent's events, are counted again. That is how the PLAN §2
--     baselines were taken, and the ratios are insensitive to it.

-- One row per model call up to the as-of moment, with the two derived facts
-- the PLAN §6.8 definitions need: the idle gap since the previous call of the
-- same (session, agent) and whether the call is a cold-cache rebuild.
-- The window runs after the as-of filter, which is safe: lag() only looks back.
CREATE VIEW v_call AS
SELECT u.session_id,
       u.src_id,
       u.ts,
       (date_trunc('week', u.ts AT TIME ZONE 'UTC'))::date AS week,
       u.turn_index,
       COALESCE(u.agent_id, 'main') AS ctx,
       u.agent_id IS NOT NULL AS is_sub,
       s.autopilot,
       u.model,
       u.initiator,
       u.input,
       u.cache_read,
       u.cache_write,
       u.output,
       u.nano_aiu / 1e9 AS aiu,
       u.ts - lag(u.ts) OVER w AS gap,
       COALESCE(u.input > 20000
                AND u.cache_read * 2 < u.input
                AND u.ts - lag(u.ts) OVER w >= interval '5 minutes', false) AS cold
FROM usage u
JOIN sessions s ON s.id = u.session_id
WHERE u.ts <= ctx_as_of()
WINDOW w AS (PARTITION BY u.session_id, COALESCE(u.agent_id, 'main') ORDER BY u.ts, u.src_id);

-- AIU per call and token type: Σ tokenCount × costPerBatch / batchSize over
-- token_details_json (kept in usage.price). The four types add up to nano_aiu.
CREATE VIEW v_token_aiu AS
SELECT u.session_id,
       u.src_id,
       (date_trunc('week', u.ts AT TIME ZONE 'UTC'))::date AS week,
       d ->> 'tokenType' AS token_type,
       (d ->> 'tokenCount')::numeric * (d ->> 'costPerBatch')::numeric
           / NULLIF((d ->> 'batchSize')::numeric, 0) / 1e9 AS aiu
FROM usage u
CROSS JOIN LATERAL jsonb_array_elements(
    CASE WHEN jsonb_typeof(u.price) = 'array' THEN u.price ELSE '[]'::jsonb END) AS d
WHERE u.ts <= ctx_as_of();

-- One row per (session, turn): all-in cost of a user turn, sub-agents included.
CREATE VIEW v_turn AS
SELECT c.session_id,
       c.turn_index,
       min(c.ts) AS started_at,
       (date_trunc('week', min(c.ts) AT TIME ZONE 'UTC'))::date AS week,
       count(*) AS calls,
       count(*) FILTER (WHERE NOT c.is_sub) AS main_calls,
       sum(c.aiu) AS aiu,
       COALESCE(sum(c.aiu) FILTER (WHERE NOT c.is_sub), 0) AS main_aiu,
       COALESCE(sum(c.aiu) FILTER (WHERE c.is_sub), 0) AS sub_aiu
FROM v_call c
GROUP BY c.session_id, c.turn_index;

-- One row per session that made calls.
CREATE VIEW v_session AS
SELECT s.id AS session_id,
       s.autopilot,
       s.repository,
       s.model,
       min(c.ts) AS first_call,
       max(c.ts) AS last_call,
       count(*) AS calls,
       count(DISTINCT c.turn_index) AS turns,
       sum(c.aiu) AS aiu,
       COALESCE(sum(c.aiu) FILTER (WHERE c.cold), 0) AS cold_aiu
FROM v_call c
JOIN sessions s ON s.id = c.session_id
GROUP BY s.id, s.autopilot, s.repository, s.model;

-- Calls and AIU per model, main agent and sub-agents apart.
CREATE VIEW v_model AS
SELECT c.model,
       c.is_sub,
       count(*) AS calls,
       sum(c.aiu)::float8 AS aiu,
       (100 * sum(c.aiu) / NULLIF(sum(sum(c.aiu)) OVER (), 0))::float8 AS aiu_pct,
       (sum(c.aiu) / NULLIF(count(*), 0))::float8 AS aiu_per_call,
       avg(c.input)::float8 AS mean_prompt_tokens
FROM v_call c
GROUP BY c.model, c.is_sub;

-- AIU by token type and by initiator (each dimension adds up to the total).
CREATE VIEW v_split AS
WITH t AS (
    SELECT 'token_type'::text AS dim, token_type AS value, NULL::bigint AS calls, sum(aiu) AS aiu
    FROM v_token_aiu
    GROUP BY token_type
    UNION ALL
    SELECT 'initiator', COALESCE(initiator, '(none)'), count(*), sum(aiu)
    FROM v_call
    GROUP BY initiator
)
SELECT dim,
       value,
       calls,
       aiu::float8 AS aiu,
       (100 * aiu / NULLIF(sum(aiu) OVER (PARTITION BY dim), 0))::float8 AS aiu_pct
FROM t;

-- Per-week quality proxies from the events (raw per-file counts, see above).
CREATE VIEW v_quality AS
SELECT (date_trunc('week', e.ts AT TIME ZONE 'UTC'))::date AS week,
       count(*) FILTER (WHERE e.type = 'abort') AS aborts,
       count(*) FILTER (WHERE e.type = 'user.message') AS user_messages,
       count(*) FILTER (WHERE e.type IN ('model.model_call_failure', 'model.turn_retry',
                                         'session.error')) AS failures,
       count(*) FILTER (WHERE e.type = 'assistant.turn_start') AS assistant_turns,
       count(*) FILTER (WHERE e.type = 'session.task_complete') AS task_completes
FROM events e
WHERE e.ts <= ctx_as_of()
  AND e.type IN ('abort', 'user.message', 'model.model_call_failure', 'model.turn_retry',
                 'session.error', 'assistant.turn_start', 'session.task_complete')
GROUP BY 1;

-- Time the user (or a policy) took to answer each permission prompt.
-- Both ends must be inside the as-of window.
CREATE VIEW v_permission_wait AS
SELECT r.session_id,
       r.request_id,
       (date_trunc('week', r.requested_at AT TIME ZONE 'UTC'))::date AS week,
       extract(epoch FROM c.completed_at - r.requested_at)::float8 AS wait_s
FROM (SELECT session_id, body ->> 'requestId' AS request_id, min(ts) AS requested_at
      FROM events
      WHERE type = 'permission.requested' AND ts <= ctx_as_of()
      GROUP BY 1, 2) r
JOIN (SELECT session_id, body ->> 'requestId' AS request_id, min(ts) AS completed_at
      FROM events
      WHERE type = 'permission.completed' AND ts <= ctx_as_of()
      GROUP BY 1, 2) c USING (session_id, request_id);

-- The weekly report: spend, per-turn ratios and the quality guardrail inputs.
CREATE VIEW v_weekly AS
WITH wc AS (
    SELECT week,
           count(*) AS calls,
           count(DISTINCT session_id) AS sessions,
           sum(aiu) AS aiu,
           count(*) FILTER (WHERE is_sub) AS sub_calls,
           COALESCE(sum(aiu) FILTER (WHERE is_sub), 0) AS sub_aiu,
           COALESCE(sum(aiu) FILTER (WHERE cold), 0) AS cold_aiu,
           COALESCE(sum(aiu) FILTER (WHERE autopilot), 0) AS autopilot_aiu,
           avg(input) AS mean_prompt_tokens
    FROM v_call
    GROUP BY week
), wt AS (
    SELECT week,
           count(*) FILTER (WHERE main_calls > 0) AS turns,
           sum(main_calls) AS main_calls
    FROM v_turn
    GROUP BY week
), wp AS (
    SELECT week,
           count(*) FILTER (WHERE wait_s >= 300) AS perm_waits_ge_300s,
           COALESCE(sum(wait_s), 0) / 3600 AS perm_wait_hours
    FROM v_permission_wait
    GROUP BY week
)
SELECT week,
       sessions,
       calls,
       aiu::float8 AS aiu,
       turns,
       (aiu / NULLIF(turns, 0))::float8 AS aiu_per_turn,
       (main_calls::numeric / NULLIF(turns, 0))::float8 AS calls_per_turn,
       mean_prompt_tokens::float8 AS mean_prompt_tokens,
       (sub_aiu / NULLIF(sub_calls, 0))::float8 AS sub_aiu_per_call,
       (100 * cold_aiu / NULLIF(aiu, 0))::float8 AS cold_aiu_pct,
       (100 * autopilot_aiu / NULLIF(aiu, 0))::float8 AS autopilot_aiu_pct,
       q.user_messages,
       q.assistant_turns,
       q.aborts,
       q.failures,
       q.task_completes,
       (100.0 * q.aborts / NULLIF(q.user_messages, 0))::float8 AS aborts_per_100_msgs,
       (100.0 * q.failures / NULLIF(q.assistant_turns, 0))::float8 AS failures_per_100_turns,
       (100.0 * q.task_completes / NULLIF(q.user_messages, 0))::float8 AS task_completes_per_100_msgs,
       p.perm_waits_ge_300s,
       (100.0 * p.perm_waits_ge_300s / NULLIF(q.user_messages, 0))::float8 AS perm_waits_ge_300s_per_100_msgs,
       p.perm_wait_hours::float8 AS perm_wait_hours
FROM wc
FULL JOIN wt USING (week)
FULL JOIN v_quality q USING (week)
FULL JOIN wp p USING (week);

-- Every headline number of PLAN §2 as (section, metric, value). `ctx-report
-- baseline` compares these with the PLAN; `ctx-report summary` prints them.
CREATE VIEW v_summary AS
WITH tot AS (
    SELECT count(*) AS calls,
           count(DISTINCT session_id) AS sessions,
           COALESCE(sum(aiu), 0) AS aiu,
           COALESCE(sum(aiu) FILTER (WHERE is_sub), 0) AS sub_aiu,
           COALESCE(sum(aiu) FILTER (WHERE input >= 100000), 0) AS aiu_ge_100k,
           COALESCE(sum(aiu) FILTER (WHERE input > 400000), 0) AS aiu_gt_400k,
           avg(input) AS mean_prompt
    FROM v_call
), tok AS (
    SELECT COALESCE(sum(aiu), 0) AS total,
           COALESCE(sum(aiu) FILTER (WHERE token_type = 'cache_read'), 0) AS cache_read,
           COALESCE(sum(aiu) FILTER (WHERE token_type = 'cache_write'), 0) AS cache_write,
           COALESCE(sum(aiu) FILTER (WHERE token_type = 'output'), 0) AS output,
           COALESCE(sum(aiu) FILTER (WHERE token_type = 'input'), 0) AS input
    FROM v_token_aiu
), conc AS (
    SELECT count(*) FILTER (WHERE aiu > 1000) AS n_1000,
           COALESCE(sum(aiu) FILTER (WHERE aiu > 1000), 0) AS aiu_1000,
           count(*) FILTER (WHERE aiu > 2000) AS n_2000,
           COALESCE(sum(aiu) FILTER (WHERE aiu > 2000), 0) AS aiu_2000,
           COALESCE((SELECT sum(aiu) FROM (SELECT aiu FROM v_session
                                           ORDER BY aiu DESC LIMIT 12) top), 0) AS aiu_top12,
           count(*) FILTER (WHERE autopilot) AS ap_sessions,
           COALESCE(sum(aiu) FILTER (WHERE autopilot), 0) AS ap_aiu,
           COALESCE(sum(calls) FILTER (WHERE autopilot), 0) AS ap_calls,
           count(*) FILTER (WHERE NOT autopilot) AS man_sessions,
           COALESCE(sum(aiu) FILTER (WHERE NOT autopilot), 0) AS man_aiu,
           COALESCE(sum(calls) FILTER (WHERE NOT autopilot), 0) AS man_calls
    FROM v_session
), cold AS (
    SELECT count(*) FILTER (WHERE cold) AS n,
           COALESCE(sum(aiu) FILTER (WHERE cold), 0) AS aiu,
           count(*) FILTER (WHERE cold AND initiator = 'user') AS user_n,
           COALESCE(sum(aiu) FILTER (WHERE cold AND initiator = 'user'), 0) AS user_aiu,
           avg(extract(epoch FROM gap) / 60) FILTER (WHERE cold AND initiator = 'user') AS user_idle_min,
           avg(input) FILTER (WHERE cold AND initiator = 'user') AS user_context,
           count(*) FILTER (WHERE cold AND initiator = 'agent') AS agent_n,
           COALESCE(sum(aiu) FILTER (WHERE cold AND initiator = 'agent'), 0) AS agent_aiu
    FROM v_call
), turn AS (
    SELECT count(*) FILTER (WHERE main_calls > 0) AS turns,
           COALESCE(sum(main_calls), 0) AS main_calls,
           COALESCE(sum(aiu), 0) AS aiu,
           count(*) FILTER (WHERE main_calls = 1) AS one_call_turns,
           COALESCE(sum(main_aiu) FILTER (WHERE main_calls = 1), 0) AS one_call_aiu
    FROM v_turn
), q AS (
    SELECT COALESCE(sum(aborts), 0) AS aborts,
           COALESCE(sum(user_messages), 0) AS user_messages,
           COALESCE(sum(failures), 0) AS failures,
           COALESCE(sum(assistant_turns), 0) AS assistant_turns,
           COALESCE(sum(task_completes), 0) AS task_completes
    FROM v_quality
), perm AS (
    SELECT count(*) AS waits,
           COALESCE(sum(wait_s), 0) / 3600 AS hours,
           count(*) FILTER (WHERE wait_s >= 60) AS ge_60,
           count(*) FILTER (WHERE wait_s >= 300) AS ge_300
    FROM v_permission_wait
), reqs AS (
    SELECT count(*) AS requests,
           count(DISTINCT body ->> 'requestId') AS distinct_requests
    FROM events
    WHERE type = 'permission.requested' AND ts <= ctx_as_of()
)
SELECT section, metric, value::float8 AS value
FROM (
    SELECT 'totals' AS section, 'calls' AS metric, calls::numeric AS value FROM tot
    UNION ALL SELECT 'totals', 'sessions_with_usage', sessions FROM tot
    UNION ALL SELECT 'totals', 'aiu_total', aiu FROM tot
    UNION ALL SELECT 'totals', 'mean_prompt_tokens', mean_prompt FROM tot
    UNION ALL SELECT 'totals', 'turns', turns FROM turn
    UNION ALL SELECT 'totals', 'aiu_per_turn', aiu / NULLIF(turns, 0) FROM turn
    UNION ALL SELECT 'totals', 'main_calls_per_turn', main_calls::numeric / NULLIF(turns, 0) FROM turn
    UNION ALL SELECT 'totals', 'one_call_turns', one_call_turns FROM turn
    UNION ALL SELECT 'totals', 'one_call_turn_aiu', one_call_aiu FROM turn
    UNION ALL SELECT 'totals', 'one_call_turn_mean_aiu', one_call_aiu / NULLIF(one_call_turns, 0) FROM turn
    UNION ALL SELECT 'token type', 'aiu_pct_cache_read', 100 * cache_read / NULLIF(total, 0) FROM tok
    UNION ALL SELECT 'token type', 'aiu_pct_cache_write', 100 * cache_write / NULLIF(total, 0) FROM tok
    UNION ALL SELECT 'token type', 'aiu_pct_output', 100 * output / NULLIF(total, 0) FROM tok
    UNION ALL SELECT 'token type', 'aiu_pct_input', 100 * input / NULLIF(total, 0) FROM tok
    UNION ALL SELECT 'token type', 'split_minus_total_aiu', tok.total - tot.aiu FROM tok, tot
    UNION ALL SELECT 'prompt size', 'aiu_pct_prompt_ge_100k', 100 * aiu_ge_100k / NULLIF(aiu, 0) FROM tot
    UNION ALL SELECT 'prompt size', 'aiu_pct_prompt_gt_400k', 100 * aiu_gt_400k / NULLIF(aiu, 0) FROM tot
    UNION ALL SELECT 'concentration', 'sessions_gt_1000_aiu', n_1000 FROM conc
    UNION ALL SELECT 'concentration', 'aiu_pct_sessions_gt_1000', 100 * aiu_1000 / NULLIF(tot.aiu, 0) FROM conc, tot
    UNION ALL SELECT 'concentration', 'sessions_gt_2000_aiu', n_2000 FROM conc
    UNION ALL SELECT 'concentration', 'aiu_pct_sessions_gt_2000', 100 * aiu_2000 / NULLIF(tot.aiu, 0) FROM conc, tot
    UNION ALL SELECT 'concentration', 'aiu_pct_top_12_sessions', 100 * aiu_top12 / NULLIF(tot.aiu, 0) FROM conc, tot
    UNION ALL SELECT 'autopilot', 'autopilot_sessions', ap_sessions FROM conc
    UNION ALL SELECT 'autopilot', 'aiu_pct_autopilot', 100 * ap_aiu / NULLIF(tot.aiu, 0) FROM conc, tot
    UNION ALL SELECT 'autopilot', 'autopilot_aiu_per_session', ap_aiu / NULLIF(ap_sessions, 0) FROM conc
    UNION ALL SELECT 'autopilot', 'autopilot_calls_per_session', ap_calls::numeric / NULLIF(ap_sessions, 0) FROM conc
    UNION ALL SELECT 'autopilot', 'manual_aiu_per_session', man_aiu / NULLIF(man_sessions, 0) FROM conc
    UNION ALL SELECT 'autopilot', 'manual_calls_per_session', man_calls::numeric / NULLIF(man_sessions, 0) FROM conc
    UNION ALL SELECT 'cold cache', 'cold_calls', n FROM cold
    UNION ALL SELECT 'cold cache', 'aiu_pct_cold', 100 * cold.aiu / NULLIF(tot.aiu, 0) FROM cold, tot
    UNION ALL SELECT 'cold cache', 'cold_user_calls', user_n FROM cold
    UNION ALL SELECT 'cold cache', 'aiu_pct_cold_user', 100 * user_aiu / NULLIF(tot.aiu, 0) FROM cold, tot
    UNION ALL SELECT 'cold cache', 'cold_user_mean_idle_min', user_idle_min FROM cold
    UNION ALL SELECT 'cold cache', 'cold_user_mean_context_tokens', user_context FROM cold
    UNION ALL SELECT 'cold cache', 'cold_user_aiu_per_call', user_aiu / NULLIF(user_n, 0) FROM cold
    UNION ALL SELECT 'cold cache', 'cold_agent_calls', agent_n FROM cold
    UNION ALL SELECT 'cold cache', 'aiu_pct_cold_agent', 100 * agent_aiu / NULLIF(tot.aiu, 0) FROM cold, tot
    UNION ALL SELECT 'sub-agents', 'aiu_pct_subagent', 100 * sub_aiu / NULLIF(aiu, 0) FROM tot
    UNION ALL SELECT 'quality proxies', 'aborts', aborts FROM q
    UNION ALL SELECT 'quality proxies', 'user_messages', user_messages FROM q
    UNION ALL SELECT 'quality proxies', 'aborts_per_100_user_messages', 100.0 * aborts / NULLIF(user_messages, 0) FROM q
    UNION ALL SELECT 'quality proxies', 'failures_retries_errors', failures FROM q
    UNION ALL SELECT 'quality proxies', 'assistant_turns', assistant_turns FROM q
    UNION ALL SELECT 'quality proxies', 'failures_per_100_assistant_turns', 100.0 * failures / NULLIF(assistant_turns, 0) FROM q
    UNION ALL SELECT 'quality proxies', 'task_completes', task_completes FROM q
    UNION ALL SELECT 'permissions', 'permission_requests', requests FROM reqs
    UNION ALL SELECT 'permissions', 'permission_requests_distinct', distinct_requests FROM reqs
    UNION ALL SELECT 'permissions', 'permission_wait_hours', hours FROM perm
    UNION ALL SELECT 'permissions', 'permission_waits_ge_60s', ge_60 FROM perm
    UNION ALL SELECT 'permissions', 'permission_waits_ge_300s', ge_300 FROM perm
) m;
