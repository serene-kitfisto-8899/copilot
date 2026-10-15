//! Report queries (PLAN §6.8) and the check of the PLAN §2 baseline.
//!
//! The definitions live in `sql/views.sql`; this module pins the as-of moment,
//! decodes view rows into printable tables, and compares the headline numbers
//! with the ones the PLAN quotes.

use std::collections::HashMap;
use std::fmt::Write as _;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, NaiveDate, Utc};
use sqlx::pool::PoolConnection;
use sqlx::postgres::{PgPool, PgRow, Postgres};
use sqlx::{AssertSqlSafe, Column, Row, TypeInfo};

/// When the PLAN §2 numbers were taken. Sessions kept running afterwards, so
/// today's totals are larger and the comparison must be pinned to this moment.
pub const BASELINE_AS_OF: &str = "2026-10-09T11:30:00Z";

/// One cell of a report table.
#[derive(Debug, Clone, PartialEq)]
pub enum Cell {
    Null,
    Int(i64),
    Float(f64),
    Text(String),
}

impl Cell {
    fn text(&self) -> String {
        match self {
            Cell::Null => "-".to_owned(),
            Cell::Int(i) => i.to_string(),
            Cell::Float(f) => fmt_float(*f),
            Cell::Text(s) => s.clone(),
        }
    }

    fn is_number(&self) -> bool {
        matches!(self, Cell::Int(_) | Cell::Float(_))
    }
}

/// Whole numbers print bare, everything else with two decimals.
pub fn fmt_float(f: f64) -> String {
    if !f.is_finite() {
        "-".to_owned()
    } else if f.fract() == 0.0 && f.abs() < 1e15 {
        format!("{f:.0}")
    } else {
        let text = format!("{f:.2}");
        // A tiny negative must not print as "-0.00".
        if text == "-0.00" {
            "0.00".to_owned()
        } else {
            text
        }
    }
}

#[derive(Debug, Clone, Default, PartialEq)]
pub struct Table {
    pub headers: Vec<String>,
    pub rows: Vec<Vec<Cell>>,
}

impl Table {
    fn from_rows(rows: &[PgRow]) -> Result<Self> {
        let Some(first) = rows.first() else {
            return Ok(Self::default());
        };
        let headers = first
            .columns()
            .iter()
            .map(|c| c.name().to_owned())
            .collect();
        let rows = rows
            .iter()
            .map(|row| (0..row.columns().len()).map(|i| decode(row, i)).collect())
            .collect::<Result<Vec<Vec<Cell>>>>()?;
        Ok(Self { headers, rows })
    }

    /// Column-aligned text: numbers right-aligned, everything else left.
    pub fn render(&self) -> String {
        if self.headers.is_empty() {
            return "(no rows)\n".to_owned();
        }
        let texts: Vec<Vec<String>> = self
            .rows
            .iter()
            .map(|row| row.iter().map(Cell::text).collect())
            .collect();
        let right: Vec<bool> = (0..self.headers.len())
            .map(|c| {
                self.rows
                    .iter()
                    .filter(|r| r[c] != Cell::Null)
                    .all(|r| r[c].is_number())
            })
            .collect();
        let widths: Vec<usize> = (0..self.headers.len())
            .map(|c| {
                texts
                    .iter()
                    .map(|r| r[c].chars().count())
                    .chain(std::iter::once(self.headers[c].chars().count()))
                    .max()
                    .unwrap_or(0)
            })
            .collect();
        let mut out = String::new();
        let mut line = |cells: &[&str]| {
            let parts: Vec<String> = cells
                .iter()
                .enumerate()
                .map(|(c, text)| {
                    if right[c] {
                        format!("{text:>w$}", w = widths[c])
                    } else {
                        format!("{text:<w$}", w = widths[c])
                    }
                })
                .collect();
            let _ = writeln!(out, "{}", parts.join("  ").trim_end());
        };
        line(&self.headers.iter().map(String::as_str).collect::<Vec<_>>());
        for row in &texts {
            line(&row.iter().map(String::as_str).collect::<Vec<_>>());
        }
        out
    }
}

/// The views only emit these types; anything else is a bug in `views.sql`.
fn decode(row: &PgRow, i: usize) -> Result<Cell> {
    let ty = row.columns()[i].type_info().name().to_owned();
    let cell = match ty.as_str() {
        "INT2" => row
            .try_get::<Option<i16>, _>(i)?
            .map(|v| Cell::Int(i64::from(v))),
        "INT4" => row
            .try_get::<Option<i32>, _>(i)?
            .map(|v| Cell::Int(i64::from(v))),
        "INT8" => row.try_get::<Option<i64>, _>(i)?.map(Cell::Int),
        "FLOAT4" => row
            .try_get::<Option<f32>, _>(i)?
            .map(|v| Cell::Float(f64::from(v))),
        "FLOAT8" => row.try_get::<Option<f64>, _>(i)?.map(Cell::Float),
        "BOOL" => row
            .try_get::<Option<bool>, _>(i)?
            .map(|v| Cell::Text(v.to_string())),
        "DATE" => row
            .try_get::<Option<NaiveDate>, _>(i)?
            .map(|v| Cell::Text(v.to_string())),
        "TIMESTAMPTZ" => row
            .try_get::<Option<DateTime<Utc>>, _>(i)?
            .map(|v| Cell::Text(v.format("%Y-%m-%d %H:%M").to_string())),
        "TEXT" | "VARCHAR" | "NAME" | "BPCHAR" => {
            row.try_get::<Option<String>, _>(i)?.map(Cell::Text)
        }
        other => bail!(
            "report column `{}` has unsupported type {other}",
            row.columns()[i].name()
        ),
    };
    Ok(cell.unwrap_or(Cell::Null))
}

/// How far a measured value may be from the PLAN's.
#[derive(Debug, Clone, Copy, PartialEq)]
pub enum Tol {
    /// Fraction of the PLAN value.
    Rel(f64),
    /// Same unit as the value (percentage points for shares).
    Abs(f64),
}

impl Tol {
    fn allows(self, plan: f64, measured: f64) -> bool {
        let diff = (measured - plan).abs();
        match self {
            Tol::Rel(r) => diff <= r * plan.abs() + 1e-9,
            Tol::Abs(a) => diff <= a + 1e-9,
        }
    }

    fn label(self) -> String {
        match self {
            Tol::Rel(r) => format!("±{}%", fmt_float(r * 100.0)),
            Tol::Abs(a) => format!("±{}", fmt_float(a)),
        }
    }
}

/// One number of PLAN §2.
#[derive(Debug, Clone, Copy)]
pub struct Expect {
    pub metric: &'static str,
    pub plan: f64,
    pub tol: Tol,
    /// P1 acceptance (the totals and the token-type split). The rest of §2 is
    /// quoted with "~" and rounded, and was taken at slightly different
    /// moments, so it is reported but does not decide the exit status.
    pub required: bool,
}

const fn req(metric: &'static str, plan: f64, tol: Tol) -> Expect {
    Expect {
        metric,
        plan,
        tol,
        required: true,
    }
}

const fn info(metric: &'static str, plan: f64, tol: Tol) -> Expect {
    Expect {
        metric,
        plan,
        tol,
        required: false,
    }
}

/// Informational tolerances: counts and amounts within 3 %, shares within 1 pt.
const COUNT: Tol = Tol::Rel(0.03);
const SHARE: Tol = Tol::Abs(1.0);

/// PLAN §2, in its order. Metric names are the `v_summary` ones plus the
/// `gpt_5_4_subagent_*` rows that [`Reporter::metrics`] adds from `v_model`.
pub const BASELINE: &[Expect] = &[
    // Acceptance: ≈129.4k AIU in ~18.7k calls over 188 sessions with usage, and
    // the token-type split (the PLAN quotes shares to 0.1 pt, so ±0.1 pt).
    req("aiu_total", 129_400.0, Tol::Rel(0.01)),
    req("calls", 18_700.0, Tol::Rel(0.01)),
    req("sessions_with_usage", 188.0, Tol::Abs(0.0)),
    req("aiu_pct_cache_read", 53.0, Tol::Abs(0.1)),
    req("aiu_pct_cache_write", 29.9, Tol::Abs(0.1)),
    req("aiu_pct_output", 14.7, Tol::Abs(0.1)),
    req("aiu_pct_input", 2.3, Tol::Abs(0.1)),
    // "exact, from token_details_json": the four types must add up to nano_aiu.
    req("split_minus_total_aiu", 0.0, Tol::Abs(0.01)),
    info("aiu_pct_prompt_ge_100k", 81.5, SHARE),
    info("aiu_pct_prompt_gt_400k", 21.6, SHARE),
    info("aiu_pct_top_12_sessions", 50.0, SHARE),
    info("sessions_gt_1000_aiu", 30.0, COUNT),
    info("aiu_pct_sessions_gt_1000", 72.0, SHARE),
    info("sessions_gt_2000_aiu", 15.0, COUNT),
    info("aiu_pct_sessions_gt_2000", 55.0, SHARE),
    info("autopilot_sessions", 86.0, COUNT),
    info("aiu_pct_autopilot", 71.8, SHARE),
    info("autopilot_aiu_per_session", 1_089.0, COUNT),
    info("autopilot_calls_per_session", 153.0, COUNT),
    info("manual_aiu_per_session", 350.0, COUNT),
    info("manual_calls_per_session", 56.0, COUNT),
    info("cold_calls", 461.0, COUNT),
    info("aiu_pct_cold", 19.9, SHARE),
    info("cold_user_calls", 247.0, COUNT),
    info("aiu_pct_cold_user", 12.4, SHARE),
    info("cold_user_mean_idle_min", 193.0, COUNT),
    info("cold_user_mean_context_tokens", 231_000.0, COUNT),
    info("cold_user_aiu_per_call", 65.0, COUNT),
    info("cold_agent_calls", 187.0, COUNT),
    info("aiu_pct_cold_agent", 7.3, SHARE),
    info("aiu_pct_subagent", 11.0, SHARE),
    info("gpt_5_4_subagent_calls", 2_219.0, COUNT),
    info("aiu_pct_gpt_5_4_subagent", 7.0, SHARE),
    info("gpt_5_4_subagent_aiu_per_call", 4.1, COUNT),
    info("gpt_5_4_subagent_mean_prompt_tokens", 86_000.0, COUNT),
    info("permission_requests_distinct", 6_607.0, COUNT),
    info("permission_wait_hours", 86.0, COUNT),
    info("permission_waits_ge_60s", 540.0, COUNT),
    info("permission_waits_ge_300s", 129.0, COUNT),
    info("aborts", 74.0, COUNT),
    info("user_messages", 2_596.0, COUNT),
    info("aborts_per_100_user_messages", 2.9, COUNT),
    info("failures_retries_errors", 353.0, COUNT),
    info("assistant_turns", 24_700.0, COUNT),
    info("failures_per_100_assistant_turns", 1.4, COUNT),
    info("task_completes", 272.0, COUNT),
];

/// The outcome for one [`Expect`].
#[derive(Debug, Clone)]
pub struct Check {
    pub expect: Expect,
    pub measured: Option<f64>,
    pub pass: bool,
}

pub fn evaluate(expects: &[Expect], measured: &HashMap<String, f64>) -> Vec<Check> {
    expects
        .iter()
        .map(|e| {
            let m = measured.get(e.metric).copied();
            Check {
                expect: *e,
                measured: m,
                pass: m.is_some_and(|m| e.tol.allows(e.plan, m)),
            }
        })
        .collect()
}

/// What a baseline run found.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    pub required: usize,
    pub required_failed: usize,
    pub info: usize,
    pub info_differing: usize,
}

impl Verdict {
    pub fn of(checks: &[Check]) -> Self {
        let mut v = Verdict {
            required: 0,
            required_failed: 0,
            info: 0,
            info_differing: 0,
        };
        for c in checks {
            if c.expect.required {
                v.required += 1;
                v.required_failed += usize::from(!c.pass);
            } else {
                v.info += 1;
                v.info_differing += usize::from(!c.pass);
            }
        }
        v
    }

    pub fn ok(&self) -> bool {
        self.required_failed == 0
    }
}

pub fn checks_table(checks: &[Check]) -> Table {
    let rows = checks
        .iter()
        .map(|c| {
            let status = match (c.measured, c.pass) {
                (None, _) => "MISSING",
                (Some(_), true) => "PASS",
                (Some(_), false) => "DIFF",
            };
            vec![
                Cell::Text(status.to_owned()),
                Cell::Text(
                    if c.expect.required {
                        "required"
                    } else {
                        "info"
                    }
                    .to_owned(),
                ),
                Cell::Text(c.expect.metric.to_owned()),
                Cell::Float(c.expect.plan),
                c.measured.map_or(Cell::Null, Cell::Float),
                c.measured
                    .map_or(Cell::Null, |m| Cell::Float(m - c.expect.plan)),
                Cell::Text(c.expect.tol.label()),
            ]
        })
        .collect();
    Table {
        headers: [
            "status",
            "kind",
            "metric",
            "plan",
            "measured",
            "diff",
            "tolerance",
        ]
        .map(str::to_owned)
        .to_vec(),
        rows,
    }
}

/// A single pinned connection, so the session setting `ctx.as_of` that the
/// views read stays in force for every query.
pub struct Reporter {
    conn: PoolConnection<Postgres>,
}

impl Reporter {
    pub async fn new(pool: &PgPool, as_of: Option<DateTime<Utc>>) -> Result<Self> {
        let mut conn = pool.acquire().await.context("connecting for the report")?;
        sqlx::query("SELECT set_config('ctx.as_of', $1, false)")
            .bind(as_of.map(|t| t.to_rfc3339()).unwrap_or_default())
            .execute(&mut *conn)
            .await?;
        Ok(Self { conn })
    }

    /// Runs a query over the views and decodes it for printing. The text is
    /// built from constants and validated numbers by the callers, never from
    /// free-form input.
    pub async fn table(&mut self, query: &str) -> Result<Table> {
        let rows = sqlx::query(AssertSqlSafe(query.to_owned()))
            .fetch_all(&mut *self.conn)
            .await?;
        Table::from_rows(&rows)
    }

    /// `(section, metric, value)` from `v_summary`, in the view's order.
    pub async fn summary(&mut self) -> Result<Vec<(String, String, Option<f64>)>> {
        Ok(
            sqlx::query_as("SELECT section, metric, value FROM v_summary")
                .fetch_all(&mut *self.conn)
                .await?,
        )
    }

    /// Every `v_summary` metric plus the per-model rows of the baseline.
    pub async fn metrics(&mut self) -> Result<HashMap<String, f64>> {
        let mut out: HashMap<String, f64> = self
            .summary()
            .await?
            .into_iter()
            .filter_map(|(_, metric, value)| value.map(|v| (metric, v)))
            .collect();
        let gpt: Option<(i64, f64, f64, Option<f64>)> = sqlx::query_as(
            "SELECT calls, aiu_pct, aiu_per_call, mean_prompt_tokens
               FROM v_model WHERE model = 'gpt-5.4' AND is_sub",
        )
        .fetch_optional(&mut *self.conn)
        .await?;
        if let Some((calls, pct, per_call, prompt)) = gpt {
            out.insert("gpt_5_4_subagent_calls".to_owned(), calls as f64);
            out.insert("aiu_pct_gpt_5_4_subagent".to_owned(), pct);
            out.insert("gpt_5_4_subagent_aiu_per_call".to_owned(), per_call);
            if let Some(p) = prompt {
                out.insert("gpt_5_4_subagent_mean_prompt_tokens".to_owned(), p);
            }
        }
        Ok(out)
    }

    /// The PLAN §2 comparison at the pinned moment.
    pub async fn baseline(&mut self) -> Result<Vec<Check>> {
        let metrics = self.metrics().await?;
        Ok(evaluate(BASELINE, &metrics))
    }

    /// Oldest and newest call and event, for the report header.
    pub async fn coverage(&mut self) -> Result<(Option<DateTime<Utc>>, Option<DateTime<Utc>>)> {
        Ok(sqlx::query_as("SELECT min(ts), max(ts) FROM v_call")
            .fetch_one(&mut *self.conn)
            .await?)
    }
}

/// Plain-text rendering of [`Reporter::summary`], grouped by section.
pub fn render_summary(rows: &[(String, String, Option<f64>)]) -> String {
    let mut sections: Vec<&str> = Vec::new();
    for (section, ..) in rows {
        if !sections.contains(&section.as_str()) {
            sections.push(section);
        }
    }
    let width = rows.iter().map(|(_, m, _)| m.len()).max().unwrap_or(0);
    let mut out = String::new();
    for section in sections {
        let _ = writeln!(out, "\n{section}");
        for (_, metric, value) in rows.iter().filter(|(s, ..)| s == section) {
            let value = value.map_or_else(|| "-".to_owned(), fmt_float);
            let _ = writeln!(out, "  {metric:<width$}  {value:>12}");
        }
    }
    out
}

/// Which way a quality proxy gets worse.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Worse {
    Higher,
    Lower,
}

/// The quality proxies (PLAN §6.8), all per-turn ratios so that quiet weeks do
/// not skew them. The names are `v_weekly` columns.
///
/// The correction-phrase rate is not here: the PLAN leaves its phrase list
/// open ("TBD"), so there is nothing to measure yet.
pub const PROXIES: [(&str, Worse); 4] = [
    ("aborts_per_100_msgs", Worse::Higher),
    ("failures_per_100_turns", Worse::Higher),
    ("task_completes_per_100_msgs", Worse::Lower),
    ("perm_waits_ge_300s_per_100_msgs", Worse::Higher),
];

/// First week the guardrail looks at: the Monday after [`BASELINE_AS_OF`].
pub const GUARDRAIL_SINCE: &str = "2026-10-12";
/// "More than 25 % worse than the Jun–Oct baseline".
pub const GUARDRAIL_THRESHOLD: f64 = 0.25;
/// Weeks with fewer user messages are too quiet for a ratio to mean anything.
pub const GUARDRAIL_MIN_MESSAGES: i64 = 30;

/// One week of proxy values, in [`PROXIES`] order.
#[derive(Debug, Clone, PartialEq)]
pub struct GuardWeek {
    pub week: NaiveDate,
    pub user_messages: i64,
    pub values: [Option<f64>; 4],
}

/// A proxy that stayed worse than the baseline for consecutive weeks.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Streak {
    pub proxy: &'static str,
    pub from: NaiveDate,
    pub to: NaiveDate,
    pub weeks: usize,
}

/// How much worse `value` is than `baseline`, as a fraction (0.3 = 30 % worse;
/// negative = better). `None` when the baseline is zero, since no ratio exists.
pub fn worse_by(kind: Worse, baseline: f64, value: f64) -> Option<f64> {
    if baseline <= 0.0 {
        return None;
    }
    Some(match kind {
        Worse::Higher => (value - baseline) / baseline,
        Worse::Lower => (baseline - value) / baseline,
    })
}

/// Streaks of at least two directly consecutive weeks in which a proxy was
/// worse than `baseline` by more than `threshold`. A week with fewer than
/// `min_messages` user messages, or without a value, breaks the streak.
pub fn guardrail(
    baseline: &[Option<f64>; 4],
    weeks: &[GuardWeek],
    threshold: f64,
    min_messages: i64,
) -> Vec<Streak> {
    let mut streaks = Vec::new();
    for (p, (proxy, kind)) in PROXIES.iter().enumerate() {
        let Some(base) = baseline[p] else { continue };
        let mut run: Option<(NaiveDate, NaiveDate, usize)> = None;
        let mut close = |run: &mut Option<(NaiveDate, NaiveDate, usize)>| {
            if let Some((from, to, weeks)) = run.take()
                && weeks >= 2
            {
                streaks.push(Streak {
                    proxy,
                    from,
                    to,
                    weeks,
                });
            }
        };
        for w in weeks {
            let bad = w.user_messages >= min_messages
                && w.values[p]
                    .and_then(|v| worse_by(*kind, base, v))
                    .is_some_and(|d| d > threshold);
            match (&mut run, bad) {
                (Some((_, last, n)), true) if (w.week - *last).num_days() == 7 => {
                    *last = w.week;
                    *n += 1;
                }
                (_, true) => {
                    close(&mut run);
                    run = Some((w.week, w.week, 1));
                }
                (_, false) => close(&mut run),
            }
        }
        close(&mut run);
    }
    streaks
}

impl Reporter {
    /// Weekly proxy values since `since`, oldest first.
    pub async fn guard_weeks(&mut self, since: NaiveDate) -> Result<Vec<GuardWeek>> {
        type Row = (
            NaiveDate,
            Option<i64>,
            Option<f64>,
            Option<f64>,
            Option<f64>,
            Option<f64>,
        );
        let rows: Vec<Row> = sqlx::query_as(
            "SELECT week, user_messages, aborts_per_100_msgs, failures_per_100_turns,
                    task_completes_per_100_msgs, perm_waits_ge_300s_per_100_msgs
               FROM v_weekly WHERE week >= $1 ORDER BY week",
        )
        .bind(since)
        .fetch_all(&mut *self.conn)
        .await?;
        Ok(rows
            .into_iter()
            .map(|(week, msgs, a, f, t, p)| GuardWeek {
                week,
                user_messages: msgs.unwrap_or(0),
                values: [a, f, t, p],
            })
            .collect())
    }

    /// The proxies over the whole baseline window; call on a reporter pinned
    /// to [`BASELINE_AS_OF`].
    pub async fn baseline_proxies(&mut self) -> Result<[Option<f64>; 4]> {
        let m = self.metrics().await?;
        let per_100_msgs = |metric: &str| {
            let msgs = *m.get("user_messages")?;
            let value = *m.get(metric)?;
            (msgs > 0.0).then(|| 100.0 * value / msgs)
        };
        Ok([
            m.get("aborts_per_100_user_messages").copied(),
            m.get("failures_per_100_assistant_turns").copied(),
            per_100_msgs("task_completes"),
            per_100_msgs("permission_waits_ge_300s"),
        ])
    }
}

/// The weekly proxies against the baseline, one row per week; `!` marks a
/// value worse than the threshold in a week with enough volume.
pub fn guardrail_table(
    baseline: &[Option<f64>; 4],
    weeks: &[GuardWeek],
    threshold: f64,
    min_messages: i64,
) -> Table {
    let cell = |p: usize, w: &GuardWeek| match (baseline[p], w.values[p]) {
        (Some(base), Some(v)) => {
            let delta = worse_by(PROXIES[p].1, base, v);
            let flag = if w.user_messages >= min_messages && delta.is_some_and(|d| d > threshold) {
                " !"
            } else {
                ""
            };
            match delta {
                Some(d) => Cell::Text(format!("{v:.2} ({:+.0}%){flag}", 100.0 * d)),
                None => Cell::Text(format!("{v:.2}")),
            }
        }
        (_, Some(v)) => Cell::Text(format!("{v:.2}")),
        _ => Cell::Null,
    };
    let mut headers = vec!["week".to_owned(), "msgs".to_owned()];
    headers.extend(PROXIES.iter().map(|(name, _)| (*name).to_owned()));
    let mut rows = vec![{
        let mut row = vec![Cell::Text("baseline".to_owned()), Cell::Null];
        row.extend(baseline.iter().map(|b| b.map_or(Cell::Null, Cell::Float)));
        row
    }];
    for w in weeks {
        let mut row = vec![Cell::Text(w.week.to_string()), Cell::Int(w.user_messages)];
        row.extend((0..PROXIES.len()).map(|p| cell(p, w)));
        rows.push(row);
    }
    Table { headers, rows }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn floats_print_bare_when_whole_and_with_two_decimals_otherwise() {
        assert_eq!(fmt_float(18_722.0), "18722");
        assert_eq!(fmt_float(129_366.447), "129366.45");
        assert_eq!(fmt_float(0.0), "0");
        assert_eq!(fmt_float(-0.0004), "0.00");
        assert_eq!(fmt_float(-1.5), "-1.50");
        assert_eq!(fmt_float(f64::NAN), "-");
    }

    #[test]
    fn tolerances_are_relative_or_absolute() {
        assert!(Tol::Rel(0.01).allows(129_400.0, 129_366.4));
        assert!(!Tol::Rel(0.01).allows(129_400.0, 131_000.0));
        assert!(Tol::Abs(0.1).allows(2.3, 2.345));
        assert!(!Tol::Abs(0.1).allows(2.3, 2.5));
        assert!(Tol::Abs(0.0).allows(188.0, 188.0));
        assert!(!Tol::Abs(0.0).allows(188.0, 187.0));
    }

    #[test]
    fn missing_metrics_fail_and_required_lines_decide_the_verdict() {
        let measured: HashMap<String, f64> = [
            ("aiu_total".to_owned(), 129_366.4),
            ("calls".to_owned(), 18_722.0),
            ("sessions_with_usage".to_owned(), 188.0),
            ("sessions_gt_2000_aiu".to_owned(), 14.0),
        ]
        .into();
        let expects = [
            req("aiu_total", 129_400.0, Tol::Rel(0.01)),
            req("calls", 18_700.0, Tol::Rel(0.01)),
            req("sessions_with_usage", 188.0, Tol::Abs(0.0)),
            info("sessions_gt_2000_aiu", 15.0, COUNT),
            info("never_measured", 1.0, COUNT),
        ];
        let checks = evaluate(&expects, &measured);
        let verdict = Verdict::of(&checks);
        assert_eq!(
            verdict,
            Verdict {
                required: 3,
                required_failed: 0,
                info: 2,
                info_differing: 2
            }
        );
        assert!(verdict.ok());

        let mut missing = measured.clone();
        missing.remove("calls");
        let verdict = Verdict::of(&evaluate(&expects, &missing));
        assert_eq!(verdict.required_failed, 1);
        assert!(!verdict.ok());
    }

    #[test]
    fn baseline_table_lists_status_and_difference() {
        let measured: HashMap<String, f64> = [("calls".to_owned(), 19_000.0)].into();
        let checks = evaluate(&[req("calls", 18_700.0, Tol::Rel(0.01))], &measured);
        let table = checks_table(&checks);
        assert_eq!(table.rows[0][0], Cell::Text("DIFF".to_owned()));
        assert_eq!(table.rows[0][5], Cell::Float(300.0));
        let rendered = table.render();
        assert!(rendered.contains("DIFF"), "{rendered}");
        assert!(rendered.contains("±1%"), "{rendered}");
    }

    #[test]
    fn numbers_align_right_and_text_left() {
        let table = Table {
            headers: vec!["name".to_owned(), "n".to_owned()],
            rows: vec![
                vec![Cell::Text("a".to_owned()), Cell::Int(5)],
                vec![Cell::Text("longer".to_owned()), Cell::Float(12.5)],
                vec![Cell::Text("c".to_owned()), Cell::Null],
            ],
        };
        let rendered = table.render();
        let lines: Vec<&str> = rendered.lines().collect();
        assert_eq!(lines[0], "name        n");
        assert_eq!(lines[1], "a           5");
        assert_eq!(lines[2], "longer  12.50");
        assert_eq!(lines[3], "c           -");
    }

    #[test]
    fn summary_groups_rows_by_section_in_first_seen_order() {
        let rows = vec![
            ("totals".to_owned(), "calls".to_owned(), Some(3.0)),
            ("cold".to_owned(), "cold_calls".to_owned(), None),
            ("totals".to_owned(), "aiu_total".to_owned(), Some(1.5)),
        ];
        let rendered = render_summary(&rows);
        let totals = rendered.find("totals").unwrap();
        let cold = rendered.find("\ncold").unwrap();
        assert!(totals < cold);
        assert!(rendered.contains("calls"));
        assert!(rendered.contains("aiu_total"));
        assert_eq!(rendered.matches("totals").count(), 1);
    }

    fn week(day: u32, msgs: i64, aborts: Option<f64>) -> GuardWeek {
        GuardWeek {
            week: NaiveDate::from_ymd_opt(2026, 10, day).unwrap(),
            user_messages: msgs,
            values: [aborts, None, None, None],
        }
    }

    const BASE: [Option<f64>; 4] = [Some(2.0), None, None, None];

    #[test]
    fn worse_by_follows_the_direction_of_each_proxy() {
        assert_eq!(worse_by(Worse::Higher, 2.0, 3.0), Some(0.5));
        assert_eq!(worse_by(Worse::Lower, 10.0, 7.5), Some(0.25));
        assert!(worse_by(Worse::Lower, 10.0, 12.0).unwrap() < 0.0);
        assert_eq!(worse_by(Worse::Higher, 0.0, 3.0), None);
    }

    #[test]
    fn two_consecutive_bad_weeks_make_a_streak_and_one_does_not() {
        // 2.6 is +30 %, 2.4 is +20 %.
        let streaks = guardrail(
            &BASE,
            &[week(12, 100, Some(2.6)), week(19, 100, Some(2.4))],
            0.25,
            30,
        );
        assert!(streaks.is_empty());

        let streaks = guardrail(
            &BASE,
            &[
                week(12, 100, Some(2.6)),
                week(19, 100, Some(3.0)),
                week(26, 100, Some(2.9)),
            ],
            0.25,
            30,
        );
        assert_eq!(
            streaks,
            vec![Streak {
                proxy: "aborts_per_100_msgs",
                from: NaiveDate::from_ymd_opt(2026, 10, 12).unwrap(),
                to: NaiveDate::from_ymd_opt(2026, 10, 26).unwrap(),
                weeks: 3,
            }]
        );
    }

    #[test]
    fn quiet_weeks_and_gaps_break_a_streak() {
        let quiet = guardrail(
            &BASE,
            &[
                week(12, 100, Some(4.0)),
                week(19, 5, Some(9.0)),
                week(26, 100, Some(4.0)),
            ],
            0.25,
            30,
        );
        assert!(
            quiet.is_empty(),
            "a low-volume week must not count or bridge"
        );

        let gap = guardrail(
            &BASE,
            &[week(12, 100, Some(4.0)), week(26, 100, Some(4.0))],
            0.25,
            30,
        );
        assert!(
            gap.is_empty(),
            "weeks that are not adjacent are not consecutive"
        );

        let missing = guardrail(
            &BASE,
            &[week(12, 100, Some(4.0)), week(19, 100, None)],
            0.25,
            30,
        );
        assert!(missing.is_empty());
    }

    #[test]
    fn a_proxy_without_a_baseline_is_never_flagged() {
        let none = [None; 4];
        let weeks = [week(12, 100, Some(9.0)), week(19, 100, Some(9.0))];
        assert!(guardrail(&none, &weeks, 0.25, 30).is_empty());
    }

    #[test]
    fn the_table_marks_weeks_over_the_threshold() {
        let table = guardrail_table(
            &BASE,
            &[week(12, 100, Some(3.0)), week(19, 5, Some(3.0))],
            0.25,
            30,
        );
        assert_eq!(table.rows[0][0], Cell::Text("baseline".to_owned()));
        assert_eq!(table.rows[1][2], Cell::Text("3.00 (+50%) !".to_owned()));
        assert_eq!(
            table.rows[2][2],
            Cell::Text("3.00 (+50%)".to_owned()),
            "5 messages is too quiet to flag"
        );
    }
}
