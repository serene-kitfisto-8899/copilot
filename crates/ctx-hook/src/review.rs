//! `ctx-hook review`: what the hook has been doing, read from the audit table
//! and from the events the CLI wrote about the same requests. PLAN.md §5 asks
//! for "3 days of shadow log reviewed before enabling"; this is that review.
//!
//! The audit table says what the hook decided. The events say what happened
//! next, and each row is joined to them in two ways:
//!
//! * `hook.start` / `hook.end`: the CLI logs every hook call with the input it
//!   gave the hook, and that input's `timestamp` is the one stored in
//!   `hook_audit.ts`, so a row and its call match exactly. That gives the time
//!   the CLI waited for the hook (the process start included, which the hook
//!   cannot measure itself), and it shows the calls that left no row: a hook
//!   that crashes or times out fails open, silently.
//! * `permission.requested` / `permission.completed`: when the hook passed, or
//!   only logged what it would have allowed (shadow mode), the CLI went on to
//!   ask a person, and that question carries the same command text. It is
//!   matched by the hash of the text and by time (the question follows the
//!   call by milliseconds), and its answer says whether a person agreed with
//!   the hook. A request the CLI approved by itself leaves no question: it was
//!   "never asked", and there is nothing to compare the hook with.
//!
//! [`analyze`] is a pure function of the joined rows and is tested on made-up
//! ones; [`load`] reads the real ones.

use std::collections::{BTreeMap, HashMap};
use std::path::PathBuf;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, Duration, FixedOffset, Local, NaiveDate, Offset, Utc};
use ctx_core::config::hook_database_url;
use ctx_core::db;
use sqlx::PgPool;

use crate::audit::{self, BENCH_SESSION_PREFIX, Drained};
use crate::config::Config;
use crate::hook::Policy;
use crate::replay::{AWAY_S, UNATTENDED, clip, line, n, nearest_rank, pct, pct_f, secs};
use crate::vars::Vars;

/// How long the log has to run under one policy before the review calls it
/// enough (PLAN.md §5: three days).
pub const OBSERVE_H: f64 = 72.0;
/// PLAN.md §5: the hook's 95th percentile is under this.
pub const P95_BUDGET_MS: f64 = 50.0;

/// What the CLI recorded about a question to a person.
#[derive(Debug, Clone, PartialEq)]
pub struct Question {
    pub request_id: String,
    pub asked_at: DateTime<Utc>,
    pub kind: String,
    /// `commandSegments[0].workingDirectory`: where the CLI says it runs the
    /// command (recorded by newer CLI builds only).
    pub cli_cwd: Option<String>,
    /// `result.kind` of the answer.
    pub result: Option<String>,
    pub waited_s: Option<f64>,
}

/// One row of `hook_audit` and what the events say about it.
#[derive(Debug, Clone, PartialEq)]
pub struct Logged {
    pub ts: DateTime<Utc>,
    pub session_id: String,
    pub tool: String,
    pub command: Option<String>,
    pub cwd: Option<String>,
    /// The decision was `allow`: in shadow mode, what the hook would have
    /// approved.
    pub allowed: bool,
    pub rule: String,
    pub shadow: bool,
    pub latency_us: Option<i32>,
    pub policy: String,
    /// From `hook.start` to `hook.end` as the CLI logged them.
    pub wall_ms: Option<f64>,
    /// Where the session was when the hook was called.
    pub session_cwd: Option<String>,
    pub question: Option<Question>,
}

/// What a person made of a question.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum Answer {
    Approved,
    Refused,
    /// There was nobody to ask (a `copilot -p` run).
    Unattended,
    None,
}

/// Anything that is not recognisably a yes counts as a no: a new kind of
/// answer in a later CLI must stop the review, not slip through it. The no's
/// known today are `denied-interactively-by-user` and `cancelled`.
fn classify(result: Option<&str>) -> Answer {
    match result {
        None => Answer::None,
        Some(UNATTENDED) => Answer::Unattended,
        Some(r) if r.starts_with("approved") => Answer::Approved,
        Some(_) => Answer::Refused,
    }
}

/// A group of rows and what became of the ones the CLI asked a person about.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Outcomes {
    pub rows: usize,
    /// No question: the CLI let the request through by itself (or the
    /// question could not be found).
    pub not_asked: usize,
    pub approved: usize,
    pub refused: usize,
    pub unattended: usize,
    pub unanswered: usize,
    /// Seconds the answered questions waited.
    pub waits: Vec<f64>,
}

impl Outcomes {
    fn add(&mut self, question: Option<&Question>) {
        self.rows += 1;
        let Some(q) = question else {
            self.not_asked += 1;
            return;
        };
        match classify(q.result.as_deref()) {
            Answer::Approved => self.approved += 1,
            Answer::Refused => self.refused += 1,
            Answer::Unattended => self.unattended += 1,
            Answer::None => self.unanswered += 1,
        }
        self.waits.extend(q.waited_s);
    }

    pub fn asked(&self) -> usize {
        self.rows - self.not_asked
    }

    /// No wait counted for more than [`AWAY_S`], as in the replay.
    pub fn wait_s(&self) -> f64 {
        self.waits.iter().map(|w| w.min(AWAY_S)).sum()
    }
}

/// The hook calls the CLI logged, against the rows the hook wrote.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Calls {
    pub logged: usize,
    pub with_row: usize,
    /// `hook.end` says the call did not succeed (a timeout, a crash).
    pub failed: usize,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Spread {
    pub n: usize,
    pub min: f64,
    pub p50: f64,
    pub p95: f64,
    pub p99: f64,
    pub max: f64,
}

pub(crate) fn spread(mut values: Vec<f64>) -> Option<Spread> {
    values.sort_by(f64::total_cmp);
    let (min, max) = (*values.first()?, *values.last()?);
    Some(Spread {
        n: values.len(),
        min,
        p50: nearest_rank(&values, 0.5),
        p95: nearest_rank(&values, 0.95),
        p99: nearest_rank(&values, 0.99),
        max,
    })
}

#[derive(Debug, Clone, PartialEq)]
pub struct PolicyRows {
    pub policy: String,
    pub rows: usize,
    pub allowed: usize,
    pub first: DateTime<Utc>,
    pub last: DateTime<Utc>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Day {
    pub date: NaiveDate,
    pub rows: usize,
    pub allowed: usize,
    pub asked: usize,
}

/// Rows whose directory could be checked against another source, and how many
/// of those differed.
#[derive(Debug, Default, Clone, Copy, PartialEq, Eq)]
pub struct Compared {
    pub compared: usize,
    pub differ: usize,
}

impl Compared {
    fn add(&mut self, hook: Option<&str>, other: Option<&str>) -> bool {
        let (Some(hook), Some(other)) = (hook, other) else {
            return false;
        };
        self.compared += 1;
        let differ = hook != other;
        self.differ += usize::from(differ);
        differ
    }
}

/// The directory the hook was given, against the CLI's own record of where the
/// command runs and against where the session was. A difference matters for a
/// request the hook would allow: its relative paths were judged somewhere else.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Dirs {
    pub cli: Compared,
    pub session: Compared,
    pub cli_allowed: Compared,
    pub session_allowed: Compared,
    pub differing: Vec<Logged>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum State {
    Pass,
    /// Not enough evidence yet.
    Wait,
    Fail,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Check {
    pub name: &'static str,
    pub state: State,
    pub detail: String,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Report {
    /// Seconds east of UTC the days and times are shown in.
    pub offset_s: i32,
    /// The policy the checks are about: the one in force now.
    pub current: String,
    pub rows: usize,
    pub first: Option<DateTime<Utc>>,
    pub last: Option<DateTime<Utc>>,
    pub shadow: usize,
    pub enforced: usize,
    pub allowed: usize,
    pub tools: Vec<(String, usize)>,
    pub policies: Vec<PolicyRows>,
    pub days: Vec<Day>,
    pub allow_rules: Vec<(String, Outcomes)>,
    pub pass_rules: Vec<(String, Outcomes)>,
    pub shadow_allow: Outcomes,
    pub shadow_pass: Outcomes,
    pub enforced_allow: Outcomes,
    pub enforced_pass: Outcomes,
    /// Rows whose question was taken by another row (the same command called
    /// twice within seconds): they count as never asked.
    pub shared: usize,
    /// Shadow rows the hook would have allowed and a person refused.
    pub refused: Vec<Logged>,
    pub calls: Calls,
    pub wall: Option<Spread>,
    pub in_process: Option<Spread>,
    pub dirs: Dirs,
    pub checks: Vec<Check>,
}

fn zone(offset_s: i32) -> FixedOffset {
    FixedOffset::east_opt(offset_s).unwrap_or_else(|| Utc.fix())
}

fn ranked(counts: BTreeMap<String, Outcomes>) -> Vec<(String, Outcomes)> {
    let mut rows: Vec<_> = counts.into_iter().collect();
    rows.sort_by_key(|row| std::cmp::Reverse(row.1.rows));
    rows
}

/// What the rows come to. `current` is the policy in force now, which the
/// checks are about: a log made under another policy says nothing about this
/// one. `offset_s` is the time zone the days are counted in.
pub fn analyze(rows: &[Logged], calls: Calls, current: &str, offset_s: i32) -> Report {
    let tz = zone(offset_s);
    let mut r = Report {
        offset_s,
        current: current.to_owned(),
        calls,
        ..Report::default()
    };

    // A question belongs to one row, the nearest in time: the same command
    // called twice within seconds must not be answered twice
    let mut owner: HashMap<(&str, &str), (usize, i64)> = HashMap::new();
    for (i, row) in rows.iter().enumerate() {
        let Some(q) = &row.question else { continue };
        let gap = (q.asked_at - row.ts).num_milliseconds().abs();
        owner
            .entry((row.session_id.as_str(), q.request_id.as_str()))
            .and_modify(|(j, best)| {
                if gap < *best {
                    (*j, *best) = (i, gap);
                }
            })
            .or_insert((i, gap));
    }
    let questions: Vec<Option<&Question>> = rows
        .iter()
        .enumerate()
        .map(|(i, row)| {
            let q = row.question.as_ref()?;
            (owner[&(row.session_id.as_str(), q.request_id.as_str())].0 == i).then_some(q)
        })
        .collect();

    let mut tools: BTreeMap<&str, usize> = BTreeMap::new();
    let mut policies: BTreeMap<&str, PolicyRows> = BTreeMap::new();
    let mut days: BTreeMap<NaiveDate, Day> = BTreeMap::new();
    let mut allow_rules: BTreeMap<String, Outcomes> = BTreeMap::new();
    let mut pass_rules: BTreeMap<String, Outcomes> = BTreeMap::new();
    let (mut wall, mut in_process) = (Vec::new(), Vec::new());

    for (row, question) in rows.iter().zip(&questions) {
        let question = *question;
        r.rows += 1;
        r.first = Some(r.first.map_or(row.ts, |t| t.min(row.ts)));
        r.last = Some(r.last.map_or(row.ts, |t| t.max(row.ts)));
        r.allowed += usize::from(row.allowed);
        if row.shadow {
            r.shadow += 1;
        } else {
            r.enforced += 1;
        }
        r.shared += usize::from(row.question.is_some() && question.is_none());
        if row.tool != "bash" {
            *tools.entry(row.tool.as_str()).or_default() += 1;
        }

        let group = match (row.shadow, row.allowed) {
            (true, true) => &mut r.shadow_allow,
            (true, false) => &mut r.shadow_pass,
            (false, true) => &mut r.enforced_allow,
            (false, false) => &mut r.enforced_pass,
        };
        group.add(question);
        if row.allowed {
            &mut allow_rules
        } else {
            &mut pass_rules
        }
        .entry(row.rule.clone())
        .or_default()
        .add(question);

        let entry = policies
            .entry(row.policy.as_str())
            .or_insert_with(|| PolicyRows {
                policy: row.policy.clone(),
                rows: 0,
                allowed: 0,
                first: row.ts,
                last: row.ts,
            });
        entry.rows += 1;
        entry.allowed += usize::from(row.allowed);
        entry.first = entry.first.min(row.ts);
        entry.last = entry.last.max(row.ts);

        let date = row.ts.with_timezone(&tz).date_naive();
        let day = days.entry(date).or_insert_with(|| Day {
            date,
            rows: 0,
            allowed: 0,
            asked: 0,
        });
        day.rows += 1;
        day.allowed += usize::from(row.allowed);
        day.asked += usize::from(question.is_some());

        wall.extend(row.wall_ms);
        in_process.extend(row.latency_us.map(|us| f64::from(us) / 1000.0));

        let cli = row.question.as_ref().and_then(|q| q.cli_cwd.as_deref());
        let off_cli = r.dirs.cli.add(row.cwd.as_deref(), cli);
        let off_session = r
            .dirs
            .session
            .add(row.cwd.as_deref(), row.session_cwd.as_deref());
        if row.allowed {
            r.dirs.cli_allowed.add(row.cwd.as_deref(), cli);
            r.dirs
                .session_allowed
                .add(row.cwd.as_deref(), row.session_cwd.as_deref());
        }
        if off_cli || off_session {
            r.dirs.differing.push(row.clone());
        }

        if row.shadow
            && row.allowed
            && question.is_some_and(|q| classify(q.result.as_deref()) == Answer::Refused)
        {
            r.refused.push(row.clone());
        }
    }

    r.tools = {
        let mut v: Vec<_> = tools.into_iter().map(|(k, c)| (k.to_owned(), c)).collect();
        v.sort_by_key(|tool| std::cmp::Reverse(tool.1));
        v
    };
    r.policies = policies.into_values().collect();
    r.policies.sort_by_key(|p| p.first);
    r.days = days.into_values().collect();
    r.allow_rules = ranked(allow_rules);
    r.pass_rules = ranked(pass_rules);
    r.wall = spread(wall);
    r.in_process = spread(in_process);
    r.checks = checks(rows, &questions, current);
    r
}

/// The gates PLAN.md §5 sets before enforcing, judged on the shadow rows made
/// under the policy now in force.
fn checks(rows: &[Logged], questions: &[Option<&Question>], current: &str) -> Vec<Check> {
    let seen: Vec<(&Logged, Option<&Question>)> = rows
        .iter()
        .zip(questions)
        .filter(|(row, _)| row.shadow && row.policy == current)
        .map(|(row, q)| (row, *q))
        .collect();
    let mut out = Vec::new();

    let span_h = match (
        seen.iter().map(|(r, _)| r.ts).min(),
        seen.iter().map(|(r, _)| r.ts).max(),
    ) {
        (Some(a), Some(b)) => (b - a).num_seconds() as f64 / 3600.0,
        _ => 0.0,
    };
    out.push(if seen.is_empty() {
        Check {
            name: "three days of log",
            state: State::Wait,
            detail: format!("no shadow rows under the policy in force ({current}) yet"),
        }
    } else {
        let state = if span_h >= OBSERVE_H {
            State::Pass
        } else {
            State::Wait
        };
        Check {
            name: "three days of log",
            state,
            detail: format!(
                "{} shadow rows over {:.1} of {:.0} days under the policy in force ({current})",
                n(seen.len()),
                span_h / 24.0,
                OBSERVE_H / 24.0
            ),
        }
    });

    let would: Vec<_> = seen.iter().filter(|(r, _)| r.allowed).collect();
    let asked = would.iter().filter(|(_, q)| q.is_some()).count();
    let refused = would
        .iter()
        .filter(|(_, q)| q.is_some_and(|q| classify(q.result.as_deref()) == Answer::Refused))
        .count();
    out.push(if refused > 0 {
        Check {
            name: "no one refused an allow",
            state: State::Fail,
            detail: format!(
                "{refused} of the {asked} requests the hook would have allowed and a person was asked about were refused"
            ),
        }
    } else if asked == 0 {
        Check {
            name: "no one refused an allow",
            state: State::Wait,
            detail: format!(
                "{} requests would have been allowed and none was asked about, so no answer to compare with yet",
                n(would.len())
            ),
        }
    } else {
        Check {
            name: "no one refused an allow",
            state: State::Pass,
            detail: format!(
                "0 of the {asked} requests the hook would have allowed and a person was asked about were refused ({} more were never asked)",
                n(would.len() - asked)
            ),
        }
    });

    let wall: Vec<f64> = seen.iter().filter_map(|(r, _)| r.wall_ms).collect();
    let in_process: Vec<f64> = seen
        .iter()
        .filter_map(|(r, _)| r.latency_us.map(|us| f64::from(us) / 1000.0))
        .collect();
    let (label, values) = if wall.is_empty() {
        ("in-process", in_process)
    } else {
        ("wall-clock", wall)
    };
    out.push(match spread(values) {
        None => Check {
            name: "p95 under 50 ms",
            state: State::Wait,
            detail: "no latency recorded yet".to_owned(),
        },
        Some(s) => Check {
            name: "p95 under 50 ms",
            state: if s.p95 < P95_BUDGET_MS {
                State::Pass
            } else {
                State::Fail
            },
            detail: format!(
                "{label} p95 {:.1} ms over {} calls (p50 {:.1}, max {:.1})",
                s.p95,
                n(s.n),
                s.p50,
                s.max
            ),
        },
    });

    let mut cli = Compared::default();
    let mut session = Compared::default();
    for (row, q) in &seen {
        if !row.allowed {
            continue;
        }
        cli.add(row.cwd.as_deref(), q.and_then(|q| q.cli_cwd.as_deref()));
        session.add(row.cwd.as_deref(), row.session_cwd.as_deref());
    }
    let differ = cli.differ + session.differ;
    out.push(if differ > 0 {
        Check {
            name: "right directory",
            state: State::Fail,
            detail: format!(
                "the hook's directory differs from the CLI's for {} of {} and from the session's for {} of {} requests it would have allowed",
                cli.differ, cli.compared, session.differ, session.compared
            ),
        }
    } else if cli.compared + session.compared == 0 {
        Check {
            name: "right directory",
            state: State::Wait,
            detail: "no allowed request could be compared with the CLI's or the session's directory yet"
                .to_owned(),
        }
    } else {
        Check {
            name: "right directory",
            state: State::Pass,
            detail: format!(
                "the same as the CLI's for {} and as the session's for {} of the requests it would have allowed",
                n(cli.compared),
                n(session.compared)
            ),
        }
    });
    out
}

// ---- the text ----

/// What `render` needs besides the numbers.
pub struct Header {
    pub mode: String,
    pub policy: String,
    pub since: Option<NaiveDate>,
    pub drained: Drained,
    pub spool: PathBuf,
}

fn short(session: &str) -> &str {
    session.get(..8).unwrap_or(session)
}

fn outcome_head(out: &mut String, label: &str, width: usize) {
    line(
        out,
        format!(
            "   {label:<width$} {:>6} {:>6} {:>8} {:>7} {:>10} {:>9} {:>12}",
            "rows", "asked", "approved", "refused", "unattended", "no answer", "never asked"
        ),
    );
}

fn outcome_row(out: &mut String, name: &str, o: &Outcomes, width: usize) {
    line(
        out,
        format!(
            "   {:<width$} {:>6} {:>6} {:>8} {:>7} {:>10} {:>9} {:>12}",
            clip(name, width),
            n(o.rows),
            n(o.asked()),
            n(o.approved),
            n(o.refused),
            n(o.unattended),
            n(o.unanswered),
            n(o.not_asked)
        ),
    );
}

fn spread_row(out: &mut String, name: &str, s: Option<&Spread>) {
    match s {
        Some(s) => line(
            out,
            format!(
                "   {name:<34} {:>6} {:>8.1} {:>8.1} {:>8.1} {:>8.1}",
                n(s.n),
                s.p50,
                s.p95,
                s.p99,
                s.max
            ),
        ),
        None => line(out, format!("   {name:<34} none recorded")),
    }
}

pub fn render(r: &Report, head: &Header, top: usize) -> String {
    let mut o = String::new();
    let tz = zone(r.offset_s);
    let when = |t: DateTime<Utc>| t.with_timezone(&tz).format("%Y-%m-%d %H:%M").to_string();
    let since = head
        .since
        .map_or_else(|| "the start".to_owned(), |d| d.to_string());
    line(
        &mut o,
        format!(
            "ctx-hook review   mode now: {}   policy now: {}   log since: {since}   times: UTC{tz}",
            head.mode, head.policy
        ),
    );

    line(
        &mut o,
        "\n1. THE SPOOL (rows the hook could not write to PostgreSQL in time)",
    );
    let d = &head.drained;
    if d.files == 0 {
        line(&mut o, "   nothing was waiting");
    } else {
        line(
            &mut o,
            format!(
                "   imported {} new of {} spooled rows from {} file(s); {} lines rejected{}",
                n(d.inserted),
                n(d.rows),
                n(d.files),
                n(d.rejected),
                if d.rejected > 0 {
                    format!(" (kept in {}.rejected)", head.spool.display())
                } else {
                    String::new()
                }
            ),
        );
    }

    line(&mut o, "\n2. THE LOG");
    if r.rows == 0 {
        line(
            &mut o,
            "   no rows: nothing has called the hook yet (a session reads its hooks when it starts)",
        );
    }
    if let (Some(a), Some(b)) = (r.first, r.last) {
        line(
            &mut o,
            format!(
                "   rows        {} from {} to {} ({:.1} days)",
                n(r.rows),
                when(a),
                when(b),
                (b - a).num_seconds() as f64 / 86400.0
            ),
        );
        let others: Vec<String> = r
            .tools
            .iter()
            .take(top)
            .map(|(t, c)| format!("{t} {}", n(*c)))
            .collect();
        line(
            &mut o,
            format!(
                "   tools       bash {}{}",
                n(r.rows - r.tools.iter().map(|(_, c)| c).sum::<usize>()),
                if others.is_empty() {
                    String::new()
                } else {
                    format!(", {}", others.join(", "))
                }
            ),
        );
        line(
            &mut o,
            format!(
                "   modes       shadow {} (decided, said nothing), enforce {}",
                n(r.shadow),
                n(r.enforced)
            ),
        );
        line(
            &mut o,
            format!(
                "   the hook would allow {} of {} ({}); it leaves the rest to the prompt",
                n(r.allowed),
                n(r.rows),
                pct(r.allowed, r.rows)
            ),
        );
        for p in &r.policies {
            line(
                &mut o,
                format!(
                    "   policy      {}{}  {} rows ({} allowed)  {} .. {}",
                    p.policy,
                    if p.policy == r.current { " (now)" } else { "" },
                    n(p.rows),
                    n(p.allowed),
                    when(p.first),
                    when(p.last)
                ),
            );
        }
        line(
            &mut o,
            format!(
                "\n   {:<12} {:>6} {:>12} {:>7}",
                "day", "rows", "would allow", "asked"
            ),
        );
        let skip = r.days.len().saturating_sub(top.max(7));
        if skip > 0 {
            line(&mut o, format!("   … {skip} earlier days"));
        }
        for day in &r.days[skip..] {
            line(
                &mut o,
                format!(
                    "   {:<12} {:>6} {:>12} {:>7}",
                    day.date,
                    n(day.rows),
                    n(day.allowed),
                    n(day.asked)
                ),
            );
        }
    }

    line(
        &mut o,
        "\n3. WHAT PEOPLE DID WITH THE REQUESTS (asked = the CLI put a question to a person; never asked = it let the request through by itself)",
    );
    outcome_head(&mut o, "what the hook said", 30);
    for (name, group) in [
        ("would allow (shadow)", &r.shadow_allow),
        ("would pass (shadow)", &r.shadow_pass),
        ("allowed (enforced)", &r.enforced_allow),
        ("passed (enforced)", &r.enforced_pass),
    ] {
        if group.rows > 0 {
            outcome_row(&mut o, name, group, 30);
        }
    }
    let (allow, pass) = (&r.shadow_allow, &r.shadow_pass);
    let questions = allow.asked() + pass.asked();
    if questions > 0 {
        line(
            &mut o,
            format!(
                "   of the {} questions put to a person in shadow mode, the policy would have answered {} ({}); that is {} of the {} they waited ({} of it by the ones it would not answer)",
                n(questions),
                n(allow.asked()),
                pct(allow.asked(), questions),
                secs(allow.wait_s()),
                secs(allow.wait_s() + pass.wait_s()),
                secs(pass.wait_s())
            ),
        );
        let wall_share = pct_f(allow.wait_s(), allow.wait_s() + pass.wait_s());
        line(&mut o, format!("   its share of the waiting: {wall_share}"));
    }
    if r.enforced_allow.asked() > 0 {
        line(
            &mut o,
            format!(
                "   !! {} requests the hook allowed in enforce mode were asked about anyway: the allow did not take",
                n(r.enforced_allow.asked())
            ),
        );
    }
    if r.shared > 0 {
        line(
            &mut o,
            format!(
                "   {} rows share a question with another row (the same command called twice within seconds); they count as never asked",
                n(r.shared)
            ),
        );
    }
    if r.refused.is_empty() {
        line(
            &mut o,
            "   no request the hook would have allowed was refused by a person",
        );
    } else {
        line(
            &mut o,
            format!(
                "   !! {} requests the hook would have allowed were REFUSED by a person:",
                n(r.refused.len())
            ),
        );
        for row in r.refused.iter().take(top) {
            line(
                &mut o,
                format!(
                    "      {}  {}  {}  {}  {}",
                    when(row.ts),
                    short(&row.session_id),
                    row.question
                        .as_ref()
                        .and_then(|q| q.result.as_deref())
                        .unwrap_or("?"),
                    row.rule,
                    clip(row.command.as_deref().unwrap_or(""), 80)
                ),
            );
        }
    }

    line(&mut o, "\n   the rules that would allow:");
    outcome_head(&mut o, "rule", 34);
    for (rule, group) in r.allow_rules.iter().take(top) {
        outcome_row(&mut o, rule, group, 34);
    }
    if r.allow_rules.is_empty() {
        line(&mut o, "   none");
    }
    line(&mut o, "\n   what stopped the rest:");
    outcome_head(&mut o, "reason", 34);
    for (rule, group) in r.pass_rules.iter().take(top) {
        outcome_row(&mut o, rule, group, 34);
    }
    if r.pass_rules.len() > top {
        line(
            &mut o,
            format!("   … {} more reasons", r.pass_rules.len() - top),
        );
    }

    line(&mut o, "\n4. THE HOOK ITSELF");
    let c = r.calls;
    if c.logged == 0 && r.rows == 0 {
        line(
            &mut o,
            "   no hook call is counted yet: with no rows there is no first row to count from",
        );
    } else if c.logged == 0 {
        line(
            &mut o,
            "   the CLI's own log has no hook call between the first row and a minute ago (the last minute is left out: the ingester is a few seconds behind)",
        );
    } else {
        let missing = c.logged.saturating_sub(c.with_row);
        let mut text = format!(
            "   the CLI logged {} calls since the first row; {} have a row",
            n(c.logged),
            n(c.with_row)
        );
        if missing > 0 {
            text.push_str(&format!(
                "; {} do not (a crash, a timeout, or another permissionRequest hook: the CLI fails open, so each of those went to the prompt as if there were no hook)",
                n(missing)
            ));
        }
        text.push_str(&format!("; {} did not succeed", n(c.failed)));
        line(&mut o, text);
    }
    line(
        &mut o,
        format!(
            "   {:<34} {:>6} {:>8} {:>8} {:>8} {:>8}",
            "milliseconds", "calls", "p50", "p95", "p99", "max"
        ),
    );
    spread_row(
        &mut o,
        "hook.start to hook.end (the CLI's)",
        r.wall.as_ref(),
    );
    spread_row(
        &mut o,
        "inside the process (its own clock)",
        r.in_process.as_ref(),
    );

    line(
        &mut o,
        "\n5. THE DIRECTORY (the hook is given the session's directory; the persistent shell might have moved)",
    );
    let dirs = &r.dirs;
    line(
        &mut o,
        format!(
            "   against the CLI's workingDirectory for the same command: {} compared, {} differ ({} compared, {} differ among those it would allow)",
            n(dirs.cli.compared),
            n(dirs.cli.differ),
            n(dirs.cli_allowed.compared),
            n(dirs.cli_allowed.differ)
        ),
    );
    line(
        &mut o,
        format!(
            "   against where the session was:                           {} compared, {} differ ({} compared, {} differ among those it would allow)",
            n(dirs.session.compared),
            n(dirs.session.differ),
            n(dirs.session_allowed.compared),
            n(dirs.session_allowed.differ)
        ),
    );
    for row in dirs.differing.iter().take(top) {
        let cli = row
            .question
            .as_ref()
            .and_then(|q| q.cli_cwd.as_deref())
            .unwrap_or("-");
        line(
            &mut o,
            format!(
                "      {}  {}  {}  hook {}  CLI {}  session {}",
                when(row.ts),
                short(&row.session_id),
                row.rule,
                row.cwd.as_deref().unwrap_or("-"),
                cli,
                row.session_cwd.as_deref().unwrap_or("-")
            ),
        );
    }

    line(
        &mut o,
        "\n6. BEFORE ENABLING (PLAN.md §5, P3; shadow rows under the policy now in force)",
    );
    let width = r.checks.iter().map(|c| c.name.len()).max().unwrap_or(0);
    for check in &r.checks {
        let mark = match check.state {
            State::Pass => "ok  ",
            State::Wait => "wait",
            State::Fail => "FAIL",
        };
        line(
            &mut o,
            format!("   {mark}  {:<width$}  {}", check.name, check.detail),
        );
    }
    let names = |state: State| -> Vec<&str> {
        r.checks
            .iter()
            .filter(|c| c.state == state)
            .map(|c| c.name)
            .collect()
    };
    let (failed, waiting) = (names(State::Fail), names(State::Wait));
    let verdict = if !failed.is_empty() {
        format!("NO: {}", failed.join(", "))
    } else if !waiting.is_empty() {
        format!("not yet: waiting for {}", waiting.join(", "))
    } else {
        "yes: the log supports mode = \"enforce\" (the decision is yours)".to_owned()
    };
    line(&mut o, format!("   ready to enable: {verdict}"));
    o
}

// ---- the log ----

#[derive(sqlx::FromRow)]
struct Raw {
    ts: DateTime<Utc>,
    session_id: String,
    tool: String,
    cmd_preview: Option<String>,
    cwd: Option<String>,
    allowed: bool,
    rule: String,
    shadow: bool,
    latency_us: Option<i32>,
    policy: String,
    wall_ms: Option<f64>,
    session_cwd: Option<String>,
    request_id: Option<String>,
    asked_at: Option<DateTime<Utc>>,
    kind: Option<String>,
    cli_cwd: Option<String>,
    result: Option<String>,
    answered_at: Option<DateTime<Utc>>,
}

/// Every row of `hook_audit`, oldest first, with what the events say about it.
/// The sub-selects are bounded in time because `events` is big and the rows
/// are few:
///
/// * `h`: the `hook.start` the CLI logged for this call. Its input carries the
///   timestamp the hook was given, which is `a.ts` to the millisecond, and its
///   `hook.end` (same `hookInvocationId`) gives the wall-clock time. The casts
///   are behind `CASE` so that a `hook.start` of another kind of hook, whose
///   input may look different, cannot fail the query.
/// * `q`: the question the CLI then put to a person: the same session, the
///   same command (compared by hash, as the hook stored it) and within a
///   moment of the call; the nearest, if the same command came twice.
/// * `r`: its first answer.
/// * `c`: where the session was when the hook was called, as the replay finds
///   it.
const LOG: &str = r#"
SELECT a.ts,
       a.session_id,
       a.tool,
       a.cmd_preview,
       a.cwd,
       a.decision = 'allow' AS allowed,
       a.rule,
       a.shadow,
       a.latency_us,
       a.policy,
       h.wall_ms,
       coalesce(c.cwd, s.cwd) AS session_cwd,
       q.request_id,
       q.asked_at,
       q.kind,
       q.cli_cwd,
       r.result,
       r.answered_at
  FROM hook_audit a
  LEFT JOIN sessions s ON s.id = a.session_id
  LEFT JOIN LATERAL (
        SELECT (extract(epoch FROM (z.ts - b.ts)) * 1000)::float8 AS wall_ms
          FROM events b
          LEFT JOIN events z
                 ON z.session_id = b.session_id
                AND z.type = 'hook.end'
                AND z.ts >= b.ts AND z.ts < b.ts + interval '1 minute'
                AND z.body->>'hookInvocationId' = b.body->>'hookInvocationId'
         WHERE b.session_id = a.session_id
           AND b.type = 'hook.start'
           AND b.ts BETWEEN a.ts - interval '2 seconds' AND a.ts + interval '2 seconds'
           AND b.body->>'hookType' = 'permissionRequest'
           AND CASE jsonb_typeof(b.body->'input'->'timestamp')
                    WHEN 'number' THEN (b.body->'input'->>'timestamp')::numeric
               END = round(extract(epoch FROM a.ts) * 1000)
         ORDER BY b.ts
         LIMIT 1
       ) h ON true
  LEFT JOIN LATERAL (
        SELECT e.body->>'requestId' AS request_id,
               e.ts AS asked_at,
               coalesce(e.body->'promptRequest'->>'kind', 'unknown') AS kind,
               e.body->'permissionRequest'->'commandSegments'->0->>'workingDirectory' AS cli_cwd
          FROM events e
         WHERE a.cmd_sha IS NOT NULL
           AND e.session_id = a.session_id
           AND e.type = 'permission.requested'
           AND e.ts BETWEEN a.ts - interval '2 seconds' AND a.ts + interval '10 seconds'
           AND encode(sha256(convert_to(
                   coalesce(e.body->'permissionRequest'->>'fullCommandText',
                            e.body->'promptRequest'->>'fullCommandText', ''),
                   'UTF8')), 'hex') = a.cmd_sha
         ORDER BY abs(extract(epoch FROM (e.ts - a.ts)))
         LIMIT 1
       ) q ON true
  LEFT JOIN LATERAL (
        SELECT x.body->'result'->>'kind' AS result,
               x.ts AS answered_at
          FROM events x
         WHERE q.request_id IS NOT NULL
           AND x.session_id = a.session_id
           AND x.type = 'permission.completed'
           AND x.ts >= q.asked_at AND x.ts < q.asked_at + interval '1 day'
           AND x.body->>'requestId' = q.request_id
         ORDER BY x.ts
         LIMIT 1
       ) r ON true
  LEFT JOIN LATERAL (
        SELECT coalesce(x.body->>'cwd', x.body->'context'->>'cwd') AS cwd
          FROM events x
         WHERE x.session_id = a.session_id
           AND x.type IN ('session.start', 'session.resume', 'session.context_changed')
           AND x.ts <= a.ts
           AND coalesce(x.body->>'cwd', x.body->'context'->>'cwd') IS NOT NULL
         ORDER BY x.ts DESC
         LIMIT 1
       ) c ON true
 WHERE ($1::timestamptz IS NULL OR a.ts >= $1)
   AND a.session_id NOT LIKE $2
 ORDER BY a.ts, a.id
"#;

/// The audit rows since `since` (all of them if none), oldest first.
pub async fn load(pool: &PgPool, since: Option<DateTime<Utc>>) -> Result<Vec<Logged>> {
    let raw: Vec<Raw> = sqlx::query_as(LOG)
        .bind(since)
        .bind(format!("{BENCH_SESSION_PREFIX}%"))
        .fetch_all(pool)
        .await
        .context("reading hook_audit and the events about it")?;
    Ok(raw
        .into_iter()
        .map(|raw| {
            let question = match (raw.request_id, raw.asked_at) {
                (Some(request_id), Some(asked_at)) => Some(Question {
                    request_id,
                    asked_at,
                    kind: raw.kind.unwrap_or_else(|| "unknown".to_owned()),
                    cli_cwd: raw.cli_cwd,
                    result: raw.result,
                    waited_s: raw
                        .answered_at
                        .map(|done| (done - asked_at).num_milliseconds() as f64 / 1000.0)
                        .filter(|w| *w >= 0.0),
                }),
                _ => None,
            };
            Logged {
                ts: raw.ts,
                session_id: raw.session_id,
                tool: raw.tool,
                command: raw.cmd_preview,
                cwd: raw.cwd,
                allowed: raw.allowed,
                rule: raw.rule,
                shadow: raw.shadow,
                latency_us: raw.latency_us,
                policy: raw.policy,
                wall_ms: raw.wall_ms,
                session_cwd: raw.session_cwd,
                question,
            }
        })
        .collect())
}

/// The hook calls in the CLI's own log from `from` until a minute ago (the
/// ingester is a few seconds behind), and how many of them left a row.
const CALLS: &str = r#"
SELECT count(*)::int8,
       (count(*) FILTER (WHERE EXISTS (
            SELECT 1
              FROM hook_audit a
             WHERE a.session_id = b.session_id
               AND a.ts BETWEEN b.ts - interval '2 seconds' AND b.ts + interval '2 seconds'
               AND round(extract(epoch FROM a.ts) * 1000) =
                   CASE jsonb_typeof(b.body->'input'->'timestamp')
                        WHEN 'number' THEN (b.body->'input'->>'timestamp')::numeric
                   END)))::int8,
       (count(*) FILTER (WHERE EXISTS (
            SELECT 1
              FROM events z
             WHERE z.session_id = b.session_id
               AND z.type = 'hook.end'
               AND z.ts >= b.ts AND z.ts < b.ts + interval '1 minute'
               AND z.body->>'hookInvocationId' = b.body->>'hookInvocationId'
               AND z.body->>'success' = 'false')))::int8
  FROM events b
 WHERE b.type = 'hook.start'
   AND b.body->>'hookType' = 'permissionRequest'
   AND b.ts >= $1
   AND b.ts < now() - interval '1 minute'
"#;

pub async fn calls(pool: &PgPool, from: DateTime<Utc>) -> Result<Calls> {
    let (logged, with_row, failed): (i64, i64, i64) = sqlx::query_as(CALLS)
        .bind(from)
        .fetch_one(pool)
        .await
        .context("counting the hook calls in the events")?;
    let count = |x: i64| usize::try_from(x).unwrap_or(0);
    Ok(Calls {
        logged: count(logged),
        with_row: count(with_row),
        failed: count(failed),
    })
}

pub struct Options {
    pub since: Option<NaiveDate>,
    pub top: usize,
}

/// Imports what is in the spool, reads the log, and returns the report.
pub fn run(opts: &Options) -> Result<String> {
    let vars = Vars::Process;
    let Some(home) = vars
        .get("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_absolute())
    else {
        bail!("HOME is not set to an absolute path");
    };
    let home_text = home.to_string_lossy().into_owned();
    let config = Config::load(&vars, &home);
    let policy = Policy::new(&home, &config, Vars::fixed(&[("HOME", home_text.as_str())]));
    // The database the hook itself writes to
    let url = hook_database_url(&|key| vars.get(key).filter(|v| !v.is_empty()));
    let spool = audit::spool_path(&vars, &home);
    // A day is a day of the clock on the wall, as in the by-day table
    let since = opts
        .since
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .and_then(|t| t.and_local_timezone(Local).earliest())
        .map(|t| t.with_timezone(&Utc));

    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let (drained, rows, calls) = runtime.block_on(async {
        let pool = db::connect(&url, "ctx-hook-review", None, 2).await?;
        let found = async {
            let drained = {
                let mut conn = pool.acquire().await?;
                audit::drain(&mut conn, &spool).await?
            };
            let rows = load(&pool, since).await?;
            let from = rows
                .first()
                .map(|r| r.ts - Duration::minutes(1))
                .map(|t| since.map_or(t, |s| s.max(t)));
            let calls = match from {
                Some(from) => self::calls(&pool, from).await?,
                None => Calls::default(),
            };
            anyhow::Ok((drained, rows, calls))
        }
        .await;
        pool.close().await;
        found
    })?;

    let offset_s = Local::now().offset().local_minus_utc();
    let report = analyze(&rows, calls, policy.id(), offset_s);
    let head = Header {
        mode: config.mode.as_str().to_owned(),
        policy: policy.id().to_owned(),
        since: opts.since,
        drained,
        spool,
    };
    Ok(render(&report, &head, opts.top))
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use ctx_core::redact::{Counts, Redactor};
    use serde_json::json;

    const NOW: &str = "v1:aaaaaaaa";

    fn t(minutes: i64) -> DateTime<Utc> {
        Utc.with_ymd_and_hms(2026, 10, 10, 8, 0, 0).unwrap() + Duration::minutes(minutes)
    }

    /// A shadow row for `ls` that the hook passed, at minute `at`, in a
    /// session where everything is in `/home/u/kms`.
    fn row(at: i64) -> Logged {
        Logged {
            ts: t(at),
            session_id: "s1-aaaaaaaa".to_owned(),
            tool: "bash".to_owned(),
            command: Some("ls".to_owned()),
            cwd: Some("/home/u/kms".to_owned()),
            allowed: false,
            rule: "pass:cmd-not-allowed".to_owned(),
            shadow: true,
            latency_us: Some(4000),
            policy: NOW.to_owned(),
            wall_ms: None,
            session_cwd: Some("/home/u/kms".to_owned()),
            question: None,
        }
    }

    impl Logged {
        fn allow(mut self) -> Logged {
            self.allowed = true;
            self.rule = "allow:ls".to_owned();
            self
        }

        fn enforced(mut self) -> Logged {
            self.shadow = false;
            self
        }

        fn policy(mut self, id: &str) -> Logged {
            self.policy = id.to_owned();
            self
        }

        fn wall(mut self, ms: f64) -> Logged {
            self.wall_ms = Some(ms);
            self
        }

        fn tool(mut self, tool: &str) -> Logged {
            self.tool = tool.to_owned();
            self
        }

        fn asked(mut self, id: &str, result: Option<&str>, waited_s: Option<f64>) -> Logged {
            self.question = Some(Question {
                request_id: id.to_owned(),
                asked_at: self.ts + Duration::milliseconds(30),
                kind: "commands".to_owned(),
                cli_cwd: Some("/home/u/kms".to_owned()),
                result: result.map(str::to_owned),
                waited_s,
            });
            self
        }

        fn cwd(mut self, cwd: &str) -> Logged {
            self.cwd = Some(cwd.to_owned());
            self
        }
    }

    fn report(rows: &[Logged]) -> Report {
        analyze(rows, Calls::default(), NOW, 0)
    }

    fn check<'a>(r: &'a Report, name: &str) -> &'a Check {
        r.checks
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("no check {name}: {:?}", r.checks))
    }

    #[test]
    fn it_counts_rows_modes_tools_and_decisions() {
        let rows = vec![
            row(0).allow(),
            row(1),
            row(2).tool("view"),
            row(3).tool("view"),
            row(4).tool("web_fetch"),
            row(5).allow().enforced(),
        ];
        let r = report(&rows);
        assert_eq!((r.rows, r.shadow, r.enforced, r.allowed), (6, 5, 1, 2));
        assert_eq!(
            r.tools,
            [("view".to_owned(), 2), ("web_fetch".to_owned(), 1)]
        );
        assert_eq!(
            (
                r.shadow_allow.rows,
                r.shadow_pass.rows,
                r.enforced_allow.rows,
                r.enforced_pass.rows
            ),
            (1, 4, 1, 0)
        );
        assert_eq!((r.first, r.last), (Some(t(0)), Some(t(5))));
        assert_eq!(r.policies.len(), 1);
        assert_eq!(r.policies[0].rows, 6);
    }

    #[test]
    fn it_sorts_what_people_answered() {
        let rows = vec![
            row(0).allow().asked("a", Some("approved"), Some(0.0)),
            row(1)
                .allow()
                .asked("b", Some("approved-for-location"), Some(2.0)),
            row(2).allow().asked("c", None, None),
            row(3).allow().asked("d", Some(UNATTENDED), Some(0.5)),
            row(4).allow(),
            row(5).asked("e", Some("denied-interactively-by-user"), Some(60.0)),
        ];
        let r = report(&rows);
        let a = &r.shadow_allow;
        assert_eq!(
            (
                a.rows,
                a.asked(),
                a.approved,
                a.refused,
                a.unattended,
                a.unanswered,
                a.not_asked
            ),
            (5, 4, 2, 0, 1, 1, 1)
        );
        assert!((a.wait_s() - 2.5).abs() < 1e-9);
        let p = &r.shadow_pass;
        assert_eq!((p.rows, p.asked(), p.refused), (1, 1, 1));
        // a person refusing what the hook would have passed is no problem
        assert!(r.refused.is_empty());
        assert_ne!(check(&r, "no one refused an allow").state, State::Fail);
    }

    #[test]
    fn what_a_person_refused_that_the_hook_would_have_allowed_fails_the_review() {
        for result in [
            "denied-interactively-by-user",
            "cancelled",
            "denied-by-some-new-rule",
        ] {
            let rows = vec![
                row(0).allow().asked("a", Some("approved"), Some(1.0)),
                row(1).allow().asked("b", Some(result), Some(9.0)),
            ];
            let r = report(&rows);
            assert_eq!(r.refused.len(), 1, "{result}");
            assert_eq!(r.refused[0].ts, t(1));
            assert_eq!(r.shadow_allow.refused, 1, "{result}");
            let c = check(&r, "no one refused an allow");
            assert_eq!(c.state, State::Fail, "{result}");
            assert!(c.detail.starts_with("1 of the 2"), "{}", c.detail);
            assert!(render(&r, &header(), 5).contains("REFUSED"));
        }
    }

    #[test]
    fn an_allow_in_enforce_mode_is_not_a_refusal_but_asking_about_it_anyway_is_noted() {
        let rows = vec![
            row(0)
                .allow()
                .enforced()
                .asked("a", Some("denied-interactively-by-user"), Some(3.0)),
            row(1).allow().enforced(),
        ];
        let r = report(&rows);
        assert!(r.refused.is_empty());
        assert_eq!(r.enforced_allow.asked(), 1);
        assert!(render(&r, &header(), 5).contains("the allow did not take"));
        // and the checks are about the shadow log only
        assert_eq!(check(&r, "three days of log").state, State::Wait);
    }

    #[test]
    fn a_question_belongs_to_the_nearest_row_only() {
        let near = row(1).allow().asked("q", Some("approved"), Some(1.0));
        let mut far = row(0).allow().asked("q", Some("approved"), Some(1.0));
        // asked a second after the far row's call, and 30 ms after the near one
        far.question.as_mut().unwrap().asked_at = near.ts + Duration::milliseconds(30);
        let r = report(&[far, near]);
        assert_eq!(r.shared, 1);
        assert_eq!(
            (
                r.shadow_allow.rows,
                r.shadow_allow.asked(),
                r.shadow_allow.not_asked
            ),
            (2, 1, 1)
        );
        assert_eq!(r.shadow_allow.waits, [1.0]);

        // two sessions may reuse a request id
        let mut other = row(1).allow().asked("q", Some("approved"), Some(1.0));
        other.session_id = "s2-bbbbbbbb".to_owned();
        let r = report(&[
            row(1).allow().asked("q", Some("approved"), Some(1.0)),
            other,
        ]);
        assert_eq!((r.shared, r.shadow_allow.asked()), (0, 2));
    }

    #[test]
    fn it_groups_by_rule_policy_and_day() {
        let mut late = row(60 * 24 * 2).allow();
        late.rule = "allow:cat".to_owned();
        let rows = vec![
            row(0).allow().asked("a", Some("approved"), Some(0.0)),
            row(1).allow(),
            row(2),
            row(3).policy("v1:bbbbbbbb"),
            late,
        ];
        let r = report(&rows);
        let allow: Vec<_> = r
            .allow_rules
            .iter()
            .map(|(k, o)| (k.as_str(), o.rows))
            .collect();
        assert_eq!(allow, [("allow:ls", 2), ("allow:cat", 1)]);
        let pass: Vec<_> = r
            .pass_rules
            .iter()
            .map(|(k, o)| (k.as_str(), o.rows))
            .collect();
        assert_eq!(pass, [("pass:cmd-not-allowed", 2)]);
        assert_eq!(r.policies.len(), 2);
        assert_eq!(r.policies[0].policy, NOW);
        assert_eq!((r.policies[0].rows, r.policies[0].allowed), (4, 3));
        assert_eq!(r.days.len(), 2);
        assert_eq!(
            (r.days[0].rows, r.days[0].allowed, r.days[0].asked),
            (4, 2, 1)
        );
        assert_eq!((r.days[1].rows, r.days[1].allowed), (1, 1));
    }

    #[test]
    fn days_are_counted_in_the_zone_it_is_given() {
        let rows = vec![row(0), row(30)];
        // 08:00 and 08:30 UTC are the 10th everywhere, but not 01:00 on the 11th
        let late = vec![
            Logged {
                ts: Utc.with_ymd_and_hms(2026, 10, 10, 23, 30, 0).unwrap(),
                ..row(0)
            },
            Logged {
                ts: Utc.with_ymd_and_hms(2026, 10, 11, 0, 30, 0).unwrap(),
                ..row(0)
            },
        ];
        assert_eq!(analyze(&rows, Calls::default(), NOW, 0).days.len(), 1);
        assert_eq!(analyze(&late, Calls::default(), NOW, 0).days.len(), 2);
        assert_eq!(
            analyze(&late, Calls::default(), NOW, 2 * 3600).days.len(),
            1
        );
    }

    #[test]
    fn latency_is_measured_on_the_clock_of_the_cli_when_there_is_one() {
        let rows = vec![
            row(0).wall(8.0),
            row(1).wall(9.0),
            row(2).wall(70.0),
            row(3).wall(9.5),
        ];
        let r = report(&rows);
        let w = r.wall.as_ref().unwrap();
        assert_eq!((w.n, w.p50, w.max), (4, 9.0, 70.0));
        assert_eq!(r.in_process.as_ref().unwrap().p95, 4.0);
        let c = check(&r, "p95 under 50 ms");
        assert_eq!(c.state, State::Fail);
        assert!(c.detail.starts_with("wall-clock p95 70.0"), "{}", c.detail);

        // without the CLI's own record, the hook's clock
        let r = report(&[row(0), row(1)]);
        let c = check(&r, "p95 under 50 ms");
        assert_eq!(c.state, State::Pass);
        assert!(c.detail.starts_with("in-process p95 4.0"), "{}", c.detail);

        let mut none = row(0);
        none.latency_us = None;
        assert_eq!(
            check(&report(&[none]), "p95 under 50 ms").state,
            State::Wait
        );
    }

    #[test]
    fn three_days_means_three_days_under_the_policy_in_force() {
        let days = |from: i64, to: i64, policy: &str| {
            vec![row(from).policy(policy), row(to).policy(policy)]
        };
        let r = report(&days(0, 60 * 24 * 3 - 1, NOW));
        assert_eq!(check(&r, "three days of log").state, State::Wait);
        let r = report(&days(0, 60 * 24 * 3, NOW));
        let c = check(&r, "three days of log");
        assert_eq!(c.state, State::Pass, "{}", c.detail);
        // a long log under another policy is no evidence about this one
        let r = report(&days(0, 60 * 24 * 9, "v1:bbbbbbbb"));
        let c = check(&r, "three days of log");
        assert_eq!(c.state, State::Wait);
        assert!(
            c.detail
                .contains("no shadow rows under the policy in force"),
            "{}",
            c.detail
        );
        // and neither is a log of what it did when enforcing
        let r = report(&[row(0).enforced(), row(60 * 24 * 4).enforced()]);
        assert_eq!(check(&r, "three days of log").state, State::Wait);
    }

    #[test]
    fn no_answers_to_compare_with_is_not_a_pass() {
        let r = report(&[row(0).allow(), row(1).allow()]);
        let c = check(&r, "no one refused an allow");
        assert_eq!(c.state, State::Wait, "{}", c.detail);
        let r = report(&[
            row(0).allow().asked("a", Some("approved"), Some(0.0)),
            row(1).allow(),
        ]);
        let c = check(&r, "no one refused an allow");
        assert_eq!(c.state, State::Pass);
        assert!(
            c.detail.contains("(1 more were never asked)"),
            "{}",
            c.detail
        );
        // nothing allowed yet
        assert_eq!(
            check(&report(&[row(0)]), "no one refused an allow").state,
            State::Wait
        );
    }

    #[test]
    fn the_directory_the_hook_was_given_is_compared_with_the_two_the_events_know() {
        let r = report(&[
            row(0).allow().asked("a", Some("approved"), Some(0.0)),
            row(1),
        ]);
        assert_eq!(
            r.dirs.cli,
            Compared {
                compared: 1,
                differ: 0
            }
        );
        assert_eq!(
            r.dirs.session,
            Compared {
                compared: 2,
                differ: 0
            }
        );
        assert_eq!(check(&r, "right directory").state, State::Pass);

        // the CLI says the command runs elsewhere than the hook was told
        let mut moved = row(0).allow().asked("a", Some("approved"), Some(0.0));
        moved.question.as_mut().unwrap().cli_cwd = Some("/home/u/kms/dash".to_owned());
        let r = report(&[moved]);
        assert_eq!(
            r.dirs.cli,
            Compared {
                compared: 1,
                differ: 1
            }
        );
        assert_eq!(
            r.dirs.cli_allowed,
            Compared {
                compared: 1,
                differ: 1
            }
        );
        assert_eq!(r.dirs.differing.len(), 1);
        assert_eq!(check(&r, "right directory").state, State::Fail);

        // or the session was somewhere else
        let r = report(&[row(0).allow().cwd("/home/u/other")]);
        assert_eq!(
            r.dirs.session_allowed,
            Compared {
                compared: 1,
                differ: 1
            }
        );
        assert_eq!(check(&r, "right directory").state, State::Fail);

        // a difference on a request the hook would only pass is listed, not failed
        let r = report(&[row(0).cwd("/home/u/other")]);
        assert_eq!(r.dirs.differing.len(), 1);
        assert_eq!(check(&r, "right directory").state, State::Wait);

        // nothing to compare with
        let mut bare = row(0).allow();
        bare.session_cwd = None;
        assert_eq!(
            check(&report(&[bare]), "right directory").state,
            State::Wait
        );
    }

    #[test]
    fn the_verdict_is_the_worst_of_the_checks() {
        let ready: Vec<Logged> = (0..4)
            .map(|d| {
                row(d * 60 * 24).allow().wall(9.0).asked(
                    &format!("q{d}"),
                    Some("approved"),
                    Some(0.0),
                )
            })
            .collect();
        let r = report(&ready);
        assert!(
            r.checks.iter().all(|c| c.state == State::Pass),
            "{:?}",
            r.checks
        );
        assert!(render(&r, &header(), 5).contains("ready to enable: yes"));

        let mut refused = ready.clone();
        refused.push(row(5).allow().asked("x", Some("cancelled"), Some(1.0)));
        let text = render(&report(&refused), &header(), 5);
        assert!(
            text.contains("ready to enable: NO: no one refused an allow"),
            "{text}"
        );

        let text = render(&report(&ready[..1]), &header(), 5);
        assert!(
            text.contains("ready to enable: not yet: waiting for three days of log"),
            "{text}"
        );
    }

    fn header() -> Header {
        Header {
            mode: "shadow".to_owned(),
            policy: NOW.to_owned(),
            since: None,
            drained: Drained::default(),
            spool: PathBuf::from("/tmp/spool"),
        }
    }

    #[test]
    fn the_report_says_what_it_found() {
        let rows = vec![
            row(0)
                .allow()
                .wall(8.0)
                .asked("a", Some("approved"), Some(0.0)),
            row(1).wall(9.0).asked("b", Some("approved"), Some(120.0)),
            row(2).tool("view"),
        ];
        let calls = Calls {
            logged: 5,
            with_row: 3,
            failed: 1,
        };
        let r = analyze(&rows, calls, NOW, 0);
        let mut head = header();
        head.drained = Drained {
            files: 1,
            rows: 4,
            inserted: 3,
            rejected: 1,
        };
        let text = render(&r, &head, 5);
        for want in [
            "ctx-hook review   mode now: shadow   policy now: v1:aaaaaaaa",
            "imported 3 new of 4 spooled rows from 1 file(s); 1 lines rejected (kept in /tmp/spool.rejected)",
            "rows        3 from 2026-10-10 08:00 to 2026-10-10 08:02",
            "bash 2, view 1",
            "would allow (shadow)",
            "the policy would have answered 1 (50.0%)",
            "allow:ls",
            "pass:cmd-not-allowed",
            "the CLI logged 5 calls since the first row; 3 have a row; 2 do not",
            "1 did not succeed",
            "hook.start to hook.end (the CLI's)",
            "against the CLI's workingDirectory",
            "6. BEFORE ENABLING",
            "wait  three days of log",
        ] {
            assert!(text.contains(want), "missing {want:?} in\n{text}");
        }
        assert!(!text.contains("REFUSED"));
    }

    #[test]
    fn a_log_without_counted_calls_says_why() {
        let text = render(&report(&[row(0).wall(8.0)]), &header(), 5);
        assert!(
            text.contains("no hook call between the first row and a minute ago"),
            "{text}"
        );
        assert!(
            !text.contains("no hook calls in the CLI's own log"),
            "{text}"
        );
    }

    #[test]
    fn an_empty_log_is_a_report_too() {
        let r = report(&[]);
        let text = render(&r, &header(), 5);
        assert!(
            text.contains("no rows: nothing has called the hook yet"),
            "{text}"
        );
        assert!(text.contains("ready to enable: not yet"), "{text}");
        assert!(
            text.contains("no hook call is counted yet: with no rows there is no first row"),
            "{text}"
        );
        assert!(!text.contains("between the first row"), "{text}");
        assert_eq!(r.checks.len(), 4);
        assert!(r.checks.iter().all(|c| c.state == State::Wait));
    }

    #[test]
    fn percentiles_are_nearest_rank() {
        let s = spread((1..=100).map(f64::from).collect()).unwrap();
        assert_eq!(
            (s.n, s.min, s.p50, s.p95, s.p99, s.max),
            (100, 1.0, 50.0, 95.0, 99.0, 100.0)
        );
        assert_eq!(spread(vec![]), None);
        assert_eq!(spread(vec![3.0]).unwrap().p99, 3.0);
    }

    /// The join with the events compares the hash of the text the hook stored
    /// with the hash of the text the ingester stored for the same command. They
    /// are redacted by different calls (`field` for the one, `json` over the
    /// whole event for the other), and must give the same text.
    #[test]
    fn the_hook_and_the_ingester_redact_a_command_to_the_same_text() {
        let redactor = Redactor::new();
        let secret = ["ghp_", "aB3dE5gH7jK9mN1pQ3sT5vX7zA9cE1fG3hJ5"].concat();
        let commands = [
            "ls -la".to_owned(),
            "git log --oneline | head -n 5".to_owned(),
            format!("curl -H 'Authorization: Bearer {secret}' https://example.invalid"),
            format!("echo {}", "x".repeat(20_000)),
            format!("echo {}", "é".repeat(5_000)),
            "echo 'a\nb'".to_owned(),
            ["echo ", "Zq8Lm3Xv9Rt2Yp7Kb4Nc6Wd1Hs5Jf0Ga"].concat(),
        ];
        let mut changed = 0;
        for command in commands {
            let mut counts = Counts::default();
            let hook = redactor.field(&command, &mut counts);
            let event = redactor.json(
                json!({"permissionRequest": {"fullCommandText": command}}),
                &[],
                &mut counts,
            );
            let stored = event["permissionRequest"]["fullCommandText"]
                .as_str()
                .unwrap();
            assert_eq!(hook, stored, "{}", clip(&command, 60));
            changed += usize::from(hook != command);
        }
        // the equality is only worth something if redaction did act on some
        assert!(
            changed >= 2,
            "only {changed} of the commands were changed by redaction"
        );
    }
}
