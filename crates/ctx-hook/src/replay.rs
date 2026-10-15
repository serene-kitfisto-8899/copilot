//! `ctx-hook replay`: the policy against everything the CLI ever asked a person
//! (PLAN.md §6.6, P3).
//!
//! Before the hook says yes to anything, the history in PostgreSQL says what
//! that would have meant: how many of the prompts the policy would have
//! answered and how long they kept the user waiting, whether it would ever have
//! approved what a person refused, what in the approved part the oracle or the
//! CLI's own read-only flags disagree with, and what stands in the way of the
//! rest. [`analyze`] is a pure function of the history and of a judge, so it is
//! tested on made-up histories; [`load`] reads the real one.
//!
//! What the replay cannot know, and so models: the environment of the shell a
//! command ran in (a clean one with only `HOME`), the directory it ran in (the
//! one the session was in when it asked, from `session.start`, `session.resume`
//! and `session.context_changed`: a `cd` in an earlier command is not seen), and
//! the files that were there then (the ones there now).

use std::cell::RefCell;
use std::collections::{BTreeMap, BTreeSet, HashMap, HashSet};
use std::path::{Path, PathBuf};

use anyhow::{Context, Result, bail};
use chrono::{DateTime, NaiveDate, Utc};
use ctx_core::config::Config as CoreConfig;
use ctx_core::db;
use ctx_core::redact::MARKER_PREFIX;
use sqlx::PgPool;

use crate::config::Config;
use crate::hook::Policy;
use crate::oracle;
use crate::payload::Request;
use crate::policy::Verdict;
use crate::vars::Vars;

/// Answers that mean a person looked and said no.
pub const REFUSED: &[&str] = &["denied-interactively-by-user", "cancelled"];
/// The answer when there was nobody to ask (a `copilot -p` run).
pub const UNATTENDED: &str = "denied-no-approval-rule-and-could-not-request-from-user";
/// What the history says when a request has no answer.
pub const NO_ANSWER: &str = "(no answer)";
/// A wait this long is a person who had gone away, not one deciding.
pub const AWAY_S: f64 = 300.0;
/// What the ingester leaves in place of what it cut off a long string.
const CUT_MARK: &str = "…[+";
/// How an assumption that a directory is a trusted root is written in the list
/// the judge is given, as opposed to a command name.
pub const ROOT_PREFIX: &str = "root:";
/// How many commands one line may lack before it is not worth following.
const MAX_LACKS: usize = 8;
/// Virtual memory only: the shell parser recurses.
const WORKER_STACK: usize = 64 * 1024 * 1024;

/// What the CLI asked a person, and what came of it.
#[derive(Debug, Clone)]
pub struct Past {
    pub session_id: String,
    pub request_id: String,
    pub asked_at: DateTime<Utc>,
    /// `commands` (the commands themselves) or `path` (a place outside what the
    /// CLI allows by itself).
    pub prompt_kind: String,
    pub command: String,
    /// Where the session was when it asked.
    pub cwd: Option<String>,
    /// That directory is not there now, so relative paths cannot be judged.
    pub cwd_gone: bool,
    /// Seconds until the answer, when there was one.
    pub waited_s: Option<f64>,
    /// `result.kind` of the answer.
    pub result: Option<String>,
    /// The commands the CLI itself did not consider read-only.
    pub not_read_only: Vec<String>,
    /// For a `path` prompt, the places it asked about.
    pub paths: Vec<String>,
}

impl Past {
    /// How long the answer took, counting no wait for more than [`AWAY_S`].
    fn capped_wait_s(&self) -> f64 {
        self.waited_s.unwrap_or(0.0).min(AWAY_S)
    }
}

/// What the policy says about a command run in a directory, with the commands
/// in the last argument taken to be on the allow-list.
pub type Judge<'a> = dyn Fn(&str, Option<&str>, &[&str]) -> Verdict + 'a;

/// A number of requests and how many of them the policy would answer.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Split {
    pub requests: usize,
    pub allowed: usize,
}

/// Requests that came to the same thing: how long they waited (no wait
/// counted for more than [`AWAY_S`]) and the shortest command among them.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct Tally {
    pub requests: usize,
    pub wait_s: f64,
    pub example: String,
}

impl Tally {
    fn add(&mut self, p: &Past) {
        self.requests += 1;
        self.wait_s += p.capped_wait_s();
        if self.example.is_empty() || p.command.len() < self.example.len() {
            self.example.clone_from(&p.command);
        }
    }
}

/// Where the answers came in time: the upper edge of each bucket, in seconds.
/// Most requests are answered in a second, by a rule and not by a person.
pub const BUCKETS: [(&str, f64); 5] = [
    ("under 1 s", 1.0),
    ("1-5 s", 5.0),
    ("5-30 s", 30.0),
    ("30 s-5 min", AWAY_S),
    ("5 min or more", f64::INFINITY),
];

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Bucket {
    pub requests: usize,
    pub allowed: usize,
    /// No wait counted for more than [`AWAY_S`].
    pub wait_s: f64,
}

fn bucket_of(wait_s: f64) -> usize {
    BUCKETS
        .iter()
        .position(|(_, edge)| wait_s < *edge)
        .unwrap_or(BUCKETS.len() - 1)
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Waits {
    /// Requests with a wait (they were answered).
    pub answered: usize,
    pub total_s: f64,
    /// As `total_s`, with no wait counted for more than [`AWAY_S`].
    pub total_capped_s: f64,
    /// The same for the requests the policy would have answered.
    pub allowed: usize,
    pub allowed_total_s: f64,
    pub allowed_capped_s: f64,
    pub allowed_median_s: f64,
    pub allowed_p90_s: f64,
    pub allowed_max_s: f64,
    pub allowed_away: usize,
}

/// A request a person refused that the policy would have approved.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Slip {
    pub session_id: String,
    pub request_id: String,
    pub result: String,
    pub command: String,
}

/// A command the policy allows and the oracle sees more than a read in.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Flagged {
    pub command: String,
    pub flags: Vec<String>,
    pub requests: usize,
}

/// Allowed requests that name one of the commands the CLI did not consider
/// read-only (when the CLI gives up on a whole line it names the line, which
/// is not an opinion about any one command: see [`Report::cli_unparsed`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Disagreement {
    pub identifier: String,
    pub requests: usize,
    pub distinct: usize,
    /// The shortest command in the group.
    pub example: String,
}

/// A command the CLI asked about as a path that the policy would allow.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Widened {
    pub command: String,
    pub requests: usize,
    pub paths: Vec<String>,
}

#[derive(Debug, Clone, PartialEq)]
pub struct Step {
    pub command: String,
    /// Requests that this addition makes allowed, given the earlier ones.
    pub gained: usize,
    pub cumulative: usize,
    /// Their waits, each counted for at most [`AWAY_S`].
    pub gained_wait_s: f64,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct WhatIf {
    /// Requests that would be allowed if every command they lack were.
    pub unlockable: usize,
    /// Requests that lack a command and would still pass: something else
    /// (structure, a path, a flag) is in the way.
    pub stuck: usize,
    pub steps: Vec<Step>,
}

/// A directory that, were it a trusted root, would let the policy answer some
/// of the requests that pass for want of one.
#[derive(Debug, Clone, PartialEq)]
pub struct Unlock {
    /// As it is written in `trusted_roots`.
    pub root: String,
    pub requests: usize,
    /// Their waits, each counted for at most [`AWAY_S`].
    pub wait_s: f64,
    /// The shortest command among them.
    pub example: String,
}

#[derive(Debug, Default, Clone, PartialEq)]
pub struct Roots {
    /// Requests whose first reason to pass was a path outside the trusted roots.
    pub untrusted: usize,
    /// Of those, the ones one more root would make allowed (by itself, with
    /// every other rule as it is).
    pub unlockable: usize,
    pub unlockable_wait_s: f64,
    /// Candidate directories, the most waiting first.
    pub rows: Vec<Unlock>,
}

#[derive(Debug, Default, Clone)]
pub struct Report {
    pub requests: usize,
    pub distinct: usize,
    pub first: Option<DateTime<Utc>>,
    pub last: Option<DateTime<Utc>>,
    pub results: BTreeMap<String, usize>,
    pub prompts: BTreeMap<String, Split>,
    /// Requests whose text was cut or redacted in the history, which are not
    /// judged and count as passes.
    pub stored: BTreeMap<&'static str, usize>,
    pub no_cwd: usize,
    pub gone_cwd: usize,
    /// Requests in a directory that is still there: the only ones whose
    /// relative paths could be judged.
    pub in_place: Split,

    pub allowed: usize,
    pub allowed_distinct: usize,
    pub allowed_by_rule: Vec<(String, Tally)>,
    pub waits: Waits,
    /// Answered requests by how long the answer took ([`BUCKETS`]).
    pub buckets: Vec<Bucket>,

    pub slips: Vec<Slip>,
    pub unattended: Split,
    pub flagged: Vec<Flagged>,
    /// Allowed requests where the CLI could not make out the line and so said
    /// nothing about any command in it.
    pub cli_unparsed: usize,
    pub disagreements: Vec<Disagreement>,
    pub widened: Vec<Widened>,

    /// The kind of the first reason a request passed: the code up to its `:`.
    pub pass_kinds: Vec<(String, Tally)>,
    /// The first reason, in full, when it was not a missing command.
    pub pass_codes: Vec<(String, Tally)>,
    /// The first command missing from the allow-list.
    pub missing: Vec<(String, Tally)>,
    pub what_if: WhatIf,
    pub roots: Roots,
}

/// Facts about the run that the report prints and the analysis does not use.
#[derive(Debug, Default, Clone)]
pub struct Header {
    pub policy: String,
    pub mode: String,
    pub home: String,
    pub roots: Vec<String>,
}

fn stored_problem(command: &str) -> Option<&'static str> {
    if command.contains(CUT_MARK) {
        Some("stored-truncated")
    } else if command.contains(MARKER_PREFIX) {
        Some("stored-redacted")
    } else {
        None
    }
}

fn kind_of(code: &str) -> &str {
    code.split_once(':').map_or(code, |(kind, _)| kind)
}

/// When the CLI cannot make out a line it names the whole line as the one
/// command in it, and calls that not read-only. That is not an opinion about
/// any command in the line.
fn names_the_line(identifier: &str, command: &str) -> bool {
    identifier.contains(char::is_whitespace) && identifier == command
}

/// The directories directly below the home directory that a request is about,
/// each as `~/name`: the one the session was in and the ones the command names.
/// They are the roots worth trying; the judge says whether one of them helps.
/// Directories whose names start with a dot (configuration, credentials) are
/// never suggested.
fn candidates(command: &str, cwd: Option<&str>, home: &str) -> BTreeSet<String> {
    fn take(found: &mut BTreeSet<String>, below_home: &str) {
        let name: String = below_home
            .chars()
            .take_while(|c| !c.is_whitespace() && !"/\"'`$;|&()<>\\*?[]{}~".contains(*c))
            .collect();
        if !name.is_empty() && !name.starts_with('.') {
            found.insert(format!("~/{name}"));
        }
    }

    let home = home.trim_end_matches('/');
    let mut found = BTreeSet::new();
    if let Some(below) = cwd
        .and_then(|c| c.strip_prefix(home))
        .and_then(|c| c.strip_prefix('/'))
    {
        take(&mut found, below);
    }
    for prefix in [
        format!("{home}/"),
        "~/".to_owned(),
        "$HOME/".to_owned(),
        "${HOME}/".to_owned(),
    ] {
        for (at, _) in command.match_indices(&prefix) {
            take(&mut found, &command[at + prefix.len()..]);
        }
    }
    found
}

/// The most waiting first (what a rule costs is what it kept people waiting),
/// then the most requests, then by name.
fn by_wait(counts: BTreeMap<String, Tally>) -> Vec<(String, Tally)> {
    let mut rows: Vec<_> = counts.into_iter().collect();
    rows.sort_by(|a, b| {
        b.1.wait_s
            .total_cmp(&a.1.wait_s)
            .then(b.1.requests.cmp(&a.1.requests))
    });
    rows
}

/// The most requests first, then by name.
fn by_requests(counts: BTreeMap<String, Tally>) -> Vec<(String, Tally)> {
    let mut rows: Vec<_> = counts.into_iter().collect();
    rows.sort_by_key(|row| std::cmp::Reverse(row.1.requests));
    rows
}

pub(crate) fn nearest_rank(sorted: &[f64], q: f64) -> f64 {
    if sorted.is_empty() {
        return 0.0;
    }
    let rank = (q * sorted.len() as f64).ceil() as usize;
    sorted[rank.clamp(1, sorted.len()) - 1]
}

fn waits(all: &[f64], allowed: &[f64]) -> Waits {
    let mut mine = allowed.to_vec();
    mine.sort_by(f64::total_cmp);
    Waits {
        answered: all.len(),
        total_s: all.iter().sum(),
        total_capped_s: all.iter().map(|w| w.min(AWAY_S)).sum(),
        allowed: allowed.len(),
        allowed_total_s: allowed.iter().sum(),
        allowed_capped_s: allowed.iter().map(|w| w.min(AWAY_S)).sum(),
        allowed_median_s: nearest_rank(&mine, 0.5),
        allowed_p90_s: nearest_rank(&mine, 0.9),
        allowed_max_s: mine.last().copied().unwrap_or(0.0),
        allowed_away: allowed.iter().filter(|w| **w >= AWAY_S).count(),
    }
}

/// What `history` comes to under the judge. `home` is the home directory the
/// requests ran under (the directories directly below it are the candidates for
/// trusted roots) and `steps` is how many additions the what-if analysis may
/// suggest.
pub fn analyze(history: &[Past], judge: &Judge<'_>, home: &str, steps: usize) -> Report {
    type Key<'a> = (&'a str, Option<&'a str>);
    #[derive(Default)]
    struct Pair {
        requests: usize,
        wait_s: f64,
    }

    let mut r = Report {
        buckets: vec![Bucket::default(); BUCKETS.len()],
        ..Report::default()
    };
    let mut seen: HashSet<Key<'_>> = HashSet::new();
    let mut memo: HashMap<Key<'_>, Verdict> = HashMap::new();
    let mut all_waits = Vec::new();
    let mut allowed_waits = Vec::new();
    let mut results: BTreeMap<String, usize> = BTreeMap::new();
    let mut rules: BTreeMap<String, Tally> = BTreeMap::new();
    let mut allowed_commands: BTreeMap<&str, usize> = BTreeMap::new();
    let mut by_identifier: BTreeMap<&str, (usize, BTreeSet<&str>)> = BTreeMap::new();
    let mut widened: BTreeMap<&str, (usize, BTreeSet<&str>)> = BTreeMap::new();
    let mut kinds: BTreeMap<String, Tally> = BTreeMap::new();
    let mut codes: BTreeMap<String, Tally> = BTreeMap::new();
    let mut missing: BTreeMap<String, Tally> = BTreeMap::new();
    let mut lacking: HashMap<Key<'_>, Pair> = HashMap::new();
    let mut untrusted: HashMap<Key<'_>, Pair> = HashMap::new();

    for p in history {
        r.requests += 1;
        r.first = Some(r.first.map_or(p.asked_at, |t| t.min(p.asked_at)));
        r.last = Some(r.last.map_or(p.asked_at, |t| t.max(p.asked_at)));
        let result = p.result.as_deref().unwrap_or(NO_ANSWER);
        *results.entry(result.to_owned()).or_default() += 1;
        let key: Key<'_> = (p.command.as_str(), p.cwd.as_deref());
        seen.insert(key);
        let in_place = p.cwd.is_some() && !p.cwd_gone;
        if p.cwd.is_none() {
            r.no_cwd += 1;
        } else if p.cwd_gone {
            r.gone_cwd += 1;
        } else {
            r.in_place.requests += 1;
        }
        r.prompts.entry(p.prompt_kind.clone()).or_default().requests += 1;
        if let Some(wait) = p.waited_s {
            all_waits.push(wait);
        }
        if result == UNATTENDED {
            r.unattended.requests += 1;
        }

        let verdict = match stored_problem(&p.command) {
            Some(why) => {
                *r.stored.entry(why).or_default() += 1;
                kinds.entry(why.to_owned()).or_default().add(p);
                None
            }
            None => Some(
                memo.entry(key)
                    .or_insert_with(|| judge(&p.command, p.cwd.as_deref(), &[]))
                    .clone(),
            ),
        };
        if let Some(wait) = p.waited_s {
            let bucket = &mut r.buckets[bucket_of(wait)];
            bucket.requests += 1;
            bucket.allowed += usize::from(matches!(verdict, Some(Verdict::Allow { .. })));
            bucket.wait_s += wait.min(AWAY_S);
        }
        match verdict {
            None => {}
            Some(Verdict::Allow { tags }) => {
                r.allowed += 1;
                r.in_place.allowed += usize::from(in_place);
                r.prompts.entry(p.prompt_kind.clone()).or_default().allowed += 1;
                rules.entry(format!("allow:{tags}")).or_default().add(p);
                *allowed_commands.entry(p.command.as_str()).or_default() += 1;
                if let Some(wait) = p.waited_s {
                    allowed_waits.push(wait);
                }
                if REFUSED.contains(&result) {
                    r.slips.push(Slip {
                        session_id: p.session_id.clone(),
                        request_id: p.request_id.clone(),
                        result: result.to_owned(),
                        command: p.command.clone(),
                    });
                }
                if result == UNATTENDED {
                    r.unattended.allowed += 1;
                }
                let identifiers: BTreeSet<&str> =
                    p.not_read_only.iter().map(String::as_str).collect();
                let mut gave_up = false;
                for identifier in identifiers {
                    if names_the_line(identifier, &p.command) {
                        gave_up = true;
                        continue;
                    }
                    let group = by_identifier.entry(identifier).or_default();
                    group.0 += 1;
                    group.1.insert(p.command.as_str());
                }
                r.cli_unparsed += usize::from(gave_up);
                if p.prompt_kind == "path" {
                    let group = widened.entry(p.command.as_str()).or_default();
                    group.0 += 1;
                    group.1.extend(p.paths.iter().map(String::as_str));
                }
            }
            Some(Verdict::Pass { code }) => {
                if let Some(name) = code.strip_prefix("cmd-not-allowed:") {
                    missing.entry(name.to_owned()).or_default().add(p);
                    kinds
                        .entry("cmd-not-allowed".to_owned())
                        .or_default()
                        .add(p);
                    let pair = lacking.entry(key).or_default();
                    pair.requests += 1;
                    pair.wait_s += p.capped_wait_s();
                } else {
                    if code == "path-untrusted" {
                        let pair = untrusted.entry(key).or_default();
                        pair.requests += 1;
                        pair.wait_s += p.capped_wait_s();
                    }
                    kinds.entry(kind_of(&code).to_owned()).or_default().add(p);
                    codes.entry(code).or_default().add(p);
                }
            }
        }
    }

    r.distinct = seen.len();
    r.results = results;
    r.allowed_distinct = allowed_commands.len();
    r.allowed_by_rule = by_requests(rules);
    r.waits = waits(&all_waits, &allowed_waits);

    r.flagged = allowed_commands
        .iter()
        .filter_map(|(command, requests)| {
            let flags = oracle::dangers(command);
            (!flags.is_empty()).then(|| Flagged {
                command: (*command).to_owned(),
                flags,
                requests: *requests,
            })
        })
        .collect();
    r.flagged.sort_by_key(|f| std::cmp::Reverse(f.requests));

    r.disagreements = by_identifier
        .into_iter()
        .map(|(identifier, (requests, commands))| Disagreement {
            identifier: identifier.to_owned(),
            requests,
            distinct: commands.len(),
            example: commands
                .iter()
                .min_by_key(|c| c.len())
                .map(|c| (*c).to_owned())
                .unwrap_or_default(),
        })
        .collect();
    r.disagreements
        .sort_by_key(|d| std::cmp::Reverse(d.requests));

    r.widened = widened
        .into_iter()
        .map(|(command, (requests, paths))| Widened {
            command: command.to_owned(),
            requests,
            paths: paths.into_iter().take(6).map(str::to_owned).collect(),
        })
        .collect();
    r.widened.sort_by_key(|w| std::cmp::Reverse(w.requests));

    r.pass_kinds = by_wait(kinds);
    r.pass_codes = by_wait(codes);
    r.missing = by_wait(missing);

    // A map's order is not the same twice, and the greedy choice adds up
    // fractions: the same history must give the same answer every time
    let mut pairs: Vec<(&str, Option<&str>, usize, f64)> = lacking
        .into_iter()
        .map(|((command, cwd), pair)| (command, cwd, pair.requests, pair.wait_s))
        .collect();
    pairs.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    r.what_if = what_if(&pairs, judge, steps);

    let mut pairs: Vec<(&str, Option<&str>, usize, f64)> = untrusted
        .into_iter()
        .map(|((command, cwd), pair)| (command, cwd, pair.requests, pair.wait_s))
        .collect();
    pairs.sort_by(|a, b| (a.0, a.1).cmp(&(b.0, b.1)));
    r.roots = roots_what_if(&pairs, judge, home);
    r
}

/// For each line that passed because a command is missing: which commands it
/// lacks (found by assuming the missing one, again and again, until the verdict
/// is no longer about commands), and whether that is all that is in its way.
/// Then, greedily, the additions that unlock most.
fn what_if(pairs: &[(&str, Option<&str>, usize, f64)], judge: &Judge<'_>, steps: usize) -> WhatIf {
    struct Need {
        requests: usize,
        wait_s: f64,
        lacks: Vec<String>,
    }
    let mut out = WhatIf::default();
    let mut needs: Vec<Need> = Vec::new();
    for &(command, cwd, requests, wait_s) in pairs {
        let mut lacks: Vec<String> = Vec::new();
        let enough = loop {
            let assumed: Vec<&str> = lacks.iter().map(String::as_str).collect();
            match judge(command, cwd, &assumed) {
                Verdict::Allow { .. } => break true,
                Verdict::Pass { code } => match code.strip_prefix("cmd-not-allowed:") {
                    Some(name) if lacks.len() < MAX_LACKS && !lacks.iter().any(|l| l == name) => {
                        lacks.push(name.to_owned());
                    }
                    _ => break false,
                },
            }
        };
        if enough && !lacks.is_empty() {
            out.unlockable += requests;
            needs.push(Need {
                requests,
                wait_s,
                lacks,
            });
        } else {
            out.stuck += requests;
        }
    }

    let mut chosen: Vec<String> = Vec::new();
    let mut done = vec![false; needs.len()];
    let mut cumulative = 0;
    for _ in 0..steps {
        let mut exact: BTreeMap<&str, usize> = BTreeMap::new();
        let mut shared: BTreeMap<&str, f64> = BTreeMap::new();
        for (need, _) in needs.iter().zip(&done).filter(|(_, done)| !**done) {
            let rest: Vec<&str> = need
                .lacks
                .iter()
                .map(String::as_str)
                .filter(|l| !chosen.iter().any(|c| c == l))
                .collect();
            for name in &rest {
                *shared.entry(name).or_default() += need.requests as f64 / rest.len() as f64;
                if rest.len() == 1 {
                    *exact.entry(name).or_default() += need.requests;
                }
            }
        }
        // what unlocks most on its own, then what is part of most of the rest;
        // on a tie the first in name order
        let mut best: Option<(&str, usize, f64)> = None;
        for (&name, &share) in &shared {
            let gain = exact.get(name).copied().unwrap_or(0);
            if best.is_none_or(|(_, g, s)| (gain, share) > (g, s)) {
                best = Some((name, gain, share));
            }
        }
        let Some((name, _, _)) = best else { break };
        chosen.push(name.to_owned());
        let (mut gained, mut gained_wait_s) = (0, 0.0);
        for (need, done) in needs.iter().zip(done.iter_mut()) {
            if !*done && need.lacks.iter().all(|l| chosen.contains(l)) {
                *done = true;
                gained += need.requests;
                gained_wait_s += need.wait_s;
            }
        }
        cumulative += gained;
        out.steps.push(Step {
            command: name.to_owned(),
            gained,
            cumulative,
            gained_wait_s,
        });
    }
    out
}

/// For each line that passed for a path outside the trusted roots: which of the
/// directories it is about, trusted by itself, would make the policy allow it.
/// Lines that need two roots, or something else besides one, are not counted.
fn roots_what_if(
    pairs: &[(&str, Option<&str>, usize, f64)],
    judge: &Judge<'_>,
    home: &str,
) -> Roots {
    let mut out = Roots::default();
    let mut rows: BTreeMap<String, Unlock> = BTreeMap::new();
    for &(command, cwd, requests, wait_s) in pairs {
        out.untrusted += requests;
        let mut unlocked = false;
        for root in candidates(command, cwd, home) {
            let assumption = format!("{ROOT_PREFIX}{root}");
            if !matches!(
                judge(command, cwd, &[assumption.as_str()]),
                Verdict::Allow { .. }
            ) {
                continue;
            }
            unlocked = true;
            let row = rows.entry(root.clone()).or_insert_with(|| Unlock {
                root,
                requests: 0,
                wait_s: 0.0,
                example: String::new(),
            });
            row.requests += requests;
            row.wait_s += wait_s;
            if row.example.is_empty() || command.len() < row.example.len() {
                command.clone_into(&mut row.example);
            }
        }
        if unlocked {
            out.unlockable += requests;
            out.unlockable_wait_s += wait_s;
        }
    }
    out.rows = rows.into_values().collect();
    out.rows.sort_by(|a, b| {
        b.wait_s
            .total_cmp(&a.wait_s)
            .then(b.requests.cmp(&a.requests))
    });
    out
}

// ---- the text ----

pub(crate) fn line(out: &mut String, text: impl AsRef<str>) {
    out.push_str(text.as_ref());
    out.push('\n');
}

pub(crate) fn n(x: usize) -> String {
    let digits = x.to_string();
    let mut out = String::new();
    for (i, c) in digits.chars().enumerate() {
        if i > 0 && (digits.len() - i).is_multiple_of(3) {
            out.push(',');
        }
        out.push(c);
    }
    out
}

pub(crate) fn pct(part: usize, whole: usize) -> String {
    if whole == 0 {
        "-".to_owned()
    } else {
        format!("{:.1}%", part as f64 * 100.0 / whole as f64)
    }
}

pub(crate) fn secs(s: f64) -> String {
    if s < 90.0 {
        format!("{s:.0} s")
    } else if s < 5400.0 {
        format!("{:.1} min", s / 60.0)
    } else {
        format!("{:.1} h", s / 3600.0)
    }
}

pub(crate) fn clip(text: &str, max: usize) -> String {
    let one_line = text.replace('\n', "⏎");
    if one_line.chars().count() <= max {
        return one_line;
    }
    let mut cut: String = one_line.chars().take(max).collect();
    cut.push('…');
    cut
}

/// A table of reasons: how many requests, and how long they kept people waiting.
/// `total` and `wait_s` are what the shares are shares of.
fn tallies(
    out: &mut String,
    title: &str,
    rows: &[(String, Tally)],
    total: usize,
    wait_s: f64,
    top: usize,
) {
    let width = rows
        .iter()
        .take(top)
        .map(|(k, _)| k.chars().count())
        .chain([title.chars().count()])
        .max()
        .unwrap_or(0)
        .min(34);
    line(
        out,
        format!(
            "    {title:<width$}  {:>8} {:>7}  {:>10} {:>7}   e.g.",
            "requests", "share", "wait", "share"
        ),
    );
    for (name, t) in rows.iter().take(top) {
        line(
            out,
            format!(
                "    {:<width$}  {:>8} {:>7}  {:>10} {:>7}   {}",
                clip(name, width),
                n(t.requests),
                pct(t.requests, total),
                secs(t.wait_s),
                pct_f(t.wait_s, wait_s),
                clip(&t.example, 70)
            ),
        );
    }
    if rows.len() > top {
        let rest = &rows[top..];
        line(
            out,
            format!(
                "    … {} more: {} requests, {}",
                rest.len(),
                n(rest.iter().map(|(_, t)| t.requests).sum()),
                secs(rest.iter().map(|(_, t)| t.wait_s).sum())
            ),
        );
    }
}

pub fn render(r: &Report, head: &Header, top: usize) -> String {
    let mut o = String::new();
    let span = match (r.first, r.last) {
        (Some(a), Some(b)) => format!("{} .. {}", a.format("%Y-%m-%d"), b.format("%Y-%m-%d")),
        _ => "none".to_owned(),
    };
    line(
        &mut o,
        format!(
            "ctx-hook replay: {} shell permission requests, {span}",
            n(r.requests)
        ),
    );
    line(
        &mut o,
        format!(
            "  policy {}, mode {}, home {}",
            head.policy, head.mode, head.home
        ),
    );
    line(&mut o, format!("  trusted roots {}", head.roots.join("  ")));
    line(
        &mut o,
        "  judged the way the hook would, but in a clean environment (only HOME) and in the",
    );
    line(
        &mut o,
        "  directory the session was in when it asked; paths are checked against the disk as it is now",
    );

    line(&mut o, "\n1. WHAT WAS ASKED");
    line(
        &mut o,
        format!(
            "  requests     {}, of {} distinct (command, directory) pairs",
            n(r.requests),
            n(r.distinct)
        ),
    );
    let prompts: Vec<String> = r
        .prompts
        .iter()
        .map(|(kind, s)| format!("{kind} {}", n(s.requests)))
        .collect();
    line(&mut o, format!("  asked as     {}", prompts.join(", ")));
    let mut results: Vec<(&String, &usize)> = r.results.iter().collect();
    results.sort_by(|a, b| b.1.cmp(a.1));
    let results: Vec<String> = results
        .iter()
        .map(|(k, c)| format!("{k} {}", n(**c)))
        .collect();
    line(&mut o, format!("  answered     {}", results.join(", ")));
    if !r.stored.is_empty() {
        let stored: Vec<String> = r
            .stored
            .iter()
            .map(|(k, c)| format!("{} {}", n(*c), k.trim_start_matches("stored-")))
            .collect();
        line(
            &mut o,
            format!(
                "  not judged   {} by the ingester (counted as passes)",
                stored.join(", ")
            ),
        );
    }
    line(
        &mut o,
        format!(
            "  directory    {} requests were in a directory that is still there; {} have none on record and {} were in one that is gone (a relative path in those cannot be trusted)",
            n(r.in_place.requests),
            n(r.no_cwd),
            n(r.gone_cwd)
        ),
    );

    line(&mut o, "\n2. WHAT THE POLICY WOULD HAVE ANSWERED");
    line(
        &mut o,
        format!(
            "  allowed      {} of {} requests ({}), {} distinct commands",
            n(r.allowed),
            n(r.requests),
            pct(r.allowed, r.requests),
            n(r.allowed_distinct)
        ),
    );
    line(
        &mut o,
        format!(
            "  in a directory that is still there: {} of {} ({})",
            n(r.in_place.allowed),
            n(r.in_place.requests),
            pct(r.in_place.allowed, r.in_place.requests)
        ),
    );
    let by_prompt: Vec<String> = r
        .prompts
        .iter()
        .map(|(kind, s)| {
            format!(
                "{kind} {} of {} ({})",
                n(s.allowed),
                n(s.requests),
                pct(s.allowed, s.requests)
            )
        })
        .collect();
    line(&mut o, format!("  asked as     {}", by_prompt.join(", ")));
    tallies(
        &mut o,
        "by rule",
        &r.allowed_by_rule,
        r.requests,
        r.waits.total_capped_s,
        top,
    );

    line(
        &mut o,
        format!(
            "\n3. WAITING (from the question to the answer; \"wait\" counts no answer for more than {})",
            secs(AWAY_S)
        ),
    );
    let w = &r.waits;
    line(
        &mut o,
        format!(
            "  all          {} answered, {} waited; {} as \"wait\"",
            n(w.answered),
            secs(w.total_s),
            secs(w.total_capped_s),
        ),
    );
    line(
        &mut o,
        format!(
            "  the allowed  {} answered, {} waited ({} of all waiting), {} as \"wait\"; median {}, p90 {}, longest {}; {} waited {} or more",
            n(w.allowed),
            secs(w.allowed_total_s),
            pct_f(w.allowed_total_s, w.total_s),
            secs(w.allowed_capped_s),
            secs(w.allowed_median_s),
            secs(w.allowed_p90_s),
            secs(w.allowed_max_s),
            n(w.allowed_away),
            secs(AWAY_S)
        ),
    );
    line(
        &mut o,
        format!(
            "    {:<14} {:>8} {:>7} {:>8} {:>7}  {:>10} {:>7}",
            "answered in", "requests", "share", "allowed", "share", "wait", "share"
        ),
    );
    let answered: usize = r.buckets.iter().map(|b| b.requests).sum();
    for ((name, _), b) in BUCKETS.iter().zip(&r.buckets) {
        line(
            &mut o,
            format!(
                "    {:<14} {:>8} {:>7} {:>8} {:>7}  {:>10} {:>7}",
                name,
                n(b.requests),
                pct(b.requests, answered),
                n(b.allowed),
                pct(b.allowed, b.requests),
                secs(b.wait_s),
                pct_f(b.wait_s, w.total_capped_s)
            ),
        );
    }

    line(&mut o, "\n4. SAFETY CHECKS");
    for kind in REFUSED {
        let asked = r.results.get(*kind).copied().unwrap_or(0);
        let slipped = r.slips.iter().filter(|s| s.result == *kind).count();
        line(
            &mut o,
            format!(
                "  {kind:<30} {} of {} would have been allowed   {}",
                n(slipped),
                n(asked),
                if slipped == 0 {
                    "ok"
                } else {
                    "PROBLEM: must be 0"
                }
            ),
        );
    }
    for s in &r.slips {
        line(
            &mut o,
            format!(
                "    {} {} {}: {}",
                s.session_id,
                s.request_id,
                s.result,
                clip(&s.command, 200)
            ),
        );
    }
    line(
        &mut o,
        format!(
            "  nobody to ask ({} runs): {} of {} would have been allowed",
            "copilot -p",
            n(r.unattended.allowed),
            n(r.unattended.requests)
        ),
    );
    line(
        &mut o,
        format!(
            "  the oracle sees more than a read in {} of the {} allowed commands {}",
            n(r.flagged.len()),
            n(r.allowed_distinct),
            if r.flagged.is_empty() {
                "ok"
            } else {
                "(each needs a person's look):"
            }
        ),
    );
    for f in &r.flagged {
        line(
            &mut o,
            format!(
                "    {}x [{}] {}",
                n(f.requests),
                f.flags.join(","),
                clip(&f.command, 200)
            ),
        );
    }
    line(
        &mut o,
        format!(
            "  the CLI called a command in the allowed requests not read-only: {} commands (and on {} allowed requests it gave up on the whole line, which says nothing about any one command)",
            n(r.disagreements.len()),
            n(r.cli_unparsed)
        ),
    );
    for d in r.disagreements.iter().take(top) {
        line(
            &mut o,
            format!(
                "    {:<14} {:>5} requests, {:>4} distinct, e.g. {}",
                d.identifier,
                n(d.requests),
                n(d.distinct),
                clip(&d.example, 110)
            ),
        );
    }
    line(
        &mut o,
        format!(
            "  asked as a path and allowed by the policy: {} commands (the CLI would have wanted an answer about these places)",
            n(r.widened.len())
        ),
    );
    for wd in r.widened.iter().take(top) {
        line(
            &mut o,
            format!(
                "    {:>4}x {}  [{}]",
                n(wd.requests),
                clip(&wd.command, 100),
                clip(&wd.paths.join(" "), 100)
            ),
        );
    }

    line(
        &mut o,
        format!(
            "\n5. WHY THE REST PASSED (the first reason on the line; \"wait\" is what they cost, no answer counted for more than {})",
            secs(AWAY_S)
        ),
    );
    let passed = r.requests - r.allowed;
    let wait = r.waits.total_capped_s;
    tallies(&mut o, "by kind", &r.pass_kinds, passed, wait, top);
    tallies(
        &mut o,
        "the command missing from the allow-list",
        &r.missing,
        passed,
        wait,
        top,
    );
    tallies(
        &mut o,
        "every other reason, in full",
        &r.pass_codes,
        passed,
        wait,
        top,
    );

    line(
        &mut o,
        "\n6. WHAT IF A COMMAND WERE ALLOWED (an upper bound: the command is taken as harmless with any\n   arguments and in any directory, so the paths it names are not judged; every other command and rule as it is)",
    );
    let wi = &r.what_if;
    line(
        &mut o,
        format!(
            "  lacking only commands {} requests ({} of all), still stuck behind another rule {}",
            n(wi.unlockable),
            pct(wi.unlockable, r.requests),
            n(wi.stuck)
        ),
    );
    line(
        &mut o,
        "  add             +requests   cumulative   share of all   wait saved (capped)",
    );
    for s in &wi.steps {
        line(
            &mut o,
            format!(
                "  {:<15} {:>9} {:>12}   {:>12}   {}",
                s.command,
                n(s.gained),
                n(r.allowed + s.cumulative),
                pct(r.allowed + s.cumulative, r.requests),
                secs(s.gained_wait_s)
            ),
        );
    }

    line(
        &mut o,
        "\n7. WHAT IF A DIRECTORY WERE A TRUSTED ROOT (trusted_roots in the settings file; each tried alone, every other rule as it is)",
    );
    let ro = &r.roots;
    line(
        &mut o,
        format!(
            "  {} requests passed first for a path outside the trusted roots; one more root would have made {} of them ({} of all) allowed, {} of waiting",
            n(ro.untrusted),
            n(ro.unlockable),
            pct(ro.unlockable, r.requests),
            secs(ro.unlockable_wait_s)
        ),
    );
    line(
        &mut o,
        format!(
            "  {:<24} {:>8} {:>7}  {:>10} {:>7}   e.g.",
            "trust", "requests", "share", "wait", "share"
        ),
    );
    for u in ro.rows.iter().take(top) {
        line(
            &mut o,
            format!(
                "  {:<24} {:>8} {:>7}  {:>10} {:>7}   {}",
                clip(&u.root, 24),
                n(u.requests),
                pct(u.requests, r.requests),
                secs(u.wait_s),
                pct_f(u.wait_s, r.waits.total_capped_s),
                clip(&u.example, 70)
            ),
        );
    }
    if ro.rows.len() > top {
        line(
            &mut o,
            format!("  … {} more directories", ro.rows.len() - top),
        );
    }
    line(
        &mut o,
        "  a root vouches for everything under it that the deny list does not name: keep out directories with secrets in them",
    );
    o
}

pub(crate) fn pct_f(part: f64, whole: f64) -> String {
    if whole <= 0.0 {
        "-".to_owned()
    } else {
        format!("{:.1}%", part * 100.0 / whole)
    }
}

// ---- the history ----

#[derive(sqlx::FromRow)]
struct Raw {
    session_id: String,
    request_id: String,
    asked_at: DateTime<Utc>,
    prompt_kind: Option<String>,
    command: Option<String>,
    not_read_only: Vec<String>,
    paths: Vec<String>,
    completed_at: Option<DateTime<Utc>>,
    result: Option<String>,
    cwd: Option<String>,
}

/// One row per request that asked about a shell command, its first question
/// (a request can be recorded twice) and first answer, and the directory the
/// session was in at the time: the latest start, resume or change of context
/// before the question, else the one the session began in.
const HISTORY: &str = r#"
SELECT r.session_id,
       r.request_id,
       r.asked_at,
       r.prompt_kind,
       r.command,
       r.not_read_only,
       r.paths,
       a.completed_at,
       a.result,
       coalesce(c.cwd, s.cwd) AS cwd
  FROM (
        SELECT DISTINCT ON (e.session_id, e.body->>'requestId')
               e.session_id,
               e.body->>'requestId' AS request_id,
               e.ts AS asked_at,
               e.body->'promptRequest'->>'kind' AS prompt_kind,
               coalesce(e.body->'permissionRequest'->>'fullCommandText',
                        e.body->'promptRequest'->>'fullCommandText') AS command,
               ARRAY(SELECT x->>'identifier'
                       FROM jsonb_array_elements(
                                coalesce(e.body->'permissionRequest'->'commands', '[]'::jsonb)) x
                      WHERE x->>'readOnly' = 'false' AND x->>'identifier' IS NOT NULL) AS not_read_only,
               ARRAY(SELECT jsonb_array_elements_text(
                                coalesce(e.body->'promptRequest'->'paths', '[]'::jsonb))) AS paths
          FROM events e
         WHERE e.type = 'permission.requested'
           AND e.body->'permissionRequest'->>'kind' = 'shell'
           AND ($1::timestamptz IS NULL OR e.ts >= $1)
         ORDER BY e.session_id, e.body->>'requestId', e.ts
       ) r
  LEFT JOIN (
        SELECT DISTINCT ON (e.session_id, e.body->>'requestId')
               e.session_id,
               e.body->>'requestId' AS request_id,
               e.ts AS completed_at,
               e.body->'result'->>'kind' AS result
          FROM events e
         WHERE e.type = 'permission.completed'
         ORDER BY e.session_id, e.body->>'requestId', e.ts
       ) a ON a.session_id = r.session_id AND a.request_id = r.request_id
  LEFT JOIN sessions s ON s.id = r.session_id
  LEFT JOIN LATERAL (
        SELECT coalesce(x.body->>'cwd', x.body->'context'->>'cwd') AS cwd
          FROM events x
         WHERE x.session_id = r.session_id
           AND x.type IN ('session.start', 'session.resume', 'session.context_changed')
           AND x.ts <= r.asked_at
           AND coalesce(x.body->>'cwd', x.body->'context'->>'cwd') IS NOT NULL
         ORDER BY x.ts DESC
         LIMIT 1
       ) c ON true
 WHERE r.command IS NOT NULL
 ORDER BY r.asked_at DESC
 LIMIT $2
"#;

/// The history, oldest first. `since` and `limit` (the most recent N) are
/// optional.
pub async fn load(
    pool: &PgPool,
    since: Option<DateTime<Utc>>,
    limit: Option<i64>,
) -> Result<Vec<Past>> {
    let rows: Vec<Raw> = sqlx::query_as(HISTORY)
        .bind(since)
        .bind(limit)
        .fetch_all(pool)
        .await
        .context("reading permission requests from events")?;
    let mut history: Vec<Past> = rows
        .into_iter()
        .map(|raw| {
            let cwd_gone = raw.cwd.as_deref().is_some_and(|c| !Path::new(c).is_dir());
            Past {
                session_id: raw.session_id,
                request_id: raw.request_id,
                asked_at: raw.asked_at,
                prompt_kind: raw.prompt_kind.unwrap_or_else(|| "unknown".to_owned()),
                command: raw.command.unwrap_or_default(),
                cwd: raw.cwd,
                cwd_gone,
                waited_s: raw
                    .completed_at
                    .map(|done| (done - raw.asked_at).num_milliseconds() as f64 / 1000.0)
                    .filter(|w| *w >= 0.0),
                result: raw.result,
                not_read_only: raw.not_read_only,
                paths: raw.paths,
            }
        })
        .collect();
    history.reverse();
    Ok(history)
}

/// The judge that the real policy makes. An assumption written `root:~/dir` is
/// the policy with that directory added to its trusted roots (the policies for
/// the roots tried are built once); any other assumption is a command taken to
/// be on the allow-list.
pub struct Judges<'a> {
    base: &'a Policy,
    config: &'a Config,
    home: &'a Path,
    with_roots: RefCell<HashMap<Vec<String>, Policy>>,
}

impl<'a> Judges<'a> {
    pub fn new(base: &'a Policy, config: &'a Config, home: &'a Path) -> Self {
        Judges {
            base,
            config,
            home,
            with_roots: RefCell::new(HashMap::new()),
        }
    }

    pub fn judge(&self, command: &str, cwd: Option<&str>, assume: &[&str]) -> Verdict {
        let request = Request::bash(command, cwd, Utc::now());
        let (roots, commands): (Vec<&str>, Vec<&str>) = assume
            .iter()
            .copied()
            .partition(|a| a.starts_with(ROOT_PREFIX));
        if roots.is_empty() {
            return self.base.judge_assuming(&request, &commands);
        }
        let mut extra: Vec<String> = roots
            .iter()
            .map(|r| r[ROOT_PREFIX.len()..].to_owned())
            .collect();
        extra.sort();
        extra.dedup();
        let mut cache = self.with_roots.borrow_mut();
        let policy = cache.entry(extra).or_insert_with_key(|extra| {
            let mut config = self.config.clone();
            for root in extra {
                if !config.roots.contains(root) {
                    config.roots.push(root.clone());
                }
            }
            let home = self.home.to_string_lossy();
            Policy::new(self.home, &config, Vars::fixed(&[("HOME", &home)]))
        });
        policy.judge_assuming(&request, &commands)
    }
}

pub struct Options {
    pub since: Option<NaiveDate>,
    pub limit: Option<i64>,
    pub top: usize,
}

/// Reads the history, judges it by the policy as configured now, and returns
/// the report.
pub fn run(opts: &Options) -> Result<String> {
    let process = Vars::Process;
    let Some(home) = process
        .get("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_absolute())
    else {
        bail!("HOME is not set to an absolute path");
    };
    let home_text = home.to_string_lossy().into_owned();
    let config = Config::load(&process, &home);
    let policy = Policy::new(&home, &config, Vars::fixed(&[("HOME", home_text.as_str())]));
    if let Err(error) = policy.trust() {
        bail!("the configuration cannot be used: {error}");
    }
    let roots = policy
        .trust()
        .map(|t| t.roots().map(|r| r.display().to_string()).collect())
        .unwrap_or_default();
    let head = Header {
        policy: policy.id().to_owned(),
        mode: config.mode.as_str().to_owned(),
        home: home_text,
        roots,
    };

    let core = CoreConfig::from_env()?;
    let since = opts
        .since
        .and_then(|d| d.and_hms_opt(0, 0, 0))
        .map(|t| t.and_utc());
    let runtime = tokio::runtime::Builder::new_current_thread()
        .enable_all()
        .build()?;
    let history = runtime.block_on(async {
        let pool = db::connect(&core.database_url, "ctx-hook-replay", None, 2).await?;
        let history = load(&pool, since, opts.limit).await;
        pool.close().await;
        history
    })?;

    // The analyzer recurses on the shell's nesting, and a command can be long
    let top = opts.top;
    std::thread::scope(|scope| {
        std::thread::Builder::new()
            .name("ctx-hook-replay".to_owned())
            .stack_size(WORKER_STACK)
            .spawn_scoped(scope, || {
                let judges = Judges::new(&policy, &config, &home);
                let judge = |command: &str, cwd: Option<&str>, assume: &[&str]| {
                    judges.judge(command, cwd, assume)
                };
                let report = analyze(&history, &judge, &head.home, top.max(10));
                render(&report, &head, top)
            })
            .context("starting the worker thread")?
            .join()
            .map_err(|_| anyhow::anyhow!("the analysis panicked"))
    })
}

#[cfg(test)]
mod tests {
    use std::cell::Cell;
    use std::iter::repeat_n;

    use super::*;

    fn at(minute: i64) -> DateTime<Utc> {
        DateTime::from_timestamp(1_700_000_000 + minute * 60, 0).unwrap()
    }

    /// The requests of each row of a table of reasons.
    fn requests(rows: &[(String, Tally)]) -> Vec<(&str, usize)> {
        rows.iter().map(|(k, t)| (k.as_str(), t.requests)).collect()
    }

    fn past(command: &str) -> Past {
        Past {
            session_id: "s1".to_owned(),
            request_id: format!("r-{command}"),
            asked_at: at(0),
            prompt_kind: "commands".to_owned(),
            command: command.to_owned(),
            cwd: Some("/home/u/kms".to_owned()),
            cwd_gone: false,
            waited_s: Some(10.0),
            result: Some("approved".to_owned()),
            not_read_only: Vec::new(),
            paths: Vec::new(),
        }
    }

    impl Past {
        fn result(mut self, result: &str) -> Past {
            self.result = Some(result.to_owned());
            self
        }

        fn wait(mut self, seconds: f64) -> Past {
            self.waited_s = Some(seconds);
            self
        }

        fn unanswered(mut self) -> Past {
            self.waited_s = None;
            self.result = None;
            self
        }

        fn cwd(mut self, cwd: &str) -> Past {
            self.cwd = Some(cwd.to_owned());
            self
        }

        fn path_prompt(mut self, paths: &[&str]) -> Past {
            self.prompt_kind = "path".to_owned();
            self.paths = paths.iter().map(|p| (*p).to_owned()).collect();
            self
        }

        fn not_read_only(mut self, ids: &[&str]) -> Past {
            self.not_read_only = ids.iter().map(|p| (*p).to_owned()).collect();
            self
        }
    }

    /// Whether a path is under the home directory (`/home/u`) and not in a trusted
    /// root. `kms` is one; another is once `root:~/dir` is assumed.
    fn untrusted(path: &str, assume: &[&str]) -> bool {
        let Some(below) = path.strip_prefix("/home/u/") else {
            return false;
        };
        let top = below.split('/').next().unwrap_or("");
        top != "kms" && !assume.contains(&format!("{ROOT_PREFIX}~/{top}").as_str())
    }

    /// Lines of `|`-separated commands. `ls`, `cat` and `git` are on the list,
    /// others are when assumed; a path under the home directory is trusted only
    /// in `kms` (and in what is assumed to be a root), and the directory the
    /// session is in is a path too; `.env` is denied wherever it is; a `;` is
    /// not understood. Checked in this order for each command, like the policy.
    fn fake(command: &str, cwd: Option<&str>, assume: &[&str]) -> Verdict {
        let mut tags: Vec<String> = Vec::new();
        for part in command.split('|') {
            if part.contains(';') {
                return Verdict::Pass {
                    code: "meta:;".to_owned(),
                };
            }
            let name = part.split_whitespace().next().unwrap_or("");
            if !["ls", "cat", "git"].contains(&name) && !assume.contains(&name) {
                return Verdict::Pass {
                    code: format!("cmd-not-allowed:{name}"),
                };
            }
            if cwd.is_some_and(|c| untrusted(c, assume))
                || part
                    .split_whitespace()
                    .skip(1)
                    .any(|o| untrusted(o, assume))
            {
                return Verdict::Pass {
                    code: "path-untrusted".to_owned(),
                };
            }
            if part.contains(".env") && name != "echo" {
                return Verdict::Pass {
                    code: "path-denied".to_owned(),
                };
            }
            if !tags.iter().any(|t| t == name) {
                tags.push(name.to_owned());
            }
        }
        Verdict::Allow {
            tags: tags.join("+"),
        }
    }

    fn report(history: &[Past]) -> Report {
        analyze(history, &fake, "/home/u", 5)
    }

    /// `fake`, counting how many times it was asked.
    fn counting(calls: &Cell<usize>) -> impl Fn(&str, Option<&str>, &[&str]) -> Verdict + '_ {
        move |command, cwd, assume| {
            calls.set(calls.get() + 1);
            fake(command, cwd, assume)
        }
    }

    #[test]
    fn it_counts_requests_answers_and_the_share_the_policy_would_answer() {
        let history = vec![
            past("ls src"),
            past("ls src").result("approved-for-location"),
            past("cat a.txt | git log"),
            past("python3 x.py"),
            past("rm -rf x").result("denied-interactively-by-user"),
            past("ls ; rm x"),
            past("git status").path_prompt(&["/etc"]),
        ];
        let r = report(&history);
        assert_eq!(r.requests, 7);
        assert_eq!(
            r.distinct, 6,
            "the same command in the same directory is one"
        );
        assert_eq!(r.allowed, 4);
        assert_eq!(r.allowed_distinct, 3);
        assert_eq!(r.results["approved"], 5);
        assert_eq!(r.results["denied-interactively-by-user"], 1);
        assert_eq!(
            r.prompts["commands"],
            Split {
                requests: 6,
                allowed: 3
            }
        );
        assert_eq!(
            r.prompts["path"],
            Split {
                requests: 1,
                allowed: 1
            }
        );
        assert_eq!(
            requests(&r.allowed_by_rule),
            [("allow:ls", 2), ("allow:cat+git", 1), ("allow:git", 1)]
        );
    }

    #[test]
    fn it_says_why_the_rest_passed() {
        let history = vec![
            past("python3 a"),
            past("python3 b"),
            past("rm x"),
            past("ls ; ls"),
            past("ls ; cat"),
            past("cat .env"),
            past("ls"),
        ];
        let r = report(&history);
        assert_eq!(
            requests(&r.pass_kinds),
            [("cmd-not-allowed", 3), ("meta", 2), ("path-denied", 1)]
        );
        assert_eq!(requests(&r.missing), [("python3", 2), ("rm", 1)]);
        assert_eq!(requests(&r.pass_codes), [("meta:;", 2), ("path-denied", 1)]);
    }

    #[test]
    fn text_the_ingester_cut_or_redacted_is_not_judged() {
        let calls = Cell::new(0);
        let judge = counting(&calls);
        let history = vec![
            past("ls aaaa…[+9000 bytes]"),
            past("cat x [REDACTED:aws-key]"),
            past("ls ok"),
        ];
        let r = analyze(&history, &judge, "/home/u", 5);
        assert_eq!(
            r.stored,
            BTreeMap::from([("stored-redacted", 1), ("stored-truncated", 1)])
        );
        assert_eq!((r.requests, r.allowed), (3, 1));
        assert_eq!(calls.get(), 1, "only the line that was whole was judged");
        assert_eq!(
            requests(&r.pass_kinds),
            [("stored-redacted", 1), ("stored-truncated", 1)]
        );
        assert_eq!(r.what_if, WhatIf::default());
    }

    #[test]
    fn each_command_in_each_directory_is_judged_once() {
        let calls = Cell::new(0);
        let judge = counting(&calls);
        let history = vec![
            past("ls a"),
            past("ls a"),
            past("ls a"),
            past("ls a").cwd("/elsewhere"),
            past("ls a").cwd("/elsewhere"),
        ];
        let r = analyze(&history, &judge, "/home/u", 5);
        assert_eq!(calls.get(), 2);
        assert_eq!((r.requests, r.distinct, r.allowed), (5, 2, 5));
    }

    #[test]
    fn directories_that_are_missing_or_gone_are_counted() {
        let mut gone = past("ls a");
        gone.cwd_gone = true;
        let mut none = past("ls b");
        none.cwd = None;
        let r = report(&[gone, none, past("ls c"), past("python3 d")]);
        assert_eq!((r.gone_cwd, r.no_cwd), (1, 1));
        assert_eq!(
            r.in_place,
            Split {
                requests: 2,
                allowed: 1
            },
            "the share of what the replay could see in full"
        );
    }

    #[test]
    fn it_adds_up_the_waiting_and_caps_the_people_who_went_away() {
        let history = vec![
            past("ls a").wait(5.0),
            past("ls b").wait(20.0),
            past("ls c").wait(4000.0),
            past("python3 x").wait(100.0),
            past("ls d").unanswered(),
        ];
        let r = report(&history);
        let w = &r.waits;
        assert_eq!(w.answered, 4);
        assert_eq!(w.total_s, 4125.0);
        assert_eq!(w.total_capped_s, 425.0);
        assert_eq!(w.allowed, 3);
        assert_eq!(w.allowed_total_s, 4025.0);
        assert_eq!(w.allowed_capped_s, 325.0);
        assert_eq!(w.allowed_median_s, 20.0);
        assert_eq!(w.allowed_p90_s, 4000.0);
        assert_eq!(w.allowed_max_s, 4000.0);
        assert_eq!(w.allowed_away, 1);
        assert_eq!(r.results[NO_ANSWER], 1);
    }

    #[test]
    fn each_reason_and_rule_has_the_waiting_it_cost() {
        let history = vec![
            past("ls a").wait(4.0),
            past("ls b").wait(2000.0),
            past("rm x").wait(1.0),
            past("rm y").wait(2.0),
            past("rm z").wait(3.0),
            past("python3 xx").wait(100.0),
            past("python3 y").unanswered(),
        ];
        let r = report(&history);
        let ls = &r.allowed_by_rule[0];
        assert_eq!(ls.0, "allow:ls");
        assert_eq!(
            (ls.1.requests, ls.1.wait_s, ls.1.example.as_str()),
            (2, 304.0, "ls a"),
            "2,000 s counts as {AWAY_S} s"
        );
        let missing: Vec<(&str, usize, f64, &str)> = r
            .missing
            .iter()
            .map(|(k, t)| (k.as_str(), t.requests, t.wait_s, t.example.as_str()))
            .collect();
        assert_eq!(
            missing,
            [("python3", 2, 100.0, "python3 y"), ("rm", 3, 6.0, "rm x")],
            "what kept people waiting longest comes first, not what came up most"
        );
        assert_eq!(r.pass_kinds[0].0, "cmd-not-allowed");
        assert_eq!(r.pass_kinds[0].1.requests, 5);
        assert_eq!(r.pass_kinds[0].1.wait_s, 106.0);
    }

    #[test]
    fn the_answers_are_sorted_into_how_long_they_took() {
        let history = vec![
            past("ls a").wait(0.2),
            past("ls b").wait(0.9),
            past("python3 x").wait(0.5),
            past("ls c").wait(1.0),
            past("python3 y").wait(10.0),
            past("ls d").wait(299.9),
            past("ls e").wait(300.0),
            past("ls f").wait(7200.0),
            past("ls g").unanswered(),
        ];
        let r = report(&history);
        let rows: Vec<(usize, usize)> = r.buckets.iter().map(|b| (b.requests, b.allowed)).collect();
        assert_eq!(
            rows,
            [(3, 2), (1, 1), (1, 0), (1, 1), (2, 2)],
            "a wait of exactly 1 s is not under 1 s; the last is 5 min or more"
        );
        assert_eq!(r.buckets.len(), BUCKETS.len());
        assert_eq!(r.buckets[4].wait_s, 2.0 * AWAY_S);
        assert_eq!(
            r.buckets.iter().map(|b| b.requests).sum::<usize>(),
            r.waits.answered,
            "every answer is in one bucket and a request nobody answered in none"
        );
    }

    #[test]
    fn when_the_cli_gives_up_on_a_line_it_has_no_opinion_on_the_commands_in_it() {
        assert!(names_the_line("ls a | cat b", "ls a | cat b"));
        assert!(!names_the_line("ls", "ls"), "one word is a command");
        assert!(!names_the_line("ls", "ls a | cat b"));
        let history = vec![
            past("ls a | cat b").not_read_only(&["ls a | cat b"]),
            past("ls a | cat b").not_read_only(&["ls a | cat b"]),
            past("cat c | ls d").not_read_only(&["ls", "git log"]),
            past("python3 x").not_read_only(&["python3 x"]),
        ];
        let r = report(&history);
        assert_eq!(
            r.cli_unparsed, 2,
            "a line the policy would not have allowed is not counted"
        );
        let rows: Vec<(&str, usize)> = r
            .disagreements
            .iter()
            .map(|d| (d.identifier.as_str(), d.requests))
            .collect();
        assert_eq!(rows, [("git log", 1), ("ls", 1)]);
    }

    #[test]
    fn the_directories_a_request_is_about_are_the_ones_below_home() {
        let found = |command: &str, cwd: Option<&str>| -> Vec<String> {
            candidates(command, cwd, "/home/u").into_iter().collect()
        };
        assert_eq!(found("ls", Some("/home/u/wine/src")), ["~/wine"]);
        assert_eq!(
            found(
                "cat /home/u/awesome/x ~/gz/y $HOME/t16/z ${HOME}/pabx0; ls",
                Some("/home/u/kms")
            ),
            ["~/awesome", "~/gz", "~/kms", "~/pabx0", "~/t16"]
        );
        assert!(
            found("cat ~/.ssh/config /home/u/.config/x", Some("/home/u")).is_empty(),
            "the home itself and what starts with a dot are never suggested"
        );
        assert!(found("ls /home/user2/x", Some("/home/user2")).is_empty());
        assert_eq!(
            found("ls /home/u/x*", None),
            ["~/x"],
            "a wildcard ends the name"
        );
    }

    #[test]
    fn it_says_which_trusted_root_would_let_the_policy_answer_more() {
        let history = vec![
            past("ls").cwd("/home/u/wine").wait(40.0),
            past("cat a").cwd("/home/u/wine").wait(20.0),
            // a command is lacking first: not a matter of roots
            past("python3 x").cwd("/home/u/wine"),
            past("cat /home/u/awesome/x").wait(100.0),
            // trusting vault would still leave the file on the deny list
            past("cat /home/u/vault/.env"),
            // two roots are needed
            past("ls /home/u/a /home/u/b"),
            past("ls").cwd("/home/u/kms"),
        ];
        let r = report(&history);
        assert_eq!(r.allowed, 1);
        assert_eq!(r.roots.untrusted, 5);
        assert_eq!(r.roots.unlockable, 3);
        assert_eq!(r.roots.unlockable_wait_s, 160.0);
        let rows: Vec<(&str, usize, f64, &str)> = r
            .roots
            .rows
            .iter()
            .map(|u| (u.root.as_str(), u.requests, u.wait_s, u.example.as_str()))
            .collect();
        assert_eq!(
            rows,
            [
                ("~/awesome", 1, 100.0, "cat /home/u/awesome/x"),
                ("~/wine", 2, 60.0, "ls")
            ]
        );
    }

    #[test]
    fn percentiles_are_nearest_rank() {
        assert_eq!(nearest_rank(&[], 0.5), 0.0);
        assert_eq!(nearest_rank(&[7.0], 0.9), 7.0);
        let ten: Vec<f64> = (1..=10).map(f64::from).collect();
        assert_eq!(nearest_rank(&ten, 0.0), 1.0);
        assert_eq!(nearest_rank(&ten, 0.5), 5.0);
        assert_eq!(nearest_rank(&ten, 0.9), 9.0);
        assert_eq!(nearest_rank(&ten, 1.0), 10.0);
    }

    #[test]
    fn what_a_person_refused_must_never_be_allowed() {
        let history = vec![
            past("rm x").result("denied-interactively-by-user"),
            past("python3 y").result("cancelled"),
            past("ls src").result("denied-interactively-by-user"),
            past("cat a").result("cancelled"),
            past("ls ok"),
        ];
        let r = report(&history);
        let slips: Vec<(&str, &str)> = r
            .slips
            .iter()
            .map(|s| (s.result.as_str(), s.command.as_str()))
            .collect();
        assert_eq!(
            slips,
            [
                ("denied-interactively-by-user", "ls src"),
                ("cancelled", "cat a")
            ]
        );
        let text = render(&r, &Header::default(), 10);
        assert!(text.contains("PROBLEM: must be 0"), "{text}");

        let clean = report(&[past("rm x").result("cancelled"), past("ls")]);
        assert!(clean.slips.is_empty());
        let text = render(&clean, &Header::default(), 10);
        assert!(!text.contains("PROBLEM"), "{text}");
        assert!(text.contains("0 of 1 would have been allowed"), "{text}");
    }

    #[test]
    fn requests_nobody_was_there_to_answer_are_counted_apart() {
        let history = vec![
            past("ls a").result(UNATTENDED),
            past("python3 b").result(UNATTENDED),
            past("ls c"),
        ];
        let r = report(&history);
        assert_eq!(
            r.unattended,
            Split {
                requests: 2,
                allowed: 1
            }
        );
        assert!(r.slips.is_empty());
    }

    #[test]
    fn allowed_commands_that_the_oracle_distrusts_are_listed() {
        let history = vec![
            past("ls src"),
            past("cat server.pem"),
            past("cat server.pem"),
            past("ls $HOME"),
        ];
        let r = report(&history);
        let listed: Vec<(&str, usize)> = r
            .flagged
            .iter()
            .map(|f| (f.command.as_str(), f.requests))
            .collect();
        assert_eq!(listed, [("cat server.pem", 2), ("ls $HOME", 1)]);
        let flags = |i: usize| r.flagged[i].flags.join(",");
        assert!(flags(0).contains("secret:"), "{}", flags(0));
        assert!(flags(1).contains("expansion"), "{}", flags(1));
    }

    #[test]
    fn it_groups_allowed_requests_by_what_the_cli_called_not_read_only() {
        let history = vec![
            past("ls a").not_read_only(&["ls"]),
            past("ls a").not_read_only(&["ls"]),
            past("ls ab").not_read_only(&["ls"]),
            past("ls zz").not_read_only(&["ls", "ls"]),
            past("cat x").not_read_only(&["cat", "x"]),
            past("python3 x").not_read_only(&["python3"]),
        ];
        let r = report(&history);
        let rows: Vec<(&str, usize, usize, &str)> = r
            .disagreements
            .iter()
            .map(|d| {
                (
                    d.identifier.as_str(),
                    d.requests,
                    d.distinct,
                    d.example.as_str(),
                )
            })
            .collect();
        assert_eq!(
            rows,
            [
                ("ls", 4, 3, "ls a"),
                ("cat", 1, 1, "cat x"),
                ("x", 1, 1, "cat x")
            ]
        );
    }

    #[test]
    fn it_lists_what_the_policy_allows_that_the_cli_asked_about_as_a_path() {
        let history = vec![
            past("git status").path_prompt(&["/var", "/etc"]),
            past("git status").path_prompt(&["/etc"]),
            past("python3 x").path_prompt(&["/x"]),
            past("ls src"),
        ];
        let r = report(&history);
        assert_eq!(
            r.widened,
            [Widened {
                command: "git status".to_owned(),
                requests: 2,
                paths: vec!["/etc".to_owned(), "/var".to_owned()],
            }]
        );
    }

    fn steps(r: &Report) -> Vec<(&str, usize, usize)> {
        r.what_if
            .steps
            .iter()
            .map(|s| (s.command.as_str(), s.gained, s.cumulative))
            .collect()
    }

    #[test]
    fn the_what_if_adds_what_unlocks_most_first_and_counts_what_is_left() {
        let mut history = Vec::new();
        history.extend(repeat_n(past("a"), 1));
        history.extend(repeat_n(past("a | b"), 3));
        history.extend(repeat_n(past("b"), 2));
        history.extend(repeat_n(past("c | ls"), 4));
        // lacks x, and then still has something in the way
        history.extend(repeat_n(past("x | y ; z"), 6));
        history.extend(repeat_n(past("ls"), 5));
        let r = report(&history);
        assert_eq!(r.allowed, 5);
        assert_eq!((r.what_if.unlockable, r.what_if.stuck), (10, 6));
        // `b` is worth 2 on its own, and then `a` is worth 4: it was not
        // worth 4 until `b` was there
        assert_eq!(steps(&r), [("c", 4, 4), ("b", 2, 6), ("a", 4, 10)]);
        assert_eq!(r.what_if.steps[0].gained_wait_s, 40.0);
    }

    #[test]
    fn a_command_that_unlocks_nothing_alone_is_added_when_most_of_what_is_left_needs_it() {
        let mut history = Vec::new();
        history.extend(repeat_n(past("a | b"), 3));
        history.extend(repeat_n(past("a | c"), 1));
        let r = report(&history);
        assert_eq!(steps(&r), [("a", 0, 0), ("b", 3, 3), ("c", 1, 4)]);
    }

    #[test]
    fn the_wait_a_new_command_would_save_is_capped_per_request() {
        let history = vec![
            past("c").wait(4000.0),
            past("c").wait(50.0),
            past("c").unanswered(),
        ];
        let r = report(&history);
        assert_eq!(steps(&r), [("c", 3, 3)]);
        assert_eq!(r.what_if.steps[0].gained_wait_s, 350.0);
    }

    #[test]
    fn a_line_that_lacks_too_many_commands_is_not_followed() {
        let names = |count: usize| {
            (1..=count)
                .map(|i| format!("c{i}"))
                .collect::<Vec<_>>()
                .join(" | ")
        };
        let r = report(&[past(&names(MAX_LACKS)), past(&names(MAX_LACKS + 1))]);
        assert_eq!((r.what_if.unlockable, r.what_if.stuck), (1, 1));
    }

    #[test]
    fn the_what_if_does_not_depend_on_the_order_of_the_history() {
        let mut history = Vec::new();
        for (i, command) in [
            "a | b", "b | c", "c | d", "d | e", "e | a", "f", "f | g", "g",
        ]
        .into_iter()
        .enumerate()
        {
            history.extend(repeat_n(past(command), i % 3 + 1));
        }
        let forward = report(&history);
        assert!(!forward.what_if.steps.is_empty());
        // every analysis has its own hash seed, so its own map order
        for _ in 0..25 {
            assert_eq!(report(&history).what_if, forward.what_if);
        }
        history.reverse();
        assert_eq!(report(&history).what_if, forward.what_if);
    }

    #[test]
    fn the_numbers_are_printed_for_people() {
        assert_eq!(n(0), "0");
        assert_eq!(n(999), "999");
        assert_eq!(n(1000), "1,000");
        assert_eq!(n(1_234_567), "1,234,567");
        assert_eq!(pct(1, 3), "33.3%");
        assert_eq!(pct(0, 0), "-");
        assert_eq!(secs(5.0), "5 s");
        assert_eq!(secs(120.0), "2.0 min");
        assert_eq!(secs(7200.0), "2.0 h");
        assert_eq!(clip("a\nb", 10), "a⏎b");
        assert_eq!(clip("abcdef", 3), "abc…");
        assert_eq!(clip("abc", 3), "abc");
    }

    #[test]
    fn the_report_says_what_it_found() {
        let history = vec![
            past("ls src"),
            past("ls src").result("approved-for-location"),
            past("cat a.txt | git log"),
            past("python3 x.py"),
            past("rm -rf x").result("denied-interactively-by-user"),
            past("ls ; rm x"),
            past("git status").path_prompt(&["/etc"]),
        ];
        let head = Header {
            policy: "v1:abcd1234".to_owned(),
            mode: "shadow".to_owned(),
            home: "/home/u".to_owned(),
            roots: vec!["/home/u/kms".to_owned()],
        };
        let text = render(&report(&history), &head, 10);
        for want in [
            "7 shell permission requests, 2023-11-14 .. 2023-11-14",
            "policy v1:abcd1234, mode shadow, home /home/u",
            "trusted roots /home/u/kms",
            "1. WHAT WAS ASKED",
            "2. WHAT THE POLICY WOULD HAVE ANSWERED",
            "allowed      4 of 7 requests (57.1%), 3 distinct commands",
            "commands 3 of 6 (50.0%), path 1 of 1 (100.0%)",
            "allow:ls",
            "3. WAITING",
            "answered in",
            "under 1 s",
            "4. SAFETY CHECKS",
            "denied-interactively-by-user",
            "0 of 1 would have been allowed   ok",
            "5. WHY THE REST PASSED",
            "cmd-not-allowed",
            "6. WHAT IF A COMMAND WERE ALLOWED",
            "python3",
            "7. WHAT IF A DIRECTORY WERE A TRUSTED ROOT",
            "in a directory that is still there: 4 of 7 (57.1%)",
        ] {
            assert!(text.contains(want), "{want:?} is not in\n{text}");
        }
    }

    #[test]
    fn an_empty_history_is_a_report_too() {
        let r = report(&[]);
        assert_eq!((r.requests, r.allowed), (0, 0));
        let text = render(&r, &Header::default(), 10);
        assert!(text.contains("0 shell permission requests, none"), "{text}");
    }
}
