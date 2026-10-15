//! `ctx-report`: AIU spend and quality-guardrail reports (PLAN §6.8).

use std::process::ExitCode;

use anyhow::{Context, Result, bail};
use chrono::{DateTime, NaiveDate, Utc};
use clap::{Parser, Subcommand};
use ctx_core::config::Config;
use ctx_core::db;
use ctx_core::report::{
    self, BASELINE_AS_OF, GUARDRAIL_MIN_MESSAGES, GUARDRAIL_SINCE, GUARDRAIL_THRESHOLD, Reporter,
    Verdict,
};
use tracing_subscriber::EnvFilter;

#[derive(Parser)]
#[command(
    version,
    about = "AIU spend and quality-guardrail reports over the ctx database"
)]
struct Cli {
    /// PostgreSQL URL [default: $CTX_DATABASE_URL, $DATABASE_URL, the local socket]
    #[arg(long, global = true, value_name = "URL")]
    database_url: Option<String>,
    /// Report as the data stood at this moment (RFC 3339, e.g. 2026-10-09T11:30:00Z)
    /// [default: now; `baseline` defaults to the moment PLAN §2 was taken]
    #[arg(long, global = true, value_name = "TIMESTAMP")]
    as_of: Option<String>,
    /// Work in this schema instead of `public` (used by the integration tests)
    #[arg(long, global = true, hide = true)]
    schema: Option<String>,
    #[command(subcommand)]
    command: Cmd,
}

#[derive(Subcommand)]
enum Cmd {
    /// Every headline number of PLAN §2, and AIU by token type and initiator
    Summary,
    /// Spend, per-turn ratios and quality proxies by week
    Weekly {
        /// How many of the latest weeks to show
        #[arg(long, default_value_t = 12)]
        weeks: u32,
    },
    /// Compare the report with the numbers of PLAN §2 (exit 2 if an acceptance line misses)
    Baseline,
    /// Sessions by AIU
    Sessions {
        /// Only sessions above this many AIU
        #[arg(long, default_value_t = 1000.0)]
        min_aiu: f64,
        #[arg(long, default_value_t = 25)]
        limit: u32,
    },
    /// Calls and AIU per model
    Models,
    /// Quality proxies against the Jun–Oct baseline (exit 2 if one stayed >25% worse for 2 weeks)
    Guardrail {
        /// First week to look at (a Monday)
        #[arg(long, default_value = GUARDRAIL_SINCE, value_name = "YYYY-MM-DD")]
        since: String,
        /// Fraction worse than the baseline that counts as worse
        #[arg(long, default_value_t = GUARDRAIL_THRESHOLD)]
        threshold: f64,
        /// Weeks with fewer user messages are ignored
        #[arg(long, default_value_t = GUARDRAIL_MIN_MESSAGES)]
        min_messages: i64,
    },
}

fn parse_as_of(text: &str) -> Result<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(text)
        .map(|t| t.with_timezone(&Utc))
        .with_context(|| {
            format!("--as-of must be an RFC 3339 timestamp like {BASELINE_AS_OF}, got `{text}`")
        })
}

fn print_table(title: &str, table: &report::Table) {
    println!("\n{title}\n{}", table.render().trim_end());
}

async fn run() -> Result<ExitCode> {
    let cli = Cli::parse();
    let mut config = Config::from_env()?;
    if let Some(url) = cli.database_url {
        config.database_url = url;
    }
    let as_of = match (&cli.as_of, &cli.command) {
        (Some(text), _) => Some(parse_as_of(text)?),
        (None, Cmd::Baseline) => Some(parse_as_of(BASELINE_AS_OF)?),
        (None, _) => None,
    };
    let pool = db::connect(&config.database_url, "ctx-report", cli.schema.as_deref(), 2).await?;
    db::migrate(&pool).await?;
    let mut reporter = Reporter::new(&pool, as_of).await?;

    let header = |reporter_range: (Option<DateTime<Utc>>, Option<DateTime<Utc>>)| {
        let when = as_of.map_or_else(|| "now".to_owned(), |t| t.to_rfc3339());
        match reporter_range {
            (Some(first), Some(last)) => {
                format!(
                    "as of {when}; model calls {} to {}",
                    first.format("%Y-%m-%d"),
                    last.format("%Y-%m-%d")
                )
            }
            _ => format!("as of {when}; no model calls"),
        }
    };

    match cli.command {
        Cmd::Summary => {
            println!("{}", header(reporter.coverage().await?));
            print!("{}", report::render_summary(&reporter.summary().await?));
            let split = reporter
                .table(
                    "SELECT dim, value, calls, round(aiu::numeric, 1)::float8 AS aiu,
                            round(aiu_pct::numeric, 1)::float8 AS aiu_pct
                       FROM v_split ORDER BY dim DESC, aiu DESC",
                )
                .await?;
            print_table("AIU by token type and initiator", &split);
        }
        Cmd::Weekly { weeks } => {
            println!("{}", header(reporter.coverage().await?));
            let query = format!(
                "SELECT week, sessions, calls, round(aiu::numeric, 1)::float8 AS aiu, turns,
                        round(aiu_per_turn::numeric, 1)::float8 AS aiu_turn,
                        round(calls_per_turn::numeric, 1)::float8 AS calls_turn,
                        round((mean_prompt_tokens / 1000)::numeric, 0)::float8 AS prompt_k,
                        round(sub_aiu_per_call::numeric, 2)::float8 AS sub_aiu_call,
                        round(cold_aiu_pct::numeric, 1)::float8 AS cold_pct,
                        round(autopilot_aiu_pct::numeric, 1)::float8 AS auto_pct,
                        user_messages AS msgs,
                        round(aborts_per_100_msgs::numeric, 2)::float8 AS abort_100,
                        round(failures_per_100_turns::numeric, 2)::float8 AS fail_100,
                        round(task_completes_per_100_msgs::numeric, 1)::float8 AS done_100,
                        perm_waits_ge_300s AS perm_5m
                   FROM (SELECT * FROM v_weekly ORDER BY week DESC LIMIT {weeks}) w
                  ORDER BY week"
            );
            let table = reporter.table(&query).await?;
            println!("{}", table.render().trim_end());
            println!(
                "\nturns = main-agent turns; calls_turn = main-agent calls per turn; aiu_turn includes \
                 sub-agents;\ncold_pct/auto_pct = share of the week's AIU; abort/fail/done per 100 user \
                 messages or assistant turns;\nperm_5m = permission prompts that waited 5 min or more"
            );
        }
        Cmd::Baseline => {
            println!("PLAN §2 baseline, {}", header(reporter.coverage().await?));
            let checks = reporter.baseline().await?;
            println!("{}", report::checks_table(&checks).render().trim_end());
            let verdict = Verdict::of(&checks);
            println!(
                "\nacceptance (required) lines: {}/{} within tolerance; other §2 lines: {}/{} within tolerance",
                verdict.required - verdict.required_failed,
                verdict.required,
                verdict.info - verdict.info_differing,
                verdict.info,
            );
            if !verdict.ok() {
                eprintln!("FAILED: the report does not reproduce PLAN §2");
                return Ok(ExitCode::from(2));
            }
        }
        Cmd::Sessions { min_aiu, limit } => {
            if !min_aiu.is_finite() || min_aiu < 0.0 {
                bail!("--min-aiu must be a non-negative number");
            }
            println!("{}", header(reporter.coverage().await?));
            let query = format!(
                "SELECT left(session_id, 8) AS session, autopilot,
                        COALESCE(left(repository, 28), '-') AS repository, first_call, calls, turns,
                        round(aiu, 1)::float8 AS aiu,
                        round(100 * cold_aiu / NULLIF(aiu, 0), 1)::float8 AS cold_pct
                   FROM v_session WHERE aiu > {min_aiu} ORDER BY aiu DESC LIMIT {limit}"
            );
            let table = reporter.table(&query).await?;
            println!("{}", table.render().trim_end());
        }
        Cmd::Models => {
            println!("{}", header(reporter.coverage().await?));
            let table = reporter
                .table(
                    "SELECT model, CASE WHEN is_sub THEN 'sub-agent' ELSE 'main' END AS role, calls,
                            round(aiu::numeric, 1)::float8 AS aiu, round(aiu_pct::numeric, 1)::float8 AS aiu_pct,
                            round(aiu_per_call::numeric, 2)::float8 AS aiu_per_call,
                            round(mean_prompt_tokens::numeric, 0)::float8 AS mean_prompt
                       FROM v_model ORDER BY aiu DESC",
                )
                .await?;
            println!("{}", table.render().trim_end());
        }
        Cmd::Guardrail {
            since,
            threshold,
            min_messages,
        } => {
            let since = NaiveDate::parse_from_str(&since, "%Y-%m-%d")
                .with_context(|| format!("--since must look like 2026-10-12, got `{since}`"))?;
            let mut baseline_reporter =
                Reporter::new(&pool, Some(parse_as_of(BASELINE_AS_OF)?)).await?;
            let baseline = baseline_reporter.baseline_proxies().await?;
            let weeks = reporter.guard_weeks(since).await?;
            println!(
                "quality proxies from {since}, against the baseline up to {BASELINE_AS_OF}; \
                 `!` = more than {:.0}% worse in a week with at least {min_messages} user messages",
                100.0 * threshold
            );
            println!(
                "{}",
                report::guardrail_table(&baseline, &weeks, threshold, min_messages)
                    .render()
                    .trim_end()
            );
            let streaks = report::guardrail(&baseline, &weeks, threshold, min_messages);
            if streaks.is_empty() {
                println!("\nno proxy stayed worse for 2 consecutive weeks");
            } else {
                for s in &streaks {
                    println!(
                        "\nFLAG: {} worse for {} consecutive weeks ({} to {})",
                        s.proxy, s.weeks, s.from, s.to
                    );
                }
                return Ok(ExitCode::from(2));
            }
        }
    }
    Ok(ExitCode::SUCCESS)
}

#[tokio::main]
async fn main() -> ExitCode {
    tracing_subscriber::fmt()
        .with_env_filter(
            EnvFilter::try_from_default_env()
                .unwrap_or_else(|_| EnvFilter::new("warn,sqlx::query=error")),
        )
        .with_writer(std::io::stderr)
        .init();
    match run().await.context("ctx-report failed") {
        Ok(code) => code,
        Err(error) => {
            eprintln!("error: {error:#}");
            ExitCode::from(1)
        }
    }
}
