//! `ctx-hook`: the Copilot CLI's permission hook and the tools around it.

use std::path::PathBuf;
use std::process::ExitCode;

use clap::{Parser, Subcommand};
use ctx_hook::{bench, hook, replay, review, vars::Vars};

#[derive(Parser)]
#[command(name = "ctx-hook", version, about)]
struct Cli {
    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// The permissionRequest hook: reads the request on stdin, logs what the
    /// policy decides to hook_audit and, in enforce mode only, approves what it
    /// allows. Always exits 0.
    Permission,
    /// What the policy decides about one command (exit status 0 = allow,
    /// 1 = pass to the normal prompt).
    Explain {
        /// The shell command, as the CLI would run it
        command: String,
        /// The directory it would run in [default: the current one]
        #[arg(long)]
        cwd: Option<PathBuf>,
    },
    /// The policy against every shell command the CLI ever asked a person
    /// about (from the events the ingester stored): what it would have
    /// answered, how long that waited, what it would have got wrong, and what
    /// stands in the way of the rest.
    Replay {
        /// Only requests asked on or after this day (UTC, YYYY-MM-DD)
        #[arg(long)]
        since: Option<chrono::NaiveDate>,
        /// Only the most recent N requests
        #[arg(long)]
        limit: Option<i64>,
        /// Rows to print in each table
        #[arg(long, default_value_t = 15)]
        top: usize,
    },
    /// What the hook has been doing: the rows of hook_audit (the spool is
    /// imported first) against what the CLI logged about the same requests,
    /// and whether the log supports enabling the hook (PLAN.md §5, P3).
    Review {
        /// Only rows on or after this day (local time, YYYY-MM-DD)
        #[arg(long)]
        since: Option<chrono::NaiveDate>,
        /// Rows to print in each table
        #[arg(long, default_value_t = 15)]
        top: usize,
    },
    /// How long the hook takes, as the CLI sees it (this binary run as a
    /// hook, against the real configuration and database; its rows are
    /// deleted afterwards): the 95th percentile has to be under 50 ms.
    Bench {
        /// Hook runs to time
        #[arg(long, default_value_t = 200)]
        runs: usize,
        /// Runs before the timed ones, to warm the caches
        #[arg(long, default_value_t = 10)]
        warmup: usize,
    },
}

fn main() -> ExitCode {
    // Exit status 2 means "deny" to the CLI, and it is what clap exits with
    // after a usage error: the hook never goes through clap
    if std::env::args_os()
        .nth(1)
        .is_some_and(|arg| arg == "permission")
    {
        hook::permission();
    }
    match Cli::parse().command {
        Command::Permission => hook::permission(),
        Command::Explain { command, cwd } => explain(&command, cwd),
        Command::Replay { since, limit, top } => {
            let options = replay::Options { since, limit, top };
            report("replay", replay::run(&options))
        }
        Command::Review { since, top } => {
            let options = review::Options { since, top };
            report("review", review::run(&options))
        }
        Command::Bench { runs, warmup } => {
            let options = bench::Options { runs, warmup };
            report("bench", bench::run(&options))
        }
    }
}

fn report(name: &str, result: anyhow::Result<String>) -> ExitCode {
    match result {
        Ok(text) => {
            print!("{text}");
            ExitCode::SUCCESS
        }
        Err(error) => {
            eprintln!("ctx-hook {name}: {error:#}");
            ExitCode::from(1)
        }
    }
}

fn explain(command: &str, cwd: Option<PathBuf>) -> ExitCode {
    let vars = Vars::Process;
    let Some(home) = vars.get("HOME").map(PathBuf::from) else {
        eprintln!("ctx-hook: HOME is not set");
        return ExitCode::from(2);
    };
    let cwd = cwd.or_else(|| std::env::current_dir().ok());
    let e = hook::explain(command, cwd.as_deref(), &vars, &home);
    println!("command  {command}");
    if let Some(cwd) = &e.cwd {
        println!("cwd      {}", cwd.display());
    }
    println!("mode     {}", e.mode.as_str());
    println!("policy   {}", e.policy);
    if let Some(error) = &e.config_error {
        println!("config   {error}");
    }
    println!("verdict  {}", e.verdict.rule());
    for (i, root) in e.roots.iter().enumerate() {
        println!("{:<9}{}", if i == 0 { "roots" } else { "" }, root.display());
    }
    if e.verdict.is_allow() {
        ExitCode::SUCCESS
    } else {
        ExitCode::from(1)
    }
}
