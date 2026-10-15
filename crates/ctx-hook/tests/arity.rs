//! The option table says which flags take a value. That claim decides whether
//! the next word is skipped by the path checks, so it is checked here against
//! the real tools: `FLAG VALUE OPERAND` must behave exactly like the attached
//! form (`--flag=VALUE`, `-fVALUE`), which no tool can misread. If the tool did
//! not take `VALUE`, it would complain about it as a file as well, and the two
//! outputs would differ.
//!
//! Only flags that claim a value need this. A flag wrongly believed to take no
//! value just leaves its value to be checked as an operand, which is stricter.

use ctx_hook::cmds;
use ctx_hook::git;
use ctx_hook::opts::{Arity, Spec, Val, v};
use std::fs;
use std::path::Path;
use std::process::{Command, Stdio};
use tempfile::TempDir;

const OPERAND: &str = "ctx-arity-operand-zzz";
const PATTERN: &str = "ctx-arity-pattern-zzz";

struct Tool {
    bin: &'static str,
    /// the git subcommand
    prefix: Vec<&'static str>,
    spec: &'static Spec,
    /// the first operand, which is not a file: grep's pattern, jq's filter
    lead: Option<&'static str>,
    /// `--flag=VALUE` and `-fVALUE` exist; jq has neither
    attached: bool,
}

fn tool(bin: &'static str, spec: &'static Spec) -> Tool {
    Tool {
        bin,
        prefix: Vec::new(),
        spec,
        lead: None,
        attached: true,
    }
}

fn sample(bin: &str, flag: &str, val: Val) -> String {
    match (bin, flag, val) {
        ("rg", "-t" | "--type" | "-T" | "--type-not", _) => "rust".into(),
        ("git", "-L", _) => "1,2".into(),
        (_, _, Val::Num | Val::Count | Val::Key) => "1".into(),
        (_, _, Val::Name) => "n".into(),
        (_, _, Val::Char) => ",".into(),
        (_, _, Val::Enum(set)) => set[0].into(),
        (_, _, Val::Text) => "x".into(),
    }
}

type Output = (Option<i32>, String, String);

/// `None` when the tool is not installed.
fn run(bin: &str, args: &[String], cwd: &Path) -> Option<Output> {
    let out = Command::new(bin)
        .args(args)
        .current_dir(cwd)
        .env_clear()
        .env("PATH", std::env::var("PATH").unwrap_or_default())
        .env("HOME", cwd)
        .env("LC_ALL", "C")
        .env("GIT_CONFIG_GLOBAL", "/dev/null")
        .env("GIT_CONFIG_SYSTEM", "/dev/null")
        .stdin(Stdio::null())
        .output()
        .ok()?;
    Some((
        out.status.code(),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    ))
}

fn args(parts: &[&str], rest: &[String]) -> Vec<String> {
    parts
        .iter()
        .map(|s| (*s).to_owned())
        .chain(rest.iter().cloned())
        .collect()
}

fn scratch_repo(dir: &Path) {
    for argv in [
        vec!["init", "-q"],
        vec![
            "-c",
            "user.name=t",
            "-c",
            "user.email=t@t",
            "commit",
            "-q",
            "--allow-empty",
            "-m",
            "x",
        ],
    ] {
        let argv: Vec<String> = argv.iter().map(|s| (*s).to_owned()).collect();
        let (code, _, err) = run("git", &argv, dir).expect("git is needed for this test");
        assert_eq!(code, Some(0), "git {argv:?}: {err}");
    }
}

/// What differs, if anything, between the separate and the reference form.
fn judge(tool: &Tool, flag: &str, val: &[String], dir: &Path) -> Result<(), String> {
    let mut separate = vec![flag.to_owned()];
    separate.extend(val.iter().cloned());
    let mut tail = Vec::new();
    // `-e PATTERN` supplies grep's pattern itself
    if let Some(lead) = tool.lead
        && !matches!(flag, "-e" | "--regexp")
    {
        tail.push(lead.to_owned());
    }
    tail.push(OPERAND.to_owned());

    let reference: Vec<String> = if tool.attached {
        let one = &val[0];
        vec![if flag.starts_with("--") {
            format!("{flag}={one}")
        } else {
            format!("{flag}{one}")
        }]
    } else {
        Vec::new()
    };
    let with = args(&tool.prefix, &[separate, tail.clone()].concat());
    let reference = args(&tool.prefix, &[reference, tail].concat());

    let Some(got) = run(tool.bin, &with, dir) else {
        return Ok(());
    };
    let want = run(tool.bin, &reference, dir).expect("same binary");
    if got != want {
        return Err(format!(
            "{} {with:?} acts differently from {reference:?}\n  separate: {got:?}\n  reference: {want:?}",
            tool.bin
        ));
    }
    let text = format!("{}{}", got.1, got.2);
    if !text.contains(OPERAND) {
        return Err(format!(
            "{} {with:?} never got as far as the operand, so the sample value proves nothing: {got:?}",
            tool.bin
        ));
    }
    Ok(())
}

#[test]
fn flags_that_claim_a_value_really_take_one() {
    let tmp = TempDir::new().unwrap();
    let plain = tmp.path().join("plain");
    let repo = tmp.path().join("repo");
    fs::create_dir_all(&plain).unwrap();
    fs::create_dir_all(&repo).unwrap();
    scratch_repo(&repo);

    let mut tools = vec![
        Tool {
            lead: Some(PATTERN),
            ..tool("grep", &cmds::GREP)
        },
        Tool {
            lead: Some(PATTERN),
            ..tool("rg", &cmds::RG)
        },
        tool("ls", &cmds::LS),
        tool("head", &cmds::HEAD),
        tool("tail", &cmds::TAIL),
        tool("wc", &cmds::WC),
        tool("sort", &cmds::SORT),
        tool("uniq", &cmds::UNIQ),
        tool("stat", &cmds::STAT),
        tool("du", &cmds::DU),
        Tool {
            lead: Some("."),
            attached: false,
            ..tool("jq", &cmds::JQ)
        },
    ];
    for (sub, spec) in git::specs() {
        tools.push(Tool {
            prefix: vec![sub],
            ..tool("git", spec)
        });
    }

    let mut tried = 0;
    let mut problems = Vec::new();
    for t in &tools {
        let dir = if t.bin == "git" { &repo } else { &plain };
        for flag in t.spec.flags {
            let values: Vec<String> = match flag.arity {
                Arity::Req(v) => vec![sample(t.bin, flag.name, v)],
                // jq: the second value of --arg/--argjson is JSON text
                Arity::Two(a, _) => vec![sample(t.bin, flag.name, a), "1".into()],
                Arity::None | Arity::Opt(_) => continue,
            };
            tried += 1;
            if let Err(why) = judge(t, flag.name, &values, dir) {
                problems.push(why);
            }
        }
    }
    assert!(
        tried > 60,
        "only {tried} flags were exercised; the tables changed shape?"
    );
    assert!(
        problems.is_empty(),
        "{} of {tried}:\n{}",
        problems.len(),
        problems.join("\n")
    );
}

/// The check above must be able to fail: flags that take no value, claimed to
/// take one, have to be noticed, and a true claim must not be.
#[test]
fn a_false_claim_is_noticed() {
    let tmp = TempDir::new().unwrap();
    let dir = tmp.path();
    let one = vec!["1".to_owned()];

    static LIES: Spec = Spec {
        numeric: false,
        flags: &[v("-l", Val::Num), v("-i", Val::Num)],
    };
    assert!(judge(&tool("ls", &LIES), "-l", &one, dir).is_err());
    let grep = Tool {
        lead: Some(PATTERN),
        ..tool("grep", &LIES)
    };
    assert!(judge(&grep, "-i", &one, dir).is_err());

    assert!(judge(&tool("head", &cmds::HEAD), "-n", &one, dir).is_ok());
    let jq = Tool {
        lead: Some("."),
        attached: false,
        ..tool("jq", &cmds::JQ)
    };
    assert!(judge(&jq, "--indent", &one, dir).is_ok());
    // jq takes no value after --seq, so `--seq 1` would eat the filter
    static JQ_LIE: Spec = Spec {
        numeric: false,
        flags: &[v("--seq", Val::Num)],
    };
    let jq_lie = Tool {
        lead: Some("."),
        attached: false,
        ..tool("jq", &JQ_LIE)
    };
    assert!(judge(&jq_lie, "--seq", &one, dir).is_err());
}
