//! Read-only git (PLAN.md §6.6).
//!
//! Reading history is what makes git worth allowing, and also where the sharp
//! edges are, all of which were checked against git 2.47 and shape the rules:
//!
//!  * `git diff A B` with two paths outside the work tree silently becomes
//!    `--no-index` and reads arbitrary files, also with `../` paths. So every
//!    word that could be a path must be relative, free of `..` components and
//!    not produced by a tilde, and `--no-index` is not allowed.
//!  * `-c`, `--exec-path`, `--git-dir`, `--work-tree`, `--output`, `--ext-diff`,
//!    `-O` and the like run programs, redirect git or write files, so only the
//!    flags listed below exist.
//!  * Config and attributes of the repository itself (`core.fsmonitor`,
//!    `diff.<driver>.textconv`) can run programs, so the work tree has to lie
//!    inside a trusted root, and `GIT_*` variables that redirect git are refused.

use crate::cmds::Env;
use crate::opts::{Flag, Parsed, Spec, Val, f, o, parse, reject, v};
use crate::shell::{Cmd, Reject, Res, Word};
use crate::trust::Trust;
use crate::vars::Vars;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

/// Variables that point git elsewhere or make it run something. `GIT_CONFIG_COUNT`
/// is handled apart, because the Copilot CLI sets it itself.
const GIT_ENV: &[&str] = &[
    "GIT_DIR",
    "GIT_WORK_TREE",
    "GIT_INDEX_FILE",
    "GIT_OBJECT_DIRECTORY",
    "GIT_ALTERNATE_OBJECT_DIRECTORIES",
    "GIT_EXTERNAL_DIFF",
    "GIT_PAGER",
    "GIT_CONFIG",
    "GIT_CONFIG_GLOBAL",
    "GIT_CONFIG_SYSTEM",
    "GIT_CONFIG_PARAMETERS",
    "GIT_EXEC_PATH",
    "GIT_NAMESPACE",
];

/// The settings the Copilot CLI itself exports to every shell it starts
/// (`GIT_CONFIG_COUNT=3`, observed on 1.0.95): they only make git safer.
const CONFIG_OK: &[(&str, &str)] = &[
    ("safe.bareRepository", "explicit"),
    ("credential.interactive", "never"),
    ("core.fsmonitor", "false"),
];

fn env_ok(vars: &Vars) -> Res<()> {
    if let Some(name) = GIT_ENV.iter().find(|n| vars.is_set(n)) {
        return Err(reject("env-git", name));
    }
    let Some(count) = vars.get("GIT_CONFIG_COUNT") else {
        return Ok(());
    };
    let n: usize = count.parse().map_err(|_| Reject::new("env-git-config"))?;
    for i in 0..n.min(64) {
        let key = vars.get(&format!("GIT_CONFIG_KEY_{i}"));
        let value = vars.get(&format!("GIT_CONFIG_VALUE_{i}"));
        match (key.as_deref(), value.as_deref()) {
            (Some(k), Some(val)) if CONFIG_OK.contains(&(k, val)) => {}
            _ => return Err(Reject::new("env-git-config")),
        }
    }
    if n > 64 {
        return Err(Reject::new("env-git-config"));
    }
    Ok(())
}

const WHEN: Val = Val::Enum(&["always", "never", "auto"]);

fn concat(parts: &[&[Flag]]) -> &'static [Flag] {
    Box::leak(
        parts
            .iter()
            .flat_map(|p| p.iter().copied())
            .collect::<Vec<_>>()
            .into_boxed_slice(),
    )
}

/// What `git diff`, `git log -p` and `git show` share. A value that can only be
/// attached (`--stat=80`) is listed with `o`, so the next word is never taken
/// for it and stays an operand to be checked.
const DIFF: &[Flag] = &[
    f("-p"),
    f("--patch"),
    f("-u"),
    f("-s"),
    f("--no-patch"),
    f("--raw"),
    o("--stat", Val::Text),
    f("--shortstat"),
    f("--numstat"),
    o("--dirstat", Val::Text),
    f("--summary"),
    f("--patch-with-stat"),
    f("--name-only"),
    f("--name-status"),
    f("--check"),
    o("--color", WHEN),
    f("--no-color"),
    o("--color-words", Val::Text),
    o(
        "--word-diff",
        Val::Enum(&["color", "plain", "porcelain", "none"]),
    ),
    f("--no-renames"),
    o("--find-renames", Val::Text),
    o("-M", Val::Text),
    o("--find-copies", Val::Text),
    o("-C", Val::Text),
    f("--find-copies-harder"),
    f("--minimal"),
    f("--patience"),
    f("--histogram"),
    o(
        "--diff-algorithm",
        Val::Enum(&["default", "myers", "minimal", "patience", "histogram"]),
    ),
    f("-w"),
    f("--ignore-all-space"),
    f("-b"),
    f("--ignore-space-change"),
    f("--ignore-space-at-eol"),
    f("--ignore-cr-at-eol"),
    f("--ignore-blank-lines"),
    f("-a"),
    f("--text"),
    f("--binary"),
    f("--full-index"),
    o("--abbrev", Val::Num),
    f("-R"),
    f("-W"),
    f("--function-context"),
    o("--diff-filter", Val::Text),
    f("--exit-code"),
    f("--quiet"),
    f("-z"),
    f("--no-ext-diff"),
    f("--no-textconv"),
    o(
        "--ignore-submodules",
        Val::Enum(&["none", "untracked", "dirty", "all"]),
    ),
    f("--no-prefix"),
    f("--compact-summary"),
    f("--relative"),
    o("-U", Val::Num),
    o("--unified", Val::Num),
];

/// What `git log` and `git show` share.
const HISTORY: &[Flag] = &[
    f("--oneline"),
    f("--graph"),
    f("--all"),
    o("--decorate", Val::Enum(&["short", "full", "auto", "no"])),
    f("--no-decorate"),
    f("--abbrev-commit"),
    f("--no-abbrev-commit"),
    o("--date", Val::Text),
    f("--no-merges"),
    f("--merges"),
    f("--first-parent"),
    f("--reverse"),
    f("--topo-order"),
    f("--date-order"),
    f("--author-date-order"),
    f("--left-right"),
    f("--cherry-pick"),
    f("--cherry-mark"),
    f("--boundary"),
    f("--parents"),
    f("--children"),
    f("--simplify-by-decoration"),
    f("--full-history"),
    f("--sparse"),
    f("--dense"),
    o("--branches", Val::Text),
    o("--tags", Val::Text),
    o("--remotes", Val::Text),
    f("--invert-grep"),
    f("--all-match"),
    f("-i"),
    f("--regexp-ignore-case"),
    f("-E"),
    f("--extended-regexp"),
    f("-F"),
    f("--fixed-strings"),
    f("-P"),
    f("--perl-regexp"),
    o("--author", Val::Text),
    o("--committer", Val::Text),
    o("--grep", Val::Text),
    o("--since", Val::Text),
    o("--until", Val::Text),
    o("--after", Val::Text),
    o("--before", Val::Text),
    o("--max-count", Val::Num),
    o("--skip", Val::Num),
    v("-n", Val::Num),
    o("--format", Val::Text),
    o("--pretty", Val::Text),
    v("-S", Val::Text),
    v("-G", Val::Text),
    f("--pickaxe-regex"),
    f("--pickaxe-all"),
    f("-m"),
    f("-c"),
    f("--cc"),
    f("--no-notes"),
    f("--follow"),
];

pub static LOG: LazyLock<Spec> = LazyLock::new(|| Spec {
    numeric: true,
    flags: concat(&[DIFF, HISTORY]),
});

pub static SHOW: LazyLock<Spec> = LazyLock::new(|| Spec {
    numeric: false,
    flags: concat(&[DIFF, HISTORY]),
});

pub static DIFF_SPEC: LazyLock<Spec> = LazyLock::new(|| Spec {
    numeric: false,
    flags: concat(&[DIFF, &[f("--cached"), f("--staged"), f("--merge-base")]]),
});

pub static STATUS: Spec = Spec {
    numeric: false,
    flags: &[
        f("-s"),
        f("--short"),
        f("-b"),
        f("--branch"),
        o("--porcelain", Val::Enum(&["v1", "v2", "1", "2"])),
        f("--long"),
        f("-z"),
        o("-u", Val::Enum(&["no", "normal", "all"])),
        o("--untracked-files", Val::Enum(&["no", "normal", "all"])),
        o("--ignored", Val::Enum(&["traditional", "no", "matching"])),
        o(
            "--ignore-submodules",
            Val::Enum(&["none", "untracked", "dirty", "all"]),
        ),
        f("--show-stash"),
        f("--ahead-behind"),
        f("--no-ahead-behind"),
        f("--renames"),
        f("--no-renames"),
        o("--column", Val::Text),
        f("--no-column"),
        f("-v"),
        f("--verbose"),
    ],
};

/// Listing only: nothing that creates, moves, copies, deletes or edits a branch.
pub static BRANCH: Spec = Spec {
    numeric: false,
    flags: &[
        f("-a"),
        f("--all"),
        f("-r"),
        f("--remotes"),
        f("-v"),
        f("--verbose"),
        f("--list"),
        f("--show-current"),
        f("--no-color"),
        o("--color", WHEN),
        o("--format", Val::Text),
        o("--sort", Val::Text),
        o("--column", Val::Text),
        f("--no-column"),
        o("--abbrev", Val::Num),
        f("--no-abbrev"),
        f("-i"),
        f("--ignore-case"),
    ],
};

pub static REV_PARSE: Spec = Spec {
    numeric: false,
    flags: &[
        f("--show-toplevel"),
        f("--is-inside-work-tree"),
        f("--is-bare-repository"),
        f("--is-inside-git-dir"),
        f("--show-prefix"),
        f("--show-cdup"),
        f("--git-dir"),
        f("--absolute-git-dir"),
        f("--git-common-dir"),
        f("--symbolic"),
        f("--symbolic-full-name"),
        f("--verify"),
        f("-q"),
        f("--quiet"),
        f("--branches"),
        f("--tags"),
        f("--remotes"),
        f("--all"),
        f("--revs-only"),
        f("--no-revs"),
        f("--flags"),
        f("--no-flags"),
        o("--abbrev-ref", Val::Enum(&["strict", "loose"])),
        o("--short", Val::Num),
        f("--show-superproject-working-tree"),
    ],
};

/// No `-X`/`--exclude-from` and `--exclude-per-directory`, which read files.
pub static LS_FILES: Spec = Spec {
    numeric: false,
    flags: &[
        f("-c"),
        f("--cached"),
        f("-d"),
        f("--deleted"),
        f("-m"),
        f("--modified"),
        f("-o"),
        f("--others"),
        f("-i"),
        f("--ignored"),
        f("-s"),
        f("--stage"),
        f("-u"),
        f("--unmerged"),
        f("-k"),
        f("--killed"),
        f("-z"),
        f("-t"),
        f("-v"),
        f("-f"),
        f("--exclude-standard"),
        f("--full-name"),
        f("--error-unmatch"),
        f("--deduplicate"),
        f("--eol"),
        f("--directory"),
        f("--no-empty-directory"),
        o("--exclude", Val::Text),
    ],
};

/// No `--contents`, `--ignore-revs-file` and `-S`, which read other files.
pub static BLAME: Spec = Spec {
    numeric: false,
    flags: &[
        v("-L", Val::Text),
        f("-w"),
        o("-M", Val::Text),
        o("-C", Val::Text),
        f("-e"),
        f("--show-email"),
        f("-p"),
        f("--porcelain"),
        f("--line-porcelain"),
        f("-s"),
        f("-l"),
        f("-t"),
        f("-f"),
        f("--show-name"),
        f("-n"),
        f("--show-number"),
        o("--date", Val::Text),
        o("--abbrev", Val::Num),
        f("--root"),
        f("--first-parent"),
    ],
};

pub static DESCRIBE: Spec = Spec {
    numeric: false,
    flags: &[
        f("--tags"),
        f("--all"),
        f("--long"),
        f("--always"),
        f("--first-parent"),
        f("--exact-match"),
        o("--dirty", Val::Text),
        o("--broken", Val::Text),
        o("--abbrev", Val::Num),
        o("--candidates", Val::Num),
        o("--match", Val::Text),
        o("--exclude", Val::Text),
        f("--contains"),
    ],
};

/// Subcommand name and its flags, for the arity test.
pub fn specs() -> Vec<(&'static str, &'static Spec)> {
    vec![
        ("log", &LOG),
        ("show", &SHOW),
        ("diff", &DIFF_SPEC),
        ("status", &STATUS),
        ("branch", &BRANCH),
        ("rev-parse", &REV_PARSE),
        ("ls-files", &LS_FILES),
        ("blame", &BLAME),
        ("describe", &DESCRIBE),
    ]
}

/// A revision or a path, which git cannot tell apart before looking.
fn word(env: &Env, w: &Word) -> Res<()> {
    let t = w.text.as_str();
    if w.glob {
        return Err(Reject::new("git-glob"));
    }
    if w.tilde {
        return Err(Reject::new("git-tilde"));
    }
    if t.is_empty() || t.len() > 256 {
        return Err(Reject::new("git-word-length"));
    }
    if !t
        .chars()
        .all(|c| c.is_ascii_alphanumeric() || "_./@^~:+=,{}-".contains(c))
    {
        return Err(reject("git-chars", t));
    }
    if t.starts_with(['/', ':']) {
        return Err(reject("git-word-start", t));
    }
    // `rev:path` names a file in a commit
    let path = t.split_once(':').map_or(t, |(_, p)| p);
    if path.starts_with('/') {
        return Err(reject("git-rev-abs", t));
    }
    if [t, path].iter().any(|s| s.split('/').any(|c| c == "..")) {
        return Err(reject("git-dotdot", t));
    }
    if env.trust.is_denied(Path::new(path)) {
        return Err(Reject::new("path-denied"));
    }
    Ok(())
}

fn words(env: &Env, ws: &[&Word]) -> Res<()> {
    ws.iter().try_for_each(|w| word(env, w))
}

/// Subcommand name, as it appears in the audit rule.
fn tag(sub: &str) -> Option<&'static str> {
    Some(match sub {
        "log" => "git-log",
        "show" => "git-show",
        "diff" => "git-diff",
        "status" => "git-status",
        "branch" => "git-branch",
        "rev-parse" => "git-rev-parse",
        "ls-files" => "git-ls-files",
        "blame" => "git-blame",
        "describe" => "git-describe",
        _ => return None,
    })
}

pub fn check(cmd: &Cmd, env: &Env) -> Res<&'static str> {
    env_ok(env.vars)?;
    let args = &cmd.args;
    let mut at = 0;
    let mut dir: Option<PathBuf> = None;
    while let Some(w) = args.get(at) {
        let t = w.text.as_str();
        match t {
            "--no-pager" | "-P" | "--no-optional-locks" => at += 1,
            "-C" => {
                if dir.is_some() {
                    return Err(Reject::new("git-multiple-C"));
                }
                let target = args
                    .get(at + 1)
                    .ok_or_else(|| Reject::new("git-C-missing"))?;
                if target.glob {
                    return Err(Reject::new("glob-in-value"));
                }
                dir = Some(env.trust.check_dir(&target.text, env.cwd)?);
                at += 2;
            }
            _ if t.starts_with('-') => return Err(reject("git-global-flag", t)),
            _ => break,
        }
    }
    let sub = args
        .get(at)
        .ok_or_else(|| Reject::new("git-no-subcommand"))?;
    let name = tag(&sub.text).ok_or_else(|| reject("git-subcommand", &sub.text))?;
    let rest = &args[at + 1..];

    let run_in = match dir.as_deref().or(env.cwd) {
        Some(d) => d.to_path_buf(),
        None => return Err(Reject::new("no-cwd")),
    };
    let top = Trust::repo_top(&run_in).ok_or_else(|| Reject::new("git-no-repo"))?;
    env.trust.check_dir(".", Some(&run_in))?;
    if !env.trust.is_trusted(&top) {
        return Err(Reject::new("git-repo-untrusted"));
    }

    match name {
        "git-log" => positional(env, &parse(rest, &LOG)?),
        "git-show" => positional(env, &parse(rest, &SHOW)?),
        "git-diff" => positional(env, &parse(rest, &DIFF_SPEC)?),
        "git-status" => positional(env, &parse(rest, &STATUS)?),
        "git-ls-files" => positional(env, &parse(rest, &LS_FILES)?),
        "git-describe" => positional(env, &parse(rest, &DESCRIBE)?),
        "git-blame" => {
            let p = parse(rest, &BLAME)?;
            if p.pos.len() > 2 {
                return Err(Reject::new("git-blame-operands"));
            }
            positional(env, &p)
        }
        "git-rev-parse" => {
            let p = parse(rest, &REV_PARSE)?;
            if p.split.is_some() {
                return Err(Reject::new("git-rev-parse-dashdash"));
            }
            positional(env, &p)
        }
        "git-branch" => {
            // a bare name would create a branch
            let p = parse(rest, &BRANCH)?;
            if !p.pos.is_empty() && !p.has("--list") {
                return Err(Reject::new("git-branch-create"));
            }
            positional(env, &p)
        }
        _ => unreachable!("tag() and this match list the same subcommands"),
    }?;
    Ok(name)
}

fn positional(env: &Env, p: &Parsed) -> Res<()> {
    words(env, &p.pos)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn every_subcommand_has_a_spec_and_a_tag() {
        for (name, spec) in specs() {
            assert!(tag(name).is_some(), "{name}");
            assert!(!spec.flags.is_empty(), "{name}");
        }
        assert_eq!(specs().len(), 9);
    }

    #[test]
    fn dangerous_flags_are_absent() {
        for (name, spec) in specs() {
            for bad in [
                "--no-index",
                "--output",
                "--ext-diff",
                "-O",
                "--paginate",
                "--exec-path",
                "--git-dir",
                "--work-tree",
                "--contents",
                "--open-files-in-pager",
                "-c",
                "-d",
                "-D",
                "-m",
            ] {
                if bad == "-c" && matches!(name, "log" | "show" | "ls-files") {
                    continue; // `-c` is a combined-diff / cached flag there
                }
                if bad == "-m" && matches!(name, "log" | "show" | "ls-files") {
                    continue; // `-m` is --diff-merges / --modified there
                }
                if bad == "-d" && name == "ls-files" {
                    continue; // --deleted
                }
                if bad == "--git-dir" && name == "rev-parse" {
                    continue; // only prints the directory; the global option redirects git
                }
                assert!(spec.find(bad).is_none(), "git {name} must not allow {bad}");
            }
        }
    }
}
