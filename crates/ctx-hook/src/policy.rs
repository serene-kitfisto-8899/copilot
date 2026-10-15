//! Decides whether a shell command may be approved without a prompt
//! (PLAN.md §6.6, D8).
//!
//! A command is allowed only when the analyzer understood every part of it,
//! every command in it is on the allow-list with only listed flags, every path
//! it can touch lies inside a trusted root and is not on the deny list, and
//! nothing in the way the commands are joined can make one of them run somewhere
//! other than where it was judged. Everything else passes: the hook says
//! nothing and the normal permission flow decides. There is no deny verdict.

use crate::cmds::{Env, lookup};
use crate::shell::{Cmd, Join, Reject, Res, analyze};
use crate::trust::Trust;
use crate::vars::Vars;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// The names of the commands involved, e.g. `cd+git-log+head`.
    Allow { tags: String },
    /// Why not: a reject code such as `cmd-not-allowed:python3`.
    Pass { code: String },
}

impl Verdict {
    pub fn is_allow(&self) -> bool {
        matches!(self, Verdict::Allow { .. })
    }

    /// As stored in `hook_audit.rule`: `allow:<tags>` or `pass:<code>`.
    pub fn rule(&self) -> String {
        match self {
            Verdict::Allow { tags } => format!("allow:{tags}"),
            Verdict::Pass { code } => format!("pass:{code}"),
        }
    }
}

pub fn evaluate(src: &str, cwd: Option<&Path>, home: &Path, trust: &Trust, vars: &Vars) -> Verdict {
    evaluate_assuming(src, cwd, home, trust, vars, &[])
}

/// As [`evaluate`], but as if the commands named in `assume` were on the
/// allow-list, whatever their arguments (tag `assumed`). The replay uses it to
/// see what adding a command would unlock; nothing that decides a real request
/// passes anything but an empty list, which is what [`evaluate`] does.
pub fn evaluate_assuming(
    src: &str,
    cwd: Option<&Path>,
    home: &Path,
    trust: &Trust,
    vars: &Vars,
    assume: &[&str],
) -> Verdict {
    match run(src, cwd, home, trust, vars, assume) {
        Ok(tags) => Verdict::Allow {
            tags: tags.join("+"),
        },
        Err(Reject(code)) => Verdict::Pass { code },
    }
}

fn run(
    src: &str,
    cwd: Option<&Path>,
    home: &Path,
    trust: &Trust,
    vars: &Vars,
    assume: &[&str],
) -> Res<Vec<&'static str>> {
    let script = analyze(src, home.to_str())?;
    if script.cmds.is_empty() {
        return Err(Reject::new("empty"));
    }
    // Option parsing changes: options after the first operand become operands
    if vars.is_set("POSIXLY_CORRECT") {
        return Err(Reject::new("env-posixly-correct"));
    }

    let has_cd = script.cmds.iter().any(|c| c.name == "cd");
    // `cd x || cmd` runs cmd in the old directory when the cd fails
    if has_cd && script.cmds.iter().any(|c| c.join == Join::Or) {
        return Err(Reject::new("cd-with-or"));
    }

    let mut cwd: Option<PathBuf> = cwd.and_then(|c| std::fs::canonicalize(c).ok());
    let mut tags: Vec<&'static str> = Vec::new();
    let mut after_cd = false;
    for (i, cmd) in script.cmds.iter().enumerate() {
        // Once a cd has happened, anything that could run when it failed would
        // run somewhere other than where it was judged: only `&&` and pipes
        // continue from it
        if after_cd && !matches!(cmd.join, Join::And | Join::Pipe) {
            return Err(Reject::new("cd-then-unconditional"));
        }
        let env = Env {
            trust,
            cwd: cwd.as_deref(),
            vars,
        };
        let tag = if cmd.name == "cd" {
            // each side of a pipe is a subshell, where a cd changes nothing
            let piped = cmd.join == Join::Pipe
                || script
                    .cmds
                    .get(i + 1)
                    .is_some_and(|next| next.join == Join::Pipe);
            if piped {
                return Err(Reject::new("cd-in-pipeline"));
            }
            cwd = Some(cd(cmd, &env)?);
            after_cd = true;
            "cd"
        } else if assume.contains(&cmd.name.as_str()) {
            "assumed"
        } else {
            let check = lookup(&cmd.name)
                .ok_or_else(|| Reject::new(format!("cmd-not-allowed:{}", cmd.name)))?;
            check(cmd, &env)?
        };
        if !tags.contains(&tag) {
            tags.push(tag);
        }
    }
    Ok(tags)
}

/// `cd DIR`, to a trusted directory and nothing fancier. A `..` is refused
/// because bash resolves it on the written path (through symlinks as written)
/// while the kernel resolves it on the real one, so the two could end up in
/// different places.
fn cd(cmd: &Cmd, env: &Env) -> Res<PathBuf> {
    let [target] = cmd.args.as_slice() else {
        return Err(Reject::new("cd-args"));
    };
    let text = target.text.as_str();
    if target.glob {
        return Err(Reject::new("glob-in-cd"));
    }
    if text.is_empty() || text.starts_with('-') {
        return Err(Reject::new("cd-flag"));
    }
    if text.split('/').any(|part| part == "..") {
        return Err(Reject::new("cd-dotdot"));
    }
    // CDPATH makes bash look elsewhere first for anything but these forms
    if env.vars.is_set("CDPATH")
        && !(text.starts_with('/') || text == "." || text.starts_with("./"))
    {
        return Err(Reject::new("env-cdpath"));
    }
    env.trust.check_dir(text, env.cwd)
}
