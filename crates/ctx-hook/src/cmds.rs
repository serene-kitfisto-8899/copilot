//! The allow-list: which commands may be approved without a prompt, with which
//! flags, and what their operands have to satisfy (PLAN.md §6.6, D8).
//!
//! The rule for every entry is that it can only read, only inside trusted
//! directories, and cannot run anything else or write anywhere. Whatever is not
//! spelled out here falls back to the normal prompt.

use crate::opts::{Flag, Parsed, Spec, Val, f, o, parse, reject, v, valid};
use crate::shell::{Cmd, Reject, Res, Word};
use crate::trust::Trust;
use crate::vars::Vars;
use std::path::Path;

pub struct Env<'a> {
    pub trust: &'a Trust,
    /// Where the command will run, canonical.
    pub cwd: Option<&'a Path>,
    pub vars: &'a Vars,
}

impl Env<'_> {
    /// One path operand, with a wildcard expanded the way the shell will.
    pub fn path(&self, w: &Word) -> Res<()> {
        if w.glob {
            for m in self.trust.expand_glob(&w.text, self.cwd)? {
                self.trust.check(&m, self.cwd)?;
            }
        } else {
            self.trust.check(&w.text, self.cwd)?;
        }
        Ok(())
    }

    pub fn operands(&self, words: &[&Word], dash_is_stdin: bool) -> Res<()> {
        for w in words {
            if dash_is_stdin && w.text == "-" {
                continue;
            }
            self.path(w)?;
        }
        Ok(())
    }

    /// For commands that fall back to the current directory.
    pub fn cwd_trusted(&self) -> Res<()> {
        self.trust.check(".", self.cwd).map(|_| ())
    }
}

/// Validates one command and names what it was, for the audit rule.
pub type Check = fn(&Cmd, &Env) -> Res<&'static str>;

pub fn lookup(name: &str) -> Option<Check> {
    Some(match name {
        "grep" => grep,
        "rg" => rg,
        "cat" => cat,
        "ls" => ls,
        "find" => find,
        "head" => head,
        "tail" => tail,
        "wc" => wc,
        "sort" => sort,
        "uniq" => uniq,
        "jq" => jq,
        "echo" => echo,
        "printf" => printf,
        "which" => which,
        "stat" => stat,
        "file" => file,
        "du" => du,
        "readlink" => readlink,
        "git" => crate::git::check,
        _ => return None,
    })
}

/// Every name `lookup` knows, plus `cd`, which the policy handles itself.
pub const ALLOWED: &[&str] = &[
    "cd", "grep", "rg", "cat", "ls", "find", "head", "tail", "wc", "sort", "uniq", "jq", "echo",
    "printf", "which", "stat", "file", "du", "readlink", "git",
];

/// `--color[=WHEN]` as GNU tools accept it.
const WHEN: Val = Val::Enum(&[
    "always", "yes", "force", "never", "no", "none", "auto", "tty", "if-tty",
]);

pub static GREP: Spec = Spec {
    numeric: true,
    flags: &[
        f("-E"),
        f("--extended-regexp"),
        f("-F"),
        f("--fixed-strings"),
        f("-G"),
        f("--basic-regexp"),
        f("-P"),
        f("--perl-regexp"),
        v("-e", Val::Text),
        v("--regexp", Val::Text),
        f("-i"),
        f("-y"),
        f("--ignore-case"),
        f("--no-ignore-case"),
        f("-w"),
        f("--word-regexp"),
        f("-x"),
        f("--line-regexp"),
        f("-z"),
        f("--null-data"),
        f("-s"),
        f("--no-messages"),
        f("-v"),
        f("--invert-match"),
        v("-m", Val::Num),
        v("--max-count", Val::Num),
        f("-b"),
        f("--byte-offset"),
        f("-n"),
        f("--line-number"),
        f("--line-buffered"),
        f("-H"),
        f("--with-filename"),
        f("-h"),
        f("--no-filename"),
        v("--label", Val::Text),
        f("-o"),
        f("--only-matching"),
        f("-q"),
        f("--quiet"),
        f("--silent"),
        v(
            "--binary-files",
            Val::Enum(&["binary", "text", "without-match"]),
        ),
        f("-a"),
        f("--text"),
        f("-I"),
        f("-r"),
        f("--recursive"),
        v("--include", Val::Text),
        v("--exclude", Val::Text),
        v("--exclude-dir", Val::Text),
        f("-L"),
        f("--files-without-match"),
        f("-l"),
        f("--files-with-matches"),
        f("-c"),
        f("--count"),
        f("-T"),
        f("--initial-tab"),
        f("-Z"),
        f("--null"),
        v("-B", Val::Num),
        v("--before-context", Val::Num),
        v("-A", Val::Num),
        v("--after-context", Val::Num),
        v("-C", Val::Num),
        v("--context", Val::Num),
        v("--group-separator", Val::Text),
        f("--no-group-separator"),
        o("--color", WHEN),
        o("--colour", WHEN),
        f("-U"),
        f("--binary"),
    ],
};

pub static RG: Spec = Spec {
    numeric: false,
    flags: &[
        f("-s"),
        f("--case-sensitive"),
        f("-F"),
        f("--fixed-strings"),
        f("-i"),
        f("--ignore-case"),
        f("-v"),
        f("--invert-match"),
        f("-x"),
        f("--line-regexp"),
        f("-U"),
        f("--multiline"),
        f("--multiline-dotall"),
        f("-P"),
        f("--pcre2"),
        f("-S"),
        f("--smart-case"),
        f("-a"),
        f("--text"),
        f("-w"),
        f("--word-regexp"),
        f("--heading"),
        f("--no-heading"),
        f("-n"),
        f("--line-number"),
        f("-N"),
        f("--no-line-number"),
        f("-o"),
        f("--only-matching"),
        f("-q"),
        f("--quiet"),
        f("-H"),
        f("--with-filename"),
        f("-I"),
        f("--no-filename"),
        f("-c"),
        f("--count"),
        f("--count-matches"),
        f("-l"),
        f("--files-with-matches"),
        f("--files-without-match"),
        f("--json"),
        f("--stats"),
        f("--files"),
        f("--no-messages"),
        f("--column"),
        f("--trim"),
        f("--type-list"),
        f("--no-config"),
        f("-b"),
        f("--byte-offset"),
        f("-p"),
        f("--pretty"),
        f("-0"),
        f("--null"),
        v("-e", Val::Text),
        v("--regexp", Val::Text),
        v("-m", Val::Num),
        v("--max-count", Val::Num),
        v("-j", Val::Num),
        v("--threads", Val::Num),
        v("-g", Val::Text),
        v("--glob", Val::Text),
        v("--iglob", Val::Text),
        v("-d", Val::Num),
        v("--max-depth", Val::Num),
        v("-t", Val::Key),
        v("--type", Val::Key),
        v("-T", Val::Key),
        v("--type-not", Val::Key),
        v("-A", Val::Num),
        v("--after-context", Val::Num),
        v("-B", Val::Num),
        v("--before-context", Val::Num),
        v("-C", Val::Num),
        v("--context", Val::Num),
        v("-M", Val::Num),
        v("--max-columns", Val::Num),
        v("-r", Val::Text),
        v("--replace", Val::Text),
        v("--color", Val::Enum(&["never", "auto", "always", "ansi"])),
        v(
            "--sort",
            Val::Enum(&["none", "path", "modified", "accessed", "created"]),
        ),
        v(
            "--sortr",
            Val::Enum(&["none", "path", "modified", "accessed", "created"]),
        ),
    ],
};

pub static CAT: Spec = Spec {
    numeric: false,
    flags: &[
        f("-A"),
        f("--show-all"),
        f("-b"),
        f("--number-nonblank"),
        f("-e"),
        f("-E"),
        f("--show-ends"),
        f("-n"),
        f("--number"),
        f("-s"),
        f("--squeeze-blank"),
        f("-t"),
        f("-T"),
        f("--show-tabs"),
        f("-u"),
        f("-v"),
        f("--show-nonprinting"),
    ],
};

pub static LS: Spec = Spec {
    numeric: false,
    flags: &[
        f("-a"),
        f("--all"),
        f("-A"),
        f("--almost-all"),
        f("--author"),
        f("-b"),
        f("--escape"),
        f("-B"),
        f("--ignore-backups"),
        f("-c"),
        f("-C"),
        o("--color", WHEN),
        f("-d"),
        f("--directory"),
        f("-f"),
        f("-F"),
        o("--classify", WHEN),
        f("--file-type"),
        v(
            "--format",
            Val::Enum(&[
                "across",
                "commas",
                "horizontal",
                "long",
                "single-column",
                "verbose",
                "vertical",
            ]),
        ),
        f("--full-time"),
        f("-g"),
        f("--group-directories-first"),
        f("-G"),
        f("--no-group"),
        f("-h"),
        f("--human-readable"),
        f("--si"),
        f("-i"),
        f("--inode"),
        v(
            "--indicator-style",
            Val::Enum(&["none", "slash", "file-type", "classify"]),
        ),
        f("-k"),
        f("--kibibytes"),
        f("-l"),
        f("-m"),
        f("-n"),
        f("--numeric-uid-gid"),
        f("-N"),
        f("--literal"),
        f("-o"),
        f("-p"),
        f("-q"),
        f("--hide-control-chars"),
        f("--show-control-chars"),
        f("-Q"),
        f("--quote-name"),
        v(
            "--quoting-style",
            Val::Enum(&[
                "literal",
                "locale",
                "shell",
                "shell-always",
                "shell-escape",
                "shell-escape-always",
                "c",
                "escape",
            ]),
        ),
        f("-r"),
        f("--reverse"),
        f("-R"),
        f("--recursive"),
        f("-s"),
        f("--size"),
        f("-S"),
        v(
            "--sort",
            Val::Enum(&["none", "size", "time", "version", "extension", "width"]),
        ),
        v(
            "--time",
            Val::Enum(&[
                "atime", "access", "use", "ctime", "status", "birth", "creation",
            ]),
        ),
        v(
            "--time-style",
            Val::Enum(&["full-iso", "long-iso", "iso", "locale"]),
        ),
        f("-t"),
        f("-u"),
        f("-U"),
        f("-v"),
        f("-x"),
        f("-X"),
        f("-1"),
        f("--zero"),
    ],
};

pub static HEAD: Spec = Spec {
    numeric: true,
    flags: &[
        v("-c", Val::Count),
        v("--bytes", Val::Count),
        v("-n", Val::Count),
        v("--lines", Val::Count),
        f("-q"),
        f("--quiet"),
        f("--silent"),
        f("-v"),
        f("--verbose"),
        f("-z"),
        f("--zero-terminated"),
    ],
};

/// No `-f`, `-F`, `--follow`, `--retry`, `--pid`, `-s`: they never end or wait.
pub static TAIL: Spec = HEAD;

pub static WC: Spec = Spec {
    numeric: false,
    flags: &[
        f("-c"),
        f("--bytes"),
        f("-m"),
        f("--chars"),
        f("-l"),
        f("--lines"),
        f("-L"),
        f("--max-line-length"),
        f("-w"),
        f("--words"),
        v("--total", Val::Enum(&["auto", "always", "only", "never"])),
    ],
};

/// No `-o`/`--output`, `-T`, `--compress-program`, `--files0-from` or
/// `--random-source`: those write files or run programs.
pub static SORT: Spec = Spec {
    numeric: false,
    flags: &[
        f("-b"),
        f("--ignore-leading-blanks"),
        f("-d"),
        f("--dictionary-order"),
        f("-f"),
        f("--ignore-case"),
        f("-g"),
        f("--general-numeric-sort"),
        f("-h"),
        f("--human-numeric-sort"),
        f("-i"),
        f("--ignore-nonprinting"),
        f("-M"),
        f("--month-sort"),
        f("-n"),
        f("--numeric-sort"),
        f("-r"),
        f("--reverse"),
        f("-V"),
        f("--version-sort"),
        f("-c"),
        f("-C"),
        f("-m"),
        f("--merge"),
        f("-s"),
        f("--stable"),
        f("-u"),
        f("--unique"),
        f("-z"),
        f("--zero-terminated"),
        v("-k", Val::Key),
        v("--key", Val::Key),
        v("-t", Val::Char),
        v("--field-separator", Val::Char),
        v("-S", Val::Key),
        v("--buffer-size", Val::Key),
        v(
            "--sort",
            Val::Enum(&[
                "general-numeric",
                "human-numeric",
                "month",
                "numeric",
                "version",
            ]),
        ),
    ],
};

pub static UNIQ: Spec = Spec {
    numeric: false,
    flags: &[
        f("-c"),
        f("--count"),
        f("-d"),
        f("--repeated"),
        f("-D"),
        o(
            "--all-repeated",
            Val::Enum(&["none", "prepend", "separate"]),
        ),
        v("-f", Val::Num),
        v("--skip-fields", Val::Num),
        o(
            "--group",
            Val::Enum(&["separate", "prepend", "append", "both"]),
        ),
        f("-i"),
        f("--ignore-case"),
        v("-s", Val::Num),
        v("--skip-chars", Val::Num),
        f("-u"),
        f("--unique"),
        f("-z"),
        f("--zero-terminated"),
        v("-w", Val::Num),
        v("--check-chars", Val::Num),
    ],
};

pub static STAT: Spec = Spec {
    numeric: false,
    flags: &[
        f("-f"),
        f("--file-system"),
        v("-c", Val::Text),
        v("--format", Val::Text),
        v("--printf", Val::Text),
        f("-t"),
        f("--terse"),
    ],
};

/// No `-m`, `-f`, `-P`, `-z`/`-Z` (decompress), `-s` (devices), `-L`.
pub static FILE: Spec = Spec {
    numeric: false,
    flags: &[
        f("-b"),
        f("--brief"),
        f("-i"),
        f("--mime"),
        f("--mime-type"),
        f("--mime-encoding"),
        f("-k"),
        f("--keep-going"),
        f("-h"),
        f("--no-dereference"),
        f("-n"),
        f("--no-buffer"),
        f("-N"),
        f("--no-pad"),
        f("-r"),
        f("--raw"),
        f("-0"),
        f("--print0"),
    ],
};

/// No `-X`/`--exclude-from`, `--files0-from`, `-L`.
pub static DU: Spec = Spec {
    numeric: false,
    flags: &[
        f("-0"),
        f("--null"),
        f("-a"),
        f("--all"),
        f("--apparent-size"),
        v("-B", Val::Key),
        v("--block-size", Val::Key),
        f("-b"),
        f("--bytes"),
        f("-c"),
        f("--total"),
        v("-d", Val::Num),
        v("--max-depth", Val::Num),
        f("-h"),
        f("--human-readable"),
        f("--inodes"),
        f("-k"),
        f("-l"),
        f("--count-links"),
        f("-m"),
        f("-P"),
        f("--no-dereference"),
        f("-S"),
        f("--separate-dirs"),
        f("--si"),
        f("-s"),
        f("--summarize"),
        v("-t", Val::Key),
        v("--threshold", Val::Key),
        v("--exclude", Val::Text),
        f("-x"),
        f("--one-file-system"),
    ],
};

pub static READLINK: Spec = Spec {
    numeric: false,
    flags: &[
        f("-f"),
        f("--canonicalize"),
        f("-e"),
        f("--canonicalize-existing"),
        f("-m"),
        f("--canonicalize-missing"),
        f("-n"),
        f("--no-newline"),
        f("-q"),
        f("--quiet"),
        f("-s"),
        f("--silent"),
        f("-v"),
        f("--verbose"),
        f("-z"),
        f("--zero"),
    ],
};

/// No `-f`/`--from-file`, `-L`, `--rawfile`, `--slurpfile`, `--args`, `--jsonargs`.
pub static JQ: Spec = Spec {
    numeric: false,
    flags: &[
        f("-n"),
        f("--null-input"),
        f("-R"),
        f("--raw-input"),
        f("-s"),
        f("--slurp"),
        f("-c"),
        f("--compact-output"),
        f("-r"),
        f("--raw-output"),
        f("--raw-output0"),
        f("-j"),
        f("--join-output"),
        f("-a"),
        f("--ascii-output"),
        f("-S"),
        f("--sort-keys"),
        f("-C"),
        f("--color-output"),
        f("-M"),
        f("--monochrome-output"),
        f("--tab"),
        v("--indent", Val::Num),
        f("--unbuffered"),
        f("--stream"),
        f("--seq"),
        f("-e"),
        f("--exit-status"),
        Flag {
            name: "--arg",
            arity: crate::opts::Arity::Two(Val::Name, Val::Text),
        },
        Flag {
            name: "--argjson",
            arity: crate::opts::Arity::Two(Val::Name, Val::Text),
        },
    ],
};

/// Parses `cmd`, checks every operand as a path and, for commands that fall back
/// to the current directory, that the directory is trusted.
fn plain<'a>(
    cmd: &'a Cmd,
    env: &Env,
    spec: &Spec,
    dash_is_stdin: bool,
    default_is_cwd: bool,
) -> Res<Parsed<'a>> {
    let parsed = parse(&cmd.args, spec)?;
    env.operands(&parsed.pos, dash_is_stdin)?;
    if default_is_cwd && parsed.pos.is_empty() {
        env.cwd_trusted()?;
    }
    Ok(parsed)
}

fn no_glob(w: &Word) -> Res<()> {
    if w.glob {
        Err(Reject::new("glob-in-pattern"))
    } else {
        Ok(())
    }
}

fn grep(cmd: &Cmd, env: &Env) -> Res<&'static str> {
    let p = parse(&cmd.args, &GREP)?;
    let mut operands = p.pos.as_slice();
    if !p.has_any(&["-e", "--regexp"]) {
        let (pattern, rest) = operands
            .split_first()
            .ok_or_else(|| Reject::new("no-pattern"))?;
        no_glob(pattern)?;
        operands = rest;
    }
    env.operands(operands, true)?;
    if operands.is_empty() && p.has_any(&["-r", "--recursive"]) {
        env.cwd_trusted()?;
    }
    Ok("grep")
}

fn rg(cmd: &Cmd, env: &Env) -> Res<&'static str> {
    // ripgrep reads extra flags from this file, which could be anything
    if env.vars.is_set("RIPGREP_CONFIG_PATH") {
        return Err(Reject::new("env-rg-config"));
    }
    let p = parse(&cmd.args, &RG)?;
    let mut operands = p.pos.as_slice();
    if !p.has_any(&["-e", "--regexp", "--files", "--type-list"]) {
        let (pattern, rest) = operands
            .split_first()
            .ok_or_else(|| Reject::new("no-pattern"))?;
        no_glob(pattern)?;
        operands = rest;
    }
    env.operands(operands, true)?;
    if operands.is_empty() && !p.has("--type-list") {
        env.cwd_trusted()?;
    }
    Ok("rg")
}

fn cat(cmd: &Cmd, env: &Env) -> Res<&'static str> {
    plain(cmd, env, &CAT, true, false)?;
    Ok("cat")
}

fn ls(cmd: &Cmd, env: &Env) -> Res<&'static str> {
    plain(cmd, env, &LS, false, true)?;
    Ok("ls")
}

fn head(cmd: &Cmd, env: &Env) -> Res<&'static str> {
    plain(cmd, env, &HEAD, true, false)?;
    Ok("head")
}

fn tail(cmd: &Cmd, env: &Env) -> Res<&'static str> {
    plain(cmd, env, &TAIL, true, false)?;
    Ok("tail")
}

fn wc(cmd: &Cmd, env: &Env) -> Res<&'static str> {
    plain(cmd, env, &WC, true, false)?;
    Ok("wc")
}

fn sort(cmd: &Cmd, env: &Env) -> Res<&'static str> {
    plain(cmd, env, &SORT, true, false)?;
    Ok("sort")
}

fn uniq(cmd: &Cmd, env: &Env) -> Res<&'static str> {
    // the second operand is the file uniq writes to
    let p = parse(&cmd.args, &UNIQ)?;
    if p.pos.len() > 1 {
        return Err(Reject::new("uniq-output-operand"));
    }
    env.operands(&p.pos, true)?;
    Ok("uniq")
}

fn stat(cmd: &Cmd, env: &Env) -> Res<&'static str> {
    plain(cmd, env, &STAT, false, false)?;
    Ok("stat")
}

fn file(cmd: &Cmd, env: &Env) -> Res<&'static str> {
    plain(cmd, env, &FILE, true, false)?;
    Ok("file")
}

fn du(cmd: &Cmd, env: &Env) -> Res<&'static str> {
    plain(cmd, env, &DU, false, true)?;
    Ok("du")
}

fn readlink(cmd: &Cmd, env: &Env) -> Res<&'static str> {
    plain(cmd, env, &READLINK, false, false)?;
    Ok("readlink")
}

/// Programs that can reach beyond their input: the environment, modules,
/// the script's own path.
const JQ_FORBIDDEN: &[&str] = &[
    "env",
    "ENV",
    "input_filename",
    "import",
    "include",
    "modulemeta",
    "get_search_list",
    "__loc__",
    "__prog_args",
    "$__",
];

fn jq(cmd: &Cmd, env: &Env) -> Res<&'static str> {
    let p = parse(&cmd.args, &JQ)?;
    let (program, files) = p
        .pos
        .split_first()
        .ok_or_else(|| Reject::new("no-program"))?;
    no_glob(program)?;
    if let Some(bad) = JQ_FORBIDDEN.iter().find(|b| program.text.contains(**b)) {
        return Err(reject("jq-program", bad));
    }
    env.operands(files, false)?;
    Ok("jq")
}

fn echo(cmd: &Cmd, _env: &Env) -> Res<&'static str> {
    if cmd.args.iter().any(|w| w.glob) {
        return Err(Reject::new("glob-in-echo"));
    }
    Ok("echo")
}

fn printf(cmd: &Cmd, _env: &Env) -> Res<&'static str> {
    if cmd.args.iter().any(|w| w.glob) {
        return Err(Reject::new("glob-in-printf"));
    }
    match cmd.args.first() {
        None => Err(Reject::new("no-format")),
        // `-v VAR` assigns a shell variable
        Some(first) if first.text.starts_with("-v") => Err(Reject::new("printf-v")),
        Some(_) => Ok("printf"),
    }
}

fn which(cmd: &Cmd, _env: &Env) -> Res<&'static str> {
    for w in &cmd.args {
        let t = w.text.as_str();
        if t == "-a" || t == "-s" {
            continue;
        }
        if w.glob || t.is_empty() || t.starts_with('-') || t.contains('/') {
            return Err(reject("which-arg", t));
        }
    }
    Ok("which")
}

/// `find` with only the tests and actions that read nothing and write nothing:
/// no `-exec`, `-execdir`, `-ok`, `-okdir`, `-delete`, `-fprint*`, `-fls`,
/// `-files0-from` and no symlink following.
const FIND_FLAGS: &[&str] = &[
    "-true",
    "-false",
    "-empty",
    "-executable",
    "-readable",
    "-writable",
    "-nouser",
    "-nogroup",
    "-prune",
    "-print",
    "-print0",
    "-ls",
    "-quit",
    "-depth",
    "-mount",
    "-xdev",
    "-noleaf",
    "-daystart",
    "-nowarn",
    "-warn",
    "-ignore_readdir_race",
    "-noignore_readdir_race",
    "-not",
    "-and",
    "-or",
    "-a",
    "-o",
    "(",
    ")",
    "!",
    ",",
];

const FIND_VALUES: &[(&str, Val)] = &[
    ("-name", Val::Text),
    ("-iname", Val::Text),
    ("-path", Val::Text),
    ("-ipath", Val::Text),
    ("-wholename", Val::Text),
    ("-iwholename", Val::Text),
    ("-lname", Val::Text),
    ("-ilname", Val::Text),
    ("-regex", Val::Text),
    ("-iregex", Val::Text),
    ("-type", Val::Key),
    ("-xtype", Val::Key),
    ("-size", Val::Count),
    ("-perm", Val::Text),
    ("-user", Val::Text),
    ("-group", Val::Text),
    ("-uid", Val::Count),
    ("-gid", Val::Count),
    ("-links", Val::Count),
    ("-inum", Val::Count),
    ("-amin", Val::Count),
    ("-atime", Val::Count),
    ("-cmin", Val::Count),
    ("-ctime", Val::Count),
    ("-mmin", Val::Count),
    ("-mtime", Val::Count),
    ("-used", Val::Count),
    ("-fstype", Val::Key),
    ("-printf", Val::Text),
    ("-maxdepth", Val::Num),
    ("-mindepth", Val::Num),
    ("-regextype", Val::Key),
];

/// Tests that name a file to compare against.
const FIND_FILE_TESTS: &[&str] = &["-newer", "-anewer", "-cnewer", "-samefile"];

/// `-newerXY REF`, where REF is a time when Y is `t` and a file otherwise.
fn find_newer_xy(primary: &str) -> Option<bool> {
    let rest = primary.strip_prefix("-newer")?;
    let mut it = rest.chars();
    let (x, y) = (it.next()?, it.next()?);
    if it.next().is_some() || !"aBcm".contains(x) || !"aBcmt".contains(y) {
        return None;
    }
    Some(y == 't')
}

fn find(cmd: &Cmd, env: &Env) -> Res<&'static str> {
    let args = &cmd.args;
    let mut i = 0;
    while args.get(i).is_some_and(|w| w.text == "-P") {
        i += 1;
    }
    let mut starts: Vec<&Word> = Vec::new();
    while let Some(w) = args.get(i) {
        let t = w.text.as_str();
        if t.starts_with('-') || matches!(t, "(" | ")" | "!" | ",") {
            break;
        }
        starts.push(w);
        i += 1;
    }
    env.operands(&starts, false)?;
    if starts.is_empty() {
        env.cwd_trusted()?;
    }
    while let Some(w) = args.get(i) {
        i += 1;
        let primary = w.text.as_str();
        if w.glob {
            return Err(Reject::new("glob-in-expression"));
        }
        if FIND_FLAGS.contains(&primary) {
            continue;
        }
        let mut argument = |name: &str| -> Res<&Word> {
            let a = args
                .get(i)
                .ok_or_else(|| reject("find-missing-arg", name))?;
            i += 1;
            Ok(a)
        };
        if let Some((_, val)) = FIND_VALUES.iter().find(|(n, _)| *n == primary) {
            let a = argument(primary)?;
            if a.glob {
                return Err(Reject::new("glob-in-value"));
            }
            if !valid(*val, &a.text) {
                return Err(reject("find-value", primary));
            }
        } else if FIND_FILE_TESTS.contains(&primary) || find_newer_xy(primary) == Some(false) {
            env.path(argument(primary)?)?;
        } else if find_newer_xy(primary) == Some(true) {
            let a = argument(primary)?;
            if a.glob {
                return Err(Reject::new("glob-in-value"));
            }
        } else {
            return Err(reject("find-primary", primary));
        }
    }
    Ok("find")
}
