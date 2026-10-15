//! A second opinion on whether a command line could do more than read.
//!
//! It is written without the analyzer and without the allow-list (a small lexer
//! of its own, lists of its own) so that the two can be set against each other:
//! the replay over real history and `tests/differential.rs` require that nothing
//! the policy allows is flagged here. It is suspicious on purpose: a flag on a
//! command the policy allowed is either a hole in the policy or a rule here that
//! is too eager, and a human decides which. Quoting is understood, so words that
//! merely contain something dangerous (`grep 'rm -rf' notes`) are not flagged.
//!
//! Wildcards are not judged here: the policy expands them against the file
//! system and checks every match, which a lexer cannot do.

use regex::Regex;
use std::sync::LazyLock;

/// Why `src` looks like more than a read, in the order it was noticed. Empty
/// means nothing was found.
pub fn dangers(src: &str) -> Vec<String> {
    let mut found = Vec::new();
    let toks = lex(src, &mut found);
    let mut words: Vec<String> = Vec::new();
    let mut redirects: Vec<(&'static str, String)> = Vec::new();
    let mut pending: Option<&'static str> = None;
    for tok in toks {
        match tok {
            Tok::Word(w) => match pending.take() {
                Some(op) => redirects.push((op, w)),
                None => words.push(w),
            },
            Tok::Op(op @ (">" | ">>" | "<" | ">&" | "<&" | "&>" | "<<" | "<<<" | "<>")) => {
                if pending.is_some() {
                    note(&mut found, "redirect-without-target");
                }
                pending = Some(op);
            }
            Tok::Op(_) => {
                if pending.take().is_some() {
                    note(&mut found, "redirect-without-target");
                }
                simple(&words, &redirects, &mut found);
                words.clear();
                redirects.clear();
            }
        }
    }
    if pending.is_some() {
        note(&mut found, "redirect-without-target");
    }
    simple(&words, &redirects, &mut found);
    found
}

fn note(found: &mut Vec<String>, what: impl Into<String>) {
    let what = what.into();
    if !found.contains(&what) {
        found.push(what);
    }
}

// ------------------------------------------------------------------- lexer

#[derive(Debug, PartialEq)]
enum Tok {
    Word(String),
    Op(&'static str),
}

/// Characters a person reading the command cannot see for what they are, or
/// that some parser might take for a separator.
fn odd(c: char) -> bool {
    if c == '\n' || c == '\t' || c == ' ' {
        return false;
    }
    c.is_control()
        || c.is_whitespace()
        || matches!(c as u32,
            0xad | 0x600..=0x605 | 0x61c | 0x6dd | 0x70f | 0x180e
            | 0x200b..=0x200f | 0x202a..=0x202e | 0x2060..=0x206f
            | 0xfe00..=0xfe0f | 0xfeff | 0xfff9..=0xfffb
            | 0xe0000..=0xe007f | 0xe0100..=0xe01ef)
}

fn lex(src: &str, found: &mut Vec<String>) -> Vec<Tok> {
    let chars: Vec<char> = src.chars().collect();
    let mut toks = Vec::new();
    let mut word: Option<String> = None;
    let mut i = 0;
    let end = |toks: &mut Vec<Tok>, word: &mut Option<String>| {
        if let Some(w) = word.take() {
            toks.push(Tok::Word(w));
        }
    };
    while i < chars.len() {
        let c = chars[i];
        let next = chars.get(i + 1).copied();
        if odd(c) {
            note(found, "odd-character");
        }
        match c {
            ' ' | '\t' => end(&mut toks, &mut word),
            '\n' => {
                end(&mut toks, &mut word);
                toks.push(Tok::Op("\n"));
            }
            '\\' => {
                note(found, "escape");
                match next {
                    Some('\n') => i += 1,
                    Some(n) => {
                        if odd(n) {
                            note(found, "odd-character");
                        }
                        word.get_or_insert_with(String::new).push(n);
                        i += 1;
                    }
                    None => note(found, "trailing-backslash"),
                }
            }
            '\'' => {
                let w = word.get_or_insert_with(String::new);
                i += 1;
                loop {
                    match chars.get(i) {
                        Some('\'') => break,
                        Some(&n) => {
                            if odd(n) {
                                note(found, "odd-character");
                            }
                            w.push(n);
                            i += 1;
                        }
                        None => {
                            note(found, "unterminated-quote");
                            break;
                        }
                    }
                }
            }
            '"' => {
                let w = word.get_or_insert_with(String::new);
                i += 1;
                loop {
                    let Some(&n) = chars.get(i) else {
                        note(found, "unterminated-quote");
                        break;
                    };
                    match n {
                        '"' => break,
                        '\\' => match chars.get(i + 1) {
                            Some('\n') => i += 1,
                            Some(&e) if "$`\"\\".contains(e) => {
                                w.push(e);
                                i += 1;
                            }
                            _ => w.push('\\'),
                        },
                        '$' => {
                            // Before a quote, inside double quotes, `$` is a plain
                            // dollar: a `"` ends the string and a `'` is only a quote.
                            if !matches!(chars.get(i + 1), Some('\'' | '"')) {
                                expansion(chars.get(i + 1).copied(), found);
                            }
                            w.push('$');
                        }
                        '`' => {
                            note(found, "substitution");
                            w.push('`');
                        }
                        '!' => {
                            note(found, "history-expansion");
                            w.push('!');
                        }
                        other => {
                            if odd(other) {
                                note(found, "odd-character");
                            }
                            w.push(other);
                        }
                    }
                    i += 1;
                }
            }
            '`' => {
                note(found, "substitution");
                word.get_or_insert_with(String::new).push('`');
            }
            '$' => {
                expansion(next, found);
                word.get_or_insert_with(String::new).push('$');
            }
            '!' => {
                note(found, "history-expansion");
                word.get_or_insert_with(String::new).push('!');
            }
            '#' if word.is_none() => {
                while chars.get(i + 1).is_some_and(|&n| n != '\n') {
                    i += 1;
                }
            }
            ';' => {
                end(&mut toks, &mut word);
                toks.push(Tok::Op(";"));
            }
            '|' => {
                end(&mut toks, &mut word);
                if matches!(next, Some('|' | '&')) {
                    i += 1;
                }
                toks.push(Tok::Op("|"));
            }
            '&' => match next {
                Some('&') => {
                    end(&mut toks, &mut word);
                    i += 1;
                    toks.push(Tok::Op("&&"));
                }
                Some('>') => {
                    end(&mut toks, &mut word);
                    i += 1;
                    if chars.get(i + 1) == Some(&'>') {
                        i += 1;
                    }
                    toks.push(Tok::Op("&>"));
                }
                _ => {
                    end(&mut toks, &mut word);
                    note(found, "background");
                    toks.push(Tok::Op("&"));
                }
            },
            '(' | ')' => {
                end(&mut toks, &mut word);
                note(found, "subshell");
                if c == '(' && next == Some('(') {
                    note(found, "arithmetic");
                }
                toks.push(Tok::Op(if c == '(' { "(" } else { ")" }));
            }
            '<' | '>' => {
                // `2>` and `2<`: the digits name a descriptor and are no word
                if word
                    .as_deref()
                    .is_some_and(|w| !w.is_empty() && w.bytes().all(|b| b.is_ascii_digit()))
                {
                    word = None;
                } else {
                    end(&mut toks, &mut word);
                }
                let op = if c == '<' {
                    match (next, chars.get(i + 2).copied()) {
                        (Some('<'), Some('<')) => {
                            i += 2;
                            "<<<"
                        }
                        (Some('<'), _) => {
                            i += 1;
                            if chars.get(i + 1) == Some(&'-') {
                                i += 1;
                            }
                            "<<"
                        }
                        (Some('('), _) => {
                            note(found, "substitution");
                            "<"
                        }
                        (Some('&'), _) => {
                            i += 1;
                            "<&"
                        }
                        (Some('>'), _) => {
                            i += 1;
                            "<>"
                        }
                        _ => "<",
                    }
                } else {
                    match next {
                        Some('>') => {
                            i += 1;
                            ">>"
                        }
                        Some('&') => {
                            i += 1;
                            ">&"
                        }
                        Some('|') => {
                            i += 1;
                            ">"
                        }
                        Some('(') => {
                            note(found, "substitution");
                            ">"
                        }
                        _ => ">",
                    }
                };
                toks.push(Tok::Op(op));
            }
            // brace expansion turns one word into several that nothing here has seen
            '{' | '}' => {
                note(found, "brace");
                word.get_or_insert_with(String::new).push(c);
            }
            other => word.get_or_insert_with(String::new).push(other),
        }
        i += 1;
    }
    end(&mut toks, &mut word);
    toks
}

/// What follows a `$` that is not quoted away.
fn expansion(next: Option<char>, found: &mut Vec<String>) {
    match next {
        Some('(') => note(found, "substitution"),
        Some('\'' | '"') => note(found, "quoted-expansion"),
        Some(n) if n.is_ascii_alphanumeric() || "_{?#@*!$-[".contains(n) => {
            note(found, "expansion");
        }
        _ => {}
    }
}

// ------------------------------------------------------------ simple command

const DANGEROUS: &[&str] = &[
    // syntax and builtins that run or change things
    "if",
    "then",
    "else",
    "elif",
    "fi",
    "for",
    "while",
    "until",
    "do",
    "done",
    "case",
    "esac",
    "select",
    "function",
    "coproc",
    "time",
    "{",
    "}",
    "!",
    "[[",
    "]]",
    "eval",
    "exec",
    "source",
    ".",
    "export",
    "unset",
    "alias",
    "unalias",
    "set",
    "shopt",
    "declare",
    "typeset",
    "local",
    "readonly",
    "let",
    "read",
    "mapfile",
    "readarray",
    "trap",
    "ulimit",
    "umask",
    "wait",
    "kill",
    "disown",
    "bg",
    "fg",
    "exit",
    "logout",
    "return",
    "break",
    "continue",
    "shift",
    "getopts",
    "enable",
    "builtin",
    "command",
    "history",
    "fc",
    "bind",
    "pushd",
    "popd",
    "suspend",
    // wrappers that run another command
    "sudo",
    "doas",
    "su",
    "env",
    "xargs",
    "nohup",
    "timeout",
    "nice",
    "ionice",
    "renice",
    "chrt",
    "taskset",
    "setsid",
    "stdbuf",
    "watch",
    "script",
    "unbuffer",
    "busybox",
    "parallel",
    "flock",
    "chroot",
    "unshare",
    "nsenter",
    "strace",
    "ltrace",
    "gdb",
    "valgrind",
    "perf",
    "firejail",
    "bwrap",
    "systemd-run",
    "at",
    "batch",
    "entr",
    "expect",
    "sshpass",
    "toybox",
    // writes
    "rm",
    "rmdir",
    "mv",
    "cp",
    "dd",
    "tee",
    "touch",
    "mkdir",
    "mkfifo",
    "mknod",
    "ln",
    "install",
    "truncate",
    "shred",
    "chmod",
    "chown",
    "chgrp",
    "chattr",
    "setfacl",
    "patch",
    "sync",
    "split",
    "csplit",
    "rename",
    "mktemp",
    "unlink",
    "fallocate",
    "rsync",
    "tar",
    "zip",
    "unzip",
    "gzip",
    "gunzip",
    "bzip2",
    "xz",
    "zstd",
    "7z",
    "cpio",
    "ar",
    "sed",
    "awk",
    "gawk",
    "mawk",
    "nawk",
    "perl",
    "vi",
    "vim",
    "nvim",
    "nano",
    "emacs",
    "ed",
    "ex",
    "code",
    "ld",
    "less",
    "more",
    "man",
    // network
    "curl",
    "wget",
    "nc",
    "ncat",
    "netcat",
    "socat",
    "telnet",
    "ftp",
    "sftp",
    "ssh",
    "scp",
    "ssh-keygen",
    "ssh-add",
    "ssh-agent",
    "mosh",
    "ping",
    "traceroute",
    "dig",
    "nslookup",
    "host",
    "whois",
    "nmap",
    "tcpdump",
    "ip",
    "ifconfig",
    "iptables",
    "nft",
    "ufw",
    "openssl",
    "gpg",
    "gh",
    "aws",
    "gcloud",
    "az",
    "kubectl",
    "helm",
    "terraform",
    "docker",
    "podman",
    "buildah",
    "nerdctl",
    "lxc",
    "vagrant",
    // interpreters, compilers and build tools
    "sh",
    "bash",
    "dash",
    "zsh",
    "fish",
    "ksh",
    "csh",
    "tcsh",
    "ash",
    "python",
    "python2",
    "python3",
    "pypy",
    "ruby",
    "irb",
    "node",
    "nodejs",
    "deno",
    "bun",
    "php",
    "lua",
    "luajit",
    "tclsh",
    "java",
    "javac",
    "kotlin",
    "scala",
    "dotnet",
    "go",
    "cargo",
    "rustc",
    "rustup",
    "gcc",
    "g++",
    "cc",
    "c++",
    "clang",
    "make",
    "gmake",
    "cmake",
    "ninja",
    "meson",
    "npm",
    "npx",
    "pnpm",
    "yarn",
    "pip",
    "pip3",
    "pipx",
    "uv",
    "poetry",
    "conda",
    "gem",
    "bundle",
    "mvn",
    "gradle",
    "ant",
    "sbt",
    "mix",
    "cabal",
    "ghc",
    "nix",
    "nix-shell",
    // system management
    "systemctl",
    "service",
    "loginctl",
    "busctl",
    "machinectl",
    "hostnamectl",
    "timedatectl",
    "apt",
    "apt-get",
    "aptitude",
    "dpkg",
    "snap",
    "flatpak",
    "rpm",
    "yum",
    "dnf",
    "pacman",
    "mount",
    "umount",
    "modprobe",
    "insmod",
    "rmmod",
    "sysctl",
    "reboot",
    "shutdown",
    "poweroff",
    "halt",
    "useradd",
    "userdel",
    "usermod",
    "groupadd",
    "passwd",
    "chpasswd",
    "visudo",
    "crontab",
    "puppet",
    "ansible",
    "ansible-playbook",
    "pkill",
    "killall",
    "fuser",
    "nmcli",
    "losetup",
    "fdisk",
    "parted",
    "mkfs",
    "fsck",
    "cryptsetup",
    "wipefs",
    "hdparm",
    "smartctl",
];

fn is_assignment(word: &str) -> bool {
    let Some((name, _)) = word.split_once('=') else {
        return false;
    };
    let mut chars = name.chars();
    chars
        .next()
        .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
        && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
}

fn simple(words: &[String], redirects: &[(&'static str, String)], found: &mut Vec<String>) {
    for (op, target) in redirects {
        match *op {
            ">" | ">>" | "&>" | "<>" if target != "/dev/null" => note(found, "redirect-out"),
            ">&" if !(target == "-"
                || !target.is_empty() && target.bytes().all(|b| b.is_ascii_digit())) =>
            {
                note(found, "redirect-out");
            }
            "<<" | "<<<" => note(found, "heredoc"),
            _ => {}
        }
        sensitive(target, found);
    }
    let mut words = words;
    while let Some(first) = words.first()
        && is_assignment(first)
    {
        note(found, "assignment");
        words = &words[1..];
    }
    for word in words {
        sensitive(word, found);
        if word.starts_with('~') && !(word == "~" || word.starts_with("~/")) {
            note(found, "tilde-user");
        }
    }
    let Some((name, args)) = words.split_first() else {
        return;
    };
    if name.contains('/') {
        note(found, "path-command");
    }
    if name.starts_with('-') {
        note(found, "dash-command");
    }
    let base = name.rsplit('/').next().unwrap_or(name);
    if DANGEROUS.contains(&base) {
        note(found, format!("cmd:{base}"));
    }
    // After `--` nothing is an option any more. `find`, `git`, `uniq`, `printf`
    // and the jq program are read differently and look at all of `all`.
    let all = args;
    let args = args
        .iter()
        .position(|a| a == "--")
        .map_or(args, |at| &args[..at]);
    match base {
        "find" => hits(
            found,
            "find",
            all,
            &[
                "-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprint", "-fprint0", "-fprintf",
                "-fls",
            ],
        ),
        "sort" => {
            cluster(found, "sort", args, &['o', 'T']);
            hits(found, "sort", args, &["--files0-from"]);
            prefixes(
                found,
                "sort",
                args,
                &["--output", "--compress-program", "--temporary-directory"],
            );
        }
        "git" => git(all, found),
        "rg" => {
            cluster(found, "rg", args, &['z']);
            hits(found, "rg", args, &["--search-zip"]);
            prefixes(
                found,
                "rg",
                args,
                &["--pre", "--hostname-bin", "--config-path"],
            );
        }
        "jq" => {
            cluster(found, "jq", args, &['f', 'L']);
            hits(
                found,
                "jq",
                args,
                &[
                    "--rawfile",
                    "--slurpfile",
                    "--from-file",
                    "--library-path",
                    "--arg-file",
                ],
            );
            // what leaves the named inputs: the environment, modules, file names.
            // `input`, `debug`, `stderr` and `halt` stay inside them.
            static JQ: LazyLock<Regex> = LazyLock::new(|| {
                Regex::new(
                    r"\benv\b|\$ENV|input_filename|\bimport\b|\binclude\b|modulemeta|get_search_list|__loc__|__prog_args|\$__",
                )
                .unwrap()
            });
            if all.iter().any(|a| !a.starts_with('-') && JQ.is_match(a)) {
                note(found, "jq:environment-or-io");
            }
        }
        "file" => {
            cluster(found, "file", args, &['C', 'm', 'f', 'z', 'Z', 'S']);
            prefixes(
                found,
                "file",
                args,
                &[
                    "--compile",
                    "--magic-file",
                    "--files-from",
                    "--uncompress",
                    "--no-sandbox",
                ],
            );
        }
        "du" => {
            cluster(found, "du", args, &['X']);
            prefixes(found, "du", args, &["--files0-from", "--exclude-from"]);
        }
        "wc" => prefixes(found, "wc", args, &["--files0-from"]),
        "tail" | "head" => {
            cluster(found, base, args, &['f', 'F']);
            prefixes(found, base, args, &["--follow", "--retry", "--pid"]);
        }
        // bash's builtin takes `-v` only before the format; later it is data
        "printf" if all.first().is_some_and(|a| a == "-v") => note(found, "printf:-v"),
        "uniq" => {
            let mut operands = 0;
            let mut skip = false;
            for arg in all {
                if skip {
                    skip = false;
                } else if matches!(arg.as_str(), "-f" | "-s" | "-w") {
                    skip = true;
                } else if !arg.starts_with('-') || arg == "-" {
                    operands += 1;
                }
            }
            if operands > 1 {
                note(found, "uniq:output-file");
            }
        }
        _ => {}
    }
}

fn hits(found: &mut Vec<String>, cmd: &str, args: &[String], flags: &[&str]) {
    for arg in args {
        if flags.contains(&arg.as_str()) {
            note(found, format!("{cmd}:{arg}"));
        }
    }
}

fn prefixes(found: &mut Vec<String>, cmd: &str, args: &[String], flags: &[&str]) {
    for arg in args {
        if flags
            .iter()
            .any(|f| arg == f || arg.starts_with(&format!("{f}=")))
        {
            note(found, format!("{cmd}:{arg}"));
        }
    }
}

/// Short options, alone or clustered (`-nro`), that name one of `letters`.
fn cluster(found: &mut Vec<String>, cmd: &str, args: &[String], letters: &[char]) {
    for arg in args {
        let Some(rest) = arg.strip_prefix('-') else {
            continue;
        };
        if !rest.starts_with('-') && rest.chars().any(|c| letters.contains(&c)) {
            note(found, format!("{cmd}:{arg}"));
        }
    }
}

// --------------------------------------------------------------------- git

const GIT_READ: &[&str] = &[
    "status",
    "log",
    "diff",
    "show",
    "ls-files",
    "ls-tree",
    "rev-parse",
    "rev-list",
    "describe",
    "blame",
    "shortlog",
    "cat-file",
    "show-ref",
    "for-each-ref",
    "name-rev",
    "merge-base",
    "diff-tree",
    "diff-index",
    "diff-files",
    "grep",
    "whatchanged",
    "cherry",
    "show-branch",
    "count-objects",
    "check-ignore",
    "check-attr",
    "var",
    "version",
    "annotate",
];

fn git(args: &[String], found: &mut Vec<String>) {
    let mut i = 0;
    while i < args.len() && args[i].starts_with('-') {
        let arg = args[i].as_str();
        if arg == "-C" {
            i += 1;
        } else if matches!(arg, "-c" | "-p")
            || [
                "--config-env",
                "--git-dir",
                "--work-tree",
                "--exec-path",
                "--super-prefix",
                "--paginate",
                "--namespace",
            ]
            .iter()
            .any(|f| arg == *f || arg.starts_with(&format!("{f}=")))
        {
            note(found, format!("git:{arg}"));
        }
        i += 1;
    }
    let rest = args.get(i + 1..).unwrap_or_default();
    // after `--` come pathspecs, which are operands whatever they look like
    let (before, after) = match rest.iter().position(|a| a == "--") {
        Some(at) => (&rest[..at], &rest[at + 1..]),
        None => (rest, <&[String]>::default()),
    };
    for arg in before {
        let long = arg.split('=').next().unwrap_or(arg);
        if matches!(
            long,
            "--output"
                | "--ext-diff"
                | "--textconv"
                | "--no-index"
                | "--open-files-in-pager"
                | "--exec"
                | "--upload-pack"
                | "--receive-pack"
                | "--help"
                | "-h"
        ) || arg.starts_with("-O")
            || arg.starts_with("--output=")
        {
            note(found, format!("git:{arg}"));
        }
    }
    let Some(sub) = args.get(i) else { return };
    if GIT_READ.contains(&sub.as_str()) {
        return;
    }
    let plain: Vec<&str> = before
        .iter()
        .filter(|a| !a.starts_with('-'))
        .chain(after)
        .map(String::as_str)
        .collect();
    let has = |names: &[&str]| before.iter().any(|a| names.contains(&a.as_str()));
    let safe = match sub.as_str() {
        "branch" | "tag" => has(&["-l", "--list"]) || plain.is_empty(),
        "remote" => plain.is_empty() || matches!(plain[0], "show" | "get-url"),
        "config" => has(&["--get", "--get-all", "--get-regexp", "-l", "--list"]),
        "stash" => matches!(plain.first(), Some(&"list" | &"show")),
        "worktree" => matches!(plain.first(), Some(&"list")),
        "reflog" => plain.is_empty() || plain[0] == "show",
        _ => false,
    };
    // `git branch -D x` has no plain words, and `-d` and its kin are options
    let destructive = has(&[
        "-d",
        "-D",
        "-m",
        "-M",
        "-c",
        "-C",
        "-f",
        "--delete",
        "--move",
        "--copy",
        "--force",
        "--set-upstream-to",
        "-u",
        "--unset-upstream",
        "--edit-description",
        "--add",
        "--unset",
        "--replace-all",
        "--rename-section",
        "--remove-section",
        "--edit",
        "-e",
    ]) || before
        .iter()
        .any(|a| a.starts_with("--set-upstream-to=") || a.starts_with("--unset"));
    if !safe || destructive {
        note(found, format!("git:{sub}"));
    }
}

// ---------------------------------------------------------------- secrets

static SENSITIVE: LazyLock<Vec<(&'static str, Regex)>> = LazyLock::new(|| {
    [
        ("ssh", r"(^|/)\.ssh(/|$)"),
        ("gnupg", r"(^|/)\.gnupg(/|$)"),
        ("aws", r"(^|/)\.aws(/|$)"),
        ("azure", r"(^|/)\.azure(/|$)"),
        ("kube", r"(^|/)\.kube(/|$)"),
        ("gcloud", r"(^|/)\.config/gcloud(/|$)"),
        ("docker-config", r"(^|/)\.docker/config\.json$"),
        ("gh-config", r"(^|/)\.config/gh(/|$)"),
        ("copilot-config", r"(^|/)\.copilot/(config|mcp-config|permissions)[^/]*$"),
        ("env-file", r"(^|/)\.env(\.[^/]*)?$"),
        ("private-key", r"(^|/)id_(rsa|dsa|ecdsa|ed25519)[^/]*$"),
        ("key-file", r"\.(pem|key|p12|pfx|jks|keystore|kdbx)$"),
        (
            "credentials",
            r"(^|/)(\.netrc|\.npmrc|\.pypirc|\.git-credentials|\.pgpass|\.htpasswd|\.vault-pass[^/]*|credentials(\.json)?)$",
        ),
        ("etc-secret", r"^/etc/(shadow|gshadow|sudoers|ssh/ssh_host|ssl/private|krb5\.keytab)"),
        ("proc-secret", r"^/proc/[^/]+/(environ|mem|maps|fd|cmdline|task)"),
        ("device", r"^/dev/(mem|kmem|port|sd[a-z]|nvme|disk|mapper|input|ptmx|pts)"),
    ]
    .into_iter()
    .map(|(name, pattern)| (name, Regex::new(pattern).unwrap()))
    .collect()
});

fn sensitive(word: &str, found: &mut Vec<String>) {
    for (name, pattern) in SENSITIVE.iter() {
        if pattern.is_match(word) {
            note(found, format!("secret:{name}"));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn flagged(src: &str, what: &str) {
        let found = dangers(src);
        assert!(
            found.iter().any(|f| f == what || f.starts_with(what)),
            "{src:?}: wanted {what:?}, got {found:?}"
        );
    }

    fn clean(src: &str) {
        let found = dangers(src);
        assert!(found.is_empty(), "{src:?} was flagged: {found:?}");
    }

    #[test]
    fn plain_reads_are_left_alone() {
        for src in [
            "ls",
            "ls -la src",
            "ls 2>&1",
            "ls > /dev/null",
            "ls 2>/dev/null | head",
            "cat README.md",
            "cat -n README.md src/main.rs",
            "grep -rn 'fn main' src",
            "grep -e one -e \"two\" README.md",
            "grep -v \"^$\" notes.txt",
            "grep -E \"\\.(rs|toml)$\" notes.txt | head",
            "echo \"cost $'x'\"",
            "grep 'rm -rf; echo $(x) > y' notes",
            "echo \"a > b ; c\" 'd | e'",
            "sort notes.txt | uniq -c | sort -rn | head -20",
            "uniq -f 1 notes.txt",
            "find . -name '*.rs' -type f",
            "jq '.items[].name' data.json",
            "jq -r '.a.b' data.json",
            "stat -c '%s %n' README.md",
            "file README.md",
            "du -sh src",
            "head -n 5 README.md",
            "tail -n 3 notes.txt",
            "tail -n +2 notes.txt",
            "which ls",
            "readlink -f src",
            "rg -n todo README.md",
            "git status",
            "git log --oneline -n 5",
            "git log --grep='fix' --oneline",
            "git diff --stat | tail -1",
            "git show HEAD:README.md",
            "git branch",
            "git branch -a",
            "git branch --list 'feat*'",
            "git tag -l",
            "git remote -v",
            "git config --get user.name",
            "git stash list",
            "git -C src log",
            "cd src && ls",
            "cd ~/kms-two && git log --oneline",
            "ls ; cat README.md",
            "cat README.md\nls src",
            "# a comment\nls",
            "echo a#b",
            "printf '%s\\n' hello",
        ] {
            clean(src);
        }
    }

    #[test]
    fn shell_structure_that_does_more_than_read() {
        flagged("echo $(id)", "substitution");
        flagged("echo `id`", "substitution");
        flagged("echo \"$(id)\"", "substitution");
        flagged("echo \"`id`\"", "substitution");
        flagged("diff <(ls) b", "substitution");
        flagged("echo $HOME", "expansion");
        flagged("echo ${HOME}", "expansion");
        flagged("echo \"$HOME\"", "expansion");
        flagged("echo $'\\x41'", "quoted-expansion");
        flagged("echo $\"x\"", "quoted-expansion");
        flagged("echo \"a\"$'\\x41'", "quoted-expansion");
        flagged("echo \"$HOME$\"", "expansion");
        flagged("ls > out", "redirect-out");
        flagged("ls >> out", "redirect-out");
        flagged("ls 2> out", "redirect-out");
        flagged("ls &> out", "redirect-out");
        flagged("ls >& out", "redirect-out");
        flagged("ls >out", "redirect-out");
        flagged("ls >| out", "redirect-out");
        flagged("cat <<EOF\nx\nEOF", "heredoc");
        flagged("cat <<< x", "heredoc");
        flagged("sleep 1 &", "background");
        flagged("FOO=bar ls", "assignment");
        flagged("LD_PRELOAD=x ls", "assignment");
        flagged("!!", "history-expansion");
        flagged("echo \"!x\"", "history-expansion");
        flagged("echo 'unterminated", "unterminated-quote");
        flagged("echo \"unterminated", "unterminated-quote");
        flagged("ls \\", "trailing-backslash");
        flagged("echo 'it'\\''s'", "escape");
        flagged("ls a\\ b", "escape");
        flagged("ls \\\u{200b}", "odd-character");
        flagged("(id)", "subshell");
        flagged("ls (id)", "subshell");
        flagged("-ls", "dash-command");
        flagged("--ls", "dash-command");
        flagged("ls >", "redirect-without-target");
        flagged("echo ((1))", "arithmetic");
        flagged("ls {a,b}", "brace");
        flagged("cat {.env,x}", "brace");
        flagged("echo {1..3}", "brace");
        clean("echo '{a,b}' \"{c}\"");
        flagged("~root/x", "tilde-user");
        flagged("/bin/ls", "path-command");
        flagged("./ls", "path-command");
        for odd in [
            "\r", "\0", "\u{a0}", "\u{200b}", "\u{202e}", "\u{feff}", "\u{3000}",
        ] {
            flagged(&format!("ls{odd}x"), "odd-character");
            flagged(&format!("ls '{odd}'"), "odd-character");
        }
    }

    #[test]
    fn commands_that_change_things_or_run_other_things() {
        for cmd in [
            "rm -rf x",
            "mv a b",
            "cp a b",
            "tee f",
            "touch f",
            "mkdir d",
            "chmod +x f",
            "dd if=a of=b",
            "curl http://x",
            "wget x",
            "ssh host",
            "sudo ls",
            "env ls",
            "xargs ls",
            "nohup ls",
            "time ls",
            "timeout 5 ls",
            "python3 x.py",
            "node x.js",
            "perl -e 1",
            "awk 1 f",
            "sed -i s/a/b/ f",
            "bash -c ls",
            "sh -c ls",
            "eval ls",
            "exec ls",
            "source f",
            ". f",
            "make",
            "cargo build",
            "docker ps",
            "systemctl stop x",
            "kill 1",
            "export A=1",
            "unset A",
            "set -x",
            "git-lfs",
        ] {
            let found = dangers(cmd);
            let name = cmd.split_whitespace().next().unwrap();
            if name != "git-lfs" {
                assert!(
                    found
                        .iter()
                        .any(|f| f.starts_with("cmd:") || f == "assignment"),
                    "{cmd:?}: {found:?}"
                );
            }
        }
        // in the middle of a line too
        flagged("ls && rm x", "cmd:rm");
        flagged("ls | xargs rm", "cmd:xargs");
        flagged("ls; sudo ls", "cmd:sudo");
        flagged("ls\nrm x", "cmd:rm");
        flagged("cd x && python3 y", "cmd:python3");
        flagged("(rm x)", "cmd:rm");
    }

    #[test]
    fn dual_use_flags() {
        flagged("find . -exec rm {} ;", "find:-exec");
        flagged("find . -delete", "find:-delete");
        flagged("find . -fprint out", "find:-fprint");
        flagged("sort -o out in", "sort:-o");
        flagged("sort -nro out in", "sort:-nro");
        flagged("sort --output=out in", "sort:--output=out");
        flagged("sort --compress-program=sh in", "sort:--compress-program");
        flagged("rg --pre ./x pat", "rg:--pre");
        flagged("rg --pre=./x pat", "rg:--pre=./x");
        flagged("rg -z pat", "rg:-z");
        flagged("rg --hostname-bin=x pat", "rg:--hostname-bin");
        flagged("jq -f prog.jq x", "jq:-f");
        flagged("jq -n env", "jq:environment-or-io");
        flagged("jq -n '$ENV.PATH'", "jq:environment-or-io");
        flagged("jq --rawfile a f .", "jq:--rawfile");
        flagged("file -C", "file:-C");
        flagged("file -m magic f", "file:-m");
        flagged("du --files0-from=x", "du:--files0-from");
        flagged("wc --files0-from=x", "wc:--files0-from");
        flagged("tail -f log", "tail:-f");
        flagged("tail --follow log", "tail:--follow");
        flagged("tail -F log", "tail:-F");
        flagged("printf -v x y", "printf:-v");
        flagged("uniq in out", "uniq:output-file");
        flagged("uniq -f 1 in out", "uniq:output-file");
        flagged("jq -n 'input_filename'", "jq:environment-or-io");
        flagged("jq -n 'import \"a\" as a; .'", "jq:environment-or-io");
        flagged("jq -n 'modulemeta'", "jq:environment-or-io");
        // what stays inside the named inputs is no reason to worry
        for fine in [
            "jq -n 'input'",
            "jq '[inputs]' data.json",
            "jq '.[] | debug' data.json",
            "jq 'stderr' data.json",
            "jq -n 'halt'",
            "printf '%s' -v",
            "printf -- -v",
            "head -- -f",
            "du -- -X",
            "rg -- -z pat",
            "git log -- --no-index",
            "git diff -- --output=f",
            "git ls-files -- -O",
        ] {
            clean(fine);
        }
        // but an operand is an operand
        flagged("git branch -- -x", "git:branch");
        flagged("git log --output=f -- x", "git:--output=f");
    }

    #[test]
    fn git_beyond_reading() {
        for sub in [
            "push",
            "commit -m x",
            "add .",
            "rm f",
            "mv a b",
            "reset --hard",
            "checkout x",
            "switch x",
            "restore f",
            "clean -fd",
            "merge x",
            "rebase x",
            "pull",
            "fetch",
            "clone x",
            "init",
            "apply p",
            "am p",
            "cherry-pick x",
            "revert x",
            "gc",
            "prune",
            "submodule update",
            "notes add",
            "bisect start",
            "maintenance run",
            "ls-remote origin",
            "help log",
            "branch -D x",
            "branch -d x",
            "branch -m x y",
            "branch x",
            "tag x",
            "tag -d x",
            "remote add o u",
            "remote remove o",
            "config user.name x",
            "config --unset a",
            "stash",
            "stash pop",
            "stash drop",
            "worktree add x",
            "reflog expire",
            "reflog delete",
        ] {
            flagged(&format!("git {sub}"), "git:");
        }
        flagged("git -c core.pager=x log", "git:-c");
        flagged("git --git-dir=/x log", "git:--git-dir=/x");
        flagged("git --work-tree=/x status", "git:--work-tree=/x");
        flagged("git diff --output=f", "git:--output=f");
        flagged("git log --ext-diff", "git:--ext-diff");
        flagged("git diff --textconv", "git:--textconv");
        flagged("git diff --no-index a b", "git:--no-index");
        flagged("git grep -O x", "git:-O");
        flagged("git grep -Ovim x", "git:-Ovim");
        flagged(
            "git grep --open-files-in-pager x",
            "git:--open-files-in-pager",
        );
        flagged("git log --help", "git:--help");
        flagged("git log --exec=x", "git:--exec=x");
    }

    #[test]
    fn secrets_by_name() {
        for path in [
            "~/.ssh/id_rsa",
            "/home/u/.ssh/config",
            ".ssh/known_hosts",
            "~/.aws/credentials",
            "~/.gnupg/pubring.kbx",
            "~/.kube/config",
            ".env",
            "kms/.env.local",
            "x/id_ed25519",
            "id_rsa.pub",
            "server.pem",
            "a/b/tls.key",
            "cert.p12",
            "~/.netrc",
            "~/.npmrc",
            "~/.git-credentials",
            "~/.pgpass",
            "~/.config/gh/hosts.yml",
            "~/.docker/config.json",
            "~/.copilot/config.json",
            "/etc/shadow",
            "/etc/sudoers",
            "/proc/1/environ",
            "/proc/self/mem",
            "/dev/mem",
            "/dev/sda",
            "~/.config/gcloud/credentials.db",
            "credentials.json",
        ] {
            for src in [
                format!("cat {path}"),
                format!("cat '{path}'"),
                format!("cat \"{path}\""),
                format!("ls < {path}"),
            ] {
                let found = dangers(&src);
                assert!(
                    found.iter().any(|f| f.starts_with("secret:")),
                    "{src:?}: {found:?}"
                );
            }
        }
        // escapes and quotes inside the name do not hide it
        flagged("cat ~/.s\\sh/id_rsa", "secret:");
        flagged("cat ~/.s''sh/x", "secret:");
        flagged("cat .\"env\"", "secret:");
        for fine in [
            "cat ssh.txt",
            "cat notes.env.md",
            "cat key.txt",
            "cat environment",
            "cat src/id.rs",
        ] {
            clean(fine);
        }
    }

    #[test]
    fn nothing_the_policy_may_allow_is_on_the_danger_list() {
        for name in crate::cmds::ALLOWED {
            assert!(
                !DANGEROUS.contains(name),
                "{name} is both allowed and dangerous"
            );
        }
    }

    #[test]
    fn it_does_not_panic_on_anything() {
        for src in [
            "", " ", "\n\n", "'", "\"", "`", "$", "\\", "<", ">", "&", "|", ";", "(", ")", "#",
            "!", "2>", "<<", "$(", "\u{0}",
        ] {
            let _ = dangers(src);
        }
    }
}
