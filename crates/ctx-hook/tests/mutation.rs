//! Mutation test for the shell analyzer. Every command here is allowed as it
//! stands; a dangerous fragment is then spliced in at every position, and none
//! of the results may be allowed. The fragments are dangerous wherever they
//! land, so a hole shows up as an allow, whichever parser quirk caused it.
//!
//! Inside quotes a fragment is first let out of the quote (`'` + fragment +
//! `'`), because inside single quotes nothing is dangerous, and a harmless
//! allow there would be a false alarm.

mod common;

use common::World;
use ctx_hook::oracle;
use ctx_hook::policy::Verdict;
use std::collections::BTreeMap;

const BASE: &[&str] = &[
    "ls",
    "ls -la src",
    "ls 2>&1",
    "ls > /dev/null",
    "cat README.md",
    "cat -n README.md src/main.rs",
    "cat README.md | head -n 5",
    "grep -rn 'fn main' src",
    "grep -e one -e \"two\" README.md",
    "grep --color=never -i todo README.md",
    "sort notes.txt | uniq -c | sort -rn | head -20",
    "wc -l README.md",
    "find . -name '*.rs' -type f",
    "find src -maxdepth 2 -name \"*.rs\"",
    "jq '.items[].name' data.json",
    "jq -r '.a.b' data.json",
    "stat -c '%s %n' README.md",
    "file README.md",
    "du -sh src",
    "head -n 5 README.md",
    "tail -n 3 notes.txt",
    "echo hello",
    "echo 'a b' \"c d\"",
    "which ls",
    "readlink -f src",
    "rg -n todo README.md",
    "git status",
    "git log --oneline -n 5",
    "git log --grep='fix' --oneline",
    "git diff --stat | tail -1",
    "git show HEAD:README.md",
    "cd src && ls",
    "cd ~/kms-two && git log --oneline",
    "cd src && cat main.rs | wc -l",
    "ls ; cat README.md",
    "cat README.md\nls src",
];

/// Dangerous anywhere outside quotes, even in the middle of a word.
const ANYWHERE: &[&str] = &[
    ";rm -rf x;",
    "&&rm x&&",
    "||rm x||",
    "|sh|",
    "|bash -s",
    "&rm x&",
    "\nrm x\n",
    "\n\nrm x",
    ">f",
    ">>f",
    "2>f",
    "&>f",
    "<f",
    "<<EOF",
    "<<<x",
    "$(id)",
    "`id`",
    "${x}",
    "$x",
    "$((1+1))",
    "$[1]",
    "<(id)",
    ">(id)",
    "$'\\x41'",
    "{a,b}",
    "{1..3}",
    "(id)",
    "((1))",
    "\\;rm x",
    "!!",
    "!rm",
];

/// Whitespace and control characters a parser may or may not count as a
/// separator; harmful at any position, quoted or not.
const ODD: &[&str] = &[
    "\r",
    "\x0b",
    "\x0c",
    "\0",
    "\x1b[31m",
    "\u{a0}",
    "\u{85}",
    "\u{2028}",
    "\u{200b}",
    "\u{3000}",
    "\u{feff}",
    "\u{202e}",
    "\u{ad}",
    "\u{2066}",
    "\u{fe0f}",
    "\u{e0041}",
    "\u{200d}",
    "\u{2060}",
];

/// Only dangerous when they start a word.
const WORD_START: &[&str] = &["~root", "~+", "~-", "~nobody/x", "#x\nrm x\n"];

/// Wrappers that would run the command that follows, or something else.
const PREFIXES: &[&str] = &[
    "sudo ",
    "env ",
    "time ",
    "nohup ",
    "command ",
    "exec ",
    "xargs ",
    "nice ",
    "timeout 5 ",
    "stdbuf -o0 ",
    "busybox ",
    "builtin ",
    "eval ",
    "bash -c ",
    "sh -c ",
    "watch ",
    "FOO=bar ",
    "LD_PRELOAD=x ",
    "PATH=/tmp ",
    "! ",
    "{ ",
    "( ",
    "if ",
    "while ",
    "for ",
    "until ",
    "case ",
    "function ",
    "[[ ",
    "coproc ",
    "select ",
    "\\",
    "-",
    "--",
];

#[derive(Clone, Copy, PartialEq)]
enum Quote {
    Out,
    Single,
    Double,
}

/// The quote state before each byte offset (the bases are plain ASCII).
fn states(s: &str) -> Vec<Quote> {
    let mut out = Vec::with_capacity(s.len() + 1);
    let mut q = Quote::Out;
    for c in s.chars() {
        out.push(q);
        q = match (q, c) {
            (Quote::Out, '\'') => Quote::Single,
            (Quote::Out, '"') => Quote::Double,
            (Quote::Single, '\'') | (Quote::Double, '"') => Quote::Out,
            (q, _) => q,
        };
    }
    out.push(q);
    out
}

fn splice(s: &str, at: usize, piece: &str) -> String {
    format!("{}{}{}", &s[..at], piece, &s[at..])
}

/// Offsets where a command starts: the beginning, and after `|`, `&&`, `;`, a newline.
fn command_starts(s: &str, q: &[Quote]) -> Vec<usize> {
    let bytes = s.as_bytes();
    let mut out = Vec::new();
    let mut after_operator = true;
    for (i, &b) in bytes.iter().enumerate() {
        if q[i] != Quote::Out {
            after_operator = false;
            continue;
        }
        match b {
            b' ' | b'\t' => {}
            b'|' | b'&' | b';' | b'\n' => after_operator = true,
            _ => {
                if after_operator {
                    out.push(i);
                }
                after_operator = false;
            }
        }
    }
    out
}

fn word_starts(s: &str, q: &[Quote]) -> Vec<usize> {
    let bytes = s.as_bytes();
    (0..=bytes.len())
        .filter(|&i| q[i] == Quote::Out && (i == 0 || matches!(bytes[i - 1], b' ' | b'\t')))
        .collect()
}

struct Mutant {
    /// What was spliced in, before any quoting around it.
    fragment: String,
    text: String,
}

fn mutations(base: &str) -> Vec<Mutant> {
    let q = states(base);
    let mut out = Vec::new();
    let mut add = |fragment: &str, text: String| {
        out.push(Mutant {
            fragment: fragment.to_owned(),
            text,
        });
    };
    for (at, state) in q.iter().enumerate() {
        match state {
            Quote::Out => {
                for f in ANYWHERE.iter().chain(&["'", "\""]) {
                    add(f, splice(base, at, f));
                }
            }
            Quote::Single => {
                for f in ANYWHERE {
                    add(f, splice(base, at, &format!("'{f}'")));
                }
            }
            Quote::Double => {
                for f in ANYWHERE {
                    add(f, splice(base, at, &format!("\"{f}\"")));
                }
                // inside double quotes these are live without leaving them
                for f in ["$(id)", "`id`", "${x}", "$x", "$((1))", "$[1]", "!rm", "!!"] {
                    add(f, splice(base, at, f));
                }
            }
        }
        for f in ODD {
            add(f, splice(base, at, f));
        }
    }
    for at in word_starts(base, &q) {
        for f in WORD_START {
            add(f, splice(base, at, &format!("{f} ")));
        }
    }
    for at in command_starts(base, &q) {
        for f in PREFIXES {
            add(f, splice(base, at, f));
        }
    }
    out
}

#[test]
fn the_base_commands_are_allowed_to_begin_with() {
    let world = World::new();
    let refused: Vec<String> = BASE
        .iter()
        .filter_map(|cmd| match world.eval(cmd, "kms") {
            Verdict::Allow { .. } => None,
            Verdict::Pass { code } => Some(format!("{cmd:?}: {code}")),
        })
        .collect();
    assert!(
        refused.is_empty(),
        "a mutation test needs allowed commands:\n{}",
        refused.join("\n")
    );
}

#[test]
fn no_dangerous_fragment_gets_through_anywhere() {
    let world = World::new();
    let mut tried = 0usize;
    let mut leaks = Vec::new();
    for base in BASE {
        assert!(
            !base.contains('\\'),
            "{base:?}: the quote tracker does not model escapes"
        );
        for mutated in mutations(base) {
            tried += 1;
            if let Verdict::Allow { tags } = world.eval(&mutated.text, "kms") {
                leaks.push(format!(
                    "{:?}\n    from {base:?}, allowed as {tags}",
                    mutated.text
                ));
            }
        }
    }
    assert!(tried > 20_000, "only {tried} mutations were tried");
    assert!(
        leaks.is_empty(),
        "{} of {tried} dangerous mutations were allowed:\n{}",
        leaks.len(),
        leaks
            .iter()
            .take(40)
            .cloned()
            .collect::<Vec<_>>()
            .join("\n")
    );
}

#[test]
fn the_oracle_agrees_the_base_commands_are_harmless() {
    let flagged: Vec<String> = BASE
        .iter()
        .filter_map(|cmd| {
            let found = oracle::dangers(cmd);
            (!found.is_empty()).then(|| format!("{cmd:?}: {found:?}"))
        })
        .collect();
    assert!(
        flagged.is_empty(),
        "the oracle is too eager, or a base is not harmless:\n{}",
        flagged.join("\n")
    );
}

/// The policy is the only judge in the test above, so a mutant it refuses for
/// the wrong reason would pass unnoticed. The oracle is a second judge, built
/// without the analyzer: it has to see what each fragment adds by itself, or
/// its silence about a real command means little.
///
/// `<f` is the one fragment it may ignore: reading a plain file is a read. The
/// policy still refuses it, because it has no way to vouch for the file, and
/// the oracle still flags it when the file is a secret by name.
#[test]
fn the_oracle_sees_what_the_mutations_add() {
    let mut tried = 0usize;
    let mut quiet: BTreeMap<String, (usize, String)> = BTreeMap::new();
    for base in BASE {
        for mutated in mutations(base) {
            tried += 1;
            if mutated.fragment != "<f" && oracle::dangers(&mutated.text).is_empty() {
                quiet
                    .entry(mutated.fragment)
                    .or_insert_with(|| (0, mutated.text))
                    .0 += 1;
            }
        }
    }
    let silent: usize = quiet.values().map(|(n, _)| n).sum();
    assert!(
        quiet.is_empty(),
        "the oracle said nothing about {silent} of {tried} dangerous mutations, by fragment:\n{}",
        quiet
            .iter()
            .map(|(f, (n, e))| format!("{f:?}: {n}, e.g. {e:?}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}
