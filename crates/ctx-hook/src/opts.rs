//! Strict command-line option parsing for the allow-listed commands.
//!
//! Every flag a command may carry is listed with its arity, copied from the
//! tool's own `--help` and verified against the real binary by
//! `tests/arity.rs`. A flag that is not listed rejects the command. That
//! direction matters: a flag wrongly believed to take no value would leave its
//! value to be read as an operand, and one wrongly believed to take a value
//! would let an operand skip the path checks. Long options are matched by their
//! exact name, because GNU tools also accept unambiguous abbreviations
//! (`--out` for `--output`) that a list of known names cannot see.

use crate::shell::{Reject, Res, Word};

#[derive(Clone, Copy, Debug)]
pub enum Val {
    /// 1 to 9 digits
    Num,
    /// optional sign, digits, optional size suffix (`+5`, `10K`)
    Count,
    /// short token without anything a shell or a tool would interpret
    Key,
    /// `jq --arg NAME`
    Name,
    /// exactly one character
    Char,
    Enum(&'static [&'static str]),
    /// anything, as long as the word has no unquoted wildcard
    Text,
}

#[derive(Clone, Copy, Debug)]
pub enum Arity {
    None,
    /// `-n 5`, `-n5`, `--lines 5` or `--lines=5`
    Req(Val),
    /// `--color=always` or `-U3`; the next word is never consumed
    Opt(Val),
    /// `--arg NAME VALUE`
    Two(Val, Val),
}

#[derive(Clone, Copy, Debug)]
pub struct Flag {
    pub name: &'static str,
    pub arity: Arity,
}

/// A flag without a value.
pub const fn f(name: &'static str) -> Flag {
    Flag {
        name,
        arity: Arity::None,
    }
}

/// A flag with a required value.
pub const fn v(name: &'static str, val: Val) -> Flag {
    Flag {
        name,
        arity: Arity::Req(val),
    }
}

/// A flag whose value can only be attached.
pub const fn o(name: &'static str, val: Val) -> Flag {
    Flag {
        name,
        arity: Arity::Opt(val),
    }
}

#[derive(Clone, Copy, Debug)]
pub struct Spec {
    pub flags: &'static [Flag],
    /// `-5` means a number of lines or of context.
    pub numeric: bool,
}

impl Spec {
    pub fn find(&self, name: &str) -> Option<&'static Flag> {
        self.flags.iter().find(|fl| fl.name == name)
    }
}

#[derive(Debug, Default)]
pub struct Parsed<'a> {
    /// Canonical names of the flags in the order given.
    pub flags: Vec<&'static str>,
    pub values: Vec<(&'static str, &'a str)>,
    /// Everything that is not a flag or a flag's value, `--` excluded.
    pub pos: Vec<&'a Word>,
    /// How many of `pos` came before a `--`, when there was one.
    pub split: Option<usize>,
    /// A `-NUM` flag.
    pub numeric: Option<&'a str>,
}

impl Parsed<'_> {
    pub fn has(&self, name: &str) -> bool {
        self.flags.contains(&name)
    }

    pub fn has_any(&self, names: &[&str]) -> bool {
        names.iter().any(|n| self.has(n))
    }
}

/// A reject code carrying a short, harmless excerpt of the offending text.
pub fn reject(code: &str, detail: &str) -> Reject {
    let clean: String = detail
        .chars()
        .take(32)
        .map(|c| {
            if c.is_ascii_alphanumeric() || "_.=:+-/".contains(c) {
                c
            } else {
                '?'
            }
        })
        .collect();
    Reject::new(format!("{code}:{clean}"))
}

fn digits(s: &str) -> bool {
    !s.is_empty() && s.len() <= 9 && s.bytes().all(|b| b.is_ascii_digit())
}

pub fn valid(val: Val, s: &str) -> bool {
    match val {
        Val::Num => digits(s),
        Val::Count => {
            let body = s.strip_prefix(['+', '-']).unwrap_or(s);
            let end = body
                .find(|c: char| !c.is_ascii_digit())
                .unwrap_or(body.len());
            digits(&body[..end])
                && body[end..].len() <= 2
                && body[end..].bytes().all(|b| b.is_ascii_alphabetic())
        }
        Val::Key => {
            !s.is_empty()
                && s.len() <= 64
                && s.starts_with(|c: char| c.is_ascii_alphanumeric())
                && s.chars()
                    .all(|c| c.is_ascii_alphanumeric() || "_.,:+-".contains(c))
        }
        Val::Name => {
            let mut chars = s.chars();
            chars
                .next()
                .is_some_and(|c| c.is_ascii_alphabetic() || c == '_')
                && s.len() <= 64
                && chars.all(|c| c.is_ascii_alphanumeric() || c == '_')
        }
        Val::Char => s.chars().count() == 1,
        Val::Enum(set) => set.contains(&s),
        Val::Text => s.len() <= 2048,
    }
}

fn checked<'a>(val: Val, flag: &str, text: &'a str) -> Res<&'a str> {
    if valid(val, text) {
        Ok(text)
    } else {
        Err(reject("flag-value", flag))
    }
}

/// The word after a flag, consumed as its value.
fn next_value<'a>(args: &'a [Word], i: &mut usize, flag: &str) -> Res<&'a str> {
    let word = args
        .get(*i)
        .ok_or_else(|| reject("flag-missing-value", flag))?;
    if word.glob {
        return Err(reject("glob-in-value", flag));
    }
    *i += 1;
    Ok(&word.text)
}

pub fn parse<'a>(args: &'a [Word], spec: &Spec) -> Res<Parsed<'a>> {
    let mut out = Parsed::default();
    let mut i = 0;
    let mut options_done = false;
    while i < args.len() {
        let word = &args[i];
        i += 1;
        let text = word.text.as_str();
        if options_done || text == "-" || !text.starts_with('-') {
            out.pos.push(word);
            continue;
        }
        if text == "--" {
            options_done = true;
            out.split = Some(out.pos.len());
            continue;
        }
        if word.glob {
            return Err(Reject::new("glob-in-flag"));
        }
        if let Some(long) = text.strip_prefix("--") {
            let (name, attached) = match long.split_once('=') {
                Some((n, a)) => (format!("--{n}"), Some(a)),
                None => (text.to_owned(), None),
            };
            let flag = spec
                .find(&name)
                .ok_or_else(|| reject("flag-not-allowed", &name))?;
            out.flags.push(flag.name);
            match (flag.arity, attached) {
                (Arity::None, None) | (Arity::Opt(_), None) => {}
                (Arity::None, Some(_)) => return Err(reject("flag-takes-no-value", &name)),
                (Arity::Req(val) | Arity::Opt(val), Some(a)) => {
                    out.values.push((flag.name, checked(val, &name, a)?));
                }
                (Arity::Req(val), None) => {
                    let value = next_value(args, &mut i, &name)?;
                    out.values.push((flag.name, checked(val, &name, value)?));
                }
                (Arity::Two(first, second), None) => {
                    let a = next_value(args, &mut i, &name)?;
                    out.values.push((flag.name, checked(first, &name, a)?));
                    let b = next_value(args, &mut i, &name)?;
                    out.values.push((flag.name, checked(second, &name, b)?));
                }
                (Arity::Two(..), Some(_)) => return Err(reject("flag-takes-two", &name)),
            }
            continue;
        }

        let body = &text[1..];
        if spec.numeric && digits(body) {
            out.numeric = Some(body);
            continue;
        }
        for (at, ch) in body.char_indices() {
            let name = format!("-{ch}");
            let flag = spec
                .find(&name)
                .ok_or_else(|| reject("flag-not-allowed", &name))?;
            out.flags.push(flag.name);
            let rest = &body[at + ch.len_utf8()..];
            match flag.arity {
                Arity::None => {}
                Arity::Req(val) => {
                    let value = if rest.is_empty() {
                        next_value(args, &mut i, &name)?
                    } else {
                        rest
                    };
                    out.values.push((flag.name, checked(val, &name, value)?));
                    break;
                }
                Arity::Opt(val) => {
                    if !rest.is_empty() {
                        out.values.push((flag.name, checked(val, &name, rest)?));
                    }
                    break;
                }
                Arity::Two(first, second) => {
                    if !rest.is_empty() {
                        return Err(reject("flag-takes-two", &name));
                    }
                    let a = next_value(args, &mut i, &name)?;
                    out.values.push((flag.name, checked(first, &name, a)?));
                    let b = next_value(args, &mut i, &name)?;
                    out.values.push((flag.name, checked(second, &name, b)?));
                    break;
                }
            }
        }
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::shell::lex_word;

    const SPEC: Spec = Spec {
        flags: &[
            f("-i"),
            f("-r"),
            f("--ignore-case"),
            v("-n", Val::Count),
            v("--lines", Val::Count),
            v("-e", Val::Text),
            o("--color", Val::Enum(&["auto", "always", "never"])),
            o("-U", Val::Num),
            Flag {
                name: "--arg",
                arity: Arity::Two(Val::Name, Val::Text),
            },
        ],
        numeric: true,
    };

    fn words(args: &[&str]) -> Vec<Word> {
        args.iter()
            .map(|a| lex_word(a, Some("/h")).unwrap())
            .collect()
    }

    type Outcome = (Vec<&'static str>, Vec<String>, Vec<(&'static str, String)>);

    fn run(args: &[&str]) -> Result<Outcome, String> {
        let w = words(args);
        parse(&w, &SPEC)
            .map(|p| {
                (
                    p.flags.clone(),
                    p.pos.iter().map(|x| x.text.clone()).collect(),
                    p.values
                        .iter()
                        .map(|(k, x)| (*k, (*x).to_owned()))
                        .collect(),
                )
            })
            .map_err(|e| e.0)
    }

    #[test]
    fn clusters_and_attached_values() {
        let (flags, pos, values) = run(&["-ir", "a", "b"]).unwrap();
        assert_eq!(flags, ["-i", "-r"]);
        assert_eq!(pos, ["a", "b"]);
        assert!(values.is_empty());

        let (_, pos, values) = run(&["-in5", "f"]).unwrap();
        assert_eq!(values, [("-n", "5".to_owned())]);
        assert_eq!(pos, ["f"]);

        let (_, pos, values) = run(&["-n", "5", "f"]).unwrap();
        assert_eq!(values, [("-n", "5".to_owned())]);
        assert_eq!(pos, ["f"]);

        // after a value-taking flag the rest of the cluster is the value, not more flags
        assert_eq!(run(&["-nr"]).unwrap_err(), "flag-value:-n");
    }

    #[test]
    fn long_flags_need_their_exact_name() {
        assert!(run(&["--ignore-case"]).is_ok());
        assert_eq!(run(&["--ignore"]).unwrap_err(), "flag-not-allowed:--ignore");
        assert_eq!(
            run(&["--ignore-case=1"]).unwrap_err(),
            "flag-takes-no-value:--ignore-case"
        );
        let (_, pos, values) = run(&["--lines", "7", "f"]).unwrap();
        assert_eq!(values, [("--lines", "7".to_owned())]);
        assert_eq!(pos, ["f"]);
        let (_, _, values) = run(&["--lines=+7"]).unwrap();
        assert_eq!(values, [("--lines", "+7".to_owned())]);
        assert_eq!(run(&["--lines"]).unwrap_err(), "flag-missing-value:--lines");
    }

    #[test]
    fn optional_values_never_consume_the_next_word() {
        let (flags, pos, values) = run(&["--color", "auto"]).unwrap();
        assert_eq!(flags, ["--color"]);
        assert_eq!(pos, ["auto"], "the next word stays an operand");
        assert!(values.is_empty());
        let (_, pos, values) = run(&["--color=always", "x"]).unwrap();
        assert_eq!(values, [("--color", "always".to_owned())]);
        assert_eq!(pos, ["x"]);
        assert_eq!(run(&["--color=purple"]).unwrap_err(), "flag-value:--color");
        let (_, pos, values) = run(&["-U3", "x"]).unwrap();
        assert_eq!(values, [("-U", "3".to_owned())]);
        assert_eq!(pos, ["x"]);
        let (_, pos, values) = run(&["-U", "3"]).unwrap();
        assert!(values.is_empty());
        assert_eq!(pos, ["3"]);
    }

    #[test]
    fn double_dash_and_lone_dash() {
        let (flags, pos, _) = run(&["-i", "--", "-r", "-"]).unwrap();
        assert_eq!(flags, ["-i"]);
        assert_eq!(pos, ["-r", "-"]);
        let w = words(&["a", "--", "b"]);
        let p = parse(&w, &SPEC).unwrap();
        assert_eq!(p.split, Some(1));
        let (_, pos, _) = run(&["-"]).unwrap();
        assert_eq!(pos, ["-"]);
    }

    #[test]
    fn options_are_accepted_anywhere_like_gnu_getopt() {
        let (flags, pos, _) = run(&["pattern", "file", "-i"]).unwrap();
        assert_eq!(flags, ["-i"]);
        assert_eq!(pos, ["pattern", "file"]);
    }

    #[test]
    fn numeric_flag() {
        let w = words(&["-5", "f"]);
        let p = parse(&w, &SPEC).unwrap();
        assert_eq!(p.numeric, Some("5"));
        assert_eq!(p.pos.len(), 1);
        assert_eq!(run(&["-5x"]).unwrap_err(), "flag-not-allowed:-5");
        let strict = Spec {
            numeric: false,
            ..SPEC
        };
        assert_eq!(parse(&w, &strict).unwrap_err().0, "flag-not-allowed:-5");
    }

    #[test]
    fn two_value_flags() {
        let (_, pos, values) = run(&["--arg", "k", "'some text'", "prog"]).unwrap();
        assert_eq!(
            values,
            [("--arg", "k".to_owned()), ("--arg", "some text".to_owned())]
        );
        assert_eq!(pos, ["prog"]);
        assert_eq!(
            run(&["--arg", "k"]).unwrap_err(),
            "flag-missing-value:--arg"
        );
        assert_eq!(
            run(&["--arg", "1bad", "v"]).unwrap_err(),
            "flag-value:--arg"
        );
        assert_eq!(run(&["--arg=k"]).unwrap_err(), "flag-takes-two:--arg");
    }

    #[test]
    fn unknown_flags_and_wildcards_are_refused() {
        assert_eq!(run(&["-z"]).unwrap_err(), "flag-not-allowed:-z");
        assert_eq!(run(&["-iz"]).unwrap_err(), "flag-not-allowed:-z");
        assert_eq!(run(&["-ñ"]).unwrap_err(), "flag-not-allowed:-?");
        let w = words(&["-*"]);
        assert_eq!(parse(&w, &SPEC).unwrap_err().0, "glob-in-flag");
        let w = words(&["-e", "*.rs"]);
        assert_eq!(parse(&w, &SPEC).unwrap_err().0, "glob-in-value:-e");
        let w = words(&["-e", "'*.rs'"]);
        assert!(parse(&w, &SPEC).is_ok(), "a quoted wildcard is plain text");
        let w = words(&["--lines=*"]);
        assert_eq!(parse(&w, &SPEC).unwrap_err().0, "glob-in-flag");
    }

    #[test]
    fn value_kinds() {
        assert!(valid(Val::Count, "+5") && valid(Val::Count, "-5") && valid(Val::Count, "10K"));
        assert!(!valid(Val::Count, "K") && !valid(Val::Count, "5KKK") && !valid(Val::Count, "5;"));
        assert!(valid(Val::Num, "0") && !valid(Val::Num, "-1") && !valid(Val::Num, "1234567890"));
        assert!(valid(Val::Key, "1,1nr") && !valid(Val::Key, "a b") && !valid(Val::Key, ""));
        assert!(!valid(Val::Key, "..") && !valid(Val::Key, ".env") && !valid(Val::Key, "-x"));
        assert!(valid(Val::Name, "_x1") && !valid(Val::Name, "1x") && !valid(Val::Name, "a-b"));
        assert!(valid(Val::Char, ",") && !valid(Val::Char, ",,") && !valid(Val::Char, ""));
        assert!(valid(Val::Text, "") && !valid(Val::Text, &"x".repeat(3000)));
    }

    #[test]
    fn reject_details_are_harmless() {
        let r = reject(
            "flag-not-allowed",
            "--x;rm -rf /\u{1b}[0m and a very long tail that goes on",
        );
        assert!(r.0.len() < 60);
        assert!(r.0.chars().all(|c| c.is_ascii_graphic()));
    }
}
