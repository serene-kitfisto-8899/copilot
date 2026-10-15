//! Strict shell analysis for the permission hook (PLAN.md §6.6, D8).
//!
//! tree-sitter-bash supplies the structure, but it is a parser for editors, not
//! the shell, so nothing it says is trusted blindly. The analysis is narrower
//! than the grammar and is cross-checked three ways:
//!
//!  1. Only a whitelist of node kinds is accepted. Any construct the policy does
//!     not know (expansions, substitutions, subshells, heredocs, `&`, functions,
//!     assignments, ...) rejects the whole command.
//!  2. Every byte of the command must belong to an accepted token or be a blank
//!     between tokens, so nothing can hide in a gap the parser skipped (a line
//!     continuation, a stray control character). A newline is only accepted
//!     where it separates statements.
//!  3. The value of every word is recomputed by an independent quote-aware lexer
//!     that rejects every shell metacharacter. If tree-sitter and bash disagree
//!     about where a word ends or what it means, that can only cause a rejection.
//!
//! Anything rejected here simply falls back to the normal permission prompt.

use tree_sitter::{Node, Parser};

pub const MAX_COMMAND_BYTES: usize = 8 * 1024;
pub const MAX_COMMANDS: usize = 32;

/// How a command is joined to the one before it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Join {
    First,
    And,
    Or,
    /// `;` or a newline
    Seq,
    Pipe,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Word {
    /// The value after quote removal and tilde expansion.
    pub text: String,
    /// An unquoted `*` or `?` is present, so the shell expands the word.
    pub glob: bool,
    /// The word started with an unquoted `~`, already expanded into `text`.
    pub tilde: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Cmd {
    pub join: Join,
    pub name: String,
    pub args: Vec<Word>,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Script {
    pub cmds: Vec<Cmd>,
}

/// Why a command was not analysed: a short code without spaces, e.g.
/// `node:command_substitution` or `meta:$`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Reject(pub String);

impl Reject {
    pub fn new(code: impl Into<String>) -> Self {
        Self(code.into())
    }
}

impl std::fmt::Display for Reject {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

pub type Res<T> = Result<T, Reject>;

/// Parses and strictly validates `src`. `home` is what a leading `~` expands to.
pub fn analyze(src: &str, home: Option<&str>) -> Res<Script> {
    precheck(src)?;
    let mut parser = Parser::new();
    parser
        .set_language(&tree_sitter_bash::LANGUAGE.into())
        .map_err(|_| Reject::new("grammar"))?;
    let tree = parser
        .parse(src, None)
        .ok_or_else(|| Reject::new("parse"))?;
    let root = tree.root_node();
    if root.has_error() || root.kind() != "program" {
        return Err(Reject::new("syntax"));
    }
    let mut walker = Walker {
        src,
        home,
        cursor: 0,
        cmds: Vec::new(),
        join: None,
    };
    walker.toplevel(root)?;
    walker.finish()
}

/// Control characters other than tab and newline, and every Unicode blank other
/// than a plain space, are refused: bash and the parser may disagree about them.
/// So are characters that print as nothing or reorder the text around them,
/// which can only make a command or a path look like something it is not.
fn precheck(src: &str) -> Res<()> {
    if src.len() > MAX_COMMAND_BYTES {
        return Err(Reject::new("too-long"));
    }
    for c in src.chars() {
        let blank = matches!(c, ' ' | '\t' | '\n');
        if !blank && (c.is_control() || c.is_whitespace()) {
            return Err(Reject::new("control-char"));
        }
        if invisible(c) {
            return Err(Reject::new("invisible-char"));
        }
    }
    Ok(())
}

/// Format characters (Unicode category Cf and its usual company) that have no
/// glyph: soft hyphen, zero-width and bidirectional controls, variation
/// selectors, tag characters, and the fillers that render as blanks.
fn invisible(c: char) -> bool {
    matches!(u32::from(c),
        0x00AD | 0x034F | 0x061C | 0x115F | 0x1160 | 0x17B4 | 0x17B5
        | 0x180B..=0x180F | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x206F
        | 0x3164 | 0xFE00..=0xFE0F | 0xFEFF | 0xFFA0 | 0xFFF9..=0xFFFB
        | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A | 0xE0000..=0xE0FFF)
}

struct Walker<'s> {
    src: &'s str,
    home: Option<&'s str>,
    /// End of the last consumed token; everything before it is accounted for.
    cursor: usize,
    cmds: Vec<Cmd>,
    /// Set by `&&`, `||`, `|` and `;`, consumed by the next command.
    join: Option<Join>,
}

impl<'s> Walker<'s> {
    /// Consumes a leaf token: only blanks (and newlines when `allow_nl`) may sit
    /// between it and the previous token.
    fn tok(&mut self, n: Node<'_>, allow_nl: bool) -> Res<&'s str> {
        let (start, end) = (n.start_byte(), n.end_byte());
        let gap = self
            .src
            .get(self.cursor..start)
            .ok_or_else(|| Reject::new("overlap"))?;
        let clean = gap
            .bytes()
            .all(|b| b == b' ' || b == b'\t' || (allow_nl && b == b'\n'));
        if !clean {
            return Err(Reject::new("gap"));
        }
        let text = self
            .src
            .get(start..end)
            .ok_or_else(|| Reject::new("slice"))?;
        self.cursor = end;
        Ok(text)
    }

    fn toplevel(&mut self, root: Node<'_>) -> Res<()> {
        let mut cur = root.walk();
        for child in root.children(&mut cur) {
            if child.is_named() {
                self.stmt(child)?;
            } else if child.kind() == ";" {
                self.tok(child, true)?;
                self.join = Some(Join::Seq);
            } else {
                return Err(Reject::new(format!("op:{}", child.kind())));
            }
        }
        Ok(())
    }

    fn stmt(&mut self, n: Node<'_>) -> Res<()> {
        if n.is_error() || n.is_missing() {
            return Err(Reject::new("syntax"));
        }
        match n.kind() {
            "command" => self.command(n),
            "redirected_statement" => self.redirected(n),
            "pipeline" => self.sequence(n, &[("|", Join::Pipe)]),
            "list" => self.sequence(n, &[("&&", Join::And), ("||", Join::Or)]),
            "comment" => self.comment(n),
            other => Err(Reject::new(format!("node:{other}"))),
        }
    }

    fn sequence(&mut self, n: Node<'_>, ops: &[(&str, Join)]) -> Res<()> {
        let mut cur = n.walk();
        for child in n.children(&mut cur) {
            if child.is_named() {
                self.stmt(child)?;
                continue;
            }
            let kind = child.kind();
            let Some((_, join)) = ops.iter().find(|(t, _)| *t == kind) else {
                return Err(Reject::new(format!("op:{kind}")));
            };
            self.tok(child, false)?;
            self.join = Some(*join);
        }
        Ok(())
    }

    fn comment(&mut self, n: Node<'_>) -> Res<()> {
        let start = n.start_byte();
        // A `#` only starts a comment at the beginning of a word; right after
        // other text it is part of that word and the parser's guess is suspect.
        let before = start
            .checked_sub(1)
            .and_then(|i| self.src.as_bytes().get(i).copied());
        if !matches!(
            before,
            None | Some(b' ' | b'\t' | b'\n' | b';' | b'|' | b'&')
        ) {
            return Err(Reject::new("comment-glued"));
        }
        self.tok(n, true)?;
        Ok(())
    }

    fn redirected(&mut self, n: Node<'_>) -> Res<()> {
        let mut cur = n.walk();
        for child in n.children(&mut cur) {
            match child.kind() {
                "command" => self.command(child)?,
                // The grammar hangs a trailing redirect on a whole list or
                // pipeline (`a && b 2>&1`) where bash gives it to the last
                // command. Only redirects that do nothing but move stderr or
                // reach /dev/null get through `redirect`, so wherever they land
                // changes nothing.
                "list" | "pipeline" => self.stmt(child)?,
                "file_redirect" => self.redirect(child)?,
                other => return Err(Reject::new(format!("node:{other}"))),
            }
        }
        Ok(())
    }

    /// Only `2>&1`-style duplications between stdout and stderr, and
    /// redirections from or to `/dev/null`, are harmless enough.
    fn redirect(&mut self, n: Node<'_>) -> Res<()> {
        let mut fd: Option<String> = None;
        let mut op: Option<String> = None;
        let mut cur = n.walk();
        for child in n.children(&mut cur) {
            match child.kind() {
                "file_descriptor" if fd.is_none() && op.is_none() => {
                    let text = self.tok(child, false)?;
                    if !matches!(text, "0" | "1" | "2") {
                        return Err(Reject::new("redirect-fd"));
                    }
                    fd = Some(text.to_owned());
                }
                ">" | ">>" | "&>" | "<" | ">&" if op.is_none() => {
                    self.tok(child, false)?;
                    op = Some(child.kind().to_owned());
                }
                "number" if op.as_deref() == Some(">&") => {
                    let text = self.tok(child, false)?;
                    let source_ok = fd.as_deref().is_none_or(|f| f == "1" || f == "2");
                    if !matches!(text, "1" | "2") || !source_ok {
                        return Err(Reject::new("redirect-dup"));
                    }
                }
                "word" | "string" | "raw_string" | "concatenation"
                    if matches!(op.as_deref(), Some(">" | ">>" | "&>" | "<")) =>
                {
                    let word = self.word(child)?;
                    if word.text != "/dev/null" || word.glob {
                        return Err(Reject::new("redirect-target"));
                    }
                }
                other => return Err(Reject::new(format!("redirect:{other}"))),
            }
        }
        // The destination of `>&` and of a file redirect is mandatory.
        let complete = match op.as_deref() {
            Some(">&") => n.child_count() >= 2 && n.named_child_count() >= 1,
            Some(_) => n.named_child_count() >= 1,
            None => false,
        };
        if !complete {
            return Err(Reject::new("redirect-incomplete"));
        }
        Ok(())
    }

    fn command(&mut self, n: Node<'_>) -> Res<()> {
        let mut cmd: Option<Cmd> = None;
        let mut cur = n.walk();
        for child in n.children(&mut cur) {
            match child.kind() {
                "command_name" => {
                    if cmd.is_some() {
                        return Err(Reject::new("two-names"));
                    }
                    let mut inner = child.walk();
                    let mut parts = child.children(&mut inner);
                    let (Some(word), None) = (parts.next(), parts.next()) else {
                        return Err(Reject::new("command-name"));
                    };
                    if word.kind() != "word" {
                        return Err(Reject::new(format!("name-node:{}", word.kind())));
                    }
                    let before = self.cursor;
                    let name = self.tok(word, true)?;
                    if name.is_empty()
                        || !name.chars().all(|c| {
                            c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '+' | '-' | '/')
                        })
                    {
                        return Err(Reject::new("name-chars"));
                    }
                    let gap = self.src.get(before..word.start_byte()).unwrap_or_default();
                    let join = self.next_join(gap)?;
                    cmd = Some(Cmd {
                        join,
                        name: name.to_owned(),
                        args: Vec::new(),
                    });
                }
                "word" | "number" | "string" | "raw_string" | "concatenation" => {
                    let Some(c) = cmd.as_mut() else {
                        return Err(Reject::new("argument-before-name"));
                    };
                    c.args.push(self.word(child)?);
                }
                "file_redirect" => self.redirect(child)?,
                other => return Err(Reject::new(format!("node:{other}"))),
            }
        }
        if let Some(c) = cmd {
            if self.cmds.len() >= MAX_COMMANDS {
                return Err(Reject::new("too-many-commands"));
            }
            self.cmds.push(c);
        }
        Ok(())
    }

    /// The join for the command that starts after `gap`: the pending operator,
    /// or a newline when two statements follow each other directly.
    fn next_join(&mut self, gap: &str) -> Res<Join> {
        match self.join.take() {
            Some(join) => Ok(join),
            None if self.cmds.is_empty() => Ok(Join::First),
            None if gap.contains('\n') => Ok(Join::Seq),
            None => Err(Reject::new("no-separator")),
        }
    }

    fn word(&mut self, n: Node<'_>) -> Res<Word> {
        check_word_node(n)?;
        let text = self.tok(n, false)?;
        lex_word(text, self.home)
    }

    fn finish(self) -> Res<Script> {
        let rest = self.src.get(self.cursor..).unwrap_or_default();
        if !rest.bytes().all(|b| matches!(b, b' ' | b'\t' | b'\n')) {
            return Err(Reject::new("trailing"));
        }
        if self.join.is_some() {
            return Err(Reject::new("dangling-operator"));
        }
        if self.cmds.is_empty() {
            return Err(Reject::new("empty"));
        }
        Ok(Script { cmds: self.cmds })
    }
}

/// The node itself must be a plain word, or quotes and words stuck together.
fn check_word_node(n: Node<'_>) -> Res<()> {
    match n.kind() {
        "word" | "number" | "raw_string" => Ok(()),
        "string" => check_string(n),
        "concatenation" => {
            let mut at = n.start_byte();
            let mut cur = n.walk();
            for child in n.children(&mut cur) {
                if child.start_byte() != at {
                    return Err(Reject::new("concat-gap"));
                }
                at = child.end_byte();
                match child.kind() {
                    "word" | "number" | "raw_string" => {}
                    "string" => check_string(child)?,
                    other => return Err(Reject::new(format!("node:{other}"))),
                }
            }
            if at == n.end_byte() {
                Ok(())
            } else {
                Err(Reject::new("concat-gap"))
            }
        }
        other => Err(Reject::new(format!("node:{other}"))),
    }
}

/// A double-quoted string may contain a bare `$` token (the parser's way of
/// saying "literal dollar") but no expansion of any kind.
fn check_string(n: Node<'_>) -> Res<()> {
    let mut cur = n.walk();
    for child in n.children(&mut cur) {
        match child.kind() {
            "\"" | "$" | "string_content" => {}
            other => return Err(Reject::new(format!("node:{other}"))),
        }
    }
    Ok(())
}

/// After an unquoted or double-quoted `$` these characters start an expansion.
fn starts_expansion(c: char) -> bool {
    c.is_ascii_alphanumeric()
        || matches!(
            c,
            '_' | '@' | '*' | '#' | '?' | '$' | '!' | '-' | '{' | '(' | '['
        )
}

/// Recomputes the value of one word from its source text. Unquoted shell
/// metacharacters are refused outright instead of being interpreted, which
/// keeps this lexer small enough to be obviously right.
pub fn lex_word(text: &str, home: Option<&str>) -> Res<Word> {
    let chars: Vec<char> = text.chars().collect();
    let mut out = String::new();
    let mut glob = false;
    let mut tilde = false;
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        match c {
            '\'' => {
                let close = chars[i + 1..]
                    .iter()
                    .position(|&d| d == '\'')
                    .ok_or_else(|| Reject::new("unterminated-quote"))?;
                out.extend(&chars[i + 1..i + 1 + close]);
                i += close + 2;
            }
            '"' => {
                i += 1;
                loop {
                    let Some(&d) = chars.get(i) else {
                        return Err(Reject::new("unterminated-quote"));
                    };
                    match d {
                        '"' => {
                            i += 1;
                            break;
                        }
                        '`' => return Err(Reject::new("meta:`")),
                        // history expansion, if the shell has it on, reaches into double quotes
                        '!' => return Err(Reject::new("meta:!")),
                        '\\' => match chars.get(i + 1) {
                            Some(&e @ ('$' | '`' | '"' | '\\')) => {
                                out.push(e);
                                i += 2;
                            }
                            Some('\n') | None => return Err(Reject::new("meta:\\")),
                            Some(_) => {
                                out.push('\\');
                                i += 1;
                            }
                        },
                        '$' => {
                            if chars.get(i + 1).copied().is_some_and(starts_expansion) {
                                return Err(Reject::new("meta:$"));
                            }
                            out.push('$');
                            i += 1;
                        }
                        _ => {
                            out.push(d);
                            i += 1;
                        }
                    }
                }
            }
            '$' | '`' | '\\' | '{' | '}' | '(' | ')' | '[' | ']' | '!' | '#' | ';' | '&' | '|'
            | '<' | '>' | ' ' | '\t' | '\n' => {
                return Err(Reject::new(format!("meta:{c}")));
            }
            '*' | '?' => {
                glob = true;
                out.push(c);
                i += 1;
            }
            '~' if i == 0 => {
                let home = home.ok_or_else(|| Reject::new("tilde-no-home"))?;
                match chars.get(1) {
                    None | Some('/') => {
                        out.push_str(home);
                        tilde = true;
                    }
                    Some(_) => return Err(Reject::new("tilde-user")),
                }
                i += 1;
            }
            '~' => {
                // bash also expands `~` right after `=` or `:` in plain arguments
                if matches!(chars[i - 1], '=' | ':') {
                    return Err(Reject::new("tilde-after-assign"));
                }
                out.push('~');
                i += 1;
            }
            _ => {
                out.push(c);
                i += 1;
            }
        }
    }
    Ok(Word {
        text: out,
        glob,
        tilde,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const HOME: Option<&str> = Some("/home/u");

    fn ok(src: &str) -> Script {
        match analyze(src, HOME) {
            Ok(script) => script,
            Err(why) => panic!("{src:?} was rejected: {why}"),
        }
    }

    fn rejected(src: &str) -> String {
        match analyze(src, HOME) {
            Ok(script) => panic!("{src:?} was accepted: {script:?}"),
            Err(why) => why.0,
        }
    }

    fn names(script: &Script) -> Vec<&str> {
        script.cmds.iter().map(|c| c.name.as_str()).collect()
    }

    fn args(cmd: &Cmd) -> Vec<&str> {
        cmd.args.iter().map(|w| w.text.as_str()).collect()
    }

    #[test]
    fn plain_commands_and_joins() {
        let s = ok("cd ~/kms && git log --oneline -5 | head; ls\npwd");
        assert_eq!(names(&s), ["cd", "git", "head", "ls", "pwd"]);
        let joins: Vec<_> = s.cmds.iter().map(|c| c.join).collect();
        assert_eq!(
            joins,
            [Join::First, Join::And, Join::Pipe, Join::Seq, Join::Seq]
        );
        assert_eq!(args(&s.cmds[0]), ["/home/u/kms"]);
        assert!(s.cmds[0].args[0].tilde);
        assert_eq!(args(&s.cmds[1]), ["log", "--oneline", "-5"]);
    }

    #[test]
    fn continuation_after_operators_is_a_separator() {
        let s = ok("ls &&\n  pwd ||\npwd |\nhead");
        let joins: Vec<_> = s.cmds.iter().map(|c| c.join).collect();
        assert_eq!(joins, [Join::First, Join::And, Join::Or, Join::Pipe]);
    }

    #[test]
    fn quotes_are_removed_and_globs_are_flagged() {
        let s = ok(r#"grep -rn "foo bar" 'a b' src/*.rs "x*y" plain?"#);
        let a = &s.cmds[0].args;
        assert_eq!(a[1].text, "foo bar");
        assert_eq!(a[2].text, "a b");
        assert!(a[3].glob && a[3].text == "src/*.rs");
        assert!(!a[4].glob && a[4].text == "x*y");
        assert!(a[5].glob);
    }

    #[test]
    fn dollar_is_literal_only_where_bash_agrees() {
        assert_eq!(ok(r#"grep "^a$" f"#).cmds[0].args[0].text, "^a$");
        assert_eq!(ok(r#"grep -E "a$|b" f"#).cmds[0].args[1].text, "a$|b");
        assert_eq!(ok(r#"echo "a\$b" "q\"r""#).cmds[0].args[0].text, "a$b");
        assert_eq!(ok("echo '$HOME'").cmds[0].args[0].text, "$HOME");
        for bad in [
            r#"echo "$HOME""#,
            r#"echo "${HOME}""#,
            r#"echo "$(id)""#,
            r#"echo "`id`""#,
            r#"echo "a $ b""#,
            r#"echo "$1""#,
            r#"echo "$-""#,
        ] {
            rejected(bad);
        }
    }

    #[test]
    fn expansions_and_substitutions_are_refused() {
        for bad in [
            "echo $HOME",
            "echo ${HOME}",
            "echo $(id)",
            "echo `id`",
            "echo $((1+2))",
            "diff <(ls) <(ls)",
            "ls >(cat)",
            "$(cat x) arg",
            "$PYTHON -c 1",
            "echo $'a\\nb'",
            "echo $\"loc\"",
            "echo a\"$(id)\"",
        ] {
            rejected(bad);
        }
    }

    #[test]
    fn compound_constructs_are_refused() {
        for bad in [
            "(ls)",
            "{ ls; }",
            "if true; then ls; fi",
            "for i in a; do ls; done",
            "while true; do ls; done",
            "case a in a) ls;; esac",
            "! ls",
            "ls &",
            "ls & pwd",
            "f() { ls; }",
            "FOO=1 ls",
            "FOO=1",
            "export FOO=1",
            "ls |& head",
            "echo a;; b",
            "cat <<EOF\nhi\nEOF",
            "cat <<< hi",
            "[[ -f x ]] && ls",
        ] {
            rejected(bad);
        }
    }

    #[test]
    fn redirects_are_limited_to_dup_and_dev_null() {
        ok("cat a > /dev/null 2>&1");
        ok("cat a >> /dev/null");
        ok("cat a &> /dev/null");
        ok("cat a 2>/dev/null");
        ok("cat a >&2");
        ok("cat a 1>&2");
        ok("cat < /dev/null");
        ok("grep a b 2>&1 | head");
        ok("cat a > \"/dev/null\"");
        for bad in [
            "cat a > out.txt",
            "cat a >> out.txt",
            "cat a 2> err.log",
            "cat a &> out",
            "cat a < in.txt",
            "cat a >&3",
            "cat a 3>&1",
            "cat a >| out",
            "cat a > /dev/nul",
            "cat a > /dev/null*",
            "cat a >&-",
            "cat a >&file",
            "cat a > /dev/tty",
            "cat a 4>/dev/null",
        ] {
            rejected(bad);
        }
    }

    #[test]
    fn words_cannot_smuggle_metacharacters() {
        for bad in [
            "echo a\\ b",
            "echo a\\\nb",
            "ls {a,b}",
            "ls {1..3}",
            "ls ./a[bc]",
            "echo a#b",
            "echo !x",
            "echo a!b",
            "ls ~root",
            "ls ~+/x",
            "ls ~-/x",
            "echo a=~/x",
            "echo a:~/x",
            "echo a\u{a0}b",
            "echo a\rb",
            "echo a\u{0}b",
            "echo a\u{b}b",
        ] {
            rejected(bad);
        }
        // A tilde in the middle of a word is literal in bash and common in git revisions
        assert_eq!(ok("git show HEAD~3").cmds[0].args[1].text, "HEAD~3");
        assert_eq!(ok("ls x~").cmds[0].args[0].text, "x~");
        assert!(!ok(r#"ls "~""#).cmds[0].args[0].tilde);
        assert_eq!(ok(r#"ls "~""#).cmds[0].args[0].text, "~");
    }

    #[test]
    fn syntax_errors_and_odd_input_are_refused() {
        for bad in [
            "",
            "   ",
            "\n\n",
            "echo \"unterminated",
            "echo 'unterminated",
            "ls &&",
            "&& ls",
            "ls ||",
            "| ls",
            "ls; ;",
            "ls ;;",
        ] {
            rejected(bad);
        }
        assert!(rejected(&"a".repeat(MAX_COMMAND_BYTES + 1)).contains("too-long"));
        let many = vec!["ls"; MAX_COMMANDS + 1].join("; ");
        assert_eq!(rejected(&many), "too-many-commands");
    }

    #[test]
    fn invisible_and_odd_characters_are_refused_anywhere() {
        for c in [
            '\u{200b}',
            '\u{feff}',
            '\u{ad}',
            '\u{202e}',
            '\u{2066}',
            '\u{fe0f}',
            '\u{e0041}',
            '\u{3164}',
        ] {
            for src in [
                format!("ls a{c}b"),
                format!("ls '{c}'"),
                format!("ls \"{c}\""),
                format!("echo x # {c}"),
            ] {
                assert_eq!(rejected(&src), "invisible-char", "{src:?}");
            }
        }
        for c in ['\r', '\u{b}', '\u{a0}', '\u{2028}', '\u{85}', '\0'] {
            assert_eq!(rejected(&format!("ls a{c}b")), "control-char");
        }
        // ordinary non-ASCII text is fine
        assert_eq!(
            args(&ok("ls caf\u{e9} \u{65e5}\u{672c}").cmds[0]),
            ["caf\u{e9}", "\u{65e5}\u{672c}"]
        );
    }

    #[test]
    fn comments_are_harmless_only_when_they_start_a_word() {
        assert_eq!(names(&ok("ls # why not")), ["ls"]);
        assert_eq!(names(&ok("ls; # $(id)\npwd")), ["ls", "pwd"]);
        assert_eq!(names(&ok("# just a note\nls")), ["ls"]);
        rejected("ls x#$(id)");
        rejected("echo \"a\"#$(id)");
    }

    #[test]
    fn leading_command_name_must_be_a_bare_word() {
        assert_eq!(rejected("'ls' -la"), "name-node:raw_string");
        assert_eq!(rejected("\"ls\" -la"), "name-node:string");
        assert_eq!(rejected("l\\s"), "name-chars");
        assert_eq!(rejected("~/bin/x"), "name-chars");
        assert_eq!(rejected("$x"), "name-node:simple_expansion");
        assert!(rejected("ls\\\n-la").starts_with("gap") || rejected("ls\\\n-la").contains("meta"));
        // bare path-qualified names are structurally fine; the allow-list never matches them
        assert_eq!(names(&ok("/usr/bin/ls -la")), ["/usr/bin/ls"]);
        assert_eq!(names(&ok("test -f x")), ["test"]);
    }

    #[test]
    fn no_tilde_without_home() {
        assert_eq!(analyze("ls ~/x", None).unwrap_err().0, "tilde-no-home");
        assert!(analyze("ls x~", None).is_ok());
    }

    #[test]
    fn newline_inside_a_command_is_not_a_blank() {
        // bash runs `-la` as its own command here; the analysis must not merge it
        let s = ok("ls\n-la");
        assert_eq!(names(&s), ["ls", "-la"]);
        let s = ok("echo \"multi\nline\"");
        assert_eq!(args(&s.cmds[0]), ["multi\nline"]);
    }

    #[test]
    fn lexer_unit_checks() {
        let w = lex_word("'it'\"s\"x", HOME).unwrap();
        assert_eq!(w.text, "itsx");
        assert!(!w.glob);
        assert_eq!(lex_word("~", HOME).unwrap().text, "/home/u");
        assert_eq!(lex_word("~/a", HOME).unwrap().text, "/home/u/a");
        assert!(lex_word("\"a\\nb\"", HOME).unwrap().text == "a\\nb");
        assert!(lex_word("\"unterminated", HOME).is_err());
        assert!(lex_word("a b", HOME).is_err());
    }
}
