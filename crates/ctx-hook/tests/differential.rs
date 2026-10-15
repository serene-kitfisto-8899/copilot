//! The policy against the oracle on generated command lines.
//!
//! The policy decides what may run unasked; the oracle (a lexer and lists of
//! its own, see `ctx_hook::oracle`) says whether a line could do more than
//! read. Nothing the policy allows may be flagged. A line that is, is either a
//! hole in the policy or a rule in the oracle that is too eager, and which of
//! the two is for a person to decide, so every such line is reported.
//!
//! The lines are made from words that the validators accept, mixed with words
//! that are dual-use or a trap for a parser, so that a good share of them is
//! allowed and the rest probes the edges. The generator is seeded: a failure
//! repeats. Secrets by name are not in the vocabulary: the oracle only sees a
//! name, and cannot tell a file from a pattern or a string, so they have a test
//! of their own, where each one is a file operand of every tool in turn.

mod common;

use common::World;
use ctx_hook::oracle;
use ctx_hook::policy::Verdict;
use std::collections::BTreeMap;

struct Rng(u64);

impl Rng {
    fn draw(&mut self) -> u64 {
        // xorshift64*
        self.0 ^= self.0 >> 12;
        self.0 ^= self.0 << 25;
        self.0 ^= self.0 >> 27;
        self.0.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }

    fn below(&mut self, n: usize) -> usize {
        (self.draw() % n as u64) as usize
    }

    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }

    fn chance(&mut self, percent: u64) -> bool {
        self.draw() % 100 < percent
    }
}

/// Per tool: arguments it takes in ordinary use.
const TYPICAL: &[(&str, &[&str])] = &[
    (
        "ls",
        &[
            "-l",
            "-a",
            "-la",
            "-lah",
            "-1",
            "-R",
            "-t",
            "-r",
            "-h",
            "-d",
            "-F",
            "-A",
            "-i",
            "--color=never",
            "--color=always",
            "src",
            ".",
            "README.md",
            "notes.txt",
        ],
    ),
    (
        "cat",
        &[
            "-n",
            "-A",
            "-b",
            "-s",
            "-E",
            "-T",
            "README.md",
            "notes.txt",
            "src/main.rs",
            "data.json",
            "src/lib.rs",
        ],
    ),
    (
        "grep",
        &[
            "-r",
            "-n",
            "-i",
            "-v",
            "-c",
            "-l",
            "-L",
            "-w",
            "-x",
            "-E",
            "-F",
            "-o",
            "-q",
            "-s",
            "-h",
            "-H",
            "-A2",
            "-B2",
            "-C2",
            "-e one",
            "-m 5",
            "--include=*.rs",
            "--color=never",
            "TODO",
            "'fn main'",
            "\"two\"",
            "README.md",
            "src",
            "notes.txt",
        ],
    ),
    (
        "rg",
        &[
            "-n",
            "-i",
            "-l",
            "-c",
            "-w",
            "-F",
            "-S",
            "--hidden",
            "--no-ignore",
            "-g '*.rs'",
            "-t rust",
            "-A 2",
            "TODO",
            "README.md",
            "src",
        ],
    ),
    (
        "find",
        &[
            ".",
            "src",
            "-name '*.rs'",
            "-name \"*.md\"",
            "-type f",
            "-type d",
            "-maxdepth 2",
            "-mindepth 1",
            "-iname '*.MD'",
            "-newer README.md",
            "-size +1k",
            "-empty",
            "-print",
            "-not",
            "-o",
            "-and",
        ],
    ),
    (
        "head",
        &["-n 5", "-c 10", "-q", "-v", "-3", "README.md", "notes.txt"],
    ),
    (
        "tail",
        &[
            "-n 5",
            "-n +2",
            "-c 10",
            "-q",
            "-v",
            "-3",
            "README.md",
            "notes.txt",
        ],
    ),
    ("wc", &["-l", "-w", "-c", "-m", "README.md", "notes.txt"]),
    (
        "sort",
        &[
            "-n",
            "-r",
            "-u",
            "-k 2",
            "-t ,",
            "-f",
            "-h",
            "-V",
            "-rn",
            "notes.txt",
        ],
    ),
    (
        "uniq",
        &["-c", "-d", "-u", "-i", "-f 1", "-s 2", "-w 3", "notes.txt"],
    ),
    // built by `jq()`, whose program has to be the first operand
    ("jq", &[]),
    (
        "echo",
        &[
            "hello",
            "'a b'",
            "\"c d\"",
            "-n",
            "-e",
            "'it is'",
            "a-b",
            "README.md",
        ],
    ),
    (
        "printf",
        &["'%s\\n'", "hello", "'%d'", "5", "\"%s %s\"", "a", "b"],
    ),
    ("which", &["ls", "git", "cat", "-a"]),
    (
        "stat",
        &["-c '%s'", "-c '%s %n'", "-L", "-f", "README.md", "src"],
    ),
    (
        "file",
        &["-b", "-i", "-L", "--mime-type", "README.md", "src/main.rs"],
    ),
    ("du", &["-sh", "-h", "-d 1", "-a", "-s", "-c", "src", "."]),
    (
        "readlink",
        &["-f", "-e", "-m", "src", "inside", "README.md"],
    ),
    (
        "cd",
        &[
            "src",
            ".",
            "..",
            "~/kms-two",
            "~",
            "-",
            "src/sub",
            "'src'",
            "\"src\"",
        ],
    ),
    // never allowed; the oracle has to keep saying so
    ("rm", &["-rf", "x", "README.md"]),
    ("sed", &["-i", "s/a/b/", "README.md", "-n", "1p"]),
    ("awk", &["'{print $1}'", "notes.txt"]),
    ("python3", &["-c", "'print(1)'", "x.py"]),
    ("curl", &["-s", "http://localhost", "-o", "x"]),
    ("env", &["ls", "FOO=1"]),
    ("xargs", &["-n1", "cat", "rm"]),
    ("time", &["ls", "cat"]),
    ("tee", &["out", "-a"]),
    ("touch", &["x"]),
    ("make", &["test", "-n"]),
];

/// Words that are dual-use or a trap for a parser. One of them ends a command,
/// after only whole units (a flag with its value), so it is never the value of
/// an earlier flag. Secrets by name are not here: see the test about them.
const TRICKY: &[&str] = &[
    "-f",
    "-F",
    "-z",
    "-Z",
    "-C",
    "-m",
    "-S",
    "-T",
    "-X",
    "-o",
    "-O",
    "-x",
    "-p",
    "-P",
    "-c",
    "-v",
    "-u",
    "-e",
    "-L",
    "--follow",
    "--retry",
    "--pid=1",
    "--output=out",
    "--output",
    "out",
    "--files0-from=f",
    "--exclude-from=f",
    "--pre=x",
    "--pre-glob=x",
    "--search-zip",
    "--hostname-bin=x",
    "--exec-path=x",
    "--ext-diff",
    "--textconv",
    "--no-index",
    "--open-files-in-pager",
    "--compress-program=sh",
    "--help",
    "--version",
    "-exec",
    "-execdir",
    "-ok",
    "-okdir",
    "-delete",
    "-fprint",
    "-fprintf",
    "-fls",
    "-fprint0",
    "-f prog.jq",
    "-o out",
    "-T /tmp",
    "-X ex",
    "-m magic",
    "--rawfile",
    "--slurpfile",
    "--from-file",
    "-L.",
    "-v=x",
    "..",
    "../other",
    "escape",
    "link-out",
    "innocent",
    "*",
    "'*'",
    ".*",
    "src/*",
    "dash/*",
    "-rf",
    "--",
    "-",
    "'x y'",
    "''",
    "\"\"",
    "~",
    "~/kms",
    "~/other",
    "~root",
    "/",
    "/etc",
    "/tmp",
    "/etc/passwd",
    "/dev/null",
    "$HOME",
    "$(id)",
    "`id`",
    "{a,b}",
    "a\\ b",
    "'a'\"b\"",
    "x=y",
    "!",
    "!!",
    "#",
    "# c",
    "-- --no-index",
    "-- -f",
    "-- -X",
    "-- --pre=x",
    "-- --output=f",
    "-- -exec",
    "-- -v",
];

const JOINERS: &[&str] = &[" | ", " && ", " ; ", "\n", " || ", "; ", " |& ", "&&"];

const SUFFIXES: &[&str] = &[
    " 2>&1",
    " > /dev/null",
    " 2>/dev/null",
    " &> /dev/null",
    " > out",
    " >> log",
    " < README.md",
    " &",
    " 2> err",
    " 1>&2",
];

const GIT_SUBS: &[&str] = &[
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
    "grep",
    "branch",
    "tag",
    "remote",
    "config",
    "stash",
    "worktree",
    "reflog",
    "name-rev",
    "merge-base",
    "diff-tree",
    "push",
    "commit",
    "add",
    "checkout",
    "reset",
    "clean",
    "fetch",
    "pull",
    "apply",
    "gc",
    "submodule",
    "bisect",
    "notes",
    "ls-remote",
    "rm",
    "mv",
    "switch",
    "restore",
    "init",
];

const GIT_GLOBAL: &[&str] = &[
    "-C src",
    "-C ..",
    "-C .",
    "--no-pager",
    "-P",
    "-c core.pager=x",
    "-c color.ui=never",
    "--git-dir=.git",
    "--work-tree=.",
    "--exec-path=x",
    "--no-optional-locks",
    "-p",
    "--literal-pathspecs",
    "--bare",
];

const GIT_ARGS: &[&str] = &[
    "--oneline",
    "-n 5",
    "-5",
    "--stat",
    "-p",
    "--name-only",
    "--name-status",
    "HEAD",
    "HEAD~1",
    "main",
    "origin/main",
    "-a",
    "-v",
    "-vv",
    "-l",
    "--list",
    "--get user.name",
    "--get-all user.name",
    "--",
    "src",
    "README.md",
    "'*.rs'",
    "--format=%H",
    "--pretty=oneline",
    "--graph",
    "--all",
    "--since=1.day",
    "--author=x",
    "--grep=fix",
    "-S needle",
    "-G re",
    "-i",
    "-w",
    "--no-color",
    "--color=never",
    "list",
    "show",
    "pop",
    "drop",
    "apply",
    "add",
    "remove",
];

/// Dual-use for git, to end a git command with.
const GIT_TRICKY: &[&str] = &[
    "-d",
    "-D",
    "-m",
    "-M",
    "-f",
    "--force",
    "--delete",
    "--set-upstream-to=x",
    "--unset",
    "--add",
    "-e",
    "--edit",
    "-u",
    "--no-index",
    "--output=f",
    "--ext-diff",
    "--textconv",
    "-O",
    "-Ovim",
    "--open-files-in-pager",
    "--output",
    "--exec=x",
];

const JQ_FLAGS: &[&str] = &[
    "-r",
    "-c",
    "-e",
    "-s",
    "-n",
    "-S",
    "-M",
    "--arg x y",
    "--tab",
    "--indent 1",
];

const JQ_FILES: &[&str] = &["data.json", "notes.txt", "missing.json"];

/// What the policy has to refuse is whatever reaches the environment, the
/// filesystem or the modules; `input`, `debug` and `halt` stay within the
/// named inputs and the standard streams, so they are allowed.
const JQ_PROGRAMS: &[&str] = &[
    "'.items[].name'",
    "'.a.b'",
    "'.'",
    "'.items | length'",
    "'keys'",
    "'.[] | debug'",
    "'input'",
    "'inputs'",
    "'[inputs]'",
    "'debug'",
    "'stderr'",
    "'halt'",
    "'input_line_number'",
    "'env'",
    "'$ENV.PATH'",
    "'env.HOME'",
    "'.a | env'",
    "'.x as $e | $ENV'",
    "'input_filename'",
    "'$__loc__'",
    "'$__prog_args'",
    "'import \"a\" as a; .'",
    "'include \"a\"; .'",
    "'modulemeta'",
    "'get_search_list'",
];

/// The program of jq is its first operand, and everything after it is a file,
/// so the program words must not be dealt out among the files: a file may well
/// be called `input_filename`, and the policy is right to let it be.
fn jq(rng: &mut Rng) -> String {
    let mut out = String::from("jq");
    for _ in 0..rng.below(3) {
        out.push(' ');
        out.push_str(rng.pick(JQ_FLAGS));
    }
    out.push(' ');
    out.push_str(rng.pick(JQ_PROGRAMS));
    for _ in 0..rng.below(3) {
        let list = if rng.chance(70) { JQ_FILES } else { JQ_FLAGS };
        out.push(' ');
        out.push_str(rng.pick(list));
    }
    if rng.chance(35) {
        out.push(' ');
        out.push_str(rng.pick(TRICKY));
    }
    if rng.chance(7) {
        out.push_str(rng.pick(SUFFIXES));
    }
    out
}

fn command(rng: &mut Rng) -> String {
    // the slots past the table are git, which is built differently
    let slot = rng.below(TYPICAL.len() + 8);
    let Some(&(name, typical)) = TYPICAL.get(slot) else {
        return git(rng);
    };
    if name == "jq" {
        return jq(rng);
    }
    let mut out = name.to_owned();
    for _ in 0..rng.below(5) {
        out.push(' ');
        out.push_str(rng.pick(typical));
    }
    if rng.chance(35) {
        out.push(' ');
        out.push_str(rng.pick(TRICKY));
    }
    if rng.chance(7) {
        out.push_str(rng.pick(SUFFIXES));
    }
    out
}

fn git(rng: &mut Rng) -> String {
    let mut out = String::from("git");
    if rng.chance(25) {
        out.push(' ');
        out.push_str(rng.pick(GIT_GLOBAL));
    }
    out.push(' ');
    out.push_str(rng.pick(GIT_SUBS));
    for _ in 0..rng.below(5) {
        out.push(' ');
        out.push_str(rng.pick(GIT_ARGS));
    }
    if rng.chance(40) {
        out.push(' ');
        out.push_str(if rng.chance(60) {
            rng.pick(GIT_TRICKY)
        } else {
            rng.pick(TRICKY)
        });
    }
    if rng.chance(7) {
        out.push_str(rng.pick(SUFFIXES));
    }
    out
}

fn line(rng: &mut Rng) -> String {
    let parts = match rng.below(100) {
        0..45 => 1,
        45..80 => 2,
        _ => 3,
    };
    let mut out = command(rng);
    for _ in 1..parts {
        out.push_str(rng.pick(JOINERS));
        out.push_str(&command(rng));
    }
    // The parser hangs a redirect at the end of a line on the whole list or
    // pipeline rather than on its last command; the policy has to look through.
    if parts > 1 && rng.chance(25) {
        out.push_str(rng.pick(SUFFIXES));
    }
    out
}

#[test]
fn nothing_the_policy_allows_is_flagged_by_the_oracle() {
    const LINES: usize = 250_000;
    let world = World::new();
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut allowed = 0usize;
    let mut by_tool: BTreeMap<String, usize> = BTreeMap::new();
    let mut disagreements: BTreeMap<String, (usize, String)> = BTreeMap::new();
    for _ in 0..LINES {
        let src = line(&mut rng);
        let Verdict::Allow { .. } = world.eval(&src, "kms") else {
            continue;
        };
        allowed += 1;
        for name in src.split(|c: char| !c.is_ascii_alphanumeric() && c != '-') {
            if ctx_hook::cmds::ALLOWED.contains(&name) && src.starts_with(name) {
                *by_tool.entry(name.to_owned()).or_default() += 1;
                break;
            }
        }
        let found = oracle::dangers(&src);
        if !found.is_empty() {
            let entry = disagreements
                .entry(found.join(","))
                .or_insert_with(|| (0, src.clone()));
            entry.0 += 1;
        }
    }
    eprintln!("allowed {allowed} of {LINES}; by first tool: {by_tool:?}");
    assert!(
        allowed > LINES / 25,
        "only {allowed} of {LINES} lines were allowed: the test is not probing much"
    );
    let total: usize = disagreements.values().map(|(n, _)| n).sum();
    assert!(
        disagreements.is_empty(),
        "{total} allowed lines were flagged by the oracle (of {allowed} allowed), by flags:\n{}",
        disagreements
            .iter()
            .map(|(flags, (n, example))| format!("{flags}: {n}, e.g. {example:?}"))
            .collect::<Vec<_>>()
            .join("\n")
    );
}

/// Each of these is a real secret in the world, or is refused by its name
/// wherever it is. The oracle cannot judge them in the test above: it sees
/// only the name, and a name given to `echo` or as a pattern to `grep` is
/// harmless. Here every `{}` is a file operand, so each combination has to be
/// refused, whichever tool reads it and however the name is spelled.
const SECRETS: &[&str] = &[
    ".env",
    "./.env",
    "src/../.env",
    "../kms/.env",
    "~/kms/.env",
    "'.env'",
    "\".env\"",
    ".en\"v\"",
    "./'.env'",
    ".env*",
    ".e*",
    ".*",
    ".?nv",
    ".en?",
    "server.pem",
    "server.key",
    "id_rsa",
    "plain.key",
    "*.pem",
    "*.key",
    "id_*",
    "ser*",
    "*",
    "~/.ssh/id_rsa",
    "~/.ssh/config",
    "~/.ssh",
    "../.ssh/config",
    "../.aws/credentials",
    "~/.aws/credentials",
    "~/.aws",
    "/etc/shadow",
    "/proc/self/environ",
    "/dev/sda",
    "../other/secret.txt",
    "../other",
];

/// Links of the world that lead to a secret, or out of the trusted roots. A
/// tool that opens a file follows them, so each of those has to refuse them;
/// git does not follow a link, so for git they are allowed (see the last test).
const LINKS: &[&str] = &["innocent", "link-out", "escape", "escape/secret.txt"];

/// `{}` is always a file the tool opens or walks.
const READERS: &[&str] = &[
    "ls {}",
    "ls -la {}",
    "ls -R {}",
    "ls -d {}",
    "cat {}",
    "cat -n {}",
    "cat -- {}",
    "cat README.md {}",
    "cat {} README.md",
    "cat {} | head -n 5",
    "head {}",
    "head -n 5 {}",
    "tail {}",
    "tail -n 3 {}",
    "wc -l {}",
    "wc -c {}",
    "sort {}",
    "sort -rn {}",
    "uniq {}",
    "uniq -c {}",
    "jq . {}",
    "jq -r '.a' {}",
    "grep -n x {}",
    "grep -r x {}",
    "grep -e x {}",
    "grep x README.md {}",
    "grep -f {} README.md",
    "grep -rn --include='*.rs' x {}",
    "rg x {}",
    "rg -n x {}",
    "rg -f {} src",
    "rg -e x {}",
    "rg --ignore-file {} x",
    "find {}",
    "find {} -name x",
    "find . -newer {}",
    "find . -samefile {}",
    "find {} -type f",
    "file {}",
    "file -b {}",
    "stat {}",
    "stat -c %s {}",
    "du {}",
    "du -sh {}",
    "readlink -f {}",
    "readlink {}",
    "git log -- {}",
    "git diff -- {}",
    "git blame {}",
    "git ls-files {}",
    "git status {}",
    "git grep x -- {}",
    "git log -p -- {}",
    "git show HEAD -- {}",
    "cd {}",
    "cd {} && ls",
    "cd {} && cat README.md",
    "ls && cat {}",
    "ls | cat {}",
];

#[test]
fn no_tool_reads_a_secret_however_the_name_is_spelled() {
    let world = World::new();
    let mut tried = 0usize;
    let mut allowed = Vec::new();
    for template in READERS {
        let links: &[&str] = if template.starts_with("git ") {
            &[]
        } else {
            LINKS
        };
        for secret in SECRETS.iter().chain(links) {
            let src = template.replace("{}", secret);
            tried += 1;
            if let Verdict::Allow { tags } = world.eval(&src, "kms") {
                allowed.push(format!("{src:?} was allowed as {tags}"));
            }
        }
    }
    assert!(tried > 2_000, "only {tried} combinations were tried");
    assert!(
        allowed.is_empty(),
        "{} of {tried} secret reads were allowed:\n{}",
        allowed.len(),
        allowed.join("\n")
    );
}

/// Git commands that name a link, to be run for real.
const GIT_LINK_READERS: &[&str] = &[
    "log -- {}",
    "log -p -- {}",
    "log --stat -p -- {}",
    "diff -- {}",
    "diff HEAD -- {}",
    "diff --cached -- {}",
    "diff -p --stat -- {}",
    "show HEAD -- {}",
    "show -p HEAD -- {}",
    "show HEAD:{}",
    "blame {}",
    "blame -- {}",
    "blame HEAD -- {}",
    "ls-files {}",
    "ls-files -s {}",
    "ls-files -- {}",
    "status {}",
    "status -- {}",
    "status --short -- {}",
];

/// What the policy leaves to git: a link named in a git command is allowed,
/// because git does not follow one in the work tree. It shows where the link
/// points (the text of the link), never what is there. The policy depends on
/// that, since it resolves the links in the operands of every other tool but
/// not in git's. So this runs the real git, in a real repository whose links
/// lead to canaries (and one of them is changed and staged), on every such
/// command that the policy allows, and looks for the canaries in the output.
#[test]
fn git_shows_where_a_link_points_and_never_what_it_leads_to() {
    use ctx_hook::policy::evaluate;
    use ctx_hook::trust::{DEFAULT_DENY, DEFAULT_ROOTS, Trust};
    use ctx_hook::vars::Vars;
    use std::os::unix::fs::symlink;
    use std::process::Command;

    let strings = |list: &[&str]| -> Vec<String> { list.iter().map(|s| (*s).to_owned()).collect() };
    let tmp = tempfile::TempDir::new().unwrap();
    let home = std::fs::canonicalize(tmp.path()).unwrap().join("home");
    let repo = home.join("kms");
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::create_dir_all(home.join("other")).unwrap();
    std::fs::write(repo.join(".env"), "CANARY-ENV\n").unwrap();
    std::fs::write(repo.join("README.md"), "plain\n").unwrap();
    std::fs::write(home.join("other/secret.txt"), "CANARY-OTHER\n").unwrap();

    let run = |program: &str, args: &[&str]| {
        Command::new(program)
            .args(args)
            .current_dir(&repo)
            .env("HOME", &home)
            .env("GIT_CONFIG_NOSYSTEM", "1")
            .env("GIT_CONFIG_GLOBAL", "/dev/null")
            .env("GIT_TERMINAL_PROMPT", "0")
            .output()
            .unwrap_or_else(|e| panic!("cannot run {program}: {e}"))
    };
    let git_ok = |args: &[&str]| {
        let out = run("git", args);
        assert!(
            out.status.success(),
            "git {args:?} failed: {}",
            String::from_utf8_lossy(&out.stderr)
        );
    };

    git_ok(&["init", "-q"]);
    for link in ["innocent", "escape", "link-out"] {
        symlink("README.md", repo.join(link)).unwrap();
    }
    git_ok(&["add", "README.md", "innocent", "escape", "link-out"]);
    git_ok(&[
        "-c",
        "user.name=t",
        "-c",
        "user.email=t@example.com",
        "-c",
        "commit.gpgsign=false",
        "commit",
        "-q",
        "-m",
        "one",
    ]);
    for (link, target) in [
        ("innocent", ".env"),
        ("escape", "../other"),
        ("link-out", "../other/secret.txt"),
    ] {
        std::fs::remove_file(repo.join(link)).unwrap();
        symlink(target, repo.join(link)).unwrap();
    }
    git_ok(&["add", "escape"]);

    // the links do lead to the canaries, or the test would prove nothing
    for path in ["innocent", "link-out", "escape/secret.txt"] {
        let out = run("cat", &[path]);
        assert!(
            String::from_utf8_lossy(&out.stdout).contains("CANARY"),
            "{path} does not lead to a canary"
        );
    }

    let trust = Trust::new(&home, &strings(DEFAULT_ROOTS), &strings(DEFAULT_DENY)).unwrap();
    let vars = Vars::fixed(&[]);
    let mut checked = 0usize;
    let mut leaked = Vec::new();
    for template in GIT_LINK_READERS {
        for link in LINKS {
            let src = format!("git {}", template.replace("{}", link));
            let Verdict::Allow { .. } = evaluate(&src, Some(&repo), &home, &trust, &vars) else {
                continue;
            };
            let args: Vec<&str> = src.split_whitespace().skip(1).collect();
            let out = run("git", &args);
            checked += 1;
            let text = [out.stdout, out.stderr].concat();
            if String::from_utf8_lossy(&text).contains("CANARY") {
                leaked.push(src);
            }
        }
    }
    eprintln!("ran {checked} git commands that name a link");
    assert!(
        checked >= 30,
        "the policy allowed only {checked} of the commands: the test is not looking at much"
    );
    assert!(leaked.is_empty(), "git printed a canary for:\n{leaked:#?}");
}
