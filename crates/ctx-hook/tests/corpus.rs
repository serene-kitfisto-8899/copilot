//! The adversarial corpus for the permission policy (PLAN.md §6.6).
//!
//! Every pass is asserted with the reason it passes for, so a case cannot start
//! passing by accident for a different reason than the one it exists to test.

mod common;

use common::World;
use ctx_hook::policy::Verdict;
use ctx_hook::vars::Vars;

/// `Ok(tags)` for an allow, `Err(code prefix)` for a pass.
type Expect = Result<&'static str, &'static str>;

struct Case {
    cwd: &'static str,
    cmd: &'static str,
    expect: Expect,
}

const fn allow(cmd: &'static str, tags: &'static str) -> Case {
    Case {
        cwd: "kms",
        cmd,
        expect: Ok(tags),
    }
}

const fn pass(cmd: &'static str, code: &'static str) -> Case {
    Case {
        cwd: "kms",
        cmd,
        expect: Err(code),
    }
}

const fn allow_in(cwd: &'static str, cmd: &'static str, tags: &'static str) -> Case {
    Case {
        cwd,
        cmd,
        expect: Ok(tags),
    }
}

const fn pass_in(cwd: &'static str, cmd: &'static str, code: &'static str) -> Case {
    Case {
        cwd,
        cmd,
        expect: Err(code),
    }
}

fn run(cases: &[Case]) {
    let world = World::new();
    let mut wrong = Vec::new();
    for c in cases {
        let got = world.eval(c.cmd, c.cwd);
        let ok = match (&c.expect, &got) {
            (Ok(tags), Verdict::Allow { tags: t }) => t == tags,
            (Err(prefix), Verdict::Pass { code }) => code.starts_with(prefix),
            _ => false,
        };
        if !ok {
            wrong.push(format!(
                "[{}] {:?}\n    wanted {:?}\n    got    {}",
                c.cwd,
                c.cmd,
                c.expect,
                got.rule()
            ));
        }
    }
    assert!(
        wrong.is_empty(),
        "{} of {} cases differ:\n{}",
        wrong.len(),
        cases.len(),
        wrong.join("\n")
    );
}

#[test]
fn ordinary_read_only_work_is_allowed() {
    run(&[
        allow("ls", "ls"),
        allow("ls -la", "ls"),
        allow("ls -l src", "ls"),
        allow("ls src/", "ls"),
        allow("ls ~/kms", "ls"),
        allow("ls ~/kms-two", "ls"),
        allow("ls inside", "ls"),
        allow("ls -1 --color=never", "ls"),
        allow("ls 2>/dev/null", "ls"),
        allow("ls 2>&1", "ls"),
        allow("ls > /dev/null", "ls"),
        allow("ls && ls 2>&1", "ls"),
        allow("git status && git log 2>/dev/null", "git-status+git-log"),
        allow("cat README.md | head -n 5 2>&1", "cat+head"),
        allow("grep x notes.txt || echo none > /dev/null", "grep+echo"),
        allow("cat README.md", "cat"),
        allow("cat -n README.md src/main.rs", "cat"),
        allow("cat README.md | head -n 5", "cat+head"),
        allow(
            "cat notes.txt | grep -n a | sort | uniq -c | sort -rn | head -20",
            "cat+grep+sort+uniq+head",
        ),
        allow("cat nonexistent.txt", "cat"),
        allow("cat ~/kms/./README.md", "cat"),
        allow("cat README*", "cat"),
        allow("cat src/*.rs", "cat"),
        allow("grep -rn TODO src", "grep"),
        allow("grep -n 'fn main' src/main.rs", "grep"),
        allow("grep -rIl --include='*.rs' fn .", "grep"),
        allow("grep -c TODO README.md", "grep"),
        allow("grep -E '^(a|b)$' notes.txt", "grep"),
        allow("grep -v \"^$\" notes.txt", "grep"),
        allow("grep -E \"\\.(rs|toml)$\" notes.txt | head", "grep+head"),
        allow("grep -e one -e two README.md", "grep"),
        allow("grep -A2 -B 1 TODO README.md", "grep"),
        allow("grep -3 TODO README.md", "grep"),
        allow("grep --color=never TODO README.md", "grep"),
        allow("grep foo", "grep"),
        allow("echo hello | grep h", "echo+grep"),
        allow("grep x notes.txt || echo none", "grep+echo"),
        allow("rg TODO", "rg"),
        allow("rg -n 'fn main' src", "rg"),
        allow("rg --files", "rg"),
        allow("rg -t rust fn src", "rg"),
        allow("rg -g '*.rs' fn", "rg"),
        allow("rg -e one -e two", "rg"),
        allow("rg --json fn src | head", "rg+head"),
        allow("rg --color never -n fn src", "rg"),
        allow("head README.md", "head"),
        allow("head -n 5 README.md", "head"),
        allow("head -5 README.md", "head"),
        allow("head -c 100 README.md", "head"),
        allow("head -n -1 README.md", "head"),
        allow("tail -n 20 README.md", "tail"),
        allow("tail -20 README.md", "tail"),
        allow("tail -n +2 README.md", "tail"),
        allow("wc -l README.md", "wc"),
        allow("wc -l src/*.rs", "wc"),
        allow("sort notes.txt", "sort"),
        allow("sort -u -k 2 notes.txt", "sort"),
        allow("sort -t , -k2,2n notes.txt", "sort"),
        allow("uniq notes.txt", "uniq"),
        allow("uniq -c notes.txt", "uniq"),
        allow("stat README.md", "stat"),
        allow("stat -c '%s' README.md", "stat"),
        allow("file README.md", "file"),
        allow("file -b --mime-type README.md", "file"),
        allow("du -sh .", "du"),
        allow("du -h --max-depth=1 src", "du"),
        allow("du -sh", "du"),
        allow("readlink -f inside", "readlink"),
        allow("jq . data.json", "jq"),
        allow("jq '.a.b' data.json", "jq"),
        allow("jq -r '.items[] | .name' data.json", "jq"),
        allow("jq --arg k a '.[$k]' data.json", "jq"),
        allow("jq -n '1 + 1'", "jq"),
        allow("find . -name '*.rs'", "find"),
        allow("find src -type f -name '*.rs' -mtime -7", "find"),
        allow("find . -maxdepth 2 -type d", "find"),
        allow("find . -type f -size +1k", "find"),
        allow("find . -name '*.rs' -newer README.md", "find"),
        allow("find . -path './src/*' -prune -o -type f -print", "find"),
        allow("find . -name '*.rs' -o -name '*.md'", "find"),
        allow("find", "find"),
        allow("find -name x", "find"),
        allow("echo hi", "echo"),
        allow("echo 'a; b'", "echo"),
        allow("echo -n x", "echo"),
        allow(r#"printf '%s\n' hello"#, "printf"),
        allow("printf 'a b c\\n'", "printf"),
        allow("which cargo", "which"),
        allow("which -a ls", "which"),
    ]);
}

#[test]
fn read_only_git_is_allowed() {
    run(&[
        allow("git status", "git-status"),
        allow("git status --short", "git-status"),
        allow("git status -sb", "git-status"),
        allow("git log", "git-log"),
        allow("git log --oneline -n 5", "git-log"),
        allow("git log --oneline -5", "git-log"),
        allow("git log -n 5 --stat", "git-log"),
        allow("git log -p -n 1", "git-log"),
        allow("git log --format=%H -n 1", "git-log"),
        allow("git log --author=alice --since=2.weeks", "git-log"),
        allow("git log main..HEAD", "git-log"),
        allow("git log HEAD~3..HEAD", "git-log"),
        allow("git log -- src", "git-log"),
        allow("git log --follow -- src/main.rs", "git-log"),
        allow("git log -S fn -- src", "git-log"),
        allow("git log --grep=fix --oneline", "git-log"),
        allow("git show", "git-show"),
        allow("git show HEAD", "git-show"),
        allow("git show HEAD~1:src/main.rs", "git-show"),
        allow("git show HEAD --stat", "git-show"),
        allow("git show v1.0.0", "git-show"),
        allow("git diff", "git-diff"),
        allow("git diff --stat", "git-diff"),
        allow("git diff HEAD~1", "git-diff"),
        allow("git diff HEAD~1 HEAD -- src", "git-diff"),
        allow("git diff --cached", "git-diff"),
        allow("git diff main...HEAD", "git-diff"),
        allow("git diff -U5 README.md", "git-diff"),
        allow("git diff -w --name-only", "git-diff"),
        allow("git branch", "git-branch"),
        allow("git branch -a", "git-branch"),
        allow("git branch -vv", "git-branch"),
        allow("git branch --list main", "git-branch"),
        allow("git branch --show-current", "git-branch"),
        allow("git rev-parse HEAD", "git-rev-parse"),
        allow("git rev-parse --show-toplevel", "git-rev-parse"),
        allow("git rev-parse --abbrev-ref HEAD", "git-rev-parse"),
        allow("git rev-parse --git-dir", "git-rev-parse"),
        allow("git ls-files", "git-ls-files"),
        allow("git ls-files src", "git-ls-files"),
        allow("git ls-files -o --exclude-standard", "git-ls-files"),
        allow("git blame src/main.rs", "git-blame"),
        allow("git blame -L 1,10 src/main.rs", "git-blame"),
        allow("git describe --tags", "git-describe"),
        allow("git describe --always --dirty", "git-describe"),
        allow("git --no-pager log", "git-log"),
        allow("git -P log -n 1", "git-log"),
        allow("git -C ~/kms-two log", "git-log"),
        allow("git -C src status", "git-status"),
        allow("git -C ../pr-7 log", "git-log"),
        allow("git log | head -5", "git-log+head"),
        allow("git diff --stat | tail -1", "git-diff+tail"),
        allow_in("kms/src", "git log --oneline", "git-log"),
        allow_in("kms/src/sub", "git status", "git-status"),
        allow_in("pr-7", "git status", "git-status"),
        allow_in("work", "git -C ~/kms status", "git-status"),
    ]);
}

#[test]
fn cd_into_a_trusted_directory_then_work() {
    run(&[
        allow("cd src && ls", "cd+ls"),
        allow("cd ~/kms-two && git log --oneline", "cd+git-log"),
        allow("cd ~/kms && ls | head", "cd+ls+head"),
        allow("cd src && cat main.rs | wc -l", "cd+cat+wc"),
        allow("cd src && cd sub && cat deep.txt", "cd+cat"),
        allow("cd ./src && ls", "cd+ls"),
        allow("cd inside && ls", "cd+ls"),
        allow("cd to-two && cat a.txt", "cd+cat"),
        allow("cd src && git log --oneline", "cd+git-log"),
        allow("ls; ls", "ls"),
        allow("ls && ls", "ls"),
        allow("ls\nls", "ls"),
        allow("cat README.md || echo none", "cat+echo"),
        allow("ls; cd src && ls", "ls+cd"),
        allow_in("work", "cd ~/kms && ls", "cd+ls"),
        allow_in("work", "cat ~/kms/README.md", "cat"),
        allow_in("/tmp", "cat ~/kms/README.md", "cat"),
    ]);
}

#[test]
fn commands_that_are_not_on_the_list() {
    run(&[
        pass("rm -rf x", "cmd-not-allowed:rm"),
        pass("mv a b", "cmd-not-allowed:mv"),
        pass("cp a b", "cmd-not-allowed:cp"),
        pass("tee out", "cmd-not-allowed:tee"),
        pass("curl http://example.com", "cmd-not-allowed:curl"),
        pass("wget http://example.com", "cmd-not-allowed:wget"),
        pass("ssh host", "cmd-not-allowed:ssh"),
        pass("scp a b", "cmd-not-allowed:scp"),
        pass("sudo ls", "cmd-not-allowed:sudo"),
        pass("python3 -c 1", "cmd-not-allowed:python3"),
        pass("node -e 1", "cmd-not-allowed:node"),
        pass("perl -e 1", "cmd-not-allowed:perl"),
        pass("ruby -e 1", "cmd-not-allowed:ruby"),
        pass("awk '{print}' README.md", "cmd-not-allowed:awk"),
        pass("sed -n 1p README.md", "cmd-not-allowed:sed"),
        pass("sed -i s/a/b/ README.md", "cmd-not-allowed:sed"),
        pass("xargs ls", "cmd-not-allowed:xargs"),
        pass("env", "cmd-not-allowed:env"),
        pass("env ls", "cmd-not-allowed:env"),
        pass("sh -c ls", "cmd-not-allowed:sh"),
        pass("bash -c ls", "cmd-not-allowed:bash"),
        pass("eval ls", "cmd-not-allowed:eval"),
        pass("exec ls", "cmd-not-allowed:exec"),
        pass("source x", "cmd-not-allowed:source"),
        pass(". x", "cmd-not-allowed:."),
        pass("time ls", "cmd-not-allowed:time"),
        pass("timeout 5 ls", "cmd-not-allowed:timeout"),
        pass("nohup ls", "cmd-not-allowed:nohup"),
        pass("nice ls", "cmd-not-allowed:nice"),
        pass("make", "cmd-not-allowed:make"),
        pass("cargo build", "cmd-not-allowed:cargo"),
        pass("docker ps", "cmd-not-allowed:docker"),
        pass("systemctl status x", "cmd-not-allowed:systemctl"),
        pass("kill 1", "cmd-not-allowed:kill"),
        pass("chmod +x x", "cmd-not-allowed:chmod"),
        pass("dd if=/dev/zero of=x", "cmd-not-allowed:dd"),
        pass("tar xf x", "cmd-not-allowed:tar"),
        pass("mkdir x", "cmd-not-allowed:mkdir"),
        pass("touch x", "cmd-not-allowed:touch"),
        pass("ln -s a b", "cmd-not-allowed:ln"),
        pass("tr a b", "cmd-not-allowed:tr"),
        pass("cut -d, -f1 README.md", "cmd-not-allowed:cut"),
        pass("diff a b", "cmd-not-allowed:diff"),
        pass("less README.md", "cmd-not-allowed:less"),
        pass("vi x", "cmd-not-allowed:vi"),
        pass("test -f x", "cmd-not-allowed:test"),
        pass("true", "cmd-not-allowed:true"),
        pass("pwd", "cmd-not-allowed:pwd"),
        pass("pushd src", "cmd-not-allowed:pushd"),
        pass("popd", "cmd-not-allowed:popd"),
        pass("/bin/ls", "cmd-not-allowed:/bin/ls"),
        pass("./ls", "cmd-not-allowed:./ls"),
        pass("ls; rm x", "cmd-not-allowed:rm"),
        pass("ls && rm x", "cmd-not-allowed:rm"),
        pass("ls || rm x", "cmd-not-allowed:rm"),
        pass("ls | rm x", "cmd-not-allowed:rm"),
        pass("ls\nrm x", "cmd-not-allowed:rm"),
        pass("cat README.md | sh", "cmd-not-allowed:sh"),
        pass("echo x | xargs rm", "cmd-not-allowed:xargs"),
        pass("echo x | python3", "cmd-not-allowed:python3"),
    ]);
}

#[test]
fn shell_features_that_cannot_be_judged() {
    run(&[
        pass("echo $(whoami)", "node:command_substitution"),
        pass("echo `whoami`", "node:command_substitution"),
        pass("cat $(ls)", "node:command_substitution"),
        pass("echo $HOME", "node:simple_expansion"),
        pass("echo ${HOME}", "node:expansion"),
        pass("echo \"$HOME\"", "node:simple_expansion"),
        pass("echo \"a $(b)\"", "node:command_substitution"),
        pass("cat $x", "node:simple_expansion"),
        pass("$x", "name-node"),
        pass("$(ls)", "name-node"),
        pass("\"ls\" x", "name-node"),
        pass("X=1 ls", "node:variable_assignment"),
        pass("X=1", "node:variable_assignment"),
        pass("export X=1", "node:declaration_command"),
        pass("ls > out", "redirect"),
        pass("ls >> out", "redirect"),
        pass("ls > /dev/nullx", "redirect"),
        pass("ls && ls > out", "redirect-target"),
        pass("ls && ls 2> /dev/nullx", "redirect-target"),
        pass("cat README.md | head >> out", "redirect-target"),
        pass("ls && git push 2>&1", "git-subcommand"),
        pass("ls && ls 2>&1 | xargs rm", "cmd-not-allowed:xargs"),
        pass("ls && ls <<EOF\nx\nEOF", "node:"),
        pass("ls && ls 3>&1", "redirect"),
        pass("ls < /etc/passwd", "redirect"),
        pass("ls 2> out", "redirect"),
        pass("ls &> out", "redirect"),
        pass("ls >& out", "redirect"),
        pass("ls 3>&1", "redirect"),
        pass("ls 1>&-", "redirect"),
        pass("cat <<EOF\nx\nEOF", "node:"),
        pass("cat <<< x", "node:"),
        pass("ls &", "op:&"),
        pass("ls & ls", "op:&"),
        pass("(ls)", "node:subshell"),
        pass("{ ls; }", "node:compound_statement"),
        pass("! ls", "node:negated_command"),
        pass("if true; then ls; fi", "node:if_statement"),
        pass("for i in 1; do ls; done", "node:for_statement"),
        pass("while true; do ls; done", "node:while_statement"),
        pass("case x in x) ls;; esac", "node:case_statement"),
        pass("f() { ls; }", "node:function_definition"),
        pass("ls |& cat", "op:"),
        pass("cat <(echo)", "node:process_substitution"),
        pass("ls $'\\x41'", "node:ansi_c_string"),
        pass("ls $\"x\"", "node:$"),
        pass("ls {a,b}", "meta:"),
        pass("ls ~root", "tilde"),
        pass("ls ~+", "tilde"),
        pass("ls ~-", "tilde"),
        pass("ls a=~/x", "tilde"),
        pass("ls a:~/x", "tilde"),
        pass("ls a\\\nb", "gap"),
        pass("echo \"unterminated", "syntax"),
        pass("echo 'unterminated", "syntax"),
        pass("", "empty"),
        pass("   ", "empty"),
        pass("\n\n", "empty"),
        pass("# just a comment", "empty"),
        allow("ls # comment", "ls"),
        pass("ls\0", "control-char"),
        pass("ls\r", "control-char"),
        pass("ls\u{000b}-la", "control-char"),
        pass("ls\u{00a0}-la", "control-char"),
        pass("ls\u{2028}-la", "control-char"),
        pass("echo a\u{1b}[0mb", "control-char"),
        pass("ls [a-z]*", "meta"),
        allow("ls ^x", "ls"),
        pass("echo !!", "meta"),
        pass("echo \"!x\"", "meta:!"),
        pass("echo \"a!\"", "meta:!"),
        pass("grep \"!important\" README.md", "meta:!"),
        allow("echo '!x'", "echo"),
        allow("grep '!important' README.md", "grep"),
        pass("echo a\\ b", "meta"),
    ]);
}

#[test]
fn limits_on_size_and_count() {
    let world = World::new();
    let many = vec!["ls"; 40].join(" && ");
    assert!(
        matches!(world.eval(&many, "kms"), Verdict::Pass { code } if code.starts_with("too-many"))
    );
    let thirty_two = vec!["ls"; 32].join(" && ");
    assert!(world.eval(&thirty_two, "kms").is_allow());
    let long = format!("echo {}", "a".repeat(9000));
    assert!(matches!(world.eval(&long, "kms"), Verdict::Pass { code } if code == "too-long"));
}

#[test]
fn paths_outside_the_trusted_roots() {
    run(&[
        pass("cat /etc/passwd", "path-untrusted"),
        pass("cat ../other/secret.txt", "path-untrusted"),
        pass("cat ../../etc/passwd", "path-untrusted"),
        pass("cat ~/.ssh/config", "path-untrusted"),
        pass("cat ~/.aws/credentials", "path-untrusted"),
        pass("cat ~/kms/../other/secret.txt", "path-untrusted"),
        pass("cat //etc/passwd", "path-untrusted"),
        pass("cat ~", "path-untrusted"),
        pass("cat /proc/self/environ", "path-untrusted"),
        pass("ls /", "path-untrusted"),
        pass("ls ~", "path-untrusted"),
        pass("ls ..", "path-untrusted"),
        pass("ls /tmp", "path-untrusted"),
        pass("ls -R /", "path-untrusted"),
        pass("ls ~/kms ~/other", "path-untrusted"),
        pass("grep -r x /", "path-untrusted"),
        pass("grep -r x ~", "path-untrusted"),
        pass("grep -r x ..", "path-untrusted"),
        pass("grep x /etc/passwd", "path-untrusted"),
        pass("rg x /etc", "path-untrusted"),
        pass("rg --files ..", "path-untrusted"),
        pass("find / -name x", "path-untrusted"),
        pass("find ~ -name x", "path-untrusted"),
        pass("find .. -name x", "path-untrusted"),
        pass("find . -newer /etc/passwd", "path-untrusted"),
        pass("find . -samefile /etc/passwd", "path-untrusted"),
        pass("head /etc/passwd", "path-untrusted"),
        pass("tail /var/log/syslog", "path-untrusted"),
        pass("wc /etc/passwd", "path-untrusted"),
        pass("sort /etc/passwd", "path-untrusted"),
        pass("stat /etc/passwd", "path-untrusted"),
        pass("stat -f /", "path-untrusted"),
        pass("file /bin/ls", "path-untrusted"),
        pass("du /", "path-untrusted"),
        pass("readlink /etc/passwd", "path-untrusted"),
        pass("jq . /etc/passwd", "path-untrusted"),
        pass("cat README.md /etc/passwd", "path-untrusted"),
        pass("cat -- /etc/passwd", "path-untrusted"),
        pass_in("work", "ls", "path-untrusted"),
        pass_in("work", "cat x.txt", "path-untrusted"),
        pass_in("other", "cat secret.txt", "path-untrusted"),
        pass_in(".", "ls", "path-untrusted"),
        pass_in("/tmp", "ls", "path-untrusted"),
        pass_in("/", "ls", "path-untrusted"),
    ]);
}

#[test]
fn symlinks_are_judged_by_where_they_lead() {
    run(&[
        pass("cat link-out", "path-untrusted"),
        pass("cat escape/secret.txt", "path-untrusted"),
        pass("ls escape", "path-untrusted"),
        pass("grep -r x escape", "path-untrusted"),
        pass("cat innocent", "path-denied"),
        pass("cat plain.key", "path-denied"),
        pass("cat esc*", "path-untrusted"),
        pass("cat link*", "path-untrusted"),
        pass("cd escape && ls", "path-untrusted"),
        pass("cd link-out && ls", "path-untrusted"),
        pass_in("kms/escape", "ls", "path-untrusted"),
        pass_in("kms/escape", "cat secret.txt", "path-untrusted"),
        pass_in("kms/escape", "cat secret.txt", "path-untrusted"),
        pass("git -C escape log", "path-untrusted"),
        allow_in("kms/to-two", "cat a.txt", "cat"),
        allow_in("kms/inside", "cat main.rs", "cat"),
    ]);
}

#[test]
fn secrets_by_name_are_refused() {
    run(&[
        pass("cat .env", "path-denied"),
        pass("cat ./.env", "path-denied"),
        pass("cat src/../.env", "path-denied"),
        pass("cat ~/kms/.env", "path-denied"),
        pass("cat server.pem", "path-denied"),
        pass("cat server.key", "path-denied"),
        pass("cat id_rsa", "path-denied"),
        pass("head -n 1 .env", "path-denied"),
        pass("grep SECRET .env", "path-denied"),
        pass("grep -n x README.md .env", "path-denied"),
        pass("rg SECRET .env", "path-denied"),
        pass("jq . .env", "path-denied"),
        pass("stat .env", "path-denied"),
        pass("file server.key", "path-denied"),
        pass("wc -c .env", "path-denied"),
        pass("sort .env", "path-denied"),
        pass("find . -newer .env", "path-denied"),
        pass("cat *", "path-denied"),
        pass("cat s*", "path-denied"),
        pass("cat *.key", "path-denied"),
        pass("cat *.pem", "path-denied"),
        pass("cat id_*", "path-denied"),
        pass("git show HEAD:.env", "path-denied"),
        pass("git show HEAD:server.pem", "path-denied"),
        pass("git diff HEAD -- .env", "path-denied"),
        pass("git log -- .env", "path-denied"),
        pass("git blame .env", "path-denied"),
        pass("git status .env", "path-denied"),
        pass("git ls-files server.key", "path-denied"),
    ]);
}

#[test]
fn wildcards_are_expanded_and_every_match_is_judged() {
    run(&[
        pass("cat *", "path-denied"),
        pass("cd dash && cat *", "glob-dash-name"),
        pass("cat dash/*", "glob-dash-name"),
        pass("cat */secret.txt", "glob-in-directory"),
        pass("cat src/*/deep.txt", "glob-in-directory"),
        pass("cat .*", "glob-dotfile"),
        pass("cat ./.*", "glob-dotfile"),
        pass("cat src/.*", "glob-dotfile"),
        pass("ls [a-z]*", "meta"),
        pass("cat ~/*", "path-untrusted"),
        pass("cat /etc/*", "path-untrusted"),
        pass("grep x *", "path-denied"),
        pass("echo *", "glob-in-echo"),
        pass("printf * ", "glob-in-printf"),
        allow("grep 'a' *.md", "grep"),
        pass("grep a* README.md", "glob-in-pattern"),
        pass("jq .* data.json", "glob-in-pattern"),
        pass("find . -name *.rs", "glob-in-value"),
        allow("find . *.rs", "find"),
        pass("git log *", "git-glob"),
        pass("head -n 5* README.md", "glob-in-value"),
        pass("ls --color=* x", "glob-in-flag"),
        allow("cat README.*", "cat"),
        allow("cat src/?ain.rs", "cat"),
        allow("ls src/*.rs", "ls"),
        allow("wc -l data/*", "wc"),
    ]);
}

#[test]
fn flags_that_read_write_or_run_things() {
    run(&[
        pass("grep -f /etc/passwd x README.md", "flag-not-allowed:-f"),
        pass("grep --file=/etc/passwd x", "flag-not-allowed:--file"),
        pass(
            "grep --exclude-from=x y README.md",
            "flag-not-allowed:--exclude-from",
        ),
        pass(
            "grep --exclude-fr=x y README.md",
            "flag-not-allowed:--exclude-fr",
        ),
        pass("grep -R x .", "flag-not-allowed:-R"),
        pass("grep -d recurse x .", "flag-not-allowed:-d"),
        pass("grep --recur x .", "flag-not-allowed:--recur"),
        pass(
            "grep --dereference-recursive x .",
            "flag-not-allowed:--dereference-recursive",
        ),
        pass("grep -E", "no-pattern"),
        pass("grep -m x foo README.md", "flag-value"),
        pass("grep -m", "flag-missing-value"),
        pass("grep --color=sometimes x README.md", "flag-value"),
        pass("grep -rn", "no-pattern"),
        pass("grep --exclude-dir", "flag-missing-value"),
        pass("sort -o out notes.txt", "flag-not-allowed:-o"),
        pass("sort --output=out notes.txt", "flag-not-allowed:--output"),
        pass("sort --out=out notes.txt", "flag-not-allowed:--out"),
        pass("sort -T /tmp notes.txt", "flag-not-allowed:-T"),
        pass(
            "sort --compress-program=sh notes.txt",
            "flag-not-allowed:--compress-program",
        ),
        pass("sort --files0-from=x", "flag-not-allowed:--files0-from"),
        pass(
            "sort --random-source=x notes.txt",
            "flag-not-allowed:--random-source",
        ),
        pass("sort -R notes.txt", "flag-not-allowed:-R"),
        pass("tail -f README.md", "flag-not-allowed:-f"),
        pass("tail -F README.md", "flag-not-allowed:-F"),
        pass("tail --follow README.md", "flag-not-allowed:--follow"),
        pass("tail --pid=1 README.md", "flag-not-allowed:--pid"),
        pass("tail -s 1 README.md", "flag-not-allowed:-s"),
        pass("tail --retry README.md", "flag-not-allowed:--retry"),
        pass("tail -n x README.md", "flag-value"),
        pass("head -n", "flag-missing-value"),
        pass("uniq notes.txt out.txt", "uniq-output-operand"),
        pass("wc --files0-from=x", "flag-not-allowed:--files0-from"),
        pass("du -X x", "flag-not-allowed:-X"),
        pass("du --files0-from=x", "flag-not-allowed:--files0-from"),
        pass("du -L .", "flag-not-allowed:-L"),
        pass("stat -L README.md", "flag-not-allowed:-L"),
        pass("file -f x", "flag-not-allowed:-f"),
        pass("file -m x README.md", "flag-not-allowed:-m"),
        pass("file -z README.md", "flag-not-allowed:-z"),
        pass("file -C", "flag-not-allowed:-C"),
        pass("ls -I x", "flag-not-allowed:-I"),
        pass("ls --hide=x", "flag-not-allowed:--hide"),
        pass("ls -w 10", "flag-not-allowed:-w"),
        pass("ls -T 5", "flag-not-allowed:-T"),
        pass("ls -L", "flag-not-allowed:-L"),
        pass("ls -H", "flag-not-allowed:-H"),
        pass("ls --dereference", "flag-not-allowed:--dereference"),
        pass("ls --block-size=1", "flag-not-allowed:--block-size"),
        pass("ls --colo=never", "flag-not-allowed:--colo"),
        pass("ls --sort=bogus", "flag-value"),
        pass("rg --pre cat x", "flag-not-allowed:--pre"),
        pass("rg --pre=cat x", "flag-not-allowed:--pre"),
        pass("rg --pre-glob '*' x", "flag-not-allowed:--pre-glob"),
        pass("rg -z x", "flag-not-allowed:-z"),
        pass("rg --search-zip x", "flag-not-allowed:--search-zip"),
        pass("rg -f patterns", "flag-not-allowed:-f"),
        pass("rg --file=patterns", "flag-not-allowed:--file"),
        pass(
            "rg --hostname-bin=x --stats y",
            "flag-not-allowed:--hostname-bin",
        ),
        pass("rg --ignore-file=x y", "flag-not-allowed:--ignore-file"),
        pass("rg --config-path x", "flag-not-allowed:--config-path"),
        pass("rg --no-ignore x", "flag-not-allowed:--no-ignore"),
        pass("rg --follow x", "flag-not-allowed:--follow"),
        pass("rg -L x", "flag-not-allowed:-L"),
        pass("rg --files --foo", "flag-not-allowed:--foo"),
        pass("rg -e", "flag-missing-value"),
        pass("rg", "no-pattern"),
        pass("jq -f prog.jq data.json", "flag-not-allowed:-f"),
        pass(
            "jq --from-file prog.jq data.json",
            "flag-not-allowed:--from-file",
        ),
        pass(
            "jq --rawfile a /etc/passwd . data.json",
            "flag-not-allowed:--rawfile",
        ),
        pass(
            "jq --slurpfile a /etc/passwd . data.json",
            "flag-not-allowed:--slurpfile",
        ),
        pass("jq -L /tmp . data.json", "flag-not-allowed:-L"),
        pass("jq --args . a", "flag-not-allowed:--args"),
        pass("jq --jsonargs . 1", "flag-not-allowed:--jsonargs"),
        pass("jq '$ENV.HOME' data.json", "jq-program:ENV"),
        pass("jq -n env", "jq-program:env"),
        pass("jq -n 'env.PATH'", "jq-program:env"),
        pass("jq 'input_filename' data.json", "jq-program:input_filename"),
        pass("jq 'import \"x\" as x; .' data.json", "jq-program:import"),
        pass("jq 'include \"x\"; .' data.json", "jq-program:include"),
        pass("jq -n '$__loc__'", "jq-program:"),
        pass("jq -n '$__prog_args'", "jq-program:"),
        pass("jq --arg a", "flag-missing-value"),
        pass("jq --arg 1x v .", "flag-value"),
        pass("jq", "no-program"),
        pass("jq -f", "flag-not-allowed:-f"),
        pass("printf -v x y", "printf-v"),
        pass("printf -vx y", "printf-v"),
        pass("printf", "no-format"),
        pass("which /bin/ls", "which-arg"),
        pass("which -x ls", "which-arg"),
        pass("which ''", "which-arg"),
        pass("find . -exec rm {} ;", "meta:{"),
        pass("find . -exec rm {} +", "meta:{"),
        pass("find . -execdir x ;", "dangling-operator"),
        pass("find . -ok rm {} ;", "meta:{"),
        pass("find . -okdir x ;", "dangling-operator"),
        pass("find . -exec rm '{}' \\;", "meta:\\"),
        pass("find . -exec rm '{}' +", "find-primary:-exec"),
        pass("find . -execdir x \\;", "meta:\\"),
        pass("find . -ok rm '{}' \\;", "meta:\\"),
        pass("find . -okdir x \\;", "meta:\\"),
        pass("find . -name x -exec cat '{}' \\;", "meta:\\"),
        pass("find . -exec rm '{}' ';'", "find-primary:-exec"),
        pass("find . -execdir x ';'", "find-primary:-execdir"),
        pass("find . -ok rm '{}' ';'", "find-primary:-ok"),
        pass("find . -okdir x ';'", "find-primary:-okdir"),
        pass("find . -name x -exec cat '{}' ';'", "find-primary:-exec"),
        pass("find . -delete", "find-primary:-delete"),
        pass("find . -fprint x", "find-primary:-fprint"),
        pass("find . -fprint0 x", "find-primary:-fprint0"),
        pass("find . -fprintf x y", "find-primary:-fprintf"),
        pass("find . -fls x", "find-primary:-fls"),
        pass("find -files0-from x", "find-primary:-files0-from"),
        pass("find . -exe x", "find-primary:-exe"),
        pass("find -L .", "find-primary:-L"),
        pass("find -H .", "find-primary:-H"),
        pass("find -D all .", "find-primary:-D"),
        pass("find . -name", "find-missing-arg"),
        pass("find . -size big", "find-value"),
        pass("find . -maxdepth x", "find-value"),
        pass("find . -newer", "find-missing-arg"),
        pass("find . -newerXY x", "find-primary:-newerXY"),
        pass("find . -newerat x y", "find-primary"),
    ]);
}

#[test]
fn git_commands_that_write_run_or_read_elsewhere() {
    run(&[
        pass("git -c core.pager=x log", "git-global-flag:-c"),
        pass("git -ccore.pager=x log", "git-global-flag:-ccore.pager"),
        pass("git --git-dir=x log", "git-global-flag:--git-dir"),
        pass("git --work-tree=x log", "git-global-flag:--work-tree"),
        pass("git --exec-path=x log", "git-global-flag:--exec-path"),
        pass("git --paginate log", "git-global-flag:--paginate"),
        pass("git -p log", "git-global-flag:-p"),
        pass("git --namespace=x log", "git-global-flag:--namespace"),
        pass("git --bare log", "git-global-flag:--bare"),
        pass("git --config-env=x=y log", "git-global-flag:--config-env"),
        pass("git --super-prefix=x log", "git-global-flag"),
        pass("git --no-index diff", "git-global-flag:--no-index"),
        pass("git -C /etc log", "path-untrusted"),
        pass("git -C ../other log", "path-untrusted"),
        pass("git -C escape log", "path-untrusted"),
        pass("git -C ~ log", "path-untrusted"),
        pass("git -C ~/kms -C ~/kms-two log", "git-multiple-C"),
        pass("git -C", "git-C-missing"),
        pass("git -C README.md log", "not-a-directory"),
        pass("git -C * log", "glob-in-value"),
        pass("git", "git-no-subcommand"),
        pass("git --no-pager", "git-no-subcommand"),
        pass("git log --output=x", "flag-not-allowed:--output"),
        pass("git diff --output=x", "flag-not-allowed:--output"),
        pass("git show --output=x HEAD", "flag-not-allowed:--output"),
        pass("git diff --no-index a b", "flag-not-allowed:--no-index"),
        pass("git diff --ext-diff", "flag-not-allowed:--ext-diff"),
        pass("git diff -O orderfile", "flag-not-allowed:-O"),
        pass("git diff -Oorderfile", "flag-not-allowed:-O"),
        pass("git log --paginate", "flag-not-allowed:--paginate"),
        pass("git log --exec=x", "flag-not-allowed:--exec"),
        pass("git log --upload-pack=x", "flag-not-allowed:--upload-pack"),
        pass("git log --open-files-in-pager", "flag-not-allowed"),
        pass("git log --glob=x", "flag-not-allowed:--glob"),
        pass("git log --abbrev-commi", "flag-not-allowed:--abbrev-commi"),
        pass("git log --onelin", "flag-not-allowed:--onelin"),
        pass("git log --stat-width=x", "flag-not-allowed"),
        pass("git diff /etc/passwd /etc/hosts", "git-word-start"),
        pass("git diff ../a ../b", "git-dotdot"),
        pass("git diff a/../b", "git-dotdot"),
        pass("git diff -- ../x", "git-dotdot"),
        pass("git diff ~/x ~/y", "git-tilde"),
        pass("git diff --cached -- ../x", "git-dotdot"),
        pass("git log -- ~/.ssh/id_rsa", "git-tilde"),
        pass("git log -- /etc/passwd", "git-word-start"),
        pass("git show HEAD:../x", "git-dotdot"),
        pass("git show :/x", "git-word-start"),
        pass("git show :0:file", "git-word-start"),
        pass("git show /etc/passwd", "git-word-start"),
        pass("git show HEAD:/etc/passwd", "git-rev-abs"),
        pass("git log HEAD^{/x}", "meta:{"),
        pass("git log 'a b'", "git-chars"),
        pass("git log 'a;b'", "git-chars"),
        pass("git log $x", "node:simple_expansion"),
        pass("git log -- ':(top)x'", "git-chars"),
        pass("git log -- ':!x'", "git-chars"),
        pass("git log ''", "git-word-length"),
        pass("git branch newbranch", "git-branch-create"),
        pass("git branch -d x", "flag-not-allowed:-d"),
        pass("git branch -D x", "flag-not-allowed:-D"),
        pass("git branch -m a b", "flag-not-allowed:-m"),
        pass("git branch -c a b", "flag-not-allowed:-c"),
        pass("git branch --delete x", "flag-not-allowed:--delete"),
        pass(
            "git branch --set-upstream-to=x",
            "flag-not-allowed:--set-upstream-to",
        ),
        pass(
            "git branch --edit-description",
            "flag-not-allowed:--edit-description",
        ),
        pass("git branch --contains x", "flag-not-allowed:--contains"),
        pass(
            "git blame --contents x README.md",
            "flag-not-allowed:--contents",
        ),
        pass(
            "git blame --ignore-revs-file x README.md",
            "flag-not-allowed:--ignore-revs-file",
        ),
        pass("git blame -S x README.md", "flag-not-allowed:-S"),
        pass("git blame a b c", "git-blame-operands"),
        pass("git blame .env", "path-denied"),
        pass("git blame ../x", "git-dotdot"),
        pass("git ls-files -X x", "flag-not-allowed:-X"),
        pass(
            "git ls-files --exclude-from=x",
            "flag-not-allowed:--exclude-from",
        ),
        pass(
            "git ls-files --exclude-per-directory=.gitignore",
            "flag-not-allowed",
        ),
        pass("git rev-parse --git-path x", "flag-not-allowed:--git-path"),
        pass("git rev-parse -- x", "git-rev-parse-dashdash"),
        pass("git status ../x", "git-dotdot"),
        pass("git checkout x", "git-subcommand:checkout"),
        pass("git commit", "git-subcommand:commit"),
        pass("git push", "git-subcommand:push"),
        pass("git pull", "git-subcommand:pull"),
        pass("git fetch", "git-subcommand:fetch"),
        pass("git reset --hard", "git-subcommand:reset"),
        pass("git clean -fd", "git-subcommand:clean"),
        pass("git add .", "git-subcommand:add"),
        pass("git stash", "git-subcommand:stash"),
        pass("git remote -v", "git-subcommand:remote"),
        pass("git config --list", "git-subcommand:config"),
        pass("git config user.name x", "git-subcommand:config"),
        pass("git grep foo", "git-subcommand:grep"),
        pass("git archive HEAD", "git-subcommand:archive"),
        pass("git worktree list", "git-subcommand:worktree"),
        pass("git tag", "git-subcommand:tag"),
        pass("git cat-file -p HEAD", "git-subcommand:cat-file"),
        pass("git clone x", "git-subcommand:clone"),
        pass("git init", "git-subcommand:init"),
        pass("git submodule update", "git-subcommand:submodule"),
        pass("git help log", "git-subcommand:help"),
        pass("git --version", "git-global-flag:--version"),
        pass_in("work", "git log", "path-untrusted"),
        pass_in("work", "git status", "path-untrusted"),
        pass_in("other", "git log", "git-no-repo"),
        pass_in("/tmp", "git log", "git-no-repo"),
    ]);
}

#[test]
fn cd_that_could_leave_the_trusted_roots_or_the_judged_directory() {
    run(&[
        pass("cd /etc && ls", "path-untrusted"),
        pass("cd .. && ls", "cd-dotdot"),
        pass("cd src/.. && ls", "cd-dotdot"),
        pass("cd ../other && ls", "cd-dotdot"),
        pass("cd ~ && ls", "path-untrusted"),
        pass("cd && ls", "cd-args"),
        pass("cd - && ls", "cd-flag"),
        pass("cd -P src && ls", "cd-args"),
        pass("cd -- src && ls", "cd-args"),
        pass("cd src sub && ls", "cd-args"),
        pass("cd * && ls", "glob-in-cd"),
        pass("cd s* && ls", "glob-in-cd"),
        pass("cd escape && ls", "path-untrusted"),
        pass("cd link-out && ls", "path-untrusted"),
        pass("cd README.md && ls", "not-a-directory"),
        pass("cd nonexistent && ls", "not-a-directory"),
        pass("cd '' && ls", "cd-flag"),
        pass("cd src; ls", "cd-then-unconditional"),
        pass("cd src\nls", "cd-then-unconditional"),
        pass("cd src && ls; ls", "cd-then-unconditional"),
        pass("cd src || ls", "cd-with-or"),
        pass("ls || cd src && ls", "cd-with-or"),
        pass("ls && cd src || ls", "cd-with-or"),
        pass("cd src | ls", "cd-in-pipeline"),
        pass("ls | cd src", "cd-in-pipeline"),
        pass("cd src && ls && cd /etc && ls", "path-untrusted"),
        pass("cd src && cat ../.env", "path-denied"),
        pass("cd src && cat ../../other/secret.txt", "path-untrusted"),
        pass("cd src && cd ..", "cd-dotdot"),
        pass("cd src && ls ../..", "path-untrusted"),
        pass("cd src && ls ../../..", "path-untrusted"),
        pass("cd $HOME", "node:simple_expansion"),
        pass("cd ~root", "tilde"),
        pass("cd src && (ls)", "node:subshell"),
        pass("cd src && { ls; }", "node:compound_statement"),
        pass("cd src && X=1 ls", "node:variable_assignment"),
        pass("cd src && rm x", "cmd-not-allowed:rm"),
        pass("cd src &", "op:&"),
        pass_in("work", "cd . && ls", "path-untrusted"),
        pass_in("work", "cd ~/kms && ls; ls", "cd-then-unconditional"),
    ]);
}

#[test]
fn no_cwd_means_relative_paths_cannot_be_judged() {
    let w = World::new();
    for (cmd, want) in [
        ("ls", "no-cwd"),
        ("cat README.md", "no-cwd"),
        ("git log", "no-cwd"),
        ("find . -name x", "no-cwd"),
        ("cd src && ls", "no-cwd"),
    ] {
        assert_eq!(w.eval_no_cwd(cmd).rule(), format!("pass:{want}"), "{cmd}");
    }
    let abs = format!("cat {}/kms/README.md", w.home.display());
    assert!(w.eval_no_cwd(&abs).is_allow());
    assert!(w.eval_no_cwd("echo hi").is_allow());
    assert!(w.eval_no_cwd("cat ~/kms/README.md").is_allow());
    assert!(w.eval_no_cwd("git -C ~/kms log").is_allow());
    // a cwd that does not exist counts as none
    assert_eq!(w.eval("ls", "kms/gone").rule(), "pass:no-cwd");
}

#[test]
fn the_environment_can_veto() {
    let w = World::new();
    let with =
        |cmd: &str, vars: &[(&str, &str)]| w.eval_with(cmd, "kms", &Vars::fixed(vars)).rule();
    assert_eq!(
        with("ls", &[("POSIXLY_CORRECT", "1")]),
        "pass:env-posixly-correct"
    );
    assert_eq!(
        with("ls", &[("POSIXLY_CORRECT", "")]),
        "pass:env-posixly-correct"
    );
    assert_eq!(
        with("rg x", &[("RIPGREP_CONFIG_PATH", "/tmp/rc")]),
        "pass:env-rg-config"
    );
    assert_eq!(
        with("cd src && ls", &[("CDPATH", "/tmp")]),
        "pass:env-cdpath"
    );
    assert_eq!(with("cd ./src && ls", &[("CDPATH", "/tmp")]), "allow:cd+ls");
    assert_eq!(
        with("cd ~/kms/src && ls", &[("CDPATH", "/tmp")]),
        "allow:cd+ls"
    );
    for name in [
        "GIT_DIR",
        "GIT_WORK_TREE",
        "GIT_EXTERNAL_DIFF",
        "GIT_CONFIG",
        "GIT_CONFIG_GLOBAL",
        "GIT_CONFIG_SYSTEM",
        "GIT_PAGER",
        "GIT_EXEC_PATH",
        "GIT_INDEX_FILE",
        "GIT_CONFIG_PARAMETERS",
    ] {
        assert_eq!(
            with("git log", &[(name, "x")]),
            format!("pass:env-git:{name}"),
            "{name}"
        );
    }
    // other tools are unaffected by git's variables
    assert_eq!(with("ls", &[("GIT_DIR", "x")]), "allow:ls");

    // the Copilot CLI's own hardening is accepted, anything else is not
    let cli = [
        ("GIT_CONFIG_COUNT", "3"),
        ("GIT_CONFIG_KEY_0", "safe.bareRepository"),
        ("GIT_CONFIG_VALUE_0", "explicit"),
        ("GIT_CONFIG_KEY_1", "credential.interactive"),
        ("GIT_CONFIG_VALUE_1", "never"),
        ("GIT_CONFIG_KEY_2", "core.fsmonitor"),
        ("GIT_CONFIG_VALUE_2", "false"),
        ("GIT_OPTIONAL_LOCKS", "0"),
        ("GIT_TERMINAL_PROMPT", "0"),
    ];
    assert_eq!(with("git log", &cli), "allow:git-log");
    let mut bad = cli.to_vec();
    bad[6] = ("GIT_CONFIG_VALUE_2", "/tmp/evil");
    assert_eq!(with("git log", &bad), "pass:env-git-config");
    let mut extra = cli.to_vec();
    extra[0] = ("GIT_CONFIG_COUNT", "4");
    extra.push(("GIT_CONFIG_KEY_3", "core.pager"));
    extra.push(("GIT_CONFIG_VALUE_3", "sh -c evil"));
    assert_eq!(with("git log", &extra), "pass:env-git-config");
    let mut missing = cli.to_vec();
    missing.remove(6);
    assert_eq!(with("git log", &missing), "pass:env-git-config");
    assert_eq!(
        with("git log", &[("GIT_CONFIG_COUNT", "lots")]),
        "pass:env-git-config"
    );
    assert_eq!(
        with("git log", &[("GIT_CONFIG_COUNT", "100000")]),
        "pass:env-git-config"
    );
}

#[test]
fn audit_rules_name_what_was_involved() {
    let w = World::new();
    assert_eq!(
        w.eval("cd src && git log | head", "kms").rule(),
        "allow:cd+git-log+head"
    );
    assert_eq!(w.eval("ls && ls | ls", "kms").rule(), "allow:ls");
    assert_eq!(w.eval("rm x", "kms").rule(), "pass:cmd-not-allowed:rm");
}

/// What the replay asks: "if this command were allowed, would the rest let the
/// line through?" It lifts the allow-list and nothing else.
#[test]
fn assuming_a_command_lifts_only_the_allow_list() {
    use ctx_hook::policy::{evaluate, evaluate_assuming};
    let w = World::new();
    let kms = w.path("kms");
    let vars = Vars::fixed(&[]);
    let assume = |src: &str, names: &[&str]| {
        evaluate_assuming(src, Some(&kms), &w.home, &w.trust, &vars, names).rule()
    };

    assert_eq!(assume("rm x", &[]), "pass:cmd-not-allowed:rm");
    assert_eq!(assume("rm x", &["rm"]), "allow:assumed");
    assert_eq!(
        assume("python3 x.py -c 'print(1)'", &["python3"]),
        "allow:assumed"
    );
    assert_eq!(
        assume("ls src | python3 x.py", &["python3"]),
        "allow:ls+assumed"
    );
    assert_eq!(
        assume("cd src && python3 x.py", &["python3"]),
        "allow:cd+assumed"
    );

    // another command on the line still has to be listed
    assert_eq!(
        assume("rm x; python3 y", &["rm"]),
        "pass:cmd-not-allowed:python3"
    );
    assert_eq!(
        assume("rm x; python3 y", &["rm", "python3"]),
        "allow:assumed"
    );
    // the structure of the line is still judged
    for src in [
        "python3 x > out",
        "python3 x &",
        "python3 $(id)",
        "cd src || python3 x",
    ] {
        let rule = assume(src, &["python3"]);
        assert!(
            rule.starts_with("pass:") && !rule.contains("cmd-not-allowed"),
            "{src}: {rule}"
        );
    }
    // and so is where it goes
    assert_eq!(assume("cd .. && python3 x", &["python3"]), "pass:cd-dotdot");
    assert_eq!(assume("ls | cat .env", &["python3"]), "pass:path-denied");
    // cd is never an assumption
    assert!(!assume("cd /etc && ls", &["cd"]).starts_with("allow"));

    // and without an assumption it is the same function
    for src in [
        "ls src",
        "rm x",
        "cat .env",
        "cd .. && ls",
        "git log | head",
    ] {
        assert_eq!(
            evaluate(src, Some(&kms), &w.home, &w.trust, &vars),
            evaluate_assuming(src, Some(&kms), &w.home, &w.trust, &vars, &[]),
            "{src}"
        );
    }
}
