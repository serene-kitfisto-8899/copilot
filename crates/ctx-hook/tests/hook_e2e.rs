//! The real `ctx-hook` binary, run the way the CLI runs it: a request on
//! stdin, nothing but a verdict on stdout, and a status that is never 2 (the
//! status that means "deny"). Everything here uses a fake home directory and a
//! database that cannot be reached, so the audit trail ends up in the spool.

use std::io::Write;
use std::net::TcpListener;
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};
use std::time::{Duration, Instant};

use ctx_hook::audit::Row;
use ctx_hook::payload::CAPTURED;
use serde_json::json;
use tempfile::TempDir;

const ALLOW: &str = r#"{"behavior":"allow"}"#;
const ENFORCE: &str = "mode = \"enforce\"\n";
const NO_DATABASE: &str = "postgres:///nope?host=/nonexistent/dir&user=x";

struct Sandbox {
    _dir: TempDir,
    home: PathBuf,
}

impl Sandbox {
    fn new(config: Option<&str>) -> Sandbox {
        let dir = tempfile::tempdir().unwrap();
        let home = std::fs::canonicalize(dir.path()).unwrap().join("home");
        for sub in ["kms/.git", "kms/src", "other/.git"] {
            std::fs::create_dir_all(home.join(sub)).unwrap();
        }
        std::fs::write(home.join("kms/README.md"), "hello\n").unwrap();
        let sandbox = Sandbox { _dir: dir, home };
        if let Some(text) = config {
            sandbox.write_config(&sandbox.home.join(".config"), text);
        }
        sandbox
    }

    fn write_config(&self, config_home: &Path, text: &str) {
        let file = config_home.join("ctx/permissions.toml");
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(file, text).unwrap();
    }

    fn command(&self, args: &[&str]) -> Command {
        let mut command = Command::new(env!("CARGO_BIN_EXE_ctx-hook"));
        command
            .args(args)
            .env_clear()
            .env("HOME", &self.home)
            .env("CTX_DATABASE_URL", NO_DATABASE)
            .current_dir(self.home.join("kms"))
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        command
    }

    fn run(&self, args: &[&str], input: &[u8]) -> Output {
        feed(self.command(args), input)
    }

    fn permission(&self, input: &[u8]) -> Output {
        self.run(&["permission"], input)
    }

    fn spool(&self) -> PathBuf {
        self.home.join(".local/state/ctx/hook-spool.jsonl")
    }

    fn spooled(&self) -> Vec<Row> {
        std::fs::read_to_string(self.spool())
            .unwrap_or_default()
            .lines()
            .map(|line| serde_json::from_str(line).unwrap())
            .collect()
    }

    fn payload(&self, command: &str) -> Vec<u8> {
        payload(&self.home.join("kms"), command)
    }
}

fn payload(cwd: &Path, command: &str) -> Vec<u8> {
    json!({
        "hookName": "permissionRequest",
        "sessionId": "e2e-session",
        "timestamp": chrono::Utc::now().timestamp_millis(),
        "cwd": cwd,
        "toolName": "bash",
        "toolInput": { "command": command },
        "permissionSuggestions": [],
    })
    .to_string()
    .into_bytes()
}

/// Writes `input` on a thread of its own (a hook that does not read all of it
/// must not hang the test) and waits for the process.
fn feed(mut command: Command, input: &[u8]) -> Output {
    let mut child = command.spawn().unwrap();
    let mut stdin = child.stdin.take().unwrap();
    let input = input.to_vec();
    let writer = std::thread::spawn(move || {
        let _ = stdin.write_all(&input);
    });
    let output = child.wait_with_output().unwrap();
    writer.join().unwrap();
    output
}

fn silent(output: &Output, what: &str) {
    assert_eq!(output.status.code(), Some(0), "{what}: {:?}", output.status);
    assert!(
        output.stdout.is_empty(),
        "{what}: stdout {:?}",
        String::from_utf8_lossy(&output.stdout)
    );
    assert!(
        output.stderr.is_empty(),
        "{what}: stderr {:?}",
        String::from_utf8_lossy(&output.stderr)
    );
}

fn stdout(output: &Output) -> String {
    String::from_utf8_lossy(&output.stdout).into_owned()
}

#[test]
fn shadow_mode_logs_the_decision_and_says_nothing() {
    for config in [None, Some("mode = \"shadow\"\n")] {
        let s = Sandbox::new(config);
        let out = s.permission(&s.payload("ls src"));
        silent(&out, "shadow");
        let rows = s.spooled();
        assert_eq!(rows.len(), 1);
        assert_eq!(rows[0].decision, "allow");
        assert_eq!(rows[0].rule, "allow:ls");
        assert!(rows[0].shadow);
        assert_eq!(rows[0].session_id, "e2e-session");
        assert_eq!(rows[0].cmd_preview.as_deref(), Some("ls src"));
        assert!(rows[0].latency_us.is_some());
    }
}

#[test]
fn enforce_mode_allows_what_the_policy_allows_and_prints_only_that() {
    let s = Sandbox::new(Some(ENFORCE));
    let out = s.permission(&s.payload("ls src && git status"));
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out), ALLOW);
    assert!(out.stderr.is_empty());
    let rows = s.spooled();
    assert_eq!(rows.len(), 1, "the row is written before the yes");
    assert!(!rows[0].shadow);
    assert_eq!(rows[0].decision, "allow");
}

#[test]
fn enforce_mode_says_nothing_about_everything_else() {
    let s = Sandbox::new(Some(ENFORCE));
    let commands = [
        "python3 x.py",
        "rm -rf src",
        "ls /etc",
        "cat ~/.ssh/id_rsa",
        "ls > out",
        "git push",
        "ls; rm x",
        "curl http://example.com",
    ];
    for command in commands {
        silent(&s.permission(&s.payload(command)), command);
    }
    let rows = s.spooled();
    assert_eq!(rows.len(), commands.len());
    assert!(rows.iter().all(|r| r.decision == "pass" && !r.shadow));
}

#[test]
fn off_mode_is_silent_and_writes_nothing() {
    let s = Sandbox::new(Some("mode = \"off\"\n"));
    silent(&s.permission(&s.payload("ls src")), "off");
    assert!(!s.spool().exists());
}

#[test]
fn a_config_it_cannot_use_never_enforces() {
    for text in [
        "mode = \"enforce\"\nnonsense = 1\n",
        "mode = \"enforce\"\ntrusted_roots = [\"relative\"]\n",
        "mode = \"enforce\"\n[",
        "mode = \"always\"\n",
    ] {
        let s = Sandbox::new(Some(text));
        silent(&s.permission(&s.payload("ls src")), text);
        let rows = s.spooled();
        assert_eq!(rows.len(), 1, "{text}");
        assert_eq!(rows[0].rule, "pass:config-error", "{text}");
        assert!(rows[0].shadow, "{text}");
    }
}

#[test]
fn the_payload_the_cli_really_sent_gets_a_row() {
    let s = Sandbox::new(Some(ENFORCE));
    // /tmp/p3nest is nobody's repository
    silent(&s.permission(CAPTURED.as_bytes()), "captured payload");
    let rows = s.spooled();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].session_id, "b5b9fbf1-124d-4b43-8215-1f8ece76583c");
    assert_eq!(rows[0].cwd.as_deref(), Some("/tmp/p3nest"));
    assert_eq!(
        rows[0].cmd_preview.as_deref(),
        Some("ls /usr/lib/postgresql")
    );
}

#[test]
fn nothing_it_is_fed_makes_it_deny_or_speak() {
    let s = Sandbox::new(Some(ENFORCE));
    let with_nul = {
        let mut input = s.payload("ls src");
        let at = input.windows(6).position(|w| w == b"ls src").unwrap();
        input.splice(at..at + 6, b"ls \\u0000src".iter().copied());
        input
    };
    let inputs: Vec<(&str, Vec<u8>)> = vec![
        ("nothing", Vec::new()),
        ("blank", b"  \n\n".to_vec()),
        ("text", b"hello".to_vec()),
        ("every byte", (0..=255u8).collect()),
        (
            "invalid UTF-8 in a string",
            b"{\"toolName\":\"bash\",\"toolInput\":{\"command\":\"ls \xff\"}}".to_vec(),
        ),
        ("null", b"null".to_vec()),
        ("array", b"[]".to_vec()),
        ("number", b"42".to_vec()),
        ("deeply nested", "[".repeat(200_000).into_bytes()),
        ("two megabytes of junk", vec![b'a'; 2 << 20]),
        (
            "two megabytes of command",
            format!(
                "{{\"toolName\":\"bash\",\"toolInput\":{{\"command\":\"{}\"}}}}",
                "a".repeat(2 << 20)
            )
            .into_bytes(),
        ),
        ("a NUL in the command", with_nul),
        (
            "a tool nobody knows",
            json!({"toolName": "teleport", "toolInput": {"command": "ls"}})
                .to_string()
                .into_bytes(),
        ),
        (
            "the wrong event",
            json!({"hookName": "preToolUse", "toolName": "bash", "toolInput": {"command": "ls src"},
                   "cwd": s.home.join("kms")})
            .to_string()
            .into_bytes(),
        ),
    ];
    for (what, input) in &inputs {
        silent(&s.permission(input), what);
    }
}

#[test]
fn arguments_cannot_turn_the_hook_into_a_usage_error() {
    // clap would exit 2 on most of these, and 2 means deny
    let s = Sandbox::new(Some(ENFORCE));
    let input = s.payload("python3 x.py");
    let cases: [&[&str]; 7] = [
        &["permission", "--bogus"],
        &["permission", "extra", "arguments"],
        &["permission", "-h"],
        &["permission", "--help"],
        &["permission", "--version"],
        &["permission", ""],
        &["permission", "--cwd"],
    ];
    for args in cases {
        silent(&s.run(args, &input), &args.join(" "));
    }
}

#[test]
fn a_usage_error_elsewhere_is_a_usage_error() {
    // which is why `permission` is dispatched before the parser sees anything
    let s = Sandbox::new(None);
    assert_eq!(s.run(&[], b"").status.code(), Some(2));
    assert_eq!(s.run(&["no-such-subcommand"], b"").status.code(), Some(2));
}

#[test]
fn without_a_usable_home_it_does_nothing() {
    let s = Sandbox::new(Some(ENFORCE));
    let input = s.payload("ls src");
    let mut unset = s.command(&["permission"]);
    unset.env_remove("HOME");
    silent(&feed(unset, &input), "no HOME");
    let mut relative = s.command(&["permission"]);
    relative.env("HOME", "relative/home");
    silent(&feed(relative, &input), "relative HOME");
    assert!(!s.spool().exists());
}

#[test]
fn the_xdg_directories_are_honoured() {
    let s = Sandbox::new(None);
    let config_home = s.home.join("cfg");
    let state_home = s.home.join("state");
    s.write_config(&config_home, ENFORCE);
    let mut command = s.command(&["permission"]);
    command
        .env("XDG_CONFIG_HOME", &config_home)
        .env("XDG_STATE_HOME", &state_home);
    let out = feed(command, &s.payload("ls src"));
    assert_eq!(stdout(&out), ALLOW, "the config under XDG_CONFIG_HOME");
    assert!(state_home.join("ctx/hook-spool.jsonl").exists());
    assert!(!s.spool().exists());
}

#[test]
fn the_spool_is_private() {
    use std::os::unix::fs::PermissionsExt;
    let s = Sandbox::new(None);
    silent(&s.permission(&s.payload("ls src")), "shadow");
    let mode = |p: &Path| std::fs::metadata(p).unwrap().permissions().mode() & 0o777;
    assert_eq!(mode(&s.spool()), 0o600);
    assert_eq!(mode(s.spool().parent().unwrap()), 0o700);
}

#[test]
fn a_hung_stdin_is_given_up_on_without_a_word() {
    let s = Sandbox::new(Some(ENFORCE));
    let mut child = s.command(&["permission"]).spawn().unwrap();
    let _stdin_held_open = child.stdin.take().unwrap();
    let started = Instant::now();
    let status = loop {
        if let Some(status) = child.try_wait().unwrap() {
            break status;
        }
        if started.elapsed() > Duration::from_secs(10) {
            child.kill().unwrap();
            panic!("the hook is still waiting for its input after 10 s");
        }
        std::thread::sleep(Duration::from_millis(20));
    };
    let waited = started.elapsed();
    assert_eq!(status.code(), Some(0));
    assert!(waited < Duration::from_secs(5), "{waited:?}");
    let out = child.wait_with_output().unwrap();
    assert!(out.stdout.is_empty());
}

#[test]
fn a_database_that_never_answers_costs_its_deadline_and_no_more() {
    // accepts connections (the kernel does that) and never says a word
    let silent_server = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = silent_server.local_addr().unwrap().port();
    let s = Sandbox::new(Some(ENFORCE));
    let mut command = s.command(&["permission"]);
    command.env(
        "CTX_DATABASE_URL",
        format!("postgres://x@127.0.0.1:{port}/db?sslmode=disable"),
    );
    let started = Instant::now();
    let out = feed(command, &s.payload("ls src"));
    let took = started.elapsed();
    assert!(took < Duration::from_secs(1), "{took:?}");
    // the spool is where the row is kept, and a kept row may be approved
    assert_eq!(out.status.code(), Some(0));
    assert_eq!(stdout(&out), ALLOW);
    assert_eq!(s.spooled().len(), 1);
}

#[test]
fn explain_tells_a_human_what_the_policy_thinks() {
    let s = Sandbox::new(Some(ENFORCE));
    let out = s.run(&["explain", "ls src"], b"");
    assert_eq!(out.status.code(), Some(0), "{}", stdout(&out));
    let text = stdout(&out);
    assert!(text.contains("verdict  allow:ls"), "{text}");
    assert!(text.contains("mode     enforce"), "{text}");
    assert!(text.contains("roots"), "{text}");

    let out = s.run(&["explain", "python3 x.py"], b"");
    assert_eq!(out.status.code(), Some(1));
    assert!(stdout(&out).contains("verdict  pass:cmd-not-allowed:python3"));

    let out = s.run(
        &[
            "explain",
            "ls",
            "--cwd",
            s.home.join("other").to_str().unwrap(),
        ],
        b"",
    );
    assert_eq!(
        out.status.code(),
        Some(1),
        "an untrusted directory: {}",
        stdout(&out)
    );
    assert!(s.spooled().is_empty(), "explain writes no audit rows");
}
