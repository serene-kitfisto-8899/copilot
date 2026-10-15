//! The `permission` hook (PLAN.md §6.6): read what the CLI is about to ask the
//! user, decide whether it is a command that is safe to approve unasked, write
//! the audit row, and only then, in enforce mode, say yes.
//!
//! What the hook protocol makes of the exit status shapes everything here:
//! **exit 2 denies**, any other failure lets the normal permission flow carry
//! on, and empty output means "no opinion". So the hook has no deny verdict at
//! all, its only possible output is `{"behavior":"allow"}`, and no error path
//! may end in status 2. [`permission`] always exits 0, never goes through the
//! argument parser (whose usage errors exit 2), runs the work on a thread of its
//! own with a generous stack, and gives up silently after [`WATCHDOG`].

use std::io::{Read, Write};
use std::panic::{AssertUnwindSafe, catch_unwind};
use std::path::{Path, PathBuf};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use chrono::Utc;
use ctx_core::config::hook_database_url;
use ctx_core::redact::Redactor;

use crate::audit::{self, Recorded, Row};
use crate::config::{Config, Mode, POLICY_VERSION};
use crate::payload::{MAX_PAYLOAD_BYTES, Request};
use crate::policy::{Verdict, evaluate_assuming};
use crate::trust::Trust;
use crate::vars::Vars;

/// The one thing the hook ever says.
pub const ALLOW: &str = r#"{"behavior":"allow"}"#;
/// After this long the hook stops waiting for itself and exits 0 without a
/// word. The CLI's own timeout (`timeoutSec`, 5 in the sample config) is
/// longer, and a timeout there is also harmless, but there is no reason to wait.
pub const WATCHDOG: Duration = Duration::from_secs(2);
/// Virtual memory only. The shell parser recurses, and the main thread has
/// whatever `ulimit -s` says.
const WORKER_STACK: usize = 64 * 1024 * 1024;

/// The policy a request is judged by: the trusted roots as they are right now,
/// the environment, and the home directory `~` means.
pub struct Policy {
    home: PathBuf,
    trust: Result<Trust, String>,
    vars: Vars,
    id: String,
}

impl Policy {
    pub fn new(home: &Path, config: &Config, vars: Vars) -> Policy {
        let trust = match &config.error {
            Some(error) => Err(error.clone()),
            None => Trust::new(home, &config.roots, &config.deny),
        };
        let id = match &trust {
            Ok(_) => config.policy_id(),
            Err(_) => format!("v{POLICY_VERSION}:config-error"),
        };
        Policy {
            home: home.to_path_buf(),
            trust,
            vars,
            id,
        }
    }

    /// What `hook_audit.policy` holds.
    pub fn id(&self) -> &str {
        &self.id
    }

    /// `Err` is why the configuration cannot be used.
    pub fn trust(&self) -> Result<&Trust, &str> {
        self.trust.as_ref().map_err(String::as_str)
    }

    pub fn judge(&self, req: &Request) -> Verdict {
        self.judge_assuming(req, &[])
    }

    /// As [`Policy::judge`], with the commands in `assume` taken to be allowed
    /// (see [`crate::policy::evaluate_assuming`]); only the replay passes any.
    pub fn judge_assuming(&self, req: &Request, assume: &[&str]) -> Verdict {
        let pass = |code: String| Verdict::Pass { code };
        if let Some(problem) = &req.problem {
            return pass(format!("payload:{problem}"));
        }
        let Ok(trust) = self.trust.as_ref() else {
            return pass("config-error".to_owned());
        };
        // Only a shell command can be judged. Anything else (a file write, a
        // URL, an MCP tool) is left to the prompt.
        if req.tool != "bash" {
            return pass(format!("tool:{}", req.tool));
        }
        // An allow does not pre-approve a request to leave the sandbox, and
        // the policy never meant to judge one.
        if req.sandbox_bypass {
            return pass("sandbox-bypass".to_owned());
        }
        // An input with something besides the command could mean something
        // else; the policy was written for a command and nothing more.
        if let Some(key) = req.extra_keys.first() {
            return pass(format!("tool-input-key:{key}"));
        }
        let Some(command) = req.command.as_deref() else {
            return pass("no-command".to_owned());
        };
        let cwd = req
            .cwd
            .as_deref()
            .map(Path::new)
            .filter(|p| p.is_absolute());
        // The analyzer is the one big piece of code between stdin and a yes.
        // Should it ever panic, the row says so instead of being lost.
        catch_unwind(AssertUnwindSafe(|| {
            evaluate_assuming(command, cwd, &self.home, trust, &self.vars, assume)
        }))
        .unwrap_or_else(|_| pass("internal-panic".to_owned()))
    }
}

/// What one invocation did.
#[derive(Debug)]
pub struct Outcome {
    /// What goes to stdout: nothing, or [`ALLOW`].
    pub print: Option<&'static str>,
    /// The audit row and where it went, when there was one to write.
    pub audited: Option<(Row, Recorded)>,
}

impl Outcome {
    fn silent() -> Outcome {
        Outcome {
            print: None,
            audited: None,
        }
    }
}

/// Everything the hook does between stdin and stdout. `started` is when the
/// process began, for the latency in the audit row.
pub fn run(started: Instant, vars: &Vars, input: &mut dyn Read) -> Outcome {
    // Read it all even when nothing is going to be said: a CLI that finds the
    // pipe closed before it has finished writing may count that as a failure.
    let mut bytes = Vec::new();
    let _ = input
        .take(MAX_PAYLOAD_BYTES as u64 + 1)
        .read_to_end(&mut bytes);
    let Some(home) = vars
        .get("HOME")
        .map(PathBuf::from)
        .filter(|h| h.is_absolute())
    else {
        return Outcome::silent();
    };
    let config = Config::load(vars, &home);
    if config.mode == Mode::Off {
        return Outcome::silent();
    }

    let req = Request::parse(&bytes, Utc::now());
    let policy = Policy::new(&home, &config, vars.clone());
    let verdict = policy.judge(&req);
    // A configuration that cannot be used is shadow mode whatever it says
    let shadow = config.mode != Mode::Enforce || policy.trust().is_err();
    let mut row = Row::build(
        &Redactor::new(),
        &req,
        &verdict,
        shadow,
        policy.id(),
        audit::new_uid(),
    );
    row.latency_us = Some(micros(started.elapsed()));

    let url = hook_database_url(&|key| vars.get(key).filter(|v| !v.is_empty()));
    let recorded = audit::record(&row, &url, &audit::spool_path(vars, &home));
    // An approval nobody can account for is not given.
    let print = (!shadow && verdict.is_allow() && recorded.kept()).then_some(ALLOW);
    Outcome {
        print,
        audited: Some((row, recorded)),
    }
}

fn micros(elapsed: Duration) -> i32 {
    i32::try_from(elapsed.as_micros()).unwrap_or(i32::MAX)
}

/// The `permission` subcommand. Never returns, and the status is always 0.
pub fn permission() -> ! {
    let started = Instant::now();
    // A panic must not write to stderr, and must not change the status
    std::panic::set_hook(Box::new(|_| {}));
    let (tx, rx) = mpsc::channel();
    let worker = std::thread::Builder::new()
        .name("ctx-hook".to_owned())
        .stack_size(WORKER_STACK)
        .spawn(move || {
            let outcome = run(started, &Vars::Process, &mut std::io::stdin().lock());
            let _ = tx.send(outcome.print);
        });
    // A worker that panicked has dropped its sender, and one that hangs times
    // out: either way nothing is printed
    let print = match worker {
        Ok(_) => rx.recv_timeout(WATCHDOG).ok().flatten(),
        Err(_) => None,
    };
    if let Some(text) = print {
        let mut out = std::io::stdout().lock();
        let _ = out.write_all(text.as_bytes());
        let _ = out.flush();
    }
    std::process::exit(0)
}

/// What the policy makes of one command, for a human (`ctx-hook explain`).
#[derive(Debug)]
pub struct Explained {
    pub mode: Mode,
    pub policy: String,
    pub config_error: Option<String>,
    pub cwd: Option<PathBuf>,
    pub verdict: Verdict,
    pub roots: Vec<PathBuf>,
}

pub fn explain(command: &str, cwd: Option<&Path>, vars: &Vars, home: &Path) -> Explained {
    let config = Config::load(vars, home);
    let policy = Policy::new(home, &config, vars.clone());
    let req = Request::bash(command, cwd.and_then(Path::to_str), Utc::now());
    Explained {
        mode: config.mode,
        policy: policy.id().to_owned(),
        config_error: policy.trust().err().map(str::to_owned),
        cwd: cwd.map(Path::to_path_buf),
        verdict: policy.judge(&req),
        roots: policy
            .trust()
            .map(|t| t.roots().cloned().collect())
            .unwrap_or_default(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::payload::CAPTURED;
    use serde_json::json;
    use std::io::Cursor;

    /// A home directory with a trusted repository in it, an untrusted one next
    /// to it, and nowhere to reach PostgreSQL.
    struct Setup {
        _dir: tempfile::TempDir,
        home: PathBuf,
        vars: Vars,
    }

    impl Setup {
        fn new(config: Option<&str>) -> Setup {
            let dir = tempfile::tempdir().unwrap();
            let home = std::fs::canonicalize(dir.path()).unwrap().join("home");
            for sub in ["kms/.git", "kms/src", "other/.git"] {
                std::fs::create_dir_all(home.join(sub)).unwrap();
            }
            std::fs::write(home.join("kms/README.md"), "hello\n").unwrap();
            if let Some(text) = config {
                let file = home.join(".config/ctx/permissions.toml");
                std::fs::create_dir_all(file.parent().unwrap()).unwrap();
                std::fs::write(file, text).unwrap();
            }
            let vars = Vars::fixed(&[
                ("HOME", home.to_str().unwrap()),
                (
                    "CTX_DATABASE_URL",
                    "postgres:///nope?host=/nonexistent/dir&user=x",
                ),
            ]);
            Setup {
                _dir: dir,
                home,
                vars,
            }
        }

        fn spool(&self) -> PathBuf {
            audit::spool_path(&self.vars, &self.home)
        }

        fn spooled(&self) -> Vec<Row> {
            std::fs::read_to_string(self.spool())
                .unwrap_or_default()
                .lines()
                .map(|l| serde_json::from_str(l).unwrap())
                .collect()
        }

        fn payload(&self, tool: &str, input: serde_json::Value, cwd: &str) -> Vec<u8> {
            json!({
                "hookName": "permissionRequest",
                "sessionId": "s-test",
                "timestamp": Utc::now().timestamp_millis(),
                "cwd": cwd,
                "toolName": tool,
                "toolInput": input,
                "permissionSuggestions": [],
            })
            .to_string()
            .into_bytes()
        }

        fn bash(&self, command: &str) -> Vec<u8> {
            self.payload(
                "bash",
                json!({ "command": command }),
                self.home.join("kms").to_str().unwrap(),
            )
        }

        fn run(&self, input: &[u8]) -> Outcome {
            run(Instant::now(), &self.vars, &mut Cursor::new(input.to_vec()))
        }
    }

    fn row(outcome: &Outcome) -> &Row {
        &outcome.audited.as_ref().expect("an audit row").0
    }

    const ENFORCE: &str = "mode = \"enforce\"\n";

    #[test]
    fn shadow_mode_decides_and_logs_but_never_speaks() {
        for config in [None, Some("mode = \"shadow\"\n")] {
            let s = Setup::new(config);
            let out = s.run(&s.bash("ls src"));
            assert_eq!(out.print, None);
            let r = row(&out);
            assert_eq!(
                (r.decision.as_str(), r.rule.as_str()),
                ("allow", "allow:ls")
            );
            assert!(r.shadow);
            assert_eq!(r.session_id, "s-test");
            assert_eq!(r.cmd_preview.as_deref(), Some("ls src"));
            assert!(r.latency_us.unwrap() > 0);
            assert!(matches!(
                out.audited.as_ref().unwrap().1,
                Recorded::Spool(_)
            ));
            assert_eq!(s.spooled(), vec![r.clone()]);
        }
    }

    #[test]
    fn enforce_mode_says_yes_to_what_the_policy_allows_and_nothing_else() {
        let s = Setup::new(Some(ENFORCE));
        let out = s.run(&s.bash("ls src && git status"));
        assert_eq!(out.print, Some(ALLOW));
        assert!(!row(&out).shadow);
        assert_eq!(row(&out).decision, "allow");
        assert_eq!(s.spooled().len(), 1, "the row is written before the yes");

        for command in [
            "python3 x.py",
            "rm -rf src",
            "ls /etc",
            "ls ../other",
            "ls src > out",
            "cat ~/.ssh/id_rsa",
            "git push",
            "curl http://x",
            "ls; rm x",
            "",
        ] {
            let out = s.run(&s.bash(command));
            assert_eq!(out.print, None, "{command}");
            assert_eq!(row(&out).decision, "pass", "{command}");
            assert!(row(&out).rule.starts_with("pass:"), "{command}");
        }
    }

    #[test]
    fn no_answer_is_the_answer_to_anything_but_a_plain_command() {
        let s = Setup::new(Some(ENFORCE));
        let kms = s.home.join("kms");
        let kms = kms.to_str().unwrap();
        let cases: Vec<(Vec<u8>, &str)> = vec![
            (
                s.payload("view", json!({"path": "src"}), kms),
                "pass:tool:view",
            ),
            (
                s.payload("create", json!({"command": "ls"}), kms),
                "pass:tool:create",
            ),
            (
                s.payload(
                    "bash",
                    json!({"command": "ls", "requestSandboxBypass": true}),
                    kms,
                ),
                "pass:sandbox-bypass",
            ),
            (
                s.payload("bash", json!({"command": "ls", "env": {"A": "1"}}), kms),
                "pass:tool-input-key:env",
            ),
            (s.payload("bash", json!({}), kms), "pass:no-command"),
            (s.payload("bash", json!({"command": 5}), kms), "pass:payload:command-not-a-string"),
            (b"not json".to_vec(), "pass:payload:not-a-json-object"),
            (Vec::new(), "pass:payload:not-a-json-object"),
            (
                json!({"hookName": "preToolUse", "toolName": "bash", "toolInput": {"command": "ls"}, "cwd": kms})
                    .to_string()
                    .into_bytes(),
                "pass:payload:hook:preToolUse",
            ),
        ];
        for (input, rule) in cases {
            let out = s.run(&input);
            assert_eq!(out.print, None, "{rule}");
            assert_eq!(row(&out).rule, rule);
        }
        assert_eq!(s.spooled().len(), 9, "all of them are in the audit trail");
    }

    #[test]
    fn a_relative_or_missing_cwd_leaves_relative_paths_unjudged() {
        let s = Setup::new(Some(ENFORCE));
        for cwd in ["", "src", "."] {
            let input = s.payload("bash", json!({"command": "ls src"}), cwd);
            assert_eq!(s.run(&input).print, None, "{cwd:?}");
        }
        let input = json!({"toolName": "bash", "toolInput": {"command": "ls src"}})
            .to_string()
            .into_bytes();
        assert_eq!(s.run(&input).print, None, "no cwd at all");
        let absolute = s.payload(
            "bash",
            json!({"command": "ls /etc"}),
            s.home.to_str().unwrap(),
        );
        assert_eq!(s.run(&absolute).print, None);
    }

    #[test]
    fn a_row_that_cannot_be_kept_means_no_yes() {
        let s = Setup::new(Some(ENFORCE));
        // the spool's directory cannot be made: a file stands in the way
        let state = s.home.join(".local");
        std::fs::create_dir_all(&state).unwrap();
        std::fs::write(state.join("state"), "x").unwrap();
        let out = s.run(&s.bash("ls src"));
        assert_eq!(row(&out).decision, "allow");
        assert!(matches!(out.audited.as_ref().unwrap().1, Recorded::Lost(_)));
        assert_eq!(out.print, None);
    }

    #[test]
    fn off_is_off() {
        let s = Setup::new(Some("mode = \"off\"\n"));
        let out = s.run(&s.bash("ls src"));
        assert!(out.print.is_none() && out.audited.is_none());
        assert!(!s.spool().exists());
    }

    #[test]
    fn a_broken_config_passes_everything_and_never_enforces() {
        for text in [
            "mode = \"enforce\"\ntrusted_root = [\"~/x\"]\n",
            "mode = \"enforce\"\ntrusted_roots = [\"relative/path\"]\n",
            "mode = \"enforce\"\ndeny = [\"[unclosed\"]\n",
            "mode = \"enforce\"\n[",
            "mode = \"enforced\"\n",
        ] {
            let s = Setup::new(Some(text));
            let out = s.run(&s.bash("ls src"));
            assert_eq!(out.print, None, "{text}");
            let r = row(&out);
            assert_eq!(r.rule, "pass:config-error", "{text}");
            assert!(r.shadow, "row says enforcing: {text}");
            assert!(
                r.policy.ends_with("config-error"),
                "policy {}: {text}",
                r.policy
            );
        }
    }

    #[test]
    fn without_a_home_there_is_nothing_to_do() {
        let s = Setup::new(Some(ENFORCE));
        for vars in [Vars::fixed(&[]), Vars::fixed(&[("HOME", "relative/home")])] {
            let out = run(Instant::now(), &vars, &mut Cursor::new(s.bash("ls src")));
            assert!(out.print.is_none() && out.audited.is_none());
        }
    }

    #[test]
    fn extra_roots_from_the_config_widen_what_is_trusted() {
        let s = Setup::new(Some("mode = \"enforce\"\ntrusted_roots = [\"~/other\"]\n"));
        let input = s.payload(
            "bash",
            json!({"command": "ls"}),
            s.home.join("other").to_str().unwrap(),
        );
        assert_eq!(s.run(&input).print, Some(ALLOW));
        let plain = Setup::new(Some(ENFORCE));
        let input = plain.payload(
            "bash",
            json!({"command": "ls"}),
            plain.home.join("other").to_str().unwrap(),
        );
        assert_eq!(plain.run(&input).print, None);
    }

    #[test]
    fn the_policy_id_goes_into_the_row() {
        let a = Setup::new(None);
        let b = Setup::new(Some("trusted_roots = [\"~/other\"]\n"));
        let id = |s: &Setup| row(&s.run(&s.bash("ls"))).policy.clone();
        assert!(id(&a).starts_with(&format!("v{POLICY_VERSION}:")));
        assert_ne!(id(&a), id(&b));
    }

    #[test]
    fn the_payload_the_cli_really_sent_is_judged_like_any_other() {
        let s = Setup::new(Some(ENFORCE));
        let out = s.run(CAPTURED.as_bytes());
        // /tmp/p3nest is not a trusted directory (and may not exist)
        assert_eq!(out.print, None);
        let r = row(&out);
        assert_eq!(r.session_id, "b5b9fbf1-124d-4b43-8215-1f8ece76583c");
        assert_eq!(r.cmd_preview.as_deref(), Some("ls /usr/lib/postgresql"));
        assert_eq!(r.decision, "pass");
    }

    #[test]
    fn it_reads_no_more_than_the_cap_and_then_passes() {
        let s = Setup::new(Some(ENFORCE));
        let mut big = s.bash("ls src");
        big.extend(std::iter::repeat_n(b' ', MAX_PAYLOAD_BYTES));
        let out = s.run(&big);
        assert_eq!(out.print, None);
        assert_eq!(row(&out).rule, "pass:payload:too-large");
    }

    #[test]
    fn explain_reports_the_verdict_the_roots_and_the_mode() {
        let s = Setup::new(Some("mode = \"enforce\"\n"));
        let kms = s.home.join("kms");
        let e = explain("ls src", Some(&kms), &s.vars, &s.home);
        assert_eq!(e.mode, Mode::Enforce);
        assert_eq!(e.verdict.rule(), "allow:ls");
        assert!(e.config_error.is_none());
        assert!(e.roots.iter().any(|r| r.ends_with("kms")), "{:?}", e.roots);
        let e = explain("python3 x", Some(&kms), &s.vars, &s.home);
        assert_eq!(e.verdict.rule(), "pass:cmd-not-allowed:python3");

        let broken = Setup::new(Some("nonsense"));
        let e = explain("ls", None, &broken.vars, &broken.home);
        assert_eq!(e.verdict.rule(), "pass:config-error");
        assert!(e.config_error.unwrap().contains("permissions.toml"));
        assert!(e.roots.is_empty());
    }
}
