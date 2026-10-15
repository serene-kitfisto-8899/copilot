//! What the Copilot CLI sends a `permissionRequest` hook on stdin.
//!
//! This is the shape Copilot CLI 1.0.95 really sends (captured from a live
//! session; the documentation does not show it in full):
//!
//! ```json
//! {"hookName":"permissionRequest","sessionId":"b5b9fbf1-124d-4b43-8215-1f8ece76583c",
//!  "timestamp":1791583990855,"cwd":"/tmp/p3nest","toolName":"bash",
//!  "toolInput":{"command":"ls /usr/lib/postgresql"},"permissionSuggestions":[]}
//! ```
//!
//! `timestamp` is in milliseconds. `toolInput` holds only `command`, plus
//! `requestSandboxBypass` when that is true. Requests to read a file never
//! reach the hook at all. The snake_case spellings and a `toolInput` that is a
//! JSON string are accepted as well, because other hook hosts send those.
//!
//! Nothing in here fails: whatever arrives becomes a [`Request`], and one that
//! cannot be understood carries a `problem`, which the policy turns into a
//! pass. That keeps the audit trail complete for requests of a shape nobody
//! planned for.

use chrono::{DateTime, Duration, Utc};
use serde_json::{Map, Value};

/// Anything bigger is not a hook payload.
pub const MAX_PAYLOAD_BYTES: usize = 1024 * 1024;

/// Byte for byte what Copilot CLI 1.0.95 sent in a live session. The tests
/// parse it, so that a change in the shape the CLI uses is not hidden behind
/// a hand-written approximation of it.
pub const CAPTURED: &str = r#"{"hookName":"permissionRequest","sessionId":"b5b9fbf1-124d-4b43-8215-1f8ece76583c","timestamp":1791583990855,"cwd":"/tmp/p3nest","toolName":"bash","toolInput":{"command":"ls /usr/lib/postgresql"},"permissionSuggestions":[]}"#;
pub const UNKNOWN: &str = "unknown";
/// A timestamp further than this from the clock is not trusted for the audit row.
const CLOCK_SLACK: Duration = Duration::minutes(10);
const MAX_TOOL_CHARS: usize = 64;
const MAX_ID_BYTES: usize = 128;

#[derive(Debug, Clone, PartialEq)]
pub struct Request {
    pub session_id: String,
    /// `bash` for a shell command.
    pub tool: String,
    pub cwd: Option<String>,
    pub ts: DateTime<Utc>,
    pub command: Option<String>,
    pub sandbox_bypass: bool,
    /// Keys of `toolInput` other than `command` and `requestSandboxBypass`: an
    /// input the policy was not written for.
    pub extra_keys: Vec<String>,
    /// Why the payload could not be understood, as a short code.
    pub problem: Option<String>,
}

impl Request {
    /// A shell request as the CLI would send it, for `explain` and the replay.
    pub fn bash(command: &str, cwd: Option<&str>, ts: DateTime<Utc>) -> Request {
        Request {
            session_id: UNKNOWN.to_owned(),
            tool: "bash".to_owned(),
            cwd: cwd.map(str::to_owned),
            ts,
            command: Some(command.to_owned()),
            sandbox_bypass: false,
            extra_keys: Vec::new(),
            problem: None,
        }
    }

    pub fn parse(bytes: &[u8], now: DateTime<Utc>) -> Request {
        let mut req = Request {
            session_id: UNKNOWN.to_owned(),
            tool: UNKNOWN.to_owned(),
            cwd: None,
            ts: now,
            command: None,
            sandbox_bypass: false,
            extra_keys: Vec::new(),
            problem: None,
        };
        if bytes.len() > MAX_PAYLOAD_BYTES {
            req.problem = Some("too-large".to_owned());
            return req;
        }
        let Ok(Value::Object(mut root)) = serde_json::from_slice::<Value>(bytes) else {
            req.problem = Some("not-a-json-object".to_owned());
            return req;
        };

        if let Some(Value::String(id)) = take(&mut root, &["sessionId", "session_id"])
            && is_identifier(&id)
        {
            req.session_id = id;
        }
        if let Some(Value::String(ts)) = take(&mut root, &["timestamp"]).map(stringify_number) {
            req.ts = parse_time(&ts, now);
        }
        if let Some(Value::String(cwd)) = take(&mut root, &["cwd"])
            && !cwd.is_empty()
        {
            req.cwd = Some(cwd);
        }
        if let Some(Value::String(name)) = take(&mut root, &["hookName", "hook_event_name"])
            && !name.eq_ignore_ascii_case("permissionRequest")
        {
            req.problem = Some(format!("hook:{}", truncate(&name, MAX_TOOL_CHARS)));
        }
        match take(&mut root, &["toolName", "tool_name"]) {
            Some(Value::String(tool)) if !tool.is_empty() => {
                req.tool = truncate(&tool, MAX_TOOL_CHARS);
            }
            _ => {
                req.problem.get_or_insert_with(|| "no-tool-name".to_owned());
            }
        }

        let input = match take(&mut root, &["toolInput", "tool_input"]) {
            Some(Value::Object(map)) => Some(map),
            Some(Value::String(text)) => match serde_json::from_str::<Value>(&text) {
                Ok(Value::Object(map)) => Some(map),
                _ => {
                    req.problem
                        .get_or_insert_with(|| "tool-input-not-an-object".to_owned());
                    None
                }
            },
            Some(Value::Null) | None => None,
            Some(_) => {
                req.problem
                    .get_or_insert_with(|| "tool-input-not-an-object".to_owned());
                None
            }
        };
        if let Some(mut input) = input {
            match take(&mut input, &["command"]) {
                Some(Value::String(command)) => req.command = Some(command),
                None | Some(Value::Null) => {}
                Some(_) => {
                    req.problem
                        .get_or_insert_with(|| "command-not-a-string".to_owned());
                }
            }
            if let Some(flag) = take(
                &mut input,
                &["requestSandboxBypass", "request_sandbox_bypass"],
            ) {
                req.sandbox_bypass = !matches!(flag, Value::Null | Value::Bool(false));
            }
            req.extra_keys = input.into_iter().map(|(key, _)| key).collect();
        }
        req
    }
}

fn take(map: &mut Map<String, Value>, names: &[&str]) -> Option<Value> {
    names.iter().find_map(|name| map.remove(*name))
}

fn stringify_number(value: Value) -> Value {
    match value {
        Value::Number(n) => Value::String(n.to_string()),
        other => other,
    }
}

/// Milliseconds since the epoch, or RFC 3339; the clock when it is neither or
/// too far off.
fn parse_time(text: &str, now: DateTime<Utc>) -> DateTime<Utc> {
    let parsed = text
        .parse::<i64>()
        .ok()
        .and_then(DateTime::from_timestamp_millis)
        .or_else(|| {
            DateTime::parse_from_rfc3339(text)
                .ok()
                .map(|t| t.with_timezone(&Utc))
        });
    match parsed {
        Some(t) if (t - now).abs() <= CLOCK_SLACK => t,
        _ => now,
    }
}

fn is_identifier(text: &str) -> bool {
    !text.is_empty()
        && text.len() <= MAX_ID_BYTES
        && text
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'-' | b'_' | b'.'))
}

fn truncate(text: &str, max_chars: usize) -> String {
    text.chars().take(max_chars).collect()
}

#[cfg(test)]
mod tests {
    use super::*;

    fn at(ms: i64) -> DateTime<Utc> {
        DateTime::from_timestamp_millis(ms).unwrap()
    }

    fn parse(text: &str) -> Request {
        Request::parse(text.as_bytes(), at(1791583990855 + 4000))
    }

    #[test]
    fn the_payload_the_cli_really_sends() {
        for text in [CAPTURED.to_owned(), format!("{CAPTURED}\n")] {
            let req = parse(&text);
            assert_eq!(req.problem, None);
            assert_eq!(req.session_id, "b5b9fbf1-124d-4b43-8215-1f8ece76583c");
            assert_eq!(req.tool, "bash");
            assert_eq!(req.cwd.as_deref(), Some("/tmp/p3nest"));
            assert_eq!(req.command.as_deref(), Some("ls /usr/lib/postgresql"));
            assert_eq!(req.ts, at(1791583990855));
            assert!(!req.sandbox_bypass);
            assert!(req.extra_keys.is_empty());
        }
    }

    #[test]
    fn snake_case_and_a_tool_input_that_is_a_string() {
        let req = parse(
            r#"{"session_id":"s-1","tool_name":"bash","tool_input":"{\"command\":\"ls\"}","cwd":"/x"}"#,
        );
        assert_eq!(req.problem, None);
        assert_eq!(req.session_id, "s-1");
        assert_eq!(req.command.as_deref(), Some("ls"));
        assert_eq!(req.tool, "bash");
    }

    #[test]
    fn a_sandbox_bypass_is_noticed_in_every_spelling_that_is_not_plainly_false() {
        let with = |flag: &str| {
            parse(&format!(
                r#"{{"toolName":"bash","toolInput":{{"command":"ls","requestSandboxBypass":{flag}}}}}"#
            ))
        };
        assert!(with("true").sandbox_bypass);
        assert!(with("\"true\"").sandbox_bypass);
        assert!(with("1").sandbox_bypass);
        assert!(with("{}").sandbox_bypass);
        assert!(!with("false").sandbox_bypass);
        assert!(!with("null").sandbox_bypass);
        let snake = parse(
            r#"{"toolName":"bash","toolInput":{"command":"ls","request_sandbox_bypass":true}}"#,
        );
        assert!(snake.sandbox_bypass);
        assert!(snake.extra_keys.is_empty());
    }

    #[test]
    fn other_input_keys_are_listed_not_ignored() {
        let req = parse(
            r#"{"toolName":"bash","toolInput":{"command":"ls","env":{"A":"1"},"cwd":"/","description":"x"}}"#,
        );
        assert_eq!(req.extra_keys, ["cwd", "description", "env"]);
        assert_eq!(req.problem, None);
    }

    #[test]
    fn other_tools_and_missing_commands() {
        let view = parse(r#"{"toolName":"view","toolInput":{"path":"/etc/passwd"}}"#);
        assert_eq!(view.tool, "view");
        assert_eq!(view.command, None);
        assert_eq!(view.extra_keys, ["path"]);
        let none = parse(r#"{"toolName":"bash"}"#);
        assert_eq!((none.command, none.problem), (None, None));
        let null = parse(r#"{"toolName":"bash","toolInput":null}"#);
        assert_eq!((null.command, null.problem), (None, None));
    }

    #[test]
    fn only_a_permission_request_is_a_permission_request() {
        for name in ["permissionRequest", "PermissionRequest"] {
            let req = parse(&format!(r#"{{"hookName":"{name}","toolName":"bash"}}"#));
            assert_eq!(req.problem, None, "{name}");
        }
        assert_eq!(
            parse(r#"{"toolName":"bash"}"#).problem,
            None,
            "no hookName at all"
        );
        for name in ["preToolUse", "postToolUse", "sessionStart", ""] {
            let req = parse(&format!(
                r#"{{"hookName":"{name}","toolName":"bash","toolInput":{{"command":"ls"}}}}"#
            ));
            assert_eq!(req.problem, Some(format!("hook:{name}")));
        }
    }

    #[test]
    fn shapes_nobody_planned_for_become_problems() {
        for (text, problem) in [
            ("", "not-a-json-object"),
            ("null", "not-a-json-object"),
            ("[]", "not-a-json-object"),
            ("\"ls\"", "not-a-json-object"),
            ("{", "not-a-json-object"),
            ("{\"toolName\":\"bash\"} trailing", "not-a-json-object"),
            ("{}", "no-tool-name"),
            (r#"{"toolName":5}"#, "no-tool-name"),
            (r#"{"toolName":""}"#, "no-tool-name"),
            (
                r#"{"toolName":"bash","toolInput":"not json"}"#,
                "tool-input-not-an-object",
            ),
            (
                r#"{"toolName":"bash","toolInput":[1]}"#,
                "tool-input-not-an-object",
            ),
            (
                r#"{"toolName":"bash","toolInput":{"command":["ls"]}}"#,
                "command-not-a-string",
            ),
            (
                r#"{"toolName":"bash","toolInput":{"command":7}}"#,
                "command-not-a-string",
            ),
        ] {
            let req = parse(text);
            assert_eq!(req.problem.as_deref(), Some(problem), "{text}");
            assert_eq!(req.command, None, "{text}");
        }
        let invalid_utf8 = Request::parse(&[b'{', 0xff, 0xfe, b'}'], at(0));
        assert_eq!(invalid_utf8.problem.as_deref(), Some("not-a-json-object"));
        let huge = vec![b' '; MAX_PAYLOAD_BYTES + 1];
        assert_eq!(
            Request::parse(&huge, at(0)).problem.as_deref(),
            Some("too-large")
        );
    }

    #[test]
    fn no_prefix_of_a_payload_panics_or_yields_a_command() {
        for end in 0..CAPTURED.len() {
            let req = Request::parse(&CAPTURED.as_bytes()[..end], at(0));
            assert!(req.problem.is_some(), "{end}");
            assert_eq!(req.command, None, "{end}");
            assert_eq!(req.session_id, UNKNOWN);
        }
    }

    #[test]
    fn session_ids_are_identifiers_or_unknown() {
        let too_long = "x".repeat(129);
        for (id, ok) in [
            ("b5b9fbf1-124d-4b43-8215-1f8ece76583c", true),
            ("abc_DEF.12", true),
            ("", false),
            ("a b", false),
            ("a/../b", false),
            ("a;b", false),
            ("é", false),
            ("a\nb", false),
            (too_long.as_str(), false),
        ] {
            let req = parse(&format!(
                r#"{{"toolName":"bash","sessionId":{}}}"#,
                Value::from(id)
            ));
            assert_eq!(req.session_id == id, ok, "{id:?}");
            if !ok {
                assert_eq!(req.session_id, UNKNOWN);
            }
        }
    }

    #[test]
    fn timestamps_are_used_when_plausible_and_the_clock_otherwise() {
        let now = at(1_800_000_000_000);
        let with = |ts: &str| {
            Request::parse(
                format!(r#"{{"toolName":"bash","timestamp":{ts}}}"#).as_bytes(),
                now,
            )
            .ts
        };
        assert_eq!(with("1799999990000"), at(1_799_999_990_000));
        assert_eq!(with("1800000300000"), at(1_800_000_300_000));
        assert_eq!(with("1799999000000"), now, "more than ten minutes ago");
        assert_eq!(with("1800001000000"), now, "more than ten minutes ahead");
        assert_eq!(with("1799999990"), now, "seconds, not milliseconds");
        assert_eq!(with("0"), now);
        assert_eq!(with("-5"), now);
        assert_eq!(with("1.5e12"), now);
        assert_eq!(with("null"), now);
        assert_eq!(with("\"nonsense\""), now);
        assert_eq!(with("9223372036854775807"), now);
        assert_eq!(
            with("\"2030-01-01T00:00:00Z\""),
            now,
            "an RFC 3339 time that is far from the clock is not used either"
        );
        let near = DateTime::from_timestamp_millis(1_800_000_000_000 + 1000).unwrap();
        let text = near.to_rfc3339();
        assert_eq!(with(&format!("\"{text}\"")), near);
    }

    #[test]
    fn long_tool_names_are_cut() {
        let long = "t".repeat(500);
        let req = parse(&format!(r#"{{"toolName":"{long}"}}"#));
        assert_eq!(req.tool.chars().count(), MAX_TOOL_CHARS);
    }

    #[test]
    fn bash_builds_the_request_the_cli_would_send() {
        let req = Request::bash("ls", Some("/x"), at(5));
        assert_eq!(
            (
                req.tool.as_str(),
                req.command.as_deref(),
                req.cwd.as_deref(),
                req.problem
            ),
            ("bash", Some("ls"), Some("/x"), None)
        );
    }
}
