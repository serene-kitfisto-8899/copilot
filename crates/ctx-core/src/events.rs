//! `events.jsonl` line -> database rows.
//!
//! Everything stored is derived from the *redacted* event body, so a secret
//! cannot leak through a side table (`tool_calls`, session facts). The only
//! values taken from the raw line are sizes.

use std::fmt;

use chrono::{DateTime, Utc};
use serde_json::Value;

use crate::redact::{Counts, Redactor};

/// Opaque or encrypted blobs the CLI keeps for its own use, removed at any
/// depth (they are large, unreadable and carry nothing a report needs).
pub const DROP_KEYS: &[&str] = &[
    "reasoningOpaque",
    "reasoning_opaque",
    "encryptedContent",
    "reasoningBlocks",
    // Verbatim duplicate of `result.content`, often much larger.
    "detailedContent",
];

/// `system.message` repeats the ~10 KB system prompt; the head is enough to
/// tell which prompt it was.
const SYSTEM_MESSAGE_KEEP_BYTES: usize = 512;

#[derive(Debug, Clone)]
pub struct EventRow {
    pub event_id: String,
    pub parent_id: Option<String>,
    pub ts: DateTime<Utc>,
    pub ty: String,
    /// `main` or the sub-agent's `agentId`.
    pub ctx: String,
    pub agent_id: Option<String>,
    pub parent_tool_call_id: Option<String>,
    pub src_offset: i64,
    pub body: Value,
}

/// One side of a tool call: `tool.execution_start` or `tool.execution_complete`.
/// Fragments of the same `tool_call_id` are merged field by field, the later
/// non-null value winning, both here and in SQL (`COALESCE(new, old)`).
#[derive(Debug, Default, Clone, PartialEq)]
pub struct ToolFragment {
    pub tool_call_id: String,
    pub ctx: Option<String>,
    pub parent_tool_call_id: Option<String>,
    pub tool: Option<String>,
    pub mcp_server: Option<String>,
    pub args: Option<Value>,
    pub result_text: Option<String>,
    /// Bytes of the result before redaction and capping.
    pub result_bytes: Option<i32>,
    pub ok: Option<bool>,
    pub exit_code: Option<i32>,
    pub t_start: Option<DateTime<Utc>>,
    pub t_end: Option<DateTime<Utc>>,
}

impl ToolFragment {
    pub fn merge(&mut self, later: ToolFragment) {
        macro_rules! take {
            ($($field:ident),*) => {
                $(if later.$field.is_some() { self.$field = later.$field; })*
            };
        }
        take!(
            ctx,
            parent_tool_call_id,
            tool,
            mcp_server,
            args,
            result_text,
            result_bytes,
            ok,
            exit_code,
            t_start,
            t_end
        );
    }
}

/// Session attributes learned from events. Later events win; `autopilot` and
/// the time bounds are monotonic.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct SessionFacts {
    pub cwd: Option<String>,
    pub git_root: Option<String>,
    pub repository: Option<String>,
    pub branch: Option<String>,
    pub host_type: Option<String>,
    pub model: Option<String>,
    pub effort: Option<String>,
    pub context_tier: Option<String>,
    pub max_ai_credits: Option<i64>,
    pub autopilot: bool,
    pub first_ts: Option<DateTime<Utc>>,
    pub last_ts: Option<DateTime<Utc>>,
}

impl SessionFacts {
    pub fn merge(&mut self, later: SessionFacts) {
        macro_rules! take {
            ($($field:ident),*) => {
                $(if later.$field.is_some() { self.$field = later.$field; })*
            };
        }
        take!(
            cwd,
            git_root,
            repository,
            branch,
            host_type,
            model,
            effort,
            context_tier,
            max_ai_credits
        );
        self.autopilot |= later.autopilot;
        self.note_ts(later.first_ts);
        self.note_ts(later.last_ts);
    }

    pub fn note_ts(&mut self, ts: Option<DateTime<Utc>>) {
        let Some(ts) = ts else { return };
        self.first_ts = Some(self.first_ts.map_or(ts, |t| t.min(ts)));
        self.last_ts = Some(self.last_ts.map_or(ts, |t| t.max(ts)));
    }
}

#[derive(Debug)]
pub struct Mapped {
    pub event: EventRow,
    pub tool: Option<ToolFragment>,
    pub facts: Option<SessionFacts>,
}

#[derive(Debug)]
pub enum LineError {
    Json(String),
    NotAnObject,
    Field(&'static str),
}

impl fmt::Display for LineError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Json(e) => write!(f, "not valid JSON: {e}"),
            Self::NotAnObject => write!(f, "not an event object"),
            Self::Field(name) => write!(f, "missing or invalid field `{name}`"),
        }
    }
}

impl std::error::Error for LineError {}

pub fn parse_ts(text: &str) -> Option<DateTime<Utc>> {
    DateTime::parse_from_rfc3339(text)
        .ok()
        .map(|t| t.with_timezone(&Utc))
}

fn get<'a>(value: &'a Value, path: &[&str]) -> Option<&'a Value> {
    path.iter().try_fold(value, |cur, key| cur.get(*key))
}

fn string_at(value: &Value, path: &[&str]) -> Option<String> {
    get(value, path)?.as_str().map(str::to_owned)
}

/// Parses, strips, redacts and maps one `events.jsonl` line (no trailing
/// newline). `offset` is where the line starts in the file.
pub fn map_line(
    redactor: &Redactor,
    line: &[u8],
    offset: u64,
    counts: &mut Counts,
) -> Result<Mapped, LineError> {
    let mut envelope: Value =
        serde_json::from_slice(line).map_err(|e| LineError::Json(e.to_string()))?;
    let obj = envelope.as_object_mut().ok_or(LineError::NotAnObject)?;

    let event_id = obj
        .get("id")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(LineError::Field("id"))?
        .to_owned();
    let ty = obj
        .get("type")
        .and_then(Value::as_str)
        .filter(|s| !s.is_empty())
        .ok_or(LineError::Field("type"))?
        .to_owned();
    let ts = obj
        .get("timestamp")
        .and_then(Value::as_str)
        .and_then(parse_ts)
        .ok_or(LineError::Field("timestamp"))?;
    let parent_id = obj
        .get("parentId")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let agent_id = obj
        .get("agentId")
        .and_then(Value::as_str)
        .map(str::to_owned);
    let mut data = obj.remove("data").unwrap_or(Value::Null);

    let result_bytes = (ty == "tool.execution_complete")
        .then(|| raw_result_len(&data))
        .flatten();
    strip_for_type(&ty, &mut data);
    let body = redactor.json(data, DROP_KEYS, counts);

    let ctx = agent_id.clone().unwrap_or_else(|| "main".to_owned());
    let tool = tool_fragment(&ty, &body, ts, &ctx, result_bytes);
    let facts = facts_for(&ty, &body);
    let parent_tool_call_id = string_at(&body, &["parentToolCallId"]);

    Ok(Mapped {
        event: EventRow {
            event_id,
            parent_id,
            ts,
            ty,
            ctx,
            agent_id,
            parent_tool_call_id,
            src_offset: i64::try_from(offset).unwrap_or(i64::MAX),
            body,
        },
        tool,
        facts,
    })
}

fn raw_result_len(data: &Value) -> Option<i32> {
    let text = get(data, &["result", "content"])
        .or_else(|| get(data, &["error", "message"]))?
        .as_str()?;
    i32::try_from(text.len()).ok()
}

/// Removes payloads that are huge and useless for analysis, per event type.
fn strip_for_type(ty: &str, data: &mut Value) {
    let Some(obj) = data.as_object_mut() else {
        return;
    };
    match ty {
        // Base64 of the asset; keep assetId, mime type and size.
        "session.binary_asset" => {
            obj.remove("data");
        }
        // The hook's view of tool results/arguments duplicates tool.* events.
        "hook.start" => {
            if let Some(Value::Object(input)) = obj.get_mut("input") {
                for key in ["toolResult", "toolArgs", "toolCalls"] {
                    input.remove(key);
                }
            }
        }
        "system.message" => {
            if let Some(Value::String(content)) = obj.get_mut("content")
                && content.len() > SYSTEM_MESSAGE_KEEP_BYTES
            {
                let mut end = SYSTEM_MESSAGE_KEEP_BYTES;
                while !content.is_char_boundary(end) {
                    end -= 1;
                }
                content.truncate(end);
            }
        }
        "tool.execution_complete" => {
            if let Some(Value::Object(result)) = obj.get_mut("result") {
                result.remove("binaryResultsForLlm");
            }
        }
        // Attached files and images travel base64-encoded in `data`.
        "user.message" => {
            if let Some(Value::Array(attachments)) = obj.get_mut("attachments") {
                for attachment in attachments {
                    if let Value::Object(attachment) = attachment {
                        attachment.remove("data");
                    }
                }
            }
        }
        _ => {}
    }
}

fn tool_fragment(
    ty: &str,
    body: &Value,
    ts: DateTime<Utc>,
    ctx: &str,
    result_bytes: Option<i32>,
) -> Option<ToolFragment> {
    match ty {
        "tool.execution_start" => Some(ToolFragment {
            tool_call_id: string_at(body, &["toolCallId"])?,
            ctx: Some(ctx.to_owned()),
            parent_tool_call_id: string_at(body, &["parentToolCallId"]),
            tool: string_at(body, &["toolName"]),
            mcp_server: string_at(body, &["mcpServerName"]),
            args: body.get("arguments").filter(|v| !v.is_null()).cloned(),
            t_start: Some(ts),
            ..ToolFragment::default()
        }),
        "tool.execution_complete" => Some(ToolFragment {
            tool_call_id: string_at(body, &["toolCallId"])?,
            ctx: Some(ctx.to_owned()),
            result_text: string_at(body, &["result", "content"])
                .or_else(|| string_at(body, &["error", "message"])),
            result_bytes,
            ok: body.get("success").and_then(Value::as_bool),
            exit_code: get(body, &["shellExecution", "exitCode"])
                .and_then(Value::as_i64)
                .and_then(|n| i32::try_from(n).ok()),
            t_end: Some(ts),
            ..ToolFragment::default()
        }),
        _ => None,
    }
}

fn context_facts(context: &Value, facts: &mut SessionFacts) {
    facts.cwd = string_at(context, &["cwd"]);
    facts.git_root = string_at(context, &["gitRoot"]);
    facts.repository = string_at(context, &["repository"]);
    facts.host_type = string_at(context, &["hostType"]);
    facts.branch = string_at(context, &["branch"]);
}

fn facts_for(ty: &str, body: &Value) -> Option<SessionFacts> {
    let mut facts = SessionFacts::default();
    match ty {
        "session.start" | "session.resume" => {
            if let Some(context) = body.get("context") {
                context_facts(context, &mut facts);
            }
            // `selectedModel` can be the alias "auto" on resume; the resolved
            // model arrives with session.model_change.
            if ty == "session.start" {
                facts.model = string_at(body, &["selectedModel"]);
            }
            facts.effort = string_at(body, &["reasoningEffort"]);
            facts.context_tier = string_at(body, &["contextTier"]);
            facts.max_ai_credits =
                get(body, &["sessionLimits", "maxAiCredits"]).and_then(Value::as_i64);
        }
        "session.context_changed" => context_facts(body, &mut facts),
        "session.model_change" => {
            facts.model = string_at(body, &["newModel"]);
            facts.effort = string_at(body, &["reasoningEffort"]);
            facts.context_tier = string_at(body, &["contextTier"]);
        }
        "session.mode_changed" => {
            facts.autopilot = string_at(body, &["newMode"]).as_deref() == Some("autopilot");
        }
        "user.message" => {
            facts.autopilot = string_at(body, &["agentMode"]).as_deref() == Some("autopilot")
                || body
                    .get("isAutopilotContinuation")
                    .and_then(Value::as_bool)
                    .unwrap_or(false);
        }
        _ => return None,
    }
    Some(facts)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    fn map(value: Value) -> Mapped {
        let line = serde_json::to_vec(&value).unwrap();
        map_line(&Redactor::new(), &line, 42, &mut Counts::default()).unwrap()
    }

    fn envelope(ty: &str, data: Value) -> Value {
        json!({"type": ty, "id": "e1", "parentId": null,
               "timestamp": "2026-09-11T11:57:44.091Z", "data": data})
    }

    #[test]
    fn envelope_fields_become_columns() {
        let mut e = envelope(
            "assistant.message",
            json!({"content": "hi", "parentToolCallId": "t9"}),
        );
        e["agentId"] = json!("agent-1");
        e["parentId"] = json!("p0");
        let m = map(e);
        assert_eq!(m.event.event_id, "e1");
        assert_eq!(m.event.parent_id.as_deref(), Some("p0"));
        assert_eq!(m.event.ty, "assistant.message");
        assert_eq!(m.event.ctx, "agent-1");
        assert_eq!(m.event.agent_id.as_deref(), Some("agent-1"));
        assert_eq!(m.event.parent_tool_call_id.as_deref(), Some("t9"));
        assert_eq!(m.event.src_offset, 42);
        assert_eq!(m.event.ts.to_rfc3339(), "2026-09-11T11:57:44.091+00:00");
        assert_eq!(m.event.body["content"], "hi");
    }

    #[test]
    fn main_context_is_the_default() {
        let m = map(envelope("session.idle", json!({})));
        assert_eq!(m.event.ctx, "main");
        assert!(m.event.agent_id.is_none());
    }

    #[test]
    fn malformed_lines_are_rejected() {
        let r = Redactor::new();
        let mut c = Counts::default();
        assert!(matches!(
            map_line(&r, b"{nope", 0, &mut c),
            Err(LineError::Json(_))
        ));
        assert!(matches!(
            map_line(&r, b"[1]", 0, &mut c),
            Err(LineError::NotAnObject)
        ));
        let no_id = br#"{"type":"x","timestamp":"2026-09-11T11:57:44Z","data":{}}"#;
        assert!(matches!(
            map_line(&r, no_id, 0, &mut c),
            Err(LineError::Field("id"))
        ));
        let bad_ts = br#"{"type":"x","id":"1","timestamp":"yesterday","data":{}}"#;
        assert!(matches!(
            map_line(&r, bad_ts, 0, &mut c),
            Err(LineError::Field("timestamp"))
        ));
    }

    #[test]
    fn opaque_and_binary_payloads_are_stripped() {
        let m = map(envelope(
            "assistant.message",
            json!({"content": "x", "reasoningOpaque": "abc", "encryptedContent": "def",
                   "nested": {"reasoning_opaque": "ghi", "keep": 1}}),
        ));
        assert!(m.event.body.get("reasoningOpaque").is_none());
        assert!(m.event.body.get("encryptedContent").is_none());
        assert!(m.event.body["nested"].get("reasoning_opaque").is_none());
        assert_eq!(m.event.body["nested"]["keep"], 1);

        let m = map(envelope(
            "session.binary_asset",
            json!({"assetId": "a", "mimeType": "image/png", "byteLength": 3, "data": "AAAA"}),
        ));
        assert!(m.event.body.get("data").is_none());
        assert_eq!(m.event.body["assetId"], "a");

        let m = map(envelope(
            "user.message",
            json!({"content": "c", "attachments": [{"type": "file", "path": "/a", "data": "QUJD"}]}),
        ));
        assert!(m.event.body["attachments"][0].get("data").is_none());
        assert_eq!(m.event.body["attachments"][0]["path"], "/a");

        let m = map(envelope(
            "hook.start",
            json!({"hookType": "postToolUse", "input": {"toolResult": "big", "toolArgs": {}, "prompt": "p"}}),
        ));
        assert!(m.event.body["input"].get("toolResult").is_none());
        assert_eq!(m.event.body["input"]["prompt"], "p");

        let long = "é".repeat(600);
        let m = map(envelope("system.message", json!({"content": long})));
        let kept = m.event.body["content"].as_str().unwrap();
        assert!(kept.len() <= SYSTEM_MESSAGE_KEEP_BYTES);
        assert!(!kept.is_empty());
    }

    #[test]
    fn tool_fragments_merge_start_and_complete() {
        let start = map(envelope(
            "tool.execution_start",
            json!({"toolCallId": "tc1", "toolName": "bash", "arguments": {"command": "ls"},
                   "mcpServerName": null, "parentToolCallId": "tp"}),
        ));
        let mut complete_env = envelope(
            "tool.execution_complete",
            json!({"toolCallId": "tc1", "success": true,
                   "result": {"content": "file.txt\n", "detailedContent": "dup"},
                   "shellExecution": {"exitCode": 3}}),
        );
        complete_env["timestamp"] = json!("2026-09-11T11:57:46.000Z");
        let complete = map(complete_env);
        assert!(
            complete.event.body["result"]
                .get("detailedContent")
                .is_none()
        );

        let mut merged = start.tool.unwrap();
        merged.merge(complete.tool.unwrap());
        assert_eq!(merged.tool_call_id, "tc1");
        assert_eq!(merged.tool.as_deref(), Some("bash"));
        assert_eq!(merged.args, Some(json!({"command": "ls"})));
        assert_eq!(merged.result_text.as_deref(), Some("file.txt\n"));
        assert_eq!(merged.result_bytes, Some(9));
        assert_eq!(merged.ok, Some(true));
        assert_eq!(merged.exit_code, Some(3));
        assert_eq!(merged.parent_tool_call_id.as_deref(), Some("tp"));
        assert!(merged.t_start.unwrap() < merged.t_end.unwrap());
    }

    #[test]
    fn failed_tool_call_uses_the_error_message() {
        let m = map(envelope(
            "tool.execution_complete",
            json!({"toolCallId": "tc2", "success": false,
                   "error": {"message": "denied", "code": "rejected"}}),
        ));
        let t = m.tool.unwrap();
        assert_eq!(t.ok, Some(false));
        assert_eq!(t.result_text.as_deref(), Some("denied"));
        assert_eq!(t.result_bytes, Some(6));
    }

    #[test]
    fn session_facts_come_from_context_events() {
        let m = map(envelope(
            "session.start",
            json!({"selectedModel": "claude-opus-4.6", "reasoningEffort": "max",
                   "contextTier": "long_context", "sessionLimits": {"maxAiCredits": 1000},
                   "context": {"cwd": "/w", "gitRoot": "/w", "repository": "o/r",
                               "hostType": "github", "branch": "main"}}),
        ));
        let f = m.facts.unwrap();
        assert_eq!(f.cwd.as_deref(), Some("/w"));
        assert_eq!(f.repository.as_deref(), Some("o/r"));
        assert_eq!(f.model.as_deref(), Some("claude-opus-4.6"));
        assert_eq!(f.effort.as_deref(), Some("max"));
        assert_eq!(f.context_tier.as_deref(), Some("long_context"));
        assert_eq!(f.max_ai_credits, Some(1000));
        assert!(!f.autopilot);

        let resume = map(envelope(
            "session.resume",
            json!({"selectedModel": "auto", "contextTier": null}),
        ));
        let f = resume.facts.unwrap();
        assert!(
            f.model.is_none(),
            "an alias must not overwrite the resolved model"
        );
        assert!(f.context_tier.is_none());

        let m = map(envelope(
            "session.mode_changed",
            json!({"previousMode": "interactive", "newMode": "autopilot"}),
        ));
        assert!(m.facts.unwrap().autopilot);
        let m = map(envelope("session.mode_changed", json!({"newMode": "plan"})));
        assert!(!m.facts.unwrap().autopilot);
        let m = map(envelope(
            "user.message",
            json!({"content": "go", "isAutopilotContinuation": true}),
        ));
        assert!(m.facts.unwrap().autopilot);
        assert!(
            map(envelope("assistant.turn_start", json!({})))
                .facts
                .is_none()
        );
    }

    #[test]
    fn facts_merge_keeps_latest_and_monotonic_flags() {
        let mut a = SessionFacts {
            branch: Some("a".into()),
            autopilot: true,
            ..SessionFacts::default()
        };
        a.note_ts(parse_ts("2026-01-02T00:00:00Z"));
        let mut b = SessionFacts {
            branch: Some("b".into()),
            ..SessionFacts::default()
        };
        b.note_ts(parse_ts("2026-01-01T00:00:00Z"));
        a.merge(b);
        assert_eq!(a.branch.as_deref(), Some("b"));
        assert!(a.autopilot);
        assert_eq!(a.first_ts, parse_ts("2026-01-01T00:00:00Z"));
        assert_eq!(a.last_ts, parse_ts("2026-01-02T00:00:00Z"));
    }

    #[test]
    fn secrets_never_reach_the_tool_fragment() {
        let token = format!("{}{}", "ghp_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8");
        let m = map(envelope(
            "tool.execution_start",
            json!({"toolCallId": "tc3", "toolName": "bash", "arguments": {"command": format!("curl -H 'X: {token}'")}}),
        ));
        let args = m.tool.unwrap().args.unwrap().to_string();
        assert!(!args.contains(&token));
        assert!(args.contains("[REDACTED:github:"));
    }
}
