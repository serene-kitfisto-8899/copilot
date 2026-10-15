//! Redaction: the single choke point every string passes through before it is
//! stored (PLAN.md §6.4).
//!
//! Secrets are replaced by `[REDACTED:<kind>:<sha8>]` where `sha8` is the
//! first 8 hex digits of the SHA-256 of the secret, so equal secrets can be
//! correlated without being recoverable. Callers only ever see counts per
//! kind: neither matches nor their hashes are logged.
//!
//! Order of operations for one string: strip NULs (PostgreSQL text/jsonb
//! reject them), replace base64 blobs, redact secrets, and only then cap the
//! length, so a secret can never survive as a harmless-looking truncated
//! prefix.

use std::collections::BTreeMap;

use regex::{Regex, RegexSet};
use serde_json::{Map, Value};
use sha2::{Digest, Sha256};

/// Longest string kept in `events.body`, `tool_calls` and friends.
pub const MAX_STRING_BYTES: usize = 8 * 1024;
/// Contiguous base64-alphabet strings at least this long are binary payloads
/// (images, opaque blobs, bare key material), not text.
const BLOB_MIN_BYTES: usize = 512;
/// Strings shorter than this cannot contain any secret pattern below.
const MIN_SCANNED_BYTES: usize = 12;

pub const MARKER_PREFIX: &str = "[REDACTED:";

/// Redactions performed, per kind.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Counts(BTreeMap<&'static str, u64>);

impl Counts {
    pub fn add(&mut self, kind: &'static str, n: u64) {
        *self.0.entry(kind).or_default() += n;
    }

    pub fn merge(&mut self, other: &Counts) {
        for (kind, n) in &other.0 {
            self.add(kind, *n);
        }
    }

    pub fn total(&self) -> u64 {
        self.0.values().sum()
    }

    pub fn is_empty(&self) -> bool {
        self.0.is_empty()
    }

    pub fn get(&self, kind: &str) -> u64 {
        self.0.get(kind).copied().unwrap_or(0)
    }

    pub fn iter(&self) -> impl Iterator<Item = (&'static str, u64)> + '_ {
        self.0.iter().map(|(k, n)| (*k, *n))
    }
}

struct Rule {
    kind: &'static str,
    re: Regex,
    /// Capture group holding the secret; the rest of the match is kept.
    group: usize,
}

const WORDS: &str = "password|passwd|pwd|secret|api[_-]?key|token|private[_-]?key|credential";

/// Rule definitions: (kind, pattern, capture group that is the secret).
fn rule_table() -> Vec<(&'static str, String, usize)> {
    vec![
        // A complete PEM block, then the fallback for a block whose END line
        // was cut off by the CLI's own output limit.
        (
            "pem",
            r"(?s)-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----.*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----".into(),
            0,
        ),
        (
            "pem",
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[A-Za-z0-9+/=\s\\:,._-]{16,}".into(),
            0,
        ),
        (
            "github",
            r"(?:gh[pousr]_[A-Za-z0-9]{36,255}|github_pat_[A-Za-z0-9_]{22,255})".into(),
            0,
        ),
        ("aws", r"\b(?:AKIA|ASIA|AROA|AIDA)[A-Z0-9]{16}\b".into(), 0),
        (
            "jwt",
            r"eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}".into(),
            0,
        ),
        (
            "bearer",
            r"(?i)\bbearer\s+([A-Za-z0-9._~+/=-]{30,})".into(),
            1,
        ),
        (
            "slack",
            r"(?:xox[baprs]-[A-Za-z0-9-]{10,}|xapp-[0-9]-[A-Za-z0-9-]{10,})".into(),
            0,
        ),
        ("stripe", r"\b[sr]k_(?:live|test)_[A-Za-z0-9]{16,}".into(), 0),
        // Provider-specific prefixes that are not in the plan's list but are
        // just as unambiguous.
        ("google", r"AIza[0-9A-Za-z_-]{35}".into(), 0),
        ("sk", r"\bsk-(?:ant-|proj-)?[A-Za-z0-9_-]{32,}".into(), 0),
        ("npm", r"\bnpm_[A-Za-z0-9]{36}".into(), 0),
        ("gitlab", r"\bglpat-[A-Za-z0-9_-]{20,}".into(), 0),
        ("hf", r"\bhf_[A-Za-z0-9]{34,}".into(), 0),
        ("pypi", r"\bpypi-[A-Za-z0-9_-]{50,}".into(), 0),
        (
            "sendgrid",
            r"\bSG\.[A-Za-z0-9_-]{22}\.[A-Za-z0-9_-]{43}".into(),
            0,
        ),
        // scheme://user:PASSWORD@host
        (
            "url_cred",
            r"://[^/\s:@]+:([^@\s/]{6,})@".into(),
            1,
        ),
        // Authorization: [Basic|Bearer|Token] VALUE
        (
            "auth_header",
            r#"(?i)\bauthorization\b\\?["']?\s*[:=]\s*\\?["']?(?:basic|bearer|token|digest)?\s*([A-Za-z0-9._~+/=-]{16,})"#.into(),
            1,
        ),
        // password / passwd / secret / api_key / token ... = VALUE (12+ chars).
        // The key may be embedded in a longer identifier (GITHUB_TOKEN) and may
        // be quoted, even with backslash-escaped quotes (JSON text inside a
        // JSON string). Values that are references rather than literals are
        // left alone: they cannot start with $ (shell/template variable),
        // `:` (a `::` path), `/` (a file path) or `[` (an existing marker), and
        // stop at `(` (a call expression).
        (
            "assign",
            format!(
                r#"(?i)(?:{WORDS})[A-Za-z0-9_.-]*\\?["']?[ \t]*[:=][ \t]*\\?["']?([^\s"'<>;&|)(\\$:/\[][^\s"'<>;&|)(\\]{{11,}})"#
            ),
            1,
        ),
    ]
}

/// JSON object keys whose string values are secrets regardless of content.
fn is_secret_key(key: &str) -> bool {
    let norm: String = key
        .chars()
        .filter(|c| *c != '_' && *c != '-')
        .map(|c| c.to_ascii_lowercase())
        .collect();
    const SUFFIXES: [&str; 9] = [
        "password",
        "passwd",
        "pwd",
        "secret",
        "apikey",
        "token",
        "privatekey",
        "credential",
        "credentials",
    ];
    norm == "authorization" || SUFFIXES.iter().any(|s| norm.ends_with(s))
}

/// Keys holding identifiers (`toolCallId`, `apiCallId`, `requestId`, ...).
fn is_id_key(key: &str) -> bool {
    let lower = key.to_ascii_lowercase();
    ["id", "ids", "uuid", "ref"]
        .iter()
        .any(|s| lower.ends_with(s))
}

pub struct Redactor {
    rules: Vec<Rule>,
    set: RegexSet,
    entropy_candidate: Regex,
}

impl Default for Redactor {
    fn default() -> Self {
        Self::new()
    }
}

impl Redactor {
    pub fn new() -> Self {
        let table = rule_table();
        let rules: Vec<Rule> = table
            .iter()
            .map(|(kind, pat, group)| Rule {
                kind,
                re: Regex::new(pat).unwrap_or_else(|e| panic!("bad redaction pattern {kind}: {e}")),
                group: *group,
            })
            .collect();
        let set = RegexSet::new(table.iter().map(|(_, p, _)| p.as_str()))
            .expect("redaction patterns compile as a set");
        Self {
            rules,
            set,
            entropy_candidate: Regex::new(r"[A-Za-z0-9+_=-]{32,}").expect("entropy pattern"),
        }
    }

    /// Redacts one string. Returns the scrubbed text (NULs removed); `counts`
    /// is updated with what was replaced.
    pub fn text(&self, input: &str, counts: &mut Counts) -> String {
        self.text_opts(input, true, counts)
    }

    /// `entropy` is off for identifier fields (`toolCallId`, `apiCallId`, ...):
    /// those are random-looking by design and must stay joinable.
    fn text_opts(&self, input: &str, entropy: bool, counts: &mut Counts) -> String {
        let mut text = if input.contains('\0') {
            input.replace('\0', "")
        } else {
            input.to_owned()
        };
        if text.len() < MIN_SCANNED_BYTES {
            return text;
        }
        let matched = self.set.matches(&text);
        if matched.matched_any() {
            for idx in matched.iter() {
                let rule = &self.rules[idx];
                text = replace_group(&rule.re, rule.group, rule.kind, &text, counts);
            }
        }
        if entropy {
            self.redact_entropy(&text, counts)
        } else {
            text
        }
    }

    /// Random-looking long tokens that no prefix rule recognised: >= 32 chars
    /// of one token alphabet, Shannon entropy >= 4.3 bits/char, and a mix of
    /// upper case, lower case and digits. Hex digests and UUIDs stay below the
    /// entropy bar (max 4.0 bits) and lower-case-only identifiers lack the mix.
    fn redact_entropy(&self, text: &str, counts: &mut Counts) -> String {
        if text.len() < 32 {
            return text.to_owned();
        }
        let mut out = String::with_capacity(text.len());
        let mut last = 0;
        let mut hit = false;
        for m in self.entropy_candidate.find_iter(text) {
            if !looks_random(m.as_str()) {
                continue;
            }
            hit = true;
            out.push_str(&text[last..m.start()]);
            out.push_str(&marker("entropy", m.as_str()));
            counts.add("entropy", 1);
            last = m.end();
        }
        if !hit {
            return text.to_owned();
        }
        out.push_str(&text[last..]);
        out
    }

    /// Redacts, strips and caps a whole JSON value. `drop_keys` are removed at
    /// any depth (opaque/encrypted blobs the CLI stores for its own use).
    pub fn json(&self, value: Value, drop_keys: &[&str], counts: &mut Counts) -> Value {
        self.json_inner(value, drop_keys, true, counts)
    }

    fn json_inner(
        &self,
        value: Value,
        drop_keys: &[&str],
        entropy: bool,
        counts: &mut Counts,
    ) -> Value {
        match value {
            Value::String(s) => {
                Value::String(self.field_opts(&s, MAX_STRING_BYTES, entropy, counts))
            }
            Value::Array(items) => Value::Array(
                items
                    .into_iter()
                    .map(|v| self.json_inner(v, drop_keys, entropy, counts))
                    .collect(),
            ),
            Value::Object(map) => {
                let mut out = Map::with_capacity(map.len());
                for (key, v) in map {
                    if drop_keys.contains(&key.as_str()) {
                        continue;
                    }
                    let v = match v {
                        Value::String(s) if is_secret_key(&key) => {
                            Value::String(self.secret_field(&s, counts))
                        }
                        other => self.json_inner(other, drop_keys, !is_id_key(&key), counts),
                    };
                    out.insert(key, v);
                }
                Value::Object(out)
            }
            other => other,
        }
    }

    /// A string stored as a column or JSON leaf: blob check, redaction, cap.
    pub fn field(&self, input: &str, counts: &mut Counts) -> String {
        self.field_opts(input, MAX_STRING_BYTES, true, counts)
    }

    /// Like [`Redactor::field`] with a caller-chosen cap (long-form columns).
    pub fn field_capped(&self, input: &str, max_bytes: usize, counts: &mut Counts) -> String {
        self.field_opts(input, max_bytes, true, counts)
    }

    fn field_opts(
        &self,
        input: &str,
        max_bytes: usize,
        entropy: bool,
        counts: &mut Counts,
    ) -> String {
        if let Some(blob) = blob_placeholder(input) {
            return blob;
        }
        let redacted = self.text_opts(input, entropy, counts);
        cap(&redacted, max_bytes)
    }

    /// The value of a secret-named key: replaced wholesale unless it is short
    /// (a flag such as "none" or an already redacted marker).
    fn secret_field(&self, input: &str, counts: &mut Counts) -> String {
        if input.len() < 12 || input.starts_with(MARKER_PREFIX) {
            return self.field(input, counts);
        }
        counts.add("key", 1);
        marker("key", input)
    }
}

fn marker(kind: &str, secret: &str) -> String {
    let digest = Sha256::digest(secret.as_bytes());
    let mut sha8 = String::with_capacity(8);
    for byte in digest.iter().take(4) {
        sha8.push_str(&format!("{byte:02x}"));
    }
    format!("{MARKER_PREFIX}{kind}:{sha8}]")
}

fn replace_group(
    re: &Regex,
    group: usize,
    kind: &'static str,
    text: &str,
    counts: &mut Counts,
) -> String {
    let mut out = String::with_capacity(text.len());
    let mut last = 0;
    let mut hit = false;
    for caps in re.captures_iter(text) {
        let Some(secret) = caps.get(group) else {
            continue;
        };
        if secret.as_str().starts_with(MARKER_PREFIX) {
            continue;
        }
        hit = true;
        out.push_str(&text[last..secret.start()]);
        out.push_str(&marker(kind, secret.as_str()));
        counts.add(kind, 1);
        last = secret.end();
    }
    if !hit {
        return text.to_owned();
    }
    out.push_str(&text[last..]);
    out
}

fn looks_random(token: &str) -> bool {
    let (mut upper, mut lower, mut digit) = (false, false, false);
    for b in token.bytes() {
        upper |= b.is_ascii_uppercase();
        lower |= b.is_ascii_lowercase();
        digit |= b.is_ascii_digit();
    }
    upper && lower && digit && shannon_entropy(token) >= 4.3
}

fn shannon_entropy(token: &str) -> f64 {
    let mut freq = [0u32; 256];
    for b in token.bytes() {
        freq[b as usize] += 1;
    }
    let len = token.len() as f64;
    freq.iter()
        .filter(|&&n| n > 0)
        .map(|&n| {
            let p = f64::from(n) / len;
            -p * p.log2()
        })
        .sum()
}

/// `[blob N bytes]` for long pure-base64 payloads (images, attachments).
fn blob_placeholder(s: &str) -> Option<String> {
    if s.len() < BLOB_MIN_BYTES {
        return None;
    }
    s.bytes()
        .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'_' | b'-'))
        .then(|| format!("[blob {} bytes]", s.len()))
}

/// Truncates to at most `max` bytes on a char boundary, noting what was cut.
pub fn cap(s: &str, max: usize) -> String {
    if s.len() <= max {
        return s.to_owned();
    }
    let mut end = max;
    while !s.is_char_boundary(end) {
        end -= 1;
    }
    format!("{}…[+{} bytes]", &s[..end], s.len() - end)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serde_json::json;

    // Synthetic secrets are assembled at run time so this file itself never
    // contains a literal that real secret scanners (or our own verify pass)
    // would flag.
    fn gh() -> String {
        format!("{}{}", "ghp_", "A1b2C3d4E5f6G7h8I9j0K1l2M3n4O5p6Q7r8")
    }

    fn pem(label: &str) -> String {
        let begin = format!("-----BEGIN {label} PRIVATE KEY-----");
        let end = format!("-----END {label} PRIVATE KEY-----");
        format!(
            "{begin}\nMIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQC7\nabcDEF123+/xyz=\n{end}"
        )
    }

    fn run(input: &str) -> (String, Counts) {
        let mut counts = Counts::default();
        let out = Redactor::new().text(input, &mut counts);
        (out, counts)
    }

    #[test]
    fn github_token_is_replaced_and_counted() {
        let token = gh();
        let (out, counts) = run(&format!("export X={token} done"));
        assert!(!out.contains(&token));
        assert!(out.contains(MARKER_PREFIX));
        assert_eq!(counts.get("github"), 1);
    }

    #[test]
    fn same_secret_gets_same_marker_and_different_secret_differs() {
        let a = marker("github", "secret-one-secret-one");
        let b = marker("github", "secret-one-secret-one");
        let c = marker("github", "secret-two-secret-two");
        assert_eq!(a, b);
        assert_ne!(a, c);
        assert_eq!(a.len(), "[REDACTED:github:".len() + 8 + 1);
    }

    #[test]
    fn complete_and_truncated_pem_blocks_are_removed() {
        for label in ["RSA", "OPENSSH", "EC", "ENCRYPTED"] {
            let block = pem(label);
            let (out, counts) = run(&format!("before\n{block}\nafter"));
            assert!(!out.contains("MIIEvQ"), "{label}: body leaked");
            assert!(out.starts_with("before\n") && out.ends_with("\nafter"));
            assert_eq!(counts.get("pem"), 1, "{label}");
        }
        let truncated = pem("RSA");
        let cut = &truncated[..truncated.find("-----END").unwrap()];
        let (out, counts) = run(cut);
        assert!(!out.contains("MIIEvQ"));
        assert_eq!(counts.get("pem"), 1);
    }

    #[test]
    fn pem_with_escaped_newlines_inside_json_text_is_removed() {
        let escaped = pem("RSA").replace('\n', "\\n");
        let (out, counts) = run(&format!("{{\"key\":\"{escaped}\"}}"));
        assert!(!out.contains("MIIEvQ"));
        assert_eq!(counts.get("pem"), 1);
    }

    #[test]
    fn aws_jwt_bearer_slack_stripe() {
        let aws = format!("{}{}", "AKIA", "ABCDEFGH12345678");
        let jwt = format!(
            "{}.{}.{}",
            "eyJhbGciOiJIUzI1NiJ9", "eyJzdWIiOiIxMjM0NTY3ODkwIn0", "dBjftJeZ4CVPmB92K27uhbUJU1p1r"
        );
        let bearer = "Bearer abcdefghijklmnopqrstuvwxyz0123456789ABC";
        let slack = format!("{}{}", "xoxb-", "123456789012-abcdefghijklmnop");
        let stripe = format!("{}{}", "sk_live_", "abcdefghijklmnop1234");
        let (out, counts) = run(&format!("{aws} {jwt} {bearer} {slack} {stripe}"));
        for kind in ["aws", "jwt", "bearer", "slack", "stripe"] {
            assert_eq!(counts.get(kind), 1, "{kind}");
        }
        assert!(!out.contains("ABCDEFGH12345678"));
        assert!(!out.contains("dBjftJeZ4"));
        assert!(!out.contains("abcdefghijklmnopqrstuvwxyz0123456789ABC"));
        assert!(
            out.contains("Bearer [REDACTED:bearer:"),
            "keeps the word Bearer"
        );
    }

    #[test]
    fn assignments_replace_only_the_value() {
        let (out, counts) = run("DB_PASSWORD=hunter2hunter2 and api_key: \"abcdefghijklmnop\"");
        assert!(out.starts_with("DB_PASSWORD=[REDACTED:assign:"));
        assert!(!out.contains("hunter2hunter2"));
        assert!(!out.contains("abcdefghijklmnop"));
        assert_eq!(counts.get("assign"), 2);
    }

    #[test]
    fn assignments_inside_escaped_json_text() {
        let (out, counts) = run(r#"{"cmd":"{\"password\": \"hunter2hunter2xyz\"}"}"#);
        assert!(!out.contains("hunter2hunter2xyz"));
        assert!(counts.get("assign") >= 1);
    }

    #[test]
    fn short_or_missing_values_are_left_alone() {
        let (out, counts) = run("password=short token: abc secret = none");
        assert_eq!(out, "password=short token: abc secret = none");
        assert!(counts.is_empty());
    }

    #[test]
    fn markers_are_never_re_redacted() {
        let token = gh();
        let (once, _) = run(&format!("token={token}"));
        let (twice, counts) = run(&once);
        assert_eq!(once, twice);
        assert!(counts.is_empty());
    }

    #[test]
    fn url_credentials_and_auth_headers() {
        let (out, counts) = run("postgres://app:s3cr3tpassw0rd@db.example:5432/x");
        assert!(out.contains("postgres://app:[REDACTED:url_cred:"));
        assert!(out.ends_with("@db.example:5432/x"));
        assert_eq!(counts.get("url_cred"), 1);

        let (out, counts) = run("Authorization: Basic dXNlcjpwYXNzd29yZHBhc3N3b3Jk");
        assert!(!out.contains("dXNlcjpwYXNz"));
        assert_eq!(counts.get("auth_header"), 1);
    }

    #[test]
    fn entropy_rule_catches_random_tokens_but_not_ids() {
        let random = "Zx9Qm2LpV7cT4bN8wRk3YfH6sJd1GaE5uXo0";
        let (out, counts) = run(&format!("value is {random} ok"));
        assert!(!out.contains(random));
        assert_eq!(counts.get("entropy"), 1);

        let sha256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855";
        let uuid = "123e4567-e89b-12d3-a456-426614174000";
        let ident = "ServerCapabilitiesInitializeRequestParamsBuilder";
        let path = "/home/user/project/target/debug/deps/libsqlx_postgres-4c2b8f1a9d3e7b50.rlib";
        let text =
            format!("{sha256} {uuid} {ident} {path} 3a6f9c1d2e4b5a7c8d9e0f1a2b3c4d5e6f708192");
        let (out, counts) = run(&text);
        assert_eq!(out, text);
        assert!(counts.is_empty());
    }

    #[test]
    fn identifier_keys_keep_random_looking_values() {
        let r = Redactor::new();
        let mut counts = Counts::default();
        let id = "Zx9Qm2LpV7cT4bN8wRk3YfH6sJd1GaE5uXo0";
        let out = r.json(
            json!({"toolCallId": id, "apiCallId": id, "ids": [id], "note": id}),
            &[],
            &mut counts,
        );
        assert_eq!(out["toolCallId"], id);
        assert_eq!(out["apiCallId"], id);
        assert_eq!(out["ids"][0], id);
        assert!(out["note"].as_str().unwrap().starts_with(MARKER_PREFIX));
        assert_eq!(counts.get("entropy"), 1);
    }

    #[test]
    fn reference_values_are_not_secrets() {
        for text in [
            "password=${DB_PASSWORD_ENV}",
            "password=$DB_PASSWORD_VALUE",
            "token: ::tokio::sync::Mutex",
            "secret=/run/secrets/db_password_file",
            "api_key = get_key()",
        ] {
            let (out, counts) = run(text);
            assert_eq!(out, text);
            assert!(counts.is_empty(), "{text}");
        }
    }

    #[test]
    fn nuls_are_stripped() {
        let (out, _) = run("a\0b\0c and some more text");
        assert!(!out.contains('\0'));
    }

    #[test]
    fn json_secret_keys_replace_the_whole_value() {
        let r = Redactor::new();
        let mut counts = Counts::default();
        let v = json!({
            "apiKey": "plain-looking-value-123",
            "client_secret": "another plain looking value",
            "tokenType": "cache_read",
            "maxTokens": 4096,
            "token": "short",
            "nested": {"Authorization": "Bearer x"},
            "list": [{"password": "correct horse battery"}],
        });
        let out = r.json(v, &[], &mut counts);
        assert!(out["apiKey"].as_str().unwrap().starts_with(MARKER_PREFIX));
        assert!(
            out["client_secret"]
                .as_str()
                .unwrap()
                .starts_with(MARKER_PREFIX)
        );
        assert_eq!(out["tokenType"], "cache_read");
        assert_eq!(out["maxTokens"], 4096);
        assert_eq!(out["token"], "short");
        assert_eq!(out["nested"]["Authorization"], "Bearer x");
        assert!(
            out["list"][0]["password"]
                .as_str()
                .unwrap()
                .starts_with(MARKER_PREFIX)
        );
        assert_eq!(counts.get("key"), 3);
    }

    #[test]
    fn json_drops_requested_keys_at_any_depth() {
        let r = Redactor::new();
        let mut counts = Counts::default();
        let v = json!({"a": 1, "reasoningOpaque": "xxxxxxxxxxxxxxxx", "n": {"encryptedContent": "yyyyyyyyyyyyyyyy", "k": 2}});
        let out = r.json(v, &["reasoningOpaque", "encryptedContent"], &mut counts);
        assert_eq!(out, json!({"a": 1, "n": {"k": 2}}));
    }

    #[test]
    fn blobs_are_replaced_and_long_text_is_capped_after_redaction() {
        let r = Redactor::new();
        let mut counts = Counts::default();
        let blob = "A".repeat(3000);
        assert_eq!(r.field(&blob, &mut counts), "[blob 3000 bytes]");

        let token = gh();
        // Secret straddles the cap boundary: it must be redacted first.
        let mut long = "x ".repeat(4090);
        long.push_str(&token);
        long.push_str(&" y".repeat(100));
        let out = r.field(&long, &mut counts);
        assert!(!out.contains("A1b2C3d4E5f6"));
        assert!(out.len() <= MAX_STRING_BYTES + 40);
        assert!(out.contains("…[+"));
    }

    #[test]
    fn cap_respects_char_boundaries() {
        let s = "é".repeat(5000);
        let out = cap(&s, 8191);
        assert!(out.starts_with('é'));
        assert!(out.is_char_boundary(out.len()));
    }
}
