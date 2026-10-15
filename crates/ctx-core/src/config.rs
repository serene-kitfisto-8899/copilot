//! Locations and connection settings, resolved from the environment.

use std::path::{Path, PathBuf};

use anyhow::{Context, Result};

/// PostgreSQL over the local unix socket with peer authentication (PLAN §6.1).
/// [`Config::from_env`] appends `&user=<login>`: without a user in the URL
/// sqlx would connect as "anonymous", which peer authentication rejects.
pub const DEFAULT_DATABASE_URL: &str = "postgres:///copilot_ctx?host=/var/run/postgresql";

/// What the Copilot CLI writes: the SQLite store in the state directory, and
/// these two files in every session directory.
pub const STORE_FILE: &str = "session-store.db";
pub const EVENTS_FILE: &str = "events.jsonl";
pub const WORKSPACE_FILE: &str = "workspace.yaml";

#[derive(Debug, Clone)]
pub struct Config {
    /// The Copilot CLI's own state directory (`~/.copilot`).
    pub copilot_dir: PathBuf,
    pub database_url: String,
}

/// Percent-encodes everything except RFC 3986 unreserved characters.
fn encode_query_value(value: &str) -> String {
    let mut out = String::with_capacity(value.len());
    for byte in value.bytes() {
        if byte.is_ascii_alphanumeric() || matches!(byte, b'-' | b'.' | b'_' | b'~') {
            out.push(char::from(byte));
        } else {
            out.push_str(&format!("%{byte:02X}"));
        }
    }
    out
}

fn default_database_url(env: &dyn Fn(&str) -> Option<String>) -> String {
    match env("PGUSER")
        .or_else(|| env("USER"))
        .or_else(|| env("LOGNAME"))
    {
        Some(user) => format!("{DEFAULT_DATABASE_URL}&user={}", encode_query_value(&user)),
        None => DEFAULT_DATABASE_URL.to_owned(),
    }
}

impl Config {
    /// `CTX_DATABASE_URL`, then `DATABASE_URL`, then [`DEFAULT_DATABASE_URL`];
    /// `CTX_COPILOT_DIR`, then `COPILOT_HOME`, then `$HOME/.copilot`.
    pub fn from_env() -> Result<Self> {
        let env = |key: &str| std::env::var(key).ok().filter(|v| !v.is_empty());
        let copilot_dir = match env("CTX_COPILOT_DIR").or_else(|| env("COPILOT_HOME")) {
            Some(dir) => PathBuf::from(dir),
            None => PathBuf::from(env("HOME").context("HOME is not set")?).join(".copilot"),
        };
        let database_url = env("CTX_DATABASE_URL")
            .or_else(|| env("DATABASE_URL"))
            .unwrap_or_else(|| default_database_url(&env));
        Ok(Self {
            copilot_dir,
            database_url,
        })
    }

    /// `<copilot_dir>/session-state`: one directory per session.
    pub fn session_state_dir(&self) -> PathBuf {
        self.copilot_dir.join("session-state")
    }

    pub fn store_db(&self) -> PathBuf {
        self.copilot_dir.join(STORE_FILE)
    }
}

/// The database for processes that run inside somebody else's environment, like
/// the Copilot CLI's hooks: `CTX_DATABASE_URL` or the default URL, never the
/// generic `DATABASE_URL`, which in a developer's shell usually names the
/// database of whatever project they are working on.
pub fn hook_database_url(env: &dyn Fn(&str) -> Option<String>) -> String {
    env("CTX_DATABASE_URL")
        .filter(|url| !url.is_empty())
        .unwrap_or_else(|| default_database_url(env))
}

/// `events.jsonl` of a session directory.
pub fn events_path(session_dir: &Path) -> PathBuf {
    session_dir.join(EVENTS_FILE)
}

/// `workspace.yaml` of a session directory.
pub fn workspace_path(session_dir: &Path) -> PathBuf {
    session_dir.join(WORKSPACE_FILE)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn default_url_names_the_login_user() {
        let env = |k: &str| (k == "USER").then(|| "alice".to_owned());
        assert_eq!(
            default_database_url(&env),
            "postgres:///copilot_ctx?host=/var/run/postgresql&user=alice"
        );
    }

    #[test]
    fn pguser_wins_and_odd_names_are_encoded() {
        let env = |k: &str| match k {
            "PGUSER" => Some("a b@c".to_owned()),
            "USER" => Some("ignored".to_owned()),
            _ => None,
        };
        assert!(default_database_url(&env).ends_with("&user=a%20b%40c"));
    }

    #[test]
    fn no_user_in_the_environment_leaves_the_bare_url() {
        assert_eq!(default_database_url(&|_| None), DEFAULT_DATABASE_URL);
    }

    #[test]
    fn hooks_use_ctx_database_url_and_never_the_generic_one() {
        let env = |k: &str| match k {
            "CTX_DATABASE_URL" => Some("postgres:///other".to_owned()),
            "DATABASE_URL" => Some("postgres://app@db.example/prod".to_owned()),
            "USER" => Some("alice".to_owned()),
            _ => None,
        };
        assert_eq!(hook_database_url(&env), "postgres:///other");

        let env = |k: &str| match k {
            "DATABASE_URL" => Some("postgres://app@db.example/prod".to_owned()),
            "USER" => Some("alice".to_owned()),
            _ => None,
        };
        assert_eq!(
            hook_database_url(&env),
            "postgres:///copilot_ctx?host=/var/run/postgresql&user=alice"
        );

        let env = |k: &str| (k == "CTX_DATABASE_URL").then(String::new);
        assert_eq!(hook_database_url(&env), DEFAULT_DATABASE_URL);
    }
}
