//! The hook's settings: `$XDG_CONFIG_HOME/ctx/permissions.toml`, which is
//! `~/.config/ctx/permissions.toml` unless `XDG_CONFIG_HOME` says otherwise.
//!
//! ```toml
//! mode = "shadow"               # off | shadow | enforce
//! trusted_roots = ["~/work/*"]  # added to the built-in roots
//! deny = ["**/vault/**"]        # added to the built-in deny list
//! ```
//!
//! The file cannot loosen the policy: roots and deny patterns only extend the
//! built-in ones. A missing file means shadow mode with the built-ins. A file
//! that cannot be read or understood (a typo in a key, a bad pattern, a mode
//! that does not exist) makes the hook pass everything and never enforce, because
//! the safe reading of a configuration mistake is "no automatic approvals".

use std::fmt::Write as _;
use std::path::{Path, PathBuf};

use ctx_core::db::sha256_hex;
use serde::Deserialize;

use crate::trust::{DEFAULT_DENY, DEFAULT_ROOTS};
use crate::vars::Vars;

/// Bumped whenever a change to the allow-list or to the rules changes what the
/// hook decides, so that `hook_audit.policy` tells which decisions are comparable.
pub const POLICY_VERSION: u32 = 1;

/// Anything bigger is not a settings file.
const MAX_BYTES: u64 = 64 * 1024;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    /// The hook exits at once and logs nothing.
    Off,
    /// Decisions are logged to `hook_audit` and nothing is said to the CLI.
    Shadow,
    /// An allow verdict is also sent to the CLI, after it has been logged.
    Enforce,
}

impl Mode {
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Off => "off",
            Mode::Shadow => "shadow",
            Mode::Enforce => "enforce",
        }
    }
}

#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
struct File {
    mode: Option<Mode>,
    #[serde(default)]
    trusted_roots: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Config {
    pub mode: Mode,
    /// The built-in roots followed by the configured ones.
    pub roots: Vec<String>,
    /// The built-in deny patterns followed by the configured ones.
    pub deny: Vec<String>,
    /// Why the file could not be used. The hook then passes everything.
    pub error: Option<String>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            mode: Mode::Shadow,
            roots: strings(DEFAULT_ROOTS),
            deny: strings(DEFAULT_DENY),
            error: None,
        }
    }
}

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

/// `extra` after `base`, without repeating anything.
fn extend(mut base: Vec<String>, extra: Vec<String>) -> Vec<String> {
    for item in extra {
        if !base.contains(&item) {
            base.push(item);
        }
    }
    base
}

/// One line, so that it fits wherever it is printed.
fn one_line(text: &str) -> String {
    text.split_whitespace().collect::<Vec<_>>().join(" ")
}

impl Config {
    /// Shadow mode with the built-ins, remembering why the file was not used.
    pub fn broken(error: impl Into<String>) -> Config {
        Config {
            error: Some(error.into()),
            ..Config::default()
        }
    }

    pub fn parse(text: &str) -> Result<Config, String> {
        let file: File = toml::from_str(text).map_err(|e| one_line(&e.to_string()))?;
        let base = Config::default();
        Ok(Config {
            mode: file.mode.unwrap_or(base.mode),
            roots: extend(base.roots, file.trusted_roots),
            deny: extend(base.deny, file.deny),
            error: None,
        })
    }

    pub fn load(vars: &Vars, home: &Path) -> Config {
        let path = path(vars, home);
        let text = match std::fs::metadata(&path) {
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Config::default(),
            Err(e) => return Config::broken(format!("{}: {e}", path.display())),
            Ok(meta) if meta.len() > MAX_BYTES => {
                return Config::broken(format!(
                    "{}: larger than {MAX_BYTES} bytes",
                    path.display()
                ));
            }
            Ok(_) => match std::fs::read_to_string(&path) {
                Ok(text) => text,
                Err(e) => return Config::broken(format!("{}: {e}", path.display())),
            },
        };
        Config::parse(&text).unwrap_or_else(|e| Config::broken(format!("{}: {e}", path.display())))
    }

    /// What `hook_audit.policy` holds: the policy version and a short digest of
    /// everything in the configuration that changes what is allowed.
    pub fn policy_id(&self) -> String {
        if self.error.is_some() {
            return format!("v{POLICY_VERSION}:config-error");
        }
        let mut roots = self.roots.clone();
        let mut deny = self.deny.clone();
        roots.sort();
        deny.sort();
        let mut text = String::new();
        let _ = write!(
            text,
            "v{POLICY_VERSION}\nroots\n{}\ndeny\n{}",
            roots.join("\n"),
            deny.join("\n")
        );
        format!("v{POLICY_VERSION}:{}", &sha256_hex(text.as_bytes())[..8])
    }
}

pub fn path(vars: &Vars, home: &Path) -> PathBuf {
    xdg(vars, "XDG_CONFIG_HOME", home, ".config").join("ctx/permissions.toml")
}

/// The XDG base directory in `var` when it is an absolute path, else
/// `~/<fallback>`.
pub fn xdg(vars: &Vars, var: &str, home: &Path, fallback: &str) -> PathBuf {
    match vars.get(var) {
        Some(dir) if Path::new(&dir).is_absolute() => PathBuf::from(dir),
        _ => home.join(fallback),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_are_shadow_with_the_built_ins() {
        let c = Config::default();
        assert_eq!(c.mode, Mode::Shadow);
        assert_eq!(c.roots, strings(DEFAULT_ROOTS));
        assert_eq!(c.deny, strings(DEFAULT_DENY));
        assert_eq!(c.error, None);
        assert_eq!(Config::parse("").unwrap(), c);
    }

    #[test]
    fn modes_parse_and_anything_else_is_an_error() {
        for (text, mode) in [
            ("off", Mode::Off),
            ("shadow", Mode::Shadow),
            ("enforce", Mode::Enforce),
        ] {
            let c = Config::parse(&format!("mode = \"{text}\"")).unwrap();
            assert_eq!(c.mode, mode);
            assert_eq!(c.mode.as_str(), text);
        }
        for bad in [
            "mode = \"Enforce\"",
            "mode = \"enforced\"",
            "mode = \"\"",
            "mode = true",
            "mode = 1",
        ] {
            assert!(Config::parse(bad).is_err(), "{bad}");
        }
    }

    #[test]
    fn roots_and_deny_extend_the_built_ins_and_cannot_remove_them() {
        let c = Config::parse(
            "mode = \"enforce\"\ntrusted_roots = [\"~/work/*\", \"~/kms*\"]\ndeny = [\"**/vault/**\"]",
        )
        .unwrap();
        assert_eq!(
            c.roots.len(),
            DEFAULT_ROOTS.len() + 1,
            "the repeated root is not added twice"
        );
        assert_eq!(
            &c.roots[..DEFAULT_ROOTS.len()],
            strings(DEFAULT_ROOTS).as_slice()
        );
        assert_eq!(c.roots.last().unwrap(), "~/work/*");
        assert_eq!(
            &c.deny[..DEFAULT_DENY.len()],
            strings(DEFAULT_DENY).as_slice()
        );
        assert_eq!(c.deny.last().unwrap(), "**/vault/**");
    }

    #[test]
    fn typos_and_wrong_types_are_errors_not_silent_defaults() {
        for bad in [
            "trusted_root = [\"~/x\"]",
            "modes = \"shadow\"",
            "trusted_roots = \"~/x\"",
            "deny = [1]",
            "mode = \"shadow\"\n[extra]\nx = 1",
            "mode = ",
            "\u{0}",
        ] {
            let err = Config::parse(bad).unwrap_err();
            assert!(!err.contains('\n'), "{err:?}");
        }
    }

    #[test]
    fn a_broken_config_is_shadow_and_says_why() {
        let c = Config::broken("nope");
        assert_eq!(c.mode, Mode::Shadow);
        assert_eq!(c.error.as_deref(), Some("nope"));
        assert_eq!(c.policy_id(), format!("v{POLICY_VERSION}:config-error"));
    }

    #[test]
    fn policy_id_follows_what_is_allowed_and_nothing_else() {
        let base = Config::default().policy_id();
        assert!(base.starts_with(&format!("v{POLICY_VERSION}:")));
        assert_eq!(base.len(), format!("v{POLICY_VERSION}:").len() + 8);
        assert!(
            base.bytes().skip(3).all(|b| b.is_ascii_hexdigit()),
            "{base}"
        );

        let enforce = Config::parse("mode = \"enforce\"").unwrap();
        assert_eq!(
            enforce.policy_id(),
            base,
            "the mode is not part of the policy"
        );

        let more = Config::parse("trusted_roots = [\"~/work/*\"]").unwrap();
        assert_ne!(more.policy_id(), base);
        let denied = Config::parse("deny = [\"**/vault/**\"]").unwrap();
        assert_ne!(denied.policy_id(), base);
        assert_ne!(denied.policy_id(), more.policy_id());

        let a = Config::parse("trusted_roots = [\"~/a/*\", \"~/b/*\"]").unwrap();
        let b = Config::parse("trusted_roots = [\"~/b/*\", \"~/a/*\"]").unwrap();
        assert_eq!(a.policy_id(), b.policy_id(), "the order does not matter");
    }

    #[test]
    fn the_file_is_found_through_xdg_or_home() {
        let home = Path::new("/home/u");
        assert_eq!(
            path(&Vars::fixed(&[]), home),
            PathBuf::from("/home/u/.config/ctx/permissions.toml")
        );
        assert_eq!(
            path(&Vars::fixed(&[("XDG_CONFIG_HOME", "/cfg")]), home),
            PathBuf::from("/cfg/ctx/permissions.toml")
        );
        for relative in ["", "cfg", "./cfg"] {
            assert_eq!(
                path(&Vars::fixed(&[("XDG_CONFIG_HOME", relative)]), home),
                PathBuf::from("/home/u/.config/ctx/permissions.toml"),
                "{relative:?}"
            );
        }
    }

    #[test]
    fn load_handles_a_missing_a_good_and_a_bad_file() {
        let dir = tempfile::tempdir().unwrap();
        let home = dir.path();
        let vars = Vars::fixed(&[]);
        assert_eq!(Config::load(&vars, home), Config::default());

        let file = path(&vars, home);
        std::fs::create_dir_all(file.parent().unwrap()).unwrap();
        std::fs::write(&file, "mode = \"enforce\"\n").unwrap();
        assert_eq!(Config::load(&vars, home).mode, Mode::Enforce);

        std::fs::write(&file, "mode = \"yes please\"\n").unwrap();
        let c = Config::load(&vars, home);
        assert_eq!(c.mode, Mode::Shadow);
        assert!(c.error.unwrap().contains("permissions.toml"));

        std::fs::write(&file, vec![b'#'; MAX_BYTES as usize + 1]).unwrap();
        assert!(
            Config::load(&vars, home)
                .error
                .unwrap()
                .contains("larger than")
        );

        std::fs::write(&file, [0xff, 0xfe, b'x']).unwrap();
        assert!(Config::load(&vars, home).error.is_some(), "not UTF-8");

        std::fs::remove_file(&file).unwrap();
        std::fs::create_dir(&file).unwrap();
        assert!(
            Config::load(&vars, home).error.is_some(),
            "a directory is not a file"
        );
    }
}
