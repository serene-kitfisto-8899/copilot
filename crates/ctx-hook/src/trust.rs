//! Which paths the hook may vouch for (PLAN.md §6.6): inside a trusted root and
//! outside the deny-list, judged on the path as the kernel will resolve it.

use crate::shell::{Reject, Res};
use globset::{Glob, GlobBuilder, GlobSet, GlobSetBuilder};
use std::collections::HashSet;
use std::ffi::OsString;
use std::io::ErrorKind;
use std::path::{Path, PathBuf};

/// Directories (directly below the home directory) whose whole tree is trusted.
pub const DEFAULT_ROOTS: &[&str] = &["~/kms*", "~/pr-*"];

/// Never vouched for, even inside a trusted root. A pattern without a `/`
/// matches a file name at any depth, like in a `.gitignore`.
pub const DEFAULT_DENY: &[&str] = &[
    ".env*",
    "*.pem",
    "*.key",
    "*.p12",
    "*.pfx",
    "id_rsa*",
    "id_dsa*",
    "id_ecdsa*",
    "id_ed25519*",
    ".netrc",
    ".npmrc",
    ".pypirc",
    ".git-credentials",
    ".pgpass",
    "~/.ssh/**",
    "~/.gnupg/**",
    "~/.aws/**",
    "~/.kube/**",
    "~/.config/gh/**",
    "~/.docker/config.json",
    "~/.copilot/config.json",
];

/// Most directory entries a wildcard may scan, and most matches it may expand to.
const GLOB_SCAN_CAP: usize = 20_000;
const GLOB_MATCH_CAP: usize = 500;

pub struct Trust {
    /// Canonical directories; everything below one of them is trusted.
    roots: HashSet<PathBuf>,
    deny: GlobSet,
}

fn has_meta(s: &str) -> bool {
    s.contains(['*', '?', '[', ']', '{', '}'])
}

fn expand_tilde(pattern: &str, home: &Path) -> String {
    let home = home.to_string_lossy();
    if pattern == "~" {
        home.into_owned()
    } else if let Some(rest) = pattern.strip_prefix("~/") {
        format!("{}/{rest}", home.trim_end_matches('/'))
    } else {
        pattern.to_owned()
    }
}

fn matcher(pattern: &str) -> Result<globset::GlobMatcher, String> {
    GlobBuilder::new(pattern)
        .literal_separator(true)
        .build()
        .map(|g| g.compile_matcher())
        .map_err(|e| format!("bad glob {pattern:?}: {e}"))
}

impl Trust {
    /// `roots` are patterns whose last path component may contain wildcards;
    /// they are resolved to the real directories that exist right now.
    pub fn new(home: &Path, roots: &[String], deny: &[String]) -> Result<Self, String> {
        let mut homes = vec![home.to_path_buf()];
        if let Ok(real) = std::fs::canonicalize(home)
            && real != home
        {
            homes.push(real);
        }
        let mut set = HashSet::new();
        for pattern in roots {
            let expanded = expand_tilde(pattern, home);
            let path = Path::new(&expanded);
            if !path.is_absolute() {
                return Err(format!(
                    "trusted root {pattern:?} is not an absolute path or ~/..."
                ));
            }
            let (Some(parent), Some(last)) = (path.parent(), path.file_name()) else {
                return Err(format!("trusted root {pattern:?} has no parent directory"));
            };
            if has_meta(&parent.to_string_lossy()) {
                return Err(format!(
                    "trusted root {pattern:?}: only the last path component may contain wildcards"
                ));
            }
            let last = last.to_string_lossy();
            if has_meta(&last) {
                let m = matcher(&last)?;
                let Ok(entries) = std::fs::read_dir(parent) else {
                    continue;
                };
                for entry in entries.flatten().take(GLOB_SCAN_CAP) {
                    let name = entry.file_name().to_string_lossy().into_owned();
                    if name.starts_with('.') && !last.starts_with('.') {
                        continue;
                    }
                    if m.is_match(&name) {
                        add_root(&mut set, &entry.path());
                    }
                }
            } else {
                add_root(&mut set, path);
            }
        }

        let mut builder = GlobSetBuilder::new();
        for pattern in deny {
            let variants: Vec<String> = if pattern.starts_with('~') {
                homes.iter().map(|h| expand_tilde(pattern, h)).collect()
            } else {
                vec![pattern.clone()]
            };
            for variant in variants {
                let anchored = if variant.contains('/') {
                    variant
                } else {
                    format!("**/{variant}")
                };
                // `dir/**` must refuse the directory itself too, not only its contents
                let bare = anchored.strip_suffix("/**").map(str::to_owned);
                for g in std::iter::once(anchored).chain(bare) {
                    let glob: Glob = GlobBuilder::new(&g)
                        .literal_separator(true)
                        .build()
                        .map_err(|e| format!("bad deny glob {pattern:?}: {e}"))?;
                    builder.add(glob);
                }
            }
        }
        let deny = builder.build().map_err(|e| format!("deny globs: {e}"))?;
        Ok(Self { roots: set, deny })
    }

    pub fn roots(&self) -> impl Iterator<Item = &PathBuf> {
        self.roots.iter()
    }

    /// An ancestor-or-self of a canonical path is a trusted root.
    pub fn is_trusted(&self, canonical: &Path) -> bool {
        canonical.ancestors().any(|a| self.roots.contains(a))
    }

    pub fn is_denied(&self, path: &Path) -> bool {
        self.deny.is_match(path)
    }

    /// The canonical form of `raw` (relative to `cwd`), provided it is trusted
    /// and not denied, judged both as written and as resolved.
    pub fn check(&self, raw: &str, cwd: Option<&Path>) -> Res<PathBuf> {
        let (lexical, canonical) = resolve(raw, cwd)?;
        if !self.is_trusted(&canonical) {
            return Err(Reject::new("path-untrusted"));
        }
        if self.is_denied(&lexical) || self.is_denied(&canonical) {
            return Err(Reject::new("path-denied"));
        }
        Ok(canonical)
    }

    pub fn check_dir(&self, raw: &str, cwd: Option<&Path>) -> Res<PathBuf> {
        let canonical = self.check(raw, cwd)?;
        if canonical.is_dir() {
            Ok(canonical)
        } else {
            Err(Reject::new("not-a-directory"))
        }
    }

    /// Expands an unquoted wildcard the way the shell would, so every file it
    /// can name is checked rather than the pattern: only `*` and `?` in the last
    /// component, never matching dotfiles, and a bounded number of matches.
    pub fn expand_glob(&self, text: &str, cwd: Option<&Path>) -> Res<Vec<String>> {
        let (dir, pattern) = match text.rsplit_once('/') {
            Some(("", pattern)) => ("/", pattern),
            Some((dir, pattern)) => (dir, pattern),
            None => ("", text),
        };
        if has_meta_other_than_glob(dir) || dir.contains(['*', '?']) {
            return Err(Reject::new("glob-in-directory"));
        }
        if pattern.starts_with('.') {
            return Err(Reject::new("glob-dotfile"));
        }
        let listing = self.check_dir(if dir.is_empty() { "." } else { dir }, cwd)?;
        let m = matcher(pattern).map_err(|_| Reject::new("glob-pattern"))?;
        let entries = std::fs::read_dir(&listing).map_err(|_| Reject::new("glob-unreadable"))?;
        let mut found = Vec::new();
        for (scanned, entry) in entries.flatten().enumerate() {
            if scanned >= GLOB_SCAN_CAP {
                return Err(Reject::new("glob-too-big"));
            }
            let name = entry.file_name().to_string_lossy().into_owned();
            if name.starts_with('.') || !m.is_match(&name) {
                continue;
            }
            // A match named like an option would be read as one by the command
            if name.starts_with('-') {
                return Err(Reject::new("glob-dash-name"));
            }
            if found.len() >= GLOB_MATCH_CAP {
                return Err(Reject::new("glob-too-many"));
            }
            found.push(match dir {
                "" => name,
                "/" => format!("/{name}"),
                _ => format!("{dir}/{name}"),
            });
        }
        if found.is_empty() {
            // Without matches the shell hands the pattern over unchanged
            found.push(text.to_owned());
        }
        Ok(found)
    }

    /// The nearest ancestor-or-self of `dir` that holds a `.git`.
    pub fn repo_top(dir: &Path) -> Option<PathBuf> {
        dir.ancestors()
            .find(|a| a.join(".git").symlink_metadata().is_ok())
            .map(Path::to_path_buf)
    }
}

fn has_meta_other_than_glob(s: &str) -> bool {
    s.contains(['[', ']', '{', '}'])
}

fn add_root(set: &mut HashSet<PathBuf>, path: &Path) {
    if let Ok(real) = std::fs::canonicalize(path)
        && real.is_dir()
    {
        set.insert(real);
    }
}

/// `(as written, as resolved)`: the longest existing prefix is canonicalised,
/// so symlinks and `..` behave as in the kernel, and the part that does not
/// exist yet is appended verbatim. A `..` in that part cannot be judged.
pub fn resolve(raw: &str, cwd: Option<&Path>) -> Res<(PathBuf, PathBuf)> {
    if raw.is_empty() {
        return Err(Reject::new("empty-path"));
    }
    let lexical = if Path::new(raw).is_absolute() {
        PathBuf::from(raw)
    } else {
        cwd.ok_or_else(|| Reject::new("no-cwd"))?.join(raw)
    };
    let mut base = lexical.clone();
    let mut missing: Vec<OsString> = Vec::new();
    loop {
        match std::fs::canonicalize(&base) {
            Ok(mut real) => {
                real.extend(missing.iter().rev());
                return Ok((lexical, real));
            }
            Err(e) if e.kind() == ErrorKind::NotFound => {
                let Some(name) = base.file_name() else {
                    return Err(Reject::new("dotdot-in-missing"));
                };
                missing.push(name.to_owned());
                if !base.pop() {
                    return Err(Reject::new("no-root"));
                }
            }
            Err(_) => return Err(Reject::new("path-unreadable")),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::os::unix::fs::symlink;
    use tempfile::TempDir;

    struct World {
        _tmp: TempDir,
        home: PathBuf,
        trust: Trust,
    }

    impl World {
        fn path(&self, rel: &str) -> String {
            self.home.join(rel).to_string_lossy().into_owned()
        }
    }

    fn world() -> World {
        let tmp = TempDir::new().unwrap();
        let home = fs::canonicalize(tmp.path()).unwrap().join("home");
        for dir in [
            "kms",
            "kms-wt/src",
            "pr-1/sub",
            "other",
            ".ssh",
            "kms/.config",
        ] {
            fs::create_dir_all(home.join(dir)).unwrap();
        }
        for file in [
            "kms/a.rs",
            "kms/b.rs",
            "kms/.env",
            "kms/server.key",
            "kms/.hidden.rs",
            "kms-wt/src/lib.rs",
            "other/secret.txt",
            ".ssh/id_rsa",
        ] {
            fs::write(home.join(file), "x").unwrap();
        }
        symlink(home.join("other"), home.join("kms/escape")).unwrap();
        symlink(home.join("other/secret.txt"), home.join("kms/link-out")).unwrap();
        symlink(home.join("kms/.env"), home.join("kms/innocent")).unwrap();
        symlink(home.join("kms/a.rs"), home.join("kms/plain.key")).unwrap();
        symlink(home.join("kms"), home.join("kms-link")).unwrap();
        let trust = Trust::new(
            &home,
            &DEFAULT_ROOTS
                .iter()
                .map(|s| (*s).to_owned())
                .collect::<Vec<_>>(),
            &DEFAULT_DENY
                .iter()
                .map(|s| (*s).to_owned())
                .collect::<Vec<_>>(),
        )
        .unwrap();
        World {
            _tmp: tmp,
            home,
            trust,
        }
    }

    fn reason(r: Res<PathBuf>) -> String {
        r.unwrap_err().0
    }

    #[test]
    fn roots_are_found_by_wildcard_and_canonicalised() {
        let w = world();
        let roots: HashSet<_> = w.trust.roots().cloned().collect();
        assert!(roots.contains(&w.home.join("kms")));
        assert!(roots.contains(&w.home.join("kms-wt")));
        assert!(roots.contains(&w.home.join("pr-1")));
        assert!(!roots.contains(&w.home.join("other")));
        // a symlinked name is a root too, but under its real location
        assert_eq!(roots.len(), 3, "{roots:?}");
    }

    #[test]
    fn trusted_inside_roots_untrusted_outside() {
        let w = world();
        let cwd = w.home.join("kms");
        assert!(w.trust.check("a.rs", Some(&cwd)).is_ok());
        assert!(w.trust.check("./a.rs", Some(&cwd)).is_ok());
        assert!(w.trust.check(&w.path("kms-wt/src/lib.rs"), None).is_ok());
        assert!(w.trust.check(&w.path("pr-1/sub"), None).is_ok());
        assert_eq!(
            reason(w.trust.check(&w.path("other/secret.txt"), None)),
            "path-untrusted"
        );
        assert_eq!(
            reason(w.trust.check("/etc/hostname", None)),
            "path-untrusted"
        );
        assert_eq!(
            reason(w.trust.check("../other/secret.txt", Some(&cwd))),
            "path-untrusted"
        );
        assert_eq!(reason(w.trust.check("a.rs", None)), "no-cwd");
        assert_eq!(reason(w.trust.check("", Some(&cwd))), "empty-path");
    }

    #[test]
    fn a_missing_target_is_judged_by_its_existing_parent() {
        let w = world();
        let cwd = w.home.join("kms");
        assert!(w.trust.check("not-yet.rs", Some(&cwd)).is_ok());
        assert!(w.trust.check("new/dir/file", Some(&cwd)).is_ok());
        assert_eq!(
            reason(w.trust.check("../other/new", Some(&cwd))),
            "path-untrusted"
        );
        // `..` after a missing component cannot be resolved, so it is not vouched for
        assert_eq!(
            reason(w.trust.check("missing/../a.rs", Some(&cwd))),
            "dotdot-in-missing"
        );
        assert_eq!(
            reason(w.trust.check("a.rs/inside", Some(&cwd))),
            "path-unreadable"
        );
    }

    #[test]
    fn symlinks_are_followed_before_judging() {
        let w = world();
        let cwd = w.home.join("kms");
        assert_eq!(
            reason(w.trust.check("escape", Some(&cwd))),
            "path-untrusted"
        );
        assert_eq!(
            reason(w.trust.check("escape/secret.txt", Some(&cwd))),
            "path-untrusted"
        );
        assert_eq!(
            reason(w.trust.check("link-out", Some(&cwd))),
            "path-untrusted"
        );
        // a symlinked root name resolves to the real root
        assert!(w.trust.check(&w.path("kms-link/a.rs"), None).is_ok());
        // a link to a denied file is denied
        assert_eq!(reason(w.trust.check("innocent", Some(&cwd))), "path-denied");
        // a denied-looking name is denied even when it points at a harmless file
        assert_eq!(
            reason(w.trust.check("plain.key", Some(&cwd))),
            "path-denied"
        );
    }

    #[test]
    fn deny_list_applies_inside_trusted_roots() {
        let w = world();
        let cwd = w.home.join("kms");
        for denied in [".env", "server.key", "./.env", "../kms/.env"] {
            assert_eq!(
                reason(w.trust.check(denied, Some(&cwd))),
                "path-denied",
                "{denied}"
            );
        }
        assert_eq!(
            reason(w.trust.check(&w.path(".ssh/id_rsa"), None)),
            "path-untrusted"
        );
        // deny globs are matched on files that do not exist yet too
        assert_eq!(
            reason(w.trust.check("sub/.env.local", Some(&cwd))),
            "path-denied"
        );
        assert_eq!(reason(w.trust.check("cert.pem", Some(&cwd))), "path-denied");
        assert!(w.trust.check("environment.rs", Some(&cwd)).is_ok());
    }

    #[test]
    fn deny_list_covers_home_dirs_even_when_roots_are_broad() {
        let w = world();
        let defaults: Vec<String> = DEFAULT_DENY.iter().map(|s| (*s).to_owned()).collect();
        // `~/*` never matches dot-directories, so `.ssh` stays outside the roots
        let star = Trust::new(&w.home, &["~/*".to_owned()], &defaults).unwrap();
        assert_eq!(
            reason(star.check(&w.path(".ssh/id_rsa"), None)),
            "path-untrusted"
        );

        // the home directory itself as a root: only the deny list protects `.ssh`
        let broad = Trust::new(&w.home, &["~".to_owned()], &defaults).unwrap();
        assert_eq!(
            reason(broad.check(&w.path(".ssh/id_rsa"), None)),
            "path-denied"
        );
        assert_eq!(reason(broad.check(&w.path(".ssh"), None)), "path-denied");
        assert_eq!(
            reason(broad.check(&w.path("kms/.env"), None)),
            "path-denied"
        );
        assert!(broad.check(&w.path("other/secret.txt"), None).is_ok());

        // the home-anchored pattern alone, without the basename patterns
        let only = Trust::new(&w.home, &["~".to_owned()], &["~/.ssh/**".to_owned()]).unwrap();
        assert_eq!(
            reason(only.check(&w.path(".ssh/anything"), None)),
            "path-denied"
        );
        assert!(only.check(&w.path("kms/.env"), None).is_ok());
    }

    #[test]
    fn wildcards_expand_to_checked_files() {
        let w = world();
        let cwd = w.home.join("kms");
        let mut got = w.trust.expand_glob("*.rs", Some(&cwd)).unwrap();
        got.sort();
        assert_eq!(got, ["a.rs", "b.rs"], "dotfiles never match");
        let abs = w.path("kms-wt/src/*.rs");
        assert_eq!(
            w.trust.expand_glob(&abs, None).unwrap(),
            [w.path("kms-wt/src/lib.rs")]
        );
        // no match: the shell passes the pattern through
        assert_eq!(w.trust.expand_glob("*.zzz", Some(&cwd)).unwrap(), ["*.zzz"]);
        assert_eq!(
            reason_of(w.trust.expand_glob("*/a.rs", Some(&cwd))),
            "glob-in-directory"
        );
        assert_eq!(
            reason_of(w.trust.expand_glob(".*", Some(&cwd))),
            "glob-dotfile"
        );
        assert_eq!(
            reason_of(w.trust.expand_glob("*", Some(&w.home.join("other")))),
            "path-untrusted"
        );
        assert_eq!(reason_of(w.trust.expand_glob("*", None)), "no-cwd");
    }

    fn reason_of(r: Res<Vec<String>>) -> String {
        r.unwrap_err().0
    }

    #[test]
    fn wildcards_matching_symlinks_are_judged_per_match() {
        let w = world();
        let cwd = w.home.join("kms");
        // `*` matches `escape` and `link-out`, which lead out of the root
        let all = w.trust.expand_glob("*", Some(&cwd)).unwrap();
        assert!(all.contains(&"escape".to_owned()));
        let verdicts: Vec<_> = all
            .iter()
            .map(|m| w.trust.check(m, Some(&cwd)).is_ok())
            .collect();
        assert!(
            verdicts.iter().any(|ok| !ok),
            "an escaping match must fail the check"
        );
    }

    #[test]
    fn dash_named_matches_are_refused() {
        let w = world();
        let cwd = w.home.join("kms");
        fs::write(cwd.join("-rf"), "x").unwrap();
        assert_eq!(
            reason_of(w.trust.expand_glob("*", Some(&cwd))),
            "glob-dash-name"
        );
    }

    #[test]
    fn config_errors_are_reported() {
        let w = world();
        let deny: Vec<String> = Vec::new();
        assert!(Trust::new(&w.home, &["~/a*/b".to_owned()], &deny).is_err());
        assert!(Trust::new(&w.home, &["relative".to_owned()], &deny).is_err());
        assert!(Trust::new(&w.home, &[], &["[".to_owned()]).is_err());
        let none = Trust::new(&w.home, &[], &deny).unwrap();
        assert!(none.check(&w.path("kms/a.rs"), None).is_err());
    }

    #[test]
    fn repo_top_finds_the_work_tree() {
        let w = world();
        fs::create_dir_all(w.home.join("kms/.git")).unwrap();
        assert_eq!(
            Trust::repo_top(&w.home.join("kms/.config")),
            Some(w.home.join("kms"))
        );
        assert_eq!(Trust::repo_top(&w.home.join("pr-1")), None);
    }
}
