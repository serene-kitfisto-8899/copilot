//! A throwaway home directory with trusted and untrusted places, symlinks that
//! lead out, secrets by name, and git work trees.

#![allow(dead_code)]

use ctx_hook::policy::{Verdict, evaluate};
use ctx_hook::trust::{DEFAULT_DENY, DEFAULT_ROOTS, Trust};
use ctx_hook::vars::Vars;
use std::fs;
use std::os::unix::fs::symlink;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

pub struct World {
    _tmp: TempDir,
    pub home: PathBuf,
    pub trust: Trust,
}

fn strings(list: &[&str]) -> Vec<String> {
    list.iter().map(|s| (*s).to_owned()).collect()
}

impl World {
    pub fn new() -> Self {
        let tmp = TempDir::new().unwrap();
        let home = fs::canonicalize(tmp.path()).unwrap().join("home");
        for dir in [
            "kms/.git",
            "kms/src/sub",
            "kms/dash",
            "kms/data",
            "kms-two/.git",
            "pr-7/.git",
            "other",
            "work/.git",
            ".ssh",
            ".aws",
        ] {
            fs::create_dir_all(home.join(dir)).unwrap();
        }
        for (file, body) in [
            ("kms/README.md", "# readme\nTODO one\nTODO two\n"),
            ("kms/notes.txt", "b 2\na 1\na 1\n"),
            ("kms/data.json", r#"{"a":{"b":1},"items":[{"name":"x"}]}"#),
            ("kms/src/main.rs", "fn main() {}\n"),
            ("kms/src/lib.rs", "pub fn f() {}\n"),
            ("kms/src/sub/deep.txt", "deep\n"),
            ("kms/dash/-rf", "x"),
            ("kms/dash/a", "x"),
            ("kms/.env", "SECRET=1\n"),
            ("kms/.hidden", "h\n"),
            ("kms/server.pem", "pem\n"),
            ("kms/server.key", "key\n"),
            ("kms/id_rsa", "rsa\n"),
            ("kms-two/a.txt", "a\n"),
            ("pr-7/b.txt", "b\n"),
            ("other/secret.txt", "secret\n"),
            ("work/x.txt", "x\n"),
            (".ssh/id_rsa", "rsa\n"),
            (".ssh/config", "Host *\n"),
            (".aws/credentials", "[default]\n"),
        ] {
            fs::write(home.join(file), body).unwrap();
        }
        for (link, target) in [
            ("kms/escape", "../other"),
            ("kms/link-out", "../other/secret.txt"),
            ("kms/innocent", ".env"),
            ("kms/plain.key", "README.md"),
            ("kms/inside", "src"),
            ("kms/to-two", "../kms-two"),
        ] {
            symlink(target, home.join(link)).unwrap();
        }
        let trust = Trust::new(&home, &strings(DEFAULT_ROOTS), &strings(DEFAULT_DENY)).unwrap();
        Self {
            _tmp: tmp,
            home,
            trust,
        }
    }

    pub fn path(&self, rel: &str) -> PathBuf {
        self.home.join(rel)
    }

    /// `cwd` is relative to the home directory.
    pub fn eval(&self, src: &str, cwd: &str) -> Verdict {
        self.eval_with(src, cwd, &Vars::fixed(&[]))
    }

    pub fn eval_with(&self, src: &str, cwd: &str, vars: &Vars) -> Verdict {
        evaluate(src, Some(&self.path(cwd)), &self.home, &self.trust, vars)
    }

    pub fn eval_no_cwd(&self, src: &str) -> Verdict {
        evaluate(src, None, &self.home, &self.trust, &Vars::fixed(&[]))
    }

    pub fn eval_at(&self, src: &str, cwd: &Path) -> Verdict {
        evaluate(src, Some(cwd), &self.home, &self.trust, &Vars::fixed(&[]))
    }
}
