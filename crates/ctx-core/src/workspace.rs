//! `workspace.yaml`: the CLI's own per-session metadata file.

use std::path::Path;

use anyhow::{Context, Result};
use serde::Deserialize;

use crate::events::parse_ts;
use crate::redact::{Counts, Redactor};
use crate::writer::SessionMeta;

/// Titles are short; a runaway value must not bloat the table.
const MAX_TEXT_BYTES: usize = 4096;

#[derive(Debug, Default, Deserialize)]
struct Raw {
    cwd: Option<String>,
    git_root: Option<String>,
    repository: Option<String>,
    branch: Option<String>,
    host_type: Option<String>,
    name: Option<String>,
    summary: Option<String>,
    created_at: Option<String>,
    updated_at: Option<String>,
}

/// Parses the YAML text; every string goes through the redactor.
pub fn parse(redactor: &Redactor, yaml: &str, counts: &mut Counts) -> Result<SessionMeta> {
    let raw: Raw = serde_yaml_ng::from_str(yaml).context("invalid workspace.yaml")?;
    let mut text = |value: Option<String>| {
        value
            .filter(|v| !v.trim().is_empty())
            .map(|v| redactor.field_capped(&v, MAX_TEXT_BYTES, counts))
    };
    Ok(SessionMeta {
        cwd: text(raw.cwd),
        git_root: text(raw.git_root),
        repository: text(raw.repository),
        branch: text(raw.branch),
        host_type: text(raw.host_type),
        name: text(raw.name),
        summary: text(raw.summary),
        started_at: raw.created_at.as_deref().and_then(parse_ts),
        ended_at: raw.updated_at.as_deref().and_then(parse_ts),
    })
}

pub fn read(redactor: &Redactor, path: &Path, counts: &mut Counts) -> Result<SessionMeta> {
    let yaml =
        std::fs::read_to_string(path).with_context(|| format!("reading {}", path.display()))?;
    parse(redactor, &yaml, counts)
}

#[cfg(test)]
mod tests {
    use super::*;

    const SAMPLE: &str = "id: 0a1b\ncwd: /home/u/proj\ngit_root: /home/u/proj\nbranch: main\n\
        repository: owner/proj\nhost_type: github\nname: Fix the thing\n\
        summary: |-\n  First line\n  second line\ncreated_at: 2026-10-01T08:00:00.123Z\n\
        updated_at: 2026-10-01T09:30:00Z\nsummary_count: 2\nfork_count: 0\nclient_name: cli\n";

    #[test]
    fn maps_known_keys_and_ignores_the_rest() {
        let mut counts = Counts::default();
        let meta = parse(&Redactor::new(), SAMPLE, &mut counts).unwrap();
        assert_eq!(meta.cwd.as_deref(), Some("/home/u/proj"));
        assert_eq!(meta.repository.as_deref(), Some("owner/proj"));
        assert_eq!(meta.name.as_deref(), Some("Fix the thing"));
        assert_eq!(meta.summary.as_deref(), Some("First line\nsecond line"));
        assert_eq!(
            meta.started_at.unwrap().to_rfc3339(),
            "2026-10-01T08:00:00.123+00:00"
        );
        assert_eq!(
            meta.ended_at.unwrap().to_rfc3339(),
            "2026-10-01T09:30:00+00:00"
        );
        assert!(counts.is_empty());
    }

    #[test]
    fn missing_and_blank_values_stay_unset() {
        let mut counts = Counts::default();
        let meta = parse(&Redactor::new(), "name: \"  \"\nbranch:\n", &mut counts).unwrap();
        assert_eq!(meta, SessionMeta::default());
    }

    #[test]
    fn secrets_in_titles_are_redacted() {
        let secret = format!("gh{}_{}", "p", "A1b2C3d4E5".repeat(4).get(..36).unwrap());
        let yaml = format!("summary: deploy with {secret} now\n");
        let mut counts = Counts::default();
        let meta = parse(&Redactor::new(), &yaml, &mut counts).unwrap();
        let summary = meta.summary.unwrap();
        assert!(!summary.contains(&secret));
        assert_eq!(counts.get("github"), 1);
    }

    #[test]
    fn garbage_is_an_error_not_a_panic() {
        let mut counts = Counts::default();
        assert!(parse(&Redactor::new(), "a: [unclosed", &mut counts).is_err());
    }
}
