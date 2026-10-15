//! `events.jsonl` -> PostgreSQL.
//!
//! One transaction per batch of lines; the resume offset is written in the
//! same transaction as the rows it covers, so a crash can neither skip nor
//! half-apply a batch (and every statement is an idempotent upsert, so a
//! replay is harmless anyway).

use std::io;
use std::path::{Path, PathBuf};
use std::sync::Arc;

use anyhow::{Context, Result};
use chrono::{DateTime, Utc};
use sqlx::PgPool;
use tokio::sync::Semaphore;
use tokio::task::JoinSet;
use tracing::{debug, warn};

use crate::config::{Config, events_path, workspace_path};
use crate::events::{EventRow, SessionFacts, ToolFragment, map_line};
use crate::reader::{LineReader, head_sha};
use crate::redact::{Counts, Redactor};
use crate::store;
use crate::workspace;
use crate::writer::{self, EventsState, TitleAuthority};

/// Lines per transaction, and a cap on the raw bytes they may hold.
pub const BATCH_LINES: usize = 1000;
pub const BATCH_BYTES: usize = 8 << 20;

#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub struct Report {
    pub sessions_read: u64,
    pub sessions_skipped: u64,
    /// Sessions re-read from byte 0 (first sight, `--force`, replaced file).
    pub sessions_restarted: u64,
    pub lines: u64,
    /// Lines that were not valid events (counted, never stored).
    pub rejected: u64,
    /// Rows actually inserted or changed (a no-op re-run reports 0).
    pub events_changed: u64,
    pub tool_calls_changed: u64,
    pub redactions: u64,
}

impl Report {
    pub fn merge(&mut self, other: &Report) {
        self.sessions_read += other.sessions_read;
        self.sessions_skipped += other.sessions_skipped;
        self.sessions_restarted += other.sessions_restarted;
        self.lines += other.lines;
        self.rejected += other.rejected;
        self.events_changed += other.events_changed;
        self.tool_calls_changed += other.tool_calls_changed;
        self.redactions += other.redactions;
    }
}

#[derive(Debug, Default)]
pub struct RunReport {
    pub totals: Report,
    pub store: store::Report,
    /// `(source, error chain)`; everything else is still done.
    pub failed: Vec<(String, String)>,
}

/// What to do with one `events.jsonl`.
#[derive(Debug, PartialEq, Eq)]
pub enum Plan {
    /// Nothing new since the last pass.
    Skip,
    /// Continue after the last consumed line.
    Resume(u64),
    /// Read the file from the start.
    Restart,
}

/// Decides how to read a file of `size` bytes given what was stored last time.
/// `file_size` equal to the current size means "unchanged", which also keeps a
/// NUL-padded tail (never consumed, so `byte_offset < size` forever) from being
/// re-read on every pass.
pub fn plan(path: &Path, size: u64, state: Option<&EventsState>, force: bool) -> io::Result<Plan> {
    let Some(state) = state else {
        return Ok(Plan::Restart);
    };
    if force {
        return Ok(Plan::Restart);
    }
    let offset = u64::try_from(state.byte_offset).unwrap_or(0);
    if offset <= size && state.file_size == i64::try_from(size).ok() {
        return Ok(Plan::Skip);
    }
    if size < offset {
        return Ok(Plan::Restart);
    }
    match (state.head_sha.as_deref(), head_sha(path, offset)?) {
        (Some(stored), Some(current)) if stored == current => Ok(Plan::Resume(offset)),
        // Different (or too short) head: not the file that was read.
        _ => Ok(Plan::Restart),
    }
}

struct Batch {
    events: Vec<EventRow>,
    tools: Vec<ToolFragment>,
    facts: SessionFacts,
    counts: Counts,
    lines: u64,
    rejected: u64,
    end_offset: u64,
    done: bool,
    head_sha: Option<String>,
}

fn read_batch(reader: &mut LineReader, redactor: &Redactor, path: &Path) -> Result<Batch> {
    let chunk = reader.next_chunk(BATCH_LINES, BATCH_BYTES)?;
    let mut batch = Batch {
        events: Vec::with_capacity(chunk.lines.len()),
        tools: Vec::new(),
        facts: SessionFacts::default(),
        counts: Counts::default(),
        lines: chunk.lines.len() as u64,
        rejected: 0,
        end_offset: chunk.end_offset,
        done: chunk.done,
        head_sha: None,
    };
    for line in &chunk.lines {
        match map_line(redactor, &line.bytes, line.offset, &mut batch.counts) {
            Ok(mapped) => {
                batch.facts.note_ts(Some(mapped.event.ts));
                if let Some(facts) = mapped.facts {
                    batch.facts.merge(facts);
                }
                batch.tools.extend(mapped.tool);
                batch.events.push(mapped.event);
            }
            Err(error) => {
                batch.rejected += 1;
                warn!(offset = line.offset, %error, "skipping a line that is not a valid event");
            }
        }
    }
    batch.head_sha = head_sha(path, chunk.end_offset)?;
    Ok(batch)
}

#[derive(Debug, Clone)]
pub struct SessionDir {
    pub id: String,
    pub dir: PathBuf,
    /// `None` when the directory has no `events.jsonl`.
    pub events_size: Option<u64>,
}

#[derive(Clone)]
pub struct Ingester {
    pool: PgPool,
    redactor: Arc<Redactor>,
    config: Config,
}

impl Ingester {
    pub fn new(pool: PgPool, config: Config) -> Self {
        Self {
            pool,
            redactor: Arc::new(Redactor::new()),
            config,
        }
    }

    pub fn pool(&self) -> &PgPool {
        &self.pool
    }

    pub fn redactor(&self) -> &Arc<Redactor> {
        &self.redactor
    }

    pub fn config(&self) -> &Config {
        &self.config
    }

    /// Session directories, biggest `events.jsonl` first (so the long jobs
    /// start early when several run at once).
    pub fn list_sessions(&self) -> Result<Vec<SessionDir>> {
        let root = self.config.session_state_dir();
        let mut out = Vec::new();
        for entry in
            std::fs::read_dir(&root).with_context(|| format!("listing {}", root.display()))?
        {
            let entry = entry?;
            let dir = entry.path();
            let Some(id) = entry.file_name().to_str().map(str::to_owned) else {
                continue;
            };
            if id.starts_with('.') || !dir.is_dir() {
                continue;
            }
            let events_size = std::fs::metadata(events_path(&dir)).ok().map(|m| m.len());
            out.push(SessionDir {
                id,
                dir,
                events_size,
            });
        }
        out.sort_by(|a, b| {
            b.events_size
                .cmp(&a.events_size)
                .then_with(|| a.id.cmp(&b.id))
        });
        Ok(out)
    }

    /// Reads whatever is new in one session's `events.jsonl`.
    pub async fn ingest_session(&self, session_id: &str, force: bool) -> Result<Report> {
        let path = events_path(&self.config.session_state_dir().join(session_id));
        let meta = match std::fs::metadata(&path) {
            Ok(meta) => meta,
            Err(e) if e.kind() == io::ErrorKind::NotFound => return Ok(Report::default()),
            Err(e) => return Err(e).with_context(|| format!("stat {}", path.display())),
        };
        let size = meta.len();
        let mtime = meta.modified().ok().map(DateTime::<Utc>::from);

        let stored = {
            let mut conn = self.pool.acquire().await?;
            writer::load_events_state(&mut conn, session_id).await?
        };
        let (start, restart) = match plan(&path, size, stored.as_ref(), force)? {
            Plan::Skip => {
                return Ok(Report {
                    sessions_skipped: 1,
                    ..Report::default()
                });
            }
            Plan::Resume(offset) => (offset, false),
            Plan::Restart => (0, true),
        };

        let mut report = Report {
            sessions_read: 1,
            sessions_restarted: u64::from(restart),
            ..Report::default()
        };
        let mut reader = LineReader::open(&path, start)
            .with_context(|| format!("opening {}", path.display()))?;
        // A pass over the whole file recounts redactions from scratch.
        let mut replace_counts = restart;
        let mut last_state = stored;
        loop {
            let redactor = Arc::clone(&self.redactor);
            let file = path.clone();
            let (returned, batch) = tokio::task::spawn_blocking(move || {
                let batch = read_batch(&mut reader, &redactor, &file)?;
                Ok::<_, anyhow::Error>((reader, batch))
            })
            .await??;
            reader = returned;

            let end = i64::try_from(batch.end_offset).context("offset overflow")?;
            let state = EventsState {
                byte_offset: end,
                file_size: batch
                    .done
                    .then(|| i64::try_from(size).unwrap_or(i64::MAX).max(end)),
                head_sha: batch.head_sha.clone(),
            };
            let changed = batch.lines > 0 || replace_counts || last_state.as_ref() != Some(&state);
            if changed {
                let mut tx = self.pool.begin().await?;
                writer::ensure_sessions(&mut tx, &[session_id.to_owned()]).await?;
                report.events_changed +=
                    writer::upsert_events(&mut tx, session_id, &batch.events).await?;
                report.tool_calls_changed +=
                    writer::upsert_tool_calls(&mut tx, session_id, &batch.tools).await?;
                writer::merge_session_facts(&mut tx, session_id, &batch.facts).await?;
                writer::add_redactions(
                    &mut tx,
                    session_id,
                    "events",
                    &batch.counts,
                    replace_counts,
                )
                .await?;
                writer::save_events_state(&mut tx, session_id, &state, mtime).await?;
                tx.commit().await?;
                replace_counts = false;
                last_state = Some(state);
            }
            report.lines += batch.lines;
            report.rejected += batch.rejected;
            report.redactions += batch.counts.total();
            if batch.done {
                break;
            }
        }
        debug!(
            session = session_id,
            lines = report.lines,
            changed = report.events_changed,
            "events read"
        );
        Ok(report)
    }

    /// Refreshes the session row from `workspace.yaml`. `false` if the file
    /// does not exist.
    pub async fn sync_workspace(&self, session_id: &str) -> Result<bool> {
        let path = workspace_path(&self.config.session_state_dir().join(session_id));
        if !path.exists() {
            return Ok(false);
        }
        let redactor = Arc::clone(&self.redactor);
        let (meta, counts) = tokio::task::spawn_blocking(move || {
            let mut counts = Counts::default();
            workspace::read(&redactor, &path, &mut counts).map(|meta| (meta, counts))
        })
        .await??;
        let mut tx = self.pool.begin().await?;
        writer::upsert_session_meta(&mut tx, session_id, &meta, TitleAuthority::Overwrite).await?;
        writer::add_redactions(&mut tx, session_id, "workspace", &counts, true).await?;
        tx.commit().await?;
        Ok(true)
    }

    /// Mirrors `session-store.db` (usage, turns, checkpoints, files, refs).
    pub async fn sync_store(&self, force: bool) -> Result<store::Report> {
        store::sync(&self.pool, &self.redactor, &self.config.store_db(), force).await
    }

    /// [`Self::sync_workspace`] for each session. One that fails is returned
    /// as `(session id, error chain)` and does not stop the others.
    pub async fn sync_workspaces(&self, ids: &[String]) -> Vec<(String, String)> {
        let mut failed = Vec::new();
        for id in ids {
            if let Err(e) = self.sync_workspace(id).await {
                warn!(session = %id, error = %format!("{e:#}"), "workspace.yaml not synced");
                failed.push((id.clone(), format!("{e:#}")));
            }
        }
        failed
    }

    /// [`Self::ingest_session`] for each session, `jobs` at a time. One that
    /// fails is returned as `(session id, error chain)` and does not stop the
    /// others; only a panicking task is an error.
    pub async fn ingest_sessions(
        &self,
        ids: Vec<String>,
        force: bool,
        jobs: usize,
    ) -> Result<(Report, Vec<(String, String)>)> {
        let permits = Arc::new(Semaphore::new(jobs.max(1)));
        let mut tasks = JoinSet::new();
        for id in ids {
            let permit = Arc::clone(&permits).acquire_owned().await?;
            let this = self.clone();
            tasks.spawn(async move {
                let _permit = permit;
                let result = this.ingest_session(&id, force).await;
                (id, result)
            });
        }
        let mut totals = Report::default();
        let mut failed = Vec::new();
        while let Some(joined) = tasks.join_next().await {
            let (id, result) = joined.context("an ingest task panicked")?;
            match result {
                Ok(report) => {
                    if report.sessions_read > 0 {
                        debug!(
                            session = %id,
                            lines = report.lines,
                            events_changed = report.events_changed,
                            "session ingested"
                        );
                    }
                    totals.merge(&report);
                }
                Err(e) => {
                    warn!(session = %id, error = %format!("{e:#}"), "session failed");
                    failed.push((id, format!("{e:#}")));
                }
            }
        }
        Ok((totals, failed))
    }

    /// Workspace metadata, the SQLite store, then every session's events,
    /// `jobs` at a time. A source that fails is reported and skipped; the
    /// others complete.
    pub async fn run_all(&self, force: bool, jobs: usize) -> Result<RunReport> {
        let sessions = self.list_sessions()?;
        let mut run = RunReport::default();

        let all: Vec<String> = sessions.iter().map(|s| s.id.clone()).collect();
        run.failed.extend(self.sync_workspaces(&all).await);

        match self.sync_store(force).await {
            Ok(report) => run.store = report,
            Err(e) => {
                warn!(error = %format!("{e:#}"), "session store not synced");
                run.failed
                    .push(("session-store.db".to_owned(), format!("{e:#}")));
            }
        }

        let with_events = sessions
            .into_iter()
            .filter(|s| s.events_size.is_some())
            .map(|s| s.id)
            .collect();
        let (totals, failed) = self.ingest_sessions(with_events, force, jobs).await?;
        run.totals = totals;
        run.failed.extend(failed);
        Ok(run)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Write;

    fn state_after_full_read(path: &Path) -> EventsState {
        let len = std::fs::metadata(path).unwrap().len();
        EventsState {
            byte_offset: len as i64,
            file_size: Some(len as i64),
            head_sha: head_sha(path, len).unwrap(),
        }
    }

    fn file(content: &[u8]) -> (tempfile::TempDir, PathBuf) {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("events.jsonl");
        std::fs::write(&path, content).unwrap();
        (dir, path)
    }

    #[test]
    fn unknown_session_is_read_from_the_start() {
        let (_d, p) = file(b"{\"a\":1}\n");
        assert_eq!(plan(&p, 8, None, false).unwrap(), Plan::Restart);
    }

    #[test]
    fn unchanged_file_is_skipped_and_growth_resumes() {
        let (_d, p) = file(b"{\"a\":1}\n{\"b\":2}\n");
        let state = state_after_full_read(&p);
        assert_eq!(plan(&p, 16, Some(&state), false).unwrap(), Plan::Skip);
        let mut f = std::fs::OpenOptions::new().append(true).open(&p).unwrap();
        f.write_all(b"{\"c\":3}\n").unwrap();
        assert_eq!(plan(&p, 24, Some(&state), false).unwrap(), Plan::Resume(16));
    }

    #[test]
    fn nul_padded_tail_is_skipped_while_its_size_is_unchanged() {
        let mut content = b"{\"a\":1}\n".to_vec();
        content.extend([0u8; 40]);
        let (_d, p) = file(&content);
        let state = EventsState {
            byte_offset: 8,
            file_size: Some(48),
            head_sha: head_sha(&p, 8).unwrap(),
        };
        assert_eq!(plan(&p, 48, Some(&state), false).unwrap(), Plan::Skip);
    }

    #[test]
    fn replaced_or_shrunk_file_restarts() {
        let (_d, p) = file(b"{\"a\":1}\n{\"b\":2}\n");
        let state = state_after_full_read(&p);
        std::fs::write(&p, b"{\"z\":9}\n{\"y\":8}\n{\"x\":7}\n").unwrap();
        assert_eq!(plan(&p, 24, Some(&state), false).unwrap(), Plan::Restart);
        std::fs::write(&p, b"{}\n").unwrap();
        assert_eq!(plan(&p, 3, Some(&state), false).unwrap(), Plan::Restart);
    }

    #[test]
    fn force_always_restarts() {
        let (_d, p) = file(b"{\"a\":1}\n");
        let state = state_after_full_read(&p);
        assert_eq!(plan(&p, 8, Some(&state), true).unwrap(), Plan::Restart);
    }

    #[test]
    fn interrupted_pass_without_a_recorded_size_resumes() {
        let (_d, p) = file(b"{\"a\":1}\n{\"b\":2}\n");
        let mut state = state_after_full_read(&p);
        state.file_size = None;
        state.byte_offset = 8;
        state.head_sha = head_sha(&p, 8).unwrap();
        assert_eq!(plan(&p, 16, Some(&state), false).unwrap(), Plan::Resume(8));
    }
}
