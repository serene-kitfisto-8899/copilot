//! `tail`: keeps the database current while the Copilot CLI is writing.
//!
//! inotify says *that* a file was touched, never *what* is new in it, and it
//! is wrong in both directions:
//!
//! * It can be silent. The kernel queue overflows under a burst
//!   (`IN_Q_OVERFLOW`), and a directory that appears between listing the
//!   state directory and watching it raises no event for the files that were
//!   already inside it.
//! * It can be noisy. Every read of a watched file raises open and close
//!   events, so a tail that reacted to those would chase its own reads
//!   forever (`ingest_session` opens `events.jsonl`, which raises an event,
//!   which schedules `ingest_session`, ...). [`Classifier`] therefore ignores
//!   every access and metadata event and keeps only the ones that change
//!   content or names.
//!
//! The notifications are consequently only hints about *when* to look. What
//! to copy is still decided by the same code as `ctx-ingest once`:
//! `ingest_session` resumes from the stored byte offset and answers an
//! unchanged file with a `stat` and a no-op, so a spurious or duplicated hint
//! costs next to nothing and a missed one is repaired by the next pass. Two
//! rules follow from that:
//!
//! 1. Watches are always in place *before* a full pass reads anything, so a
//!    change either shows up in that pass or raises an event afterwards.
//! 2. A periodic full pass ([`TailOptions::rescan`], the very `run_all` that
//!    `once` runs) backs the notifications up. Its cost on an unchanged tree
//!    is a few hundred milliseconds.
//!
//! # Scheduling
//!
//! A busy session appends several events a second, and reading after every
//! write would mean one tiny transaction per line. Hints are therefore
//! collected and acted on when the files have been quiet for
//! [`TailOptions::debounce`], but never later than
//! [`TailOptions::max_delay`] after the first hint of the batch, so a session
//! that never pauses still lands in the database. The session store changes
//! with every turn and is the most expensive source to mirror, so it also has
//! a floor of [`TailOptions::store_interval`] between two syncs. Everything
//! runs on one task: a pass never overlaps another, and two writers can never
//! work on the same session.
//!
//! The process holds the ingest lock for its whole life (taken by the caller),
//! so a `ctx-ingest once` started by hand while the service runs is refused
//! instead of racing it. PostgreSQL drops the lock with its connection, so the
//! caller also watches that connection and stops the tail when it dies (a
//! server restart, say); the service manager then starts a fresh tail that
//! takes the lock again. Run it at a low priority (`Nice=`/`IOSchedulingClass=`
//! in the unit file, `nice -n 10` by hand); the code cannot lower its own
//! priority because the workspace forbids `unsafe`.

use std::collections::{BTreeSet, HashSet};
use std::future::Future;
use std::mem;
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

use anyhow::{Context, Result, bail};
use notify::event::ModifyKind;
use notify::{Event, EventKind, RecommendedWatcher, RecursiveMode, Watcher};
use tokio::sync::mpsc::{self, UnboundedReceiver};
use tokio::time::MissedTickBehavior;
use tracing::{debug, info, warn};

use crate::config::{Config, EVENTS_FILE, STORE_FILE, WORKSPACE_FILE};
use crate::ingest::{Ingester, Report, RunReport};

/// Stands in for "never" when nothing is scheduled.
const IDLE: Duration = Duration::from_secs(24 * 3600);

#[derive(Debug, Clone)]
pub struct TailOptions {
    /// Sessions read concurrently.
    pub jobs: usize,
    /// How long the files must stay quiet before they are read.
    pub debounce: Duration,
    /// The longest a change may wait when the files never go quiet.
    pub max_delay: Duration,
    /// The shortest time between two syncs of the SQLite store.
    pub store_interval: Duration,
    /// Period of the full pass that backs up the notifications.
    pub rescan: Duration,
}

impl Default for TailOptions {
    fn default() -> Self {
        Self {
            jobs: 4,
            debounce: Duration::from_secs(2),
            max_delay: Duration::from_secs(10),
            store_interval: Duration::from_secs(15),
            rescan: Duration::from_secs(60),
        }
    }
}

impl TailOptions {
    /// `tokio::time::interval` panics on a zero period and a zero-sized
    /// semaphore would never admit a session.
    fn normalized(mut self) -> Self {
        self.jobs = self.jobs.max(1);
        self.rescan = self.rescan.max(Duration::from_secs(1));
        self
    }
}

/// What a tail did, for the log line at shutdown and for the tests.
#[derive(Debug, Default, Clone)]
pub struct Summary {
    /// Passes over just the files that raised a hint.
    pub flushes: u64,
    /// Full passes: the catch-up at startup, the periodic rescan, and the
    /// ones forced by lost notifications.
    pub full_passes: u64,
    pub totals: Report,
    /// Rows the store syncs inserted or changed.
    pub store_rows: u64,
    /// Sources that failed (and are retried by the next full pass).
    pub failures: u64,
}

/// What a file-system event means for the database.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Change {
    /// `events.jsonl` of this session may have grown.
    Events(String),
    /// `workspace.yaml` of this session was written.
    Workspace(String),
    /// An entry of the state directory was created, renamed or removed. What
    /// happened is read from the file system, not from the event, so the
    /// kind of event does not matter.
    Dir(String),
    /// The SQLite store (or its write-ahead log) was written.
    Store,
    /// The kernel dropped events: nothing seen so far can be trusted.
    Lost,
}

/// Turns raw notify events into [`Change`]s. Pure, so it is tested without a
/// file system.
#[derive(Debug, Clone)]
pub struct Classifier {
    sessions_root: PathBuf,
    copilot_dir: PathBuf,
}

impl Classifier {
    pub fn new(config: &Config) -> Self {
        Self {
            sessions_root: config.session_state_dir(),
            copilot_dir: config.copilot_dir.clone(),
        }
    }

    pub fn classify(&self, event: &Event) -> Vec<Change> {
        if event.need_rescan() {
            return vec![Change::Lost];
        }
        match event.kind {
            // Opening and closing are what our own reads do; the write that
            // preceded a close already raised its own event.
            EventKind::Access(_) => return Vec::new(),
            // chmod, touch, ...: the content did not change.
            EventKind::Modify(ModifyKind::Metadata(_)) => return Vec::new(),
            _ => {}
        }
        let mut out: Vec<Change> = Vec::new();
        for path in &event.paths {
            // A rename names two paths; both may lead to the same change.
            if let Some(change) = self.place(path)
                && !out.contains(&change)
            {
                out.push(change);
            }
        }
        out
    }

    fn place(&self, path: &Path) -> Option<Change> {
        if let Ok(rest) = path.strip_prefix(&self.sessions_root) {
            let mut parts = rest.components();
            let id = parts.next()?.as_os_str().to_str()?;
            if id.starts_with('.') {
                return None;
            }
            return match (parts.next(), parts.next()) {
                (None, _) => Some(Change::Dir(id.to_owned())),
                (Some(name), None) => match name.as_os_str().to_str()? {
                    EVENTS_FILE => Some(Change::Events(id.to_owned())),
                    WORKSPACE_FILE => Some(Change::Workspace(id.to_owned())),
                    // `files/`, `checkpoints/`, temporary files, ...
                    _ => None,
                },
                _ => None,
            };
        }
        if path.parent() == Some(self.copilot_dir.as_path()) {
            let name = path.file_name()?.to_str()?;
            // `-shm` is shared memory that readers write to as well; it
            // carries no data of its own.
            if name == STORE_FILE || name.strip_prefix(STORE_FILE) == Some("-wal") {
                return Some(Change::Store);
            }
        }
        None
    }
}

/// When changes of one kind are due: after `debounce` of quiet, but never
/// more than `max_delay` after the first one.
#[derive(Debug, Default, Clone, Copy)]
struct Lane {
    first: Option<Instant>,
    last: Option<Instant>,
}

impl Lane {
    fn touch(&mut self, now: Instant) {
        self.first.get_or_insert(now);
        self.last = Some(now);
    }

    fn clear(&mut self) {
        *self = Self::default();
    }

    fn due(&self, debounce: Duration, max_delay: Duration) -> Option<Instant> {
        Some((self.last? + debounce).min(self.first? + max_delay))
    }
}

/// What to do now.
#[derive(Debug, Default, PartialEq, Eq)]
struct Work {
    events: Vec<String>,
    workspaces: Vec<String>,
    store: bool,
    /// Notifications were lost: do a full pass instead of the targeted one.
    full: bool,
}

impl Work {
    fn is_empty(&self) -> bool {
        self.events.is_empty() && self.workspaces.is_empty() && !self.store && !self.full
    }
}

/// Hints collected since the last pass.
#[derive(Debug, Default)]
struct Pending {
    events: BTreeSet<String>,
    workspaces: BTreeSet<String>,
    lost: bool,
    /// Sessions and workspaces, and the full pass.
    work: Lane,
    /// The store has its own lane: it is gated by `store_ready_at` on top of
    /// the debounce, and must not hold the session files back.
    store: Lane,
}

impl Pending {
    fn note(&mut self, change: Change, now: Instant) {
        match change {
            Change::Events(id) => {
                self.events.insert(id);
                self.work.touch(now);
            }
            Change::Workspace(id) => {
                self.workspaces.insert(id);
                self.work.touch(now);
            }
            Change::Store => self.store.touch(now),
            Change::Lost => {
                self.lost = true;
                self.work.touch(now);
            }
            // The tail turns it into watches and `Events`/`Workspace` hints.
            Change::Dir(_) => {}
        }
    }

    fn clear(&mut self) {
        *self = Self::default();
    }

    fn store_due(&self, opts: &TailOptions, store_ready_at: Instant) -> Option<Instant> {
        self.store
            .due(opts.debounce, opts.max_delay)
            .map(|due| due.max(store_ready_at))
    }

    /// The next moment something is due, if anything is pending.
    fn wake_at(&self, opts: &TailOptions, store_ready_at: Instant) -> Option<Instant> {
        let work = self.work.due(opts.debounce, opts.max_delay);
        match (work, self.store_due(opts, store_ready_at)) {
            (Some(a), Some(b)) => Some(a.min(b)),
            (a, b) => a.or(b),
        }
    }

    /// Removes and returns what is due at `now`; the rest stays pending.
    fn take_due(&mut self, now: Instant, opts: &TailOptions, store_ready_at: Instant) -> Work {
        let mut work = Work::default();
        if self
            .work
            .due(opts.debounce, opts.max_delay)
            .is_some_and(|due| due <= now)
        {
            work.events = mem::take(&mut self.events).into_iter().collect();
            work.workspaces = mem::take(&mut self.workspaces).into_iter().collect();
            work.full = mem::take(&mut self.lost);
            self.work.clear();
        }
        if self
            .store_due(opts, store_ready_at)
            .is_some_and(|due| due <= now)
        {
            work.store = true;
            self.store.clear();
        }
        work
    }
}

/// What the watcher thread hands over.
enum Message {
    Changes(Vec<Change>),
    /// The backend failed (for example the inotify watch limit): events may
    /// have been missed.
    Failed(String),
}

struct Tail {
    ingester: Ingester,
    opts: TailOptions,
    sessions_root: PathBuf,
    watcher: RecommendedWatcher,
    /// Session directories that have a watch.
    watched: HashSet<String>,
    pending: Pending,
    store_ready_at: Instant,
    summary: Summary,
}

impl Tail {
    /// Starts the watcher on the state directory (to see sessions appear) and
    /// on the Copilot directory (to see the store change). Session
    /// directories are added by [`Self::reconcile_watches`].
    fn start(ingester: Ingester, opts: TailOptions) -> Result<(Self, UnboundedReceiver<Message>)> {
        let (tx, rx) = mpsc::unbounded_channel();
        let classifier = Classifier::new(ingester.config());
        // Runs on notify's own thread; classifying there keeps the stream of
        // access events our reads raise away from the async task.
        let mut watcher = notify::recommended_watcher(move |result: notify::Result<Event>| {
            let message = match result {
                Ok(event) => {
                    let changes = classifier.classify(&event);
                    if changes.is_empty() {
                        return;
                    }
                    Message::Changes(changes)
                }
                Err(error) => Message::Failed(error.to_string()),
            };
            // Closed only while the tail is shutting down.
            let _ = tx.send(message);
        })
        .context("starting the file watcher")?;

        let sessions_root = ingester.config().session_state_dir();
        watcher
            .watch(&sessions_root, RecursiveMode::NonRecursive)
            .with_context(|| format!("watching {}", sessions_root.display()))?;
        let copilot_dir = &ingester.config().copilot_dir;
        watcher
            .watch(copilot_dir, RecursiveMode::NonRecursive)
            .with_context(|| format!("watching {}", copilot_dir.display()))?;

        let tail = Self {
            ingester,
            opts,
            sessions_root,
            watcher,
            watched: HashSet::new(),
            pending: Pending::default(),
            store_ready_at: Instant::now(),
            summary: Summary::default(),
        };
        Ok((tail, rx))
    }

    /// Makes sure `id` has a watch if its directory exists, and drops the
    /// watch if it does not. Returns whether the directory exists.
    fn watch_session(&mut self, id: &str) -> bool {
        let dir = self.sessions_root.join(id);
        if !dir.is_dir() {
            if self.watched.remove(id) {
                // The kernel already dropped the watch with the directory;
                // this only makes notify forget it.
                let _ = self.watcher.unwatch(&dir);
            }
            return false;
        }
        match self.watcher.watch(&dir, RecursiveMode::NonRecursive) {
            Ok(()) => {
                self.watched.insert(id.to_owned());
            }
            Err(error) => {
                // Most likely the inotify watch limit. The periodic full pass
                // still covers this session.
                warn!(session = id, %error, "cannot watch the session directory; relying on the periodic rescan");
                self.watched.remove(id);
            }
        }
        true
    }

    /// Brings the watches in line with the directories that exist. Returns
    /// how many sessions are watched.
    fn reconcile_watches(&mut self) -> Result<usize> {
        let listed = self.ingester.list_sessions()?;
        let present: HashSet<&str> = listed.iter().map(|s| s.id.as_str()).collect();
        let departed: Vec<String> = self
            .watched
            .iter()
            .filter(|id| !present.contains(id.as_str()))
            .cloned()
            .collect();
        for id in departed {
            self.watch_session(&id);
        }
        for session in &listed {
            if !self.watched.contains(&session.id) {
                self.watch_session(&session.id);
            }
        }
        Ok(self.watched.len())
    }

    fn receive(&mut self, message: Message, now: Instant) {
        match message {
            Message::Changes(changes) => {
                for change in changes {
                    self.note(change, now);
                }
            }
            Message::Failed(error) => {
                warn!(%error, "the file watcher reported an error; scheduling a full pass");
                self.pending.note(Change::Lost, now);
            }
        }
    }

    fn note(&mut self, change: Change, now: Instant) {
        if let Change::Dir(id) = change {
            // Watch first, then look inside: whatever is created after the
            // watch raises an event, whatever existed before is read now.
            // Doing it again for a directory that is already watched is
            // harmless, and it repairs a watch that died with a directory
            // that was replaced faster than we processed the events.
            if self.watch_session(&id) {
                self.pending.note(Change::Events(id.clone()), now);
                self.pending.note(Change::Workspace(id), now);
            }
        } else {
            self.pending.note(change, now);
        }
    }

    fn wake_at(&self) -> Option<Instant> {
        self.pending.wake_at(&self.opts, self.store_ready_at)
    }

    /// Everything, once: the startup catch-up and the periodic rescan.
    async fn full_pass(&mut self) -> Result<(RunReport, usize)> {
        // Watches first: see the module comment.
        let watching = self.reconcile_watches()?;
        let run = self.ingester.run_all(false, self.opts.jobs).await?;
        // The pass looked at everything that was pending, and no hint can
        // have been noted while it ran (this task is the only one that
        // notes them).
        self.pending.clear();
        self.store_ready_at = Instant::now() + self.opts.store_interval;
        self.summary.full_passes += 1;
        self.summary.totals.merge(&run.totals);
        self.summary.store_rows += run.store.changed();
        self.summary.failures += run.failed.len() as u64;
        Ok((run, watching))
    }

    async fn catch_up(&mut self) -> Result<()> {
        let started = Instant::now();
        let (run, watching) = self.full_pass().await?;
        info!(
            watching,
            sessions_read = run.totals.sessions_read,
            lines = run.totals.lines,
            events_changed = run.totals.events_changed,
            store_rows = run.store.changed(),
            failed = run.failed.len(),
            seconds = format!("{:.1}", started.elapsed().as_secs_f64()),
            "caught up; following changes"
        );
        Ok(())
    }

    /// A failed rescan (the state directory vanished for a moment, say) is
    /// not worth killing a service for: the next one retries.
    async fn rescan(&mut self) {
        let started = Instant::now();
        match self.full_pass().await {
            Ok((run, watching)) => debug!(
                watching,
                lines = run.totals.lines,
                events_changed = run.totals.events_changed,
                store_rows = run.store.changed(),
                failed = run.failed.len(),
                millis = started.elapsed().as_millis() as u64,
                "full pass done"
            ),
            Err(error) => {
                warn!(error = %format!("{error:#}"), "full pass failed; retrying at the next one")
            }
        }
    }

    async fn flush_due(&mut self) -> Result<()> {
        let work = self
            .pending
            .take_due(Instant::now(), &self.opts, self.store_ready_at);
        if work.full {
            self.rescan().await;
            return Ok(());
        }
        if work.is_empty() {
            return Ok(());
        }
        let started = Instant::now();
        let mut failed = self.ingester.sync_workspaces(&work.workspaces).await;
        let mut store_rows = 0;
        if work.store {
            match self.ingester.sync_store(false).await {
                Ok(report) => store_rows = report.changed(),
                Err(error) => {
                    warn!(error = %format!("{error:#}"), "session store not synced");
                    failed.push((STORE_FILE.to_owned(), format!("{error:#}")));
                }
            }
            self.store_ready_at = Instant::now() + self.opts.store_interval;
        }
        let sessions = work.events.len();
        let (report, failures) = self
            .ingester
            .ingest_sessions(work.events, false, self.opts.jobs)
            .await?;
        failed.extend(failures);

        self.summary.flushes += 1;
        self.summary.totals.merge(&report);
        self.summary.store_rows += store_rows;
        self.summary.failures += failed.len() as u64;
        debug!(
            sessions,
            workspaces = work.workspaces.len(),
            lines = report.lines,
            events_changed = report.events_changed,
            store_rows,
            failed = failed.len(),
            millis = started.elapsed().as_millis() as u64,
            "changes copied"
        );
        Ok(())
    }
}

/// Follows the Copilot CLI's files until `shutdown` completes: a full pass
/// first, then targeted passes on notifications, plus the periodic rescan.
///
/// `shutdown` is honoured between passes (and while the startup catch-up
/// runs): a pass in progress finishes its transaction batch, which keeps
/// every stored byte offset consistent with the rows behind it.
pub async fn run(
    ingester: Ingester,
    opts: TailOptions,
    shutdown: impl Future<Output = ()>,
) -> Result<Summary> {
    let opts = opts.normalized();
    tokio::pin!(shutdown);
    let (mut tail, mut rx) = Tail::start(ingester, opts)?;
    info!(
        root = %tail.sessions_root.display(),
        debounce = ?tail.opts.debounce,
        max_delay = ?tail.opts.max_delay,
        store_interval = ?tail.opts.store_interval,
        rescan = ?tail.opts.rescan,
        jobs = tail.opts.jobs,
        "tail starting"
    );
    tokio::select! {
        caught_up = tail.catch_up() => caught_up?,
        () = &mut shutdown => {
            info!("stopped while catching up");
            return Ok(tail.summary);
        }
    }

    let mut rescan = tokio::time::interval_at(
        tokio::time::Instant::now() + tail.opts.rescan,
        tail.opts.rescan,
    );
    rescan.set_missed_tick_behavior(MissedTickBehavior::Delay);
    loop {
        // Fold in everything that is already waiting, so that the deadline
        // below reflects the latest change.
        while let Ok(message) = rx.try_recv() {
            tail.receive(message, Instant::now());
        }
        let wake = tail.wake_at();
        let timer = tokio::time::sleep_until(tokio::time::Instant::from_std(
            wake.unwrap_or_else(|| Instant::now() + IDLE),
        ));
        tokio::pin!(timer);
        // `biased` plus this order: shutting down beats everything, and a
        // due pass beats new hints, so a stream of hints cannot starve it.
        tokio::select! {
            biased;
            () = &mut shutdown => break,
            () = &mut timer, if wake.is_some() => tail.flush_due().await?,
            _ = rescan.tick() => tail.rescan().await,
            message = rx.recv() => match message {
                Some(message) => tail.receive(message, Instant::now()),
                None => bail!("the file watcher stopped"),
            },
        }
    }
    let summary = tail.summary;
    info!(
        flushes = summary.flushes,
        full_passes = summary.full_passes,
        lines = summary.totals.lines,
        events_changed = summary.totals.events_changed,
        store_rows = summary.store_rows,
        failures = summary.failures,
        "tail stopped"
    );
    Ok(summary)
}

#[cfg(test)]
mod tests {
    use super::*;
    use notify::event::{
        AccessKind, AccessMode, CreateKind, DataChange, MetadataKind, RemoveKind, RenameMode,
    };

    fn classifier() -> Classifier {
        Classifier {
            sessions_root: PathBuf::from("/h/.copilot/session-state"),
            copilot_dir: PathBuf::from("/h/.copilot"),
        }
    }

    fn event(kind: EventKind, paths: &[&str]) -> Event {
        paths.iter().fold(Event::new(kind), |event, path| {
            event.add_path(PathBuf::from(path))
        })
    }

    fn data() -> EventKind {
        EventKind::Modify(ModifyKind::Data(DataChange::Any))
    }

    const SID: &str = "0b5e7f1a-aaaa-bbbb-cccc-1234567890ab";

    fn in_session(file: &str) -> String {
        format!("/h/.copilot/session-state/{SID}/{file}")
    }

    #[test]
    fn appended_events_file_is_a_hint_for_that_session() {
        assert_eq!(
            classifier().classify(&event(data(), &[&in_session("events.jsonl")])),
            vec![Change::Events(SID.to_owned())]
        );
    }

    #[test]
    fn created_or_removed_events_file_is_a_hint_too() {
        let c = classifier();
        for kind in [
            EventKind::Create(CreateKind::File),
            EventKind::Remove(RemoveKind::File),
        ] {
            assert_eq!(
                c.classify(&event(kind, &[&in_session("events.jsonl")])),
                vec![Change::Events(SID.to_owned())]
            );
        }
    }

    #[test]
    fn our_own_reads_raise_no_hint() {
        let c = classifier();
        let path = in_session("events.jsonl");
        for kind in [
            EventKind::Access(AccessKind::Open(AccessMode::Any)),
            EventKind::Access(AccessKind::Close(AccessMode::Read)),
            // The write that preceded this close raised its own event.
            EventKind::Access(AccessKind::Close(AccessMode::Write)),
        ] {
            assert!(c.classify(&event(kind, &[&path])).is_empty(), "{kind:?}");
        }
        assert!(
            c.classify(&event(
                EventKind::Access(AccessKind::Open(AccessMode::Any)),
                &["/h/.copilot/session-store.db-wal"]
            ))
            .is_empty()
        );
    }

    #[test]
    fn metadata_changes_are_not_content() {
        let kind = EventKind::Modify(ModifyKind::Metadata(MetadataKind::Any));
        assert!(
            classifier()
                .classify(&event(kind, &[&in_session("events.jsonl")]))
                .is_empty()
        );
    }

    #[test]
    fn workspace_yaml_is_recognised_also_when_it_arrives_by_rename() {
        let c = classifier();
        let want = vec![Change::Workspace(SID.to_owned())];
        let renamed = EventKind::Modify(ModifyKind::Name(RenameMode::To));
        assert_eq!(
            c.classify(&event(renamed, &[&in_session("workspace.yaml")])),
            want
        );
        // Both ends of a rename in one event: the temporary name is ignored.
        let both = EventKind::Modify(ModifyKind::Name(RenameMode::Both));
        assert_eq!(
            c.classify(&event(
                both,
                &[
                    &in_session("workspace.yaml.tmp"),
                    &in_session("workspace.yaml")
                ]
            )),
            want
        );
        assert!(
            c.classify(&event(data(), &[&in_session("workspace.yaml.tmp")]))
                .is_empty()
        );
    }

    #[test]
    fn session_directories_appearing_and_going_are_rechecked() {
        let c = classifier();
        let dir = format!("/h/.copilot/session-state/{SID}");
        for kind in [
            EventKind::Create(CreateKind::Folder),
            EventKind::Remove(RemoveKind::Folder),
            EventKind::Modify(ModifyKind::Name(RenameMode::From)),
            EventKind::Modify(ModifyKind::Name(RenameMode::To)),
        ] {
            assert_eq!(
                c.classify(&event(kind, &[&dir])),
                vec![Change::Dir(SID.to_owned())],
                "{kind:?}"
            );
        }
    }

    #[test]
    fn hidden_entries_and_the_root_itself_are_ignored() {
        let c = classifier();
        let create = EventKind::Create(CreateKind::Folder);
        assert!(
            c.classify(&event(create, &["/h/.copilot/session-state/.tmp-1234"]))
                .is_empty()
        );
        assert!(
            c.classify(&event(create, &["/h/.copilot/session-state"]))
                .is_empty()
        );
    }

    #[test]
    fn other_files_of_a_session_are_ignored() {
        let c = classifier();
        for file in [
            "files/plan.md",
            "checkpoints/index.md",
            "research",
            "lock.json",
        ] {
            assert!(
                c.classify(&event(data(), &[&in_session(file)])).is_empty(),
                "{file}"
            );
        }
    }

    #[test]
    fn only_the_store_and_its_log_are_hints_in_the_copilot_directory() {
        let c = classifier();
        for file in ["session-store.db", "session-store.db-wal"] {
            assert_eq!(
                c.classify(&event(data(), &[&format!("/h/.copilot/{file}")])),
                vec![Change::Store],
                "{file}"
            );
        }
        for file in [
            "session-store.db-shm",
            "session-store.db-journal",
            "session-store.dbx",
            "command-history-state.json",
            "settings.json",
        ] {
            assert!(
                c.classify(&event(data(), &[&format!("/h/.copilot/{file}")]))
                    .is_empty(),
                "{file}"
            );
        }
        // Nested like the store, but not in the Copilot directory itself.
        assert!(
            c.classify(&event(data(), &["/h/.copilot/logs/session-store.db"]))
                .is_empty()
        );
    }

    #[test]
    fn a_kernel_overflow_means_everything_is_suspect() {
        let overflow = Event::new(EventKind::Other).set_flag(notify::event::Flag::Rescan);
        assert_eq!(classifier().classify(&overflow), vec![Change::Lost]);
    }

    fn opts() -> TailOptions {
        TailOptions {
            jobs: 1,
            debounce: Duration::from_secs(2),
            max_delay: Duration::from_secs(10),
            store_interval: Duration::from_secs(15),
            rescan: Duration::from_secs(60),
        }
    }

    fn at(base: Instant, secs: f64) -> Instant {
        base + Duration::from_secs_f64(secs)
    }

    #[test]
    fn nothing_pending_means_no_wakeup() {
        let base = Instant::now();
        assert_eq!(Pending::default().wake_at(&opts(), base), None);
    }

    #[test]
    fn work_is_due_after_the_quiet_period_and_each_hint_extends_it() {
        let (o, t0) = (opts(), Instant::now());
        let mut p = Pending::default();
        p.note(Change::Events("a".into()), at(t0, 0.0));
        assert_eq!(p.wake_at(&o, t0), Some(at(t0, 2.0)));
        p.note(Change::Events("a".into()), at(t0, 1.5));
        assert_eq!(p.wake_at(&o, t0), Some(at(t0, 3.5)));
        assert_eq!(p.take_due(at(t0, 3.0), &o, t0), Work::default());
        let work = p.take_due(at(t0, 3.5), &o, t0);
        assert_eq!(work.events, ["a"]);
        assert!(p.wake_at(&o, t0).is_none());
    }

    #[test]
    fn a_session_that_never_pauses_is_still_read_after_the_maximum_delay() {
        let (o, t0) = (opts(), Instant::now());
        let mut p = Pending::default();
        for i in 0..40 {
            p.note(Change::Events("busy".into()), at(t0, f64::from(i) * 0.5));
        }
        // The last hint came at 19.5 s; without the cap the pass would wait
        // for 21.5 s, and for ever if the hints never stopped.
        assert_eq!(p.wake_at(&o, t0), Some(at(t0, 10.0)));
        assert_eq!(p.take_due(at(t0, 10.0), &o, t0).events, ["busy"]);
    }

    #[test]
    fn hints_are_deduplicated_and_sorted() {
        let (o, t0) = (opts(), Instant::now());
        let mut p = Pending::default();
        for id in ["b", "a", "b", "a", "c"] {
            p.note(Change::Events(id.into()), t0);
        }
        p.note(Change::Workspace("b".into()), t0);
        p.note(Change::Workspace("b".into()), t0);
        let work = p.take_due(at(t0, 5.0), &o, t0);
        assert_eq!(work.events, ["a", "b", "c"]);
        assert_eq!(work.workspaces, ["b"]);
    }

    #[test]
    fn the_store_waits_for_its_floor_but_does_not_hold_the_sessions_back() {
        let (o, t0) = (opts(), Instant::now());
        let ready = at(t0, 15.0);
        let mut p = Pending::default();
        p.note(Change::Store, at(t0, 0.0));
        p.note(Change::Events("a".into()), at(t0, 0.0));
        // Sessions at 2 s; the store would be due then too but is gated to 15 s.
        assert_eq!(p.wake_at(&o, ready), Some(at(t0, 2.0)));
        let first = p.take_due(at(t0, 2.0), &o, ready);
        assert_eq!(first.events, ["a"]);
        assert!(!first.store);
        // Only the store is left, and it keeps its place in the queue.
        assert_eq!(p.wake_at(&o, ready), Some(ready));
        assert!(!p.take_due(at(t0, 14.9), &o, ready).store);
        assert!(p.take_due(ready, &o, ready).store);
        assert!(p.wake_at(&o, ready).is_none());
    }

    #[test]
    fn a_store_that_is_written_continuously_is_synced_at_the_floor() {
        let (o, t0) = (opts(), Instant::now());
        let ready = at(t0, 15.0);
        let mut p = Pending::default();
        for i in 0..100 {
            p.note(Change::Store, at(t0, f64::from(i) * 0.3));
        }
        assert_eq!(p.wake_at(&o, ready), Some(ready));
    }

    #[test]
    fn lost_notifications_turn_the_next_pass_into_a_full_one() {
        let (o, t0) = (opts(), Instant::now());
        let mut p = Pending::default();
        p.note(Change::Lost, t0);
        p.note(Change::Events("a".into()), t0);
        let work = p.take_due(at(t0, 2.0), &o, t0);
        assert!(work.full);
        assert!(!work.is_empty());
        // Handed over once.
        p.note(Change::Events("a".into()), at(t0, 3.0));
        assert!(!p.take_due(at(t0, 6.0), &o, t0).full);
    }

    #[test]
    fn clearing_forgets_everything() {
        let (o, t0) = (opts(), Instant::now());
        let mut p = Pending::default();
        p.note(Change::Events("a".into()), t0);
        p.note(Change::Workspace("a".into()), t0);
        p.note(Change::Store, t0);
        p.note(Change::Lost, t0);
        p.clear();
        assert!(p.wake_at(&o, t0).is_none());
        assert!(p.take_due(at(t0, 99.0), &o, t0).is_empty());
    }

    #[test]
    fn degenerate_options_are_made_safe() {
        let o = TailOptions {
            jobs: 0,
            rescan: Duration::ZERO,
            ..opts()
        }
        .normalized();
        assert_eq!(o.jobs, 1);
        assert!(o.rescan >= Duration::from_secs(1));
    }
}
