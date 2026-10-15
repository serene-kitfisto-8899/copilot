//! Shared library for the Copilot context tooling (see PLAN.md).

pub mod config;
pub mod db;
pub mod events;
pub mod ingest;
pub mod reader;
pub mod redact;
pub mod report;
pub mod store;
pub mod verify;
pub mod watch;
pub mod workspace;
pub mod writer;

pub static MIGRATOR: sqlx::migrate::Migrator = sqlx::migrate!("../../migrations");
