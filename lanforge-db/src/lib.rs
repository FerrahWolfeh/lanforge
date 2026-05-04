//! # Lanforge DB — Persistence Layer
//!
//! Synchronous SQLite storage library for the Lanforge daemon.
//! Ensures that discovered network devices, DHCP leases, static configurations,
//! and event history survive system restarts.
//!
//! ## Architecture
//!
//! This crate implements two independent persistence mechanisms:
//!
//! - **`LeaseDb`** — Primary database for devices and leases (survives reboots)
//! - **`LogDb`** — Transient event log database (24h retention, optimized for tmpfs/ramdisk)
//!
//! ## Execution Model
//!
//! All database I/O runs on a **dedicated thread** via [`DbWorker`](worker::DbWorker),
//! which consumes events from the [`EventBus`](lanforge_core::bus::EventBus) through
//! a [`SyncBusReceiver`](lanforge_core::service::SyncBusReceiver). This keeps the
//! main Tokio runtime unblocked.
//!
//! ## Write Strategy
//!
//! | Mechanism | Description |
//! | :--- | :--- |
//! | **Batch Upsert** | Accumulates `DeviceUpdated` in a HashMap, flushes every 2s |
//! | **Full Snapshot** | `DeviceTableDirty` → immediate `save_table()` |
//! | **Debounce** | 2s trailing edge + flush on idle (protects SD cards from micro-writes) |
//! | **WAL Mode** | SQLite Write-Ahead Logging — writes don't block reads |
//! | **CASCADE** | `ON DELETE CASCADE` automatically removes child rows |
//!
//! ## Bootstrap Hydration Flow
//!
//! ```text
//! main.rs
//!   ├── LeaseDb::open(path)          → opens SQLite, runs migrations
//!   ├── db.load_table()              → reconstructs State from disk
//!   ├── LanforgeContext::new(bus, state)
//!   ├── applies TOML overrides        → precedence over DB entries
//!   └── set_db_ready(true)           → unblocks dependent workers
//! ```
//!
//! ## Modules
//!
//! | Module | Responsibility |
//! | :--- | :--- |
//! | [`engine`] | `LeaseDb` — schema, migrations, save/load, vacuum, prune |
//! | [`log_engine`] | `LogDb` — transient logs with auto-pruning (24h + 50K cap) |
//! | [`worker`] | `DbWorker` — sync service coordinating persistence |
//! | [`error`] | `LeaseDbError` — I/O and SQLite error hierarchy |
#[cfg(not(any(feature = "sqlite", feature = "postgres")))]
compile_error!("Either 'sqlite' or 'postgres' feature must be enabled for lanforge-db.");

#[warn(clippy::all, clippy::nursery, clippy::pedantic)]
#[allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
pub mod config;
pub mod engine;
pub mod error;
pub mod log_engine;
#[cfg(test)]
mod tests;
pub mod worker;

pub use error::LeaseDbError;
