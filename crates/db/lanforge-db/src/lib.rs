//! # Lanforge DB — Persistence Layer
//!
//! Storage and persistence layer for the Lanforge daemon.
//! Ensures that discovered network devices, DHCP leases, static configurations,
//! and event history survive system restarts.
//!
//! ## Architecture
//!
//! This crate implements two independent persistence mechanisms:
//!
//! - **`LanforgeDb`** — Primary PostgreSQL database for devices, leases, and configuration.
//! - **`LogDb`** — Transient event and DNS query log database (in-memory ring buffer with tmpfs JSONL auto-pruning).
//!
//! ## Execution Model
//!
//! All database I/O runs asynchronously coordinated by [`DbWorker`](worker::DbWorker),
//! which consumes events from the [`EventBus`](lanforge_core::bus::EventBus).
//!
//! ## Write Strategy
//!
//! | Mechanism | Description |
//! | :--- | :--- |
//! | **Batch Upsert** | Accumulates modified devices and leases, flushing on a 5s interval |
//! | **Full Snapshot** | `StorageEvent::TableDirty` → immediate table snapshot flush |
//! | **Log Buffer Auto-Pruning** | `LogDb` auto-trims transient entries older than 24h every 60s |
//!
//! ## Bootstrap Hydration Flow
//!
//! ```text
//! bootstrap.rs
//!   ├── LanforgeDb::open(url)            → connects to PostgreSQL, runs migrations
//!   ├── db.load_all_devices()            → reconstructs State from database
//!   ├── LanforgeContext::new(bus, state)
//!   ├── applies TOML overrides          → configuration precedence
//!   └── set_db_ready(true)              → unblocks dependent services
//! ```
//!
//! ## Modules
//!
//! | Module | Responsibility |
//! | :--- | :--- |
//! | [`engine`] | `LanforgeDb` — Postgres database facade for devices, leases, and config |
//! | [`log_engine`] | `LogDb` — transient logs in tmpfs with auto-pruning |
//! | [`worker`] | `DbWorker` — async service coordinating persistence |
//! | [`error`] | `LanforgeDbError` — database error hierarchy |
#[cfg(not(feature = "postgres"))]
compile_error!("The 'postgres' feature must be enabled for lanforge-db.");

#[warn(clippy::all, clippy::nursery, clippy::pedantic)]
#[allow(clippy::missing_errors_doc, clippy::missing_panics_doc)]
pub mod config;
pub mod engine;
pub mod error;
pub mod log_engine;
#[cfg(test)]
mod tests;
pub mod worker;

pub use engine::LanforgeDb;
pub use lanforge_db_core::{
    AdblockStore, ApiTokenStore, DeviceStore, DhcpConfigStore, DnsStore, DnsUpstreamStore,
    PppoeConfigStore, RaConfigStore, UserStore, sanitize_db_url,
};
