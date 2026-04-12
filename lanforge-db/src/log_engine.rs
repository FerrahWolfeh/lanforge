//! `LogDb` — SQLite engine for transient system logs.
//!
//! Stores `LanforgeEvent`s in a separate database (typically on tmpfs/ramdisk)
//! to provide history for `log --follow` without causing SD card wear.
//!
//! ## Design
//!
//! The `LogDb` is optimized for high-throughput, low-latency writes with minimal
//! durability guarantees:
//!
//! | PRAGMA | Value | Rationale |
//! | :--- | :--- | :--- |
//! | `journal_mode` | `WAL` | Minimal write amplification |
//! | `synchronous` | `OFF` | Data is volatile (ramdisk); loss is acceptable |
//!
//! ## Auto-Pruning
//!
//! Logs are automatically pruned using a dual-limit strategy:
//!
//! 1. **Time window:** Entries older than 24 hours are deleted
//! 2. **Capacity cap:** Maximum 50,000 entries (prevents OOM on small ramdisks)
//!
//! Pruning runs at most once every 60 seconds to avoid overhead.

use rusqlite::{Connection, params};
use serde_json;
use std::{
    cell::Cell,
    path::Path,
    time::{Duration, Instant, UNIX_EPOCH},
};
use tracing::info;

use crate::LeaseDbError;
use lanforge_core::bus::{LanforgeEvent, TimedEvent};

/// A SQLite-backed log store for transient system events.
///
/// Designed for use on tmpfs/ramdisk where data loss on reboot is acceptable
/// but high write throughput and low SD card wear are essential.
///
/// # Auto-Pruning
///
/// Automatically prunes logs older than 24 hours and caps the total at 50,000
/// entries. Pruning is rate-limited to once per 60 seconds.
pub struct LogDb {
    conn: Connection,
    last_prune: Cell<Instant>,
}

impl LogDb {
    /// Opens (or creates) the log database at the given path.
    ///
    /// Configures SQLite with `synchronous=OFF` and `journal_mode=WAL` for
    /// maximum throughput on tmpfs/ramdisk. Creates the `system_logs` table
    /// and its timestamp index if they don't exist.
    pub fn open(path: &Path) -> Result<Self, LeaseDbError> {
        if let Some(parent) = path.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)
                .map_err(|e| LeaseDbError::PathAccess(parent.to_path_buf(), e))?;
        }

        let conn = Connection::open(path)
            .map_err(|e| LeaseDbError::ConnectionOpen(path.to_path_buf(), e))?;

        // Optimized for high performance and low wear on the host FS (which is likely a ramdisk anyway)
        conn.execute_batch(
            "PRAGMA journal_mode=WAL;
             PRAGMA synchronous=OFF;
             CREATE TABLE IF NOT EXISTS system_logs (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  INTEGER NOT NULL,
                module     TEXT,
                event_json TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON system_logs(timestamp);",
        )?;

        info!("Log database opened at {}", path.display());
        Ok(Self {
            conn,
            last_prune: Cell::new(Instant::now()),
        })
    }

    /// Records a new event in the log history.
    ///
    /// Serializes the `LanforgeEvent` to JSON and inserts it into `system_logs`.
    /// Triggers auto-pruning if more than 60 seconds have elapsed since the last prune.
    pub fn record_log(&self, timed_event: &TimedEvent) -> Result<(), LeaseDbError> {
        let json = serde_json::to_string(&timed_event.event)
            .map_err(|e| LeaseDbError::Migration("event serialization".into(), e.to_string()))?;

        let now_secs = timed_event
            .timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        self.conn.execute(
            "INSERT INTO system_logs (timestamp, module, event_json) VALUES (?1, ?2, ?3)",
            params![now_secs, timed_event.module, json],
        )?;

        // Pruning: Keep only logs from the last 24 hours at most once every 60 seconds
        // Safety cap: also delete entries if we exceed 50,000 logs to prevent RAM bloat
        if self.last_prune.get().elapsed() >= Duration::from_secs(60) {
            let cutoff = now_secs - (24 * 3600);
            self.conn.execute(
                "DELETE FROM system_logs WHERE timestamp < ?1",
                params![cutoff],
            )?;

            // Safety cap: keep at most 50,000 entries
            self.conn.execute(
                "DELETE FROM system_logs WHERE id <= (SELECT MAX(id) FROM system_logs) - 50000",
                [],
            )?;

            self.last_prune.set(Instant::now());
        }

        Ok(())
    }

    /// Wipes all logged events from the database.
    ///
    /// Also resets the autoincrement counter by clearing `sqlite_sequence`.
    pub fn clear_logs(&self) -> Result<(), LeaseDbError> {
        self.conn.execute("DELETE FROM system_logs", [])?;
        self.conn
            .execute("DELETE FROM sqlite_sequence WHERE name='system_logs'", [])?;
        Ok(())
    }

    /// Retrieves the most recent log entries.
    ///
    /// Returns up to `limit` entries, ordered oldest-first (chronological)
    /// for convenient display in UIs and log viewers.
    pub fn get_history(&self, limit: usize) -> Result<Vec<TimedEvent>, LeaseDbError> {
        let mut stmt = self.conn.prepare(
            "SELECT timestamp, module, event_json FROM system_logs ORDER BY id DESC LIMIT ?1",
        )?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            let ts: i64 = row.get(0)?;
            let module: Option<String> = row.get(1)?;
            let json: String = row.get(2)?;
            Ok((ts, module, json))
        })?;

        let mut entries = Vec::new();
        for row in rows.flatten() {
            let (ts, module, json) = row;
            if let Ok(event) = serde_json::from_str::<LanforgeEvent>(&json) {
                entries.push(TimedEvent {
                    event,
                    timestamp: UNIX_EPOCH + Duration::from_secs(ts as u64),
                    module,
                });
            }
        }

        // Return in chronological order (oldest first for the UI)
        entries.reverse();
        Ok(entries)
    }
}
