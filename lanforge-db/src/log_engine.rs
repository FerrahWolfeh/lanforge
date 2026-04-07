//! `LogDb` — SQLite engine for transient system logs.
//!
//! Stores LanforgeEvents in a separate database (typically on tmpfs)
//! to provide history for `log --follow` without SSD wear.

use rusqlite::{Connection, params};
use serde_json;
use std::{
    path::Path,
    time::{Duration, UNIX_EPOCH},
};
use tracing::info;

use crate::LeaseDbError;
use lanforge_core::bus::{LanforgeEvent, TimedEvent};

pub struct LogDb {
    conn: Connection,
}

impl LogDb {
    /// Opens (or creates) the log database.
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
        Ok(Self { conn })
    }

    /// Records a new event in the log history.
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

        // Pruning: Keep only logs from the last 24 hours
        // Safety cap: also delete entries if we exceed 50,000 logs to prevent RAM bloat
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

        Ok(())
    }

    /// Wipes all logged events from the database.
    pub fn clear_logs(&self) -> Result<(), LeaseDbError> {
        self.conn.execute("DELETE FROM system_logs", [])?;
        self.conn
            .execute("DELETE FROM sqlite_sequence WHERE name='system_logs'", [])?;
        Ok(())
    }

    /// Retrieves the most recent log entries.
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
