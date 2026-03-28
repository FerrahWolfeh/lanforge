//! `LogDb` — SQLite engine for transient system logs.
//!
//! Stores LanforgeEvents in a separate database (typically on tmpfs)
//! to provide history for `log --follow` without SSD wear.

use rusqlite::{Connection, params};
use serde_json;
use std::path::Path;
use tracing::info;

use crate::{LeaseDbError, Result};
use lanforge_core::bus::LanforgeEvent;

pub struct LogDb {
    conn: Connection,
}

impl LogDb {
    /// Opens (or creates) the log database.
    pub fn open(path: &Path) -> Result<Self> {
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
                event_json TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON system_logs(timestamp);",
        )?;

        info!("Log database opened at {}", path.display());
        Ok(Self { conn })
    }

    /// Records a new event in the log history.
    pub fn record_log(&self, event: &LanforgeEvent) -> Result<()> {
        let json = serde_json::to_string(event)
            .map_err(|e| LeaseDbError::Migration("event serialization".into(), e.to_string()))?;

        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        self.conn.execute(
            "INSERT INTO system_logs (timestamp, event_json) VALUES (?1, ?2)",
            params![now, json],
        )?;

        // Pruning: Keep only the last 1000 entries
        // This is done on every insert to keep the tmpfs usage predictable.
        // We delete anything with an ID less than (CurrentMaxID - 1000).
        self.conn.execute(
            "DELETE FROM system_logs WHERE id <= (SELECT MAX(id) FROM system_logs) - 1000",
            &[] as &[&dyn rusqlite::ToSql],
        )?;

        Ok(())
    }

    /// Retrieves the most recent log entries.
    pub fn get_history(&self, limit: usize) -> Result<Vec<LanforgeEvent>> {
        let mut stmt = self
            .conn
            .prepare("SELECT event_json FROM system_logs ORDER BY id DESC LIMIT ?1")?;

        let rows = stmt.query_map(params![limit as i64], |row| {
            let json: String = row.get(0)?;
            Ok(json)
        })?;

        let mut events = Vec::new();
        for json in rows.flatten() {
            if let Ok(event) = serde_json::from_str::<LanforgeEvent>(&json) {
                events.push(event);
            }
        }

        // Return in chronological order (oldest first for the UI)
        events.reverse();
        Ok(events)
    }
}
