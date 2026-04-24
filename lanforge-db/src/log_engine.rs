//! `LogDb` — SQLite engine for transient system logs.
//!
//! Stores `LanforgeEvent`s in an in-memory database
//! to provide history for `log --follow` without causing disk wear.
//!
//! ## Auto-Pruning
//!
//! Logs are automatically pruned using a dual-limit strategy:
//!
//! 1. **Time window:** Entries older than 24 hours are deleted
//! 2. **Capacity cap:** Maximum 50,000 entries (prevents RAM bloat)
//!
//! Pruning runs at most once every 60 seconds to avoid overhead.

use serde_json;
use std::path::Path;
use std::time::{Duration, Instant, UNIX_EPOCH};
use tokio::sync::Mutex;
use tracing::{debug, info};

use crate::LeaseDbError;
use lanforge_core::bus::{LanforgeEvent, TimedEvent};
use sqlx::Row;

/// A SQLite-backed log store for transient system events.
///
/// Designed for in-memory storage where data loss on reboot is acceptable
/// but high write throughput and zero disk wear are essential.
pub struct LogDb {
    pool: sqlx::SqlitePool,
    last_prune: Mutex<Instant>,
}

impl LogDb {
    /// Opens the log database at the specified URL.
    pub async fn open(url: &str) -> Result<Self, LeaseDbError> {
        // Ensure parent directory exists for local SQLite files
        if url.starts_with("sqlite:") && !url.contains(":memory:") {
            let path_str = url
                .strip_prefix("sqlite://")
                .or_else(|| url.strip_prefix("sqlite:"))
                .unwrap_or(url);

            let path_str = path_str.split('?').next().unwrap_or(path_str);

            if let Some(parent) = Path::new(path_str).parent()
                && !parent.as_os_str().is_empty()
                && !parent.exists()
            {
                let _ = std::fs::create_dir_all(parent);
            }
        }

        let pool = sqlx::SqlitePool::connect(url).await?;

        // Initialize PRAGMAs for performance and reliability
        sqlx::query("PRAGMA journal_mode=WAL")
            .execute(&pool)
            .await?;
        sqlx::query("PRAGMA synchronous=NORMAL")
            .execute(&pool)
            .await?;

        sqlx::query(
            "CREATE TABLE IF NOT EXISTS system_logs (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  INTEGER NOT NULL,
                module     TEXT,
                event_json TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON system_logs(timestamp);",
        )
        .execute(&pool)
        .await?;

        info!("In-memory log database initialized");
        Ok(Self {
            pool,
            last_prune: Mutex::new(Instant::now()),
        })
    }

    /// Records a new event in the log history.
    pub async fn record_log(&self, timed_event: &TimedEvent) -> Result<(), LeaseDbError> {
        let json = serde_json::to_string(&timed_event.event)
            .map_err(|e| LeaseDbError::Migration("event serialization".into(), e.to_string()))?;

        let now_secs = timed_event
            .timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        sqlx::query("INSERT INTO system_logs (timestamp, module, event_json) VALUES (?, ?, ?)")
            .bind(now_secs)
            .bind(&timed_event.module)
            .bind(json)
            .execute(&self.pool)
            .await?;

        // Pruning: Keep only logs from the last 24 hours at most once every 60 seconds
        let mut last_prune = self.last_prune.lock().await;
        if last_prune.elapsed() >= Duration::from_secs(60) {
            let cutoff = now_secs - (24 * 3600);

            sqlx::query("DELETE FROM system_logs WHERE timestamp < ?")
                .bind(cutoff)
                .execute(&self.pool)
                .await?;

            // Safety cap: keep at most 50,000 entries
            sqlx::query(
                "DELETE FROM system_logs WHERE id <= (SELECT MAX(id) FROM system_logs) - 50000",
            )
            .execute(&self.pool)
            .await?;

            *last_prune = Instant::now();
            debug!("Log database pruned");
        }

        Ok(())
    }

    /// Wipes all logged events from the database.
    pub async fn clear_logs(&self) -> Result<(), LeaseDbError> {
        sqlx::query("DELETE FROM system_logs")
            .execute(&self.pool)
            .await?;
        sqlx::query("DELETE FROM sqlite_sequence WHERE name='system_logs'")
            .execute(&self.pool)
            .await?;
        Ok(())
    }

    /// Retrieves the most recent log entries.
    pub async fn get_history(&self, limit: usize) -> Result<Vec<TimedEvent>, LeaseDbError> {
        let limit = limit as i64;
        let rows = sqlx::query(
            "SELECT timestamp, module, event_json FROM system_logs ORDER BY id DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let mut entries = Vec::new();
        for row in rows {
            let timestamp: i64 = row.get("timestamp");
            let module: Option<String> = row.get("module");
            let event_json: String = row.get("event_json");

            if let Ok(event) = serde_json::from_str::<LanforgeEvent>(&event_json) {
                entries.push(TimedEvent {
                    event,
                    timestamp: UNIX_EPOCH + Duration::from_secs(timestamp as u64),
                    module,
                });
            }
        }

        // Return in chronological order (oldest first for the UI)
        entries.reverse();
        Ok(entries)
    }
}
