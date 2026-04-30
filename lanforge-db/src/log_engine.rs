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
use std::fs::{OpenOptions, create_dir_all};
use std::net::IpAddr;
use std::path::Path;
use std::time::{Duration, Instant, UNIX_EPOCH};
use tokio::sync::Mutex;
use tracing::{debug, info};

use crate::LeaseDbError;
use lanforge_core::bus::{LanforgeEvent, TimedEvent};
use sqlx::{Row, SqlitePool};

/// A SQLite-backed log store for transient system events.
///
/// Designed for in-memory storage where data loss on reboot is acceptable
/// but high write throughput and zero disk wear are essential.
pub struct LogDb {
    pool: SqlitePool,
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
            let path = Path::new(path_str);

            if let Some(parent) = path.parent()
                && !parent.as_os_str().is_empty()
                && !parent.exists()
            {
                let _ = create_dir_all(parent);
            }

            // Manually create the file if it doesn't exist to avoid "unable to open database file"
            if !path.exists() {
                debug!("Creating new log database file: {}", path_str);
                let _ = OpenOptions::new()
                    .write(true)
                    .create(true)
                    .truncate(true)
                    .open(path);
            }
        }

        let pool = SqlitePool::connect(url).await?;

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
                event_json TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON system_logs(timestamp);
             CREATE TABLE IF NOT EXISTS dns_blocked_logs (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  INTEGER NOT NULL,
                src_ip     TEXT NOT NULL,
                src_mac    TEXT,
                domain     TEXT NOT NULL
             );
             CREATE INDEX IF NOT EXISTS idx_dns_logs_timestamp ON dns_blocked_logs(timestamp);",
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
        self.record_logs_batch(std::slice::from_ref(timed_event))
            .await
    }

    /// Records multiple events in a single transaction.
    pub async fn record_logs_batch(&self, events: &[TimedEvent]) -> Result<(), LeaseDbError> {
        if events.is_empty() {
            return Ok(());
        }

        let mut tx = self.pool.begin().await?;

        let mut last_timestamp = 0;
        for timed_event in events {
            let json = serde_json::to_string(&timed_event.event).map_err(|e| {
                LeaseDbError::Migration("event serialization".into(), e.to_string())
            })?;

            let now_secs = timed_event
                .timestamp
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            last_timestamp = now_secs;

            sqlx::query("INSERT INTO system_logs (timestamp, event_json) VALUES (?, ?)")
                .bind(now_secs)
                .bind(json)
                .execute(&mut *tx)
                .await?;
        }

        tx.commit().await.map_err(LeaseDbError::TransactionFailed)?;

        if last_timestamp > 0 {
            self.maybe_prune(last_timestamp).await?;
        }
        Ok(())
    }

    /// Records a blocked DNS query.
    pub async fn record_dns_block(
        &self,
        timed_event: &TimedEvent,
        src_ip: IpAddr,
        domain: &str,
        src_mac: Option<String>,
    ) -> Result<(), LeaseDbError> {
        let now_secs = timed_event
            .timestamp
            .duration_since(UNIX_EPOCH)
            .unwrap_or_default()
            .as_secs() as i64;

        sqlx::query(
            "INSERT INTO dns_blocked_logs (timestamp, src_ip, src_mac, domain) VALUES (?, ?, ?, ?)",
        )
        .bind(now_secs)
        .bind(src_ip.to_string())
        .bind(src_mac)
        .bind(domain)
        .execute(&self.pool)
        .await?;

        self.maybe_prune(now_secs).await?;
        Ok(())
    }

    async fn maybe_prune(&self, now_secs: i64) -> Result<(), LeaseDbError> {
        let mut last_prune = self.last_prune.lock().await;
        if last_prune.elapsed() >= Duration::from_secs(60) {
            let cutoff = now_secs - (24 * 3600);

            // Prune system logs
            sqlx::query("DELETE FROM system_logs WHERE timestamp < ?")
                .bind(cutoff)
                .execute(&self.pool)
                .await?;

            sqlx::query(
                "DELETE FROM system_logs WHERE id <= (SELECT MAX(id) FROM system_logs) - 50000",
            )
            .execute(&self.pool)
            .await?;

            // Prune DNS logs
            sqlx::query("DELETE FROM dns_blocked_logs WHERE timestamp < ?")
                .bind(cutoff)
                .execute(&self.pool)
                .await?;

            sqlx::query(
                "DELETE FROM dns_blocked_logs WHERE id <= (SELECT MAX(id) FROM dns_blocked_logs) - 50000",
            )
            .execute(&self.pool)
            .await?;

            *last_prune = Instant::now();
            debug!("Log database pruned");
        }
        Ok(())
    }

    /// Retrieves the most recent blocked DNS queries.
    pub async fn get_dns_block_history(
        &self,
        limit: usize,
    ) -> Result<Vec<serde_json::Value>, LeaseDbError> {
        let limit = limit as i64;
        let rows = sqlx::query(
            "SELECT timestamp, src_ip, src_mac, domain FROM dns_blocked_logs ORDER BY id DESC LIMIT ?",
        )
        .bind(limit)
        .fetch_all(&self.pool)
        .await?;

        let mut entries = Vec::new();
        for row in rows {
            let timestamp: i64 = row.get("timestamp");
            let src_ip: String = row.get("src_ip");
            let src_mac: Option<String> = row.get("src_mac");
            let domain: String = row.get("domain");

            entries.push(serde_json::json!({
                "timestamp": timestamp,
                "src_ip": src_ip,
                "src_mac": src_mac,
                "domain": domain,
            }));
        }
        Ok(entries)
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
        let rows =
            sqlx::query("SELECT timestamp, event_json FROM system_logs ORDER BY id DESC LIMIT ?")
                .bind(limit)
                .fetch_all(&self.pool)
                .await?;

        let mut entries = Vec::new();
        for row in rows {
            let timestamp: i64 = row.get("timestamp");
            let event_json: String = row.get("event_json");

            if let Ok(event) = serde_json::from_str::<LanforgeEvent>(&event_json) {
                entries.push(TimedEvent {
                    event,
                    timestamp: UNIX_EPOCH + Duration::from_secs(timestamp as u64),
                });
            }
        }

        // Return in chronological order (oldest first for the UI)
        entries.reverse();
        Ok(entries)
    }
}
