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

use lanforge_core::types::QueryResult;
use lanforge_core::types::network::{DnsRecordType, QueryLogEntry};
use serde_json;
use std::fs::{OpenOptions, create_dir_all};
use std::net::{IpAddr, Ipv4Addr};
use std::path::Path;
use std::time::{Duration, Instant, UNIX_EPOCH};
use tokio::sync::Mutex;
use tracing::debug;

use crate::LeaseDbError;
use futures::StreamExt;
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
        sqlx::query("PRAGMA auto_vacuum=INCREMENTAL")
            .execute(&pool)
            .await?;
        sqlx::query("PRAGMA page_size=4096").execute(&pool).await?;

        #[cfg_attr(not(feature = "adblock"), allow(unused_mut))]
        let mut init_query = "
            CREATE TABLE IF NOT EXISTS system_logs (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  INTEGER NOT NULL,
                event_json TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON system_logs(timestamp);
            CREATE TABLE IF NOT EXISTS dns_queries (
                id          INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp   INTEGER NOT NULL,
                src_ip      TEXT NOT NULL,
                src_mac     TEXT,
                domain      TEXT NOT NULL,
                qtype       INTEGER NOT NULL,
                result      TEXT NOT NULL,
                upstream_us INTEGER NOT NULL,
                cached      INTEGER NOT NULL,
                answer      TEXT,
                protocol    TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_dns_queries_timestamp ON dns_queries(timestamp);
        "
        .to_string();

        #[cfg(feature = "adblock")]
        init_query.push_str(
            "
            CREATE TABLE IF NOT EXISTS dns_blocked_logs (
                id         INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp  INTEGER NOT NULL,
                src_ip     TEXT NOT NULL,
                src_mac    TEXT,
                domain     TEXT NOT NULL
            );
            CREATE INDEX IF NOT EXISTS idx_dns_logs_timestamp ON dns_blocked_logs(timestamp);
            ",
        );

        sqlx::query(&init_query).execute(&pool).await?;

        debug!("In-memory log database initialized");
        Ok(Self {
            pool,
            last_prune: Mutex::new(Instant::now()),
        })
    }

    /// Records a new event in the log history.
    pub async fn record_log(&self, timed_event: &TimedEvent) -> Result<(), LeaseDbError> {
        let mut buf = String::new();
        self.record_logs_batch(std::slice::from_ref(timed_event), &mut buf)
            .await
    }

    /// Records multiple events in a single transaction using a reusable buffer.
    pub async fn record_logs_batch(
        &self,
        events: &[TimedEvent],
        json_buf: &mut String,
    ) -> Result<(), LeaseDbError> {
        if events.is_empty() {
            return Ok(());
        }

        let mut tx = self.pool.begin().await?;

        let mut last_timestamp = 0;
        for timed_event in events {
            json_buf.clear();
            // Safety: serde_json always produces valid UTF-8
            unsafe {
                serde_json::to_writer(json_buf.as_mut_vec(), &timed_event.event).map_err(|e| {
                    LeaseDbError::Migration("event serialization".into(), e.to_string())
                })?;
            }

            let now_secs = timed_event
                .timestamp
                .duration_since(UNIX_EPOCH)
                .unwrap_or_default()
                .as_secs() as i64;
            last_timestamp = now_secs;

            sqlx::query("INSERT INTO system_logs (timestamp, event_json) VALUES (?, ?)")
                .bind(now_secs)
                .bind(json_buf.as_str())
                .execute(&mut *tx)
                .await?;

            #[cfg(feature = "hotpath")]
            {
                hotpath::gauge!("log_db_system_count").inc(1.0);
            }
        }

        tx.commit().await.map_err(LeaseDbError::TransactionFailed)?;

        if last_timestamp > 0 {
            self.maybe_prune(last_timestamp).await?;
        }
        Ok(())
    }

    /// Records a blocked DNS query.
    #[cfg(feature = "adblock")]
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

        #[cfg(feature = "hotpath")]
        {
            hotpath::gauge!("log_db_blocked_count").inc(1.0);
        }

        self.maybe_prune(now_secs).await?;
        Ok(())
    }

    /// Records a resolved DNS query.
    #[cfg_attr(feature = "hotpath", hotpath::measure)]
    pub async fn record_dns_query(&self, entry: &QueryLogEntry) -> Result<(), LeaseDbError> {
        sqlx::query(
            "INSERT INTO dns_queries (timestamp, src_ip, src_mac, domain, qtype, result, upstream_us, cached, answer, protocol) 
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
        )
        .bind(entry.timestamp as i64)
        .bind(entry.src_ip.to_string())
        .bind(entry.src_mac.as_ref().map(|m| m.to_string()))
        .bind(entry.domain.as_ref())
        .bind(u16::from(entry.qtype) as i32)
        .bind(format!("{:?}", entry.result).to_lowercase())
        .bind(i64::from(entry.upstream_us))
        .bind(i32::from(entry.cached))
        .bind(entry.answer.as_ref())
        .bind(entry.protocol.to_string().to_lowercase())
        .execute(&self.pool)
        .await?;

        #[cfg(feature = "hotpath")]
        {
            hotpath::gauge!("log_db_dns_count").inc(1.0);
        }

        self.maybe_prune(entry.timestamp as i64).await?;
        Ok(())
    }

    #[cfg_attr(feature = "hotpath", hotpath::measure)]
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
                "DELETE FROM system_logs WHERE id <= (SELECT MAX(id) FROM system_logs) - 10000",
            )
            .execute(&self.pool)
            .await?;

            // Prune DNS logs
            #[cfg(feature = "adblock")]
            {
                sqlx::query("DELETE FROM dns_blocked_logs WHERE timestamp < ?")
                    .bind(cutoff)
                    .execute(&self.pool)
                    .await?;

                sqlx::query(
                    "DELETE FROM dns_blocked_logs WHERE id <= (SELECT MAX(id) FROM dns_blocked_logs) - 10000",
                )
                .execute(&self.pool)
                .await?;
            }

            // Prune full DNS query logs
            sqlx::query("DELETE FROM dns_queries WHERE timestamp < ?")
                .bind(cutoff)
                .execute(&self.pool)
                .await?;

            sqlx::query(
                "DELETE FROM dns_queries WHERE id <= (SELECT MAX(id) FROM dns_queries) - 20000",
            )
            .execute(&self.pool)
            .await?;

            *last_prune = Instant::now();
            debug!("Log database pruned");

            #[cfg(feature = "hotpath")]
            {
                let sys_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM system_logs")
                    .fetch_one(&self.pool)
                    .await
                    .unwrap_or((0,));
                let dns_count: (i64,) = sqlx::query_as("SELECT COUNT(*) FROM dns_queries")
                    .fetch_one(&self.pool)
                    .await
                    .unwrap_or((0,));
                hotpath::gauge!("log_db_system_count").set(sys_count.0 as f64);
                hotpath::gauge!("log_db_dns_count").set(dns_count.0 as f64);
            }
        }
        Ok(())
    }

    /// Retrieves the most recent DNS queries.
    pub async fn get_dns_query_history(
        &self,
        limit: usize,
    ) -> Result<Vec<QueryLogEntry>, LeaseDbError> {
        let limit = limit as i64;
        let rows = sqlx::query(
            "SELECT timestamp, src_ip, src_mac, domain, qtype, result, upstream_us, cached, answer, protocol 
             FROM dns_queries ORDER BY id DESC LIMIT ?",
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
            let qtype: i32 = row.get("qtype");
            let result: String = row.get("result");
            let upstream_us: i64 = row.get("upstream_us");
            let cached: i32 = row.get("cached");
            let answer: Option<String> = row.get("answer");
            let protocol: String = row.get("protocol");

            entries.push(QueryLogEntry {
                timestamp: timestamp as u64,
                src_ip: src_ip.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED)),
                src_mac: src_mac.and_then(|m| m.parse().ok()),
                domain: std::sync::Arc::from(domain),
                qtype: DnsRecordType::from(qtype as u16),
                result: match result.as_str() {
                    "local" => QueryResult::Local,
                    "forwarded" => QueryResult::Forwarded,
                    "blocked" => QueryResult::Blocked,
                    "nxdomain" => QueryResult::NxDomain,
                    "error" => QueryResult::Error,
                    "cached" => QueryResult::Cached,
                    "rewritten" => QueryResult::Rewritten,
                    "cachedblock" => QueryResult::CachedBlock,
                    _ => QueryResult::Local,
                },
                upstream_us: upstream_us as u32,
                cached: cached != 0,
                answer,
                protocol: match protocol.as_str() {
                    "udp" => lanforge_core::types::TransportProtocol::Udp,
                    "tcp" => lanforge_core::types::TransportProtocol::Tcp,
                    "dot" => lanforge_core::types::TransportProtocol::Tls,
                    "doq" => lanforge_core::types::TransportProtocol::Quic,
                    "doh" => lanforge_core::types::TransportProtocol::Https,
                    _ => lanforge_core::types::TransportProtocol::Udp,
                },
            });
        }
        Ok(entries)
    }

    /// Retrieves top domains by query count.
    pub async fn get_dns_top_domains(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, u64)>, LeaseDbError> {
        let rows = sqlx::query(
            "SELECT domain, COUNT(*) as count FROM dns_queries GROUP BY domain ORDER BY count DESC LIMIT ?"
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| (r.get("domain"), r.get::<i64, _>("count") as u64))
            .collect())
    }

    /// Retrieves query counts by type.
    pub async fn get_dns_query_types(&self) -> Result<Vec<(u16, u64)>, LeaseDbError> {
        let rows = sqlx::query(
            "SELECT qtype, COUNT(*) as count FROM dns_queries GROUP BY qtype ORDER BY count DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<i32, _>("qtype") as u16,
                    r.get::<i64, _>("count") as u64,
                )
            })
            .collect())
    }

    /// Retrieves query rate timeline (grouped by 30s buckets for the last 10 minutes).
    pub async fn get_dns_query_rate(
        &self,
        since_secs: u64,
    ) -> Result<Vec<(u64, u64)>, LeaseDbError> {
        let rows = sqlx::query(
            "SELECT (timestamp / 30) * 30 as bucket, COUNT(*) as count 
             FROM dns_queries 
             WHERE timestamp >= ? 
             GROUP BY bucket 
             ORDER BY bucket ASC",
        )
        .bind(since_secs as i64)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| {
                (
                    r.get::<i64, _>("bucket") as u64,
                    r.get::<i64, _>("count") as u64,
                )
            })
            .collect())
    }

    /// Retrieves top clients by query count.
    pub async fn get_dns_top_clients(
        &self,
        limit: usize,
    ) -> Result<Vec<(String, u64)>, LeaseDbError> {
        let rows = sqlx::query(
            "SELECT src_ip, COUNT(*) as count FROM dns_queries GROUP BY src_ip ORDER BY count DESC LIMIT ?"
        )
        .bind(limit as i64)
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| (r.get("src_ip"), r.get::<i64, _>("count") as u64))
            .collect())
    }

    /// Retrieves query counts by protocol.
    pub async fn get_dns_protocol_stats(&self) -> Result<Vec<(String, u64)>, LeaseDbError> {
        let rows = sqlx::query(
            "SELECT protocol, COUNT(*) as count FROM dns_queries GROUP BY protocol ORDER BY count DESC",
        )
        .fetch_all(&self.pool)
        .await?;

        Ok(rows
            .into_iter()
            .map(|r| (r.get("protocol"), r.get::<i64, _>("count") as u64))
            .collect())
    }

    /// Retrieves the most recent blocked DNS queries.
    #[cfg(feature = "adblock")]
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
    /// Streams the most recent system events.
    pub fn stream_history(
        &self,
        limit: usize,
    ) -> impl futures::Stream<Item = Result<TimedEvent, LeaseDbError>> + '_ {
        let limit = limit as i64;
        let query =
            sqlx::query("SELECT timestamp, event_json FROM system_logs ORDER BY id DESC LIMIT ?")
                .bind(limit);

        query.fetch(&self.pool).map(|res| {
            let row = res.map_err(|e| LeaseDbError::Internal(e.to_string()))?;
            let timestamp: i64 = row.get("timestamp");
            let event_json: String = row.get("event_json");

            let event: LanforgeEvent = serde_json::from_str(&event_json)
                .map_err(|e| LeaseDbError::Internal(format!("JSON error: {e}")))?;

            Ok(TimedEvent {
                timestamp: UNIX_EPOCH + Duration::from_secs(timestamp as u64),
                event,
            })
        })
    }

    /// Retrieves the most recent log entries.
    pub async fn get_history(&self, limit: usize) -> Result<Vec<TimedEvent>, LeaseDbError> {
        let mut stream = self.stream_history(limit);
        let mut entries = Vec::new();
        while let Some(res) = stream.next().await {
            entries.push(res?);
        }
        // Return in chronological order (oldest first for the UI)
        entries.reverse();
        Ok(entries)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use lanforge_core::types::DnsRecordType;
    use lanforge_core::types::QueryResult;
    use lanforge_core::types::TransportProtocol;

    #[tokio::test]
    async fn test_dns_log_protocol_tracking() {
        let db = LogDb::open("sqlite::memory:").await.unwrap();

        let entry = QueryLogEntry {
            timestamp: 123456789,
            src_ip: "192.168.1.10".parse().unwrap(),
            src_mac: Some("00:11:22:33:44:55".parse().unwrap()),
            domain: "example.com".into(),
            qtype: DnsRecordType::A,
            result: QueryResult::Forwarded,
            upstream_us: 15000,
            cached: false,
            answer: Some("1.2.3.4".to_string()),
            protocol: TransportProtocol::Tls,
        };

        db.record_dns_query(&entry).await.unwrap();

        // Check history
        let history = db.get_dns_query_history(10).await.unwrap();
        assert_eq!(history.len(), 1);
        assert_eq!(history[0].protocol, TransportProtocol::Tls);

        // Check stats
        let stats = db.get_dns_protocol_stats().await.unwrap();
        assert_eq!(stats.len(), 1);
        assert_eq!(stats[0].0, "dot");
        assert_eq!(stats[0].1, 1);
    }
}
