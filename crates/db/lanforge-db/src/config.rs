//! Configuration for the Lanforge database engine.

use std::path::PathBuf;
use serde::{Deserialize, Serialize};

/// Configuration for the database persistence layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    /// Database path or URL (e.g., "/var/lib/lanforge/lanforge.redb" or "memory").
    pub url: String,

    /// Transient log database URL / file path (e.g., "/tmp/lanforge-logs.jsonl").
    pub log_url: String,

    /// How often to flush in-memory state to the persistent database (seconds).
    pub flush_interval: u64,

    /// Maximum number of concurrent connections (kept for compatibility).
    pub max_connections: u32,

    /// Minimum number of idle connections (kept for compatibility).
    pub min_connections: u32,
}

impl DatabaseConfig {
    /// Returns true if an in-memory database mode was requested or specified.
    #[must_use]
    pub fn is_in_memory(&self) -> bool {
        let u = self.url.trim().to_lowercase();
        u.is_empty()
            || u == "memory"
            || u == "none"
            || u == "mock"
            || u.starts_with("mock:")
            || u.starts_with("sqlite:")
            || u.contains(":memory:")
    }

    /// Resolves the redb file path.
    #[must_use]
    pub fn db_path(&self) -> PathBuf {
        let trimmed = self.url.trim();
        let path_str = trimmed
            .strip_prefix("redb://")
            .or_else(|| trimmed.strip_prefix("file://"))
            .unwrap_or(trimmed);
        PathBuf::from(path_str)
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "/var/lib/lanforge/lanforge.redb".to_string()),
            log_url: "/tmp/lanforge-logs.jsonl".to_string(),
            flush_interval: 60,
            max_connections: 10,
            min_connections: 2,
        }
    }
}
