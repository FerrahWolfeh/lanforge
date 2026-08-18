//! Configuration for the Lanforge database engine.

use serde::{Deserialize, Serialize};

/// Configuration for the database persistence layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    /// Connection URL (e.g., "<postgres://lanforge:lanforge@localhost:5432/lanforge>").
    pub url: String,

    /// Transient log database URL / file path (e.g., "/tmp/lanforge-logs.jsonl").
    pub log_url: String,

    /// How often to flush in-memory state to the persistent database (seconds).
    pub flush_interval: u64,

    /// Maximum number of concurrent connections (`PostgreSQL` only).
    pub max_connections: u32,

    /// Minimum number of idle connections (`PostgreSQL` only).
    pub min_connections: u32,
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        Self {
            url: std::env::var("DATABASE_URL")
                .unwrap_or_else(|_| "postgres://lanforge:lanforge@localhost:5432/lanforge".to_string()),
            log_url: "/tmp/lanforge-logs.jsonl".to_string(),
            flush_interval: 60,
            max_connections: 10,
            min_connections: 2,
        }
    }
}
