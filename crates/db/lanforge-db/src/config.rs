//! Configuration for the Lanforge database engine.

use serde::{Deserialize, Serialize};

/// Configuration for the database persistence layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    /// Connection URL (e.g., "<sqlite:///var/lib/lanforge/lanforge.db>").
    pub url: String,

    /// Transient log database URL (e.g., "<sqlite:///tmp/lanforge-logs.db>").
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
            url: "sqlite:///var/lib/lanforge/lanforge.db".to_string(),
            log_url: "sqlite:///tmp/lanforge-logs.db".to_string(),
            flush_interval: 60,
            max_connections: 10,
            min_connections: 2,
        }
    }
}
