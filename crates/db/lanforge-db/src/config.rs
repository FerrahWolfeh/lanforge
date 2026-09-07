//! Configuration for the Lanforge database engine.

use std::path::PathBuf;
use serde::{Deserialize, Serialize};

/// Configuration for the database persistence layer.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(default)]
pub struct DatabaseConfig {
    /// Persistent configuration database file path (e.g., "/var/lib/lanforge/config.redb").
    #[serde(alias = "path", alias = "url")]
    pub config_path: String,

    /// Volatile runtime database file path (e.g., "/run/lanforge/runtime.redb" or "/tmp/lanforge/runtime.redb").
    #[serde(alias = "runtime_db_path", alias = "log_path", alias = "log_url")]
    pub runtime_path: String,

    /// How often to flush in-memory state to the persistent database (seconds).
    pub flush_interval: u64,

    /// Maximum number of concurrent connections (kept for compatibility).
    pub max_connections: u32,

    /// Minimum number of idle connections (kept for compatibility).
    pub min_connections: u32,
}

impl DatabaseConfig {
    /// Returns true if an in-memory database mode was requested or specified for the config database.
    #[must_use]
    pub fn is_in_memory(&self) -> bool {
        let u = self.config_path.trim().to_lowercase();
        u.is_empty()
            || u == "memory"
            || u == "none"
            || u == "mock"
            || u.starts_with("mock:")
            || u.starts_with("sqlite:")
            || u.contains(":memory:")
    }

    /// Returns true if an in-memory mode was requested or specified for the runtime database.
    #[must_use]
    pub fn is_runtime_in_memory(&self) -> bool {
        let u = self.runtime_path.trim().to_lowercase();
        u.is_empty()
            || u == "memory"
            || u == "none"
            || u == "mock"
            || u.starts_with("mock:")
            || u.starts_with("sqlite:")
            || u.contains(":memory:")
    }

    /// Resolves the config redb file path.
    #[must_use]
    pub fn config_db_path(&self) -> PathBuf {
        let trimmed = self.config_path.trim();
        let path_str = trimmed
            .strip_prefix("redb://")
            .or_else(|| trimmed.strip_prefix("file://"))
            .unwrap_or(trimmed);
        PathBuf::from(path_str)
    }

    /// Resolves the runtime redb file path.
    #[must_use]
    pub fn runtime_db_path(&self) -> PathBuf {
        let trimmed = self.runtime_path.trim();
        let path_str = trimmed
            .strip_prefix("redb://")
            .or_else(|| trimmed.strip_prefix("file://"))
            .unwrap_or(trimmed);
        PathBuf::from(path_str)
    }

    /// Backwards compatibility accessor for `config_db_path`.
    #[must_use]
    pub fn db_path(&self) -> PathBuf {
        self.config_db_path()
    }

    /// Backwards compatibility accessor for `config_path`.
    #[must_use]
    pub fn path(&self) -> &str {
        &self.config_path
    }

    /// Backwards compatibility accessor for `runtime_path`.
    #[must_use]
    pub fn log_path(&self) -> &str {
        &self.runtime_path
    }

    /// Backwards compatibility accessor for `config_path`.
    #[must_use]
    pub fn url(&self) -> &str {
        &self.config_path
    }

    /// Backwards compatibility accessor for `runtime_path`.
    #[must_use]
    pub fn log_url(&self) -> &str {
        &self.runtime_path
    }
}

impl Default for DatabaseConfig {
    fn default() -> Self {
        let config_path = std::env::var("LANFORGE_CONFIG_DB_PATH")
            .or_else(|_| std::env::var("LANFORGE_DB_PATH"))
            .or_else(|_| std::env::var("DATABASE_URL"))
            .unwrap_or_else(|_| "/var/lib/lanforge/config.redb".to_string());
        let runtime_path = std::env::var("LANFORGE_RUNTIME_DB_PATH")
            .or_else(|_| std::env::var("LANFORGE_LOG_PATH"))
            .or_else(|_| std::env::var("LANFORGE_LOG_DB_URL"))
            .unwrap_or_else(|_| "/run/lanforge/runtime.redb".to_string());

        Self {
            config_path,
            runtime_path,
            flush_interval: 60,
            max_connections: 10,
            min_connections: 2,
        }
    }
}
