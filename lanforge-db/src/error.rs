use std::{io::Error, path::PathBuf};
use thiserror::Error;

/// Specific error types for the Lanforge database engine.
#[derive(Debug, Error)]
pub enum LeaseDbError {
    /// Failed to access the database file or directory on disk.
    #[error("I/O failure at {0}: {1}")]
    PathAccess(PathBuf, #[source] Error),

    /// Generic I/O error not directly tied to a specific path.
    #[error("Generic I/O failure: {0}")]
    Io(#[from] Error),

    /// Failed to open or create the SQLite connection at the specified path.
    #[error("Failed to open SQLite at {0}: {1}")]
    ConnectionOpen(PathBuf, #[source] rusqlite::Error),

    /// Low-level SQLite execution error.
    #[error("SQLite database failure: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// Failed during a schema migration or initial table creation.
    #[error("Failed to execute migration '{0}': {1}")]
    Migration(String, String),

    /// A transactional operation failed to commit.
    #[error("Failed to commit database transaction: {0}")]
    TransactionFailed(#[source] rusqlite::Error),

    /// Database optimization (VACUUM) failed.
    #[error("Failed to execute VACUUM: {0}")]
    VacuumFailed(#[source] rusqlite::Error),

    /// A requested entity (e.g., a specific lease) was not found in the database.
    #[error("Entity not found: {0}")]
    NotFound(String),

    /// Migration version mismatch or integrity error.
    #[error("Database migration error: {0}")]
    MigrationIncompatibility(String),
}
