use std::path::PathBuf;
use thiserror::Error;

/// Specific error types for the Lanforge database engine.
#[derive(Debug, Error)]
pub enum LeaseDbError {
    /// Failed to access the database file or directory on disk.
    #[error("I/O failure at {0}: {1}")]
    PathAccess(PathBuf, #[source] std::io::Error),

    /// Generic I/O error not directly tied to a specific path.
    #[error("Generic I/O failure: {0}")]
    Io(#[from] std::io::Error),

    /// Failed to open or create the SQLite connection at the specified path.
    #[error("Failed to open SQLite at {0}: {1}")]
    ConnectionOpen(PathBuf, #[source] rusqlite::Error),

    /// Low-level SQLite execution error.
    #[error("SQLite database failure: {0}")]
    Sqlite(#[from] rusqlite::Error),

    /// Failed during a schema migration or initial table creation.
    #[error("Failed to execute migration/statute {0}: {1}")]
    Migration(String, #[source] rusqlite::Error),

    /// A transactional operation failed to commit.
    #[error("Failed to commit transaction: {0}")]
    TransactionFailed(#[source] rusqlite::Error),

    /// Database optimization (VACUUM) failed.
    #[error("Failed to execute VACUUM: {0}")]
    VacuumFailed(#[source] rusqlite::Error),

    /// A requested entity (e.g., a specific lease) was not found in the database.
    #[error("Entity not found: {0}")]
    NotFound(String),
}
