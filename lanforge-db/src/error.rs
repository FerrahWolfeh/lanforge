//! Error hierarchy for Lanforge database operations.
//!
//! Covers I/O failures, SQLite errors, migration failures, and maintenance errors.

use std::{io::Error, num::TryFromIntError, path::PathBuf};
use thiserror::Error;

/// Errors specific to the Lanforge lease database engine.
///
/// This enum covers all possible failures during persistence operations,
/// from file access to schema migration errors.
///
/// # Example
///
/// ```ignore
/// match LeaseDb::open(Path::new("/var/lib/lanforge/leases.db")) {
///     Ok(db) => { /* ready to use */ }
///     Err(LeaseDbError::ConnectionOpen(path, source)) => {
///         eprintln!("Could not open database at {}: {}", path.display(), source);
///     }
///     Err(LeaseDbError::Migration(step, detail)) => {
///         eprintln!("Migration failure ({step}): {detail}");
///     }
///     Err(e) => eprintln!("Database error: {e}"),
/// }
/// ```
#[derive(Debug, Error)]
pub enum LeaseDbError {
    /// Failed to access a file or directory path on disk.
    ///
    /// Occurs when the parent directory doesn't exist or lacks read/write permissions.
    #[error("I/O failure at {0}: {1}")]
    PathAccess(PathBuf, #[source] Error),

    /// Generic I/O error not associated with a specific path.
    #[error("Generic I/O failure: {0}")]
    Io(#[from] Error),

    /// Failed to open or create the database connection at the given path.
    ///
    /// May indicate a corrupted database file or insufficient permissions.
    #[error("Failed to connect to database at {0}: {1}")]
    ConnectionOpen(PathBuf, #[source] sqlx::Error),

    /// Low-level database execution error from `sqlx`.
    #[error("Database failure: {0}")]
    Sqlx(#[from] sqlx::Error),

    /// Failed during a schema migration or initial table creation.
    ///
    /// The first field describes the migration step, the second the error detail.
    #[error("Failed to execute migration '{0}': {1}")]
    Migration(String, String),

    /// A transactional operation failed during commit.
    #[error("Failed to commit database transaction: {0}")]
    TransactionFailed(#[source] sqlx::Error),

    /// Database optimization (VACUUM) failed.
    #[error("Failed to execute VACUUM: {0}")]
    VacuumFailed(#[source] sqlx::Error),

    /// A requested entity (e.g., a specific lease) was not found in the database.
    #[error("Entity not found: {0}")]
    NotFound(String),

    /// Migration version mismatch or schema integrity error.
    #[error("Database migration error: {0}")]
    MigrationIncompatibility(String),

    /// Value out of expected range during database deserialization.
    #[error("Invalid value for {0}: {1} (range: {2}..={3})")]
    RangeError(String, i64, i64, i64),

    /// Integer conversion failed during database deserialization.
    #[error("Invalid integer conversion: {0}")]
    IntConversion(#[from] TryFromIntError),

    /// Internal error (e.g., serialization failure).
    #[error("Internal database error: {0}")]
    Internal(String),

    /// A generic database error with a custom message.
    #[error("Database error: {0}")]
    Generic(String),
}
