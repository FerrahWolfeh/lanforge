//! Network error types for `lanforge-probe`.

use std::io;
use thiserror::Error;

/// Errors that can occur in the Lanforge network probing subsystem.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// Standard I/O error.
    #[error("I/O failure: {0}")]
    Io(#[from] io::Error),

    /// Socket error.
    #[error("Socket error: {0}")]
    Socket(String),

    /// Generic networking error.
    #[error("Generic network failure: {0}")]
    Generic(String),
}
