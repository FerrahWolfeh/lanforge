//! Network error types for `lanforge-wol`.

use std::io;
use thiserror::Error;

/// Errors that can occur in the Lanforge Wake-on-LAN subsystem.
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

    /// Invalid MAC address.
    #[error("Invalid MAC address: {0}")]
    InvalidMac(String),
}
