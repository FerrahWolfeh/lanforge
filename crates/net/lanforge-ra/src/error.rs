//! Network error types for `lanforge-ra`.

use std::io;
use thiserror::Error;

/// Errors that can occur in the Lanforge Router Advertisement subsystem.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// Standard I/O error.
    #[error("I/O failure: {0}")]
    Io(#[from] io::Error),

    /// Socket error.
    #[error("Socket error: {0}")]
    Socket(String),

    /// Configuration error.
    #[error("Configuration error: {0}")]
    Config(String),

    /// Generic networking error.
    #[error("Generic network failure: {0}")]
    Generic(String),

    /// Invalid MAC address.
    #[error("Invalid MAC address: {0}")]
    InvalidMac(String),

    /// No IPv6 Link-Local address found on the interface.
    #[error("Missing link-local address on interface {0}")]
    NoLinkLocal(u32),
}
