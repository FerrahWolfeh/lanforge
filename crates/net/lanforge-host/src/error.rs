//! Network error types for `lanforge-host`.

use std::io;
use thiserror::Error;

/// Errors that can occur in the Lanforge host monitoring subsystem.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// Standard I/O error.
    #[error("I/O failure: {0}")]
    Io(#[from] io::Error),

    /// Error from the `rtnetlink` subsystem.
    #[error("Netlink failure: {0}")]
    Netlink(#[from] rtnetlink::Error),

    /// Generic networking error.
    #[error("Generic network failure: {0}")]
    Generic(String),

    /// The specified network interface could not be found.
    #[error("Interface '{0}' not found or invalid")]
    InterfaceNotFound(String),
}
