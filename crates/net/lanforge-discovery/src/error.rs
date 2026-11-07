//! Discovery error types for `lanforge-discovery`.

use std::io;
use thiserror::Error;

/// Errors that can occur in the Lanforge neighbor monitoring and discovery subsystem.
#[derive(Debug, Error)]
pub enum DiscoveryError {
    /// Standard I/O error.
    #[error("I/O failure: {0}")]
    Io(#[from] io::Error),

    /// Error from the `rtnetlink` subsystem.
    #[error("Netlink failure: {0}")]
    Netlink(#[from] rtnetlink::Error),

    /// Socket error.
    #[error("Socket error: {0}")]
    Socket(String),

    /// Generic networking error.
    #[error("Generic network failure: {0}")]
    Generic(String),

    /// No IPv6 Link-Local address found on the interface.
    #[error("Missing link-local address on interface {0}")]
    NoLinkLocal(u32),
}
