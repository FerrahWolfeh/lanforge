//! Network error types for `lanforge-dhcp`.
//!
//! Covers failure modes across the DHCP stack: I/O, socket creation,
//! raw packet injection, and configuration issues.

use std::io;
use thiserror::Error;

/// Errors that can occur in the Lanforge DHCP subsystem.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// Standard I/O error (e.g., socket read/write failure).
    #[error("I/O failure: {0}")]
    Io(#[from] io::Error),

    /// Invalid or incompatible configuration for a networking protocol.
    #[error("Invalid network configuration: {0}")]
    Config(String),

    /// Failed to create or configure a UDP/TCP socket.
    #[error("Socket creation/config failure: {0}")]
    Socket(String),

    /// Error related to raw `AF_PACKET` sockets (used for L2 packet injection in `DHCPv4`).
    #[error("AF_PACKET raw socket error: {0}")]
    RawSocket(String),

    /// Generic networking error without a more specific category.
    #[error("Generic network failure: {0}")]
    Generic(String),

    /// The specified network interface could not be found or is invalid.
    #[error("Interface '{0}' not found or invalid")]
    InterfaceNotFound(String),

    /// Invalid or missing MAC address where one was expected.
    #[error("Invalid or missing MAC address: {0}")]
    InvalidMac(String),
}
