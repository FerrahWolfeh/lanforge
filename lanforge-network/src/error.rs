//! Network error types for `lanforge-network`.
//!
//! Covers all failure modes across the networking stack: I/O, netlink communication,
//! socket creation, raw packet injection, mDNS protocol errors, and configuration issues.

use std::io;
use thiserror::Error;

/// Errors that can occur in the Lanforge network subsystem.
///
/// # Example
///
/// ```
/// use lanforge_network::error::NetworkError;
///
/// // Pattern match on specific error types
/// fn handle_error(err: NetworkError) {
///     match err {
///         NetworkError::InterfaceNotFound(iface) => {
///             eprintln!("Interface '{iface}' not found");
///         }
///         NetworkError::Io(io_err) => {
///             eprintln!("I/O error: {io_err}");
///         }
///         _ => eprintln!("Other network error: {err}"),
///     }
/// }
/// ```
#[derive(Debug, Error)]
pub enum NetworkError {
    /// Standard I/O error (e.g., socket read/write failure).
    #[error("I/O failure: {0}")]
    Io(#[from] io::Error),

    /// Error from the `rtnetlink` subsystem (interface/address queries, neighbor events).
    #[error("Netlink failure: {0}")]
    Netlink(#[from] rtnetlink::Error),

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

    /// No IPv6 Link-Local address (`fe80::/10`) found on the interface.
    /// Required for RA and NDP operations.
    #[error("Missing link-local address on interface {0}")]
    NoLinkLocal(u32),

    /// mDNS protocol error (packet parsing, socket setup, or name resolution).
    #[error("mDNS failure: {0}")]
    Mdns(String),
}
