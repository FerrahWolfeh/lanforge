use std::io;
use thiserror::Error;

/// Specific error types for the Lanforge network subsystem.
#[derive(Debug, Error)]
pub enum NetworkError {
    /// Standard I/O error.
    #[error("I/O failure: {0}")]
    Io(#[from] io::Error),

    /// Error originating from the `rtnetlink` subsystem.
    #[error("Netlink failure: {0}")]
    Netlink(#[from] rtnetlink::Error),

    /// Invalid configuration for a networking protocol.
    #[error("Invalid network configuration: {0}")]
    Config(String),

    /// Failed to create or configure a UDP/TCP socket.
    #[error("Socket creation/config failure: {0}")]
    Socket(String),

    /// Error related to raw `AF_PACKET` sockets (used for RA/SLAAC).
    #[error("AF_PACKET raw socket error: {0}")]
    RawSocket(String),

    /// Generic networking error.
    #[error("Generic network failure: {0}")]
    Generic(String),

    /// The specified network interface could not be found or is invalid.
    #[error("Interface '{0}' not found or invalid")]
    InterfaceNotFound(String),

    /// Invalid or missing MAC address where one was expected.
    #[error("Invalid or missing MAC address: {0}")]
    InvalidMac(String),

    /// No IPv6 Link-Local address (`fe80::`) found on the interface.
    #[error("Missing link-local address on interface {0}")]
    NoLinkLocal(u32),

    /// mDNS protocol or packet failure.
    #[error("mDNS failure: {0}")]
    Mdns(String),
}

/// A specialized Result type for network operations.
pub type Result<T> = std::result::Result<T, NetworkError>;
