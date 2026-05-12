//! Error hierarchy for DNS server operations.

use thiserror::Error;

/// Errors that can occur during DNS server operation.
///
/// Covers I/O failures, protocol errors, wire parsing failures,
/// upstream forwarding errors, and binding errors.
#[derive(Debug, Error)]
pub enum DnsError {
    /// Standard I/O error from socket operations.
    #[error("I/O failure: {0}")]
    Io(#[from] std::io::Error),

    /// Failed to decode a UDP DNS response message.
    #[error("Corrupt UDP response: {0}")]
    UdpDecode(String),

    /// Failed to encode a UDP DNS response message.
    #[error("Failed to encode UDP response: {0}")]
    UdpEncode(String),

    /// Failed to decode a TCP DNS response message.
    #[error("Corrupt TCP response: {0}")]
    TcpDecode(String),

    /// Failed to encode a TCP DNS response message.
    #[error("Failed to encode TCP response: {0}")]
    TcpEncode(String),

    /// Timed out while waiting for a response from the upstream resolver.
    #[error("Timeout waiting for upstream response")]
    UpstreamTimeout,

    /// The response channel (oneshot) was closed prematurely.
    #[error("Response channel closed prematurely")]
    ChannelClosed,

    /// Failed to bind the UDP or TCP socket.
    #[error("Failed to bind {0} socket: {1}")]
    BindError(&'static str, #[source] std::io::Error),

    /// Failed to parse a DNS message using the zero-allocation wire parser.
    /// The message may be truncated, malformed, or contain unsupported features.
    #[error("Zero-alloc wire parser failure")]
    WireParseError,

    /// The request was refused (e.g. no upstreams configured).
    #[error("DNS request refused")]
    Refused,

    /// TLS configuration or handshake error.
    #[error("TLS error: {0}")]
    Tls(String),

    /// A generic or internal error.
    #[error("Generic error: {0}")]
    Generic(String),

    /// TLS PEM parsing error.
    #[cfg(feature = "dot")]
    #[error("TLS PEM parsing error: {0}")]
    TlsPem(#[from] rustls_pki_types::pem::Error),
}
