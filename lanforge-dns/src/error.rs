use thiserror::Error;

/// Specific error types for the Lanforge DNS server.
#[derive(Debug, Error)]
pub enum DnsError {
    /// Standard I/O error.
    #[error("I/O failure: {0}")]
    Io(#[from] std::io::Error),

    /// Error originating from the DNS protocol logic (Hickory-DNS).
    #[error("DNS Protocol failure: {0}")]
    Protocol(#[from] hickory_proto::ProtoError),

    /// Failed to decode a UDP DNS message.
    #[error("Corrupt UDP response: {0}")]
    UdpDecode(String),

    /// Failed to encode a UDP DNS response.
    #[error("Failed to encode UDP response: {0}")]
    UdpEncode(String),

    /// Failed to decode a TCP DNS message.
    #[error("Corrupt TCP response: {0}")]
    TcpDecode(String),

    /// Failed to encode a TCP DNS response.
    #[error("Failed to encode TCP response: {0}")]
    TcpEncode(String),

    /// Timed out while waiting for a response from the upstream resolver.
    #[error("Timeout waiting for upstream response")]
    UpstreamTimeout,

    /// The response channel was closed prematurely.
    #[error("Response channel closed prematurely")]
    ChannelClosed,

    /// Failed to bind to the specified UDP or TCP socket.
    #[error("Failed to bind {0} socket: {1}")]
    BindError(&'static str, #[source] std::io::Error),

    /// Failed to parse the DNS message using the custom zero-allocation wire parser.
    #[error("Zero-alloc wire parser failure")]
    WireParseError,
}
