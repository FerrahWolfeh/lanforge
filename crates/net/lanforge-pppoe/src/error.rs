use std::os::fd::OwnedFd;

use thiserror::Error;
use tokio::io::unix::AsyncFdRegisterError;

#[derive(Debug, Error)]
pub enum PppoeError {
    #[error("ppp_generic interface device /dev/ppp is not available")]
    DevPppUnavailable,

    #[error("PPPoE discovery timed out or failed")]
    DiscoveryTimeout,

    #[error("PPPoE negotiation failed: {0}")]
    NegotiationFailed(String),

    #[error("PPP LCP negotiation failed: {0}")]
    LcpFailed(String),

    /// The peer explicitly rejected the credentials (PAP Auth-Nak, CHAP Failure).
    #[error("PPP Authentication failed: {0}")]
    AuthFailed(String),

    /// The peer did not answer in time: a busy or rate-limiting concentrator, not bad credentials.
    #[error("PPP Authentication timed out: {0}")]
    AuthTimeout(String),

    #[error("PPP IPCP negotiation failed: {0}")]
    IpcpFailed(String),

    #[error("PPP IPv6CP negotiation failed: {0}")]
    Ipv6cpFailed(String),

    #[error("Kernel PPP handoff failed: {0}")]
    KernelHandoffFailed(String),

    #[error("LCP Echo keepalive timeout")]
    KeepAliveTimeout,

    #[error("PPPoE session terminated remotely: {0}")]
    Terminated(String),

    #[error("No carrier on {0}")]
    CarrierDown(String),

    #[error("Terminal {0} unreachable on {1}")]
    TerminalUnreachable(std::net::Ipv4Addr, String),

    #[error("I/O error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Nix error: {0}")]
    Nix(#[from] nix::errno::Errno),

    #[error("AsyncFd registration error: {0}")]
    Fd(#[from] AsyncFdRegisterError<OwnedFd>),
}
