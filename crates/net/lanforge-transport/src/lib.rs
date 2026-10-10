//! High-performance foundational transport layer for Lanforge.
//!
//! Provides:
//! - **Y-Shaped Dual-Stack UDP Transport** (`UdpTransport`): Concurrent native IPv4 and IPv6 sockets with automatic outbound routing.
//! - **Y-Shaped Dual-Stack TCP Listener** (`DualTcpListener`): Concurrent native IPv4 and IPv6 listener for WebUI/HTTP.
//! - **Specialized ICMPv6 Transport** (`Icmp6Transport`): Raw socket with `ICMP6_FILTER` and hop limit validation.
//! - **Rootless Inert Testing** (`InertHandle`): In-memory synthetic datagram and reply channels for sudo-free tests.
//! - **Transparent Metrics & Rate Limiting** (`TransportMetrics`, `RateLimiter`): Zero-overhead counters and bounded token buckets.

pub mod icmp6;
pub mod inert;
pub mod limiter;
pub mod metrics;
pub mod tcp;
pub mod udp;

pub use icmp6::Icmp6Transport;
pub use inert::InertHandle;
pub use limiter::{RateLimitConfig, RateLimiter};
pub use metrics::TransportMetrics;
pub use tcp::DualTcpListener;
pub use udp::UdpTransport;
