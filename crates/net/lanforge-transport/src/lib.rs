//! High-performance foundational transport layer for Lanforge.
//!
//! Provides:
//! - **Y-Shaped Dual-Stack UDP Transport** (`UdpTransport`): Concurrent native IPv4 and IPv6 sockets with automatic outbound routing.
//! - **Y-Shaped Dual-Stack TCP Listener** (`DualTcpListener`): Concurrent native IPv4 and IPv6 listener for WebUI/HTTP.
//! - **Specialized ICMPv6 Transport** (`Icmp6Transport`): Raw socket with `ICMP6_FILTER` and hop limit validation.
//! - **Rootless Inert Testing** (`InertHandle`): In-memory synthetic datagram and reply channels for sudo-free tests.
//! - **Transparent Metrics & Rate Limiting** (`TransportMetrics`, `RateLimiter`): Zero-overhead counters and bounded token buckets.

pub mod arp;
pub mod icmp;
pub mod icmp6;
pub mod inert;
pub mod limiter;
pub mod metrics;
pub mod pppoe;
pub mod tcp;
pub mod udp;
pub mod wol;

pub use arp::{ArpProber, ArpReply};
pub use icmp::{IcmpPinger, parse_icmpv4_echo_reply, parse_icmpv6_echo_reply};
pub use icmp6::Icmp6Transport;
pub use inert::InertHandle;
pub use limiter::{RateLimitConfig, RateLimiter};
pub use metrics::{TransportMetrics, TransportSnapshot, TransportStats};
pub use pppoe::{PppoeInertHandle, PppoeTransport};
pub use tcp::DualTcpListener;
pub use udp::UdpTransport;
pub use wol::{build_magic_packet, send_wol_magic_packet};
