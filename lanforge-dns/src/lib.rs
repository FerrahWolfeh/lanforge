//! # Lanforge DNS — High-Performance Authoritative LAN DNS Server
//!
//! A custom DNS server optimized for ultra-low latency on local network queries.
//! Features a **zero-allocation wire parser** for hot-path routing (A/AAAA/PTR),
//! with a full-featured Hickory-DNS fallback for complex queries. All non-local
//! requests are forwarded to an upstream resolver.
//!
//! ## Architecture
//!
//! The DNS server uses a **triage model** with three resolution phases:
//!
//! ```text
//! Inbound Query (4096 bytes)
//!   ├── Phase 1: Zero-Alloc Triage (WireHeader + WireQuestion)
//!   │     ├── Simple name? → Phase 2: Local Resolution
//!   │     └── Complex (pointers/CNAME)? → Fallback: Full Hickory parse
//!   ├── Phase 2: Local Resolution (LanforgeContext lookup)
//!   │     ├── A/AAAA/ANY → resolve_ip()
//!   │     └── PTR        → resolve_ptr() (reverse DNS)
//!   └── Phase 3: Recursive Forwarding (UpstreamManager)
//!         ├── UDP with 3s timeout
//!         └── TCP fallback on truncation (RFC 1035)
//! ```
//!
//! ## Key Design Decisions
//!
//! | Feature | Rationale |
//! | :--- | :--- |
//! | **Zero-alloc wire parser** | Avoids UTF-8 validation and heap allocation for 99% of LAN queries |
//! | **Moka sync cache** | Synchronous cache with O(1) TTL expiry — no `.await` overhead in hot path |
//! | **`DnsContext` (Arc)** | Single shared context replaces individual `Arc` clones per query |
//! | **`ResponseBuilder`** | Constructs responses via Hickory-DNS `Message` for correctness |
//! | **EDNS preservation** | Copies extension data from query to response for compatibility |
//!
//! ## Hot-Path Flow
//!
//! 1. `WireHeader::parse(data)` — validates header (12 bytes, zero alloc)
//! 2. `WireQuestion::parse(data)` — extracts QNAME, QTYPE, QCLASS (may fallback if pointers found)
//! 3. `extract_local_hostname_wire()` — matches hostname against `multi_search_labels`
//! 4. `LocalResolver::resolve_ip()` — looks up device in `LanforgeContext`, builds records
//! 5. Response serialized via Hickory-DNS `Message::to_bytes()`
//!
//! ## Modules
//!
//! | Module | Responsibility |
//! | :--- | :--- |
//! | [`server`] | `DnsService` — UDP/TCP listeners, `handle_query` triage, shutdown |
//! | [`resolver`] | `LocalResolver` — A/AAAA/PTR resolution from `LanforgeContext` |
//! | [`response`] | `ResponseBuilder` — constructs DNS response messages |
//! | [`upstream`] | `UpstreamManager` — UDP forwarding with TCP fallback, Moka cache |
//! | [`cache`] | `DnsCache` — synchronous upstream response cache with TTL-based expiry |
//! | [`wire`] | Zero-allocation DNS wire parser (`WireHeader`, `WireQuestion`, `WireLabelIter`) |
//! | [`utils`] | ARPA parsing, hostname extraction, prefix/suffix combining |
//! | [`stats`] | `DnsStats` — atomic counters for requests, cache hits, auth queries, etc. |
//! | [`config`] | `DnsConfig` — listen address, upstream, search domain, prefixes |
//! | [`error`] | `DnsError` — I/O, protocol, wire parse, timeout errors |

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

pub mod cache;
pub mod config;
#[cfg(feature = "dot")]
pub mod dot;
#[cfg(feature = "doh-upstream")]
pub mod doh;
pub mod error;
#[cfg(feature = "adblock")]
pub mod filter;
pub mod health;
pub mod query_log;
pub mod resolver;
pub mod response;
pub mod server;
pub mod stats;
pub mod strategy;
#[cfg(feature = "dot")]
pub mod tls_utils;
pub mod upstream;
pub mod utils;
pub mod wire;

#[cfg(feature = "doq")]
pub mod doq;

#[cfg(test)]
mod tests;
#[cfg(test)]
mod io_tests;

// Re-exports for convenience and compatibility
pub use config::{BlockingMode, DnsConfig, PrioritizedUpstream, RewriteAnswer};
#[cfg(feature = "doq")]
pub use doq::DoqService;
#[cfg(feature = "dot")]
pub use dot::DotService;
pub use error::DnsError;
pub use server::DnsService;
