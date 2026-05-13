//! Lanforge DNS Server
//!
//! A high-performance, modular DNS server for local network orchestration.
//! Features zero-allocation wire parsing, ad-blocking, and recursive forwarding.

pub mod config;
pub mod error;
pub mod pipeline;
pub mod resolver;
pub mod server;
pub mod telemetry;
pub mod utils;
pub mod wire;

// Re-exports for convenience
pub use config::{BlockingMode, DnsConfig, UpstreamEntry};
pub use error::DnsError;
pub use resolver::LocalResolver;
pub use resolver::filter::AdBlocker;
pub use resolver::recursive::UpstreamManager;
pub use server::DnsContext;
pub use server::service::DnsService;

#[cfg(feature = "doq")]
pub use server::transport::doq::DoqService;
#[cfg(feature = "dot")]
pub use server::transport::dot::DotService;
