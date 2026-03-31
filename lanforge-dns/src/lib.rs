//! `lanforge-dns` — High-performance authoritative LAN DNS server.
//!
//! Features a custom zero-allocation wire parser for internal routing and
//! local resolution (A/AAAA/PTR), with a full-featured fallback to Hickory-DNS
//! for complex queries. Forwards all non-local requests to an upstream resolver.

pub mod cache;
pub mod config;
pub mod error;
pub mod resolver;
pub mod response;
pub mod server;
pub mod upstream;
pub mod utils;
pub mod wire;

#[cfg(test)]
mod tests;

// Re-exports para conveniência e compatibilidade
pub use config::DnsConfig;
pub use error::DnsError;
pub use server::DnsService;
