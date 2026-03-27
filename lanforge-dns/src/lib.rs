//! lanforge-dns — Servidor DNS autoritativo da LAN
//!
//! Responde A/AAAA/PTR para dispositivos conhecidos pelo Manager e encaminha
//! todo o resto para o Unbound (ou outro resolver upstream).

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
pub use server::dns_service;
