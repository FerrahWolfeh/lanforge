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
