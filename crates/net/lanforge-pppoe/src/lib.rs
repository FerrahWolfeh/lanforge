//! # Lanforge `PPPoE` Orchestrator
//!
//! Clean-room implementation of `PPPoE` discovery + PPP negotiation in userspace
//! with data-path handoff to the Linux kernel `ppp_generic` driver.

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

pub mod auth;
pub mod backoff;
pub mod config;
pub mod discovery;
pub mod error;
pub mod handoff;
pub mod host;
pub mod ipcp;
pub mod keepalive;
pub mod kernel;
pub mod lcp;
pub mod service;
pub mod session;
mod wan_dns;

pub use config::{AuthMethod, PppoeConfig, PppoeCredentials};
pub use error::PppoeError;
pub use host::{KernelHost, PppoeHost};
pub use lanforge_transport::PppoeTransport;
pub use service::PppoeService;

#[cfg(test)]
#[allow(
    clippy::pedantic,
    clippy::nursery,
    reason = "integration tests keep the workspace lint level they had as a test crate"
)]
mod integration_tests;
