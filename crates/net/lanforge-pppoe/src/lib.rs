//! # Lanforge `PPPoE` Orchestrator
//!
//! Clean-room implementation of `PPPoE` discovery + PPP negotiation in userspace
//! with data-path handoff to the Linux kernel `ppp_generic` driver.

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

pub mod auth;
pub mod config;
pub mod discovery;
#[cfg(feature = "ebpf")]
pub mod ebpf;
pub mod error;
pub mod ipcp;
pub mod keepalive;
pub mod kernel;
pub mod lcp;
pub mod service;
pub mod session;

pub use config::{AuthMethod, PppoeConfig, PppoeCredentials};
pub use error::PppoeError;
pub use service::PppoeService;
