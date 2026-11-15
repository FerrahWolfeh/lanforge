#![forbid(unsafe_code)]
//! # Lanforge Discovery Service
//!
//! Unified neighbor discovery, mDNS prober, and active ICMP ping engine.
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

pub mod error;
pub mod interface;
pub mod mdns;
pub mod ndp;
pub mod ping;

#[cfg(test)]
mod integration_tests;

pub use interface::refresh_interface;
