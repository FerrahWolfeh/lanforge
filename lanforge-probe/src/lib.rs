//! # Lanforge Network Probes
//!
//! Active and passive discovery probers for Lanforge (mDNS, LLDP).
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

pub mod error;
pub mod lldp;
pub mod mdns;
