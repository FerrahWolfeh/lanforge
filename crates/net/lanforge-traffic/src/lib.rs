//! # Lanforge Traffic & NIC Orchestrator
//!
//! High-performance network interface hardware optimization, RPS/RFS/XPS packet steering,
//! and CAKE Smart Queue Management (SQM) for bufferbloat mitigation.

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

pub mod service;
pub mod sqm;
pub mod tuning;

pub use lanforge_types::events::traffic::*;
pub use lanforge_types::network::traffic::*;
pub use service::TrafficService;
