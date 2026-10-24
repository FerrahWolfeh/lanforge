//! # Lanforge Traffic & NIC Orchestrator
//!
//! High-performance network interface hardware optimization, RPS/RFS/XPS packet steering,
//! and CAKE Smart Queue Management (SQM) for bufferbloat mitigation.

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

pub mod collector;
pub mod service;
pub mod sqm;
pub mod tuning;

pub use collector::{
    collect_traffic_telemetry, get_traffic_history_snapshot, record_traffic_telemetry_tick,
    restore_traffic_history,
};
pub use lanforge_types::events::traffic::*;
pub use lanforge_types::network::traffic::*;
pub use service::TrafficService;
