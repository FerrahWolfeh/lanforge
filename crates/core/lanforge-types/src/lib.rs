#![forbid(unsafe_code)]
//! Core data structures and shared types for Lanforge.
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
pub mod auth;
pub mod build;
pub mod config;
pub mod device;
pub mod dhcp;
pub mod events;
pub mod identifiers;
pub mod network;
pub mod storage;
pub mod system;
pub mod update;
pub mod utils;

pub use config::{
    AdblockRules, ChangeImpact, ConfigDomain, ConfigSection, DnsListenConfig, DomainSet,
};
pub use network::{InterfaceSnapshot, Ipv6Net, LinkInfo, WanSnapshot, WanState};
pub use system::{
    DegradedReason, DormantReason, ServiceBanner, ServiceId, ServiceState, StateDetail,
};

#[cfg(test)]
#[allow(
    clippy::pedantic,
    clippy::nursery,
    reason = "integration tests keep the workspace lint level they had as a test crate"
)]
mod integration_tests;
