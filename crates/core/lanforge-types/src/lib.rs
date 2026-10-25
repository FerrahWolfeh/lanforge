//! Core data structures and shared types for Lanforge.
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
pub mod auth;
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

pub use config::{ChangeImpact, ConfigDomain, ConfigSection, DnsAllowlist, DnsListenConfig, DomainSet};
