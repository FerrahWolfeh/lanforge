//! # Lanforge `nftables` Firewall & Router Orchestrator
//!
//! Declarative management of `table inet lanforge`, providing host protection,
//! inter-zone routing policies, flowtable offloading, NAT masquerading,
//! and hairpin reflection.

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

pub mod ruleset;

pub use lanforge_types::events::firewall::*;
pub use lanforge_types::network::firewall::*;
pub use ruleset::RulesetBuilder;
