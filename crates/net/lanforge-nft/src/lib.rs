#![forbid(unsafe_code)]
//! # Lanforge `nftables` Firewall & Router Orchestrator
//!
//! Declarative management of `table inet lanforge`, providing host protection,
//! inter-zone routing policies, flowtable offloading, NAT masquerading,
//! and hairpin reflection.

#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

pub mod applier;
pub mod ruleset;
pub mod service;

#[cfg(any(test, feature = "inert"))]
pub use applier::RecordingNft;
pub use applier::{KernelNft, NftApplier};
pub use lanforge_types::events::firewall::*;
pub use lanforge_types::network::firewall::*;
pub use ruleset::RulesetBuilder;
pub use service::NftService;
