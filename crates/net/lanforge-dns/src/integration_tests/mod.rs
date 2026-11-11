//! Integration tests: they drive the crate through its public entry points like an outside
//! user would, but live in the lib's test build so `cargo test` links one binary per crate.
//! Add new test files as modules here, never as new `tests/*.rs` files.

mod common;

mod adblock;
mod adblock_fallback;
mod adblock_live;
mod adblock_manual_rules;
mod adblock_restart;
mod adblock_retry;
mod adblock_toggle;
mod banner_transport;
mod cache_telemetry;
mod coalescing;
mod condition;
mod doq_listener;
mod dot_listener;
mod hedging;
mod isp_upstreams;
mod junk_names;
mod parsing;
mod pipeline;
mod reload;
mod resolution;
mod restart_counters;
mod rewrite_semantics;
mod rewrites;
mod shielding;
mod simulation;
mod site_zone;
mod state;
mod tcp_rebind;
mod upstream_accounting;
mod upstream_mode;
