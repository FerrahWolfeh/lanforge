//! Integration tests, linked into one binary: every `tests/*.rs` file used to be its own
//! executable linking the whole dependency graph. Add new test files as modules here.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    reason = "test assertions and setup"
)]
#![allow(
    unused_crate_dependencies,
    reason = "integration test crates see every dev-dependency"
)]

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
