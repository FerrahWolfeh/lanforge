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

mod config_patch_acceptance;
#[cfg(feature = "uds")]
mod db_reset;
#[cfg(feature = "dhcp")]
mod dhcp_core_consistency;
#[cfg(all(feature = "dhcp", feature = "nft", feature = "ra", feature = "traffic"))]
mod eventbus_reactivity;
mod phase2_service_contract;
mod phase3_graph_supervisor;
mod phase4_wan_acceptance;
mod readiness_race;
#[cfg(all(feature = "dhcp", feature = "nft", feature = "ra", feature = "traffic"))]
mod rootless_pipeline;
