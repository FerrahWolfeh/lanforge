//! Integration tests: they drive the crate through its public entry points like an outside
//! user would, but live in the lib's test build so `cargo test` links one binary per crate.
//! Add new test files as modules here, never as new `tests/*.rs` files.

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
