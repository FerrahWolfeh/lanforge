//! Integration tests: they drive the crate through its public entry points like an outside
//! user would, but live in the lib's test build so `cargo test` links one binary per crate.
//! Add new test files as modules here, never as new `tests/*.rs` files.

mod api_tests;
mod banners;
mod dispatch;
#[cfg(feature = "adblock")]
mod error_kinds_adblock;
mod error_kinds_auth;
mod error_kinds_control;
mod error_kinds_inspect;
mod error_kinds_query;
mod error_kinds_rewrite;
mod error_kinds_setup;
mod error_kinds_stats;
mod log_level;
mod reload;
mod stop_impact;
