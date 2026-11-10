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

mod api_tests;
mod banners;
mod dispatch;
mod reload;
