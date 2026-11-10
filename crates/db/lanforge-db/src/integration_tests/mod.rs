//! Integration tests: they drive the crate through its public entry points like an outside
//! user would, but live in the lib's test build so `cargo test` links one binary per crate.
//! Add new test files as modules here, never as new `tests/*.rs` files.

mod worker_lifecycle;
