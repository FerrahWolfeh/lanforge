#![forbid(unsafe_code)]
#![warn(clippy::missing_errors_doc)]
pub mod api;
pub mod config_file;
pub mod rpc;

/// HTTP response header carrying the daemon's build token on every API answer.
pub const BUILD_HEADER: &str = "x-lanforge-build";

#[cfg(test)]
mod integration_tests;
