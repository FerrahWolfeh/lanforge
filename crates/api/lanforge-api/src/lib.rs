#![forbid(unsafe_code)]
pub mod api;
pub mod config_file;
pub mod rpc;

/// HTTP response header carrying the daemon's build token on every API answer.
pub const BUILD_HEADER: &str = "x-lanforge-build";
