#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

// The binary initializes profiling; the library propagates its feature to services.
#[cfg(feature = "hotpath")]
use hotpath as _;

use rustls as _;
use toml as _;
use tracing_subscriber as _;

#[cfg(test)]
use dhcproto as _;
#[cfg(test)]
use lanforge_api_dispatch as _;
#[cfg(test)]
use lanforge_dns_wire as _;
#[cfg(test)]
use lanforge_transport as _;
#[cfg(test)]
use serde_json as _;

pub mod app;
pub mod bootstrap;
pub mod config;
pub mod event_loop;
pub mod registry;
pub mod supervisor;
pub mod synthetic;

#[cfg(test)]
#[allow(
    clippy::pedantic,
    clippy::nursery,
    reason = "integration tests keep the workspace lint level they had as a test crate"
)]
mod integration_tests;
