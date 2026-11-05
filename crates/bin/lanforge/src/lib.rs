#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

use rustls as _;
use toml as _;
use tracing_subscriber as _;

#[cfg(test)]
use dhcproto as _;
#[cfg(test)]
use lanforge_api_dispatch as _;
#[cfg(test)]
use lanforge_transport as _;

pub mod app;
pub mod bootstrap;
pub mod config;
pub mod event_loop;
pub mod registry;
pub mod supervisor;
pub mod synthetic;
