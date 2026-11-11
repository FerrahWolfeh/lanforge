#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

#[cfg(feature = "server")]
pub mod config;
pub mod error;

#[cfg(feature = "server")]
pub mod auth;
#[cfg(feature = "server")]
pub mod authz;
#[cfg(all(feature = "server", feature = "doh"))]
pub mod doh;
#[cfg(feature = "server")]
pub mod metrics;
#[cfg(feature = "client")]
pub mod remote;
#[cfg(feature = "server")]
pub mod routes;
#[cfg(feature = "server")]
pub mod server;
#[cfg(feature = "server")]
pub mod throttle;

#[cfg(feature = "client")]
pub use remote::RemoteClient;
#[cfg(feature = "server")]
pub use server::HttpService;

#[cfg(all(test, feature = "server"))]
mod tests;
#[cfg(test)]
use tempfile as _;
#[cfg(test)]
use tower as _;

#[cfg(test)]
#[allow(
    clippy::pedantic,
    clippy::nursery,
    reason = "integration tests keep the workspace lint level they had as a test crate"
)]
mod integration_tests;
