#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

pub mod config;
pub mod error;

#[cfg(feature = "server")]
pub mod auth;
#[cfg(feature = "server")]
pub mod metrics;
#[cfg(feature = "client")]
pub mod remote;
#[cfg(feature = "server")]
pub mod routes;
#[cfg(feature = "server")]
pub mod server;

#[cfg(feature = "client")]
pub use remote::RemoteClient;
#[cfg(feature = "server")]
pub use server::HttpService;

#[cfg(test)]
mod tests;
