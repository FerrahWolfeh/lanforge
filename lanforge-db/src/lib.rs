//! # Lanforge DB
//!
//! This crate provides the persistent storage layer for the Lanforge daemon.
//! It uses SQLite as a backend to ensure that discovered network devices, leases,
//! and static configurations survive system restarts.

pub mod engine;
pub mod error;
#[cfg(test)]
mod tests;
pub mod worker;

pub use error::LeaseDbError;
pub type Result<T> = std::result::Result<T, LeaseDbError>;
