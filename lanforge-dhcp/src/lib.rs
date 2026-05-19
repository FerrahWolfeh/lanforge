//! # Lanforge DHCP
//!
//! `DHCPv4` and `DHCPv6` server implementations for Lanforge.
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

pub mod error;
pub mod identity;
pub mod options;
pub mod v4;
pub mod v6;

#[cfg(test)]
pub mod test_utils;
