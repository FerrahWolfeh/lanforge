//! # Lanforge DHCP
//!
//! `DHCPv4` and `DHCPv6` server implementations for Lanforge.
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

pub mod dhcp;
pub mod error;
#[cfg(test)]
pub mod test_utils;
