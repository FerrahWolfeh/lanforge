//! # Lanforge DHCP
//!
//! `DHCPv4` and `DHCPv6` server implementations for Lanforge.
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

pub mod error;
pub mod identity;
pub mod options;
pub mod traits;
pub mod v4;
pub mod v6;

pub use v4::{Dhcpv4Config, Dhcpv4InertHandle, Dhcpv4InertReply, Dhcpv4Service, Dhcpv4Transport};
pub use v6::{Dhcpv6Config, Dhcpv6Service, Dhcpv6Transport};

#[cfg(test)]
pub mod test_utils;
