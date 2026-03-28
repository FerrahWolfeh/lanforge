//! # Lanforge Network
//!
//! This crate implements the core networking protocols for the Lanforge daemon.
//! It handles low-level interactions with the Linux kernel via Netlink, as well
//! as higher-level address assignment protocols:
//!
//! - **Netlink**: Neighbor discovery monitoring and interface management.
//! - **DHCPv4**: Standard IPv4 address assignment.
//! - **DHCPv6**: Stateful IPv6 address and prefix delegation.
//! - **RA (Router Advertisement)**: ICMPv6-based network configuration.
//! - **SLAAC**: Stateless IPv6 address discovery.

pub mod dhcp;
pub mod error;
pub mod mdns;
pub mod netlink;
pub mod ra;
pub mod slaac;
