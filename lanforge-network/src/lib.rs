//! # Lanforge Network
//!
//! Low-level networking and address assignment protocols for the Lanforge daemon.
//!
//! This crate implements the full stack of LAN network services: interface monitoring,
//! `DHCPv4`/`DHCPv6` servers with stateful pools, `ICMPv6` Router Advertisements, `SLAAC` discovery,
//! `mDNS` probing, and Wake-on-LAN. All services integrate with `lanforge-core` via
//! `LanforgeContext`, `EventBus`, and the `DeviceUpdate` state machine.
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

pub mod dhcp;
pub mod error;
pub mod ifmon;
pub mod lldp;
pub mod mdns;
pub mod ndp;
pub mod ra;
pub mod slaac;
#[cfg(test)]
pub(crate) mod test_utils;
pub mod wol;
