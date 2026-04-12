//! # Lanforge Network
//!
//! Low-level networking and address assignment protocols for the Lanforge daemon.
//!
//! This crate implements the full stack of LAN network services: interface monitoring,
//! `DHCPv4`/`DHCPv6` servers with stateful pools, `ICMPv6` Router Advertisements, `SLAAC` discovery,
//! `mDNS` probing, and Wake-on-LAN. All services integrate with `lanforge-core` via
//! `LanforgeContext`, `EventBus`, and the `DeviceUpdate` state machine.
//!
//! ## Service Map
//!
//! | Service | Protocol | Execution Model | Role |
//! | :--- | :--- | :--- | :--- |
//! | `InterfaceMonitor` | Netlink RTNL | Async + blocking bootstrap | Tracks interface IP changes |
//! | `Dhcpv4Service` | `DHCPv4` (RFC 2131) | Sync (blocking UDP) | IPv4 address assignment |
//! | `Dhcpv6Service` | `DHCPv6` (RFC 8415) | Sync (blocking UDP) | IPv6 address + prefix delegation |
//! | `RaService` | RA (RFC 4861) | Async (raw `ICMPv6`) | Router Advertisement broadcasting |
//! | `NeighborMonitor` | NDP/ARP | Async | Neighbor table monitoring |
//! | `MdnsProber` | mDNS (RFC 6762) | Async (spawn-blocking listeners) | Hostname discovery via multicast |
//!
//! ## Architecture Overview
//!
//! ```mermaid
//! graph TD
//!     IF["ifmon.rs\nInterface Monitor"] --> CTX["LanforgeContext\n(global state)"]
//!     D4["dhcp/v4/\nDHCPv4 Server"] --> CTX
//!     D6["dhcp/v6/\nDHCPv6 Server"] --> CTX
//!     RA["ra/\nRouter Advertisements"] --> CTX
//!     NDP["ndp/\nNeighbor Monitor"] --> CTX
//!     MDNS["mdns.rs\nmDNS Prober"] --> CTX
//!     SLAAC["slaac/\nSLAAC Bootstrap"] --> NDP
//!     SLAAC --> CTX
//!     WOL["wol.rs\nWake-on-LAN"]
//!     BUS["EventBus\n(bus events)"] --> D4
//!     BUS --> D6
//!     BUS --> RA
//!     BUS --> NDP
//!     BUS --> IF
//!     BUS --> MDNS
//! ```
//!
//! ## Key Design Decisions
//!
//! - **Sync DHCP, Async everything else**: DHCP servers use blocking I/O with 200ms read timeouts
//!   to avoid async runtime complexity in packet processing loops. All other services are async.
//! - **`LanforgeContext` as single source of truth**: DHCP pools check the context for lease
//!   ownership before allocating, preventing pool/context divergence.
//! - **`DeviceUpdate` events**: All state changes flow through typed `DeviceUpdate` variants,
//!   automatically persisted by `lanforge-db` via the `DbWorker` batch system.
//! - **Raw socket injection**: `DHCPv4` replies use `AF_PACKET` (via `pnet`) for L2 unicast
//!   delivery when the client has no ARP entry — required by RFC 2131.
//!
//! ## Module Summary
//!
//! | Module | Purpose |
//! | :--- | :--- |
//! | `dhcp` | DHCPv4 and DHCPv6 servers, pools, identity, raw packet injection |
//! | `error` | `NetworkError` enum covering all failure modes |
//! | `ifmon` | Netlink-based interface address change monitor |
//! | `mdns` | mDNS multicast prober for hostname discovery |
//! | `ndp` | IPv4/IPv6 neighbor table monitoring and scanning |
//! | `ra` | ICMPv6 Router Advertisement packet builder and service |
//! | `slaac` | SLAAC address bootstrap via kernel neighbor dump |
//! | `wol` | Wake-on-LAN magic packet sender |
#![warn(clippy::all, clippy::pedantic, clippy::nursery)]
#![allow(clippy::missing_panics_doc, clippy::missing_errors_doc)]

pub mod dhcp;
pub mod error;
pub mod ifmon;
pub mod mdns;
pub mod ndp;
pub mod ra;
pub mod slaac;
#[cfg(test)]
pub(crate) mod test_utils;
pub mod wol;
