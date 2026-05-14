//! IPv6 and EUI-64 utility functions.
//!
//! This module provides helper functions for working with IPv6 addresses,
//! particularly in the context of SLAAC (Stateless Address Autoconfiguration)
//! and EUI-64 identifier generation.
//!
//! # EUI-64 Background
//!
//! EUI-64 identifiers are formed by taking the 48-bit MAC address,
//! splitting it in half, inserting `0xfffe` in the middle, and inverting
//! the 7th bit (Universal/Local) of the first byte.
//!
//! ```text
//! MAC:  AA:BB:CC:DD:EE:FF
//! IID:  (AA^0x02):BB:CC:FF:FE:DD:EE:FF
//! ```
//!
//! # Example
//!
//! ```rust
//! use std::net::Ipv6Addr;
//! use lanforge_types::MacAddr;
//! use lanforge_core::utils::{mac_from_eui64_link_local, is_slaac_iid, ip_matches_prefix};
//!
//! let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
//! // Link-local with EUI-64: fe80::(aa^02):bb:cc:ff:fe:dd:ee:ff
//! let ip: Ipv6Addr = "fe80::a8bb:ccff:fedd:eeff".parse().unwrap();
//! let recovered = mac_from_eui64_link_local(&ip).unwrap();
//! assert_eq!(recovered, mac);
//! assert!(is_slaac_iid(&ip, &mac));
//! ```

pub use lanforge_types::utils::{
    compute_eui64_ip, ip_matches_prefix, is_slaac_iid, mac_from_eui64_link_local,
};

pub mod auth;
