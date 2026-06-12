//! DHCP (Dynamic Host Configuration Protocol) address pool types.
//!
//! This module provides configuration structures for both `DHCPv4` and `DHCPv6`
//! dynamic address pools.
//!
//! # Concepts
//!
//! ## `DHCPv4`
//! Under `DHCPv4` (RFC 2131), the server assigns IPv4 addresses from a defined range
//! (`range_start` to `range_end` inclusive). Clients request leases, which remain valid
//! for a duration defined by `lease_time` (or a global default).
//!
//! ## `DHCPv6`
//! Under `DHCPv6` (RFC 8415), address pools can be defined dynamically relative to an
//! advertised prefix.
//! * **Relative Suffix Ranges:** By using [`Ipv6AddrOrSuffix::Suffix`], the pool range is
//!   specified via the lower 64 bits of the address. The actual address pool range is computed
//!   by combining these suffixes with the active network prefix. This is particularly useful
//!   when the prefix is dynamic (e.g., via `DHCPv6` Prefix Delegation).
//! * **Absolute Ranges:** Alternatively, pool boundaries can be defined using absolute
//!   IPv6 addresses via [`Ipv6AddrOrSuffix::Full`].
//! * **Static Allocation:** A static network segment or subnet CIDR can be specified via
//!   the `address` field.

use crate::network::Ipv6AddrOrSuffix;
use serde::{Deserialize, Serialize};
use std::net::Ipv4Addr;

/// Configuration for a single `DHCPv4` address pool.
///
/// Defines a contiguous range of IPv4 addresses that the `DHCPv4` server is permitted to lease
/// dynamically to clients on the local network link.
///
/// # Example
///
/// ```
/// # use std::net::Ipv4Addr;
/// # use lanforge_types::network::dhcp::Dhcpv4Pool;
/// let pool = Dhcpv4Pool {
///     range_start: Ipv4Addr::new(192, 168, 1, 100),
///     range_end: Ipv4Addr::new(192, 168, 1, 200),
///     lease_time: Some(86400), // 24 hours
/// };
/// ```
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct Dhcpv4Pool {
    /// Start of the dynamic IP range (inclusive).
    pub range_start: Ipv4Addr,
    /// End of the dynamic IP range (inclusive).
    pub range_end: Ipv4Addr,
    /// Custom lease time for this pool in seconds.
    ///
    /// If `None`, the global or service-default lease time is used.
    pub lease_time: Option<u32>,
}

/// Configuration for a single `DHCPv6` address pool.
///
/// In IPv6 networks, `DHCPv6` can be operated in stateful mode to allocate addresses dynamically from
/// a pool (analogous to `DHCPv4`). Unlike `DHCPv4`, the pool ranges can be defined relative to the active
/// prefix using suffix boundaries, allowing the pool to shift dynamically when the prefix changes.
///
/// # Example (Suffix-based range)
///
/// ```
/// # use std::str::FromStr;
/// # use lanforge_types::network::Ipv6AddrOrSuffix;
/// # use lanforge_types::network::dhcp::Dhcpv6Pool;
/// let pool = Dhcpv6Pool {
///     range_start: Some(Ipv6AddrOrSuffix::from_str("::1000").unwrap()),
///     range_end: Some(Ipv6AddrOrSuffix::from_str("::2000").unwrap()),
///     address: None,
///     lease_time: Some(43200), // 12 hours
/// };
/// ```
#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
pub struct Dhcpv6Pool {
    /// Lower bound suffix or full address for the pool range (inclusive).
    ///
    /// If a suffix is specified, it is resolved against the active network prefix.
    pub range_start: Option<Ipv6AddrOrSuffix>,
    /// Upper bound suffix or full address for the pool range (inclusive).
    ///
    /// If a suffix is specified, it is resolved against the active network prefix.
    pub range_end: Option<Ipv6AddrOrSuffix>,
    /// Static CIDR address or prefix (alternative to range-based pools).
    ///
    /// E.g., `"2001:db8:1::/64"`.
    pub address: Option<String>,
    /// Custom lease time for this pool in seconds.
    ///
    /// If `None`, the global or service-default lease time is used.
    pub lease_time: Option<u32>,
}
