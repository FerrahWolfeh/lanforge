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
//! use lanforge_core::identifiers::MacAddr;
//! use lanforge_core::utils::{mac_from_eui64_link_local, is_slaac_iid, ip_matches_prefix};
//!
//! let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
//! // Link-local with EUI-64: fe80::(aa^02):bb:cc:ff:fe:dd:ee:ff
//! let ip: Ipv6Addr = "fe80::a8bb:ccff:fedd:eeff".parse().unwrap();
//! let recovered = mac_from_eui64_link_local(&ip).unwrap();
//! assert_eq!(recovered, mac);
//! assert!(is_slaac_iid(&ip, &mac));
//! ```

use std::net::Ipv6Addr;

use crate::identifiers::MacAddr;

/// Returns true if the given `ip` belongs to the same /64 subnet as the `prefix`.
///
/// Compares the first 64 bits (4 segments) of both addresses.
/// This is useful for checking if an address belongs to a specific subnet prefix.
///
/// # Example
///
/// ```rust
/// use std::net::Ipv6Addr;
/// use lanforge_core::utils::ip_matches_prefix;
///
/// let prefix: Ipv6Addr = "fd00::".parse().unwrap();
/// let ip: Ipv6Addr = "fd00::1234:5678:9abc:def0".parse().unwrap();
/// assert!(ip_matches_prefix(&ip, &prefix));
///
/// let other: Ipv6Addr = "2001:db8::1".parse().unwrap();
/// assert!(!ip_matches_prefix(&other, &prefix));
/// ```
#[must_use]
pub fn ip_matches_prefix(ip: &Ipv6Addr, prefix: &Ipv6Addr) -> bool {
    let ip_segs = ip.segments();
    let prefix_segs = prefix.segments();
    // Compare the first 64 bits (4 segments)
    ip_segs[..4] == prefix_segs[..4]
}

/// Generates an EUI-64 IPv6 address from a /64 prefix and a MAC address.
///
/// This is used to predict the default SLAAC address for a device.
///
/// # Example
///
/// ```rust
/// use std::net::Ipv6Addr;
/// use lanforge_core::identifiers::MacAddr;
/// use lanforge_core::utils::compute_eui64_ip;
///
/// let prefix: Ipv6Addr = "fd00::".parse().unwrap();
/// let mac = MacAddr::parse("00:11:22:33:44:55").unwrap();
/// let expected: Ipv6Addr = "fd00::0211:22ff:fe33:4455".parse().unwrap();
/// assert_eq!(compute_eui64_ip(&prefix, &mac), expected);
/// ```
#[must_use]
pub fn compute_eui64_ip(prefix: &Ipv6Addr, mac: &MacAddr) -> Ipv6Addr {
    let mut octets = prefix.octets();
    let m = mac.0;

    // First 64 bits come from the prefix.
    // The last 64 bits (Interface ID) are generated from the MAC.
    octets[8] = m[0] ^ 0x02;
    octets[9] = m[1];
    octets[10] = m[2];
    octets[11] = 0xff;
    octets[12] = 0xfe;
    octets[13] = m[3];
    octets[14] = m[4];
    octets[15] = m[5];

    Ipv6Addr::from(octets)
}

// ---------------------------------------------------------------------------
// EUI-64 helpers
// ---------------------------------------------------------------------------

/// Attempts to recover a MAC address from an EUI-64 Link-Local IPv6 address.
///
/// EUI-64 identifiers are formed by taking the 48-bit MAC address,
/// splitting it in half, inserting `0xfffe` in the middle, and inverting
/// the 7th bit (Universal/Local) of the first byte.
///
/// # Example format
/// ```text
/// MAC:  AA:BB:CC:DD:EE:FF
/// IID:  (AA^0x02):BB:CC:FF:FE:DD:EE:FF
/// ```
///
/// Returns `None` if:
/// - The address is not within `fe80::/10` (link-local range)
/// - The `FF:FE` marker is not found at bytes 11-12
/// - The U/L bit inversion doesn't match the expected pattern
///
/// # Example
///
/// ```rust
/// use std::net::Ipv6Addr;
/// use lanforge_core::identifiers::MacAddr;
/// use lanforge_core::utils::mac_from_eui64_link_local;
///
/// let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
/// // fe80:: + (aa^02):bb:cc:ff:fe:dd:ee:ff
/// let ip: Ipv6Addr = "fe80::a8bb:ccff:fedd:eeff".parse().unwrap();
/// let recovered = mac_from_eui64_link_local(&ip).unwrap();
/// assert_eq!(recovered, mac);
/// ```
///
/// This is a `const fn`, usable in const contexts.
#[must_use]
pub const fn mac_from_eui64_link_local(ip: &Ipv6Addr) -> Option<MacAddr> {
    let o = ip.octets();
    if o[0] != 0xfe || (o[1] & 0xc0) != 0x80 {
        return None; // não é fe80::/10
    }
    if o[11] != 0xff || o[12] != 0xfe {
        return None; // Marker FF:FE not found
    }
    // Revert the U/L bit (bit 1 of the first IID octet, i.e., byte 8 of the IP)
    Some(MacAddr([o[8] ^ 0x02, o[9], o[10], o[13], o[14], o[15]]))
}

/// Returns true if the IPv6 address suffix matches the EUI-64 identifier for the given MAC.
///
/// This function checks:
/// 1. The `FF:FE` marker is present at bytes 11-12
/// 2. The remaining IID bytes match the MAC (with U/L bit inversion on byte 8)
///
/// Unlike [`mac_from_eui64_link_local`], this function does **not** check
/// if the address is link-local — it only validates the EUI-64 pattern.
///
/// # Example
///
/// ```rust
/// use std::net::Ipv6Addr;
/// use lanforge_core::identifiers::MacAddr;
/// use lanforge_core::utils::is_slaac_iid;
///
/// let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
/// // Any prefix + EUI-64 suffix
/// let ip: Ipv6Addr = "fd00::a8bb:ccff:fedd:eeff".parse().unwrap();
/// assert!(is_slaac_iid(&ip, &mac));
/// ```
///
/// This is a `const fn`, usable in const contexts.
#[must_use]
pub const fn is_slaac_iid(ip: &Ipv6Addr, mac: &MacAddr) -> bool {
    let o = ip.octets();
    let m = mac.0;

    // Check EUI-64 markers
    if o[11] != 0xff || o[12] != 0xfe {
        return false;
    }

    // Compare rest of the IID (ignoring Universal/Local bit flip)
    if o[9] != m[1] || o[10] != m[2] || o[13] != m[3] || o[14] != m[4] || o[15] != m[5] {
        return false;
    }

    // Finally check first byte with U/L bit (bit 7 of the OUI / bit 1 of the IID)
    if (o[8] ^ 0x02) != m[0] {
        return false;
    }

    true
}
