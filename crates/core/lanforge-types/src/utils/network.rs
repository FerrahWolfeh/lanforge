//! IPv6 and EUI-64 utility functions.

use crate::identifiers::MacAddr;
use std::net::Ipv6Addr;

/// Returns true if the given `ip` belongs to the same /64 subnet as the `prefix`.
///
/// Compares the first 64 bits (4 segments) of both addresses.
/// This is useful for checking if an address belongs to a specific subnet prefix.
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

/// Attempts to recover a MAC address from an EUI-64 Link-Local IPv6 address.
///
/// EUI-64 identifiers are formed by taking the 48-bit MAC address,
/// splitting it in half, inserting `0xfffe` in the middle, and inverting
/// the 7th bit (Universal/Local) of the first byte.
///
/// Returns `None` if:
/// - The address is not within `fe80::/10` (link-local range)
/// - The `FF:FE` marker is not found at bytes 11-12
/// - The U/L bit inversion doesn't match the expected pattern
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
