use std::net::Ipv6Addr;

use crate::identifiers::MacAddr;

/// Returns true if the given `ip` belongs to the same /64 subnet as the `prefix`.
#[must_use]
pub fn ip_matches_prefix(ip: &Ipv6Addr, prefix: &Ipv6Addr) -> bool {
    let ip_segs = ip.segments();
    let prefix_segs = prefix.segments();
    // Compare the first 64 bits (4 segments)
    ip_segs[..4] == prefix_segs[..4]
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
/// Returns `None` if the address is not within `fe80::/10` or does not
/// appear to follow the EUI-64 pattern.
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
