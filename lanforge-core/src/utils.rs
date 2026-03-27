use std::net::Ipv6Addr;

use crate::identifiers::MacAddr;

/// Retorna true se `ip` pertence ao mesmo /64 que `prefix`.
pub fn ip_matches_prefix(ip: &Ipv6Addr, prefix: &Ipv6Addr) -> bool {
    let ip_segs = ip.segments();
    let prefix_segs = prefix.segments();
    // Compara os primeiros 4 segmentos (64 bits)
    ip_segs[..4] == prefix_segs[..4]
}

// ---------------------------------------------------------------------------
// EUI-64 helpers
// ---------------------------------------------------------------------------

/// Tenta recuperar o MAC de um endereço IPv6 link-local EUI-64.
///
/// Formato EUI-64:
/// ```text
/// MAC:  AA:BB:CC:DD:EE:FF
/// IID:  (AA^0x02):BB:CC:FF:FE:DD:EE:FF
///        ^^^^^^^^             ^^ ^^ ^^ bytes 11,12 = FF:FE (marcador)
/// ```
/// Retorna `None` se o endereço não for link-local ou não usar EUI-64.
pub const fn mac_from_eui64_link_local(ip: &Ipv6Addr) -> Option<MacAddr> {
    let o = ip.octets();
    if o[0] != 0xfe || (o[1] & 0xc0) != 0x80 {
        return None; // não é fe80::/10
    }
    if o[11] != 0xff || o[12] != 0xfe {
        return None; // não é EUI-64
    }
    // Reverte o bit U/L (bit 6 do primeiro octeto do IID)
    Some(MacAddr([o[8] ^ 0x02, o[9], o[10], o[13], o[14], o[15]]))
}
