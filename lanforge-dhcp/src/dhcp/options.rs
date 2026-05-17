use std::net::{Ipv4Addr, Ipv6Addr};
use tracing::warn;

/// Parses a typed DHCP option value string (e.g., "s:hello", "ip:1.1.1.1", "hex:aabb").
///
/// Supported prefixes:
/// - `s:` or `ascii:` -> ASCII string bytes
/// - `ip:` -> Single IPv4 or IPv6 address bytes
/// - `hex:` -> Raw hex-encoded bytes (default if no prefix matches)
pub fn parse_typed_option(val: &str) -> Option<Vec<u8>> {
    if let Some(s) = val.strip_prefix("s:") {
        return Some(s.as_bytes().to_vec());
    }
    if let Some(s) = val.strip_prefix("ascii:") {
        return Some(s.as_bytes().to_vec());
    }

    if let Some(s) = val.strip_prefix("ip:") {
        // Try IPv4 first
        if let Ok(ip) = s.parse::<Ipv4Addr>() {
            return Some(ip.octets().to_vec());
        }
        // Then IPv6
        if let Ok(ip) = s.parse::<Ipv6Addr>() {
            return Some(ip.octets().to_vec());
        }
        warn!("Failed to parse IP option value: {}", s);
        return None;
    }

    // Default to hex
    let hex_val = val.strip_prefix("hex:").unwrap_or(val).replace("0x", "");
    match hex::decode(&hex_val) {
        Ok(data) => Some(data),
        Err(e) => {
            warn!("Failed to decode hex option value '{}': {}", hex_val, e);
            None
        }
    }
}
