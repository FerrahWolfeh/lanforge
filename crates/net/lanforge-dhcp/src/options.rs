use std::collections::HashMap;
use std::hash::{BuildHasher, Hash};
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
    let hex_val = val.strip_prefix("hex:").unwrap_or(val);
    let hex_clean = hex_val
        .strip_prefix("0x")
        .or_else(|| hex_val.strip_prefix("0X"))
        .unwrap_or(hex_val);
    match hex::decode(hex_clean) {
        Ok(data) => Some(data),
        Err(e) => {
            warn!("Failed to decode hex option value '{hex_clean}': {e}");
            None
        }
    }
}

/// Returns an iterator of `(code, bytes)` from a custom options map,
/// skipping unparseable values and protected codes.
pub fn iter_custom_options<'a, K, S: BuildHasher>(
    options: &'a HashMap<K, String, S>,
    protected: &'static [K],
) -> impl Iterator<Item = (K, Vec<u8>)> + 'a
where
    K: Copy + Eq + Hash + std::fmt::Display + 'static,
{
    options.iter().filter_map(move |(&code, val)| {
        if protected.contains(&code) {
            warn!("Custom option code {} is protected, ignoring", code);
            return None;
        }
        let parsed = parse_typed_option(val)?;
        Some((code, parsed))
    })
}
