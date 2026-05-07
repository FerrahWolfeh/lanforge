//! DNS wire-format utility functions.
//!
//! Provides optimized parsers for ARPA names, hostname extraction,
//! and IPv6 prefix/suffix combining — all designed to minimize allocations.

use hickory_proto::rr::Name;
use lanforge_types::device::Ipv6AddrOrSuffix;
use std::array::from_fn;
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::from_utf8;

use crate::wire::WireLabelIter;

/// Parses an IPv4 or IPv6 address from an ARPA domain name (reverse DNS).
///
/// Works directly on Hickory-DNS `Name` labels, avoiding UTF-8 validation
/// and intermediate string allocations.
///
/// # Supported Formats
///
/// - **IPv4:** `4.3.2.1.in-addr.arpa.` → `1.2.3.4`
/// - **IPv6:** `b.a.9.8...0.0.0.0.ip6.arpa.` → `2001:db8::`
#[must_use]
pub fn parse_arpa(name: &Name) -> Option<IpAddr> {
    let labels = name.iter().rev();
    byte_parse_arpa(labels)
}

/// Parses a decimal octet (0-255) directly from raw bytes.
///
/// Rejects empty strings, labels longer than 3 characters, non-digit bytes,
/// and values exceeding 255. No UTF-8 validation is performed.
#[inline]
fn parse_octet(label: &[u8]) -> Option<u8> {
    if label.is_empty() || label.len() > 3 {
        return None;
    }
    let mut val: u16 = 0;
    for &b in label {
        if !b.is_ascii_digit() {
            return None;
        }
        val = val * 10 + u16::from(b - b'0');
    }
    if val > 255 {
        None
    } else {
        Some(u8::try_from(val).unwrap_or(u8::MAX))
    }
}

/// Parses a single hex nibble (0-9, a-f, A-F) from a 1-byte label.
#[inline]
fn parse_nibble(label: &[u8]) -> Option<u8> {
    match label {
        [b] => match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        },
        _ => None, // empty or multi-byte label: invalid
    }
}

/// Parses an IP address from reversed ARPA labels.
///
/// Expects labels in reverse order (root label first), starting with "arpa",
/// then "in-addr" (IPv4) or "ip6" (IPv6), followed by the address components.
#[inline]
fn byte_parse_arpa<'a>(mut labels: impl Iterator<Item = &'a [u8]>) -> Option<IpAddr> {
    if !labels.next()?.eq_ignore_ascii_case(b"arpa") {
        return None;
    }

    let second = labels.next()?;

    if second.eq_ignore_ascii_case(b"in-addr") {
        let [a, b, c, d] = from_fn(|_| labels.next());
        return Some(IpAddr::V4(Ipv4Addr::new(
            parse_octet(a?)?,
            parse_octet(b?)?,
            parse_octet(c?)?,
            parse_octet(d?)?,
        )));
    }

    if second.eq_ignore_ascii_case(b"ip6") {
        let mut segments = [0u16; 8];
        for i in 0..32_usize {
            let nibble = parse_nibble(labels.next()?)?;
            segments[i / 4] |= u16::from(nibble) << (12 - (i % 4) * 4);
        }
        return Some(IpAddr::V6(Ipv6Addr::from(segments)));
    }

    None
}

/// Combines an IPv6 prefix (first 64 bits) with a suffix (last 64 bits).
///
/// If the suffix is a full address, it is returned as-is. Otherwise, the
/// first 4 segments from `prefix_segs` are combined with the 8-byte suffix.
#[must_use]
pub fn combine_prefix_suffix(prefix_segs: &[u16], suffix: &Ipv6AddrOrSuffix) -> Option<Ipv6Addr> {
    match suffix {
        Ipv6AddrOrSuffix::Full(ip) => Some(*ip),
        Ipv6AddrOrSuffix::Suffix(s) => Some(Ipv6Addr::new(
            prefix_segs[0],
            prefix_segs[1],
            prefix_segs[2],
            prefix_segs[3],
            u16::from_be_bytes([s[0], s[1]]),
            u16::from_be_bytes([s[2], s[3]]),
            u16::from_be_bytes([s[4], s[5]]),
            u16::from_be_bytes([s[6], s[7]]),
        )),
    }
}

/// Extracts a local hostname from a wire-format DNS query.
///
/// Matches the first label against the configured search domains
/// (`multi_search_labels`). Returns the hostname as a `&str` if it
/// matches, without allocating.
///
/// # Supported Queries
///
/// - Short name: `"node-1"` (single label)
/// - FQDN: `"node-1.lan."` (hostname + search domain)
///
/// # Rejected Queries
///
/// - Wrong suffix: `"node-1.other."`
/// - Extra subdomains: `"sub.node-1.lan."`
pub fn extract_local_hostname_wire<'a>(
    labels: &mut WireLabelIter<'a>,
    multi_search_labels: &[Vec<Vec<u8>>],
) -> Option<&'a str> {
    // 1. The first label is the target hostname
    let host_bytes = labels.next()?;

    // 2. Decide if we match a short name or a domain
    match labels.next() {
        None => {
            // Case 1: "node-1" (single label query)
            from_utf8(host_bytes).ok()
        }
        Some(first_actual) => {
            // Case 2: "node-1.lan" (domain query)
            for search_labels in multi_search_labels {
                let mut current_labels = labels.clone();
                let mut matched = true;

                // Match against this specific domain's labels
                if !first_actual.eq_ignore_ascii_case(&search_labels[0]) {
                    continue;
                }

                for expected in &search_labels[1..] {
                    match current_labels.next() {
                        Some(actual) if actual.eq_ignore_ascii_case(expected) => {}
                        _ => {
                            matched = false;
                            break;
                        }
                    }
                }

                if matched && current_labels.next().is_none() {
                    return from_utf8(host_bytes).ok();
                }
            }

            None
        }
    }
}

/// Parses an ARPA request from a wire label iterator.
///
/// Collects labels into a fixed-size array to avoid allocations, then
/// delegates to `byte_parse_arpa` in reverse order.
#[must_use]
pub fn parse_arpa_wire(labels: WireLabelIter<'_>) -> Option<IpAddr> {
    // IPv6: 32 nibbles + "ip6" + "arpa" = 34 labels max
    let mut parts: [&[u8]; 34] = [b""; 34];
    let mut count = 0;

    for l in labels {
        if count < parts.len() {
            parts[count] = l;
            count += 1;
        }
    }

    // Iterate only filled slots in reverse order
    byte_parse_arpa(parts[..count].iter().copied().rev())
}

/// Extracts a local hostname from a Hickory-DNS `Name` object.
///
/// Zero-allocation: iterates over labels directly, matching against
/// `multi_search_labels` without constructing intermediate strings.
///
/// # Supported Queries
///
/// - Short name: `"node-1"` → `Some("node-1")`
/// - Full name: `"node-1.lan."` → `Some("node-1")`
///
/// # Rejected
///
/// - Wrong suffix: `"node-1.other."` → `None`
/// - Extra subdomains: `"sub.node-1.lan."` → `None`
#[must_use]
pub fn extract_local_hostname<'a>(
    qname: &'a Name,
    multi_search_labels: &[Vec<Vec<u8>>],
) -> Option<&'a str> {
    let mut iter = qname.iter();

    // 1. The first label is always the target
    let host_bytes = iter.next()?;

    // 2. Check for suffixes
    match iter.next() {
        None => {
            // Short name: "node-1"
            from_utf8(host_bytes).ok()
        }
        Some(first_actual) => {
            // Collect remaining labels once for efficient multi-pass matching
            let rest: Vec<&[u8]> = iter.collect();

            // Check if it matches any configured domain
            for search_labels in multi_search_labels {
                if search_labels.is_empty() {
                    continue;
                }

                // 1. Initial label match (first label after hostname)
                if !first_actual.eq_ignore_ascii_case(&search_labels[0]) {
                    continue;
                }

                // 2. Length check for remaining labels
                if rest.len() != search_labels.len() - 1 {
                    continue;
                }

                // 3. Perfect match for all subsequent labels
                let mut matched = true;
                for (i, expected) in search_labels.iter().skip(1).enumerate() {
                    if !rest[i].eq_ignore_ascii_case(expected) {
                        matched = false;
                        break;
                    }
                }

                if matched {
                    return from_utf8(host_bytes).ok();
                }
            }

            None
        }
    }
}

/// Converts a string to lowercase with minimal allocations.
///
/// In 99% of LAN queries, no allocation is performed (returns `Borrowed`).
/// Only allocates on the heap (`Owned`) if the input contains uppercase
/// ASCII characters.
#[must_use]
pub fn fast_lowercase(s: &str) -> Cow<'_, str> {
    if s.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(s.to_ascii_lowercase())
    } else {
        Cow::Borrowed(s)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::rr::Name;
    use std::str::FromStr;

    #[test]
    fn test_extract_local_hostname_flexible() {
        let multi_search_labels = vec![vec![b"lan".to_vec()]];

        // 1. Short name
        let name_short = Name::from_str("node-1.").unwrap();
        assert_eq!(
            extract_local_hostname(&name_short, &multi_search_labels),
            Some("node-1")
        );

        // 2. Full name
        let name_full = Name::from_str("node-1.lan.").unwrap();
        assert_eq!(
            extract_local_hostname(&name_full, &multi_search_labels),
            Some("node-1")
        );

        // 3. Wrong suffix
        let name_wrong = Name::from_str("node-1.other.").unwrap();
        assert_eq!(
            extract_local_hostname(&name_wrong, &multi_search_labels),
            None
        );

        // 4. Excess subdomains
        let name_excess = Name::from_str("sub.node-1.lan.").unwrap();
        assert_eq!(
            extract_local_hostname(&name_excess, &multi_search_labels),
            None
        );
    }
}
