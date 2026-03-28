use hickory_proto::rr::Name;
use lanforge_core::device::Ipv6AddrOrSuffix;
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

use crate::wire::WireLabelIter;

/// Optimized ARPA parser that operates directly on Name labels, avoiding allocations.
pub fn parse_arpa(name: &Name) -> Option<IpAddr> {
    let labels = name.iter().rev();

    byte_parse_arpa(labels)
}

/// Parses a decimal octet directly from bytes without UTF-8 validation.
/// Rejects empty strings, labels > 3 chars, non-digits, and values > 255.
#[inline(always)]
fn parse_octet(label: &[u8]) -> Option<u8> {
    if label.is_empty() || label.len() > 3 {
        return None;
    }
    let mut val: u16 = 0;
    for &b in label {
        if !b.is_ascii_digit() {
            return None;
        }
        val = val * 10 + (b - b'0') as u16;
    }
    if val > 255 { None } else { Some(val as u8) }
}

/// Parses a single hex nibble (0-9, a-f, A-F) from a 1-byte label.
#[inline(always)]
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

#[inline]
fn byte_parse_arpa<'a>(mut labels: impl Iterator<Item = &'a [u8]>) -> Option<IpAddr> {
    if !labels.next()?.eq_ignore_ascii_case(b"arpa") {
        return None;
    }

    let second = labels.next()?;

    if second.eq_ignore_ascii_case(b"in-addr") {
        let [a, b, c, d] = std::array::from_fn(|_| labels.next());
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
            segments[i / 4] |= (nibble as u16) << (12 - (i % 4) * 4);
        }
        return Some(IpAddr::V6(Ipv6Addr::from(segments)));
    }

    None
}

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

/// Extracts the local hostname directly from a wire iterator's labels without allocations.
pub fn extract_local_hostname_wire<'a>(
    labels: &mut WireLabelIter<'a>,
    search_labels: &[Vec<u8>],
) -> Option<&'a str> {
    // 1. The first label is the target hostname
    let host_bytes = labels.next()?;

    // 2. Validate the rest of the query against search domains
    for expected in search_labels {
        let actual = labels.next()?;
        if !actual.eq_ignore_ascii_case(expected) {
            return None;
        }
    }

    // 3. Reject queries with excess subdomains
    if labels.next().is_some() {
        return None;
    }

    std::str::from_utf8(host_bytes).ok()
}

/// Parses an ARPA request directly from a wire label iterator.
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

/// Extracts the local hostname directly from a Hickory-DNS Name object.
/// Allocation cost: 0 bytes.
pub fn extract_local_hostname<'a>(qname: &'a Name, search_labels: &[Vec<u8>]) -> Option<&'a str> {
    let mut iter = qname.iter();

    // 1. The first label is always the target (e.g., "node-12" in "node-12.lanforge.local")
    let host_bytes = iter.next()?;

    // 2. Validate that the rest of the query matches the search domain exactly
    for expected_label in search_labels {
        let actual_label = iter.next()?;

        // Case-insensitive byte comparison (much faster than UTF-8 string conversion)
        if !actual_label.eq_ignore_ascii_case(expected_label) {
            return None;
        }
    }

    // 3. If the query has more labels (e.g., sub.node-12.lanforge.local), reject it
    if iter.next().is_some() {
        return None;
    }

    // 4. Everything matches. Convert hostname bytes to &str and return
    std::str::from_utf8(host_bytes).ok()
}

/// Ensures a string is lowercase with minimal allocations.
///
/// In 99% of LAN queries, no allocation is performed (returns `Borrowed`).
/// Only allocates on the heap (`Owned`) if the input contains uppercase ASCII characters.
pub fn fast_lowercase(s: &str) -> Cow<'_, str> {
    if s.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(s.to_ascii_lowercase())
    } else {
        Cow::Borrowed(s)
    }
}
