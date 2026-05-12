use lanforge_core::types::device::Ipv6AddrOrSuffix;
use std::array::from_fn;
use std::borrow::Cow;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::from_utf8;

use crate::wire::WireLabelIter;

/// Parses an IPv4 or IPv6 address from an ARPA domain name (reverse DNS).
#[must_use]
pub fn parse_arpa(name: &str) -> Option<IpAddr> {
    let labels = name.split('.').map(|s| s.as_bytes()).rev();
    // DNS names often have a trailing dot, so split will have an empty string at the end.
    // If we rev(), the first element might be empty.
    let mut iter = labels;
    if let Some(first) = iter.next() && first.is_empty() {
        byte_parse_arpa(iter)
    } else {
        // No trailing dot case
        byte_parse_arpa(name.split('.').map(|s| s.as_bytes()).rev())
    }
}

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

#[inline]
fn parse_nibble(label: &[u8]) -> Option<u8> {
    match label {
        [b] => match b {
            b'0'..=b'9' => Some(b - b'0'),
            b'a'..=b'f' => Some(b - b'a' + 10),
            b'A'..=b'F' => Some(b - b'A' + 10),
            _ => None,
        },
        _ => None,
    }
}

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

pub fn extract_local_hostname_wire<'a>(
    labels: &mut WireLabelIter<'a>,
    multi_search_labels: &[Vec<Vec<u8>>],
) -> Option<&'a str> {
    let host_bytes = labels.next()?;

    match labels.next() {
        None => from_utf8(host_bytes).ok(),
        Some(first_actual) => {
            for search_labels in multi_search_labels {
                let mut current_labels = labels.clone();
                let mut matched = true;

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

#[must_use]
pub fn parse_arpa_wire(labels: WireLabelIter<'_>) -> Option<IpAddr> {
    let mut parts: [&[u8]; 34] = [b""; 34];
    let mut count = 0;

    for l in labels {
        if count < parts.len() {
            parts[count] = l;
            count += 1;
        }
    }

    byte_parse_arpa(parts[..count].iter().copied().rev())
}

#[must_use]
pub fn extract_local_hostname<'a>(
    qname: &'a str,
    multi_search_labels: &[Vec<Vec<u8>>],
) -> Option<&'a str> {
    let mut parts = qname.split('.');
    let host = parts.next()?;
    if host.is_empty() {
        return None;
    }

    let first_actual = match parts.next() {
        Some(s) if !s.is_empty() => s,
        _ => return Some(host),
    };

    let rest: Vec<&str> = parts.filter(|s| !s.is_empty()).collect();

    for search_labels in multi_search_labels {
        if search_labels.is_empty() {
            continue;
        }

        if !first_actual.as_bytes().eq_ignore_ascii_case(&search_labels[0]) {
            continue;
        }

        if rest.len() != search_labels.len() - 1 {
            continue;
        }

        let mut matched = true;
        for (i, expected) in search_labels.iter().skip(1).enumerate() {
            if !rest[i].as_bytes().eq_ignore_ascii_case(expected) {
                matched = false;
                break;
            }
        }

        if matched {
            return Some(host);
        }
    }
    None
}

#[must_use]
pub fn fast_lowercase(s: &str) -> Cow<'_, str> {
    if s.bytes().any(|b| b.is_ascii_uppercase()) {
        Cow::Owned(s.to_ascii_lowercase())
    } else {
        Cow::Borrowed(s)
    }
}
