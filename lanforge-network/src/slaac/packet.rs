//! `ICMPv6` Echo Request packet construction.

use crate::ra::packet::icmpv6_checksum;
use std::net::Ipv6Addr;

/// `ICMPv6` type for Echo Request (128).
pub const ICMPV6_TYPE_ECHO_REQUEST: u8 = 128;
/// `ICMPv6` type for Echo Reply (129).
pub const ICMPV6_TYPE_ECHO_REPLY: u8 = 129;

/// Builds an `ICMPv6` Echo Request packet.
///
/// # Arguments
///
/// * `src` — Source IPv6 address (for checksum)
/// * `dst` — Destination IPv6 address (usually `ff02::1` for multicast)
/// * `id` — Echo identifier
/// * `seq` — Echo sequence number
#[must_use]
pub fn build_echo_request(src: &Ipv6Addr, dst: &Ipv6Addr, id: u16, seq: u16) -> Vec<u8> {
    let mut p = Vec::with_capacity(8);
    p.push(ICMPV6_TYPE_ECHO_REQUEST);
    p.push(0u8); // code = 0
    p.extend([0u8; 2]); // checksum placeholder
    p.extend(id.to_be_bytes());
    p.extend(seq.to_be_bytes());

    let csum = icmpv6_checksum(src, dst, &p);
    p[2] = (csum >> 8) as u8;
    p[3] = (csum & 0xFF) as u8;

    p
}
