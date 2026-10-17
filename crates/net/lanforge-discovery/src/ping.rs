//! # Active ICMP Ping Engine
//!
//! Re-exports the unified dual-stack `IcmpPinger` and packet parsers
//! from `lanforge-transport`.

pub use lanforge_transport::icmp::{
    checksum, parse_icmpv4_echo_reply, parse_icmpv6_echo_reply, IcmpPinger,
};

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_parse_icmpv4_echo_reply_standard_header() {
        // Standard IPv4 packet: 20 bytes IP header (IHL = 5) + 8 bytes ICMP Echo Reply
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45; // Version 4, IHL = 5 (20 bytes)
        packet[20] = 0; // ICMP Type: Echo Reply
        packet[21] = 0; // ICMP Code
        packet[24..26].copy_from_slice(&0x1234u16.to_be_bytes()); // ID
        packet[26..28].copy_from_slice(&0x0042u16.to_be_bytes()); // Seq

        let res = parse_icmpv4_echo_reply(&packet);
        assert_eq!(res, Some((0x1234, 0x0042)));
    }

    #[test]
    fn test_parse_icmpv4_echo_reply_with_options() {
        // IPv4 packet with options: 24 bytes IP header (IHL = 6) + 8 bytes ICMP Echo Reply
        let mut packet = vec![0u8; 32];
        packet[0] = 0x46; // Version 4, IHL = 6 (24 bytes)
        packet[24] = 0; // ICMP Type: Echo Reply
        packet[25] = 0; // ICMP Code
        packet[28..30].copy_from_slice(&0xABCDu16.to_be_bytes()); // ID
        packet[30..32].copy_from_slice(&0x0100u16.to_be_bytes()); // Seq

        let res = parse_icmpv4_echo_reply(&packet);
        assert_eq!(res, Some((0xABCD, 0x0100)));
    }

    #[test]
    fn test_parse_icmpv4_non_reply_types() {
        let mut packet = vec![0u8; 28];
        packet[0] = 0x45;

        // Type 8: Echo Request
        packet[20] = 8;
        assert_eq!(parse_icmpv4_echo_reply(&packet), None);

        // Type 3: Destination Unreachable
        packet[20] = 3;
        assert_eq!(parse_icmpv4_echo_reply(&packet), None);

        // Type 11: Time Exceeded
        packet[20] = 11;
        assert_eq!(parse_icmpv4_echo_reply(&packet), None);
    }

    #[test]
    fn test_parse_icmpv4_truncated_and_corrupt() {
        // Completely empty
        assert_eq!(parse_icmpv4_echo_reply(&[]), None);

        // Less than minimum IPv4 + ICMP header (28 bytes)
        assert_eq!(parse_icmpv4_echo_reply(&[0x45; 10]), None);

        // IHL < 5 (corrupt IPv4 header)
        let mut packet = vec![0u8; 28];
        packet[0] = 0x44; // IHL = 4 (16 bytes, invalid)
        assert_eq!(parse_icmpv4_echo_reply(&packet), None);

        // Packet shorter than IHL claims
        let mut packet = vec![0u8; 28];
        packet[0] = 0x48; // IHL = 8 (32 bytes required for IP header alone)
        assert_eq!(parse_icmpv4_echo_reply(&packet), None);
    }

    #[test]
    fn test_parse_icmpv6_echo_reply() {
        let mut packet = vec![0u8; 8];
        packet[0] = 129; // Echo Reply
        packet[1] = 0; // Code
        packet[4..6].copy_from_slice(&0x5678u16.to_be_bytes()); // ID
        packet[6..8].copy_from_slice(&0x0099u16.to_be_bytes()); // Seq

        let res = parse_icmpv6_echo_reply(&packet);
        assert_eq!(res, Some((0x5678, 0x0099)));
    }

    #[test]
    fn test_parse_icmpv6_non_reply_types() {
        let mut packet = vec![0u8; 8];

        // Type 128: Echo Request
        packet[0] = 128;
        assert_eq!(parse_icmpv6_echo_reply(&packet), None);

        // Type 1: Destination Unreachable
        packet[0] = 1;
        assert_eq!(parse_icmpv6_echo_reply(&packet), None);

        // Type 133: Router Solicitation
        packet[0] = 133;
        assert_eq!(parse_icmpv6_echo_reply(&packet), None);
    }

    #[test]
    fn test_parse_icmpv6_truncated() {
        assert_eq!(parse_icmpv6_echo_reply(&[]), None);
        assert_eq!(parse_icmpv6_echo_reply(&[129; 7]), None);
    }

    #[test]
    fn test_checksum_calculation() {
        let data = [0x08, 0x00, 0x00, 0x00, 0x12, 0x34, 0x00, 0x01];
        let cs = checksum(&data);
        assert_ne!(cs, 0);

        let mut with_cs = data;
        with_cs[2..4].copy_from_slice(&cs.to_be_bytes());
        assert_eq!(checksum(&with_cs), 0);
    }
}
