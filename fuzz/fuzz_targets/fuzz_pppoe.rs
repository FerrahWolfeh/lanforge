#![no_main]

use lanforge_pppoe::discovery::frame::PppoeDiscoveryFrame;
use lanforge_pppoe::ipcp::{parse_peer_ip, parse_peer_v6_ifid};
use lanforge_pppoe::lcp::LcpPacket;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // 1. PPPoE Discovery Frame parsing and serialization roundtrip
    if let Some(frame) = PppoeDiscoveryFrame::parse(data) {
        let encoded = frame.encode();
        if let Some(reparsed) = PppoeDiscoveryFrame::parse(&encoded) {
            assert_eq!(frame.dst_mac, reparsed.dst_mac);
            assert_eq!(frame.src_mac, reparsed.src_mac);
            assert_eq!(frame.code, reparsed.code);
            assert_eq!(frame.session_id, reparsed.session_id);
            assert_eq!(frame.tags.len(), reparsed.tags.len());
        }
    }

    // 2. LCP packet parsing and serialization roundtrip
    if let Some(lcp) = LcpPacket::parse(data) {
        let encoded = lcp.encode();
        if let Some(reparsed) = LcpPacket::parse(&encoded) {
            assert_eq!(lcp.code, reparsed.code);
            assert_eq!(lcp.id, reparsed.id);
            assert_eq!(lcp.options.len(), reparsed.options.len());
        }
    }

    // 3. IPCP option extraction (IPv4 peer address)
    let _ = parse_peer_ip(data, data.len());

    // 4. IPv6CP option extraction (EUI-64 interface identifier)
    let _ = parse_peer_v6_ifid(data, data.len());
});
