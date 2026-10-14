#![no_main]

use lanforge_dns_wire::{
    PtrResponseArgs, WireDecoder, WireHeader, WireOptScanner, WireQuestion, WireResponseScanner,
    WireResponseWriter,
};
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

fuzz_target!(|data: &[u8]| {
    // 1. Full wire decoding and name decompression
    let mut decoder = WireDecoder::new(data);
    if let Some(msg) = decoder.decode_message() {
        let _ = msg.to_owned();
    }

    // 2. TTL scanner for cache insertions
    let scanner = WireResponseScanner::new(data);
    let _ = scanner.scan_ttls();

    // 3. Fast wire header inspection and in-place ID patching
    let header_opt = WireHeader::parse(data);
    if let Some(header) = &header_opt {
        let _ = header.id();
        let _ = header.is_query();
        let _ = header.rd();
        let _ = header.tc();
        let _ = header.qdcount();
        let _ = header.ancount();
        let _ = header.nscount();
        let _ = header.arcount();
        let _ = header.to_owned();

        let mut patch_buf = data.to_vec();
        WireHeader::patch_id(&mut patch_buf, 0x5a5a);
    }

    // 4. Fast question extraction, label iteration, and response generation
    if let (Some(header), Some(question)) = (header_opt.as_ref(), WireQuestion::parse(data)) {
        let _ = question.qname_raw();
        let _ = question.qtype();
        let _ = question.qclass();
        let _ = question.to_domain_lowercase();
        for label in question.labels() {
            let _ = label.len();
        }

        // Test OPT scanning
        let edns = WireOptScanner::scan(data, header, &question);

        // Test error response writer
        let mut err_resp = Vec::new();
        WireResponseWriter::write_error_response(data, &question, 3, edns, true, &mut err_resp);

        // Test IP response writer (both IPv4 and IPv6)
        let mut ip_resp = Vec::new();
        let ips = [
            IpAddr::V4(Ipv4Addr::new(127, 0, 0, 1)),
            IpAddr::V6(Ipv6Addr::new(0, 0, 0, 0, 0, 0, 0, 1)),
        ];
        WireResponseWriter::write_ip_response(
            data,
            &question,
            &ips,
            300,
            edns,
            true,
            &mut ip_resp,
        );

        // Test PTR response writer
        let mut ptr_resp = Vec::new();
        WireResponseWriter::write_ptr_response(
            PtrResponseArgs {
                query_data: data,
                question: &question,
                host: "router",
                domain: "lanforge.local",
                ttl: 300,
                edns,
                ra: true,
            },
            &mut ptr_resp,
        );
    }
});
