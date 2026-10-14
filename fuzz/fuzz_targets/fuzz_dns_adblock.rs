#![no_main]

use lanforge_dns::resolver::filter::engine::encode_reversed_domain;
use lanforge_dns::resolver::filter::parse::{detect_format, parse_source};
use lanforge_types::network::dns::adblock::AdblockSourceFormat;
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    // Process input as lossy string to cover arbitrary byte patterns
    let text = String::from_utf8_lossy(data);

    // 1. Format detection on arbitrary inputs
    let detected = detect_format(&text);

    // 2. Parse under detected format
    let res = parse_source(&text, detected);

    // 3. Parse under explicit format modes
    let _ = parse_source(&text, AdblockSourceFormat::Adblock);
    let _ = parse_source(&text, AdblockSourceFormat::Hosts);
    let _ = parse_source(&text, AdblockSourceFormat::Domains);
    let _ = parse_source(&text, AdblockSourceFormat::WildcardDomains);

    // 4. Test domain encoding and reversal engine on all parsed rules
    let mut rev_buf = [0u8; 256];
    for rule in res.rules {
        let _ = encode_reversed_domain(&rule.domain, &mut rev_buf);
        let _ = rule.flags.is_self();
        let _ = rule.flags.is_subdomains();
        let _ = rule.flags.is_important();
    }
});
