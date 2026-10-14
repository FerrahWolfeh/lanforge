#![no_main]

use lanforge_types::identifiers::{DeviceIdentifier, Duid, MacAddr};
use lanforge_types::network::{Hostname, IpSubnet, classify_ip, classify_ipv6, is_ula};
use libfuzzer_sys::fuzz_target;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};
use std::str::FromStr;

fuzz_target!(|data: &[u8]| {
    // 1. DUID tests (raw bytes and string representation)
    let duid = Duid::new(data.to_vec());
    let duid_str = duid.to_string();
    let _ = duid.as_bytes();
    let _ = duid.duid_type();
    let _ = duid.extract_mac();

    if let Ok(parsed_duid) = Duid::from_str(&duid_str) {
        let _ = parsed_duid.extract_mac();
    }

    // 2. MAC address tests (from_slice and string parsing)
    if let Some(mac) = MacAddr::from_slice(data) {
        let _ = mac.to_string();
        let _ = mac.is_zero();
        let _ = mac.as_bytes();
    }

    let lossy_str = String::from_utf8_lossy(data);
    if let Some(mac) = MacAddr::parse(&lossy_str) {
        let mac_str = mac.to_string();
        let _ = mac.contains_str(&lossy_str);
        let _ = mac.eq_str(&lossy_str);
        let _ = mac.eq_str(&mac_str);
        let _ = mac.is_zero();
        let _ = mac.as_bytes();
    }

    // 3. Subnet parsing and containment checks
    if let Ok(subnet) = IpSubnet::from_str(&lossy_str) {
        let _ = subnet.to_string();
        let dummy_v4 = IpAddr::V4(Ipv4Addr::new(192, 168, 1, 1));
        let dummy_v6 = IpAddr::V6(Ipv6Addr::new(0xfd00, 0, 0, 0, 0, 0, 0, 1));
        let _ = subnet.contains(dummy_v4);
        let _ = subnet.contains(dummy_v6);
        let _ = subnet.contains(subnet.addr);
    }

    // 4. Device identifier parsing and serialization
    if let Ok(dev_id) = DeviceIdentifier::from_str(&lossy_str) {
        let _ = dev_id.to_string();
        if let Ok(serialized) = serde_json::to_string(&dev_id) {
            let _ = serde_json::from_str::<DeviceIdentifier>(&serialized);
        }
    }

    // 5. Hostname sanitization
    let sanitized = Hostname::sanitize(&lossy_str);
    let host = Hostname::from(sanitized);
    let _ = host.display();

    // 6. IP classification functions
    if data.len() >= 4 {
        let v4 = Ipv4Addr::new(data[0], data[1], data[2], data[3]);
        let ip = IpAddr::V4(v4);
        let _ = classify_ip(&ip);
    }
    if data.len() >= 16 {
        let mut v6_octets = [0u8; 16];
        v6_octets.copy_from_slice(&data[..16]);
        let v6 = Ipv6Addr::from(v6_octets);
        let _ = classify_ipv6(&v6);
        let ip = IpAddr::V6(v6);
        let _ = classify_ip(&ip);
        let _ = is_ula(&v6);
    }
});
