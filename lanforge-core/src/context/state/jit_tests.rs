use crate::bus::EventBus;
use crate::context::LanforgeContext;
use crate::context::state::DeviceUpdate;
use lanforge_types::device::{Device, Origin};
use lanforge_types::identifiers::MacAddr;
use std::sync::Arc;
use std::time::{Duration, SystemTime};

fn setup() -> LanforgeContext {
    let bus = Arc::new(EventBus::new());
    LanforgeContext::new(bus, crate::context::state::State::new(), None)
}

#[test]
fn test_lazy_indexing_and_jit_promotion() {
    let ctx = setup();

    // 1. Disable indexing (simulating initial load)
    ctx.set_indexing_enabled(false);

    let mac = MacAddr::parse("aa:bb:cc:dd:ee:ff").unwrap();
    let hostname = "test-device";

    // Create a device update
    let update = DeviceUpdate::DhcpHostnameHint {
        mac,
        hostname: hostname.to_string(),
    };

    // Apply update - it should NOT be indexed in name_index because indexing is disabled
    let _ = ctx.apply(update);

    assert!(ctx.read().devices.contains_key(&mac));
    assert!(!ctx.read().indices.name_index.contains_key(hostname));

    // 2. Perform JIT lookup
    let found_mac = ctx.find_mac_by_hostname_jit(hostname, None);

    // Should find the mac
    assert_eq!(found_mac, Some(mac));

    // Should NOW be promoted to the index
    assert_eq!(ctx.read().indices.name_index.get(hostname), Some(&mac));
}

#[test]
fn test_last_seen_heuristic() {
    let ctx = setup();
    ctx.set_indexing_enabled(false);

    let mac = MacAddr::parse("11:22:33:44:55:66").unwrap();
    let hostname = "old-device";

    // Insert device directly with an old last_seen
    let mut dev = Device::new(mac);
    dev.hostname.name = hostname.to_string();
    // 10 days ago
    dev.last_seen = SystemTime::now() - Duration::from_hours(240);

    ctx.insert_device(mac, dev);

    // JIT lookup with 7 day threshold should FAIL
    let threshold = Duration::from_hours(168);
    let found_mac = ctx.find_mac_by_hostname_jit(hostname, Some(threshold));
    assert_eq!(found_mac, None);

    // JIT lookup with 15 day threshold should SUCCEED
    let threshold = Duration::from_hours(360);
    let found_mac = ctx.find_mac_by_hostname_jit(hostname, Some(threshold));
    assert_eq!(found_mac, Some(mac));
}

#[test]
fn test_static_devices_always_indexed() {
    let ctx = setup();

    // Disable indexing
    ctx.set_indexing_enabled(false);

    let mac = MacAddr::parse("cc:cc:cc:cc:cc:cc").unwrap();
    let hostname = "static-device";

    // Create a device with Static origin
    let mut dev = Device::new(mac);
    dev.hostname.name = hostname.to_string();
    dev.origin = Origin::Static;

    // insert_device calls index_device
    ctx.insert_device(mac, dev);

    // Should be in index IMMEDIATELY even if indexing_enabled is false
    assert_eq!(ctx.read().indices.name_index.get(hostname), Some(&mac));
}

#[test]
fn test_jit_lookup_case_insensitive() {
    let ctx = setup();
    ctx.set_indexing_enabled(false);

    let mac = MacAddr::parse("dd:dd:dd:dd:dd:dd").unwrap();
    let hostname = "Mixed-Case-Host";

    let mut dev = Device::new(mac);
    dev.hostname.name = hostname.to_string();
    ctx.insert_device(mac, dev);

    // Lookup with lowercase
    let found_mac = ctx.find_mac_by_hostname_jit("mixed-case-host", None);
    assert_eq!(found_mac, Some(mac));

    // Lookup with different casing
    let found_mac = ctx.find_mac_by_hostname_jit("MIXED-CASE-HOST", None);
    assert_eq!(found_mac, Some(mac));
}
