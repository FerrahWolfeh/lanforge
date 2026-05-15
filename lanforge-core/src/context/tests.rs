use crate::bus::EventBus;
use crate::context::LanforgeContext;
use crate::context::state::State;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::update::DeviceUpdate;
use std::sync::Arc;

#[test]
fn test_topology_update() {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus, state, None);

    let mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let parent_mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    let port = "Gi0/1".to_string();

    // 1. Apply topology update
    let changed = ctx.apply(DeviceUpdate::TopologyUpdated {
        mac,
        parent_mac: Some(parent_mac),
        port: Some(port.clone()),
        ifindex: 1,
    });

    assert!(changed);

    // 2. Verify state
    let dev = ctx.get_device(&mac).expect("Device should exist");
    let topo = dev.topology.as_ref().expect("Topology should be present");
    assert_eq!(topo.parent_mac, Some(parent_mac));
    assert_eq!(topo.port, Some(port));
    assert_eq!(topo.local_ifindex, 1);

    // 3. Apply same update, should not change
    let changed = ctx.apply(DeviceUpdate::TopologyUpdated {
        mac,
        parent_mac: Some(parent_mac),
        port: Some("Gi0/1".to_string()),
        ifindex: 1,
    });
    assert!(!changed);

    // 4. Update port
    let changed = ctx.apply(DeviceUpdate::TopologyUpdated {
        mac,
        parent_mac: Some(parent_mac),
        port: Some("Gi0/2".to_string()),
        ifindex: 1,
    });
    assert!(changed);
    let dev = ctx.get_device(&mac).expect("Device should exist");
    assert_eq!(
        dev.topology.as_ref().unwrap().port,
        Some("Gi0/2".to_string())
    );
}
