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

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_core_state_concurrency_stress() {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus, state, None);

    let mut write_tasks = Vec::new();
    for t_idx in 0..50 {
        let ctx = ctx.clone();
        write_tasks.push(tokio::spawn(async move {
            for i in 0..100 {
                let mac_bytes = [0x00, 0x11, 0x22, 0x33, t_idx as u8, i as u8];
                let mac = MacAddr(mac_bytes);
                let _ = ctx.apply(DeviceUpdate::TopologyUpdated {
                    mac,
                    parent_mac: Some(MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF])),
                    port: Some(format!("Gi0/{i}")),
                    ifindex: 1,
                });
                tokio::task::yield_now().await;
            }
        }));
    }

    let mut read_tasks = Vec::new();
    for _ in 0..50 {
        let ctx = ctx.clone();
        read_tasks.push(tokio::spawn(async move {
            for _ in 0..100 {
                let devices = ctx.all_devices();
                for dev in devices {
                    let _mac = dev.mac;
                    let _topo = dev.topology.clone();
                }
                let _ = ctx.get_device(&MacAddr([0x00, 0x11, 0x22, 0x33, 0, 0]));
                tokio::task::yield_now().await;
            }
        }));
    }

    // Wait for all writers and readers
    for t in write_tasks {
        t.await.unwrap();
    }
    for t in read_tasks {
        t.await.unwrap();
    }

    // Verify all 5000 devices were added
    let devices = ctx.all_devices();
    assert_eq!(devices.len(), 5000);
}
