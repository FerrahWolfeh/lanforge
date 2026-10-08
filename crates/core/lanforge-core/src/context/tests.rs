use crate::bus::EventBus;
use crate::context::LanforgeContext;
use crate::context::state::State;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::update::DeviceUpdate;
use std::sync::Arc;

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_core_state_concurrency_stress() {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus, state, None);

    let mut write_tasks = Vec::new();
    for t_idx in 0u8..50 {
        let ctx = ctx.clone();
        write_tasks.push(tokio::spawn(async move {
            for i in 0u8..100 {
                let mac_bytes = [0x00, 0x11, 0x22, 0x33, t_idx, i];
                let mac = MacAddr(mac_bytes);
                let _ = ctx.apply(DeviceUpdate::DhcpHostnameHint {
                    mac,
                    hostname: format!("host-{i}"),
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
                    let _hostname = dev.hostname.name.clone();
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

#[tokio::test]
async fn test_wait_for_service_dependency() {
    use crate::bus::{LanforgeEvent, SystemEvent};
    use crate::service::ServiceDependency;
    use lanforge_types::system::ServiceState;

    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus.clone(), state, None);

    // 1. When already online, wait_for_dependency should return Ok(()) immediately
    ctx.set_service_state("dns", ServiceState::Online);
    let res = ctx
        .wait_for_dependency(ServiceDependency::Service("dns"))
        .await;
    assert!(res.is_ok());

    // 2. When not online, it should wait for ServiceReady event
    let ctx_clone = ctx.clone();
    let wait_handle = tokio::spawn(async move {
        ctx_clone
            .wait_for_dependency(ServiceDependency::Service("db"))
            .await
    });

    std::thread::sleep(std::time::Duration::from_millis(10));
    ctx.set_service_state("db", ServiceState::Online);
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::ServiceReady {
        name: "db".to_string(),
    }));

    let res = wait_handle.await.unwrap();
    assert!(res.is_ok());
}

#[tokio::test]
async fn test_dynamic_pppoe_config() {
    use lanforge_types::network::pppoe::PppoeConfig;

    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus, state, None);

    assert!(ctx.get_pppoe_config().is_none());

    let mut cfg = PppoeConfig::default();
    cfg.username = "test_user".to_string();
    cfg.wan_iface = "eth42".to_string();

    ctx.update_pppoe_config(cfg);

    let retrieved = ctx.get_pppoe_config();
    assert!(retrieved.is_some());
    let retrieved = retrieved.unwrap();
    assert_eq!(retrieved.username, "test_user");
    assert_eq!(retrieved.wan_iface, "eth42");
}
