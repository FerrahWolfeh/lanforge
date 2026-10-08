use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use lanforge_core::bus::{EventBus, LanforgeEvent, NetworkEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::AsyncService;
use lanforge_ra::{RaConfig, RaService};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::ra::{PrefixLifetime, PrefixSource, RAPrefix, RaServerConfig, RouterPriority};
use lanforge_types::system::ServiceState;
use lanforge_types::update::DeviceUpdate;
use tokio::time::timeout;

fn create_test_context() -> (LanforgeContext, Arc<EventBus>) {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus.clone(), state, None);

    ctx.set_target_interface_name("lan0".to_string());
    (ctx, bus)
}

#[tokio::test]
async fn test_ra_synthetic_full_lifecycle() {
    let (ctx, bus) = create_test_context();
    let mut net_sub = bus.subscribe_network();

    // 1. Configure RA prefix in Context
    let prefix = RAPrefix {
        source: PrefixSource::Static,
        address: Some("2001:db8:cafe::".to_string()),
        prefix_len: 64,
        on_link: true,
        autonomous: true,
        router_addr: false,
        valid_lifetime: PrefixLifetime::Secs(86400),
        preferred_lifetime: PrefixLifetime::Secs(14400),
    };

    ctx.update_ra_server_config(RaServerConfig {
        enabled: true,
        iface: Some("lan0".into()),
        managed: false,
        other_config: false,
        hop_limit: 64,
        priority: RouterPriority::Medium,
        max_interval_secs: 600,
        min_interval_secs: Some(200),
        lifetime_secs: Some(1800),
        reachable_time_ms: 0,
        retrans_timer_ms: 0,
        mtu: Some(1500),
        prefixes: vec![prefix],
        rdnss: vec![],
        dnssl: vec![],
    });

    let cfg = RaConfig::default();

    // 2. Initialize synthetic service
    let (handle, service) = RaService::synthetic(cfg, ctx.clone());
    assert!(service.is_synthetic());

    // 3. Spawn service task
    let mut service_clone = service.clone();
    let ctx_clone = ctx.clone();
    let serve_handle = tokio::spawn(async move { service_clone.serve(&ctx_clone).await });

    // 4. Verify initial startup multicast RA is emitted to synthetic handle
    let startup_ra = timeout(Duration::from_millis(500), handle.recv_ra())
        .await
        .expect("Timeout waiting for initial synthetic RA")
        .expect("RA channel closed unexpectedly");

    // Router Advertisement has ICMPv6 type = 134 (0x86)
    assert!(!startup_ra.is_empty());
    assert_eq!(startup_ra[0], 134, "Expected ICMPv6 Type 134 (Router Advertisement)");

    // Verify service state is Online
    assert_eq!(ctx.get_service_state("ra"), ServiceState::Online);

    // Verify status was updated in context
    let initial_status = ctx.with_state(|state| state.interfaces.ra_status.clone());
    assert!(initial_status.is_some());
    let st = initial_status.unwrap();
    assert_eq!(st.sent_multicast_ras, 1);
    assert_eq!(st.received_solicitations, 0);

    // 5. Register a client device in context so SLAAC trigger recognizes it
    let client_mac = MacAddr::parse("00:11:22:33:44:55").unwrap();
    let client_ip: Ipv6Addr = "fe80::211:22ff:fe33:4455".parse().unwrap();
    let _ = ctx.apply(DeviceUpdate::NdpSeen {
        mac: client_mac,
        ip: client_ip,
        is_active: true,
    });

    // 6. Simulate incoming Router Solicitation (RS) from client
    let rs_packet = vec![
        133, 0, 0, 0, // Type=133 (RS), Code=0, Checksum placeholder
        0, 0, 0, 0,   // Reserved
    ];
    let client_src = SocketAddrV6::new(client_ip, 0, 0, 0);
    handle.send_rs(rs_packet, client_src).await;

    // 7. Verify unicast RA response is received by client
    let unicast_ra = timeout(Duration::from_millis(500), handle.recv_ra())
        .await
        .expect("Timeout waiting for unicast synthetic RA response")
        .expect("RA channel closed unexpectedly");

    assert_eq!(unicast_ra[0], 134, "Expected unicast ICMPv6 RA response");

    // 8. Verify SLAAC passive discovery event was published on EventBus
    let rs_evt = timeout(Duration::from_millis(500), async {
        loop {
            if let Ok(event) = net_sub.recv().await
                && let LanforgeEvent::Network(NetworkEvent::RsReceived { mac }) = event.event
            {
                return mac;
            }
        }
    })
    .await
    .expect("Timeout waiting for NetworkEvent::RsReceived");

    assert_eq!(rs_evt, client_mac);

    // 9. Verify live status reflects the solicitation and response
    let updated_status = ctx.with_state(|state| state.interfaces.ra_status.clone()).unwrap();
    assert_eq!(updated_status.sent_multicast_ras, 1);
    assert_eq!(updated_status.sent_unicast_ras, 1);
    assert_eq!(updated_status.received_solicitations, 1);

    // 10. Clean shutdown
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let shutdown_res = timeout(Duration::from_millis(500), serve_handle).await;
    assert!(shutdown_res.is_ok());
}
