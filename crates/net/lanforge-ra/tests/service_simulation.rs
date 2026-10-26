use std::net::{Ipv6Addr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use lanforge_core::bus::{EventBus, LanforgeEvent, NetworkEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::{AsyncService, ServiceHandle};
use lanforge_ra::{RaConfig, RaService};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::ra::{
    PrefixLifetime, PrefixSource, RAPrefix, RaServerConfig, RouterPriority,
};
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
async fn test_ra_inert_full_lifecycle() {
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
        deprecate_on_renumber: true,
    });

    let cfg = RaConfig::default();

    // 2. Initialize service with inert transport
    let (handle, transport) = lanforge_transport::Icmp6Transport::inert();
    assert!(transport.is_inert());
    let service = RaService::with_transport(cfg, ctx.clone(), transport);

    // 3. Spawn service task
    let mut service_clone = service.clone();
    let ctx_clone = ctx.clone();
    let serve_handle = tokio::spawn(async move {
        let h = ServiceHandle::new(lanforge_types::system::ServiceId::Ra, ctx_clone.clone());
        service_clone.serve(&ctx_clone, &h).await
    });

    // 4. Verify initial startup multicast RA is emitted to inert handle
    let startup_ra = timeout(Duration::from_millis(500), handle.recv_payload())
        .await
        .expect("Timeout waiting for initial inert RA")
        .expect("RA channel closed unexpectedly");

    // Router Advertisement has ICMPv6 type = 134 (0x86)
    assert!(!startup_ra.is_empty());
    assert_eq!(
        startup_ra[0], 134,
        "Expected ICMPv6 Type 134 (Router Advertisement)"
    );

    // Verify service state is Online
    assert_eq!(
        ctx.get_service_state(lanforge_types::system::ServiceId::Ra),
        ServiceState::Online
    );

    // Verify status was updated in context
    let initial_status = ctx.ra_status();
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
        0, 0, 0, 0, // Reserved
    ];
    let client_src = SocketAddrV6::new(client_ip, 0, 0, 0);
    handle.inject(rs_packet, client_src).await;

    // 7. Verify unicast RA response is received by client
    let unicast_ra = timeout(Duration::from_millis(500), handle.recv_payload())
        .await
        .expect("Timeout waiting for unicast inert RA response")
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
    let updated_status = ctx.ra_status().unwrap();
    assert_eq!(updated_status.sent_multicast_ras, 1);
    assert_eq!(updated_status.sent_unicast_ras, 1);
    assert_eq!(updated_status.received_solicitations, 1);

    // 10. Clean shutdown
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let shutdown_res = timeout(Duration::from_millis(500), serve_handle).await;
    assert!(shutdown_res.is_ok());
}

#[tokio::test]
async fn test_ra_prefix_deprecation_on_renumber() {
    use lanforge_types::network::snapshot::{Ipv6Net, WanSnapshot, WanState};

    let (ctx, bus) = create_test_context();

    // 1. Configure RA with dynamic GUA prefix
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
        prefixes: vec![RAPrefix::gua_dynamic()],
        rdnss: vec![],
        dnssl: vec![],
        deprecate_on_renumber: true,
    });

    let initial_p1: Ipv6Addr = "2001:db8:1000::1".parse().unwrap();
    ctx.set_wan_snapshot(WanSnapshot {
        state: WanState::Up,
        ifindex: Some(10),
        ifname: Some("ppp0".into()),
        v4: None,
        v6_prefixes: vec![Ipv6Net {
            addr: initial_p1,
            prefix_len: 64,
        }]
        .into(),
        generation: 1,
    });

    let cfg = RaConfig::default();
    let (handle, transport) = lanforge_transport::Icmp6Transport::inert();
    let service = RaService::with_transport(cfg, ctx.clone(), transport);

    let mut service_clone = service.clone();
    let ctx_clone = ctx.clone();
    let serve_handle = tokio::spawn(async move {
        let h = ServiceHandle::new(lanforge_types::system::ServiceId::Ra, ctx_clone.clone());
        service_clone.serve(&ctx_clone, &h).await
    });

    // 2. Receive initial RA
    let initial_ra = timeout(Duration::from_millis(500), handle.recv_payload())
        .await
        .expect("Timeout waiting for initial RA")
        .expect("RA channel closed");
    assert_eq!(initial_ra[0], 134);

    // 3. Renumber WAN prefix to 2001:db8:2000::1
    let new_p2: Ipv6Addr = "2001:db8:2000::1".parse().unwrap();
    ctx.set_wan_snapshot(WanSnapshot {
        state: WanState::Up,
        ifindex: Some(10),
        ifname: Some("ppp0".into()),
        v4: None,
        v6_prefixes: vec![Ipv6Net {
            addr: new_p2,
            prefix_len: 64,
        }]
        .into(),
        generation: 2,
    });

    // 4. Renumbering triggers immediate burst RA within 1 second
    let burst_ra = timeout(Duration::from_millis(1000), handle.recv_payload())
        .await
        .expect("Timeout waiting for burst RA after renumbering")
        .expect("RA channel closed");
    assert_eq!(burst_ra[0], 134);

    // Parse prefix options in burst_ra
    let mut offset = 16; // skip 16B fixed header + SLLAO
    let mut prefixes: Vec<(Ipv6Addr, u32, u32)> = Vec::new();
    while offset + 8 <= burst_ra.len() {
        let opt_type = burst_ra[offset];
        let opt_len = burst_ra[offset + 1] as usize * 8;
        if opt_len == 0 || offset + opt_len > burst_ra.len() {
            break;
        }
        if opt_type == 3 && opt_len >= 32 {
            let valid_lt = u32::from_be_bytes(burst_ra[offset + 4..offset + 8].try_into().unwrap());
            let pref_lt = u32::from_be_bytes(burst_ra[offset + 8..offset + 12].try_into().unwrap());
            let addr_bytes: [u8; 16] = burst_ra[offset + 16..offset + 32].try_into().unwrap();
            let addr = Ipv6Addr::from(addr_bytes);
            prefixes.push((addr, valid_lt, pref_lt));
        }
        offset += opt_len;
    }

    let expected_new: Ipv6Addr = "2001:db8:2000::".parse().unwrap();
    let expected_old: Ipv6Addr = "2001:db8:1000::".parse().unwrap();

    // Must contain the new prefix (preferred > 0, valid > 0)
    let new_opt = prefixes.iter().find(|(addr, _, _)| *addr == expected_new);
    assert!(
        new_opt.is_some(),
        "New prefix should be advertised in burst RA"
    );
    let (_, new_valid, new_pref) = new_opt.unwrap();
    assert!(*new_valid > 0);
    assert!(*new_pref > 0);

    // Must contain the deprecated old prefix (RFC 4862 §5.5.3e: preferred = 0, valid <= 7200)
    let dep_opt = prefixes.iter().find(|(addr, _, _)| *addr == expected_old);
    assert!(
        dep_opt.is_some(),
        "Old prefix should be deprecated in burst RA"
    );
    let (_, dep_valid, dep_pref) = dep_opt.unwrap();
    assert_eq!(
        *dep_pref, 0,
        "Deprecated prefix must have preferred_lifetime = 0"
    );
    assert!(
        *dep_valid <= 7200 && *dep_valid > 0,
        "Deprecated prefix valid_lifetime must be capped at 7200s"
    );

    // Clean shutdown
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let shutdown_res = timeout(Duration::from_millis(500), serve_handle).await;
    assert!(shutdown_res.is_ok());
}
