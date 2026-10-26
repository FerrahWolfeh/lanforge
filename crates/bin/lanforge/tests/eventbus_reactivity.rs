use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dhcproto::v4::{DhcpOption, Message, MessageType};
use dhcproto::{Encodable, Encoder};
use lanforge_core::bus::{
    AdminChange, DeviceEvent, EventBus, FirewallEvent, LanforgeEvent, NetworkChange, NetworkEvent,
    SystemEvent,
};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::{AsyncService, ServiceHandle};
use lanforge_dhcp::{Dhcpv4Config, Dhcpv4Service};
use lanforge_nft::NftService;
use lanforge_ra::{RaConfig, RaService};
use lanforge_traffic::TrafficService;
use lanforge_types::device::IPv4State;
use lanforge_types::events::network::PrefixChangeDetails;
use lanforge_types::events::pppoe::{PppoeEvent, PppoeSessionUp};
use lanforge_types::events::traffic::TrafficEvent;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dhcp::Dhcpv4Pool;
use lanforge_types::network::firewall::{
    DynamicPortRequest, FirewallConfig, FirewallMode, L4Protocol,
};
use lanforge_types::network::ra::{
    PrefixLifetime, PrefixSource, RAPrefix, RaServerConfig, RouterPriority,
};
use lanforge_types::network::traffic::{NicTuningConfig, SqmConfig, SqmDiffserv, TrafficConfig};
use lanforge_types::system::ServiceId;
use lanforge_types::update::LeaseTarget;
use tokio::time::timeout;

fn create_test_context() -> (LanforgeContext, Arc<EventBus>) {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus.clone(), state, None);

    ctx.update_firewall_config(FirewallConfig {
        enabled: true,
        mode: FirewallMode::Full,
        ..Default::default()
    });
    ctx.set_target_interface_name("lan0".to_string());
    (ctx, bus)
}

fn build_dhcp_packet(
    mac: MacAddr,
    msg_type: MessageType,
    requested_ip: Option<Ipv4Addr>,
    server_id: Option<Ipv4Addr>,
    hostname: Option<&str>,
) -> Vec<u8> {
    let mut msg = Message::new(
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        &mac.0,
    );
    msg.opts_mut().insert(DhcpOption::MessageType(msg_type));

    if let Some(req_ip) = requested_ip {
        msg.opts_mut()
            .insert(DhcpOption::RequestedIpAddress(req_ip));
    }
    if let Some(srv) = server_id {
        msg.opts_mut().insert(DhcpOption::ServerIdentifier(srv));
    }
    if let Some(host) = hostname {
        msg.opts_mut()
            .insert(DhcpOption::Hostname(host.to_string()));
    }

    let mut buf = Vec::new();
    let mut enc = Encoder::new(&mut buf);
    msg.encode(&mut enc).expect("Failed to encode test message");
    buf
}

// ===========================================================================
// Test 1: Firewall EventBus Reactivity
// ===========================================================================
#[tokio::test]
async fn test_firewall_eventbus_reactivity() {
    let (ctx, bus) = create_test_context();
    let mut fw_sub = bus.subscribe_firewall();

    let mut service = NftService::inert();
    let ctx_clone = ctx.clone();
    let handle = tokio::spawn(async move {
        let h = ServiceHandle::new(ServiceId::Nft, ctx_clone.clone());
        service.serve(&ctx_clone, &h).await
    });

    // Allow service to initialize
    tokio::time::sleep(Duration::from_millis(50)).await;
    while fw_sub.try_recv().is_ok() {}

    // 1. PortOpenRequested: Register dynamic port requirement (e.g. WebUI port 8080)
    ctx.register_service_port(DynamicPortRequest {
        service: "webui".into(),
        zone: "internal".into(),
        comment: Some("Test WebUI Port".into()),
        port: 8080,
        protocol: L4Protocol::Tcp,
    });

    let applied = timeout(Duration::from_millis(500), async {
        loop {
            if let Ok(evt) = fw_sub.recv().await
                && let LanforgeEvent::Firewall(FirewallEvent::RulesetApplied(summary)) = evt.event
            {
                return summary;
            }
        }
    })
    .await
    .expect("Timeout waiting for RulesetApplied on port open");
    assert!(applied.rules_count >= 1);

    // 2. PortReleaseRequested: Release dynamic port
    ctx.release_service_port("webui", 8080, L4Protocol::Tcp);

    let released_applied = timeout(Duration::from_millis(500), async {
        loop {
            if let Ok(evt) = fw_sub.recv().await
                && let LanforgeEvent::Firewall(FirewallEvent::RulesetApplied(summary)) = evt.event
            {
                return summary;
            }
        }
    })
    .await
    .expect("Timeout waiting for RulesetApplied on port release");
    assert_eq!(released_applied.rules_count, 0);

    // 3. RulesetChanged: In-place manual ruleset recompile
    let _ = bus.publish(LanforgeEvent::Firewall(FirewallEvent::RulesetChanged));
    let recompile_applied = timeout(Duration::from_millis(500), async {
        loop {
            if let Ok(evt) = fw_sub.recv().await
                && matches!(
                    evt.event,
                    LanforgeEvent::Firewall(FirewallEvent::RulesetApplied(_))
                )
            {
                return true;
            }
        }
    })
    .await
    .expect("Timeout waiting for RulesetApplied on RulesetChanged");
    assert!(recompile_applied);

    // 4. SystemEvent::ReloadConfig: Full reload trigger
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::ReloadConfig));
    let reload_applied = timeout(Duration::from_millis(500), async {
        loop {
            if let Ok(evt) = fw_sub.recv().await
                && matches!(
                    evt.event,
                    LanforgeEvent::Firewall(FirewallEvent::RulesetApplied(_))
                )
            {
                return true;
            }
        }
    })
    .await
    .expect("Timeout waiting for RulesetApplied on ReloadConfig");
    assert!(reload_applied);

    // Clean shutdown
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = timeout(Duration::from_millis(500), handle).await;
}

// ===========================================================================
// Test 2: Traffic EventBus Reactivity (SQM, WAN Session, In-Place Reconfiguration)
// ===========================================================================
#[tokio::test]
async fn test_traffic_eventbus_reactivity() {
    let (ctx, bus) = create_test_context();
    let mut traffic_sub = bus.subscribe_traffic();

    let cfg = TrafficConfig {
        tuning: NicTuningConfig {
            enabled: true,
            cpu_mask: "0-1".into(),
            ..Default::default()
        },
        sqm: SqmConfig {
            enabled: true,
            interface: "auto".into(),
            download_mbps: 100,
            upload_mbps: 50,
            diffserv: SqmDiffserv::Diffserv4,
            ingress_device: "ifb4lanforge".into(),
            ..Default::default()
        },
    };

    let mut service = TrafficService::inert(cfg);
    let ctx_clone = ctx.clone();
    let handle = tokio::spawn(async move {
        let h = ServiceHandle::new(ServiceId::Traffic, ctx_clone.clone());
        service.serve(&ctx_clone, &h).await
    });

    // Allow service to initialize and emit startup events
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 1. PppoeEvent::SessionUp -> Re-binds SQM to ppp0
    let session_up = PppoeSessionUp {
        interface: "ppp0".to_string(),
        ac_mac: None,
        ac_name: Some("AC-Test".into()),
        session_id: 42,
        mru: 1492,
        ipv4: Some(Ipv4Addr::new(100, 64, 1, 10)),
        ipv4_peer: Some(Ipv4Addr::new(100, 64, 1, 1)),
        dns: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
        ipv6_link_local: false,
    };
    let _ = bus.publish(LanforgeEvent::Pppoe(PppoeEvent::SessionUp(Box::new(
        session_up,
    ))));

    let bound_to_ppp0 = timeout(Duration::from_millis(500), async {
        loop {
            if let Ok(evt) = traffic_sub.recv().await
                && let LanforgeEvent::Traffic(ref te) = evt.event
                && let TrafficEvent::SqmApplied {
                    ref interface,
                    download_mbps,
                    upload_mbps,
                    ..
                } = **te
                && interface == "ppp0"
            {
                return (download_mbps, upload_mbps);
            }
        }
    })
    .await
    .expect("Timeout waiting for SqmApplied on ppp0");
    assert_eq!(bound_to_ppp0, (100, 50));

    // 2. TrafficEvent::RulesetChanged: In-place reconfiguration with updated limits
    ctx.update_traffic_config(TrafficConfig {
        tuning: NicTuningConfig {
            enabled: true,
            cpu_mask: "0-3".into(),
            ..Default::default()
        },
        sqm: SqmConfig {
            enabled: true,
            interface: "auto".into(),
            download_mbps: 300,
            upload_mbps: 150,
            diffserv: SqmDiffserv::Diffserv4,
            ingress_device: "ifb4lanforge".into(),
            ..Default::default()
        },
    });
    let _ = bus.publish(LanforgeEvent::Traffic(Box::new(
        TrafficEvent::RulesetChanged,
    )));

    let updated_sqm = timeout(Duration::from_millis(500), async {
        loop {
            if let Ok(evt) = traffic_sub.recv().await
                && let LanforgeEvent::Traffic(ref te) = evt.event
                && let TrafficEvent::SqmApplied {
                    ref interface,
                    download_mbps,
                    upload_mbps,
                    ..
                } = **te
                && interface == "ppp0"
                && download_mbps == 300
            {
                return (download_mbps, upload_mbps);
            }
        }
    })
    .await
    .expect("Timeout waiting for SqmApplied with 300 Mbps in-place");
    assert_eq!(updated_sqm, (300, 150));

    // 3. PppoeEvent::SessionDown -> Clears SQM on ppp0
    let _ = bus.publish(LanforgeEvent::Pppoe(PppoeEvent::SessionDown {
        reason: "Peer closed connection".into(),
    }));

    let sqm_cleared = timeout(Duration::from_millis(500), async {
        loop {
            if let Ok(evt) = traffic_sub.recv().await
                && let LanforgeEvent::Traffic(ref te) = evt.event
                && let TrafficEvent::SqmCleared { ref interface } = **te
                && interface == "ppp0"
            {
                return true;
            }
        }
    })
    .await
    .expect("Timeout waiting for SqmCleared on ppp0");
    assert!(sqm_cleared);

    // 4. SystemEvent::InterfaceReady: Absorbed without errors
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::InterfaceReady));
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Clean shutdown
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = timeout(Duration::from_millis(500), handle).await;
}

// ===========================================================================
// Test 3: RA EventBus Reactivity (Prefix Changes, Burst Triggers, In-Place Reload)
// ===========================================================================
#[tokio::test]
async fn test_ra_eventbus_reactivity() {
    let (ctx, bus) = create_test_context();

    let prefix = RAPrefix {
        source: PrefixSource::Static,
        address: Some("2001:db8:10::".into()),
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

    let (ra_handle, ra_trans) = lanforge_transport::Icmp6Transport::inert();
    let service = RaService::with_transport(RaConfig::default(), ctx.clone(), ra_trans);
    let mut service_clone = service.clone();
    let ctx_clone = ctx.clone();
    let handle = tokio::spawn(async move {
        let h = ServiceHandle::new(ServiceId::Ra, ctx_clone.clone());
        service_clone.serve(&ctx_clone, &h).await
    });

    // Initial startup multicast RA
    let initial_ra = timeout(Duration::from_millis(500), ra_handle.recv_payload())
        .await
        .expect("Timeout waiting for initial RA")
        .expect("RA channel closed");
    assert_eq!(initial_ra[0], 134);

    // 1. NetworkEvent::PrefixChanged -> Emits immediate RA burst
    let new_gua: Ipv6Addr = "2001:db8:20::".parse().unwrap();
    let _ = bus.publish(LanforgeEvent::Network(NetworkEvent::PrefixChanged(
        Box::new(PrefixChangeDetails {
            gua: Some(new_gua),
            ula: None,
            preferred: 14400,
            valid: 86400,
        }),
    )));

    let prefix_burst_ra = timeout(Duration::from_millis(500), ra_handle.recv_payload())
        .await
        .expect("Timeout waiting for prefix burst RA")
        .expect("RA channel closed");
    assert_eq!(prefix_burst_ra[0], 134);

    // 2. NetworkEvent::RaTriggerRequested -> Emits immediate RA burst
    let _ = bus.publish(LanforgeEvent::Network(NetworkEvent::RaTriggerRequested));
    let manual_burst_ra = timeout(Duration::from_millis(500), ra_handle.recv_payload())
        .await
        .expect("Timeout waiting for manual burst RA")
        .expect("RA channel closed");
    assert_eq!(manual_burst_ra[0], 134);

    // 3. SystemEvent::ConfigRaChanged: In-place parameters reload
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::ConfigRaChanged));
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Clean shutdown
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = timeout(Duration::from_millis(500), handle).await;
}

// ===========================================================================
// Test 4: DHCP EventBus Reactivity (Lease Renew/Release, Admin/Network Events)
// ===========================================================================
#[tokio::test]
async fn test_dhcp_eventbus_reactivity() {
    let (ctx, bus) = create_test_context();

    let pool = Dhcpv4Pool {
        name: Some("Reactive Test Scope".into()),
        range_start: Ipv4Addr::new(192, 168, 1, 100),
        range_end: Ipv4Addr::new(192, 168, 1, 200),
        lease_time: Some(3600),
        router: Some(Ipv4Addr::new(192, 168, 1, 1)),
        dns_servers: vec![Ipv4Addr::new(192, 168, 1, 1)],
        domain_name: Some("lan".into()),
        ..Default::default()
    };
    ctx.update_dhcp_v4_pools(vec![pool.clone()]);

    let dhcp_cfg = Dhcpv4Config {
        enabled: true,
        iface: "lan0".into(),
        server_id: Ipv4Addr::new(192, 168, 1, 1),
        lease_time: 3600,
        router: Ipv4Addr::new(192, 168, 1, 1),
        subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
        dns: vec![Ipv4Addr::new(192, 168, 1, 1)],
        domain_name: Some("lan".into()),
        pools: vec![pool],
        ..Default::default()
    };

    let (dhcp_handle, dhcp_trans) = lanforge_dhcp::Dhcpv4Transport::inert();
    let service = Dhcpv4Service::with_transport(dhcp_cfg.clone(), ctx.clone(), dhcp_trans);
    let mut service_clone = service.clone();
    let ctx_clone = ctx.clone();
    let handle = tokio::spawn(async move {
        let h = ServiceHandle::new(ServiceId::Dhcp4, ctx_clone.clone());
        service_clone.serve(&ctx_clone, &h).await
    });

    // Allow service to initialize
    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_mac = MacAddr([0x00, 0xAA, 0xBB, 0xCC, 0xDD, 0xEE]);
    let client_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 68);

    // Initial DORA to obtain lease
    let discover = build_dhcp_packet(
        client_mac,
        MessageType::Discover,
        None,
        None,
        Some("test-device"),
    );
    dhcp_handle.send_packet(discover, client_src).await;

    let offer = timeout(Duration::from_millis(500), dhcp_handle.recv_reply())
        .await
        .expect("Timeout waiting for OFFER")
        .expect("Channel closed");
    let assigned_ip = offer.message().unwrap().yiaddr();

    let request = build_dhcp_packet(
        client_mac,
        MessageType::Request,
        Some(assigned_ip),
        Some(dhcp_cfg.server_id),
        Some("test-device"),
    );
    dhcp_handle.send_packet(request, client_src).await;

    let ack = timeout(Duration::from_millis(500), dhcp_handle.recv_reply())
        .await
        .expect("Timeout waiting for ACK")
        .expect("Channel closed");
    assert_eq!(ack.message().unwrap().yiaddr(), assigned_ip);

    // Verify lease is registered
    let dev = ctx
        .get_device(&client_mac)
        .expect("Device should be registered");
    assert!(matches!(dev.v4, IPv4State::Dynamic(_)));

    // 1. NetworkEvent::LeaseRenewRequested -> Triggers FORCERENEW packet from server
    let _ = bus.publish(LanforgeEvent::Network(NetworkEvent::LeaseRenewRequested {
        mac: client_mac,
        target: Some(LeaseTarget::V4),
    }));

    let forcerenew_reply = timeout(Duration::from_millis(500), dhcp_handle.recv_reply())
        .await
        .expect("Timeout waiting for FORCERENEW reply")
        .expect("Channel closed");
    let forcerenew_msg = forcerenew_reply.message().expect("Decode FORCERENEW");
    assert_eq!(
        forcerenew_msg
            .opts()
            .get(dhcproto::v4::OptionCode::MessageType),
        Some(&DhcpOption::MessageType(MessageType::ForceRenew))
    );

    // 2. NetworkEvent::LeaseReleaseRequested -> Frees lease in pool and context
    let _ = bus.publish(LanforgeEvent::Network(
        NetworkEvent::LeaseReleaseRequested {
            mac: client_mac,
            target: Some(LeaseTarget::V4),
        },
    ));

    // Allow event processing
    tokio::time::sleep(Duration::from_millis(50)).await;
    let dev_after_release = ctx
        .get_device(&client_mac)
        .expect("Device still in registry");
    assert!(matches!(dev_after_release.v4, IPv4State::None));

    // 3. DeviceEvent::AdminUpdate (AdminChange::V4StaticChanged) -> Reserves static IP in pool
    let static_ip = Ipv4Addr::new(192, 168, 1, 150);
    let _ = bus.publish(LanforgeEvent::Device(DeviceEvent::AdminUpdate {
        mac: client_mac,
        hostname: Some("static-dev".into()),
        change: Box::new(AdminChange::V4StaticChanged {
            ip: Some(static_ip),
        }),
    }));
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 4. DeviceEvent::NetworkUpdate (NetworkChange::IpDeleted) -> Releases IP in pool
    let _ = bus.publish(LanforgeEvent::Device(DeviceEvent::NetworkUpdate {
        mac: client_mac,
        hostname: Some("static-dev".into()),
        change: Box::new(NetworkChange::IpDeleted {
            ip: IpAddr::V4(static_ip),
        }),
    }));
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 5. SystemEvent::ConfigDhcpOptionsChanged: Absorbed in-place
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::ConfigDhcpOptionsChanged));
    tokio::time::sleep(Duration::from_millis(50)).await;

    // Clean shutdown
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = timeout(Duration::from_millis(500), handle).await;
}

// ===========================================================================
// Test 5: Cross-Domain WAN Transition Cascade & Service Isolation
// ===========================================================================
#[tokio::test]
async fn test_cross_domain_wan_transition_cascade() {
    let (ctx, bus) = create_test_context();
    let mut traffic_sub = bus.subscribe_traffic();
    let mut fw_sub = bus.subscribe_firewall();

    // Setup configurations
    let dhcp_pool = Dhcpv4Pool {
        range_start: Ipv4Addr::new(192, 168, 1, 100),
        range_end: Ipv4Addr::new(192, 168, 1, 200),
        ..Default::default()
    };
    ctx.update_dhcp_v4_pools(vec![dhcp_pool.clone()]);
    let dhcp_cfg = Dhcpv4Config {
        enabled: true,
        iface: "lan0".into(),
        pools: vec![dhcp_pool],
        ..Default::default()
    };

    let ra_prefix = RAPrefix {
        source: PrefixSource::Static,
        address: Some("2001:db8:30::".into()),
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
        prefixes: vec![ra_prefix],
        ..Default::default()
    });

    let traffic_cfg = TrafficConfig {
        tuning: NicTuningConfig {
            enabled: true,
            cpu_mask: "0-1".into(),
            ..Default::default()
        },
        sqm: SqmConfig {
            enabled: true,
            interface: "auto".into(),
            download_mbps: 200,
            upload_mbps: 100,
            diffserv: SqmDiffserv::Diffserv4,
            ingress_device: "ifb4lanforge".into(),
            ..Default::default()
        },
    };

    let mut nft_service = NftService::inert();
    let mut traffic_service = TrafficService::inert(traffic_cfg);
    let (_ra_handle, ra_trans) = lanforge_transport::Icmp6Transport::inert();
    let mut ra_service = RaService::with_transport(RaConfig::default(), ctx.clone(), ra_trans);
    let (_dhcp_handle, dhcp_trans) = lanforge_dhcp::Dhcpv4Transport::inert();
    let mut dhcp_service = Dhcpv4Service::with_transport(dhcp_cfg, ctx.clone(), dhcp_trans);

    let c1 = ctx.clone();
    let t_nft = tokio::spawn(async move {
        let h = ServiceHandle::new(ServiceId::Nft, c1.clone());
        nft_service.serve(&c1, &h).await
    });
    let c2 = ctx.clone();
    let t_traffic = tokio::spawn(async move {
        let h = ServiceHandle::new(ServiceId::Traffic, c2.clone());
        traffic_service.serve(&c2, &h).await
    });
    let c3 = ctx.clone();
    let t_ra = tokio::spawn(async move {
        let h = ServiceHandle::new(ServiceId::Ra, c3.clone());
        ra_service.serve(&c3, &h).await
    });
    let c4 = ctx.clone();
    let t_dhcp = tokio::spawn(async move {
        let h = ServiceHandle::new(ServiceId::Dhcp4, c4.clone());
        dhcp_service.serve(&c4, &h).await
    });

    // Allow services to initialize
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Trigger PPPoE WAN Session Up
    let session_up = PppoeSessionUp {
        interface: "ppp0".to_string(),
        ac_mac: None,
        ac_name: Some("BRAS-WAN".into()),
        session_id: 101,
        mru: 1492,
        ipv4: Some(Ipv4Addr::new(203, 0, 113, 2)),
        ipv4_peer: Some(Ipv4Addr::new(203, 0, 113, 1)),
        dns: vec![IpAddr::V4(Ipv4Addr::new(8, 8, 8, 8))],
        ipv6_link_local: true,
    };
    let _ = bus.publish(LanforgeEvent::Pppoe(PppoeEvent::SessionUp(Box::new(
        session_up,
    ))));

    // 1. Verify TrafficService binds SQM to ppp0
    let traffic_bound = timeout(Duration::from_millis(500), async {
        loop {
            if let Ok(evt) = traffic_sub.recv().await
                && let LanforgeEvent::Traffic(ref te) = evt.event
                && let TrafficEvent::SqmApplied { ref interface, .. } = **te
                && interface == "ppp0"
            {
                return true;
            }
        }
    })
    .await
    .expect("TrafficService must bind SQM to ppp0");
    assert!(traffic_bound);

    // 2. Verify NftService binds WAN to ppp0 and recompiles ruleset in inert mode
    let fw_bound = timeout(Duration::from_millis(500), async {
        loop {
            if let Ok(evt) = fw_sub.recv().await
                && let LanforgeEvent::Firewall(FirewallEvent::RulesetApplied(summary)) = evt.event
                && summary.wan_iface == Some("ppp0".into())
            {
                return true;
            }
        }
    })
    .await
    .expect("NftService must recompile ruleset with wan_iface=ppp0");
    assert!(fw_bound);

    // 3. Verify Golden Rule of Isolation: RA and DHCP remain Online and unaffected
    assert_eq!(
        ctx.get_service_state(ServiceId::Ra),
        lanforge_types::system::ServiceState::Online
    );
    assert_eq!(
        ctx.get_service_state(ServiceId::Dhcp4),
        lanforge_types::system::ServiceState::Online
    );

    // 4. Clean Shutdown across all 4 services
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let shutdown = timeout(Duration::from_millis(800), async {
        let _ = tokio::join!(t_nft, t_traffic, t_ra, t_dhcp);
    })
    .await;
    assert!(
        shutdown.is_ok(),
        "All services must shut down cleanly within timeout"
    );
}
