use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr, SocketAddrV6};
use std::sync::Arc;
use std::time::Duration;

use dhcproto::v4::{DhcpOption, Message, MessageType};
use dhcproto::{Encodable, Encoder};
use lanforge_core::bus::{EventBus, FirewallEvent, LanforgeEvent, NetworkEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::{AsyncService, ServiceHandle};
use lanforge_dhcp::{Dhcpv4Config, Dhcpv4Service};
use lanforge_nft::NftService;
use lanforge_ra::{RaConfig, RaService};
use lanforge_traffic::TrafficService;
use lanforge_types::device::IPv4State;
use lanforge_types::events::pppoe::{PppoeEvent, PppoeSessionUp};
use lanforge_types::events::traffic::TrafficEvent;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dhcp::Dhcpv4Pool;
use lanforge_types::network::ra::{PrefixLifetime, PrefixSource, RAPrefix, RaServerConfig, RouterPriority};
use lanforge_types::network::traffic::{NicTuningConfig, SqmConfig, SqmDiffserv, TrafficConfig};
use lanforge_types::system::{ServiceId, ServiceState};
use lanforge_types::update::DeviceUpdate;
use tokio::time::timeout;

fn create_test_context() -> (LanforgeContext, Arc<EventBus>) {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus.clone(), state, None);

    ctx.update_firewall_config(lanforge_types::network::firewall::FirewallConfig {
        enabled: true,
        mode: lanforge_types::network::firewall::FirewallMode::Full,
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
        msg.opts_mut().insert(DhcpOption::RequestedIpAddress(req_ip));
    }
    if let Some(srv) = server_id {
        msg.opts_mut().insert(DhcpOption::ServerIdentifier(srv));
    }
    if let Some(host) = hostname {
        msg.opts_mut().insert(DhcpOption::Hostname(host.to_string()));
    }

    let mut buf = Vec::new();
    let mut enc = Encoder::new(&mut buf);
    msg.encode(&mut enc).expect("Failed to encode test message");
    buf
}

#[tokio::test]
async fn test_rootless_pipeline_e2e() {
    let (ctx, bus) = create_test_context();

    // Subscribe to domain topics before services start
    let mut fw_sub = bus.subscribe_firewall();
    let mut traffic_sub = bus.subscribe_traffic();
    let mut net_sub = bus.subscribe_network();

    // -----------------------------------------------------------------------
    // 1. Configure Services in Context
    // -----------------------------------------------------------------------

    // DHCP pool setup
    let dhcp_pool = Dhcpv4Pool {
        name: Some("E2E Rootless Pool".to_string()),
        range_start: Ipv4Addr::new(192, 168, 1, 100),
        range_end: Ipv4Addr::new(192, 168, 1, 200),
        lease_time: Some(3600),
        router: Some(Ipv4Addr::new(192, 168, 1, 1)),
        dns_servers: vec![Ipv4Addr::new(192, 168, 1, 1)],
        domain_name: Some("lan".to_string()),
        ..Default::default()
    };
    ctx.update_dhcp_v4_pools(vec![dhcp_pool.clone()]);

    let dhcp_cfg = Dhcpv4Config {
        enabled: true,
        iface: "lan0".into(),
        server_id: Ipv4Addr::new(192, 168, 1, 1),
        lease_time: 3600,
        router: Ipv4Addr::new(192, 168, 1, 1),
        subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
        dns: vec![Ipv4Addr::new(192, 168, 1, 1)],
        domain_name: Some("lan".to_string()),
        pools: vec![dhcp_pool],
        ..Default::default()
    };

    // RA prefix setup
    let ra_prefix = RAPrefix {
        source: PrefixSource::Static,
        address: Some("2001:db8:rootless::".to_string()),
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
        prefixes: vec![ra_prefix],
        rdnss: vec![],
        dnssl: vec![],
    });

    let traffic_cfg = TrafficConfig {
        tuning: NicTuningConfig {
            enabled: true,
            cpu_mask: "0-3".into(),
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

    // -----------------------------------------------------------------------
    // 2. Initialize Services in Rootless / Inert / Synthetic Modes
    // -----------------------------------------------------------------------
    let mut nft_service = NftService::inert();
    assert!(nft_service.is_inert());

    let mut traffic_service = TrafficService::inert(traffic_cfg);
    assert!(traffic_service.is_inert());

    let (ra_handle, ra_trans) = lanforge_transport::Icmp6Transport::inert();
    let mut ra_service = RaService::with_transport(RaConfig::default(), ctx.clone(), ra_trans);

    let (dhcp_handle, dhcp_trans) = lanforge_dhcp::Dhcpv4Transport::inert();
    let mut dhcp_service = Dhcpv4Service::with_transport(dhcp_cfg.clone(), ctx.clone(), dhcp_trans);

    // -----------------------------------------------------------------------
    // 3. Spawn All Services as Background Async Tasks
    // -----------------------------------------------------------------------
    let ctx_nft = ctx.clone();
    let nft_task = tokio::spawn(async move {
        let h = ServiceHandle::new(ServiceId::Nft, ctx_nft.clone());
        nft_service.serve(&ctx_nft, &h).await
    });

    let ctx_traffic = ctx.clone();
    let traffic_task = tokio::spawn(async move {
        let h = ServiceHandle::new(ServiceId::Traffic, ctx_traffic.clone());
        traffic_service.serve(&ctx_traffic, &h).await
    });

    let ctx_ra = ctx.clone();
    let ra_task = tokio::spawn(async move {
        let h = ServiceHandle::new(ServiceId::Ra, ctx_ra.clone());
        ra_service.serve(&ctx_ra, &h).await
    });

    let ctx_dhcp = ctx.clone();
    let dhcp_task = tokio::spawn(async move {
        let h = ServiceHandle::new(ServiceId::Dhcp4, ctx_dhcp.clone());
        dhcp_service.serve(&ctx_dhcp, &h).await
    });

    // Allow services to initialize and subscribe to domain events
    tokio::time::sleep(Duration::from_millis(60)).await;

    // Verify all active services transitioned to Online
    assert_eq!(ctx.get_service_state(ServiceId::Nft), ServiceState::Online);
    assert_eq!(ctx.get_service_state(ServiceId::Traffic), ServiceState::Online);
    assert_eq!(ctx.get_service_state(ServiceId::Ra), ServiceState::Online);
    assert_eq!(ctx.get_service_state(ServiceId::Dhcp4), ServiceState::Online);

    // -----------------------------------------------------------------------
    // 4. Verify Initial Service Outputs & Events
    // -----------------------------------------------------------------------

    // RA Service emits initial unsolicited multicast RA
    let initial_ra = timeout(Duration::from_millis(500), ra_handle.recv_payload())
        .await
        .expect("Timeout waiting for initial RA")
        .expect("RA channel closed");
    assert_eq!(initial_ra[0], 134, "Expected ICMPv6 RA Type 134");

    // Traffic Service emitted TuningApplied + SqmApplied (fallback lan0)
    let _ = timeout(Duration::from_millis(500), traffic_sub.recv())
        .await
        .expect("Timeout waiting for initial traffic event");

    // -----------------------------------------------------------------------
    // 5. Client Joins IPv4: DHCP DORA Cycle in Memory
    // -----------------------------------------------------------------------
    let client_mac = MacAddr([0x00, 0x50, 0x79, 0x66, 0x68, 0x01]);
    let client_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 68);

    // DISCOVER -> OFFER
    let discover = build_dhcp_packet(client_mac, MessageType::Discover, None, None, Some("homelab-node"));
    dhcp_handle.send_packet(discover, client_src).await;

    let offer_reply = timeout(Duration::from_millis(500), dhcp_handle.recv_reply())
        .await
        .expect("Timeout waiting for DHCP OFFER")
        .expect("DHCP channel closed");
    let offer_msg = offer_reply.message().expect("Decode OFFER");
    let assigned_ip = offer_msg.yiaddr();
    assert!(assigned_ip >= Ipv4Addr::new(192, 168, 1, 100));

    // REQUEST -> ACK
    let request = build_dhcp_packet(
        client_mac,
        MessageType::Request,
        Some(assigned_ip),
        Some(dhcp_cfg.server_id),
        Some("homelab-node"),
    );
    dhcp_handle.send_packet(request, client_src).await;

    let ack_reply = timeout(Duration::from_millis(500), dhcp_handle.recv_reply())
        .await
        .expect("Timeout waiting for DHCP ACK")
        .expect("DHCP channel closed");
    let ack_msg = ack_reply.message().expect("Decode ACK");
    assert_eq!(ack_msg.yiaddr(), assigned_ip);

    // Verify context updated with newly leased client
    let client_device = ctx.get_device(&client_mac).expect("Client device must exist in context");
    assert_eq!(client_device.display_hostname(), "homelab-node");
    assert!(matches!(client_device.v4, IPv4State::Dynamic(_)));

    // -----------------------------------------------------------------------
    // 6. Client Joins IPv6: SLAAC & Router Solicitation
    // -----------------------------------------------------------------------
    let client_v6: Ipv6Addr = "fe80::250:79ff:fe66:6801".parse().unwrap();
    let _ = ctx.apply(DeviceUpdate::NdpSeen {
        mac: client_mac,
        ip: client_v6,
        is_active: true,
    });

    // Send RS from client link-local IP
    let rs_packet = vec![133, 0, 0, 0, 0, 0, 0, 0];
    let client_v6_src = SocketAddrV6::new(client_v6, 0, 0, 0);
    ra_handle.inject(rs_packet, client_v6_src).await;

    // Receive unicast RA reply
    let unicast_ra = timeout(Duration::from_millis(500), ra_handle.recv_payload())
        .await
        .expect("Timeout waiting for unicast RA response")
        .expect("RA channel closed");
    assert_eq!(unicast_ra[0], 134);

    // Verify SLAAC discovery event was published
    let rs_event = timeout(Duration::from_millis(500), async {
        loop {
            if let Ok(event) = net_sub.recv().await
                && let LanforgeEvent::Network(NetworkEvent::RsReceived { mac }) = event.event
            {
                return mac;
            }
        }
    })
    .await
    .expect("Timeout waiting for RsReceived event");
    assert_eq!(rs_event, client_mac);

    // -----------------------------------------------------------------------
    // 7. Multi-Service In-Place Dynamic Reconfiguration (WAN / PPPoE Bounce)
    // -----------------------------------------------------------------------

    // PPPoE establishes session on ppp0
    let session_up = PppoeSessionUp {
        interface: "ppp0".to_string(),
        ac_mac: None,
        ac_name: Some("BRAS-01".to_string()),
        session_id: 1,
        mru: 1492,
        ipv4: Some(Ipv4Addr::new(100, 64, 0, 2)),
        ipv4_peer: Some(Ipv4Addr::new(100, 64, 0, 1)),
        dns: vec![IpAddr::V4(Ipv4Addr::new(1, 1, 1, 1))],
        ipv6_link_local: false,
    };
    let _ = bus.publish(LanforgeEvent::Pppoe(PppoeEvent::SessionUp(Box::new(session_up))));

    // Verify Traffic Service absorbed the transition and rebound SQM to ppp0
    let sqm_rebound = timeout(Duration::from_millis(500), async {
        loop {
            if let Ok(event) = traffic_sub.recv().await
                && let LanforgeEvent::Traffic(ref te) = event.event
                && let TrafficEvent::SqmApplied { ref interface, .. } = **te
                && interface == "ppp0"
            {
                return true;
            }
        }
    })
    .await
    .expect("Timeout waiting for SQM rebinding to ppp0");
    assert!(sqm_rebound);

    // Trigger Firewall ruleset recompile
    let _ = bus.publish(LanforgeEvent::Firewall(FirewallEvent::RulesetChanged));

    // Verify NftService re-compiled ruleset in inert mode without kernel netlink call
    let fw_recompiled = timeout(Duration::from_millis(500), async {
        loop {
            if let Ok(event) = fw_sub.recv().await
                && matches!(event.event, LanforgeEvent::Firewall(FirewallEvent::RulesetApplied(_)))
            {
                return true;
            }
        }
    })
    .await
    .expect("Timeout waiting for Firewall RulesetApplied event");
    assert!(fw_recompiled);

    // Trigger RA burst
    let _ = bus.publish(LanforgeEvent::Network(NetworkEvent::RaTriggerRequested));
    let burst_ra = timeout(Duration::from_millis(500), ra_handle.recv_payload())
        .await
        .expect("Timeout waiting for triggered burst RA")
        .expect("RA channel closed");
    assert_eq!(burst_ra[0], 134);

    // -----------------------------------------------------------------------
    // 8. Clean Tear Down
    // -----------------------------------------------------------------------
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));

    let shutdown = timeout(
        Duration::from_millis(800),
        async {
            let _ = tokio::join!(nft_task, traffic_task, ra_task, dhcp_task);
        },
    )
    .await;
    assert!(shutdown.is_ok(), "All services should shut down cleanly within timeout");
}
