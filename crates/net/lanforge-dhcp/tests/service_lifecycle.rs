use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dhcproto::v4::{DhcpOption, Message, MessageType};
use dhcproto::{Encodable, Encoder};
use lanforge_core::bus::{EventBus, LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::AsyncService;
use lanforge_dhcp::{Dhcpv4Config, Dhcpv4Service, Dhcpv4Transport};
use lanforge_types::device::{IPv4State, Origin};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dhcp::Dhcpv4Pool;
use lanforge_types::system::ServiceState;
use tokio::time::timeout;

fn create_test_context() -> (LanforgeContext, Arc<EventBus>) {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus.clone(), state, None);

    ctx.set_target_interface_name("lan0".to_string());
    (ctx, bus)
}

fn create_test_config() -> Dhcpv4Config {
    Dhcpv4Config {
        enabled: true,
        iface: "lan0".into(),
        server_id: Ipv4Addr::new(192, 168, 1, 1),
        lease_time: 3600,
        router: Ipv4Addr::new(192, 168, 1, 1),
        subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
        dns: vec![Ipv4Addr::new(192, 168, 1, 1)],
        domain_name: Some("lan".to_string()),
        pools: vec![Dhcpv4Pool {
            name: Some("Primary LAN Scope".to_string()),
            range_start: Ipv4Addr::new(192, 168, 1, 100),
            range_end: Ipv4Addr::new(192, 168, 1, 200),
            lease_time: Some(3600),
            router: Some(Ipv4Addr::new(192, 168, 1, 1)),
            dns_servers: vec![Ipv4Addr::new(192, 168, 1, 1)],
            domain_name: Some("lan".to_string()),
            ..Default::default()
        }],
        ..Default::default()
    }
}

fn build_packet(
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
async fn test_dhcpv4_synthetic_full_lifecycle() {
    let (ctx, bus) = create_test_context();
    let cfg = create_test_config();

    // 1. Configure pool in context
    ctx.update_dhcp_v4_pools(cfg.pools.clone());

    // 2. Initialize inert service
    let (handle, transport) = Dhcpv4Transport::inert();
    assert!(transport.is_inert());
    let service = Dhcpv4Service::with_transport(cfg.clone(), ctx.clone(), transport);

    // 3. Spawn service task
    let mut service_clone = service.clone();
    let ctx_clone = ctx.clone();
    let serve_handle = tokio::spawn(async move { service_clone.serve(&ctx_clone).await });

    // Allow service to initialize and transition to Online
    tokio::time::sleep(Duration::from_millis(50)).await;
    assert_eq!(ctx.get_service_state("dhcpv4"), ServiceState::Online);

    let client_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let client_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 68);

    // --- Step 1: DISCOVER -> OFFER ---
    let discover_bytes = build_packet(
        client_mac,
        MessageType::Discover,
        None,
        None,
        Some("client-laptop"),
    );
    handle.send_packet(discover_bytes, client_src).await;

    let offer_reply = timeout(Duration::from_millis(500), handle.recv_reply())
        .await
        .expect("Timeout waiting for DHCP OFFER")
        .expect("Synthetic reply channel closed unexpectedly");

    let offer_msg = offer_reply.message().expect("Failed to decode OFFER message");
    let offered_ip = offer_msg.yiaddr();
    assert!(
        offered_ip >= Ipv4Addr::new(192, 168, 1, 100)
            && offered_ip <= Ipv4Addr::new(192, 168, 1, 200),
        "Offered IP {offered_ip} not within pool range"
    );

    // --- Step 2: REQUEST -> ACK ---
    let request_bytes = build_packet(
        client_mac,
        MessageType::Request,
        Some(offered_ip),
        Some(cfg.server_id),
        Some("client-laptop"),
    );
    handle.send_packet(request_bytes, client_src).await;

    let ack_reply = timeout(Duration::from_millis(500), handle.recv_reply())
        .await
        .expect("Timeout waiting for DHCP ACK")
        .expect("Synthetic reply channel closed unexpectedly");

    let ack_msg = ack_reply.message().expect("Failed to decode ACK message");
    assert_eq!(ack_msg.yiaddr(), offered_ip);

    // --- Step 3: Verify Context State Updates ---
    let dev = ctx.get_device(&client_mac).expect("Device should be registered in context");
    assert_eq!(dev.display_hostname(), "client-laptop");
    match dev.v4 {
        IPv4State::Dynamic(ref lease) => {
            assert_eq!(lease.ip, offered_ip);
        }
        _ => panic!("Expected dynamic IPv4 lease in device state"),
    }

    // Verify stats
    let stats = ctx.dhcpv4_stats();
    assert_eq!(stats.discovers.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(stats.offers.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(stats.requests.load(std::sync::atomic::Ordering::Relaxed), 1);
    assert_eq!(stats.acks.load(std::sync::atomic::Ordering::Relaxed), 1);

    // --- Step 4: Static Lease Pinning ---
    let static_mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    let pinned_ip = Ipv4Addr::new(192, 168, 1, 50);
    let _ = ctx.apply(lanforge_types::update::DeviceUpdate::CliHostUpdated {
        mac: static_mac,
        update: Box::new(lanforge_types::update::CliHostUpdate {
            hostname: Some("static-printer".to_string()).into(),
            duid: None.into(),
            v4_static: Some(pinned_ip).into(),
            v6_suffix: None.into(),
            boot_file: None.into(),
            dns_fallback: None.into(),
            class: None.into(),
            origin: Origin::Static,
        }),
    });

    let static_discover = build_packet(
        static_mac,
        MessageType::Discover,
        None,
        None,
        Some("printer"),
    );
    handle.send_packet(static_discover, client_src).await;

    let static_offer = timeout(Duration::from_millis(500), handle.recv_reply())
        .await
        .expect("Timeout waiting for static DHCP OFFER")
        .expect("Synthetic reply channel closed unexpectedly");

    let static_offer_msg = static_offer.message().expect("Failed to decode static OFFER");
    assert_eq!(
        static_offer_msg.yiaddr(),
        pinned_ip,
        "Expected offered IP to be pinned static IP"
    );

    // --- Step 5: Clean Shutdown ---
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let shutdown_res = timeout(Duration::from_millis(500), serve_handle).await;
    assert!(shutdown_res.is_ok());
}
