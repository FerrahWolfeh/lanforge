use std::net::{IpAddr, Ipv4Addr, SocketAddr};
use std::sync::Arc;
use std::time::Duration;

use dhcproto::v4::{DhcpOption, Message, MessageType, OptionCode};
use dhcproto::{Encodable, Encoder};
use lanforge_core::bus::{EventBus, LanforgeEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_core::service::{AsyncService, ServiceHandle};
use lanforge_dhcp::{Dhcpv4Config, Dhcpv4Service, Dhcpv4Transport};
use lanforge_types::device::{IPv4State, Origin};
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dhcp::Dhcpv4Pool;
use lanforge_types::update::{CliHostUpdate, DeviceUpdate, FieldUpdate, LeaseTarget};
use tokio::time::timeout;

fn add_static_device(
    ctx: &LanforgeContext,
    mac: MacAddr,
    hostname: &str,
    v4_static: Option<Ipv4Addr>,
) {
    let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
        mac,
        update: Box::new(CliHostUpdate {
            hostname: FieldUpdate::from(Some(hostname.to_string())),
            duid: FieldUpdate::NoChange,
            v4_static: FieldUpdate::from(v4_static),
            v6_suffix: FieldUpdate::NoChange,
            boot_file: FieldUpdate::NoChange,
            dns_fallback: FieldUpdate::NoChange,
            class: FieldUpdate::NoChange,
            origin: Origin::Static,
        }),
    });
}

fn create_test_context() -> (LanforgeContext, Arc<EventBus>) {
    let bus = Arc::new(EventBus::new());
    let state = State::new();
    let ctx = LanforgeContext::new(bus.clone(), state, None);
    (ctx, bus)
}

fn create_test_config() -> (Dhcpv4Config, Dhcpv4Pool) {
    let pool = Dhcpv4Pool {
        name: Some("Test LAN Scope".to_string()),
        range_start: Ipv4Addr::new(192, 168, 1, 100),
        range_end: Ipv4Addr::new(192, 168, 1, 200),
        lease_time: Some(3600),
        router: Some(Ipv4Addr::new(192, 168, 1, 1)),
        dns_servers: vec![Ipv4Addr::new(192, 168, 1, 1)],
        domain_name: Some("lan".to_string()),
        ..Default::default()
    };
    let cfg = Dhcpv4Config {
        enabled: true,
        iface: "lan0".to_string(),
        server_id: Ipv4Addr::new(192, 168, 1, 1),
        lease_time: 3600,
        router: Ipv4Addr::new(192, 168, 1, 1),
        subnet_mask: Ipv4Addr::new(255, 255, 255, 0),
        dns: vec![Ipv4Addr::new(192, 168, 1, 1)],
        domain_name: Some("lan".to_string()),
        pools: vec![pool.clone()],
        ..Default::default()
    };
    (cfg, pool)
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


// ===========================================================================
// Test 1: Dynamic to Static Lease Transition & Obsolete Lease NAK Consistency
// ===========================================================================
#[tokio::test]
async fn test_dynamic_to_static_lease_transition_consistency() {
    let (ctx, bus) = create_test_context();
    let (cfg, pool) = create_test_config();
    ctx.update_dhcp_v4_pools(vec![pool]);

    let (dhcp_handle, transport) = Dhcpv4Transport::inert();
    let service = Dhcpv4Service::with_transport(cfg.clone(), ctx.clone(), transport);
    let mut service_clone = service.clone();
    let ctx_clone = ctx.clone();
    let handle = tokio::spawn(async move {
        let h = ServiceHandle::new("dhcpv4", ctx_clone.clone());
        service_clone.serve(&ctx_clone, &h).await
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let client_mac = MacAddr([0xAA, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let client_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 68);

    // 1. Client obtains initial dynamic lease
    let discover = build_dhcp_packet(client_mac, MessageType::Discover, None, None, Some("workstation-pc"));
    dhcp_handle.send_packet(discover, client_src).await;

    let offer = timeout(Duration::from_millis(500), dhcp_handle.recv_reply())
        .await
        .expect("Timeout waiting for OFFER")
        .expect("Channel closed");
    let initial_ip = offer.message().unwrap().yiaddr();
    assert!(initial_ip >= Ipv4Addr::new(192, 168, 1, 100));

    let request = build_dhcp_packet(
        client_mac,
        MessageType::Request,
        Some(initial_ip),
        Some(cfg.server_id),
        Some("workstation-pc"),
    );
    dhcp_handle.send_packet(request, client_src).await;

    let ack = timeout(Duration::from_millis(500), dhcp_handle.recv_reply())
        .await
        .expect("Timeout waiting for ACK")
        .expect("Channel closed");
    assert_eq!(ack.message().unwrap().yiaddr(), initial_ip);

    // Verify Core state and reverse index consistency
    tokio::time::sleep(Duration::from_millis(30)).await;
    let dev = ctx.get_device(&client_mac).expect("Device must be registered in Core");
    assert!(matches!(dev.v4, IPv4State::Dynamic(ref l) if l.ip == initial_ip));
    assert_eq!(ctx.get_mac_by_ip(IpAddr::V4(initial_ip)), Some(client_mac));
    assert_eq!(dev.display_hostname(), "workstation-pc");

    // 2. Administrator assigns static IP 192.168.1.50 to this workstation
    let static_ip = Ipv4Addr::new(192, 168, 1, 50);
    add_static_device(&ctx, client_mac, "workstation-pc", Some(static_ip));
    tokio::time::sleep(Duration::from_millis(30)).await;

    // Verify Core state updated to Static
    let dev_static = ctx.get_device(&client_mac).expect("Device must exist");
    assert!(matches!(dev_static.v4, IPv4State::Static(ip) if ip == static_ip));

    // 3. Client attempts to renew / request its OLD dynamic IP (initial_ip)
    let stale_request = build_dhcp_packet(
        client_mac,
        MessageType::Request,
        Some(initial_ip),
        Some(cfg.server_id),
        Some("workstation-pc"),
    );
    dhcp_handle.send_packet(stale_request, client_src).await;

    // 4. Server MUST send DHCPNAK because client has a static reservation for static_ip!
    let nak_reply = timeout(Duration::from_millis(500), dhcp_handle.recv_reply())
        .await
        .expect("Timeout waiting for NAK")
        .expect("Channel closed");
    let nak_msg = nak_reply.message().unwrap();
    assert_eq!(
        nak_msg.opts().get(OptionCode::MessageType),
        Some(&DhcpOption::MessageType(MessageType::Nak)),
        "Server must NAK stale dynamic lease when host has static reservation"
    );

    // 5. Client falls back to DISCOVER
    let discover2 = build_dhcp_packet(client_mac, MessageType::Discover, None, None, Some("workstation-pc"));
    dhcp_handle.send_packet(discover2, client_src).await;

    // 6. Server MUST offer the static IP 192.168.1.50
    let offer2 = timeout(Duration::from_millis(500), dhcp_handle.recv_reply())
        .await
        .expect("Timeout waiting for OFFER of static IP")
        .expect("Channel closed");
    assert_eq!(offer2.message().unwrap().yiaddr(), static_ip);

    // 7. Client requests static IP
    let request_static = build_dhcp_packet(
        client_mac,
        MessageType::Request,
        Some(static_ip),
        Some(cfg.server_id),
        Some("workstation-pc"),
    );
    dhcp_handle.send_packet(request_static, client_src).await;

    let ack_static = timeout(Duration::from_millis(500), dhcp_handle.recv_reply())
        .await
        .expect("Timeout waiting for ACK of static IP")
        .expect("Channel closed");
    assert_eq!(ack_static.message().unwrap().yiaddr(), static_ip);

    // 8. Verify Core state retains Static (not downgraded to Dynamic) and indices match
    tokio::time::sleep(Duration::from_millis(30)).await;
    let dev_final = ctx.get_device(&client_mac).expect("Device must exist");
    assert!(
        matches!(dev_final.v4, IPv4State::Static(ip) if ip == static_ip),
        "Core state must remain Static, never downgraded by lease grant"
    );
    assert_eq!(ctx.get_mac_by_ip(IpAddr::V4(static_ip)), Some(client_mac));

    // Clean shutdown
    let _ = bus.publish(LanforgeEvent::System(lanforge_core::bus::SystemEvent::Shutdown));
    let _ = timeout(Duration::from_millis(500), handle).await;
}

// ===========================================================================
// Test 2: Static Lease Outside Dynamic Pool Bounds
// ===========================================================================
#[tokio::test]
async fn test_static_lease_outside_pool_bounds() {
    let (ctx, bus) = create_test_context();
    let (cfg, pool) = create_test_config();
    ctx.update_dhcp_v4_pools(vec![pool]);

    let (dhcp_handle, transport) = Dhcpv4Transport::inert();
    let service = Dhcpv4Service::with_transport(cfg.clone(), ctx.clone(), transport);
    let mut service_clone = service.clone();
    let ctx_clone = ctx.clone();
    let handle = tokio::spawn(async move {
        let h = ServiceHandle::new("dhcpv4", ctx_clone.clone());
        service_clone.serve(&ctx_clone, &h).await
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let server_mac = MacAddr([0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x01]);
    let static_outside_ip = Ipv4Addr::new(192, 168, 1, 10); // Outside 100-200 pool, but valid on /24

    add_static_device(&ctx, server_mac, "nas-server", Some(static_outside_ip));
    tokio::time::sleep(Duration::from_millis(30)).await;

    let client_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 68);

    // Discover from nas-server
    let discover = build_dhcp_packet(server_mac, MessageType::Discover, None, None, Some("nas-server"));
    dhcp_handle.send_packet(discover, client_src).await;

    let offer = timeout(Duration::from_millis(500), dhcp_handle.recv_reply())
        .await
        .expect("Timeout waiting for OFFER")
        .expect("Channel closed");
    assert_eq!(offer.message().unwrap().yiaddr(), static_outside_ip);

    // Request
    let req = build_dhcp_packet(
        server_mac,
        MessageType::Request,
        Some(static_outside_ip),
        Some(cfg.server_id),
        Some("nas-server"),
    );
    dhcp_handle.send_packet(req, client_src).await;

    let ack = timeout(Duration::from_millis(500), dhcp_handle.recv_reply())
        .await
        .expect("Timeout waiting for ACK")
        .expect("Channel closed");
    assert_eq!(ack.message().unwrap().yiaddr(), static_outside_ip);

    // Core verification
    assert_eq!(ctx.get_mac_by_ip(IpAddr::V4(static_outside_ip)), Some(server_mac));

    let _ = bus.publish(LanforgeEvent::System(lanforge_core::bus::SystemEvent::Shutdown));
    let _ = timeout(Duration::from_millis(500), handle).await;
}

// ===========================================================================
// Test 3: IP Stealing Prevention (Unauthorized Client Requesting Taken IP)
// ===========================================================================
#[tokio::test]
async fn test_ip_stealing_prevention() {
    let (ctx, bus) = create_test_context();
    let (cfg, pool) = create_test_config();
    ctx.update_dhcp_v4_pools(vec![pool]);

    let (dhcp_handle, transport) = Dhcpv4Transport::inert();
    let service = Dhcpv4Service::with_transport(cfg.clone(), ctx.clone(), transport);
    let mut service_clone = service.clone();
    let ctx_clone = ctx.clone();
    let handle = tokio::spawn(async move {
        let h = ServiceHandle::new("dhcpv4", ctx_clone.clone());
        service_clone.serve(&ctx_clone, &h).await
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let legit_mac = MacAddr([0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let rogue_mac = MacAddr([0x99, 0x88, 0x77, 0x66, 0x55, 0x44]);
    let client_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 68);

    // 1. Legit client leases an IP
    let discover = build_dhcp_packet(legit_mac, MessageType::Discover, None, None, Some("legit-pc"));
    dhcp_handle.send_packet(discover, client_src).await;
    let offer = dhcp_handle.recv_reply().await.unwrap();
    let legit_ip = offer.message().unwrap().yiaddr();

    let request = build_dhcp_packet(legit_mac, MessageType::Request, Some(legit_ip), Some(cfg.server_id), None);
    dhcp_handle.send_packet(request, client_src).await;
    let ack = dhcp_handle.recv_reply().await.unwrap();
    assert_eq!(ack.message().unwrap().yiaddr(), legit_ip);

    tokio::time::sleep(Duration::from_millis(30)).await;
    assert_eq!(ctx.get_mac_by_ip(IpAddr::V4(legit_ip)), Some(legit_mac));

    // 2. Rogue client directly sends REQUEST for legit_ip
    let rogue_request = build_dhcp_packet(
        rogue_mac,
        MessageType::Request,
        Some(legit_ip),
        Some(cfg.server_id),
        Some("rogue-pc"),
    );
    dhcp_handle.send_packet(rogue_request, client_src).await;

    // 3. Server MUST NAK rogue client
    let nak = timeout(Duration::from_millis(500), dhcp_handle.recv_reply())
        .await
        .expect("Timeout waiting for NAK on IP steal attempt")
        .expect("Channel closed");
    assert_eq!(
        nak.message().unwrap().opts().get(OptionCode::MessageType),
        Some(&DhcpOption::MessageType(MessageType::Nak)),
        "Server must NAK unauthorized request for an already leased IP"
    );

    // 4. Verify legit client ownership is uncompromised
    assert_eq!(ctx.get_mac_by_ip(IpAddr::V4(legit_ip)), Some(legit_mac));

    let _ = bus.publish(LanforgeEvent::System(lanforge_core::bus::SystemEvent::Shutdown));
    let _ = timeout(Duration::from_millis(500), handle).await;
}

// ===========================================================================
// Test 4: DHCP Decline Quarantine Consistency
// ===========================================================================
#[tokio::test]
async fn test_dhcp_decline_quarantine_consistency() {
    let (ctx, bus) = create_test_context();
    let (cfg, pool) = create_test_config();
    ctx.update_dhcp_v4_pools(vec![pool]);

    let (dhcp_handle, transport) = Dhcpv4Transport::inert();
    let service = Dhcpv4Service::with_transport(cfg.clone(), ctx.clone(), transport);
    let mut service_clone = service.clone();
    let ctx_clone = ctx.clone();
    let handle = tokio::spawn(async move {
        let h = ServiceHandle::new("dhcpv4", ctx_clone.clone());
        service_clone.serve(&ctx_clone, &h).await
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mac = MacAddr([0x44, 0x55, 0x66, 0x77, 0x88, 0x99]);
    let client_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 68);

    // Initial Discover
    let discover = build_dhcp_packet(mac, MessageType::Discover, None, None, None);
    dhcp_handle.send_packet(discover.clone(), client_src).await;
    let offer = dhcp_handle.recv_reply().await.unwrap();
    let declined_ip = offer.message().unwrap().yiaddr();

    // Client declines the IP (simulating ARP collision detected by client host)
    let decline = build_dhcp_packet(mac, MessageType::Decline, Some(declined_ip), Some(cfg.server_id), None);
    dhcp_handle.send_packet(decline, client_src).await;

    // Small yield
    tokio::time::sleep(Duration::from_millis(30)).await;

    // Client sends Discover again
    dhcp_handle.send_packet(discover, client_src).await;
    let offer2 = timeout(Duration::from_millis(500), dhcp_handle.recv_reply())
        .await
        .expect("Timeout waiting for second offer")
        .expect("Channel closed");
    let new_ip = offer2.message().unwrap().yiaddr();

    assert_ne!(
        new_ip, declined_ip,
        "Server must not offer quarantined IP immediately after Decline"
    );

    let _ = bus.publish(LanforgeEvent::System(lanforge_core::bus::SystemEvent::Shutdown));
    let _ = timeout(Duration::from_millis(500), handle).await;
}

// ===========================================================================
// Test 5: EventBus IpDeleted Event Recovers Pool Allocation
// ===========================================================================
#[tokio::test]
async fn test_eventbus_ip_deleted_recovers_pool() {
    let (ctx, bus) = create_test_context();

    // Single-IP pool to strictly test exhaustion and recovery
    let small_pool = Dhcpv4Pool {
        name: Some("Tiny Scope".to_string()),
        range_start: Ipv4Addr::new(192, 168, 1, 100),
        range_end: Ipv4Addr::new(192, 168, 1, 100), // Exactly 1 IP!
        lease_time: Some(3600),
        router: Some(Ipv4Addr::new(192, 168, 1, 1)),
        dns_servers: vec![Ipv4Addr::new(192, 168, 1, 1)],
        ..Default::default()
    };
    let mut cfg = create_test_config().0;
    cfg.pools = vec![small_pool.clone()];
    ctx.update_dhcp_v4_pools(vec![small_pool]);

    let (dhcp_handle, transport) = Dhcpv4Transport::inert();
    let service = Dhcpv4Service::with_transport(cfg.clone(), ctx.clone(), transport);
    let mut service_clone = service.clone();
    let ctx_clone = ctx.clone();
    let handle = tokio::spawn(async move {
        let h = ServiceHandle::new("dhcpv4", ctx_clone.clone());
        service_clone.serve(&ctx_clone, &h).await
    });

    tokio::time::sleep(Duration::from_millis(50)).await;

    let mac1 = MacAddr([0x10, 0x10, 0x10, 0x10, 0x10, 0x10]);
    let mac2 = MacAddr([0x20, 0x20, 0x20, 0x20, 0x20, 0x20]);
    let client_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 68);

    // 1. Client 1 grabs the only IP (192.168.1.100)
    let d1 = build_dhcp_packet(mac1, MessageType::Discover, None, None, None);
    dhcp_handle.send_packet(d1, client_src).await;
    let o1 = dhcp_handle.recv_reply().await.unwrap();
    assert_eq!(o1.message().unwrap().yiaddr(), Ipv4Addr::new(192, 168, 1, 100));

    let r1 = build_dhcp_packet(mac1, MessageType::Request, Some(Ipv4Addr::new(192, 168, 1, 100)), Some(cfg.server_id), None);
    dhcp_handle.send_packet(r1, client_src).await;
    let _ = dhcp_handle.recv_reply().await.unwrap();

    // 2. Client 2 tries to discover -> Pool is exhausted, server ignores
    let d2 = build_dhcp_packet(mac2, MessageType::Discover, None, None, None);
    dhcp_handle.send_packet(d2.clone(), client_src).await;
    let exhausted = timeout(Duration::from_millis(150), dhcp_handle.recv_reply()).await;
    assert!(exhausted.is_err(), "Pool must be exhausted, no reply expected");

    // 3. Lease is released in Core
    let _ = ctx.apply(DeviceUpdate::LeaseReleased {
        mac: mac1,
        target: LeaseTarget::V4,
    });
    tokio::time::sleep(Duration::from_millis(50)).await;

    // 4. Client 2 tries to discover again -> IP should now be available!
    dhcp_handle.send_packet(d2, client_src).await;
    let o2 = timeout(Duration::from_millis(500), dhcp_handle.recv_reply())
        .await
        .expect("Timeout waiting for Client 2 offer after IP release")
        .expect("Channel closed");
    assert_eq!(o2.message().unwrap().yiaddr(), Ipv4Addr::new(192, 168, 1, 100));

    let _ = bus.publish(LanforgeEvent::System(lanforge_core::bus::SystemEvent::Shutdown));
    let _ = timeout(Duration::from_millis(500), handle).await;
}
