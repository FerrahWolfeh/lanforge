use std::net::Ipv4Addr;
use std::sync::Arc;

use dhcproto::v4::{DhcpOption, Message, MessageType, OptionCode};
use dhcproto::{Decodable, Decoder, Encodable, Encoder};
use lanforge_core::bus::EventBus;
use lanforge_core::context::LanforgeContext;
use lanforge_core::context::state::State;
use lanforge_dhcp::v4::Dhcpv4Config;
use lanforge_dhcp::v4::server::{DhcpServer, HandleResult};
use lanforge_types::device::Origin;
use lanforge_types::identifiers::MacAddr;
use lanforge_types::network::dhcp::Dhcpv4Pool;
use lanforge_types::update::{CliHostUpdate, DeviceUpdate};

fn create_test_context() -> LanforgeContext {
    let bus = Arc::new(EventBus::new());
    let table = State::new();
    LanforgeContext::new(bus, table, None)
}

fn create_test_config() -> Dhcpv4Config {
    Dhcpv4Config {
        enabled: true,
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

#[test]
fn test_dhcp_dora_lifecycle_simulation() {
    let ctx = create_test_context();
    let cfg = create_test_config();
    let mut server = DhcpServer::new(cfg, ctx.clone());

    let client_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

    // --- 1. DISCOVER ---
    let discover_bytes = build_packet(client_mac, MessageType::Discover, None, None, Some("test-laptop"));
    let res = server.handle_packet(&discover_bytes, None);

    let (offered_ip, offer_msg) = match res {
        HandleResult::Reply { packet, msg_type, .. } => {
            assert_eq!(msg_type, MessageType::Offer);
            let msg = Message::decode(&mut Decoder::new(&packet)).expect("Failed to decode offer packet");
            let offered = msg.yiaddr();
            assert!(offered >= Ipv4Addr::new(192, 168, 1, 100));
            assert!(offered <= Ipv4Addr::new(192, 168, 1, 200));
            (offered, msg)
        }
        _ => panic!("Expected Reply with Offer"),
    };

    // Verify Offer Options
    assert_eq!(
        offer_msg.opts().get(OptionCode::SubnetMask),
        Some(&DhcpOption::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)))
    );
    assert_eq!(
        offer_msg.opts().get(OptionCode::Router),
        Some(&DhcpOption::Router(vec![Ipv4Addr::new(192, 168, 1, 1)]))
    );

    // --- 2. REQUEST ---
    let request_bytes = build_packet(
        client_mac,
        MessageType::Request,
        Some(offered_ip),
        Some(Ipv4Addr::new(192, 168, 1, 1)),
        Some("test-laptop"),
    );
    let res = server.handle_packet(&request_bytes, None);

    match res {
        HandleResult::Reply { packet, msg_type, .. } => {
            assert_eq!(msg_type, MessageType::Ack);
            let msg = Message::decode(&mut Decoder::new(&packet)).expect("Failed to decode ack packet");
            assert_eq!(msg.yiaddr(), offered_ip);
        }
        _ => panic!("Expected Reply with Ack"),
    }
    assert_eq!(server.last_assigned_ip, Some(offered_ip));

    // Register granted lease in context (what the service wrapper does)
    let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
        mac: client_mac,
        ip: offered_ip,
        expires: std::time::SystemTime::now() + std::time::Duration::from_secs(3600),
    });

    // --- 3. RELEASE ---
    let mut release_msg = Message::new(
        offered_ip, // ciaddr
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        Ipv4Addr::UNSPECIFIED,
        &client_mac.0,
    );
    release_msg.opts_mut().insert(DhcpOption::MessageType(MessageType::Release));
    release_msg.opts_mut().insert(DhcpOption::ServerIdentifier(Ipv4Addr::new(192, 168, 1, 1)));
    let mut release_bytes = Vec::new();
    release_msg.encode(&mut Encoder::new(&mut release_bytes)).unwrap();

    let res = server.handle_packet(&release_bytes, None);
    match res {
        HandleResult::Release { ip } => {
            assert_eq!(ip, offered_ip);
        }
        _ => panic!("Expected Release result"),
    }
}

#[test]
fn test_dhcp_static_reservation_simulation() {
    let ctx = create_test_context();
    let static_mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    let reserved_ip = Ipv4Addr::new(192, 168, 1, 42);

    // Register static reservation in context
    let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
        mac: static_mac,
        update: Box::new(CliHostUpdate {
            hostname: Some("static-server".to_string()).into(),
            duid: None.into(),
            v4_static: Some(reserved_ip).into(),
            v6_suffix: None.into(),
            boot_file: None.into(),
            dns_fallback: None.into(),
            class: None.into(),
            origin: Origin::Static,
        }),
    });

    let cfg = create_test_config();
    let mut server = DhcpServer::new(cfg, ctx.clone());

    let device = ctx.with_state(|s| s.get_device(&static_mac));
    assert!(device.is_some());

    // Send Discover from reserved MAC
    let discover_bytes = build_packet(static_mac, MessageType::Discover, None, None, None);
    let res = server.handle_packet(&discover_bytes, device.as_deref());

    match res {
        HandleResult::Reply { packet, msg_type, .. } => {
            assert_eq!(msg_type, MessageType::Offer);
            let msg = Message::decode(&mut Decoder::new(&packet)).expect("Failed to decode offer packet");
            assert_eq!(msg.yiaddr(), reserved_ip);
        }
        _ => panic!("Expected Reply with static reserved IP"),
    }
}

#[test]
fn test_dhcp_decline_quarantine_simulation() {
    let ctx = create_test_context();
    let cfg = create_test_config();
    let mut server = DhcpServer::new(cfg, ctx.clone());

    let mac = MacAddr([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]);

    // Discover first IP
    let discover_bytes = build_packet(mac, MessageType::Discover, None, None, None);
    let res = server.handle_packet(&discover_bytes, None);
    let offered_ip = match res {
        HandleResult::Reply { packet, .. } => {
            let msg = Message::decode(&mut Decoder::new(&packet)).unwrap();
            msg.yiaddr()
        }
        _ => panic!("Expected offer"),
    };

    // Client declines the offered IP (e.g. ARP collision detected by client)
    let decline_bytes = build_packet(
        mac,
        MessageType::Decline,
        Some(offered_ip),
        Some(Ipv4Addr::new(192, 168, 1, 1)),
        None,
    );
    let res = server.handle_packet(&decline_bytes, None);
    assert!(matches!(res, HandleResult::Ignore));

    // Next Discover should allocate a DIFFERENT address because the first one is quarantined
    let res2 = server.handle_packet(&discover_bytes, None);
    let new_offered_ip = match res2 {
        HandleResult::Reply { packet, .. } => {
            let msg = Message::decode(&mut Decoder::new(&packet)).unwrap();
            msg.yiaddr()
        }
        _ => panic!("Expected new offer"),
    };

    assert_ne!(offered_ip, new_offered_ip, "Declined IP must not be offered immediately");
}
