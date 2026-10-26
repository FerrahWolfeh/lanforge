mod common;

use std::net::{Ipv4Addr, Ipv6Addr};
use std::time::{Duration, SystemTime};

use common::{
    Dhcpv4PacketBuilder, Dhcpv6PacketBuilder, create_test_v4_server, create_test_v6_server,
    init_test_context, init_test_context_with_interface,
};
use dhcproto::v4::{
    DhcpOption as Dhcpv4Option, Message as MessageV4, MessageType as MessageTypeV4,
    OptionCode as OptionCodeV4,
};
use dhcproto::v6::{
    DhcpOption as Dhcpv6Option, Message as MessageV6, MessageType as MessageTypeV6,
    OptionCode as OptionCodeV6,
};
use dhcproto::{Decodable, Decoder};
use lanforge_dhcp::v4::server::HandleResult as HandleResultV4;
use lanforge_dhcp::v6::server::HandleResult as HandleResultV6;
use lanforge_types::device::Origin;
use lanforge_types::identifiers::{Duid, MacAddr};
use lanforge_types::update::{CliHostUpdate, DeviceUpdate};

#[test]
fn test_dhcpv4_dora_lifecycle_simulation() {
    let (ctx, _bus) = init_test_context();
    let mut server = create_test_v4_server(ctx.clone());
    let client_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);

    // --- 1. DISCOVER ---
    let discover_bytes = Dhcpv4PacketBuilder::discover(client_mac)
        .with_hostname("test-laptop")
        .build();
    let res = server.handle_packet(&discover_bytes, None);

    let (offered_ip, offer_msg) = match res {
        HandleResultV4::Reply {
            packet, msg_type, ..
        } => {
            assert_eq!(msg_type, MessageTypeV4::Offer);
            let msg = MessageV4::decode(&mut Decoder::new(&packet))
                .expect("Failed to decode offer packet");
            let offered = msg.yiaddr();
            assert!(offered >= Ipv4Addr::new(192, 168, 1, 100));
            assert!(offered <= Ipv4Addr::new(192, 168, 1, 200));
            (offered, msg)
        }
        _ => panic!("Expected Reply with Offer"),
    };

    // Verify Offer Options
    assert_eq!(
        offer_msg.opts().get(OptionCodeV4::SubnetMask),
        Some(&Dhcpv4Option::SubnetMask(Ipv4Addr::new(255, 255, 255, 0)))
    );
    assert_eq!(
        offer_msg.opts().get(OptionCodeV4::Router),
        Some(&Dhcpv4Option::Router(vec![Ipv4Addr::new(192, 168, 1, 1)]))
    );

    // --- 2. REQUEST ---
    let request_bytes = Dhcpv4PacketBuilder::request(client_mac, offered_ip, server.cfg.server_id)
        .with_hostname("test-laptop")
        .build();
    let res = server.handle_packet(&request_bytes, None);

    match res {
        HandleResultV4::Reply {
            packet, msg_type, ..
        } => {
            assert_eq!(msg_type, MessageTypeV4::Ack);
            let msg =
                MessageV4::decode(&mut Decoder::new(&packet)).expect("Failed to decode ack packet");
            assert_eq!(msg.yiaddr(), offered_ip);
        }
        _ => panic!("Expected Reply with Ack"),
    }
    assert_eq!(server.last_assigned_ip, Some(offered_ip));

    // Register granted lease in context (what the service wrapper does)
    let _ = ctx.apply(DeviceUpdate::V4LeaseGranted {
        mac: client_mac,
        ip: offered_ip,
        expires: SystemTime::now() + Duration::from_secs(3600),
    });

    // --- 3. RELEASE ---
    let release_bytes =
        Dhcpv4PacketBuilder::release(client_mac, offered_ip, server.cfg.server_id).build();
    let res = server.handle_packet(&release_bytes, None);
    match res {
        HandleResultV4::Release { ip } => {
            assert_eq!(ip, offered_ip);
        }
        _ => panic!("Expected Release result"),
    }
}

#[test]
fn test_dhcpv4_static_reservation_simulation() {
    let (ctx, _bus) = init_test_context();
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

    let mut server = create_test_v4_server(ctx.clone());

    let device = ctx.with_state(|s| s.get_device(&static_mac));
    assert!(device.is_some());

    // Send Discover from reserved MAC
    let discover_bytes = Dhcpv4PacketBuilder::discover(static_mac).build();
    let res = server.handle_packet(&discover_bytes, device.as_deref());

    match res {
        HandleResultV4::Reply {
            packet, msg_type, ..
        } => {
            assert_eq!(msg_type, MessageTypeV4::Offer);
            let msg = MessageV4::decode(&mut Decoder::new(&packet))
                .expect("Failed to decode offer packet");
            assert_eq!(msg.yiaddr(), reserved_ip);
        }
        _ => panic!("Expected Reply with static reserved IP"),
    }
}

#[test]
fn test_dhcpv4_decline_quarantine_simulation() {
    let (ctx, _bus) = init_test_context();
    let mut server = create_test_v4_server(ctx);
    let mac = MacAddr([0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC]);

    // Discover first IP
    let discover_bytes = Dhcpv4PacketBuilder::discover(mac).build();
    let res = server.handle_packet(&discover_bytes, None);
    let offered_ip = match res {
        HandleResultV4::Reply { packet, .. } => {
            let msg = MessageV4::decode(&mut Decoder::new(&packet)).unwrap();
            msg.yiaddr()
        }
        _ => panic!("Expected offer"),
    };

    // Client declines the offered IP (e.g. ARP collision detected by client)
    let decline_bytes = Dhcpv4PacketBuilder::decline(mac, offered_ip, server.cfg.server_id).build();
    let res = server.handle_packet(&decline_bytes, None);
    assert!(matches!(res, HandleResultV4::Ignore));

    // Next Discover should allocate a DIFFERENT address because the first one is quarantined
    let res2 = server.handle_packet(&discover_bytes, None);
    let new_offered_ip = match res2 {
        HandleResultV4::Reply { packet, .. } => {
            let msg = MessageV4::decode(&mut Decoder::new(&packet)).unwrap();
            msg.yiaddr()
        }
        _ => panic!("Expected new offer"),
    };

    assert_ne!(
        offered_ip, new_offered_ip,
        "Declined IP must not be offered immediately"
    );
}

#[test]
fn test_dhcpv6_sarr_lifecycle_simulation() {
    let client_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x66]);
    let (ctx, _bus) = init_test_context_with_interface(1, "lan0", client_mac);
    let (mut server, server_duid) = create_test_v6_server(ctx.clone());

    let client_duid = Duid::new(vec![
        0x00, 0x03, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x66,
    ]);
    let client_ll = "fe80::11:2233:4466".parse::<Ipv6Addr>().unwrap();

    // --- 1. SOLICIT ---
    let solicit_msg = Dhcpv6PacketBuilder::solicit(client_duid.clone())
        .with_ia_na(1, None)
        .build_message();
    let mut buf = Vec::new();
    let res = server.handle_packet(&solicit_msg, client_ll, Some(client_mac), &mut buf);

    let offered_ip = match res {
        HandleResultV6::Reply(bytes, dest, duid, mac, assigned, _, msg_type) => {
            assert_eq!(msg_type, MessageTypeV6::Advertise);
            assert_eq!(dest, client_ll);
            assert_eq!(duid, Some(client_duid.clone()));
            assert_eq!(mac, Some(client_mac));
            assert!(assigned.na.contains(&1), "Assigned IAIDs must contain 1");

            let reply_msg =
                MessageV6::decode(&mut Decoder::new(bytes)).expect("Failed to decode advertise");
            let mut addr = None;
            for opt in reply_msg.opts().iter() {
                if let Dhcpv6Option::IANA(iana) = opt {
                    for sub in iana.opts.iter() {
                        if let Dhcpv6Option::IAAddr(ia_addr) = sub {
                            addr = Some(ia_addr.addr);
                        }
                    }
                }
            }
            addr.expect("Advertise message must contain an IAAddr option")
        }
        _ => panic!("Expected Reply with Advertise"),
    };

    assert!(offered_ip >= "fd97:f00d:cafe:3731::100".parse::<Ipv6Addr>().unwrap());
    assert!(offered_ip <= "fd97:f00d:cafe:3731::200".parse::<Ipv6Addr>().unwrap());

    // --- 2. REQUEST ---
    let request_msg = Dhcpv6PacketBuilder::request(client_duid.clone(), server_duid.clone())
        .with_ia_na(1, Some(offered_ip))
        .build_message();
    let mut buf2 = Vec::new();
    let res = server.handle_packet(&request_msg, client_ll, Some(client_mac), &mut buf2);

    match res {
        HandleResultV6::Reply(bytes, dest, _, _, assigned, _, msg_type) => {
            assert_eq!(msg_type, MessageTypeV6::Reply);
            assert_eq!(dest, client_ll);
            assert!(assigned.na.contains(&1));

            let reply_msg =
                MessageV6::decode(&mut Decoder::new(bytes)).expect("Failed to decode reply");
            let mut confirmed_addr = None;
            for opt in reply_msg.opts().iter() {
                if let Dhcpv6Option::IANA(iana) = opt {
                    for sub in iana.opts.iter() {
                        if let Dhcpv6Option::IAAddr(ia_addr) = sub {
                            confirmed_addr = Some(ia_addr.addr);
                        }
                    }
                }
            }
            assert_eq!(confirmed_addr, Some(offered_ip));
        }
        _ => panic!("Expected Reply with Ack Reply"),
    }

    assert_eq!(
        server.last_assignment_for(&client_duid, 1),
        vec![offered_ip]
    );

    // Register lease in context (what the service wrapper does)
    let _ = ctx.apply(DeviceUpdate::V6LeaseGranted(Box::new(
        lanforge_types::update::V6LeaseUpdate {
            mac: Some(client_mac),
            duid: client_duid.clone(),
            iaid: 1,
            ip: offered_ip,
            expires: SystemTime::now() + Duration::from_secs(86400),
        },
    )));

    // --- 3. RELEASE ---
    let release_msg = Dhcpv6PacketBuilder::release(client_duid.clone(), server_duid)
        .with_ia_na(1, Some(offered_ip))
        .build_message();
    let mut buf3 = Vec::new();
    let res = server.handle_packet(&release_msg, client_ll, Some(client_mac), &mut buf3);

    match res {
        HandleResultV6::Reply(_, _, _, _, _, released, msg_type) => {
            assert_eq!(msg_type, MessageTypeV6::Reply);
            assert!(released.na.contains(&1), "Released IAIDs must contain 1");
        }
        _ => panic!("Expected Reply with release confirmation"),
    }
}

#[test]
fn test_dhcpv6_rapid_commit_simulation() {
    let client_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x77]);
    let (ctx, _bus) = init_test_context_with_interface(1, "lan0", client_mac);
    let (mut server, _server_duid) = create_test_v6_server(ctx);

    let client_duid = Duid::new(vec![
        0x00, 0x03, 0x00, 0x01, 0x00, 0x11, 0x22, 0x33, 0x44, 0x77,
    ]);
    let client_ll = "fe80::11:2233:4477".parse::<Ipv6Addr>().unwrap();

    // Solicit with Rapid Commit option enabled
    let solicit_msg = Dhcpv6PacketBuilder::solicit(client_duid)
        .with_ia_na(1, None)
        .with_rapid_commit(true)
        .build_message();

    let mut buf = Vec::new();
    let res = server.handle_packet(&solicit_msg, client_ll, Some(client_mac), &mut buf);

    // In Rapid Commit, the server responds immediately with a Reply (skipping Advertise)
    match res {
        HandleResultV6::Reply(bytes, _, _, _, assigned, _, msg_type) => {
            assert_eq!(
                msg_type,
                MessageTypeV6::Reply,
                "Rapid Commit must yield immediate Reply"
            );
            assert!(assigned.na.contains(&1));

            let reply_msg =
                MessageV6::decode(&mut Decoder::new(bytes)).expect("Failed to decode reply");
            assert!(
                reply_msg.opts().get(OptionCodeV6::RapidCommit).is_some(),
                "Rapid Commit option must be echoed in Reply"
            );
        }
        _ => panic!("Expected Reply for Rapid Commit Solicit"),
    }
}

#[test]
fn test_dhcpv6_static_suffix_reservation_simulation() {
    let static_mac = MacAddr([0xCA, 0xFE, 0xBA, 0xBE, 0x00, 0x01]);
    let static_duid = Duid::new(vec![
        0x00, 0x03, 0x00, 0x01, 0xca, 0xfe, 0xba, 0xbe, 0x00, 0x01,
    ]);
    let (ctx, _bus) = init_test_context_with_interface(1, "lan0", static_mac);

    // Register static reservation with v6_suffix "::beef"
    let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
        mac: static_mac,
        update: Box::new(CliHostUpdate {
            hostname: Some("nas-server".to_string()).into(),
            duid: Some(static_duid.clone()).into(),
            v4_static: None.into(),
            v6_suffix: Some("::beef".parse().unwrap()).into(),
            boot_file: None.into(),
            dns_fallback: None.into(),
            class: None.into(),
            origin: Origin::Static,
        }),
    });

    let (mut server, _server_duid) = create_test_v6_server(ctx);
    let client_ll = "fe80::cafe:babe:0001".parse::<Ipv6Addr>().unwrap();

    let solicit_msg = Dhcpv6PacketBuilder::solicit(static_duid)
        .with_ia_na(1, None)
        .build_message();

    let mut buf = Vec::new();
    let res = server.handle_packet(&solicit_msg, client_ll, Some(static_mac), &mut buf);

    match res {
        HandleResultV6::Reply(bytes, _, _, _, _, _, _) => {
            let reply_msg = MessageV6::decode(&mut Decoder::new(bytes)).unwrap();
            let mut addr = None;
            for opt in reply_msg.opts().iter() {
                if let Dhcpv6Option::IANA(iana) = opt {
                    for sub in iana.opts.iter() {
                        if let Dhcpv6Option::IAAddr(ia_addr) = sub {
                            addr = Some(ia_addr.addr);
                        }
                    }
                }
            }
            let assigned_ip = addr.expect("Must allocate an address");
            let expected_ip = "fd97:f00d:cafe:3731::beef".parse::<Ipv6Addr>().unwrap();
            assert_eq!(
                assigned_ip, expected_ip,
                "Assigned IPv6 address must match static reservation suffix ::beef"
            );
        }
        _ => panic!("Expected Reply with static suffix reservation"),
    }
}
