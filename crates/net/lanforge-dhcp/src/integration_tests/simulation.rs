//! A full DHCPv6 exchange at the server level, ending in a RELEASE from the client that holds
//! the binding (RFC 8415 §18.3.7). The DHCPv4 flows and the other DHCPv6 cases are covered by
//! the server's unit tests and by `service_lifecycle` through `serve`.

use std::iter;
use std::net::Ipv6Addr;
use std::time::{Duration, SystemTime};

use super::common::{Dhcpv6PacketBuilder, create_test_v6_server, init_test_context_with_interface};
use crate::v6::server::HandleResult as HandleResultV6;
use dhcproto::v6::{
    DhcpOption as Dhcpv6Option, Message as MessageV6, MessageType as MessageTypeV6,
};
use dhcproto::{Decodable, Decoder};
use lanforge_types::identifiers::{Duid, MacAddr};
use lanforge_types::update::{DeviceUpdate, V6LeaseUpdate};

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
    let _ = ctx.apply(DeviceUpdate::V6LeaseGranted(Box::new(V6LeaseUpdate {
        mac: Some(client_mac),
        duid: client_duid.clone(),
        iaid: 1,
        ips: iter::once(offered_ip).collect(),
        expires: SystemTime::now() + Duration::from_secs(86400),
    })));

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
