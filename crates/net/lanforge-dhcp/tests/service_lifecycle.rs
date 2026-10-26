mod common;

use common::{
    Dhcpv4PacketBuilder, Dhcpv6PacketBuilder, create_test_v4_config, create_test_v6_config,
    init_test_context, init_test_context_with_interface,
};
use dhcproto::v4::MessageType as MessageTypeV4;
use dhcproto::v6::{DhcpOption as Dhcpv6Option, Message as MessageV6, MessageType as MessageTypeV6, OptionCode as OptionCodeV6};
use dhcproto::{Decodable, Decoder};
use lanforge_core::bus::{LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::service::{AsyncService, ServiceHandle};
use lanforge_dhcp::{
    Dhcpv4Service, Dhcpv4Transport, Dhcpv6Service, Dhcpv6Transport,
};
use lanforge_types::device::{IPv4State, Origin};
use lanforge_types::identifiers::{Duid, MacAddr};
use lanforge_types::system::{ServiceId, ServiceState};
use lanforge_types::update::{CliHostUpdate, DeviceUpdate};
use std::error::Error;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr, SocketAddr};
use std::sync::atomic::Ordering;
use std::time::Duration;
use tokio::time::timeout;

const TEST_TIMEOUT: Duration = Duration::from_millis(1000);

async fn wait_for_service_online(
    ctx: &LanforgeContext,
    service_id: ServiceId,
) -> Result<(), Box<dyn Error>> {
    for _ in 0..100 {
        if ctx.get_service_state(service_id) == ServiceState::Online {
            return Ok(());
        }
        tokio::task::yield_now().await;
    }
    Err(format!("Service '{service_id:?}' did not transition to Online in time").into())
}

#[tokio::test]
async fn test_dhcpv4_synthetic_full_lifecycle() -> Result<(), Box<dyn Error>> {
    let (ctx, bus) = init_test_context();
    ctx.set_target_interface_name("lan0".to_string());
    let cfg = create_test_v4_config();

    // 1. Configure pool in context
    ctx.update_dhcp_v4_pools(cfg.pools.clone());

    // 2. Initialize inert service
    let (handle, transport) = Dhcpv4Transport::inert();
    assert!(transport.is_inert(), "Transport must be in inert mode");
    let service = Dhcpv4Service::with_transport(cfg.clone(), ctx.clone(), transport);

    // 3. Spawn service task
    let mut service_clone = service.clone();
    let ctx_clone = ctx.clone();
    let serve_handle = tokio::spawn(async move {
        let h = ServiceHandle::new(ServiceId::Dhcp4, ctx_clone.clone());
        service_clone.serve(&ctx_clone, &h).await
    });

    // Await Online state cooperatively without fixed sleep
    wait_for_service_online(&ctx, ServiceId::Dhcp4).await?;

    let client_mac = MacAddr([0x00, 0x11, 0x22, 0x33, 0x44, 0x55]);
    let client_src = SocketAddr::new(IpAddr::V4(Ipv4Addr::UNSPECIFIED), 68);

    // --- Step 1: DISCOVER -> OFFER ---
    let discover_bytes = Dhcpv4PacketBuilder::discover(client_mac)
        .with_hostname("client-laptop")
        .build();
    handle.inject(discover_bytes, client_src).await;

    let offer_reply = timeout(TEST_TIMEOUT, handle.recv_reply())
        .await?
        .ok_or("Synthetic reply channel closed unexpectedly")?;

    let offer_msg = offer_reply.message()?;
    assert_eq!(
        offer_msg.opts().get(dhcproto::v4::OptionCode::MessageType),
        Some(&dhcproto::v4::DhcpOption::MessageType(MessageTypeV4::Offer))
    );
    let offered_ip = offer_msg.yiaddr();
    assert!(
        offered_ip >= Ipv4Addr::new(192, 168, 1, 100)
            && offered_ip <= Ipv4Addr::new(192, 168, 1, 200),
        "Offered IP {offered_ip} not within pool range"
    );

    // --- Step 2: REQUEST -> ACK ---
    let request_bytes = Dhcpv4PacketBuilder::request(client_mac, offered_ip, cfg.server_id)
        .with_hostname("client-laptop")
        .build();
    handle.inject(request_bytes, client_src).await;

    let ack_reply = timeout(TEST_TIMEOUT, handle.recv_reply())
        .await?
        .ok_or("Synthetic reply channel closed unexpectedly")?;

    let ack_msg = ack_reply.message()?;
    assert_eq!(
        ack_msg.opts().get(dhcproto::v4::OptionCode::MessageType),
        Some(&dhcproto::v4::DhcpOption::MessageType(MessageTypeV4::Ack))
    );
    assert_eq!(ack_msg.yiaddr(), offered_ip);

    // --- Step 3: Verify Context State Updates ---
    let dev = ctx
        .get_device(&client_mac)
        .ok_or("Device should be registered in context")?;
    assert_eq!(dev.display_hostname(), "client-laptop");
    match dev.v4 {
        IPv4State::Dynamic(ref lease) => {
            assert_eq!(lease.ip, offered_ip);
        }
        _ => return Err("Expected dynamic IPv4 lease in device state".into()),
    }

    // Verify atomic stats
    let stats = ctx.dhcpv4_stats();
    assert_eq!(stats.discovers.load(Ordering::Relaxed), 1);
    assert_eq!(stats.offers.load(Ordering::Relaxed), 1);
    assert_eq!(stats.requests.load(Ordering::Relaxed), 1);
    assert_eq!(stats.acks.load(Ordering::Relaxed), 1);

    // --- Step 4: Static Lease Pinning ---
    let static_mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    let pinned_ip = Ipv4Addr::new(192, 168, 1, 50);
    let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
        mac: static_mac,
        update: Box::new(CliHostUpdate {
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

    let static_discover = Dhcpv4PacketBuilder::discover(static_mac)
        .with_hostname("printer")
        .build();
    handle.inject(static_discover, client_src).await;

    let static_offer = timeout(TEST_TIMEOUT, handle.recv_reply())
        .await?
        .ok_or("Synthetic reply channel closed unexpectedly")?;

    let static_offer_msg = static_offer.message()?;
    assert_eq!(
        static_offer_msg.yiaddr(),
        pinned_ip,
        "Expected offered IP to match pinned static IP"
    );

    // --- Step 5: Clean Shutdown ---
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let shutdown_res = timeout(TEST_TIMEOUT, serve_handle).await?;
    assert!(shutdown_res.is_ok());

    Ok(())
}

#[tokio::test]
async fn test_dhcpv6_synthetic_full_lifecycle() -> Result<(), Box<dyn Error>> {
    let server_mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    let (ctx, bus) = init_test_context_with_interface(1, "lan0", server_mac);
    let cfg = create_test_v6_config();

    // 1. Configure pool in context
    ctx.update_dhcp_v6_pools(cfg.pools.clone());

    // 2. Initialize inert service
    let (handle, transport) = Dhcpv6Transport::inert();
    assert!(transport.is_inert(), "Transport must be in inert mode");
    let service = Dhcpv6Service::with_transport(cfg.clone(), ctx.clone(), transport);

    // 3. Spawn service task
    let mut service_clone = service.clone();
    let ctx_clone = ctx.clone();
    let serve_handle = tokio::spawn(async move {
        let h = ServiceHandle::new(ServiceId::Dhcp6, ctx_clone.clone());
        service_clone.serve(&ctx_clone, &h).await
    });

    // Await Online state cooperatively without fixed sleep
    wait_for_service_online(&ctx, ServiceId::Dhcp6).await?;

    let client_duid = Duid::new(vec![0x00, 0x03, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66]);
    let client_src: SocketAddr = "[fe80::cafe:100]:546".parse()?;

    // --- Step 1: SOLICIT -> ADVERTISE ---
    let solicit_bytes = Dhcpv6PacketBuilder::solicit(client_duid.clone()).build();
    handle.inject(solicit_bytes, client_src).await;

    let reply_bytes = timeout(TEST_TIMEOUT, handle.recv_payload())
        .await?
        .ok_or("Synthetic reply channel closed unexpectedly")?;

    let adv_msg = MessageV6::decode(&mut Decoder::new(&reply_bytes))?;
    assert_eq!(adv_msg.msg_type(), MessageTypeV6::Advertise);

    // Extract server DUID and offered IPv6 address from IANA option
    let server_duid = match adv_msg.opts().get(OptionCodeV6::ServerId) {
        Some(Dhcpv6Option::ServerId(d)) => Duid::new(d.clone()),
        _ => return Err("Expected ServerId in Advertise".into()),
    };

    let offered_v6 = match adv_msg.opts().get(OptionCodeV6::IANA) {
        Some(Dhcpv6Option::IANA(iana)) => match iana.opts.get(OptionCodeV6::IAAddr) {
            Some(Dhcpv6Option::IAAddr(ia_addr)) => ia_addr.addr,
            _ => return Err("Expected IAAddr inside IANA in Advertise".into()),
        },
        _ => return Err("Expected IANA in Advertise".into()),
    };

    let ula_start: Ipv6Addr = "fd97:f00d:cafe:3731::100".parse()?;
    let ula_end: Ipv6Addr = "fd97:f00d:cafe:3731::200".parse()?;
    assert!(
        offered_v6 >= ula_start && offered_v6 <= ula_end,
        "Offered IPv6 {offered_v6} not in ULA pool range"
    );

    // --- Step 2: REQUEST -> REPLY ---
    let req_bytes = Dhcpv6PacketBuilder::request(client_duid.clone(), server_duid)
        .with_ia_na(1, Some(offered_v6))
        .build();
    handle.inject(req_bytes, client_src).await;

    let reply_bytes = timeout(TEST_TIMEOUT, handle.recv_payload())
        .await?
        .ok_or("Synthetic reply channel closed unexpectedly")?;

    let reply_msg = MessageV6::decode(&mut Decoder::new(&reply_bytes))?;
    assert_eq!(reply_msg.msg_type(), MessageTypeV6::Reply);

    // --- Step 3: Verify Context State Updates & Stats ---
    let dev = ctx
        .with_state(|state| {
            state
                .devices
                .values()
                .find(|d| d.duid.as_ref() == Some(&client_duid))
                .cloned()
        })
        .ok_or("Device with DUID should be registered in context state")?;

    let has_dynamic_lease = dev.v6.iter().any(|v6| match v6 {
        lanforge_types::device::IPv6State::Dynamic(lease) => lease.ip == offered_v6,
        _ => false,
    });
    assert!(has_dynamic_lease, "Device state must contain granted dynamic IPv6 lease");

    let stats = ctx.dhcpv6_stats();
    assert_eq!(stats.solicits.load(Ordering::Relaxed), 1);
    assert_eq!(stats.advertises.load(Ordering::Relaxed), 1);
    assert_eq!(stats.requests.load(Ordering::Relaxed), 1);
    assert_eq!(stats.replies.load(Ordering::Relaxed), 1);

    // --- Step 4: Static Suffix Pinning ---
    let static_duid = Duid::new(vec![0x00, 0x03, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff]);
    let pinned_suffix: lanforge_types::network::Ipv6Suffix = "::50".parse()?;
    let dummy_static_mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

    let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
        mac: dummy_static_mac,
        update: Box::new(CliHostUpdate {
            hostname: Some("static-v6-server".to_string()).into(),
            duid: Some(static_duid.clone()).into(),
            v4_static: None.into(),
            v6_suffix: Some(lanforge_types::device::Ipv6AddrOrSuffix::Suffix(pinned_suffix)).into(),
            boot_file: None.into(),
            dns_fallback: None.into(),
            class: None.into(),
            origin: Origin::Static,
        }),
    });

    let static_solicit = Dhcpv6PacketBuilder::solicit(static_duid).build();
    handle.inject(static_solicit, client_src).await;

    let reply_bytes = timeout(TEST_TIMEOUT, handle.recv_payload())
        .await?
        .ok_or("Synthetic reply channel closed unexpectedly")?;

    let static_adv = MessageV6::decode(&mut Decoder::new(&reply_bytes))?;
    let static_offered = match static_adv.opts().get(OptionCodeV6::IANA) {
        Some(Dhcpv6Option::IANA(iana)) => match iana.opts.get(OptionCodeV6::IAAddr) {
            Some(Dhcpv6Option::IAAddr(ia_addr)) => ia_addr.addr,
            _ => return Err("Expected IAAddr in static Advertise".into()),
        },
        _ => return Err("Expected IANA in static Advertise".into()),
    };

    let expected_pinned: Ipv6Addr = "fd97:f00d:cafe:3731::50".parse()?;
    assert_eq!(
        static_offered, expected_pinned,
        "Offered IPv6 must match pinned static suffix"
    );

    // --- Step 5: Clean Shutdown ---
    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let shutdown_res = timeout(TEST_TIMEOUT, serve_handle).await?;
    assert!(shutdown_res.is_ok());

    Ok(())
}
