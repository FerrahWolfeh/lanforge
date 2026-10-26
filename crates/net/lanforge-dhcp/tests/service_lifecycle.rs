mod common;

use common::{
    Dhcpv4PacketBuilder, Dhcpv6PacketBuilder, create_test_v4_config, create_test_v6_config,
    init_test_context, init_test_context_with_interface,
};
use dhcproto::v4::MessageType as MessageTypeV4;
use dhcproto::v6::{
    DhcpOption as Dhcpv6Option, Message as MessageV6, MessageType as MessageTypeV6,
    OptionCode as OptionCodeV6,
};
use dhcproto::{Decodable, Decoder};
use lanforge_core::bus::{LanforgeEvent, SystemEvent};
use lanforge_core::context::LanforgeContext;
use lanforge_core::service::{AsyncService, ServiceHandle};
use lanforge_dhcp::{Dhcpv4Service, Dhcpv4Transport, Dhcpv6Service, Dhcpv6Transport};
use lanforge_types::device::{IPv4State, Origin};
use lanforge_types::identifiers::{Duid, MacAddr};
use lanforge_types::system::{ServiceId, ServiceState};
use lanforge_types::update::{CliHostUpdate, DeviceUpdate, InterfaceState};
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

    let client_duid = Duid::new(vec![
        0x00, 0x03, 0x00, 0x01, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66,
    ]);
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
    assert!(
        has_dynamic_lease,
        "Device state must contain granted dynamic IPv6 lease"
    );

    let stats = ctx.dhcpv6_stats();
    assert_eq!(stats.solicits.load(Ordering::Relaxed), 1);
    assert_eq!(stats.advertises.load(Ordering::Relaxed), 1);
    assert_eq!(stats.requests.load(Ordering::Relaxed), 1);
    assert_eq!(stats.replies.load(Ordering::Relaxed), 1);

    // --- Step 4: Static Suffix Pinning ---
    let static_duid = Duid::new(vec![
        0x00, 0x03, 0x00, 0x01, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ]);
    let pinned_suffix: lanforge_types::network::Ipv6Suffix = "::50".parse()?;
    let dummy_static_mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);

    let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
        mac: dummy_static_mac,
        update: Box::new(CliHostUpdate {
            hostname: Some("static-v6-server".to_string()).into(),
            duid: Some(static_duid.clone()).into(),
            v4_static: None.into(),
            v6_suffix: Some(lanforge_types::device::Ipv6AddrOrSuffix::Suffix(
                pinned_suffix,
            ))
            .into(),
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

/// All IA_NA addresses offered in an ADVERTISE.
fn advertised_addrs(adv: &MessageV6) -> Vec<Ipv6Addr> {
    adv.opts()
        .iter()
        .filter_map(|opt| match opt {
            Dhcpv6Option::IANA(iana) => Some(iana.opts.iter().filter_map(|o| match o {
                Dhcpv6Option::IAAddr(a) => Some(a.addr),
                _ => None,
            })),
            _ => None,
        })
        .flatten()
        .collect()
}

/// Pools follow the prefix of the served LAN interface only. On a PPPoE reconnect `ppp0` gets
/// its own /64; leasing addresses from it leaves clients with an unroutable IPv6 address.
#[tokio::test]
async fn test_dhcpv6_pool_ignores_wan_prefix_changes() -> Result<(), Box<dyn Error>> {
    const LAN: u32 = 1;
    const PPP0: u32 = 10;
    let server_mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    let (ctx, bus) = init_test_context_with_interface(LAN, "lan0", server_mac);
    let cfg = create_test_v6_config();
    ctx.update_dhcp_v6_pools(cfg.pools.clone());

    let (handle, transport) = Dhcpv6Transport::inert();
    let mut service = Dhcpv6Service::with_transport(cfg, ctx.clone(), transport);
    let ctx_clone = ctx.clone();
    let serve_handle = tokio::spawn(async move {
        let h = ServiceHandle::new(ServiceId::Dhcp6, ctx_clone.clone());
        service.serve(&ctx_clone, &h).await
    });
    wait_for_service_online(&ctx, ServiceId::Dhcp6).await?;

    let set_gua = |ifindex: u32, gua: &str| {
        let _ = ctx.apply(DeviceUpdate::InterfaceIpsChanged {
            ifindex,
            state: Box::new(InterfaceState {
                v4: (ifindex == LAN).then_some((Ipv4Addr::new(192, 168, 1, 1), 24)),
                link_local: Some("fe80::1".parse().unwrap()),
                gua: Some(gua.parse().unwrap()),
                ula: (ifindex == LAN).then(|| "fd97:f00d:cafe:3731::".parse().unwrap()),
                gua_preferred: 3600,
                gua_valid: 7200,
                mac: Some(server_mac),
            }),
        });
    };
    let handle = &handle;
    let solicit = |n: u8| async move {
        let duid = Duid::new(vec![
            0x00, 0x03, 0x00, 0x01, 0x10, 0x20, 0x30, 0x40, 0x50, n,
        ]);
        handle
            .inject(
                Dhcpv6PacketBuilder::solicit(duid).build(),
                "[fe80::cafe:200]:546".parse().unwrap(),
            )
            .await;
        let reply = timeout(TEST_TIMEOUT, handle.recv_payload())
            .await
            .expect("advertise in time")
            .expect("reply channel open");
        advertised_addrs(&MessageV6::decode(&mut Decoder::new(&reply)).expect("valid DHCPv6"))
    };
    let in_prefix = |addr: &Ipv6Addr, prefix: &str| {
        let p: Ipv6Addr = prefix.parse().unwrap();
        addr.segments()[..4] == p.segments()[..4]
    };

    // `ppp0` renumbers: no lease may come from its prefix.
    set_gua(PPP0, "2804:bdc:1f38:c8e4::1");
    tokio::time::sleep(Duration::from_millis(50)).await;
    let addrs = solicit(1).await;
    assert!(
        !addrs.iter().any(|a| in_prefix(a, "2804:bdc:1f38:c8e4::")),
        "leased from the WAN prefix: {addrs:?}"
    );

    // The LAN gets a delegated prefix: leases follow it.
    set_gua(LAN, "2804:bdc:508e:db00::1");
    tokio::time::sleep(Duration::from_millis(50)).await;
    let addrs = solicit(2).await;
    assert!(
        addrs.iter().any(|a| in_prefix(a, "2804:bdc:508e:db00::")),
        "expected a lease from the LAN prefix: {addrs:?}"
    );
    assert!(!addrs.iter().any(|a| in_prefix(a, "2804:bdc:1f38:c8e4::")));

    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = timeout(TEST_TIMEOUT, serve_handle).await?;
    Ok(())
}

/// Static host with a fixed suffix: the ULA lease is infinite (our own prefix), the GUA lease is
/// bounded by the delegated prefix, and T1 stays finite so the client renews and follows a
/// renumbered GUA (clients ignore Reconfigure in practice). On the renewal after a renumbering
/// the old GUA address comes back with zero lifetimes and the new one keeps the same suffix.
#[tokio::test]
async fn test_dhcpv6_static_suffix_follows_renumbered_gua() -> Result<(), Box<dyn Error>> {
    const LAN: u32 = 1;
    let server_mac = MacAddr([0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF]);
    let (ctx, bus) = init_test_context_with_interface(LAN, "lan0", server_mac);
    let cfg = create_test_v6_config();
    ctx.update_dhcp_v6_pools(cfg.pools.clone());

    let set_lan_gua = |gua: &str| {
        let _ = ctx.apply(DeviceUpdate::InterfaceIpsChanged {
            ifindex: LAN,
            state: Box::new(InterfaceState {
                v4: Some((Ipv4Addr::new(192, 168, 1, 1), 24)),
                link_local: Some("fe80::1".parse().unwrap()),
                gua: Some(gua.parse().unwrap()),
                ula: Some("fd97:f00d:cafe:3731::".parse().unwrap()),
                gua_preferred: 3600,
                gua_valid: 7200,
                mac: Some(server_mac),
            }),
        });
    };
    set_lan_gua("2804:bdc:50a7:e800::1");

    // Static host with the `::1057:cafe` token.
    let duid = Duid::new(vec![
        0x00, 0x03, 0x00, 0x01, 0x02, 0x11, 0x22, 0x33, 0x44, 0x55,
    ]);
    let _ = ctx.apply(DeviceUpdate::CliHostUpdated {
        mac: MacAddr([0x02, 0x11, 0x22, 0x33, 0x44, 0x55]),
        update: Box::new(CliHostUpdate {
            hostname: Some("desktop".to_string()).into(),
            duid: Some(duid.clone()).into(),
            v4_static: None.into(),
            v6_suffix: Some(lanforge_types::device::Ipv6AddrOrSuffix::Suffix(
                "::1057:cafe".parse()?,
            ))
            .into(),
            boot_file: None.into(),
            dns_fallback: None.into(),
            class: None.into(),
            origin: Origin::Static,
        }),
    });

    let (handle, transport) = Dhcpv6Transport::inert();
    let mut service = Dhcpv6Service::with_transport(cfg, ctx.clone(), transport);
    let ctx_clone = ctx.clone();
    let serve_handle = tokio::spawn(async move {
        let h = ServiceHandle::new(ServiceId::Dhcp6, ctx_clone.clone());
        service.serve(&ctx_clone, &h).await
    });
    wait_for_service_online(&ctx, ServiceId::Dhcp6).await?;
    let client_src: SocketAddr = "[fe80::1057:cafe]:546".parse()?;

    let exchange = |bytes: Vec<u8>| {
        let handle = &handle;
        async move {
            handle.inject(bytes, client_src).await;
            let reply = timeout(TEST_TIMEOUT, handle.recv_payload())
                .await
                .expect("reply in time")
                .expect("reply channel open");
            MessageV6::decode(&mut Decoder::new(&reply)).expect("valid DHCPv6")
        }
    };
    /// `(addr, preferred, valid)` of every IA_NA address, plus the IA's T1.
    fn ia_view(msg: &MessageV6) -> (Vec<(Ipv6Addr, u32, u32)>, u32) {
        let mut addrs = Vec::new();
        let mut t1 = 0;
        for opt in msg.opts().iter() {
            if let Dhcpv6Option::IANA(iana) = opt {
                t1 = iana.t1;
                for o in iana.opts.iter() {
                    if let Dhcpv6Option::IAAddr(a) = o {
                        addrs.push((a.addr, a.preferred_life, a.valid_life));
                    }
                }
            }
        }
        (addrs, t1)
    }

    let old_gua: Ipv6Addr = "2804:bdc:50a7:e800::1057:cafe".parse()?;
    let new_gua: Ipv6Addr = "2804:bdc:50a9:f300::1057:cafe".parse()?;
    let ula: Ipv6Addr = "fd97:f00d:cafe:3731::1057:cafe".parse()?;

    let adv = exchange(Dhcpv6PacketBuilder::solicit(duid.clone()).build()).await;
    let server_duid = match adv.opts().get(OptionCodeV6::ServerId) {
        Some(Dhcpv6Option::ServerId(d)) => Duid::new(d.clone()),
        _ => return Err("Expected ServerId in Advertise".into()),
    };
    let (addrs, t1) = ia_view(&adv);
    let find = |a: Ipv6Addr| addrs.iter().find(|(x, _, _)| *x == a).copied();
    assert_eq!(
        find(ula).map(|(_, p, v)| (p, v)),
        Some((u32::MAX, u32::MAX)),
        "ULA lease is infinite: {addrs:?}"
    );
    assert_eq!(
        find(old_gua).map(|(_, p, v)| (p, v)),
        Some((3600, 7200)),
        "GUA lease bounded by the PD: {addrs:?}"
    );
    assert!(
        t1 > 0 && t1 <= 3600,
        "T1 must be finite and capped, got {t1}"
    );

    // Bind the lease (Request), as the client does after the Advertise.
    let bound = exchange(
        Dhcpv6PacketBuilder::request(duid.clone(), server_duid.clone())
            .with_ia_na(1, Some(old_gua))
            .build(),
    )
    .await;
    assert!(
        ia_view(&bound).0.iter().any(|(a, _, _)| *a == old_gua),
        "lease bound"
    );

    // The ISP delegates a new prefix; at T1 the client renews the address it holds.
    set_lan_gua("2804:bdc:50a9:f300::1");
    tokio::time::sleep(Duration::from_millis(50)).await;
    let reply = exchange(
        Dhcpv6PacketBuilder::renew(duid, server_duid)
            .with_ia_na(1, Some(old_gua))
            .build(),
    )
    .await;
    let (addrs, _) = ia_view(&reply);
    let find = |a: Ipv6Addr| addrs.iter().find(|(x, _, _)| *x == a).copied();
    assert_eq!(
        find(old_gua).map(|(_, p, v)| (p, v)),
        Some((0, 0)),
        "old GUA withdrawn: {addrs:?}"
    );
    assert!(
        find(new_gua).is_some_and(|(_, p, _)| p > 0),
        "same suffix on the new GUA: {addrs:?}"
    );

    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    let _ = timeout(TEST_TIMEOUT, serve_handle).await?;
    Ok(())
}
