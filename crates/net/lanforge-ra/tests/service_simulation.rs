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
    PrefixLifetime, PrefixSource, PreviousLanPrefix, RAPrefix, RaServerConfig, RouterPriority,
};
use lanforge_types::system::ServiceState;
use lanforge_types::update::{DeviceUpdate, InterfaceState};
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

/// Prefix options `(prefix, valid, preferred)` of an RA payload.
fn ra_prefixes(ra: &[u8]) -> Vec<(Ipv6Addr, u32, u32)> {
    let mut offset = 16; // ICMPv6 header + RA fixed fields
    let mut prefixes = Vec::new();
    while offset + 8 <= ra.len() {
        let opt_type = ra[offset];
        let opt_len = ra[offset + 1] as usize * 8;
        if opt_len == 0 || offset + opt_len > ra.len() {
            break;
        }
        if opt_type == 3 && opt_len >= 32 {
            let valid = u32::from_be_bytes(ra[offset + 4..offset + 8].try_into().unwrap());
            let preferred = u32::from_be_bytes(ra[offset + 8..offset + 12].try_into().unwrap());
            let addr: [u8; 16] = ra[offset + 16..offset + 32].try_into().unwrap();
            prefixes.push((Ipv6Addr::from(addr), valid, preferred));
        }
        offset += opt_len;
    }
    prefixes
}

/// Sets the IPv6 addresses of an interface the way netlink does (emits `PrefixChanged`).
fn set_iface_gua(ctx: &LanforgeContext, ifindex: u32, gua: Option<Ipv6Addr>) {
    let _ = ctx.apply(DeviceUpdate::InterfaceIpsChanged {
        ifindex,
        state: Box::new(InterfaceState {
            v4: None,
            link_local: Some("fe80::1".parse().unwrap()),
            gua,
            ula: None,
            gua_preferred: 3600,
            gua_valid: 7200,
            mac: Some(MacAddr([0x02, 0, 0, 0, 0, 0x01])),
        }),
    });
}

/// RA follows the LAN prefix (delegated by the OS), never the WAN link prefix: on a PPPoE
/// reconnect `ppp0` gets its own /64 while the LAN keeps or changes its delegated prefix.
#[tokio::test]
async fn test_ra_prefix_deprecation_on_renumber() {
    // No LAN ifindex in this context: RA serves interface 1. `ppp0` is interface 10.
    const LAN: u32 = 1;
    const PPP0: u32 = 10;
    let (ctx, bus) = create_test_context();

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

    let lan_p1: Ipv6Addr = "2001:db8:1000::".parse().unwrap();
    let lan_p2: Ipv6Addr = "2001:db8:2000::".parse().unwrap();
    let wan_prefix: Ipv6Addr = "2001:db8:ffff::".parse().unwrap();
    set_iface_gua(&ctx, LAN, Some("2001:db8:1000::1".parse().unwrap()));
    set_iface_gua(&ctx, PPP0, Some("2001:db8:ffff::1".parse().unwrap()));

    let (handle, transport) = lanforge_transport::Icmp6Transport::inert();
    let service = RaService::with_transport(RaConfig::default(), ctx.clone(), transport);
    let mut service_clone = service.clone();
    let ctx_clone = ctx.clone();
    let serve_handle = tokio::spawn(async move {
        let h = ServiceHandle::new(lanforge_types::system::ServiceId::Ra, ctx_clone.clone());
        service_clone.serve(&ctx_clone, &h).await
    });
    let next_ra = || async {
        timeout(Duration::from_millis(1000), handle.recv_payload())
            .await
            .expect("Timeout waiting for RA")
            .expect("RA channel closed")
    };
    let find = |ra: &[u8], p: Ipv6Addr| ra_prefixes(ra).into_iter().find(|(a, _, _)| *a == p);

    // 1. Startup: the LAN prefix is advertised, the WAN link prefix never.
    let ra = next_ra().await;
    assert!(find(&ra, lan_p1).is_some_and(|(_, v, p)| v > 0 && p > 0));
    assert!(
        find(&ra, wan_prefix).is_none(),
        "WAN prefix must never be advertised"
    );

    // 2. A `ppp0`-only change (reconnect, new WAN /64) must not touch the LAN advertisement.
    set_iface_gua(&ctx, PPP0, Some("2001:db8:eeee::1".parse().unwrap()));
    let _ = bus.publish(LanforgeEvent::Network(NetworkEvent::RaTriggerRequested));
    let ra = next_ra().await;
    assert!(
        find(&ra, lan_p1).is_some_and(|(_, _, p)| p > 0),
        "LAN prefix must stay preferred"
    );

    // 3. The LAN is renumbered (new delegated prefix): burst with new + deprecated old.
    set_iface_gua(&ctx, LAN, Some("2001:db8:2000::1".parse().unwrap()));
    let ra = next_ra().await;
    let (_, new_valid, new_pref) = find(&ra, lan_p2).expect("new prefix advertised");
    assert!(new_valid > 0 && new_pref > 0);
    let (_, dep_valid, dep_pref) = find(&ra, lan_p1).expect("old prefix deprecated");
    assert_eq!(dep_pref, 0, "RFC 4862 §5.5.3e: preferred_lifetime = 0");
    assert!(
        dep_valid > 0 && dep_valid <= 7200,
        "valid_lifetime capped at 2h"
    );

    // 4. The LAN loses its prefix (PD withdrawn mid-reconnect): deprecate, advertise nothing new.
    set_iface_gua(&ctx, LAN, None);
    let ra = next_ra().await;
    assert_eq!(
        find(&ra, lan_p2).map(|(_, _, p)| p),
        Some(0),
        "lost prefix is deprecated"
    );
    assert!(
        find(&ra, wan_prefix).is_none() && find(&ra, "2001:db8:eeee::".parse().unwrap()).is_none()
    );

    // 5. The same prefix comes back: advertised once, preferred again (not also as deprecated).
    set_iface_gua(&ctx, LAN, Some("2001:db8:2000::1".parse().unwrap()));
    let ra = next_ra().await;
    let opts: Vec<_> = ra_prefixes(&ra)
        .into_iter()
        .filter(|(a, _, _)| *a == lan_p2)
        .collect();
    assert_eq!(
        opts.len(),
        1,
        "a returning prefix must not be advertised twice"
    );
    assert!(opts[0].2 > 0);

    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    assert!(
        timeout(Duration::from_millis(500), serve_handle)
            .await
            .is_ok()
    );
}

/// The delegated prefix changed while the daemon was down: the first RA after startup must
/// deprecate the prefix advertised before (hydrated from the DB), not leave clients preferring it.
#[tokio::test]
async fn test_ra_deprecates_prefix_from_before_restart() {
    let (ctx, bus) = create_test_context();
    ctx.update_ra_server_config(RaServerConfig {
        enabled: true,
        iface: Some("lan0".into()),
        prefixes: vec![RAPrefix::gua_dynamic()],
        deprecate_on_renumber: true,
        ..RaServerConfig::default()
    });
    let old: Ipv6Addr = "2804:bdc:508e:db00::".parse().unwrap();
    let new: Ipv6Addr = "2804:bdc:509d:4500::".parse().unwrap();
    ctx.provide_shared(Arc::new(PreviousLanPrefix(
        lanforge_types::network::Ipv6Prefix::from_addr(old),
    )));
    set_iface_gua(&ctx, 1, Some("2804:bdc:509d:4500::1".parse().unwrap()));

    let (handle, transport) = lanforge_transport::Icmp6Transport::inert();
    let mut service = RaService::with_transport(RaConfig::default(), ctx.clone(), transport);
    let ctx_clone = ctx.clone();
    let serve_handle = tokio::spawn(async move {
        let h = ServiceHandle::new(lanforge_types::system::ServiceId::Ra, ctx_clone.clone());
        service.serve(&ctx_clone, &h).await
    });

    let ra = timeout(Duration::from_millis(1000), handle.recv_payload())
        .await
        .expect("Timeout waiting for startup RA")
        .expect("RA channel closed");
    let prefixes = ra_prefixes(&ra);
    let find = |p: Ipv6Addr| prefixes.iter().find(|(a, _, _)| *a == p).copied();
    assert!(
        find(new).is_some_and(|(_, _, pref)| pref > 0),
        "current prefix advertised"
    );
    assert_eq!(
        find(old).map(|(_, _, pref)| pref),
        Some(0),
        "previous prefix deprecated"
    );

    let _ = bus.publish(LanforgeEvent::System(SystemEvent::Shutdown));
    assert!(
        timeout(Duration::from_millis(500), serve_handle)
            .await
            .is_ok()
    );
}
